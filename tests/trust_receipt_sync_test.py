#!/usr/bin/env python3
"""POST /v1/trust/receipt-sync 回执同步与防重放端到端测试。

直接运行：python3 tests/trust_receipt_sync_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源：同一服务的“来源租户”先经 verify-receipt + consume 产生真实
回执消费历史，再由 export（NDJSON）与 manifest（签名清单）导出；目标
租户登记同 did/公钥的信任锚点后通过 receipt-sync 同步。

覆盖：
- 外层错误（非法 JSON/非对象/缺漏字段/manifest 非对象/ndjson 非字符串/
  显式空租户头）400 且仅 {"error": 非空中文}；
- 沿用清单验真：清单非法/锚点不可用/签名校验失败/导出内容不匹配 均
  200 {valid:false,reason}；
- NDJSON 解析：键序、类型、cursor 严格递增且 after<cursor<=snapshot、
  页内或与历史重复 (verifier_did,nonce) 均 200 reason“导出内容非法”；
- 检查点 (tenant,signer_did)：首 after=0；续页同 snapshot、after=末
  cursor；新 snapshot 仅在旧快照追平（末 cursor=旧 snapshot）时接受且
  after=旧 snapshot；旧快照/跳页/同位异内容 409 且仅
  {"error":"同步游标冲突"}；
- 首次 201、同页重放 200；成功响应键序恰为 valid、signer_did、snapshot、
  next_after、count，后三为非负整数；
- 同步原子落盘、不写审计；落盘失败 500 {"error":"存储失败"} 并回滚；
  并发同页仅一次 201；
- consume / consume-batch 验真后命中同步键 -> 200“回执已消费”，不写
  消费记录与审计；
- 租户隔离；跨重启检查点稳定。
"""

import concurrent.futures
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402
from vcbackend.store import StorageError, VCStore  # noqa: E402

SYNC_PATH = "/v1/trust/receipt-sync"
EXPORT_PATH = "/v1/trust/credentials/receipt/consumptions/export"
MANIFEST_PATH = "/v1/trust/credentials/receipt/consumptions/manifest"
VERIFY_RECEIPT_PATH = "/v1/trust/credentials/verify-receipt"
CONSUME_PATH = "/v1/trust/credentials/receipt/consume"
CONSUME_BATCH_PATH = "/v1/trust/credentials/receipt/consume-batch"
ANCHORS_PATH = "/v1/trust/anchors"
OK_KEYS = ["valid", "signer_did", "snapshot", "next_after", "count"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def main():
    port = 9051
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"

    def post(path, payload=None, headers=None, raw_body=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw_body=raw_body)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        SRC = {"X-Tenant-ID": "src-tenant"}
        DST = {"X-Tenant-ID": "dst-tenant"}
        OTHER = {"X-Tenant-ID": "other-tenant"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:receipt-issuer.example"

        # 来源侧：签发者为外部密钥信任锚点；验证者（清单签名者）须为
        # 来源租户内注册的本地 DID（回执由其托管私钥签署），随后再以同
        # did/公钥登记含 vc 用途的信任锚点。
        st, _, _ = post(ANCHORS_PATH,
                        {"did": issuer_did, "public_key": issuer_pub,
                         "key_version": 1}, SRC)
        assert st == 201, st
        st, _, raw = post("/v1/dids",
                          {"method": "web",
                           "public_key": "receipt-sync-signer-handle"}, SRC)
        assert st == 201, (st, raw)
        did_rec = json.loads(raw)
        signer_did = did_rec["did"]
        signer_pub = did_rec["public_key"]

        def read_signer_private():
            with open(store_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            return state["tenants"]["src-tenant"]["dids"][signer_did][
                "key_history"][0]["private_key_pem"]

        signer_priv = read_signer_private()

        for tenant in (SRC, DST):
            st, _, _ = post(ANCHORS_PATH,
                            {"did": signer_did, "public_key": signer_pub,
                             "key_version": 1}, tenant)
            assert st in (200, 201), st
        # 目标侧也登记签发者锚点（回执消费命中时会重算凭证摘要，无需
        # 锚点，但保持两侧拓扑一致）。
        st, _, _ = post(ANCHORS_PATH,
                        {"did": issuer_did, "public_key": issuer_pub,
                         "key_version": 1}, DST)
        assert st in (200, 201), st

        packs = []

        def consume_one(index):
            body = {
                "credential_id": f"vc_sync_{index:03d}",
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"seq": index},
                "issued_at": "2026-09-20T00:00:00Z",
                "issuer_key_version": 1,
            }
            sig = crypto.sign(body, issuer_priv)
            nonce = f"sync-nonce-{index}"
            st, _, raw = post(VERIFY_RECEIPT_PATH,
                              {"body": body, "signature": sig,
                               "verifier_did": signer_did, "nonce": nonce},
                              SRC)
            assert st == 200
            pack = json.loads(raw)
            assert pack["valid"] is True
            st, _, raw = post(CONSUME_PATH,
                              {"receipt": pack["receipt"],
                               "receipt_signature": pack["receipt_signature"],
                               "body": body, "signature": sig,
                               "nonce": nonce}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw
            packs.append((body, sig, nonce, pack))

        for i in range(1, 6):  # 来源侧 5 条消费历史
            consume_one(i)

        def export_page(after, limit, snapshot, headers=SRC):
            st, _, raw = get(
                f"{EXPORT_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}", headers=headers)
            assert st == 200, (st, raw)
            return raw.decode("utf-8")

        def manifest_page(after, limit, snapshot, headers=SRC):
            st, _, raw = get(
                f"{MANIFEST_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}&signer_did={signer_did}",
                headers=headers)
            assert st == 200, (st, raw)
            return json.loads(raw)

        def sync(manifest_obj, ndjson_text, headers=DST):
            return post(SYNC_PATH,
                        {"manifest": manifest_obj, "ndjson": ndjson_text},
                        headers=headers)

        # ---------------------------------------------------------- #
        # 1. 外层 400：仅 {error: 非空中文}
        # ---------------------------------------------------------- #
        def expect_400(name, **kwargs):
            st, _, raw = post(SYNC_PATH, headers=DST, **kwargs)
            r = json.loads(raw.decode() or "{}")
            check(name, st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("非法 JSON", raw_body=b"not-json")
        expect_400("非对象", raw_body=b"[1,2]")
        expect_400("空体", raw_body=b"")
        expect_400("缺 manifest", payload={"ndjson": ""})
        expect_400("缺 ndjson", payload={"manifest": {}})
        expect_400("多余字段",
                   payload={"manifest": {}, "ndjson": "", "x": 1})
        expect_400("manifest 非对象",
                   payload={"manifest": "x", "ndjson": ""})
        expect_400("ndjson 非字符串",
                   payload={"manifest": {}, "ndjson": 5})
        st, _, _ = post(SYNC_PATH,
                        payload={"manifest": {}, "ndjson": ""},
                        headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 清单验真失败：200 {valid:false,reason}
        # ---------------------------------------------------------- #
        nd1 = export_page(0, 2, 2)
        m1 = manifest_page(0, 2, 2)

        def invalid_manifest(name, manifest_obj, ndjson_text, reason):
            st, _, raw = sync(manifest_obj, ndjson_text)
            check(name, st == 200
                  and json.loads(raw) == {"valid": False, "reason": reason})

        bad = copy.deepcopy(m1)
        bad.pop("alg")
        invalid_manifest("清单非法", bad, nd1, "清单非法")
        bad = copy.deepcopy(m1)
        bad["signature"] = "A" * 86
        invalid_manifest("签名校验失败", bad, nd1, "签名校验失败")
        invalid_manifest("导出内容不匹配", m1, nd1 + '{"cursor":9}\n',
                         "导出内容不匹配")
        # 他租户无 signer 锚点 -> 锚点不可用
        st, _, raw = sync(m1, nd1, headers=OTHER)
        check("锚点不可用（他租户）",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 3. 首次同步 201：首页 snapshot=2，after=0，两行
        # ---------------------------------------------------------- #
        st, _, raw = sync(m1, nd1)
        r = json.loads(raw)
        check("首次 201", st == 201)
        check("成功响应键序", list(r.keys()) == OK_KEYS)
        check("首次内容",
              r == {"valid": True, "signer_did": signer_did,
                    "snapshot": 2, "next_after": 2, "count": 2},)
        check("snapshot/next_after/count 非负整数",
              all(isinstance(r[k], int) and not isinstance(r[k], bool)
                  and r[k] >= 0
                  for k in ("snapshot", "next_after", "count")))

        # 完全相同的页重放 -> 200
        st, _, raw = sync(m1, nd1)
        r = json.loads(raw)
        check("同页重放 200",
              st == 200 and r["valid"] is True and r["count"] == 2
              and r["next_after"] == 2)

        # 旧窗口重发（after=0 首页一致）仍 200
        st, _, _ = sync(m1, nd1)
        check("同首页再次重放 200", st == 200)

        # ---------------------------------------------------------- #
        # 4. 检查点冲突：409 仅 {error:同步游标冲突}
        # ---------------------------------------------------------- #
        def expect_409(name, manifest_obj, ndjson_text):
            st, _, raw = sync(manifest_obj, ndjson_text)
            check(name, st == 409
                  and json.loads(raw) == {"error": "同步游标冲突"})

        # 旧快照倒退：snapshot=1
        nd_old = export_page(0, 1, 1)
        m_old = manifest_page(0, 1, 1)
        expect_409("旧快照倒退", m_old, nd_old)

        # 跳页：新快照 5 但 after=4 只给 cursor5，跳过 cursor3/4
        nd_skip = export_page(4, 1, 5)
        m_skip = manifest_page(4, 1, 5)
        expect_409("跳页（缺 cursor3/4）", m_skip, nd_skip)

        # 同位异内容：同页 cursor1/2 中改一行的 nonce（重签清单保证验真
        # 通过，digest 仍匹配篡改后的 NDJSON）
        rows = [json.loads(line) for line in nd1.strip().split("\n")]
        rows[0]["nonce"] = "tampered-nonce"
        tampered_nd = "".join(
            json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
            for row in rows
        )
        m_tamper = copy.deepcopy(m1)
        m_tamper["digest"] = hashlib.sha256(
            tampered_nd.encode("utf-8")).hexdigest()
        m_tamper["signature"] = crypto.sign(
            {k: m_tamper[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, signer_priv)
        expect_409("同位异内容", m_tamper, tampered_nd)

        # ---------------------------------------------------------- #
        # 5. NDJSON 非法：200 “导出内容非法”
        # ---------------------------------------------------------- #
        def resign(manifest_obj, ndjson_text):
            m = copy.deepcopy(manifest_obj)
            m["count"] = ndjson_text.count("\n")
            m["digest"] = hashlib.sha256(
                ndjson_text.encode("utf-8")).hexdigest()
            m["signature"] = crypto.sign(
                {k: m[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return m

        good_rows = [json.loads(line) for line in nd1.strip().split("\n")]

        def illegal_ndjson(name, ndjson_text, reason="导出内容非法",
                           base_manifest=m1):
            m = resign(base_manifest, ndjson_text)
            st, _, raw = sync(m, ndjson_text)
            check(name, st == 200
                  and json.loads(raw) == {"valid": False, "reason": reason})

        row = good_rows[0]
        # 键序错误（键集合相同、顺序不同）
        reordered = json.dumps(
            {"receipt_id": row["receipt_id"], "cursor": row["cursor"],
             "verifier_did": row["verifier_did"], "nonce": row["nonce"],
             "consumed_at": row["consumed_at"]},
            separators=(",", ":"), ensure_ascii=False) + "\n"
        illegal_ndjson("行键序错误", reordered)
        # 多余键
        extra_row = dict(row)
        extra_row["x"] = 1
        illegal_ndjson(
            "行多余键",
            json.dumps(extra_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        # 缺键
        miss_row = {k: row[k] for k in row if k != "nonce"}
        illegal_ndjson(
            "行缺键",
            json.dumps(miss_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        # cursor 为布尔
        bool_row = dict(row)
        bool_row["cursor"] = True
        illegal_ndjson(
            "cursor 为布尔",
            json.dumps(bool_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        # 字符串字段为空串
        empty_row = dict(row)
        empty_row["nonce"] = ""
        illegal_ndjson(
            "字段为空串",
            json.dumps(empty_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        # cursor 非递增（两行相同 cursor）
        dup_cursor = "".join(
            json.dumps(dict(r, cursor=1), separators=(",", ":"),
                       ensure_ascii=False) + "\n"
            for r in good_rows)
        illegal_ndjson("cursor 非递增", dup_cursor)
        # cursor 越出 after<cursor<=snapshot 窗口
        out_row = dict(row)
        out_row["cursor"] = 3
        illegal_ndjson(
            "cursor 超过 snapshot",
            json.dumps(out_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        # 非 JSON 行（digest 匹配，结构非法）
        illegal_ndjson("非 JSON 行", "not-json\n")
        # 空行 / CR
        illegal_ndjson("含空行",
                       json.dumps(row, separators=(",", ":"),
                                  ensure_ascii=False) + "\n\n")
        illegal_ndjson(
            "含 CR",
            json.dumps(row, separators=(",", ":"), ensure_ascii=False)
            + "\r\n")
        # 页内重复 (verifier_did,nonce)：合法续页窗口 snapshot=5 after=2
        # 的行中放两个相同键（cursor 递增）。先取 cursor3 行作模板。
        nd3 = export_page(2, 3, 5)
        m3 = manifest_page(2, 3, 5)
        r3, r4, r5 = (json.loads(line) for line in nd3.strip().split("\n"))
        dup_key_rows = [r3, dict(r4, nonce=r3["nonce"],
                                 receipt_id="f" * 64), r5]
        dup_key_nd = "".join(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
            for r in dup_key_rows)
        illegal_ndjson("页内重复 (verifier_did,nonce)", dup_key_nd)
        # 与历史重复：续页 cursor3 复用首页 cursor1 的键
        hist_dup_rows = [dict(r3, verifier_did=good_rows[0]["verifier_did"],
                              nonce=good_rows[0]["nonce"],
                              receipt_id="e" * 64), r4, r5]
        hist_dup_nd = "".join(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
            for r in hist_dup_rows)
        illegal_ndjson("与历史重复 (verifier_did,nonce)", hist_dup_nd)

        # 非法请求不得推进检查点：合法续页仍可正常进行
        st, _, raw = sync(m3, nd3)
        check("非法后合法续页 200（追平到 5）",
              st == 200 and json.loads(raw)
              == {"valid": True, "signer_did": signer_did,
                  "snapshot": 5, "next_after": 5, "count": 3})

        # ---------------------------------------------------------- #
        # 6. 分页与换新快照（来源新增事件后）
        # ---------------------------------------------------------- #
        for i in range(6, 9):  # 再来 3 条 -> snapshot=8
            consume_one(i)
        # 未追平不接受：当前 cp=(5,5)；先同步 snapshot=8 只给 cursor7,8
        # （after=6 跳过 cursor6）-> 409
        nd_jump = export_page(6, 2, 8)
        m_jump = manifest_page(6, 2, 8)
        expect_409("新快照跳页（缺 cursor6）", m_jump, nd_jump)
        # 合法：snapshot=8 after=5 给 cursor6,7,8 -> 一次追平
        nd8 = export_page(5, 3, 8)
        m8 = manifest_page(5, 3, 8)
        st, _, raw = sync(m8, nd8)
        check("换新快照 200",
              st == 200 and json.loads(raw)
              == {"valid": True, "signer_did": signer_did,
                  "snapshot": 8, "next_after": 8, "count": 3})

        # 空页换快照：cp=(8,8)，来源无新事件时 snapshot=8 after=8 空 NDJSON
        m_empty = manifest_page(8, 1000, 8)
        st, _, raw = sync(m_empty, "")
        r = json.loads(raw)
        check("追平后空页 200",
              st == 200 and r["snapshot"] == 8 and r["next_after"] == 8
              and r["count"] == 0)

        # ---------------------------------------------------------- #
        # 7. 同步不写审计（目标租户无任何 receipt 审计）
        # ---------------------------------------------------------- #
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions = [e["action"] for e in json.loads(raw)["events"]]
        check("同步不写审计", all("receipt" not in a for a in actions))

        # ---------------------------------------------------------- #
        # 8. consume / consume-batch 命中同步键 -> 回执已消费
        # ---------------------------------------------------------- #
        body1, sig1, nonce1, pack1 = packs[0]  # (verifier=signer, n=sync-nonce-1)
        consume_req = {
            "receipt": pack1["receipt"],
            "receipt_signature": pack1["receipt_signature"],
            "body": body1, "signature": sig1, "nonce": nonce1,
        }
        st, _, raw = post(CONSUME_PATH, consume_req, headers=DST)
        check("consume 命中同步键",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "回执已消费"})
        st, _, raw = post(CONSUME_BATCH_PATH, {"items": [consume_req]},
                          headers=DST)
        r = json.loads(raw)
        check("consume-batch 命中同步键",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "回执已消费"})
        # 未同步的新键在目标租户仍可正常消费（见下方 fresh-nonce 场景，
        # 同步判重不应误伤未出现过的键）。
        # 命中后仍不写审计
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions2 = [e["action"] for e in json.loads(raw)["events"]]
        check("命中同步键不写审计",
              all("receipt" not in a for a in actions2))

        # consume 一条来源从未同步过的键 -> 正常首次消费。
        # 目标租户未托管签名者私钥，故按公开协议手工构造合法回执（七阶
        # 段验真仅依赖锚点公钥）。
        body = {
            "credential_id": "vc_sync_fresh",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"fresh": True},
            "issued_at": "2026-09-20T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)
        nonce = "fresh-nonce-not-synced"
        receipt = {
            "credential_id": body["credential_id"],
            "issuer_did": body["issuer_did"],
            "issuer_key_version": 1,
            "credential_digest": hashlib.sha256(
                crypto.canonicalize({"body": body, "signature": sig})
            ).hexdigest(),
            "verifier_did": signer_did,
            "verifier_key_version": 1,
            "nonce": nonce,
        }
        receipt_sig = crypto.sign(receipt, signer_priv)
        st, _, raw = post(CONSUME_PATH,
                          {"receipt": receipt,
                           "receipt_signature": receipt_sig,
                           "body": body, "signature": sig, "nonce": nonce},
                          DST)
        r = json.loads(raw)
        check("未同步键正常消费 200",
              st == 200 and r.get("valid") is True and r["receipt_id"])

        # ---------------------------------------------------------- #
        # 9. 租户隔离：他租户首次同步同内容仍 201
        # ---------------------------------------------------------- #
        # other 租户也注册 signer 锚点
        st, _, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1}, OTHER)
        assert st == 201, st
        nd_iso = export_page(0, 2, 2)
        m_iso = manifest_page(0, 2, 2)
        st, _, raw = sync(m_iso, nd_iso, headers=OTHER)
        check("他租户首次同步独立 201",
              st == 201 and json.loads(raw)["count"] == 2)

        # ---------------------------------------------------------- #
        # 10. 并发同页只增一次（仅一个 201）
        # ---------------------------------------------------------- #
        conc_signer_priv, conc_signer_pub = _keypair()
        conc_signer = "did:web:conc-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                     {"did": conc_signer, "public_key": conc_signer_pub,
                      "key_version": 1}, DST)
        assert st == 201, st
        conc_nd = (
            json.dumps(
                {"cursor": 1, "receipt_id": "c" * 64,
                 "verifier_did": "did:web:conc-verifier.example",
                 "nonce": "c1", "consumed_at": "2026-09-20T00:00:00Z"},
                separators=(",", ":"), ensure_ascii=False) + "\n"
        )
        conc_manifest = {
            "snapshot": 1,
            "filters": {"after": 0, "limit": 1000},
            "count": 1,
            "alg": "SHA-256",
            "digest": hashlib.sha256(conc_nd.encode("utf-8")).hexdigest(),
            "signer_did": conc_signer,
            "key_version": 1,
        }
        conc_manifest["signature"] = crypto.sign(
            {k: conc_manifest[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, conc_signer_priv)

        def call_sync(_):
            st, _, _ = sync(conc_manifest, conc_nd)
            return st

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            codes = list(pool.map(call_sync, range(16)))
        check("并发同页仅一次 201，其余 200",
              codes.count(201) == 1 and codes.count(200) == 15,
              )

        # ---------------------------------------------------------- #
        # 11. 跨重启：检查点保留，同内容为 200 重放
        # ---------------------------------------------------------- #
        captured = (m8, nd8)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, _, raw = sync(*captured)
        check("重启后当前快照页重放 200", st == 200)
        # 重启后旧快照冲突仍然成立
        st, _, raw = sync(m_old, nd_old)
        check("重启后旧快照仍 409", st == 409)
        # 重启后 consume 仍命中同步键
        body1, sig1, nonce1, pack1 = packs[0]
        st, _, raw = post(CONSUME_PATH,
                          {"receipt": pack1["receipt"],
                           "receipt_signature": pack1["receipt_signature"],
                           "body": body1, "signature": sig1,
                           "nonce": nonce1}, DST)
        check("重启后 consume 仍命中",
              json.loads(raw) == {"valid": False, "reason": "回执已消费"})

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store_path):
            os.remove(store_path)

    # -------------------------------------------------------------- #
    # 12. 直连 VCStore：落盘失败 500 语义（StorageError）与原子回滚
    # -------------------------------------------------------------- #
    rollback_failures = _store_rollback_checks()
    failures.extend(rollback_failures)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


def _store_rollback_checks():
    """落盘失败回滚 + 重试只增一次（直连存储，不经 HTTP）。"""
    local_failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            local_failures.append(name)

    store = VCStore(tempfile.mktemp(suffix=".json"))
    tenant = "rollback-sync"
    signer = "did:web:rb-signer.example"

    def row(cursor, nonce):
        return {
            "cursor": cursor,
            "receipt_id": f"{cursor:064d}",
            "verifier_did": "did:web:rb-verifier.example",
            "nonce": nonce,
            "consumed_at": "2026-09-20T00:00:00Z",
        }

    events = [row(1, "rb-n1"), row(2, "rb-n2")]

    original_save = store._save_locked  # noqa: SLF001

    def boom():
        raise OSError("模拟磁盘已满")

    store._save_locked = boom  # type: ignore[assignment]  # noqa: SLF001
    try:
        try:
            store.sync_receipt_consumptions(tenant, signer, 2, 0, events)
            raised = False
        except StorageError:
            raised = True
        check("落盘失败抛 StorageError", raised)
    finally:
        store._save_locked = original_save  # type: ignore[assignment]  # noqa: SLF001

    # 回滚后内存无检查点、无同步事件与判重索引
    check("回滚后无检查点",
          (tenant, signer) not in [
              (t, s)
              for t, by_s in store._receipt_sync_checkpoints.items()  # noqa: SLF001
              for s in by_s])
    bucket = store._tenants.get(tenant, {})  # noqa: SLF001
    check("回滚后无同步事件",
          not bucket.get("synced_receipt_consumption_events", {}).get(signer))
    check("回滚后无判重索引", not bucket.get("synced_receipts"))
    check("回滚不写审计", all(
        e["tenant_id"] != tenant for e in store._audit))  # noqa: SLF001

    # 恢复后重试成功且为首次 201；再次调用为重放 200
    created, _, next_after, count = store.sync_receipt_consumptions(
        tenant, signer, 2, 0, events)
    check("恢复后重试首次创建",
          created and next_after == 2 and count == 2)
    created2, _, _, count2 = store.sync_receipt_consumptions(
        tenant, signer, 2, 0, [dict(e) for e in events])
    check("重试后同内容为幂等重放", (not created2) and count2 == 2)

    # 磁盘文件未被失败写污染：重新加载得到同一检查点
    reloaded = VCStore(store.path)
    cp = reloaded._receipt_sync_checkpoints.get(tenant, {}).get(signer)  # noqa: SLF001
    check("重启加载检查点 (2,2)", cp == {"snapshot": 2, "after": 2})
    os.remove(store.path)
    return local_failures


if __name__ == "__main__":
    raise SystemExit(main())
