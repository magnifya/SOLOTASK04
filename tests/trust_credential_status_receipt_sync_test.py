#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt-sync 状态回执消费清单
同步与防重放端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_sync_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源：同一服务的“来源租户”先经 credential-status/receipt/consume
产生真实状态回执消费历史，再由同目录 export（NDJSON）与 manifest（签名
清单）导出；目标租户登记同 did/公钥且含 status 用途的信任锚点后通过
credential-status/receipt-sync 同步。

覆盖（完整对齐 POST /v1/trust/receipt-sync 语义，差异为 status 锚点
用途、独立检查点/索引、consume 命中返“状态回执已消费”）：
- 外层错误 400 且仅 {"error": 非空中文}，显式空租户头 400；
- 五阶段清单验真：清单非法/锚点不可用（status 用途）/签名校验失败/
  导出内容不匹配 均 200 {valid:false,reason}；
- NDJSON：键序、类型、游标窗口、页内或与历史重复 (verifier_did,nonce)
  均 200“导出内容非法”；
- 检查点 (tenant,signer_did) 独立于普通验真回执同步：首 after=0、
  续页/换新快照/旧快照/跳页/同位异内容 409；
- 首次 201、重放 200；成功响应键序恰为 valid、signer_did、snapshot、
  next_after、count；
- consume / consume-batch 验真后命中同步键 -> 200“状态回执已消费”，
  不写消费记录与审计；
- 同步不写审计、租户隔离、并发仅一次 201、跨重启检查点稳定；
- 直连存储：落盘失败 StorageError 并原子回滚。
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

SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
PLAIN_SYNC_PATH = "/v1/trust/receipt-sync"
EXPORT_PATH = (
    "/v1/trust/credential-status/receipt/consumptions/export"
)
MANIFEST_PATH = (
    "/v1/trust/credential-status/receipt/consumptions/manifest"
)
CONSUME_PATH = "/v1/trust/credential-status/receipt/consume"
CONSUME_BATCH_PATH = (
    "/v1/trust/credential-status/receipt/consume-batch"
)
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
    port = 9063
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
        SRC = {"X-Tenant-ID": "cs-src-tenant"}
        DST = {"X-Tenant-ID": "cs-dst-tenant"}
        OTHER = {"X-Tenant-ID": "cs-other-tenant"}

        # 验证者（清单签名者）为来源租户托管本地 DID，回执由其托管私钥
        # 签署；随后在来源与目标租户登记同 did/公钥、含 status 用途的
        # 信任锚点。
        st, _, raw = post("/v1/dids",
                          {"method": "web",
                           "public_key": "cs-receipt-sync-signer-handle"},
                          SRC)
        assert st == 201, (st, raw)
        did_rec = json.loads(raw)
        signer_did = did_rec["did"]
        signer_pub = did_rec["public_key"]

        def read_signer_private():
            with open(store_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            return state["tenants"]["cs-src-tenant"]["dids"][signer_did][
                "key_history"][0]["private_key_pem"]

        signer_priv = read_signer_private()

        for tenant in (SRC, DST):
            st, _, _ = post(ANCHORS_PATH,
                            {"did": signer_did, "public_key": signer_pub,
                             "key_version": 1,
                             "uses": ["generic", "status"]}, tenant)
            assert st in (200, 201), st

        def make_receipt(index, nonce):
            rcpt = {
                "issuer_did": "did:web:cs-receipt-issuer.example",
                "credential_id": f"vc_cs_sync_{index:03d}",
                "status": "active",
                "reason": None,
                "updated_at": "2026-09-20T00:00:00Z",
                "issuer_key_version": 1,
                "verifier_did": signer_did,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return rcpt, crypto.sign(rcpt, signer_priv)

        packs = []

        def consume_one(index):
            nonce = f"cs-sync-nonce-{index}"
            rcpt, rcpt_sig = make_receipt(index, nonce)
            st, _, raw = post(CONSUME_PATH,
                              {"receipt": rcpt, "signature": rcpt_sig,
                               "nonce": nonce}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw
            packs.append((rcpt, rcpt_sig, nonce))

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
        # 锚点用途收紧为不含 status -> 锚点不可用
        vc_only_priv, vc_only_pub = _keypair()
        st, _, _ = post(ANCHORS_PATH,
                        {"did": "did:web:vc-only.example",
                         "public_key": vc_only_pub, "key_version": 1,
                         "uses": ["vc"]}, DST)
        assert st == 201, st
        m_vc = copy.deepcopy(m1)
        m_vc["signer_did"] = "did:web:vc-only.example"
        m_vc["signature"] = crypto.sign(
            {k: m_vc[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, vc_only_priv)
        invalid_manifest("锚点用途不含 status", m_vc, nd1, "锚点不可用")

        # ---------------------------------------------------------- #
        # 3. 首次同步 201：首页 snapshot=2，after=0，两行
        # ---------------------------------------------------------- #
        st, _, raw = sync(m1, nd1)
        r = json.loads(raw)
        check("首次 201", st == 201)
        check("成功响应键序", list(r.keys()) == OK_KEYS)
        check("首次内容",
              r == {"valid": True, "signer_did": signer_did,
                    "snapshot": 2, "next_after": 2, "count": 2})
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

        # ---------------------------------------------------------- #
        # 4. 检查点冲突：409 仅 {error:同步游标冲突}
        # ---------------------------------------------------------- #
        def expect_409(name, manifest_obj, ndjson_text):
            st, _, raw = sync(manifest_obj, ndjson_text)
            check(name, st == 409
                  and json.loads(raw) == {"error": "同步游标冲突"})

        nd_old = export_page(0, 1, 1)
        m_old = manifest_page(0, 1, 1)
        expect_409("旧快照倒退", m_old, nd_old)

        nd_skip = export_page(4, 1, 5)
        m_skip = manifest_page(4, 1, 5)
        expect_409("跳页（缺 cursor3/4）", m_skip, nd_skip)

        # 同位异内容（重签清单保证验真与摘要通过）
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
        reordered = json.dumps(
            {"receipt_id": row["receipt_id"], "cursor": row["cursor"],
             "verifier_did": row["verifier_did"], "nonce": row["nonce"],
             "consumed_at": row["consumed_at"]},
            separators=(",", ":"), ensure_ascii=False) + "\n"
        illegal_ndjson("行键序错误", reordered)
        extra_row = dict(row)
        extra_row["x"] = 1
        illegal_ndjson(
            "行多余键",
            json.dumps(extra_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        miss_row = {k: row[k] for k in row if k != "nonce"}
        illegal_ndjson(
            "行缺键",
            json.dumps(miss_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        bool_row = dict(row)
        bool_row["cursor"] = True
        illegal_ndjson(
            "cursor 为布尔",
            json.dumps(bool_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        empty_row = dict(row)
        empty_row["nonce"] = ""
        illegal_ndjson(
            "字段为空串",
            json.dumps(empty_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        dup_cursor = "".join(
            json.dumps(dict(r, cursor=1), separators=(",", ":"),
                       ensure_ascii=False) + "\n"
            for r in good_rows)
        illegal_ndjson("cursor 非递增", dup_cursor)
        out_row = dict(row)
        out_row["cursor"] = 3
        illegal_ndjson(
            "cursor 超过 snapshot",
            json.dumps(out_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        illegal_ndjson("非 JSON 行", "not-json\n")
        illegal_ndjson("含空行",
                       json.dumps(row, separators=(",", ":"),
                                  ensure_ascii=False) + "\n\n")
        illegal_ndjson(
            "含 CR",
            json.dumps(row, separators=(",", ":"), ensure_ascii=False)
            + "\r\n")
        # 页内重复键：合法续页窗口 snapshot=5 after=2
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

        # 非法请求不推进检查点：合法续页追平到 5
        st, _, raw = sync(m3, nd3)
        check("非法后合法续页 200（追平到 5）",
              st == 200 and json.loads(raw)
              == {"valid": True, "signer_did": signer_did,
                  "snapshot": 5, "next_after": 5, "count": 3})

        # ---------------------------------------------------------- #
        # 6. 换新快照
        # ---------------------------------------------------------- #
        for i in range(6, 9):  # 再来 3 条 -> snapshot=8
            consume_one(i)
        nd_jump = export_page(6, 2, 8)
        m_jump = manifest_page(6, 2, 8)
        expect_409("新快照跳页（缺 cursor6）", m_jump, nd_jump)
        nd8 = export_page(5, 3, 8)
        m8 = manifest_page(5, 3, 8)
        st, _, raw = sync(m8, nd8)
        check("换新快照 200",
              st == 200 and json.loads(raw)
              == {"valid": True, "signer_did": signer_did,
                  "snapshot": 8, "next_after": 8, "count": 3})
        m_empty = manifest_page(8, 1000, 8)
        st, _, raw = sync(m_empty, "")
        r = json.loads(raw)
        check("追平后空页 200",
              st == 200 and r["snapshot"] == 8 and r["next_after"] == 8
              and r["count"] == 0)

        # ---------------------------------------------------------- #
        # 7. 与普通验真回执同步相互独立：普通 receipt-sync 的检查点/
        #    索引对本端点不可见，反之亦然。
        # ---------------------------------------------------------- #
        # 用普通回执同步端点同步一页（不同签名者、不同 verifier 键），
        # 其键即使 (verifier_did,nonce) 相同也不影响状态回执空间。
        plain_priv, plain_pub = _keypair()
        plain_signer = "did:web:plain-signer.example"
        # 普通清单验真要求 vc 用途锚点
        st, _, _ = post(ANCHORS_PATH,
                        {"did": plain_signer, "public_key": plain_pub,
                         "key_version": 1, "uses": ["vc"]}, DST)
        assert st == 201, st
        plain_verifier = good_rows[0]["verifier_did"]
        # 普通同步页复用与状态同步历史完全相同的 (verifier_did,nonce)
        plain_row = dict(good_rows[0])
        plain_nd = json.dumps(
            plain_row, separators=(",", ":"), ensure_ascii=False) + "\n"
        plain_manifest = {
            "snapshot": 1,
            "filters": {"after": 0, "limit": 1000},
            "count": 1,
            "alg": "SHA-256",
            "digest": hashlib.sha256(
                plain_nd.encode("utf-8")).hexdigest(),
            "signer_did": plain_signer,
            "key_version": 1,
        }
        plain_manifest["signature"] = crypto.sign(
            {k: plain_manifest[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, plain_priv)
        st, _, raw = post(PLAIN_SYNC_PATH,
                          {"manifest": plain_manifest,
                           "ndjson": plain_nd}, DST)
        check("普通回执同步独立落盘 201",
              st == 201 and json.loads(raw)["valid"] is True)
        # 状态同步检查点不受普通同步影响：对状态 signer 再传旧快照仍 409
        expect_409("状态检查点独立于普通同步", m_old, nd_old)

        # ---------------------------------------------------------- #
        # 8. 同步不写审计（目标租户无任何状态回执审计）
        # ---------------------------------------------------------- #
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions = [e["action"] for e in json.loads(raw)["events"]]
        check("同步不写审计",
              all("status.receipt" not in a for a in actions))

        # ---------------------------------------------------------- #
        # 9. consume / consume-batch 命中同步键 -> 状态回执已消费
        # ---------------------------------------------------------- #
        rcpt1, rcpt_sig1, nonce1 = packs[0]
        consume_req = {
            "receipt": rcpt1, "signature": rcpt_sig1, "nonce": nonce1,
        }
        st, _, raw = post(CONSUME_PATH, consume_req, headers=DST)
        check("consume 命中同步键",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "状态回执已消费"})
        st, _, raw = post(CONSUME_BATCH_PATH, {"items": [consume_req]},
                          headers=DST)
        r = json.loads(raw)
        check("consume-batch 命中同步键",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "状态回执已消费"})
        # 命中后不写审计
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions2 = [e["action"] for e in json.loads(raw)["events"]]
        check("命中同步键不写审计",
              all("status.receipt" not in a for a in actions2))
        # 命中不写本地消费记录/历史：目标租户消费历史仍为空
        st, _, raw = get(
            "/v1/trust/credential-status/receipt/consumptions?limit=200",
            headers=DST)
        check("命中不写本地消费历史",
              st == 200 and json.loads(raw)["events"] == [])

        # 未同步的新键在目标租户仍可正常首次消费
        fresh_rcpt, fresh_sig = make_receipt(99, "fresh-nonce-not-synced")
        st, _, raw = post(CONSUME_PATH,
                          {"receipt": fresh_rcpt, "signature": fresh_sig,
                           "nonce": "fresh-nonce-not-synced"}, DST)
        r = json.loads(raw)
        check("未同步键正常消费 200",
              st == 200 and r.get("valid") is True and r["receipt_id"])

        # ---------------------------------------------------------- #
        # 10. 租户隔离：他租户首次同步同内容仍 201
        # ---------------------------------------------------------- #
        st, _, _ = post(ANCHORS_PATH,
                        {"did": signer_did, "public_key": signer_pub,
                         "key_version": 1,
                         "uses": ["generic", "status"]}, OTHER)
        assert st == 201, st
        nd_iso = export_page(0, 2, 2)
        m_iso = manifest_page(0, 2, 2)
        st, _, raw = sync(m_iso, nd_iso, headers=OTHER)
        check("他租户首次同步独立 201",
              st == 201 and json.loads(raw)["count"] == 2)

        # ---------------------------------------------------------- #
        # 11. 并发同页只增一次（仅一个 201）
        # ---------------------------------------------------------- #
        conc_priv, conc_pub = _keypair()
        conc_signer = "did:web:cs-conc-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                        {"did": conc_signer, "public_key": conc_pub,
                         "key_version": 1,
                         "uses": ["generic", "status"]}, DST)
        assert st == 201, st
        conc_nd = (
            json.dumps(
                {"cursor": 1, "receipt_id": "c" * 64,
                 "verifier_did": "did:web:cs-conc-verifier.example",
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
                "signer_did", "key_version")}, conc_priv)

        def call_sync(_):
            st, _, _ = sync(conc_manifest, conc_nd)
            return st

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            codes = list(pool.map(call_sync, range(16)))
        check("并发同页仅一次 201，其余 200",
              codes.count(201) == 1 and codes.count(200) == 15)

        # ---------------------------------------------------------- #
        # 12. 跨重启：检查点保留；consume 仍命中
        # ---------------------------------------------------------- #
        captured = (m8, nd8)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, _, raw = sync(*captured)
        check("重启后当前快照页重放 200", st == 200)
        st, _, raw = sync(m_old, nd_old)
        check("重启后旧快照仍 409", st == 409)
        rcpt1, rcpt_sig1, nonce1 = packs[0]
        st, _, raw = post(CONSUME_PATH,
                          {"receipt": rcpt1, "signature": rcpt_sig1,
                           "nonce": nonce1}, DST)
        check("重启后 consume 仍命中",
              json.loads(raw) == {"valid": False,
                                  "reason": "状态回执已消费"})

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store_path):
            os.remove(store_path)

    # -------------------------------------------------------------- #
    # 13. 直连 VCStore：落盘失败 500 语义与原子回滚（独立状态空间）
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
    local_failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            local_failures.append(name)

    store = VCStore(tempfile.mktemp(suffix=".json"))
    tenant = "cs-rollback-sync"
    signer = "did:web:cs-rb-signer.example"

    def row(cursor, nonce):
        return {
            "cursor": cursor,
            "receipt_id": f"{cursor:064d}",
            "verifier_did": "did:web:cs-rb-verifier.example",
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
            store.sync_credential_status_receipt_consumptions(
                tenant, signer, 2, 0, events)
            raised = False
        except StorageError:
            raised = True
        check("落盘失败抛 StorageError", raised)
    finally:
        store._save_locked = original_save  # type: ignore[assignment]  # noqa: SLF001

    check("回滚后无检查点",
          (tenant, signer) not in [
              (t, s)
              for t, by_s in (
                  store._credential_status_receipt_sync_checkpoints.items()  # noqa: SLF001
              )
              for s in by_s])
    bucket = store._tenants.get(tenant, {})  # noqa: SLF001
    check("回滚后无同步事件",
          not bucket.get(
              "synced_credential_status_receipt_consumption_events", {}
          ).get(signer))
    check("回滚后无判重索引",
          not bucket.get("synced_credential_status_receipts"))
    check("回滚不写审计", all(
        e["tenant_id"] != tenant for e in store._audit))  # noqa: SLF001

    created, _, next_after, count = (
        store.sync_credential_status_receipt_consumptions(
            tenant, signer, 2, 0, events)
    )
    check("恢复后重试首次创建",
          created and next_after == 2 and count == 2)
    created2, _, _, count2 = (
        store.sync_credential_status_receipt_consumptions(
            tenant, signer, 2, 0, [dict(e) for e in events])
    )
    check("重试后同内容为幂等重放", (not created2) and count2 == 2)

    # consume 命中同步索引：返回 (False, None)，不写本地记录与审计
    consumed, consumed_at = store.consume_credential_status_receipt(
        tenant, "did:web:cs-rb-verifier.example", "rb-n1",
        "x" * 64)
    check("consume 命中同步索引", not consumed and consumed_at is None)
    bucket = store._tenants[tenant]
    check("命中不写本地消费记录",
          not bucket["consumed_credential_status_receipts"])
    check("命中不追加消费历史",
          not bucket["credential_status_receipt_consumption_events"])
    check("命中不写审计", all(
        e["tenant_id"] != tenant for e in store._audit))  # noqa: SLF001

    reloaded = VCStore(store.path)
    cp = (
        reloaded._credential_status_receipt_sync_checkpoints  # noqa: SLF001
        .get(tenant, {}).get(signer)
    )
    check("重启加载检查点 (2,2)", cp == {"snapshot": 2, "after": 2})
    os.remove(store.path)
    return local_failures


if __name__ == "__main__":
    raise SystemExit(main())
