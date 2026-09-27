#!/usr/bin/env python3
"""POST /v1/trust/presentation-sync 跨系统外部演示消费历史同步与防重放
端到端测试。

直接运行：python3 tests/trust_presentation_sync_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源：同一服务的“来源租户”先经 /v1/trust/presentations/consume 产生
真实外部演示消费历史，再由 export（NDJSON）与 manifest（签名清单）导出；
目标租户登记同 did/公钥（含 vp 用途）的信任锚点后通过 presentation-sync
同步。

注意：外部演示消费历史的 cursor 取首次消费审计的 seq，为稀疏严格递增
空间（非 1..n 稠密），故本测试不硬编码游标，全部从 export 实际行读取。

覆盖：
- 外层错误（非法 JSON/非对象/空体/缺漏字段/manifest 非对象/ndjson 非
  字符串/显式空租户头）400 且仅 {"error":"请求非法"}；
- 沿用演示消费清单验真：清单非法/锚点不可用/签名校验失败/导出内容不
  匹配均 200 {valid:false,reason}；
- NDJSON 解析：键序、类型、cursor 严格递增且 after<cursor<=snapshot、
  页内或与历史（同步页或本地 consume）重复 (issuer_did,presentation_id)
  均 200 reason“导出内容非法”；
- 检查点 (tenant,signer_did)：首 after=0；同 snapshot 续页 after=已存
  next_after；追至旧 snapshot 后方可接收更大 snapshot；重放 200，旧页、
  跳页、同位异内容 409 且仅 {"error":"同步游标冲突"}；
- 首次 201、新页 200；成功响应键序恰为 valid、signer_did、snapshot、
  next_after、count；
- 同步原子落盘、不写审计；落盘失败 500 {"error":"存储失败"} 并回滚；
  并发同页仅一次 201；
- consume / consume-batch 验真后命中同步索引 -> 200“外部演示已消费”，
  不写入、不审计；未同步新键仍可首次消费；
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

SYNC_PATH = "/v1/trust/presentation-sync"
EXPORT_PATH = "/v1/trust/presentations/consumptions/export"
MANIFEST_PATH = "/v1/trust/presentations/consumptions/manifest"
CONSUME_PATH = "/v1/trust/presentations/consume"
CONSUME_BATCH_PATH = "/v1/trust/presentations/consume-batch"
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


ISSUER_DID = "did:web:pres-issuer.example"


def make_presentation(priv, index, presentation_id=None,
                      issuer_did=None, challenge=None):
    """构造并签发一个合法的未绑定外部演示（九字段）。"""
    p = {
        "presentation_id": presentation_id or f"vp_sync_{index:03d}",
        "credential_id": f"vc_sync_{index:03d}",
        "issuer_did": issuer_did or ISSUER_DID,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin", "seq": index},
        "challenge": challenge or f"chal-{index}",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    p["proof"] = crypto.sign(dict(p), priv)
    return p, p["challenge"]


def main():
    port = 9061
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

        # 来源侧：签发者为外部密钥信任锚点；清单签名者须为来源租户内
        # 注册的本地 DID，随后以同 did/公钥登记含 vp 用途的信任锚点。
        st, _, _ = post(ANCHORS_PATH,
                        {"did": ISSUER_DID, "public_key": issuer_pub,
                         "key_version": 1}, SRC)
        assert st == 201, st
        st, _, raw = post("/v1/dids",
                          {"method": "web",
                           "public_key": "presentation-sync-signer-handle"},
                          SRC)
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
        # 目标侧也登记签发者锚点（consume 验真需要 vp 用途锚点）。
        st, _, _ = post(ANCHORS_PATH,
                        {"did": ISSUER_DID, "public_key": issuer_pub,
                         "key_version": 1}, DST)
        assert st in (200, 201), st

        consumed = []

        def consume_one(index):
            presentation, challenge = make_presentation(issuer_priv, index)
            st, _, raw = post(CONSUME_PATH,
                              {"presentation": presentation,
                               "challenge": challenge}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw
            consumed.append((presentation, challenge))

        for i in range(1, 6):  # 来源侧 5 条消费历史
            consume_one(i)

        def export_page(after, limit, snapshot, headers=SRC):
            st, hd, raw = get(
                f"{EXPORT_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}", headers=headers)
            assert st == 200, (st, raw)
            return raw.decode("utf-8"), int(hd["X-Snapshot-Cursor"])

        def manifest_page(after, limit, snapshot, headers=SRC):
            st, _, raw = get(
                f"{MANIFEST_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}&signer_did={signer_did}",
                headers=headers)
            assert st == 200, (st, raw)
            return json.loads(raw)

        def current_snapshot():
            _, hd, _ = get(f"{EXPORT_PATH}?after=0&limit=1", headers=SRC)
            return int(hd["X-Snapshot-Cursor"])

        def sync(manifest_obj, ndjson_text, headers=DST):
            return post(SYNC_PATH,
                        {"manifest": manifest_obj, "ndjson": ndjson_text},
                        headers=headers)

        # 来源游标为审计 seq（稀疏），全部从实际导出行读取：c1..c5。
        s5 = current_snapshot()
        full_nd, full_snap = export_page(0, 1000, s5)
        assert full_snap == s5
        all_rows = [json.loads(line) for line in full_nd.strip().split("\n")]
        assert len(all_rows) == 5
        c1, c2, c3, c4, c5 = (row["cursor"] for row in all_rows)
        assert c1 < c2 < c3 < c4 < c5 == s5

        # ---------------------------------------------------------- #
        # 1. 外层 400：仅 {error:"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, **kwargs):
            st, _, raw = post(SYNC_PATH, headers=DST, **kwargs)
            r = json.loads(raw.decode() or "{}")
            check(name, st == 400 and r == {"error": "请求非法"})

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
        nd1, _ = export_page(0, 2, s5)
        m1 = manifest_page(0, 2, s5)
        first_rows = [json.loads(line) for line in nd1.strip().split("\n")]
        assert [r["cursor"] for r in first_rows] == [c1, c2]

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
        # 3. 首次同步 201：首页 snapshot=s5，after=0，两行 c1,c2
        # ---------------------------------------------------------- #
        st, _, raw = sync(m1, nd1)
        r = json.loads(raw)
        check("首次 201", st == 201)
        check("成功响应键序", list(r.keys()) == OK_KEYS)
        check("首次内容",
              r["valid"] is True and r["signer_did"] == signer_did
              and r["snapshot"] == s5 and r["next_after"] == c2
              and r["count"] == 2)
        check("snapshot/next_after/count 非负整数",
              all(isinstance(r[k], int) and not isinstance(r[k], bool)
                  and r[k] >= 0
                  for k in ("snapshot", "next_after", "count")))

        # 完全相同的页重放 -> 200
        st, _, raw = sync(m1, nd1)
        r = json.loads(raw)
        check("同页重放 200",
              st == 200 and r["valid"] is True and r["count"] == 2
              and r["next_after"] == c2 and r["snapshot"] == s5)
        st, _, _ = sync(m1, nd1)
        check("同首页再次重放 200", st == 200)

        # ---------------------------------------------------------- #
        # 4. 检查点冲突：409 仅 {error:同步游标冲突}
        # ---------------------------------------------------------- #
        def expect_409(name, manifest_obj, ndjson_text):
            st, _, raw = sync(manifest_obj, ndjson_text)
            check(name, st == 409
                  and json.loads(raw) == {"error": "同步游标冲突"})

        # 旧快照倒退：snapshot=c1（小于已存 s5）
        nd_old, _ = export_page(0, 1, c1)
        m_old = manifest_page(0, 1, c1)
        expect_409("旧快照倒退", m_old, nd_old)

        # 旧页/同位异内容：snapshot=s5 但只重发首行（after=0 的旧窗口
        # 子集），重签清单保证验真通过。
        first_line = nd1.split("\n", 1)[0] + "\n"
        m_first = manifest_page(0, 1, s5)
        m_first["count"] = 1
        m_first["digest"] = hashlib.sha256(
            first_line.encode("utf-8")).hexdigest()
        m_first["signature"] = crypto.sign(
            {k: m_first[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, signer_priv)
        expect_409("旧页（同位异内容）", m_first, first_line)

        # 跳页：after=c4（超过已存 next_after=c2），只给 cursor c5
        nd_skip, _ = export_page(c4, 1, s5)
        m_skip = manifest_page(c4, 1, s5)
        expect_409("跳页（after 越过 next_after）", m_skip, nd_skip)

        # 同位异内容：同首页中改一条 consumption_id（重签清单）
        rows = [json.loads(line) for line in nd1.strip().split("\n")]
        rows[0]["consumption_id"] = "f" * 64
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

        good_rows = first_rows
        row = good_rows[0]

        def illegal_ndjson(name, ndjson_text, reason="导出内容非法",
                           base_manifest=m1):
            m = resign(base_manifest, ndjson_text)
            st, _, raw = sync(m, ndjson_text)
            check(name, st == 200
                  and json.loads(raw) == {"valid": False, "reason": reason})

        # 键序错误（键集合相同、顺序不同）
        reordered = json.dumps(
            {"consumption_id": row["consumption_id"], "cursor": row["cursor"],
             "issuer_did": row["issuer_did"],
             "presentation_id": row["presentation_id"],
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
        miss_row = {k: row[k] for k in row if k != "consumption_id"}
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
        empty_row["presentation_id"] = ""
        illegal_ndjson(
            "字段为空串",
            json.dumps(empty_row, separators=(",", ":"),
                       ensure_ascii=False) + "\n")
        # cursor 非递增（两行相同 cursor）
        dup_cursor = "".join(
            json.dumps(dict(r, cursor=c1), separators=(",", ":"),
                       ensure_ascii=False) + "\n"
            for r in good_rows)
        illegal_ndjson("cursor 非递增", dup_cursor)
        # cursor 越出 after<cursor<=snapshot 窗口
        out_row = dict(row)
        out_row["cursor"] = s5 + 1
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
        # 页内/与历史重复键：使用合法续页窗口 after=c2 snapshot=s5 的
        # 行 c3,c4,c5。
        nd3, _ = export_page(c2, 3, s5)
        m3 = manifest_page(c2, 3, s5)
        r3, r4, r5 = (json.loads(line) for line in nd3.strip().split("\n"))
        assert [r3["cursor"], r4["cursor"], r5["cursor"]] == [c3, c4, c5]
        dup_key_rows = [r3,
                        dict(r4, presentation_id=r3["presentation_id"],
                             consumption_id="d" * 64),
                        r5]
        dup_key_nd = "".join(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
            for r in dup_key_rows)
        illegal_ndjson("页内重复 (issuer_did,presentation_id)", dup_key_nd)
        # 与历史重复：续页首行复用首页行的 (issuer_did,presentation_id)
        hist_dup_rows = [
            dict(r3, issuer_did=good_rows[0]["issuer_did"],
                 presentation_id=good_rows[0]["presentation_id"],
                 consumption_id="e" * 64), r4, r5]
        hist_dup_nd = "".join(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
            for r in hist_dup_rows)
        illegal_ndjson("与同步历史重复 (issuer_did,presentation_id)",
                       hist_dup_nd, base_manifest=m3)

        # 非法请求不得推进检查点：合法续页仍可正常进行
        st, _, raw = sync(m3, nd3)
        check("非法后合法续页 200（追平到 s5）",
              st == 200 and json.loads(raw)
              == {"valid": True, "signer_did": signer_did,
                  "snapshot": s5, "next_after": c5, "count": 3})

        # ---------------------------------------------------------- #
        # 5b. 新行与本地 consume 重复 -> 导出内容非法（独立签名方首页）
        # ---------------------------------------------------------- #
        local_pid = "vp_local_consumed_dup"
        local_pres, local_chal = make_presentation(
            issuer_priv, 900, presentation_id=local_pid,
            challenge="chal-local")
        st, _, raw = post(CONSUME_PATH,
                          {"presentation": local_pres,
                           "challenge": local_chal}, DST)
        assert json.loads(raw)["valid"] is True, raw
        local_dup_signer_priv, local_dup_signer_pub = _keypair()
        local_dup_signer = "did:web:local-dup-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                        {"did": local_dup_signer,
                         "public_key": local_dup_signer_pub,
                         "key_version": 1}, DST)
        assert st == 201, st
        local_dup_nd = json.dumps(
            {"cursor": 1, "consumption_id": "a" * 64,
             "issuer_did": ISSUER_DID, "presentation_id": local_pid,
             "consumed_at": "2099-01-01T00:00:00Z"},
            separators=(",", ":"), ensure_ascii=False) + "\n"
        local_dup_manifest = {
            "snapshot": 1,
            "filters": {"after": 0, "limit": 1000},
            "count": 1,
            "alg": "SHA-256",
            "digest": hashlib.sha256(
                local_dup_nd.encode("utf-8")).hexdigest(),
            "signer_did": local_dup_signer,
            "key_version": 1,
        }
        local_dup_manifest["signature"] = crypto.sign(
            {k: local_dup_manifest[k] for k in (
                "snapshot", "filters", "count", "alg", "digest",
                "signer_did", "key_version")}, local_dup_signer_priv)
        st, _, raw = sync(local_dup_manifest, local_dup_nd)
        check("与本地 consume 重复 -> 导出内容非法",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "导出内容非法"})

        # ---------------------------------------------------------- #
        # 6. 分页与换新快照（来源新增事件后）
        # ---------------------------------------------------------- #
        for i in range(6, 9):  # 再来 3 条 -> 新快照 s8
            consume_one(i)
        s8 = current_snapshot()
        new_full, _ = export_page(0, 1000, s8)
        new_rows = [json.loads(line) for line in new_full.strip().split("\n")]
        c6, c7, c8 = (r["cursor"] for r in new_rows[5:8])
        assert c5 < c6 < c7 < c8 == s8
        # 未追平旧快照衔接点即换新快照：after=c6（不等于旧 snapshot=c5），
        # 只给 c7,c8 -> 409
        nd_jump, _ = export_page(c6, 2, s8)
        m_jump = manifest_page(c6, 2, s8)
        expect_409("新快照衔接点错误（缺 cursor6）", m_jump, nd_jump)
        # 合法：snapshot=s8 after=c5 给 c6,c7,c8 -> 一次追平
        nd8, _ = export_page(c5, 3, s8)
        m8 = manifest_page(c5, 3, s8)
        st, _, raw = sync(m8, nd8)
        check("换新快照 200",
              st == 200 and json.loads(raw)
              == {"valid": True, "signer_did": signer_did,
                  "snapshot": s8, "next_after": c8, "count": 3})

        # 空页：检查点已 (s8,c8)，snapshot=s8 after=c8 空 NDJSON
        m_empty = manifest_page(c8, 1000, s8)
        st, _, raw = sync(m_empty, "")
        r = json.loads(raw)
        check("追平后空页 200",
              st == 200 and r["snapshot"] == s8 and r["next_after"] == c8
              and r["count"] == 0)

        # ---------------------------------------------------------- #
        # 7. 同步不写审计（目标租户仅有两次本地 consume 审计）
        # ---------------------------------------------------------- #
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions = [e["action"] for e in json.loads(raw)["events"]]
        check("同步不写审计",
              all("presentation" not in a for a in actions
                  if a != "trust.presentation.consumed")
              and actions.count("trust.presentation.consumed") == 1)

        # ---------------------------------------------------------- #
        # 8. consume / consume-batch 命中同步索引 -> 外部演示已消费
        # ---------------------------------------------------------- #
        presentation1, challenge1 = consumed[0]
        consume_req = {
            "presentation": presentation1,
            "challenge": challenge1,
        }
        st, _, raw = post(CONSUME_PATH, consume_req, headers=DST)
        check("consume 命中同步索引",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "外部演示已消费"})
        st, _, raw = post(CONSUME_BATCH_PATH, {"items": [consume_req]},
                          headers=DST)
        r = json.loads(raw)
        check("consume-batch 命中同步索引",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "外部演示已消费"})
        # 命中后仍不写审计（仍仅 1 条；fresh 消费在后面才发生）
        st, _, raw = get("/v1/audit?limit=200", headers=DST)
        actions2 = [e["action"] for e in json.loads(raw)["events"]]
        check("命中同步索引不写审计",
              actions2.count("trust.presentation.consumed") == 1)

        # 未同步的新 (issuer_did,presentation_id) 在目标租户仍可首次消费。
        fresh_pres, fresh_chal = make_presentation(
            issuer_priv, 901, presentation_id="vp_fresh_not_synced",
            challenge="chal-fresh")
        st, _, raw = post(CONSUME_PATH,
                          {"presentation": fresh_pres,
                           "challenge": fresh_chal}, DST)
        r = json.loads(raw)
        check("未同步键正常首次消费 200",
              st == 200 and r.get("valid") is True and r["consumption_id"])

        # ---------------------------------------------------------- #
        # 9. 租户隔离：他租户首次同步同内容仍 201
        # ---------------------------------------------------------- #
        st, _, _ = post(ANCHORS_PATH,
                        {"did": signer_did, "public_key": signer_pub,
                         "key_version": 1}, OTHER)
        assert st == 201, st
        nd_iso, _ = export_page(0, 2, s5)
        m_iso = manifest_page(0, 2, s5)
        st, _, raw = sync(m_iso, nd_iso, headers=OTHER)
        check("他租户首次同步独立 201",
              st == 201 and json.loads(raw)["count"] == 2)

        # ---------------------------------------------------------- #
        # 10. 并发同页只增一次（仅一个 201）
        # ---------------------------------------------------------- #
        conc_signer_priv, conc_signer_pub = _keypair()
        conc_signer = "did:web:conc-pres-signer.example"
        st, _, _ = post(ANCHORS_PATH,
                        {"did": conc_signer, "public_key": conc_signer_pub,
                         "key_version": 1}, DST)
        assert st == 201, st
        conc_nd = (
            json.dumps(
                {"cursor": 1, "consumption_id": "c" * 64,
                 "issuer_did": "did:web:conc-issuer.example",
                 "presentation_id": "vp_conc_1",
                 "consumed_at": "2099-01-01T00:00:00Z"},
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
              codes.count(201) == 1 and codes.count(200) == 15)

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
        # 重启后 consume 仍命中同步索引
        presentation1, challenge1 = consumed[0]
        st, _, raw = post(CONSUME_PATH,
                          {"presentation": presentation1,
                           "challenge": challenge1}, DST)
        check("重启后 consume 仍命中",
              json.loads(raw) == {"valid": False, "reason": "外部演示已消费"})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
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
    tenant = "rollback-pres-sync"
    signer = "did:web:rb-pres-signer.example"

    def row(cursor, pid):
        return {
            "cursor": cursor,
            "consumption_id": f"{cursor:064d}",
            "issuer_did": "did:web:rb-pres-issuer.example",
            "presentation_id": pid,
            "consumed_at": "2099-01-01T00:00:00Z",
        }

    events = [row(1, "vp_rb_1"), row(2, "vp_rb_2")]

    original_save = store._save_locked  # noqa: SLF001

    def boom():
        raise OSError("模拟磁盘已满")

    store._save_locked = boom  # type: ignore[assignment]  # noqa: SLF001
    try:
        try:
            store.sync_trust_presentation_consumptions(
                tenant, signer, 2, 0, events)
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
              for t, by_s in store._presentation_sync_checkpoints.items()  # noqa: SLF001
              for s in by_s])
    bucket = store._tenants.get(tenant, {})  # noqa: SLF001
    check("回滚后无同步事件",
          not bucket.get(
              "synced_trust_presentation_consumption_events", {}
          ).get(signer))
    check("回滚后无判重索引",
          not bucket.get("synced_trust_presentations"))
    check("回滚不写审计", all(
        e["tenant_id"] != tenant for e in store._audit))  # noqa: SLF001

    # 恢复后重试成功且为首次 201；再次调用为重放 200
    created, _, next_after, count = store.sync_trust_presentation_consumptions(
        tenant, signer, 2, 0, events)
    check("恢复后重试首次创建",
          created and next_after == 2 and count == 2)
    created2, _, _, count2 = (
        store.sync_trust_presentation_consumptions(
            tenant, signer, 2, 0, [dict(e) for e in events])
    )
    check("重试后同内容为幂等重放", (not created2) and count2 == 2)

    # consume 命中同步索引：返回 (False, None)，不写标记/审计
    consumed, _ = store.consume_trust_presentation(
        tenant, "did:web:rb-pres-issuer.example", "vp_rb_1", "x" * 64)
    check("consume 命中同步索引", consumed is False)

    # 磁盘文件未被失败写污染：重新加载得到同一检查点
    reloaded = VCStore(store.path)
    cp = reloaded._presentation_sync_checkpoints.get(  # noqa: SLF001
        tenant, {}).get(signer)
    check("重启加载检查点 (snapshot=2,after=2)",
          cp is not None and cp["snapshot"] == 2 and cp["after"] == 2
          and cp["last_after"] == 0
          and len(cp["digest"]) == 64)
    os.remove(store.path)
    return local_failures


if __name__ == "__main__":
    raise SystemExit(main())
