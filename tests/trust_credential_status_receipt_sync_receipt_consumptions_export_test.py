#!/usr/bin/env python3
"""GET /v1/trust/credential-status/receipt-sync/receipt/consumptions/export
确定性 NDJSON 快照导出端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consumptions_export_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/snapshot 三参数且不得重复，空值、未知参数、
  ASCII 整数/范围非法、snapshot 超过当前最大游标、after>snapshot 均 400
  且恰返 {"error": "请求非法"}；
- limit 缺省 1000、限 1–10000；snapshot 缺省为请求时租户最大 cursor
  （无事件为 0）；
- 成功 200：Content-Type application/x-ndjson; charset=utf-8，
  X-Snapshot-Cursor 为生效快照、X-Next-After 为末行 cursor（空为 after）；
- 每行键序 cursor、receipt_id、verifier_did、nonce、consumed_at，
  UTF-8 紧凑 JSON、非 ASCII 不转义、RFC8259 最短转义、LF 结行
  （末行亦有 LF）、无 BOM，空结果零字节；
- 同 snapshot 续页排除快照后新消费；
- 租户隔离、缺省 default 租户、纯只读（不改消费/游标/状态/审计）、
  跨重启字节一致。
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


def _http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _http_raw(url, headers=None):
    """GET 并返回 (status, 响应头, 原始字节)，不解析 JSON。"""
    req = urllib.request.Request(url, method="GET")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read()


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


SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt-sync/receipt"
EXPORT_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consumptions/export"
)
LIST_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consumptions"
)
CONSUME_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume"
)
BATCH_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume-batch"
)
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"
EVENT_KEYS = ["cursor", "receipt_id", "verifier_did", "nonce", "consumed_at"]

ROW_VERIFIER_DID = "did:web:cssync-exp-row-signer.example"


def _make_row(cursor, index):
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-cssync-exp-{index:055d}",
        "verifier_did": ROW_VERIFIER_DID,
        "nonce": f"cssync-exp-row-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def _to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9026
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def post(path, payload=None, headers=None):
        return _http("POST", base + path, payload=payload, headers=headers)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    def export(query="", headers=None):
        url = f"{base}{EXPORT_PATH}?{query}" if query else base + EXPORT_PATH
        return _http_raw(url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "cssync-exp-a"}
        TB = {"X-Tenant-ID": "cssync-exp-b"}

        # ---------------------------------------------------------- #
        # 1. 无事件：200 零字节，快照 0，X-Next-After=after
        # ---------------------------------------------------------- #
        st, hd, body = export(headers=TA)
        check("无事件 200 零字节",
              st == 200 and body == b"")
        check("无事件 Content-Type",
              hd.get("Content-Type") == "application/x-ndjson; charset=utf-8")
        check("无事件快照头为 0、next_after=after(0)",
              hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        st, hd, body = export("after=0", headers=TA)
        check("无事件 after=0 空结果 X-Next-After 保持 0",
              st == 200 and body == b"" and hd.get("X-Next-After") == "0"
              and hd.get("X-Snapshot-Cursor") == "0")

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且恰返 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, _, raw = export(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 恰为 error 请求非法: {name}",
                  st == 400 and r == {"error": "请求非法"})

        expect_400("未知参数", "unknown=1")
        expect_400("verifier_did 不被允许", "verifier_did=did:web:x")
        expect_400("limit 空值", "limit=")
        expect_400("limit 重复", "limit=1&limit=2")
        expect_400("limit=0", "limit=0")
        expect_400("limit=10001", "limit=10001")
        expect_400("limit 字母", "limit=abc")
        expect_400("limit 小数", "limit=1.5")
        expect_400("limit 符号", "limit=%2B1")
        expect_400("limit 布尔", "limit=true")
        expect_400("limit 空白", "limit=%20")
        expect_400("limit Unicode 数字", "limit=%E0%A9%91")
        expect_400("after 空值", "after=")
        expect_400("after 负数", "after=-1")
        expect_400("after 小数", "after=1.0")
        expect_400("after 布尔", "after=true")
        expect_400("after 重复", "after=0&after=1")
        expect_400("snapshot 空值", "snapshot=")
        expect_400("snapshot 负数", "snapshot=-1")
        expect_400("snapshot 小数", "snapshot=1.0")
        expect_400("snapshot 布尔", "snapshot=true")
        expect_400("snapshot 空白", "snapshot=%20")
        expect_400("snapshot Unicode 数字", "snapshot=%E0%A9%91")
        expect_400("snapshot 重复", "snapshot=0&snapshot=1")
        expect_400("snapshot 超过当前最大游标(无事件)", "snapshot=1")
        expect_400("无事件 after>snapshot(缺省0)", "after=1")
        expect_400("after 超长数字串", "after=" + "1" * 5000)
        expect_400("snapshot 超长数字串", "snapshot=" + "9" * 5000)
        st, _, raw = export("", headers={"X-Tenant-ID": ""})
        try:
            r = json.loads(raw.decode() or "{}")
        except ValueError:
            r = {}
        check("显式空 X-Tenant-ID -> 400 且仅 error",
              st == 400 and r == {"error": "X-Tenant-ID 不能为空"})

        # ---------------------------------------------------------- #
        # 3. 准备同步来源与本地验证者，并消费同步进度回执
        # ---------------------------------------------------------- #
        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:cssync-exp-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, TA)
        assert st in (200, 201), st

        def _signed_manifest(snapshot, after, ndjson):
            manifest = {
                "snapshot": snapshot,
                "filters": {"after": after, "limit": 1000},
                "count": ndjson.count("\n"),
                "alg": "SHA-256",
                "digest": hashlib.sha256(ndjson.encode("utf-8")).hexdigest(),
                "signer_did": signer_did,
                "key_version": 1,
            }
            manifest["signature"] = crypto.sign(
                {k: manifest[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return manifest

        def _sync_page(cursors):
            rows = [_make_row(c, c) for c in cursors]
            ndjson = _to_ndjson(rows)
            st, r = post(SYNC_PATH,
                         {"manifest": _signed_manifest(
                             cursors[-1], 0, ndjson),
                          "ndjson": ndjson}, TA)
            assert st in (200, 201), (st, r)
            return ndjson

        ndjson1 = _sync_page([1, 2, 3])

        verifiers = []
        for handle in ("cssync-exp-verifier-a", "cssync-exp-verifier-b"):
            st, rec = post(DIDS_PATH,
                           {"method": "web", "public_key": handle}, TA)
            assert st == 201, (st, rec)
            v_did = rec["did"]
            st, _ = post(ANCHORS_PATH,
                         {"did": v_did, "public_key": rec["public_key"],
                          "key_version": rec["key_version"],
                          "uses": ["generic", "status"]}, TA)
            assert st in (200, 201), st
            verifiers.append(v_did)
        va, vb = verifiers

        def make_item(verifier, nonce):
            qs = urllib.parse.urlencode(
                {"signer_did": signer_did, "verifier_did": verifier,
                 "nonce": nonce})
            st, issued = get(f"{RECEIPT_PATH}?{qs}", headers=TA)
            assert st == 200, (st, issued)
            return {"receipt": issued["receipt"],
                    "signature": issued["signature"],
                    "ndjson": ndjson1, "nonce": nonce}

        def receipt_id_of(item):
            return hashlib.sha256(
                crypto.canonicalize(item["receipt"])
            ).hexdigest()

        # 接受顺序 item1, item2, item3, item4（末两项走批量入口）；
        # nonce 覆盖中文、引号、反斜杠、换行、制表符
        item1 = make_item(va, "n-中文-1")
        item2 = make_item(vb, 'n-"引号"\\反斜杠\n换行\t制表')
        item3 = make_item(va, "n-3")
        item4 = make_item(vb, "n-4")
        st, r = post(CONSUME_PATH, item1, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, r = post(CONSUME_PATH, item2, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, r = post(BATCH_PATH, {"items": [item3, item4]}, headers=TA)
        assert st == 200 and [x.get("valid") for x in r["results"]] == [
            True, True
        ], r

        want_items = [item1, item2, item3, item4]
        want_ids = [receipt_id_of(x) for x in want_items]
        want_nonces = [x["nonce"] for x in want_items]

        # ---------------------------------------------------------- #
        # 4. 全量导出：字节级形状
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TA)
        check("导出 200 且 Content-Type 正确",
              st == 200
              and hd.get("Content-Type")
              == "application/x-ndjson; charset=utf-8")
        check("快照头为最大 cursor、next_after 为末行 cursor",
              hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4")
        check("无 BOM", not raw.startswith(b"\xef\xbb\xbf"))
        check("LF 结行且末行亦有 LF",
              raw.endswith(b"\n") and b"\r" not in raw
              and raw.count(b"\n") == 4)
        lines = raw.decode("utf-8").split("\n")[:-1]
        check("四行均为紧凑 JSON（无空格）",
              all(", " not in line and ": " not in line for line in lines))
        events = [json.loads(line) for line in lines]
        check("行键序固定",
              all(list(e.keys()) == EVENT_KEYS for e in events))
        check("行类型正确",
              all(type(e["cursor"]) is int
                  and e["cursor"] > 0
                  and isinstance(e["receipt_id"], str)
                  and bool(e["receipt_id"])
                  and isinstance(e["verifier_did"], str)
                  and bool(e["verifier_did"])
                  and isinstance(e["nonce"], str)
                  and bool(e["nonce"])
                  and isinstance(e["consumed_at"], str)
                  and bool(e["consumed_at"])
                  for e in events))
        check("cursor 按消费顺序升序 1..4",
              [e["cursor"] for e in events] == [1, 2, 3, 4])
        check("receipt_id 依次匹配",
              [e["receipt_id"] for e in events] == want_ids)
        check("验证者依次为 A,B,A,B",
              [e["verifier_did"] for e in events] == [va, vb, va, vb])
        check("nonce 依次匹配",
              [e["nonce"] for e in events] == want_nonces)
        check("consumed_at 为 UTC 秒精度 Z",
              all(e["consumed_at"].endswith("Z")
                  and len(e["consumed_at"]) == 20
                  and e["consumed_at"][4] == "-"
                  for e in events))
        check("非 ASCII 不转义",
              "n-中文-1".encode("utf-8") in raw and b"\\u" not in raw)
        check("字符串按 RFC8259 最短转义",
              'n-\\"引号\\"\\\\反斜杠\\n换行\\t制表'.encode("utf-8")
              in raw)
        full_export_bytes = raw

        # 与查询端点同事件内容一致
        st, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        check("与查询端点事件一致",
              st == 200 and r["events"] == events)

        # ---------------------------------------------------------- #
        # 5. 分页与快照续传
        # ---------------------------------------------------------- #
        st, hd, raw = export("limit=2", headers=TA)
        page1 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("limit=2 首页",
              st == 200 and [e["cursor"] for e in page1] == [1, 2]
              and hd.get("X-Next-After") == "2"
              and hd.get("X-Snapshot-Cursor") == "4")
        st, hd, raw = export("limit=2&after=2", headers=TA)
        page2 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("after=2 第二页",
              [e["cursor"] for e in page2] == [3, 4]
              and hd.get("X-Next-After") == "4")
        st, hd, raw = export("after=4", headers=TA)
        check("after=末游标空结果零字节且 X-Next-After=after",
              st == 200 and raw == b"" and hd.get("X-Next-After") == "4"
              and hd.get("X-Snapshot-Cursor") == "4")

        # 显式 snapshot 合法：等于/小于最大值
        st, hd, raw = export("snapshot=2", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("显式 snapshot=2 仅含 cursor<=2",
              st == 200 and [e["cursor"] for e in ev] == [1, 2]
              and hd.get("X-Snapshot-Cursor") == "2"
              and hd.get("X-Next-After") == "2")
        st, hd, raw = export("snapshot=0", headers=TA)
        check("显式 snapshot=0 空结果",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        expect_400("snapshot 超过当前最大值", "snapshot=5")
        expect_400("snapshot 远超当前最大值", "snapshot=999999")
        expect_400("after 大于显式 snapshot", "after=3&snapshot=2")
        expect_400("after 等于 snapshot+1", "after=5")

        # 同 snapshot 续页排除快照后新消费
        st, hd, raw = export("limit=2", headers=TA)
        snap = hd["X-Snapshot-Cursor"]
        check("续传首页快照=4", snap == "4")
        item5 = make_item(va, "n-5")
        st, r = post(CONSUME_PATH, item5, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(f"snapshot={snap}&after=2", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("同 snapshot 续页排除后续消费",
              st == 200 and [e["cursor"] for e in ev] == [3, 4]
              and hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4")
        st, hd, raw = export(headers=TA)
        check("新请求缺省快照读到新最大值 5",
              hd.get("X-Snapshot-Cursor") == "5"
              and hd.get("X-Next-After") == "5"
              and raw.count(b"\n") == 5)
        expect_400("snapshot 超过新最大值", "snapshot=6")

        # ---------------------------------------------------------- #
        # 6. 租户隔离与缺省租户
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TB)
        check("他租户不可见（零字节、快照 0）",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0"
              and hd.get("X-Next-After") == "0")
        st, hd, raw = export()
        check("缺省 default 租户零字节",
              st == 200 and raw == b"" and hd.get("X-Snapshot-Cursor") == "0")

        # 租户 B 独立同步来源、验证者并消费
        b_signer_priv, b_signer_pub = _keypair()
        b_signer_did = "did:web:cssync-exp-signer-b.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": b_signer_did, "public_key": b_signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, TB)
        assert st in (200, 201), st
        b_rows = [_make_row(1, 1)]
        b_ndjson = _to_ndjson(b_rows)
        st, _ = post(SYNC_PATH,
                     {"manifest": {
                         "snapshot": 1,
                         "filters": {"after": 0, "limit": 1000},
                         "count": 1,
                         "alg": "SHA-256",
                         "digest": hashlib.sha256(
                             b_ndjson.encode("utf-8")).hexdigest(),
                         "signer_did": b_signer_did,
                         "key_version": 1,
                         "signature": crypto.sign({
                             "snapshot": 1,
                             "filters": {"after": 0, "limit": 1000},
                             "count": 1,
                             "alg": "SHA-256",
                             "digest": hashlib.sha256(
                                 b_ndjson.encode("utf-8")).hexdigest(),
                             "signer_did": b_signer_did,
                             "key_version": 1,
                         }, b_signer_priv)},
                      "ndjson": b_ndjson}, TB)
        assert st in (200, 201), st
        st, rec = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "cssync-exp-verifier-a"}, TB)
        assert st == 201, st
        bv_did = rec["did"]
        st, _ = post(ANCHORS_PATH,
                     {"did": bv_did, "public_key": rec["public_key"],
                      "key_version": rec["key_version"],
                      "uses": ["generic", "status"]}, TB)
        assert st in (200, 201), st
        qs = urllib.parse.urlencode(
            {"signer_did": b_signer_did, "verifier_did": bv_did,
             "nonce": "租户B-nonce"})
        st, issued = get(f"{RECEIPT_PATH}?{qs}", headers=TB)
        assert st == 200, (st, issued)
        b_item = {"receipt": issued["receipt"],
                  "signature": issued["signature"],
                  "ndjson": b_ndjson, "nonce": "租户B-nonce"}
        st, r = post(CONSUME_PATH, b_item, headers=TB)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(headers=TB)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("他租户游标自 1 计起",
              [(e["cursor"], e["verifier_did"], e["nonce"]) for e in ev]
              == [(1, bv_did, "租户B-nonce")]
              and hd.get("X-Snapshot-Cursor") == "1"
              and hd.get("X-Next-After") == "1")
        st, hd, raw = export(headers=TA)
        check("租户 A 不受影响（仍 5 条）",
              raw.count(b"\n") == 5 and hd.get("X-Snapshot-Cursor") == "5")

        # ---------------------------------------------------------- #
        # 7. 纯只读：导出不改消费、游标、状态与审计
        # ---------------------------------------------------------- #
        st, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        st, hd, raw = export(headers=TA)
        full_export_bytes_5 = raw
        st, hd2, raw2 = export(headers=TA)
        check("重复导出字节一致",
              raw == raw2
              and hd.get("X-Snapshot-Cursor") == hd2.get("X-Snapshot-Cursor")
              and hd.get("X-Next-After") == hd2.get("X-Next-After"))
        st, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("导出不记审计", audit_before == audit_after)
        st, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        check("导出不改游标与事件",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4, 5]
              and r["next_after"] == 5)
        # 重放仍被判为已消费（导出未改消费标记）
        st, r = post(CONSUME_PATH, item1, headers=TA)
        check("导出后重放仍为状态同步回执已消费",
              st == 200 and r == {"valid": False, "reason": "状态同步回执已消费"})

        # 游标空间独立于普通凭证状态回执消费历史导出
        st, hd, raw = _http_raw(
            base + "/v1/trust/credential-status/receipt/consumptions/export",
            headers=TA)
        check("普通凭证状态回执消费导出为空（游标空间隔离）",
              st == 200 and raw == b""
              and hd.get("X-Snapshot-Cursor") == "0")

        # ---------------------------------------------------------- #
        # 8. 跨重启字节一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, hd, raw = export(headers=TA)
        check("重启后全量导出字节一致",
              st == 200 and raw == full_export_bytes_5
              and hd.get("X-Snapshot-Cursor") == "5"
              and hd.get("X-Next-After") == "5")
        st2, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        exported = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("重启后导出与查询事件一致",
              st2 == 200 and exported == r["events"])
        head4 = b"".join(raw.splitlines(keepends=True)[:4])
        check("重启后前 4 条字节一致", head4 == full_export_bytes)
        st, hd, raw = export("snapshot=4", headers=TA)
        check("重启后旧快照仍可用且排除 cursor=5",
              st == 200 and raw == full_export_bytes
              and hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4")
        st, hd, raw = export(headers=TB)
        check("重启后租户 B 导出稳定",
              raw.count(b"\n") == 1 and hd.get("X-Snapshot-Cursor") == "1"
              and hd.get("X-Next-After") == "1")

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store):
            os.remove(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
