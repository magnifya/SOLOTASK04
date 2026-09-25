#!/usr/bin/env python3
"""GET /v1/trust/credentials/receipt/consumptions/export 确定性 NDJSON
快照导出端到端测试。

直接运行：python3 tests/trust_credential_receipt_consumptions_export_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/snapshot 三参数且不得重复，空值、未知参数、
  ASCII 整数/范围非法、snapshot 超过当前最大游标、after>snapshot 均 400
  且恰返 {"error": "非空中文原因"}；
- limit 缺省 1000、限 1–10000；snapshot 缺省为请求时租户最大 cursor
  （无事件为 0）；
- 成功 200：Content-Type application/x-ndjson; charset=utf-8，
  X-Snapshot-Cursor 为生效快照、X-Next-After 为末行 cursor（空为 after）；
- 每行键序 cursor、receipt_id、verifier_did、nonce、consumed_at，
  UTF-8 紧凑 JSON、非 ASCII 不转义、RFC8259 最短转义、LF 结行
  （末行亦有 LF）、无 BOM，空结果零字节；
- 同 snapshot 续页排除快照后新事件；
- 租户隔离、纯只读（不改游标/状态/审计）、跨重启字节一致。
"""

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


EXPORT_PATH = "/v1/trust/credentials/receipt/consumptions/export"
LIST_PATH = "/v1/trust/credentials/receipt/consumptions"
CONSUME_PATH = "/v1/trust/credentials/receipt/consume"
BATCH_PATH = "/v1/trust/credentials/receipt/consume-batch"
EVENT_KEYS = ["cursor", "receipt_id", "verifier_did", "nonce", "consumed_at"]


def main():
    port = 9023
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

    def export(query="", headers=None):
        url = f"{base}{EXPORT_PATH}?{query}" if query else base + EXPORT_PATH
        return _http_raw(url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "rcpt-a"}
        TB = {"X-Tenant-ID": "rcpt-b"}

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
        # 无事件缺省快照为 0，after 不得大于 snapshot，故 after=7 为 400；
        # after=0 空页 X-Next-After 保持 0。
        st, hd, body = export("after=0", headers=TA)
        check("无事件 after=0 空结果 X-Next-After 保持 0",
              st == 200 and body == b"" and hd.get("X-Next-After") == "0"
              and hd.get("X-Snapshot-Cursor") == "0")

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且恰返非空中文 error
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, _, raw = export(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error 非空中文: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

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
        expect_400("snapshot 超过当前最大值(无事件)", "snapshot=1")
        expect_400("无事件 after>snapshot(缺省0)", "after=1")
        expect_400("显式空 X-Tenant-ID", "", headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 3. 准备锚点与回执消费（含非 ASCII nonce 与特殊转义字符）
        # ---------------------------------------------------------- #
        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:issuer-exp.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": issuer_did, "public_key": issuer_pub,
                       "key_version": 1}, headers=TA)
        assert st == 201
        va = "did:web:verifier-a-exp.example"
        vb = "did:web:verifier-b-exp.example"
        va_priv, va_pub = _keypair()
        vb_priv, vb_pub = _keypair()
        for did, pub in ((va, va_pub), (vb, vb_pub)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub, "key_version": 1},
                          headers=TA)
            assert st == 201

        def make_body(cid, claim="管理员"):
            return {
                "credential_id": cid,
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject-exp.example",
                "claims": {"role": claim},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }

        def make_item(cid, verifier, v_priv, nonce):
            b = make_body(cid)
            s = crypto.sign(b, issuer_priv)
            rcpt = {
                "credential_id": b["credential_id"],
                "issuer_did": b["issuer_did"],
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": b, "signature": s})
                ).hexdigest(),
                "verifier_did": verifier,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            rs = crypto.sign(rcpt, v_priv)
            return {"receipt": rcpt, "receipt_signature": rs,
                    "body": b, "signature": s, "nonce": nonce}

        def receipt_id_of(item):
            return hashlib.sha256(
                crypto.canonicalize(item["receipt"])
            ).hexdigest()

        # 接受顺序 item1, item2, item3（批量内两项）；nonce 覆盖中文、
        # 引号、反斜杠、换行、制表符
        item1 = make_item("vc_e_0001", va, va_priv, "n-中文-1")
        item2 = make_item("vc_e_0002", vb, vb_priv,
                          'n-"引号"\\反斜杠\n换行\t制表')
        item3 = make_item("vc_e_0003", va, va_priv, "n-3")
        item4 = make_item("vc_e_0004", vb, vb_priv, "n-4")
        st, r = _http("POST", f"{base}{CONSUME_PATH}", item1, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, r = _http("POST", f"{base}{CONSUME_PATH}", item2, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"items": [item3, item4]}, headers=TA)
        assert st == 200 and [x.get("valid") for x in r["results"]] == [
            True, True
        ], r

        want_ids = [receipt_id_of(x) for x in (item1, item2, item3, item4)]

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
                  and isinstance(e["receipt_id"], str)
                  and isinstance(e["verifier_did"], str)
                  and isinstance(e["nonce"], str)
                  and isinstance(e["consumed_at"], str)
                  for e in events))
        check("cursor 按消费顺序升序 1..4",
              [e["cursor"] for e in events] == [1, 2, 3, 4])
        check("receipt_id 依次匹配",
              [e["receipt_id"] for e in events] == want_ids)
        check("验证者依次为 A,B,A,B",
              [e["verifier_did"] for e in events] == [va, vb, va, vb])
        check("nonce 依次匹配",
              [e["nonce"] for e in events]
              == [item1["nonce"], item2["nonce"], "n-3", "n-4"])
        check("非 ASCII 不转义",
              "n-中文-1".encode("utf-8") in raw and b"\\u" not in raw)
        check("字符串按 RFC8259 最短转义",
              'n-\\"引号\\"\\\\反斜杠\\n换行\\t制表'.encode("utf-8") in raw)
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

        # 同 snapshot 续页排除快照后新事件
        st, hd, raw = export("limit=2", headers=TA)
        snap = hd["X-Snapshot-Cursor"]
        check("续传首页快照=4", snap == "4")
        # 快照后新增一条消费（cursor=5）
        item5 = make_item("vc_e_0005", va, va_priv, "n-5")
        st, r = _http("POST", f"{base}{CONSUME_PATH}", item5, headers=TA)
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
        # 租户 B 独立锚点并消费同 nonce
        iss_b_priv, iss_b_pub = _keypair()
        iss_b = "did:web:issuer-b.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": iss_b, "public_key": iss_b_pub,
                       "key_version": 1}, headers=TB)
        assert st == 201
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": va, "public_key": va_pub, "key_version": 1},
                      headers=TB)
        assert st == 201
        # 租户 B 的发行者与验证者均在租户 B 注册锚点
        body_b = {
            "credential_id": "vc_e_0001",
            "issuer_did": iss_b,
            "subject_did": "did:web:subject-exp.example",
            "claims": {"role": "租户B"},
            "issued_at": "2026-09-22T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig_b = crypto.sign(body_b, iss_b_priv)
        rcpt_b = {
            "credential_id": body_b["credential_id"],
            "issuer_did": body_b["issuer_did"],
            "issuer_key_version": 1,
            "credential_digest": hashlib.sha256(
                crypto.canonicalize({"body": body_b, "signature": sig_b})
            ).hexdigest(),
            "verifier_did": va,
            "verifier_key_version": 1,
            "nonce": "租户B-nonce",
        }
        b_item = {
            "receipt": rcpt_b,
            "receipt_signature": crypto.sign(rcpt_b, va_priv),
            "body": body_b,
            "signature": sig_b,
            "nonce": "租户B-nonce",
        }
        st, r = _http("POST", f"{base}{CONSUME_PATH}", b_item, headers=TB)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(headers=TB)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("他租户游标自 1 计起",
              [(e["cursor"], e["verifier_did"], e["nonce"]) for e in ev]
              == [(1, va, "租户B-nonce")]
              and hd.get("X-Snapshot-Cursor") == "1")
        st, hd, raw = export(headers=TA)
        check("租户 A 不受影响（仍 5 条）",
              raw.count(b"\n") == 5 and hd.get("X-Snapshot-Cursor") == "5")

        # ---------------------------------------------------------- #
        # 7. 纯只读：导出不改游标、状态与审计
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
        # 前 4 条字节与重启前完全一致
        head4 = b"".join(raw.splitlines(keepends=True)[:4])
        check("重启后前 4 条字节一致", head4 == full_export_bytes)
        st, hd, raw = export("snapshot=4", headers=TA)
        check("重启后旧快照仍可用且排除 cursor=5",
              st == 200 and raw == full_export_bytes
              and hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4")
        st, hd, raw = export(headers=TB)
        check("重启后租户 B 导出稳定",
              raw.count(b"\n") == 1 and hd.get("X-Snapshot-Cursor") == "1")

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
