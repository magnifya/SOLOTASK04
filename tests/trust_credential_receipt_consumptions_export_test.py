#!/usr/bin/env python3
"""GET /v1/trust/credentials/receipt/consumptions/export 端到端测试。

直接运行：python3 tests/trust_credential_receipt_consumptions_export_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 仅允许 limit/after/snapshot 三参数且不得重复，空值、未知参数、
  ASCII 整数/范围非法、snapshot 超过当前最大游标、after>snapshot 均 400
  且恰返 {"error": "非空中文原因"}；
- limit 缺省 1000、限 1–10000；after 缺省 0；snapshot 缺省为请求时
  租户最大 cursor（无事件为 0）；
- 成功 200：Content-Type application/x-ndjson; charset=utf-8，
  X-Snapshot-Cursor 为生效快照、X-Next-After 为末行 cursor（空为 after）；
- 每行键序 cursor、receipt_id、verifier_did、nonce、consumed_at，
  UTF-8 紧凑 JSON、非 ASCII 不转义、RFC8259 最短转义、LF 结行（末行亦有
  LF）、无 BOM，空结果零字节；
- 同 snapshot 续页排除快照后新消费；租户隔离、显式空 X-Tenant-ID 400；
- 纯只读（不改游标/状态/审计）、跨重启字节一致。
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
EVENT_KEYS = ["cursor", "receipt_id", "verifier_did", "nonce", "consumed_at"]


def main():
    port = 9017
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

    def expect_400(name, query, headers=None):
        st, _, raw = export(query, headers=headers)
        try:
            r = json.loads(raw.decode() or "{}")
        except ValueError:
            r = {}
        check(f"400 仅 error 非空中文: {name}",
              st == 400 and list(r.keys()) == ["error"]
              and isinstance(r["error"], str) and bool(r["error"]))

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
        # 无事件时快照为 0，after<=snapshot 约束下 after>0 一律 400
        expect_400("无事件 after=7 超过缺省 snapshot=0", "after=7")
        st, hd, body = export("after=0", headers=TA)
        check("无事件 after=0 空结果 X-Next-After 保持 0",
              st == 200 and body == b"" and hd.get("X-Next-After") == "0"
              and hd.get("X-Snapshot-Cursor") == "0")

        # ---------------------------------------------------------- #
        # 2. 参数非法 -> 400 且恰返非空中文 error
        # ---------------------------------------------------------- #
        expect_400("未知参数", "unknown=1")
        expect_400("未知参数 verifier_did", "verifier_did=did:x")
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
        expect_400("after>snapshot(显式)", "after=2&snapshot=1")
        expect_400("after>snapshot(无事件)", "after=1&snapshot=0")
        expect_400("显式空 X-Tenant-ID", "", headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 3. 准备锚点与消费事件（nonce 含非 ASCII 与最短转义字符）
        # ---------------------------------------------------------- #
        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:issuer-exp.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": issuer_did, "public_key": issuer_pub,
                       "key_version": 1}, headers=TA)
        assert st == 201

        verifier_a = "did:web:verifier-exp-a.example"
        va_priv, va_pub = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": verifier_a, "public_key": va_pub,
                       "key_version": 1}, headers=TA)
        assert st == 201
        verifier_b = "did:web:verifier-exp-b.example"
        vb_priv, vb_pub = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": verifier_b, "public_key": vb_pub,
                       "key_version": 1}, headers=TA)
        assert st == 201

        def make_item(cid, verifier, v_priv, nonce):
            b = {
                "credential_id": cid,
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin"},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
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

        nonce_special = '含"引号"与\\反斜杠\n换行\t制表'
        item1 = make_item("vc_e_0001", verifier_a, va_priv, nonce_special)
        item2 = make_item("vc_e_0002", verifier_b, vb_priv, "n-2")
        item3 = make_item("vc_e_0003", verifier_a, va_priv, "n-3")
        for item in (item1, item2, item3):
            st, r = _http("POST", f"{base}{CONSUME_PATH}", item, headers=TA)
            assert st == 200 and r.get("valid") is True, r

        want_ids = [receipt_id_of(x) for x in (item1, item2, item3)]

        # ---------------------------------------------------------- #
        # 4. 全量导出：字节级形状
        # ---------------------------------------------------------- #
        st, hd, raw = export(headers=TA)
        check("导出 200 且 Content-Type 正确",
              st == 200
              and hd.get("Content-Type")
              == "application/x-ndjson; charset=utf-8")
        check("快照头为最大 cursor、next_after 为末行 cursor",
              hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
        check("无 BOM", not raw.startswith(b"\xef\xbb\xbf"))
        check("LF 结行且末行亦有 LF",
              raw.endswith(b"\n") and b"\r" not in raw
              and raw.count(b"\n") == 3)
        lines = raw.decode("utf-8").split("\n")[:-1]
        check("三行均为紧凑 JSON（无空格）",
              all(", " not in line and ": " not in line for line in lines))
        events = [json.loads(line) for line in lines]
        check("行键序固定",
              all(list(e.keys()) == EVENT_KEYS for e in events))
        check("cursor 为正整数，其余为字符串",
              all(type(e["cursor"]) is int and e["cursor"] >= 1
                  and all(isinstance(e[k], str) for k in EVENT_KEYS[1:])
                  for e in events))
        check("cursor 按消费顺序升序 1..3",
              [e["cursor"] for e in events] == [1, 2, 3])
        check("receipt_id 依次匹配",
              [e["receipt_id"] for e in events] == want_ids)
        check("验证者依次为 A,B,A",
              [e["verifier_did"] for e in events]
              == [verifier_a, verifier_b, verifier_a])
        check("nonce 依次匹配",
              [e["nonce"] for e in events]
              == [nonce_special, "n-2", "n-3"])
        check("非 ASCII 不转义",
              "含".encode("utf-8") in raw and b"\\u" not in raw)
        check("字符串按 RFC8259 最短转义",
              '\\"引号\\"与\\\\反斜杠\\n换行\\t制表'.encode("utf-8") in raw)
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
              and hd.get("X-Snapshot-Cursor") == "3")
        st, hd, raw = export("limit=2&after=2", headers=TA)
        page2 = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("after=2 第二页",
              [e["cursor"] for e in page2] == [3]
              and hd.get("X-Next-After") == "3")
        st, hd, raw = export("after=3", headers=TA)
        check("after=末游标空结果零字节且 X-Next-After=after",
              st == 200 and raw == b"" and hd.get("X-Next-After") == "3"
              and hd.get("X-Snapshot-Cursor") == "3")
        expect_400("有事件后 after>缺省 snapshot", "after=4")

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
        expect_400("snapshot 超过当前最大值", "snapshot=4")
        expect_400("snapshot 远超当前最大值", "snapshot=999999")
        expect_400("after>snapshot(显式有事件)", "after=3&snapshot=2")
        expect_400("after=snapshot+? 首页越界", "snapshot=1&after=2")

        # 同 snapshot 续页排除快照后新消费
        st, hd, raw = export("limit=2", headers=TA)
        snap = hd["X-Snapshot-Cursor"]
        check("续传首页快照=3", snap == "3")
        item4 = make_item("vc_e_0004", verifier_b, vb_priv, "n-4")
        st, r = _http("POST", f"{base}{CONSUME_PATH}", item4, headers=TA)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(f"snapshot={snap}&after=2", headers=TA)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("同 snapshot 续页排除后续消费",
              st == 200 and [e["cursor"] for e in ev] == [3]
              and hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
        st, hd, raw = export(headers=TA)
        check("新请求缺省快照读到新最大值 4",
              hd.get("X-Snapshot-Cursor") == "4"
              and hd.get("X-Next-After") == "4"
              and raw.count(b"\n") == 4)
        expect_400("snapshot 超过新最大值", "snapshot=5")

        # 重放不产生新事件，导出不变
        st, _ = _http("POST", f"{base}{CONSUME_PATH}", item1, headers=TA)
        st, hd, raw = export(headers=TA)
        check("重放后导出仍为 4 行",
              raw.count(b"\n") == 4 and hd.get("X-Snapshot-Cursor") == "4")

        # limit 上限边界
        st, hd, raw = export("limit=10000", headers=TA)
        check("limit=10000 合法",
              st == 200 and raw.count(b"\n") == 4)

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
        # 租户 B 注册自己的同名验证者并消费同 nonce
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": verifier_a, "public_key": va_pub,
                       "key_version": 1}, headers=TB)
        assert st == 201
        other = make_item("vc_e_0001", verifier_a, va_priv, nonce_special)
        st, r = _http("POST", f"{base}{CONSUME_PATH}", other, headers=TB)
        assert st == 200 and r.get("valid") is True, r
        st, hd, raw = export(headers=TB)
        ev = [json.loads(x) for x in raw.decode().split("\n")[:-1]]
        check("他租户游标自 1 计起",
              len(ev) == 1 and ev[0]["cursor"] == 1
              and ev[0]["verifier_did"] == verifier_a
              and hd.get("X-Snapshot-Cursor") == "1"
              and hd.get("X-Next-After") == "1")
        st, hd, raw = export(headers=TA)
        check("租户 A 不受影响（仍 4 条）",
              raw.count(b"\n") == 4 and hd.get("X-Snapshot-Cursor") == "4")

        # ---------------------------------------------------------- #
        # 7. 纯只读：导出不改游标、状态与审计
        # ---------------------------------------------------------- #
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=TA)
        st, hd, raw = export(headers=TA)
        st, hd2, raw2 = export(headers=TA)
        check("重复导出字节一致",
              raw == raw2
              and hd.get("X-Snapshot-Cursor") == hd2.get("X-Snapshot-Cursor")
              and hd.get("X-Next-After") == hd2.get("X-Next-After"))
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=TA)
        check("导出不记审计", audit_before == audit_after)
        st, r = _http("GET", f"{base}{LIST_PATH}?limit=200", headers=TA)
        check("导出不改游标与事件",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4]
              and r["next_after"] == 4)

        # ---------------------------------------------------------- #
        # 8. 跨重启字节一致
        # ---------------------------------------------------------- #
        # 重启前的全量导出字节（4 行）作为期望基准。
        full_4_bytes = raw

        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, hd, raw = export(headers=TA)
        check("重启后全量导出字节一致",
              st == 200 and raw == full_4_bytes
              and hd.get("X-Snapshot-Cursor") == "4")
        st, hd, raw = export("snapshot=3", headers=TA)
        check("重启后旧快照仍可用且排除 cursor=4",
              st == 200 and raw == full_export_bytes
              and hd.get("X-Snapshot-Cursor") == "3"
              and hd.get("X-Next-After") == "3")
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
