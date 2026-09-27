#!/usr/bin/env python3
"""只读消费历史 GET /v1/trust/credential-status/receipt/consumptions
的端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_consumptions_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
import socket
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

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

LIST_PATH = "/v1/trust/credential-status/receipt/consumptions"
CONSUME_PATH = "/v1/trust/credential-status/receipt/consume"
BATCH_PATH = "/v1/trust/credential-status/receipt/consume-batch"
ANCHORS_PATH = "/v1/trust/anchors"


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is None:
        data = json.dumps(payload).encode() if payload is not None else None
    else:
        data = raw
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def gen_keypair():
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


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def main():
    port = 8989
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def listing(qs="", headers=None):
        return _http("GET", f"{base}{LIST_PATH}{qs}", headers=headers)

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    def consumed_audits(headers):
        return [e for e in audit_events(headers)
                if e["action"]
                == "trust.credential.status.receipt.consumed"]

    def expect_400(name, qs="", headers=None):
        st, r = listing(qs, headers=headers)
        check(name,
              st == 400 and r == {"error": "请求非法"})

    def raw_get(path):
        """用原始 socket 发 GET（urllib 会丢弃空值头）。"""
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(
            b"GET " + path.encode() + b" HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nX-Tenant-ID: \r\n"
            b"Connection: close\r\n\r\n"
        )
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        status_line, rest = data.split(b"\r\n", 1)
        body = json.loads(rest.split(b"\r\n\r\n", 1)[1].decode())
        return int(status_line.split()[1]), body

    try:
        T1 = {"X-Tenant-ID": "csr-hist-a"}
        T2 = {"X-Tenant-ID": "csr-hist-b"}

        # 空历史：200 恰返 events、next_after
        st, r = listing(headers=T1)
        check("空历史 -> 200", st == 200)
        check("空历史键序恰为 events,next_after 且空页 next_after=0",
              list(r.keys()) == ["events", "next_after"]
              and r["events"] == [] and r["next_after"] == 0)

        # 查询参数非法 -> 400 恰返 {"error":"请求非法"}
        expect_400("未知参数 -> 400", "?foo=1")
        expect_400("重复 limit -> 400", "?limit=1&limit=2")
        expect_400("重复 after -> 400", "?after=0&after=1")
        expect_400("重复 verifier_did -> 400",
                   "?verifier_did=a&verifier_did=b")
        expect_400("空 limit -> 400", "?limit=")
        expect_400("空 after -> 400", "?after=")
        expect_400("空 verifier_did -> 400", "?verifier_did=")
        expect_400("limit=0 -> 400", "?limit=0")
        expect_400("limit=201 -> 400", "?limit=201")
        expect_400("limit=-1 -> 400", "?limit=-1")
        expect_400("limit=1.0 -> 400", "?limit=1.0")
        expect_400("limit=true -> 400", "?limit=true")
        expect_400("limit 含空白 -> 400", "?limit=%201")
        expect_400("limit Unicode 数字 -> 400", "?limit=%E0%A5%91")
        expect_400("after=-1 -> 400", "?after=-1")
        expect_400("after=+1 -> 400", "?after=%2B1")
        expect_400("after 含空白 -> 400", "?after=%20")
        expect_400("after 小数 -> 400", "?after=1.5")
        st, r = raw_get(LIST_PATH)
        check("显式空租户头 -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"} and r["error"])

        # ---- 准备验证者锚点（回执验真只查验证者 status 用途锚点）----
        va_priv, va_pub = gen_keypair()
        verifier_a = "did:web:csr-verifier-a.example"
        st, _ = _http(
            "POST", f"{base}{ANCHORS_PATH}",
            {"did": verifier_a, "public_key": va_pub, "key_version": 1,
             "uses": ["generic", "status"]},
            headers=T1,
        )
        assert st in (200, 201), st
        vb_priv, vb_pub = gen_keypair()
        verifier_b = "did:web:csr-verifier-b.example"
        st, _ = _http(
            "POST", f"{base}{ANCHORS_PATH}",
            {"did": verifier_b, "public_key": vb_pub, "key_version": 1,
             "uses": ["generic", "status"]},
            headers=T1,
        )
        assert st in (200, 201), st

        def make_item(nonce, verifier, v_priv):
            rcpt = {
                "issuer_did": "did:web:csr-issuer.example",
                "credential_id": f"vc_csr_hist_{nonce}",
                "status": "active",
                "reason": None,
                "updated_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
                "verifier_did": verifier,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return {"receipt": rcpt,
                    "signature": crypto.sign(rcpt, v_priv),
                    "nonce": nonce}

        def receipt_id_of(item):
            return hashlib.sha256(
                crypto.canonicalize(item["receipt"])
            ).hexdigest()

        # 单条消费两次（不同验证者），批量消费两项（再次跨验证者），
        # 同租户游标跨验证者共享递增。
        item1 = make_item("csr-n-1", verifier_a, va_priv)
        item2 = make_item("csr-n-2", verifier_b, vb_priv)
        item3 = make_item("csr-n-3", verifier_a, va_priv)
        item4 = make_item("csr-n-4", verifier_b, vb_priv)

        st, r = _http("POST", f"{base}{CONSUME_PATH}", item1, headers=T1)
        check("单条消费 item1 成功", st == 200 and r.get("valid") is True)
        st, r = _http("POST", f"{base}{CONSUME_PATH}", item2, headers=T1)
        check("单条消费 item2 成功", st == 200 and r.get("valid") is True)
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"items": [item3, item4]}, headers=T1)
        check("批量消费 item3/item4 成功",
              st == 200
              and [x.get("valid") for x in r.get("results", [])]
              == [True, True])

        want_ids = [receipt_id_of(x) for x in (item1, item2, item3, item4)]

        # 全量查询
        st, r = listing("?limit=200", headers=T1)
        check("全量查询 -> 200", st == 200)
        check("响应键序 events,next_after",
              list(r.keys()) == ["events", "next_after"])
        events = r["events"]
        check("四条消费事件", len(events) == 4)
        check("事件键序恰为 cursor,receipt_id,verifier_did,nonce,consumed_at",
              all(list(e.keys()) == ["cursor", "receipt_id",
                                    "verifier_did", "nonce", "consumed_at"]
                  for e in events))
        check("cursor 为正整数且按升序连续 1..4",
              [e["cursor"] for e in events] == [1, 2, 3, 4])
        check("receipt_id 依次匹配",
              [e["receipt_id"] for e in events] == want_ids)
        check("验证者依次为 A,B,A,B（跨验证者共享游标）",
              [e["verifier_did"] for e in events]
              == [verifier_a, verifier_b, verifier_a, verifier_b])
        check("nonce 依次为 csr-n-1..csr-n-4",
              [e["nonce"] for e in events]
              == ["csr-n-1", "csr-n-2", "csr-n-3", "csr-n-4"])
        check("consumed_at 均为 UTC 秒精度 Z 字符串",
              all(isinstance(e["consumed_at"], str)
                  and UTC_Z_RE.fullmatch(e["consumed_at"])
                  for e in events))
        check("receipt_id 均为 64 位小写 hex",
              all(SHA256_HEX_RE.fullmatch(e["receipt_id"]) for e in events))
        check("next_after 为末项 cursor=4", r["next_after"] == 4)

        # verifier_did 精确过滤
        st, r = listing(f"?limit=200&verifier_did={verifier_a}",
                        headers=T1)
        ev_a = r["events"]
        check("verifier_a 过滤得两条且 cursor 为 1,3",
              st == 200 and [e["cursor"] for e in ev_a] == [1, 3]
              and all(e["verifier_did"] == verifier_a for e in ev_a))
        check("过滤后 next_after=3", r["next_after"] == 3)
        st, r = listing("?verifier_did=did:web:nobody.example",
                        headers=T1)
        check("无匹配验证者 -> 空页 next_after=0",
              st == 200 and r["events"] == [] and r["next_after"] == 0)

        # 分页：limit=2
        st, p1 = listing("?limit=2", headers=T1)
        check("第一页两条 next_after=2",
              st == 200 and [e["cursor"] for e in p1["events"]] == [1, 2]
              and p1["next_after"] == 2)
        st, p2 = listing(f"?limit=2&after={p1['next_after']}", headers=T1)
        check("第二页两条 next_after=4",
              st == 200 and [e["cursor"] for e in p2["events"]] == [3, 4]
              and p2["next_after"] == 4)
        st, p3 = listing(f"?limit=2&after={p2['next_after']}", headers=T1)
        check("空页 next_after 保持 after=4",
              st == 200 and p3["events"] == [] and p3["next_after"] == 4)

        # 过滤 + 分页：after=1 仅验证者 A
        st, r = listing(f"?after=1&verifier_did={verifier_a}", headers=T1)
        check("after=1 + verifier_a 仅得 cursor=3",
              [e["cursor"] for e in r["events"]] == [3]
              and r["next_after"] == 3)

        # 纯只读：查询不追加审计、不改状态
        audits_before = consumed_audits(T1)
        st1, r1 = listing("?limit=1", headers=T1)
        st2, r2 = listing("?limit=1", headers=T1)
        check("重复只读查询结果一致", r1 == r2 and st1 == st2 == 200)
        check("查询不记消费审计",
              consumed_audits(T1) == audits_before)

        # 重放不追加历史
        st, _ = _http("POST", f"{base}{CONSUME_PATH}", item1, headers=T1)
        st, r = listing("?limit=200", headers=T1)
        check("重放不追加历史事件",
              st == 200 and len(r["events"]) == 4
              and [e["cursor"] for e in r["events"]] == [1, 2, 3, 4])

        # 租户隔离：T2 独立游标、空历史；显式同键消费互不影响
        st, r = listing(headers=T2)
        check("租户 B 初始空历史",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        st, _ = _http(
            "POST", f"{base}{ANCHORS_PATH}",
            {"did": verifier_a, "public_key": va_pub, "key_version": 1,
             "uses": ["generic", "status"]},
            headers=T2,
        )
        assert st in (200, 201), st
        other = make_item("csr-n-1", verifier_a, va_priv)
        st, r = _http("POST", f"{base}{CONSUME_PATH}", other, headers=T2)
        check("租户 B 同键独立消费成功",
              st == 200 and r.get("valid") is True)
        st, r = listing(headers=T2)
        check("租户 B 游标从 1 起且隔离",
              [e["cursor"] for e in r["events"]] == [1]
              and r["events"][0]["nonce"] == "csr-n-1")
        st, r = listing("?limit=200", headers=T1)
        check("租户 A 历史不受租户 B 影响",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4])

        # ---- 旧记录补录：删除新结构后重启，按
        # (consumed_at, verifier_did, nonce) 稳定补录，游标重启不变 ----
        proc.terminate()
        proc.wait(timeout=10)
        with open(store, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for bucket in raw.get("tenants", {}).values():
            bucket.pop(
                "credential_status_receipt_consumption_events", None
            )
        raw.pop("credential_status_receipt_consumption_cursors", None)
        with open(store, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, ensure_ascii=False, indent=2, sort_keys=True)

        proc = start_server(port, store)

        def backfill_snapshot(headers):
            st, r = listing("?limit=200", headers=headers)
            assert st == 200
            return [
                (e["cursor"], e["receipt_id"], e["verifier_did"],
                 e["nonce"], e["consumed_at"])
                for e in r["events"]
            ], r["next_after"]

        snap1, na1 = backfill_snapshot(T1)
        check("补录后租户 A 仍为四条", len(snap1) == 4)
        check("补录 cursor 连续 1..4",
              [row[0] for row in snap1] == [1, 2, 3, 4])
        check("补录 next_after=4", na1 == 4)
        check("补录 receipt_id 集合一致",
              sorted(row[1] for row in snap1) == sorted(want_ids))
        check("补录 (verifier_did,nonce) 集合一致",
              sorted((row[2], row[3]) for row in snap1)
              == sorted([(verifier_a, "csr-n-1"),
                         (verifier_b, "csr-n-2"),
                         (verifier_a, "csr-n-3"),
                         (verifier_b, "csr-n-4")]))
        check("补录 consumed_at 均为 UTC 秒精度 Z",
              all(UTC_Z_RE.fullmatch(row[4]) for row in snap1))

        # 再次重启：补录结果稳定（cursor 不变）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        snap2, na2 = backfill_snapshot(T1)
        check("重启后补录 cursor 与顺序不变", snap2 == snap1 and na2 == na1)

        # 补录后新消费继续在既有 cursor 之上递增
        item5 = make_item("csr-n-5", verifier_a, va_priv)
        st, r = _http("POST", f"{base}{CONSUME_PATH}", item5, headers=T1)
        check("补录后新消费成功", st == 200 and r.get("valid") is True)
        st, r = listing("?limit=200", headers=T1)
        check("补录后新事件 cursor=5",
              [e["cursor"] for e in r["events"]] == [1, 2, 3, 4, 5]
              and r["events"][-1]["nonce"] == "csr-n-5")

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store):
            os.unlink(store)

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
