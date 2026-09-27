#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt/consume 一次性消费凭证
状态同步签名回执端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_consume_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400：空体、非法 JSON、非对象、键集错（缺/多键）、类型错，均仅
  {"error":"请求非法"}；显式空租户头 400；
- 200 验真失败原因沿用 verify 五阶段优先级（回执非法 -> nonce错误
  -> 锚点不可用 -> 签名格式错误 -> 签名校验失败），失败不写消费、
  不记审计；
- 首次 200 恰返 valid、receipt_id、consumed_at；receipt_id 为完整
  receipt 规范化 JSON UTF-8 字节 SHA-256 小写 64 位 hex；
  consumed_at 为 UTC 秒精度 Z；
- 同键重放（内容不同）及并发后到者均 200，仅
  {"valid":false,"reason":"状态回执已消费"}；
- 首次记 trust.credential.status.receipt.consumed 审计
  （resource_type=credential_status_receipt、resource_id=receipt_id），
  失败与重放不记；租户隔离；重启判重。
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt"
CONSUME_PATH = "/v1/trust/credential-status/receipt/consume"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    data = raw_body
    if data is None and payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _raw_post(port, path, body, extra_headers=b""):
    """用原始 socket 发请求（urllib 会丢弃空值头）。"""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(
        b"POST " + path.encode() + b" HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
        + extra_headers
        + b"Content-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n" + body
    )
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()
    status_line, rest = data.split(b"\r\n", 1)
    payload = json.loads(rest.split(b"\r\n\r\n", 1)[1].decode())
    return int(status_line.split()[1]), payload


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
    port = 9120
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
        TENANT = {"X-Tenant-ID": "csrc-tenant"}
        OTHER = {"X-Tenant-ID": "csrc-other"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:csrc-issuer.example"
        cred_id = "vc_csrc_0001"
        st, _ = post(ANCHORS_PATH,
                     {"did": issuer_did, "public_key": issuer_pub,
                      "key_version": 1, "uses": ["generic", "status"]},
                     TENANT)
        assert st in (200, 201), st

        def sync_status(status, updated_at, reason=None):
            body = {
                "issuer_did": issuer_did,
                "credential_id": cred_id,
                "status": status,
                "updated_at": updated_at,
                "issuer_key_version": 1,
            }
            if reason is not None:
                body["reason"] = reason
            return post(SYNC_PATH,
                        {"body": body,
                         "signature": crypto.sign(body, issuer_priv)},
                        TENANT)

        st, _ = sync_status("active", "2026-09-20T00:00:00Z")
        assert st == 201, st

        # 本地托管验证者 DID（receipt 的签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "example",
                        "public_key": "credential-status-receipt-consume"},
                       TENANT)
        assert st == 201, st
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]
        verifier_version = verifier_rec["key_version"]

        # 为验证者登记含 status 用途的 active 锚点。
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": verifier_version,
                      "uses": ["generic", "status"]}, TENANT)
        assert st in (200, 201), st

        nonce = "nonce-消费挑战"

        def get_receipt(nonce_value):
            st, raw = post(RECEIPT_PATH,
                           {"issuer_did": issuer_did,
                            "credential_id": cred_id,
                            "verifier_did": verifier_did,
                            "nonce": nonce_value}, TENANT)
            assert st == 200, (st, raw)
            issued = json.loads(raw)
            return issued["receipt"], issued["signature"]

        receipt, signature = get_receipt(nonce)

        def consume(payload=None, headers=TENANT, raw_body=None):
            st, raw = post(CONSUME_PATH, payload=payload, headers=headers,
                           raw_body=raw_body)
            return st, json.loads(raw.decode() or "null")

        good = {"receipt": receipt, "signature": signature, "nonce": nonce}

        # ---------------------------------------------------------- #
        # 1. 400：仅 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, payload=None, raw_body=None, headers=TENANT):
            st, body = consume(payload, headers=headers, raw_body=raw_body)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("空体 400", raw_body=b"")
        expect_400("非法 JSON 400", raw_body=b"{not json")
        expect_400("非对象（数组）400", raw_body=b"[1,2]")
        expect_400("非对象（null）400", raw_body=b"null")
        expect_400("非对象（字符串）400", raw_body=b'"x"')
        for field in ("receipt", "signature", "nonce"):
            expect_400(f"缺 {field} 400",
                       {k: v for k, v in good.items() if k != field})
        extra = dict(good)
        extra["x"] = 1
        expect_400("多键 400", extra)
        bad = dict(good)
        bad["receipt"] = "not-object"
        expect_400("receipt 非对象", bad)
        bad = dict(good)
        bad["receipt"] = []
        expect_400("receipt 为数组", bad)
        bad = dict(good)
        bad["signature"] = ""
        expect_400("signature 空串", bad)
        bad = dict(good)
        bad["signature"] = 123
        expect_400("signature 非串", bad)
        bad = dict(good)
        bad["nonce"] = ""
        expect_400("nonce 空串", bad)
        bad = dict(good)
        bad["nonce"] = 1
        expect_400("nonce 数字", bad)
        bad = dict(good)
        bad["nonce"] = True
        expect_400("nonce 布尔", bad)
        bad = dict(good)
        bad["nonce"] = "a" * 257
        expect_400("nonce 257 码点", bad)

        # 显式空租户头 400（原始 socket），统一租户头错误，不进验真。
        st, body = _raw_post(port, CONSUME_PATH,
                             json.dumps(good).encode("utf-8"),
                             b"X-Tenant-ID: \r\n")
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and set(body.keys()) == {"error"} and body["error"])

        # ---------------------------------------------------------- #
        # 2. 验真失败 200：沿用 verify 的 reason，不写消费不记审计
        # ---------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=TENANT)
        assert st == 200
        audit_before = json.loads(audit_before)

        def expect_reason(name, payload, reason, headers=TENANT):
            st, body = consume(payload, headers=headers)
            check(name, st == 200
                  and list(body.keys()) == ["valid", "reason"]
                  and body == {"valid": False, "reason": reason})

        bad_struct = {k: v for k, v in receipt.items() if k != "status"}
        expect_reason("回执非法不消费",
                      {"receipt": bad_struct, "signature": signature,
                       "nonce": nonce}, "回执非法")
        expect_reason("nonce 错误不消费",
                      {"receipt": receipt, "signature": signature,
                       "nonce": "别的"}, "nonce错误")
        expect_reason("跨租户锚点不可用不消费", good, "锚点不可用",
                      headers=OTHER)
        expect_reason("签名格式错误不消费",
                      {"receipt": receipt, "signature": "!!!",
                       "nonce": nonce}, "签名格式错误")
        other_priv, _ = _keypair()
        expect_reason("签名校验失败不消费",
                      {"receipt": receipt,
                       "signature": crypto.sign(receipt, other_priv),
                       "nonce": nonce}, "签名校验失败")

        st, audit_after = get("/v1/audit?limit=200", headers=TENANT)
        check("验真失败不记审计",
              audit_before == json.loads(audit_after))

        # ---------------------------------------------------------- #
        # 3. 首次消费：valid、receipt_id、consumed_at
        # ---------------------------------------------------------- #
        st, body = consume(good)
        expected_id = hashlib.sha256(
            crypto.canonicalize(receipt)).hexdigest()
        check(
            "首次消费 200 键序 valid/receipt_id/consumed_at",
            st == 200
            and list(body.keys()) == ["valid", "receipt_id", "consumed_at"]
            and body["valid"] is True
            and body["receipt_id"] == expected_id
            and re.fullmatch(r"[0-9a-f]{64}", body["receipt_id"]) is not None
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                             body["consumed_at"]) is not None,
        )
        receipt_id = body["receipt_id"]
        consumed_at = body["consumed_at"]

        # ---------------------------------------------------------- #
        # 4. 审计：恰好一条，字段正确
        # ---------------------------------------------------------- #
        st, raw = get("/v1/audit?limit=200", headers=TENANT)
        events = [e for e in json.loads(raw)["events"]
                  if e["action"]
                  == "trust.credential.status.receipt.consumed"]
        check(
            "首次记一条消费审计且字段正确",
            len(events) == 1
            and events[0]["resource_type"] == "credential_status_receipt"
            and events[0]["resource_id"] == receipt_id
            and events[0]["tenant_id"] == "csrc-tenant",
        )

        # ---------------------------------------------------------- #
        # 5. 同键重放（内容不同）：状态回执已消费，不重复记审计
        # ---------------------------------------------------------- #
        st, body = consume(good)
        check("同请求重放 -> 状态回执已消费",
              st == 200
              and list(body.keys()) == ["valid", "reason"]
              and body == {"valid": False, "reason": "状态回执已消费"})

        # 推进同步状态后以同 verifier_did/nonce 取得内容不同的新回执。
        st, _ = sync_status("suspended", "2026-09-21T00:00:00Z",
                            reason="调查中")
        assert st == 200, st
        receipt2, signature2 = get_receipt(nonce)
        assert receipt2 != receipt
        expect_reason("同键不同内容重放 -> 状态回执已消费",
                      {"receipt": receipt2, "signature": signature2,
                       "nonce": nonce}, "状态回执已消费")

        st, raw = get("/v1/audit?limit=200", headers=TENANT)
        events = [e for e in json.loads(raw)["events"]
                  if e["action"]
                  == "trust.credential.status.receipt.consumed"]
        check("重放不追加审计", len(events) == 1)

        # 同租户不同 nonce 可独立消费。
        nonce_b = "nonce-consume-b"
        receipt_b, signature_b = get_receipt(nonce_b)
        st, body = consume({"receipt": receipt_b, "signature": signature_b,
                            "nonce": nonce_b})
        check("不同 nonce 独立消费",
              st == 200 and body.get("valid") is True
              and body.get("receipt_id") == hashlib.sha256(
                  crypto.canonicalize(receipt_b)).hexdigest()
              and body.get("consumed_at") >= consumed_at)

        # ---------------------------------------------------------- #
        # 6. 租户隔离：他租户/default 同键未消费（锚点不可用）
        # ---------------------------------------------------------- #
        st, body = consume(good, headers=OTHER)
        check("他租户隔离（锚点不可用）",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        st, body = consume(good, headers={})
        check("缺省租户头 default 隔离",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

        # 他租户审计中无本动作。
        st, raw = get("/v1/audit?limit=200", headers=OTHER)
        events = [e for e in json.loads(raw)["events"]
                  if e["action"]
                  == "trust.credential.status.receipt.consumed"]
        check("他租户无消费审计", events == [])

        # ---------------------------------------------------------- #
        # 7. 并发：同键仅一次成功
        # ---------------------------------------------------------- #
        nonce_c = "nonce-consume-c"
        receipt_c, signature_c = get_receipt(nonce_c)
        payload_c = json.dumps(
            {"receipt": receipt_c, "signature": signature_c,
             "nonce": nonce_c}).encode("utf-8")
        barrier = threading.Barrier(8)

        def fire():
            barrier.wait()
            req = urllib.request.Request(base + CONSUME_PATH, data=payload_c,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Tenant-ID", "csrc-tenant")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: fire(), range(8)))
        oks = [b for s, b in responses if s == 200 and b.get("valid") is True]
        replays = [b for s, b in responses
                   if s == 200 and b == {
                       "valid": False, "reason": "状态回执已消费"}]
        check("并发同键恰一次成功、其余重放",
              len(oks) == 1 and len(replays) == 7
              and oks[0]["receipt_id"] == hashlib.sha256(
                  crypto.canonicalize(receipt_c)).hexdigest())

        # ---------------------------------------------------------- #
        # 8. 重启判重
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = consume(good)
        check("重启后同键仍判重",
              st == 200 and body == {
                  "valid": False, "reason": "状态回执已消费"})
        st, body = consume({"receipt": receipt2, "signature": signature2,
                            "nonce": nonce})
        check("重启后同键不同内容仍判重",
              st == 200 and body == {
                  "valid": False, "reason": "状态回执已消费"})
        st, body = consume(good, headers=OTHER)
        check("重启后他租户未被污染",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.remove(store_path)

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
