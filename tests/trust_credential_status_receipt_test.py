#!/usr/bin/env python3
"""凭证状态同步签名回执 POST /v1/trust/credential-status/receipt 端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


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


def _raw_post(port, path, body: bytes, extra_headers: bytes = b""):
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


def main():
    port = 8977
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credential-status/receipt"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def receipt(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    try:
        assert wait_up(port), "服务启动超时"
        T1 = {"X-Tenant-ID": "csr-a"}
        T2 = {"X-Tenant-ID": "csr-b"}

        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:issuer.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": issuer_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册签发者锚点 -> 201", st == 201)

        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-csr-a"},
            headers=T1,
        )
        check("注册验证者 DID -> 201", st == 201)
        verifier_did = r["did"]
        verifier_pub = r["public_key"]
        check("验证者版本为 1", r["key_version"] == 1)

        cred_id = "vc_status_0001"

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
            sig = crypto.sign(body, issuer_priv)
            return _http(
                "POST", f"{base}/v1/trust/credential-status/sync",
                {"body": body, "signature": sig}, headers=T1,
            )

        good = {
            "issuer_did": issuer_did,
            "credential_id": cred_id,
            "verifier_did": verifier_did,
            "nonce": "nonce-挑战",
        }

        # 1. 未同步 -> 404
        st, r = receipt(good, headers=T1)
        check("未同步凭证 -> 404 仅 {error:资源不存在}",
              st == 404 and r == {"error": "资源不存在"})

        # 2. 同步 active 后成功回执：结构、键序、内容、签名
        st, _ = sync_status("active", "2026-09-20T00:00:00Z")
        check("同步 active -> 201", st == 201)
        st, r = receipt(good, headers=T1)
        check("成功回执 -> 200", st == 200)
        check("顶层键序恰为 receipt,signature",
              list(r.keys()) == ["receipt", "signature"])
        rcpt = r["receipt"]
        check("receipt 键序恰为九键",
              list(rcpt.keys()) == [
                  "issuer_did", "credential_id", "status", "reason",
                  "updated_at", "issuer_key_version", "verifier_did",
                  "verifier_key_version", "nonce",
              ])
        check(
            "receipt 内容取同步记录、reason 为 null、版本为正整数",
            rcpt["issuer_did"] == issuer_did
            and rcpt["credential_id"] == cred_id
            and rcpt["status"] == "active"
            and rcpt["reason"] is None
            and rcpt["updated_at"] == "2026-09-20T00:00:00Z"
            and rcpt["issuer_key_version"] == 1
            and rcpt["verifier_did"] == verifier_did
            and rcpt["verifier_key_version"] == 1
            and rcpt["nonce"] == "nonce-挑战"
            and isinstance(rcpt["issuer_key_version"], int)
            and not isinstance(rcpt["issuer_key_version"], bool)
            and isinstance(rcpt["verifier_key_version"], int)
            and not isinstance(rcpt["verifier_key_version"], bool),
        )
        check(
            "signature 为 86 字符无填充 base64url",
            len(r["signature"]) == 86
            and all(ch.isalnum() or ch in "_-" for ch in r["signature"]),
        )
        try:
            crypto.verify(rcpt, r["signature"], verifier_pub)
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("signature 由验证者当前私钥按 ES256 签 receipt", sig_ok)

        # 3. 验证者轮换后版本前进、以新当前私钥签名
        st, rot = _http(
            "POST", f"{base}/v1/dids/{verifier_did}/keys/rotate",
            {"key_handle": "verifier-csr-a-v2"}, headers=T1,
        )
        check("轮换验证者密钥 -> 200", st == 200 and rot["key_version"] == 2)
        st, r = receipt(good, headers=T1)
        check("轮换后 verifier_key_version=2",
              st == 200 and r["receipt"]["verifier_key_version"] == 2)
        try:
            crypto.verify(r["receipt"], r["signature"], rot["public_key"])
            v2_ok = True
        except Exception:  # noqa: BLE001
            v2_ok = False
        check("轮换后签名由 v2 私钥所签", v2_ok)

        # 4. suspended 回执取裁剪后 reason；revoked 同理
        st, _ = sync_status("suspended", "2026-09-21T00:00:00Z",
                            reason=" 调查中 ")
        check("同步 suspended -> 200", st == 200)
        st, r = receipt(dict(good, nonce="n2"), headers=T1)
        check("suspended 回执保存裁剪 reason",
              st == 200 and r["receipt"]["status"] == "suspended"
              and r["receipt"]["reason"] == "调查中"
              and r["receipt"]["updated_at"] == "2026-09-21T00:00:00Z")

        # 5. 400 系列：空体、非法 JSON、非对象、键集、类型、nonce 长度
        def expect_400(name, payload=None, raw=None):
            st, r = receipt(payload=payload, raw=raw, headers=T1)
            check(name, st == 400 and r == {"error": "请求非法"})

        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("非对象（数组） -> 400", raw=b"[1]")
        expect_400("非对象（null） -> 400", raw=b"null")
        expect_400("缺 issuer_did -> 400",
                   {"credential_id": cred_id,
                    "verifier_did": verifier_did, "nonce": "n"})
        expect_400("缺 credential_id -> 400",
                   {"issuer_did": issuer_did,
                    "verifier_did": verifier_did, "nonce": "n"})
        expect_400("缺 verifier_did -> 400",
                   {"issuer_did": issuer_did, "credential_id": cred_id,
                    "nonce": "n"})
        expect_400("缺 nonce -> 400",
                   {"issuer_did": issuer_did, "credential_id": cred_id,
                    "verifier_did": verifier_did})
        expect_400("多余字段 -> 400", dict(good, x=1))
        expect_400("issuer_did 空串 -> 400", dict(good, issuer_did=""))
        expect_400("credential_id 空串 -> 400", dict(good, credential_id=""))
        expect_400("verifier_did 空串 -> 400", dict(good, verifier_did=""))
        expect_400("issuer_did 非字符串 -> 400", dict(good, issuer_did=1))
        expect_400("credential_id 布尔 -> 400",
                   dict(good, credential_id=True))
        expect_400("verifier_did 数组 -> 400", dict(good, verifier_did=[]))
        expect_400("nonce 空串 -> 400", dict(good, nonce=""))
        expect_400("nonce 数字 -> 400", dict(good, nonce=1))
        expect_400("nonce 布尔 -> 400", dict(good, nonce=True))
        expect_400("nonce 257 码点 -> 400", dict(good, nonce="a" * 257))
        for value in ("a", "a" * 256, "中"):
            st, _ = receipt(dict(good, nonce=value), headers=T1)
            check(f"nonce {len(value)} 码点 -> 200", st == 200)

        # 显式空租户头 400（原始 socket）
        st, r = _raw_post(port, path, json.dumps(good).encode(),
                          b"X-Tenant-ID: \r\n")
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"} and r["error"])

        # 6. 404：未知验证者、未知签发者、跨租户验证者/凭证
        st, r = receipt(dict(good, verifier_did="did:example:unknown"),
                        headers=T1)
        check("未知验证者 -> 404", st == 404
              and r == {"error": "资源不存在"})
        st, r = receipt(dict(good, issuer_did="did:web:nope.example"),
                        headers=T1)
        check("未同步签发者 -> 404", st == 404
              and r == {"error": "资源不存在"})
        st, rt2 = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-csr-b"},
            headers=T2,
        )
        check("T2 注册验证者 -> 201", st == 201)
        st, r = receipt(dict(good, verifier_did=rt2["did"]), headers=T1)
        check("跨租户验证者 -> 404 同形", st == 404
              and r == {"error": "资源不存在"})
        st, r = receipt(good, headers=T2)
        check("跨租户未同步凭证 -> 404 同形", st == 404
              and r == {"error": "资源不存在"})

        # 7. 409：验证者停用
        st, _ = _http(
            "POST", f"{base}/v1/dids/{verifier_did}/deactivate",
            {"reason": "验证者业务终止"}, headers=T1,
        )
        check("停用验证者 -> 200", st == 200)
        st, r = receipt(good, headers=T1)
        check("已停用验证者 -> 409 仅 {error:验证者已停用}",
              st == 409 and r == {"error": "验证者已停用"})

        # 8. 纯只读：不记审计
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            receipt(good, headers=T1)  # 409
            receipt(dict(good, verifier_did="did:example:unknown"),
                    headers=T1)  # 404
            receipt(dict(good, nonce=""), headers=T1)  # 400
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("任何结果均不记审计", len(after["events"]) == n_before)

        # 9. 并发：严格更新与回执并发，结果须全属写前或写后
        st, rv = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-csr-active"},
            headers=T1,
        )
        check("注册新活动验证者 -> 201", st == 201)
        active_verifier = rv["did"]
        st, _ = sync_status("active", "2026-09-23T00:00:00Z")
        check("重置为 active -> 200", st == 200)
        seen = []
        barrier = threading.Barrier(8)

        def worker(index):
            barrier.wait()
            if index == 0:
                sync_status("revoked", "2026-09-24T00:00:00Z",
                            reason="终局吊销")
            else:
                st, r = receipt(
                    {"issuer_did": issuer_did, "credential_id": cred_id,
                     "verifier_did": active_verifier,
                     "nonce": f"c{index}"},
                    headers=T1,
                )
                seen.append((st, r["receipt"]["status"],
                             r["receipt"]["updated_at"]))

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        check("并发回执全部 200", all(item[0] == 200 for item in seen))
        check("并发结果全属写前或写后",
              {(s, u) for _, s, u in seen} <= {
                  ("active", "2026-09-23T00:00:00Z"),
                  ("revoked", "2026-09-24T00:00:00Z"),
              })
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 10. 跨重启：状态持久化、回执字段稳定、签名可验
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        # T1 验证者已停用并跨重启保留
        st, r = receipt(good, headers={"X-Tenant-ID": "csr-a"})
        check("重启后停用验证者仍 409", st == 409
              and r == {"error": "验证者已停用"})
        # T2 同步一份 revoked 状态，同句柄取回验证者后出回执
        t2_issuer_priv, t2_issuer_pub = gen_keypair()
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": t2_issuer_pub,
             "key_version": 1},
            headers=T2,
        )
        check("T2 注册锚点 -> 201", st == 201)
        body = {
            "issuer_did": issuer_did,
            "credential_id": "vc_t2_0001",
            "status": "revoked",
            "updated_at": "2026-09-22T00:00:00Z",
            "issuer_key_version": 1,
            "reason": "违规",
        }
        st, _ = _http(
            "POST", f"{base}/v1/trust/credential-status/sync",
            {"body": body, "signature": crypto.sign(body, t2_issuer_priv)},
            headers=T2,
        )
        check("T2 同步 revoked -> 201", st == 201)
        st, rv = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-csr-b"},
            headers=T2,
        )
        check("T2 同句柄取回验证者 -> 200/201", st in (200, 201))
        st, r = receipt(
            {"issuer_did": issuer_did, "credential_id": "vc_t2_0001",
             "verifier_did": rv["did"], "nonce": "重启-nonce"},
            headers=T2,
        )
        check("重启后 T2 成功回执 200", st == 200)
        check(
            "重启后回执字段稳定",
            r["receipt"]["credential_id"] == "vc_t2_0001"
            and r["receipt"]["status"] == "revoked"
            and r["receipt"]["reason"] == "违规"
            and r["receipt"]["updated_at"] == "2026-09-22T00:00:00Z"
            and r["receipt"]["issuer_key_version"] == 1
            and r["receipt"]["verifier_key_version"] == 1
            and r["receipt"]["nonce"] == "重启-nonce",
        )
        try:
            crypto.verify(r["receipt"], r["signature"], rv["public_key"])
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("重启后回执签名可验真", sig_ok)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

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
