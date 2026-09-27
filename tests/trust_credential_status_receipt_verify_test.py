#!/usr/bin/env python3
"""只读回执验真 POST /v1/trust/credential-status/receipt/verify 端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
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
    port = 8917
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credential-status/receipt/verify"
    receipt_path = "/v1/trust/credential-status/receipt"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    try:
        assert wait_up(port), "服务启动超时"
        T1 = {"X-Tenant-ID": "csv-a"}
        T2 = {"X-Tenant-ID": "csv-b"}

        # ---- 准备：签发者锚点（status 用途）+ 状态同步 + 验证者 ----
        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:issuer.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": issuer_pub,
             "key_version": 1, "uses": ["status"]},
            headers=T1,
        )
        check("注册签发者锚点 -> 201", st == 201)

        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-csv-a"},
            headers=T1,
        )
        check("注册验证者 DID -> 201", st == 201)
        verifier_did = r["did"]
        verifier_pub = r["public_key"]

        # 验证者锚点（status 用途），公钥与托管私钥配对
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": verifier_did, "public_key": verifier_pub,
             "key_version": 1, "uses": ["status"]},
            headers=T1,
        )
        check("注册验证者 status 锚点 -> 201", st == 201)

        cred_id = "vc_csv_0001"
        sync_body = {
            "issuer_did": issuer_did,
            "credential_id": cred_id,
            "status": "active",
            "updated_at": "2026-09-20T00:00:00Z",
            "issuer_key_version": 1,
        }
        st, _ = _http(
            "POST", f"{base}/v1/trust/credential-status/sync",
            {"body": sync_body,
             "signature": crypto.sign(sync_body, issuer_priv)},
            headers=T1,
        )
        check("同步 active -> 201", st == 201)

        nonce = "nonce-状态回执"
        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"issuer_did": issuer_did, "credential_id": cred_id,
             "verifier_did": verifier_did, "nonce": nonce},
            headers=T1,
        )
        check("取回状态回执 -> 200", st == 200)
        receipt = r["receipt"]
        signature = r["signature"]
        good = {"receipt": receipt, "signature": signature, "nonce": nonce}

        # 1. 成功：200 且恰为 {"valid": true}
        st, r = verify(good, headers=T1)
        check("成功 -> 200 恰为 {valid:true}",
              st == 200 and r == {"valid": True})

        # 2. 键序不影响验真：乱序提交 receipt 与外层键
        shuffled_receipt = {
            k: receipt[k] for k in (
                "nonce", "verifier_key_version", "verifier_did",
                "issuer_key_version", "updated_at", "reason", "status",
                "credential_id", "issuer_did",
            )
        }
        st, r = verify(
            {"nonce": nonce, "signature": signature,
             "receipt": shuffled_receipt},
            headers=T1,
        )
        check("乱序提交 -> 200 valid:true", st == 200 and r == {"valid": True})

        # 缺省租户头（default 无锚点）-> 锚点不可用
        st, r = verify(good)
        check("缺省租户头按 default 隔离 -> 200 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        # 3. 400 系列：仅 {error:请求非法}
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r = verify(payload=payload, raw=raw, headers=headers)
            check(name, st == 400 and r == {"error": "请求非法"})

        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("非对象（数组） -> 400", raw=b"[1]")
        expect_400("非对象（null） -> 400", raw=b"null")
        for field in ("receipt", "signature", "nonce"):
            expect_400(f"缺 {field} -> 400",
                       {k: v for k, v in good.items() if k != field})
        expect_400("多余字段 -> 400", dict(good, x=1))
        expect_400("receipt 非对象 -> 400", dict(good, receipt="x"))
        expect_400("receipt 数组 -> 400", dict(good, receipt=[]))
        expect_400("signature 空串 -> 400", dict(good, signature=""))
        expect_400("signature 数字 -> 400", dict(good, signature=1))
        expect_400("nonce 空串 -> 400", dict(good, nonce=""))
        expect_400("nonce 数字 -> 400", dict(good, nonce=1))
        expect_400("nonce 布尔 -> 400", dict(good, nonce=True))
        expect_400("nonce 257 码点 -> 400",
                   dict(good, nonce="中" * 257))
        for value in ("a", "中" * 256):
            st, r = verify(dict(good, nonce=value), headers=T1)
            check(f"nonce {len(value)} 码点 -> 200", st == 200)

        # 显式空租户头 400（原始 socket），仅返 {error}
        st, r = _raw_post(port, path, json.dumps(good).encode(),
                          b"X-Tenant-ID: \r\n")
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"} and r["error"])

        # 4. 外层合法后失败均 200，键序恰为 valid,reason
        def expect_invalid(name, payload, reason, headers=T1):
            st, r = verify(payload, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        # 4a. 回执非法
        expect_invalid("回执缺字段 -> 回执非法",
                       dict(good,
                            receipt={k: v for k, v in receipt.items()
                                     if k != "nonce"}),
                       "回执非法")
        expect_invalid("回执多字段 -> 回执非法",
                       dict(good, receipt=dict(receipt, x=1)),
                       "回执非法")
        expect_invalid("回执 issuer_did 空串 -> 回执非法",
                       dict(good, receipt=dict(receipt, issuer_did="")),
                       "回执非法")
        expect_invalid("回执 credential_id 数字 -> 回执非法",
                       dict(good, receipt=dict(receipt, credential_id=1)),
                       "回执非法")
        expect_invalid("回执 status 非法取值 -> 回执非法",
                       dict(good, receipt=dict(receipt, status="expired")),
                       "回执非法")
        expect_invalid("回执 status 非字符串 -> 回执非法",
                       dict(good, receipt=dict(receipt, status=1)),
                       "回执非法")
        expect_invalid("回执 updated_at 非法时刻 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt,
                                         updated_at="2026-13-40T99:99:99Z")),
                       "回执非法")
        expect_invalid("回执 updated_at 缺 Z -> 回执非法",
                       dict(good,
                            receipt=dict(receipt,
                                         updated_at="2026-09-20T00:00:00")),
                       "回执非法")
        expect_invalid("回执 updated_at 数字 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, updated_at=1)),
                       "回执非法")
        expect_invalid("回执版本为 0 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, issuer_key_version=0)),
                       "回执非法")
        expect_invalid("回执版本为布尔 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt,
                                         verifier_key_version=True)),
                       "回执非法")
        expect_invalid("回执版本为字符串 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, issuer_key_version="1")),
                       "回执非法")
        expect_invalid("回执 verifier_did 空串 -> 回执非法",
                       dict(good, receipt=dict(receipt, verifier_did="")),
                       "回执非法")
        expect_invalid("回执内层 nonce 空串 -> 回执非法",
                       dict(good, receipt=dict(receipt, nonce="")),
                       "回执非法")
        expect_invalid("回执内层 nonce 257 码点 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, nonce="中" * 257)),
                       "回执非法")
        expect_invalid("回执 reason 数字 -> 回执非法",
                       dict(good, receipt=dict(receipt, reason=1)),
                       "回执非法")
        expect_invalid("suspended 回执 reason 为 null -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, status="suspended",
                                         reason=None)),
                       "回执非法")
        expect_invalid("suspended 回执 reason 全空白 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, status="suspended",
                                         reason="   ")),
                       "回执非法")
        expect_invalid("suspended 回执 reason 带首尾空白 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, status="suspended",
                                         reason=" 调查中 ")),
                       "回执非法")
        expect_invalid("suspended 回执 reason 257 码点 -> 回执非法",
                       dict(good,
                            receipt=dict(receipt, status="suspended",
                                         reason="中" * 257)),
                       "回执非法")

        # 4b. nonce错误：内外 nonce 不等（回执本身合法）
        expect_invalid("内外 nonce 不等 -> nonce错误",
                       dict(good, nonce="其他nonce"),
                       "nonce错误")
        # 优先级：回执非法先于 nonce
        expect_invalid("回执非法优先于 nonce错误",
                       dict(good, nonce="其他nonce",
                            receipt=dict(receipt, x=1)),
                       "回执非法")

        # 4c. 锚点不可用
        expect_invalid("他租户无验证者锚点 -> 锚点不可用",
                       good, "锚点不可用", headers=T2)
        expect_invalid("验证者版本不存在 -> 锚点不可用",
                       dict(good,
                            receipt=dict(receipt, verifier_key_version=9),
                            signature=crypto.sign(
                                dict(receipt, verifier_key_version=9),
                                # 无对应私钥，用其他密钥签也须先判锚点
                                gen_keypair()[0])),
                       "锚点不可用")
        # 用途不含 status -> 锚点不可用
        vp_priv, vp_pub = gen_keypair()
        vp_did = "did:web:vp-only.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": vp_did, "public_key": vp_pub,
             "key_version": 1, "uses": ["vc", "vp"]},
            headers=T1,
        )
        check("注册仅 vc/vp 用途锚点 -> 201", st == 201)
        vp_receipt = dict(receipt, verifier_did=vp_did,
                          verifier_key_version=1, nonce=nonce)
        expect_invalid("锚点用途不含 status -> 锚点不可用",
                       {"receipt": vp_receipt,
                        "signature": crypto.sign(vp_receipt, vp_priv),
                        "nonce": nonce},
                       "锚点不可用")
        # 吊销验证者锚点 -> 锚点不可用
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{verifier_did}/1/status",
            {"status": "revoked"},
            headers=T1,
        )
        check("吊销验证者锚点 -> 200", st == 200)
        expect_invalid("验证者锚点已吊销 -> 锚点不可用",
                       good, "锚点不可用")

        # 4d. 签名格式错误：重新注册验证者锚点（同公钥幂等不行——吊销后
        # 用新 DID 承载同公钥），结构与锚点均合法后判格式
        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-csv-a2"},
            headers=T1,
        )
        check("注册第二验证者 DID -> 201", st == 201)
        v2_did = r["did"]
        v2_pub = r["public_key"]
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": v2_did, "public_key": v2_pub,
             "key_version": 1, "uses": ["status"]},
            headers=T1,
        )
        check("注册第二验证者 status 锚点 -> 201", st == 201)
        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"issuer_did": issuer_did, "credential_id": cred_id,
             "verifier_did": v2_did, "nonce": nonce},
            headers=T1,
        )
        check("以第二验证者取回回执 -> 200", st == 200)
        rcpt2 = r["receipt"]
        good2 = {"receipt": rcpt2, "signature": r["signature"],
                 "nonce": nonce}
        st, rr = verify(good2, headers=T1)
        check("第二验证者回执验真成功", st == 200 and rr == {"valid": True})
        expect_invalid("签名格式非法 -> 签名格式错误",
                       dict(good2, signature="!!!bad!!!"),
                       "签名格式错误")
        expect_invalid("签名 85 字符 -> 签名格式错误",
                       dict(good2, signature="A" * 85),
                       "签名格式错误")
        expect_invalid("签名带 base64 填充 -> 签名格式错误",
                       dict(good2, signature=r["signature"][:-1] + "="),
                       "签名格式错误")

        # 4e. 签名校验失败：格式合法但非锚点密钥所签 / 回执被篡改
        other_priv, _ = gen_keypair()
        expect_invalid("他钥签回执 -> 签名校验失败",
                       dict(good2, signature=crypto.sign(rcpt2, other_priv)),
                       "签名校验失败")
        tampered = dict(rcpt2, status="revoked", reason="终局")
        expect_invalid("回执被篡改 -> 签名校验失败",
                       dict(good2, receipt=tampered,
                            signature=crypto.sign(tampered, other_priv)),
                       "签名校验失败")
        # 优先级：锚点不可用先于签名格式/验签
        # good2 的锚点 active；改用被吊销 DID 制造锚点失败，同时签名坏
        bad_anchor_rcpt = dict(rcpt2, verifier_did=verifier_did,
                               verifier_key_version=1)
        expect_invalid("锚点不可用优先于签名格式错误",
                       {"receipt": bad_anchor_rcpt, "signature": "!!!",
                        "nonce": nonce},
                       "锚点不可用")
        expect_invalid("nonce错误优先于锚点不可用",
                       {"receipt": rcpt2, "signature": r["signature"],
                        "nonce": "不一致"},
                       "nonce错误")

        # 5. 不查询当前同步状态：从未同步的凭证 + 手工构造的合法回执
        my_priv, my_pub = gen_keypair()
        my_verifier = "did:web:offline-verifier.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": my_verifier, "public_key": my_pub,
             "key_version": 2, "uses": ["status"]},
            headers=T1,
        )
        check("注册自备 status 锚点 v2 -> 201", st == 201)
        offline_receipt = {
            "issuer_did": "did:web:never-synced.example",
            "credential_id": "vc_never_0001",
            "status": "suspended",
            "reason": "调查中",
            "updated_at": "2026-09-22T08:30:00Z",
            "issuer_key_version": 7,
            "verifier_did": my_verifier,
            "verifier_key_version": 2,
            "nonce": "offline-nonce",
        }
        st, rr = verify(
            {"receipt": offline_receipt,
             "signature": crypto.sign(offline_receipt, my_priv),
             "nonce": "offline-nonce"},
            headers=T1,
        )
        check("未同步凭证的合法回执 -> 200 valid:true",
              st == 200 and rr == {"valid": True})

        # unknown 状态、reason=null 合法
        unknown_receipt = dict(
            offline_receipt,
            credential_id="vc_never_0002",
            status="unknown",
            reason=None,
            updated_at="2026-09-22T09:30:00Z",
        )
        st, rr = verify(
            {"receipt": unknown_receipt,
             "signature": crypto.sign(unknown_receipt, my_priv),
             "nonce": "offline-nonce"},
            headers=T1,
        )
        check("unknown + reason=null -> 200 valid:true",
              st == 200 and rr == {"valid": True})

        # revoked 携带 reason 合法
        revoked_receipt = dict(
            offline_receipt,
            credential_id="vc_never_0003",
            status="revoked",
            reason="违规终局",
            updated_at="2026-09-22T10:30:00Z",
        )
        st, rr = verify(
            {"receipt": revoked_receipt,
             "signature": crypto.sign(revoked_receipt, my_priv),
             "nonce": "offline-nonce"},
            headers=T1,
        )
        check("revoked + reason 非空 -> 200 valid:true",
              st == 200 and rr == {"valid": True})

        # 当前同步状态变化不影响旧回执：同步记录更新为 revoked 后
        # 旧 active 回执仍验真通过
        sync_body2 = dict(sync_body, status="revoked",
                          updated_at="2026-09-25T00:00:00Z",
                          reason="终局吊销")
        st, _ = _http(
            "POST", f"{base}/v1/trust/credential-status/sync",
            {"body": sync_body2,
             "signature": crypto.sign(sync_body2, issuer_priv)},
            headers=T1,
        )
        check("同步更新为 revoked -> 200", st == 200)
        st, rr = verify(good2, headers=T1)
        check("状态变化后旧回执结论不变 -> valid:true",
              st == 200 and rr == {"valid": True})

        # 真实 suspended 回执（reason 经同步裁剪）端到端可验真
        cred_susp = "vc_csv_0002"
        sync_susp = {
            "issuer_did": issuer_did,
            "credential_id": cred_susp,
            "status": "suspended",
            "updated_at": "2026-09-26T12:00:00Z",
            "issuer_key_version": 1,
            "reason": " 调查中 ",
        }
        st, _ = _http(
            "POST", f"{base}/v1/trust/credential-status/sync",
            {"body": sync_susp,
             "signature": crypto.sign(sync_susp, issuer_priv)},
            headers=T1,
        )
        check("同步 suspended -> 201", st == 201)
        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"issuer_did": issuer_did, "credential_id": cred_susp,
             "verifier_did": v2_did, "nonce": "susp-nonce"},
            headers=T1,
        )
        check("suspended 回执 reason 已裁剪",
              st == 200 and r["receipt"]["status"] == "suspended"
              and r["receipt"]["reason"] == "调查中")
        st, rr = verify(
            {"receipt": r["receipt"], "signature": r["signature"],
             "nonce": "susp-nonce"},
            headers=T1,
        )
        check("真实 suspended 回执 -> 200 valid:true",
              st == 200 and rr == {"valid": True})

        # 6. 纯只读：不记审计
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(good2, headers=T1)
            verify(dict(good2, nonce="x"), headers=T1)
            verify(dict(good2, signature="!!!"), headers=T1)
            verify(raw=b"", headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("成功与失败调用均不记审计",
              len(after["events"]) == n_before)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 7. 跨重启：锚点持久化，回执验真结论稳定
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        my_priv2, my_pub2 = gen_keypair()
        restart_did = "did:web:restart-verifier.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": restart_did, "public_key": my_pub2,
             "key_version": 1, "uses": ["status"]},
            headers={"X-Tenant-ID": "csv-a"},
        )
        check("重启前注册锚点 -> 201", st == 201)
        rcpt = {
            "issuer_did": "did:web:issuer.example",
            "credential_id": "vc_restart_0001",
            "status": "active",
            "reason": None,
            "updated_at": "2026-09-26T00:00:00Z",
            "issuer_key_version": 1,
            "verifier_did": restart_did,
            "verifier_key_version": 1,
            "nonce": "重启-nonce",
        }
        payload = {"receipt": rcpt,
                   "signature": crypto.sign(rcpt, my_priv2),
                   "nonce": "重启-nonce"}
        st, r = verify(payload, headers={"X-Tenant-ID": "csv-a"})
        check("重启前验真成功", st == 200 and r == {"valid": True})
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务二次重启超时"
        st, r = verify(payload, headers={"X-Tenant-ID": "csv-a"})
        check("重启后同回执仍 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(payload, headers={"X-Tenant-ID": "csv-b"})
        check("重启后跨租户仍 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
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
