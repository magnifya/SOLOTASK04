#!/usr/bin/env python3
"""只读回执校验 POST /v1/trust/credentials/receipt/verify 的端到端测试。

直接运行：python3 tests/trust_credential_receipt_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
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


def main():
    port = 8982
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/receipt/verify"
    receipt_path = "/v1/trust/credentials/verify-receipt"
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

        T1 = {"X-Tenant-ID": "rv-a"}
        T2 = {"X-Tenant-ID": "rv-b"}

        # ---- 准备：外部签发者锚点 + 本地验证者 DID + 验证者锚点 ----
        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:issuer.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": issuer_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册外部签发者锚点 -> 201", st == 201)

        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-handle-a"},
            headers=T1,
        )
        check("注册本地验证者 DID -> 201", st == 201)
        verifier_did = r["did"]
        verifier_pub = r["public_key"]

        # 验证者锚点（含 vc 用途）供 receipt/verify 验签
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": verifier_did, "public_key": verifier_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册验证者锚点 -> 201", st == 201)

        body = {
            "credential_id": "vc_rv_0001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)
        nonce = "nonce-回执-001"

        # 经 verify-receipt 取得真实回执
        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": nonce},
            headers=T1,
        )
        check("verify-receipt 出回执 -> 200", st == 200 and r.get("valid"))
        receipt = r["receipt"]
        receipt_signature = r["receipt_signature"]

        good_payload = {
            "receipt": receipt,
            "receipt_signature": receipt_signature,
            "body": body,
            "signature": sig,
            "nonce": nonce,
        }

        # 1. 成功：200 且恰为 {"valid": true}
        st, r = verify(good_payload, headers=T1)
        check("成功 -> 200 恰为 {valid:true}",
              st == 200 and list(r.keys()) == ["valid"]
              and r["valid"] is True)

        # 缺省租户头（default 租户无锚点）-> 锚点不可用而非 400
        st, r = verify(good_payload)
        check("缺省租户头按 default 隔离 -> 200 锚点不可用",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "锚点不可用")

        # 2. 400 系列：仅 {error: 非空中文}
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r = verify(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 400 and set(r.keys()) == {"error"}
                  and isinstance(r["error"], str) and r["error"])

        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("非对象（数组） -> 400", raw=b"[1,2]")
        for field in ("receipt", "receipt_signature", "body",
                      "signature", "nonce"):
            expect_400(f"缺 {field} -> 400",
                       {k: v for k, v in good_payload.items() if k != field})
        expect_400("多余字段 -> 400", dict(good_payload, x=1))
        expect_400("receipt 非对象 -> 400",
                   dict(good_payload, receipt="x"))
        expect_400("body 非对象 -> 400", dict(good_payload, body=[]))
        expect_400("receipt_signature 空串 -> 400",
                   dict(good_payload, receipt_signature=""))
        expect_400("receipt_signature 非字符串 -> 400",
                   dict(good_payload, receipt_signature=1))
        expect_400("signature 空串 -> 400", dict(good_payload, signature=""))
        expect_400("nonce 空串 -> 400", dict(good_payload, nonce=""))
        expect_400("nonce 非字符串 -> 400", dict(good_payload, nonce=1))
        expect_400("nonce 257 码点 -> 400",
                   dict(good_payload, nonce="中" * 257))
        expect_400("显式空租户头 -> 400", good_payload,
                   headers={"X-Tenant-ID": ""})
        # nonce 边界 1/256 码点不 400（nonce 与回执不符 -> nonce错误）
        st, r = verify(dict(good_payload, nonce="中"), headers=T1)
        check("nonce 1 码点 -> 200 nonce错误",
              st == 200 and r.get("reason") == "nonce错误")
        st, r = verify(dict(good_payload, nonce="中" * 256), headers=T1)
        check("nonce 256 码点 -> 200 nonce错误",
              st == 200 and r.get("reason") == "nonce错误")

        # 3. 失败均 200，键序恰为 valid,reason
        def expect_invalid(name, payload, reason, headers=T1):
            st, r = verify(payload, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        # 回执非法：缺字段/多字段/类型非法
        expect_invalid("回执缺字段 -> 回执非法",
                       dict(good_payload,
                            receipt={k: v for k, v in receipt.items()
                                     if k != "nonce"}),
                       "回执非法")
        expect_invalid("回执多字段 -> 回执非法",
                       dict(good_payload, receipt=dict(receipt, x=1)),
                       "回执非法")
        expect_invalid("回执版本为 0 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, issuer_key_version=0)),
                       "回执非法")
        expect_invalid("回执版本为布尔 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, verifier_key_version=True)),
                       "回执非法")
        expect_invalid("回执摘要非 hex -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, credential_digest="zz")),
                       "回执非法")
        expect_invalid("回执 nonce 超 256 码点 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, nonce="中" * 257)),
                       "回执非法")
        expect_invalid("回执 credential_id 空串 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, credential_id="")),
                       "回执非法")

        # nonce错误：两处 nonce 不等
        expect_invalid("两处 nonce 不等 -> nonce错误",
                       dict(good_payload, nonce="其他nonce"),
                       "nonce错误")

        # 绑定错误：receipt 与 body 的标识/版本不符
        expect_invalid("body credential_id 不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, credential_id="vc_other")),
                       "绑定错误")
        expect_invalid("body issuer_did 不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, issuer_did="did:web:other")),
                       "绑定错误")
        expect_invalid("body 版本不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, issuer_key_version=2)),
                       "绑定错误")
        body_nov = {k: v for k, v in body.items()
                    if k != "issuer_key_version"}
        expect_invalid("回执版本 2 而 body 缺版本（按 1）-> 绑定错误",
                       dict(good_payload,
                            receipt=dict(receipt, issuer_key_version=2),
                            body=body_nov),
                       "绑定错误")

        # 摘要错误：绑定字段不变但签名/claims 改动使复算摘要不同
        expect_invalid("签名不同 -> 摘要错误",
                       dict(good_payload, signature=crypto.sign(
                           body, issuer_priv)),
                       "摘要错误")
        expect_invalid("claims 改动 -> 摘要错误",
                       dict(good_payload,
                            body=dict(body, claims={"role": "user"})),
                       "摘要错误")

        # 锚点不可用：他租户无验证者锚点
        expect_invalid("他租户无验证者锚点 -> 锚点不可用",
                       good_payload, "锚点不可用", headers=T2)

        # 签名格式错误：非 86 字符无填充 base64url
        expect_invalid("receipt_signature 格式非法 -> 签名格式错误",
                       dict(good_payload, receipt_signature="!!!bad!!!"),
                       "签名格式错误")

        # 签名校验失败：格式合法但非验证者所签
        other_priv, _ = gen_keypair()
        expect_invalid("他钥签回执 -> 签名校验失败",
                       dict(good_payload,
                            receipt_signature=crypto.sign(receipt,
                                                          other_priv)),
                       "签名校验失败")
        expect_invalid("回执被篡改 -> 签名校验失败",
                       dict(good_payload,
                            receipt=dict(receipt, nonce=nonce),
                            nonce=nonce,
                            receipt_signature=crypto.sign(
                                dict(receipt, credential_id="vc_rv_0001"),
                                other_priv)),
                       "签名校验失败")

        # 4. 自备验证者密钥：锚点用途/版本/吊销与不重验凭证签名
        my_priv, my_pub = gen_keypair()
        my_verifier = "did:web:verifier.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": my_verifier, "public_key": my_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册自备验证者锚点 -> 201", st == 201)

        def make_receipt(b, s, n, version=1, vkey=1, verifier=my_verifier):
            rcpt = {
                "credential_id": b.get("credential_id"),
                "issuer_did": b.get("issuer_did"),
                "issuer_key_version": version,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": b, "signature": s})
                ).hexdigest(),
                "verifier_did": verifier,
                "verifier_key_version": vkey,
                "nonce": n,
            }
            return rcpt, crypto.sign(rcpt, my_priv)

        # 凭证签名对 body 无效（用他钥签）也不重验：回执合法即通过
        bad_cred_sig = crypto.sign(body, other_priv)
        rcpt, rcpt_sig = make_receipt(body, bad_cred_sig, "n-1")
        st, r = verify(
            {"receipt": rcpt, "receipt_signature": rcpt_sig,
             "body": body, "signature": bad_cred_sig, "nonce": "n-1"},
            headers=T1,
        )
        check("不重验凭证签名 -> 200 valid:true",
              st == 200 and r == {"valid": True})

        # body 缺 issuer_key_version 时按 1 绑定成功
        rcpt, rcpt_sig = make_receipt(body_nov, sig, "n-2", version=1)
        st, r = verify(
            {"receipt": rcpt, "receipt_signature": rcpt_sig,
             "body": body_nov, "signature": sig, "nonce": "n-2"},
            headers=T1,
        )
        check("body 缺版本按 1 绑定 -> 200 valid:true",
              st == 200 and r == {"valid": True})

        # 锚点版本不存在 -> 锚点不可用
        rcpt, rcpt_sig = make_receipt(body, sig, "n-3", vkey=9)
        st, r = verify(
            {"receipt": rcpt, "receipt_signature": rcpt_sig,
             "body": body, "signature": sig, "nonce": "n-3"},
            headers=T1,
        )
        check("验证者锚点版本不存在 -> 锚点不可用",
              st == 200 and r.get("reason") == "锚点不可用")

        # 锚点用途不含 vc -> 锚点不可用
        vp_priv, vp_pub = gen_keypair()
        vp_verifier = "did:web:vp-only.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": vp_verifier, "public_key": vp_pub,
             "key_version": 1, "uses": ["vp"]},
            headers=T1,
        )
        check("注册仅 vp 用途锚点 -> 201", st == 201)
        rcpt = {
            "credential_id": body["credential_id"],
            "issuer_did": body["issuer_did"],
            "issuer_key_version": 1,
            "credential_digest": hashlib.sha256(
                crypto.canonicalize({"body": body, "signature": sig})
            ).hexdigest(),
            "verifier_did": vp_verifier,
            "verifier_key_version": 1,
            "nonce": "n-4",
        }
        st, r = verify(
            {"receipt": rcpt,
             "receipt_signature": crypto.sign(rcpt, vp_priv),
             "body": body, "signature": sig, "nonce": "n-4"},
            headers=T1,
        )
        check("锚点用途不含 vc -> 锚点不可用",
              st == 200 and r.get("reason") == "锚点不可用")

        # 锚点吊销 -> 锚点不可用
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{my_verifier}/1/status",
            {"status": "revoked"},
            headers=T1,
        )
        check("吊销自备验证者锚点 -> 200", st == 200)
        rcpt, rcpt_sig = make_receipt(body, sig, "n-5")
        st, r = verify(
            {"receipt": rcpt, "receipt_signature": rcpt_sig,
             "body": body, "signature": sig, "nonce": "n-5"},
            headers=T1,
        )
        check("验证者锚点已吊销 -> 锚点不可用",
              st == 200 and r.get("reason") == "锚点不可用")

        # 5. 纯只读：不记审计
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        verify(good_payload, headers=T1)
        verify(dict(good_payload, nonce="x"), headers=T1)
        verify(dict(good_payload, receipt_signature="!!!"), headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("成功与失败调用均不记审计",
              len(after["events"]) == n_before)

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
