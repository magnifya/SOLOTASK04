#!/usr/bin/env python3
"""校验验真签名回执 POST /v1/trust/credentials/receipt/verify 的端到端测试。

直接运行：python3 tests/trust_credential_receipt_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

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

        T1 = {"X-Tenant-ID": "rcv-a"}
        T2 = {"X-Tenant-ID": "rcv-b"}

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

        # 验证者公钥登记为本租户含 vc 用途的锚点，供回执验签
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": verifier_did, "public_key": verifier_pub,
             "key_version": 1, "uses": ["vc"]},
            headers=T1,
        )
        check("注册验证者锚点（vc 用途） -> 201", st == 201)

        cred_id = "vc_receipt_verify_0001"
        body = {
            "credential_id": cred_id,
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin", "nested": {"city": "北京"}},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)
        nonce = "nonce-校验-001"

        def make_receipt(req_body=None, req_sig=None, req_nonce=None,
                         req_verifier=None):
            st, r = _http(
                "POST", f"{base}{receipt_path}",
                {"body": req_body if req_body is not None else body,
                 "signature": req_sig if req_sig is not None else sig,
                 "verifier_did": (req_verifier
                                  if req_verifier is not None
                                  else verifier_did),
                 "nonce": req_nonce if req_nonce is not None else nonce},
                headers=T1,
            )
            assert st == 200 and r.get("valid") is True, f"出回执失败: {r}"
            return r["receipt"], r["receipt_signature"]

        receipt, receipt_sig = make_receipt()
        good_payload = {
            "receipt": receipt,
            "receipt_signature": receipt_sig,
            "body": body,
            "signature": sig,
            "nonce": nonce,
        }

        # 1. 成功：恰为 {"valid": true}
        st, r = verify(good_payload, headers=T1)
        check("成功校验 -> 200", st == 200)
        check("成功响应恰为 {\"valid\": true}",
              list(r.keys()) == ["valid"] and r.get("valid") is True)

        # 省略 issuer_key_version 的 body：绑定按版本 1，仍成功
        body_nov = {k: v for k, v in body.items() if k != "issuer_key_version"}
        sig_nov = crypto.sign(body_nov, issuer_priv)
        receipt_nov, receipt_sig_nov = make_receipt(
            req_body=body_nov, req_sig=sig_nov, req_nonce="nov")
        st, r = verify(
            {"receipt": receipt_nov, "receipt_signature": receipt_sig_nov,
             "body": body_nov, "signature": sig_nov, "nonce": "nov"},
            headers=T1,
        )
        check("body 缺 issuer_key_version 按 1 绑定成功",
              st == 200 and list(r.keys()) == ["valid"]
              and r.get("valid") is True)

        # 2. 400 系列：仅 {error: 非空中文}
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r = verify(payload=payload, raw=raw, headers=headers)
            check(
                name,
                st == 400 and set(r.keys()) == {"error"}
                and isinstance(r["error"], str) and r["error"],
            )

        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("非对象（数组） -> 400", raw=b"[1,2]")
        expect_400("非对象（null） -> 400", raw=b"null")
        for field in ("receipt", "receipt_signature", "body", "signature",
                      "nonce"):
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
        expect_400("signature 非字符串 -> 400",
                   dict(good_payload, signature=1))
        expect_400("nonce 空串 -> 400", dict(good_payload, nonce=""))
        expect_400("nonce 非字符串 -> 400", dict(good_payload, nonce=1))
        expect_400("nonce 257 码点 -> 400",
                   dict(good_payload, nonce="中" * 257))
        expect_400("显式空 X-Tenant-ID -> 400", good_payload,
                   headers={"X-Tenant-ID": ""})

        # 3. 200 失败系列：键序恰为 valid,reason
        def expect_invalid(name, payload, reason, headers=T1):
            st, r = verify(payload, headers=headers)
            check(
                name,
                st == 200
                and list(r.keys()) == ["valid", "reason"]
                and r.get("valid") is False
                and r.get("reason") == reason,
            )

        # 回执非法：缺字段、多字段、类型/取值不符
        expect_invalid("回执缺字段 -> 回执非法",
                       dict(good_payload,
                            receipt={k: v for k, v in receipt.items()
                                     if k != "nonce"}),
                       "回执非法")
        expect_invalid("回执多字段 -> 回执非法",
                       dict(good_payload, receipt=dict(receipt, x=1)),
                       "回执非法")
        expect_invalid("回执 credential_id 空串 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, credential_id="")),
                       "回执非法")
        expect_invalid("回执 issuer_key_version 为 0 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, issuer_key_version=0)),
                       "回执非法")
        expect_invalid("回执 issuer_key_version 为布尔 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, issuer_key_version=True)),
                       "回执非法")
        expect_invalid("回执 credential_digest 非 64 位小写 hex -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, credential_digest="zz")),
                       "回执非法")
        expect_invalid("回执 nonce 空串 -> 回执非法",
                       dict(good_payload, receipt=dict(receipt, nonce="")),
                       "回执非法")
        expect_invalid("回执 nonce 257 码点 -> 回执非法",
                       dict(good_payload,
                            receipt=dict(receipt, nonce="中" * 257)),
                       "回执非法")

        # nonce 错误
        expect_invalid("两处 nonce 不等 -> nonce错误",
                       dict(good_payload, nonce="别的nonce"),
                       "nonce错误")

        # 绑定错误
        expect_invalid("credential_id 不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, credential_id="vc_other")),
                       "绑定错误")
        expect_invalid("issuer_did 不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, issuer_did="did:web:other")),
                       "绑定错误")
        expect_invalid("issuer_key_version 不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, issuer_key_version=2)),
                       "绑定错误")

        # 摘要错误：绑定字段不变但签名不同（摘要随 signature 改变）
        other_body = dict(body, claims={"role": "user"})
        other_sig = crypto.sign(other_body, issuer_priv)
        expect_invalid("签名被替换 -> 摘要错误",
                       dict(good_payload, signature=other_sig),
                       "摘要错误")
        expect_invalid("body 扩展字段改动 -> 摘要错误",
                       dict(good_payload,
                            body=dict(body, extra="x"),
                            signature=crypto.sign(dict(body, extra="x"),
                                                  issuer_priv)),
                       "摘要错误")

        # 锚点不可用：他租户无验证者锚点
        expect_invalid("他租户无验证者锚点 -> 锚点不可用",
                       good_payload, "锚点不可用", headers=T2)
        # 未知验证者锚点
        unknown_receipt = dict(receipt, verifier_did="did:example:unknown")
        unknown_sig = crypto.sign(unknown_receipt, issuer_priv)
        expect_invalid("未知验证者锚点 -> 锚点不可用",
                       dict(good_payload, receipt=unknown_receipt,
                            receipt_signature=unknown_sig),
                       "锚点不可用")

        # 签名格式错误
        expect_invalid("receipt_signature 非法编码 -> 签名格式错误",
                       dict(good_payload, receipt_signature="!!!bad!!!"),
                       "签名格式错误")

        # 签名校验失败：用另一 nonce 的回执签名张冠李戴
        receipt2, receipt_sig2 = make_receipt(req_nonce="另一个nonce")
        expect_invalid("张冠李戴的回执签名 -> 签名校验失败",
                       dict(good_payload, receipt_signature=receipt_sig2),
                       "签名校验失败")

        # 锚点吊销后 -> 锚点不可用
        st, _ = _http(
            "PUT",
            f"{base}/v1/trust/anchors/{verifier_did}/1/status",
            {"status": "revoked"},
            headers=T1,
        )
        check("吊销验证者锚点 -> 200", st == 200)
        expect_invalid("验证者锚点已吊销 -> 锚点不可用",
                       good_payload, "锚点不可用")

        # 4. 纯只读：不记审计、不登记资源
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        verify(good_payload, headers=T1)
        verify(dict(good_payload, nonce="x"), headers=T1)
        verify(raw=b"not-json", headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("回执校验端点任何结果均不记审计",
              len(after["events"]) == n_before)
        st, _ = _http("GET", f"{base}/v1/credentials/{cred_id}", headers=T1)
        check("回执校验端点不登记本地凭证（404）", st == 404)

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
