#!/usr/bin/env python3
"""跨系统凭证验真签名回执 POST /v1/trust/credentials/verify-receipt 的端到端测试。

直接运行：python3 tests/trust_credential_verify_receipt_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
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

_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
RECEIPT_KEYS = [
    "credential_id",
    "issuer_did",
    "issuer_key_version",
    "credential_digest",
    "verifier_did",
    "verifier_key_version",
    "nonce",
]


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
            raw_body = resp.read()
            parsed = json.loads(raw_body.decode() or "{}")
            return resp.status, parsed, raw_body
    except urllib.error.HTTPError as exc:
        raw_body = exc.read()
        return exc.code, json.loads(raw_body.decode() or "{}"), raw_body


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
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
    port = 8964
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/verify-receipt"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def receipt_call(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def expect_400(name, payload=None, raw=None, headers=None):
        st, r, _ = receipt_call(payload=payload, raw=raw, headers=headers)
        check(
            name,
            st == 400
            and set(r.keys()) == {"error"}
            and isinstance(r.get("error"), str)
            and r["error"],
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tcr-a"}
        T2 = {"X-Tenant-ID": "tcr-b"}

        # 显式空租户头：在进入任何处理前统一 400
        st, r, _ = receipt_call(
            payload={"body": {}, "signature": "x",
                     "verifier_did": "did:example:x", "nonce": "n"},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400 仅 error",
              st == 400 and set(r) == {"error"})

        # 外部签发者锚点
        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:external-issuer.example"
        st, _r, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": issuer_did, "public_key": issuer_pub,
                           "key_version": 1}, headers=T1)
        check("注册外部签发锚点 v1 -> 201", st == 201)

        # 本租户验证者 DID（托管密钥）
        st, verifier, _ = _http("POST", f"{base}/v1/dids",
                                {"method": "example",
                                 "public_key": "verifier-key-handle"},
                                headers=T1)
        check("注册验证者 DID -> 201", st == 201)
        verifier_did = verifier["did"]
        verifier_pub_v1 = verifier["public_key"]
        check("验证者初始版本为 1", verifier["key_version"] == 1)

        cred_id = "vc_external_receipt_0001"

        def make_body(version=1, extra=None):
            b = {
                "credential_id": cred_id,
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin", "level": 3,
                           "nested": {"city": "北京"}},
                "issued_at": "2026-09-21T00:00:00Z",
            }
            if version is not None:
                b["issuer_key_version"] = version
            if extra:
                b.update(extra)
            return b

        def req(body, sig, did=verifier_did, nonce="nonce-xyz"):
            return {"body": body, "signature": sig,
                    "verifier_did": did, "nonce": nonce}

        # ---------------------------------------------------------------- #
        # 1. 400 请求门：非法 JSON / 非对象 / 键集 / verifier_did / nonce
        # ---------------------------------------------------------------- #
        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("UTF-8 非法 -> 400", raw=b"\xff\xfe")
        expect_400("数组非对象 -> 400", raw=b"[1,2]")
        expect_400("字符串非对象 -> 400", raw=b'"x"')
        expect_400("数字非对象 -> 400", raw=b"123")
        expect_400("null 非对象 -> 400", raw=b"null")
        expect_400("true 非对象 -> 400", raw=b"true")
        expect_400("空对象 -> 400", {})

        good = {"body": {}, "signature": "s",
                "verifier_did": verifier_did, "nonce": "n"}
        for missing in ("body", "signature", "verifier_did", "nonce"):
            partial = dict(good)
            partial.pop(missing)
            expect_400(f"缺字段 {missing} -> 400", partial, headers=T1)
        expect_400("多余字段 -> 400", dict(good, extra=1), headers=T1)

        expect_400("verifier_did 空串 -> 400",
                   dict(good, verifier_did=""), headers=T1)
        expect_400("verifier_did 数字 -> 400",
                   dict(good, verifier_did=123), headers=T1)
        expect_400("verifier_did null -> 400",
                   dict(good, verifier_did=None), headers=T1)
        expect_400("nonce 空串 -> 400",
                   dict(good, nonce=""), headers=T1)
        expect_400("nonce 257 码点 -> 400",
                   dict(good, nonce="中" * 257), headers=T1)
        expect_400("nonce 数字 -> 400",
                   dict(good, nonce=1), headers=T1)
        expect_400("nonce null -> 400",
                   dict(good, nonce=None), headers=T1)
        expect_400("nonce 布尔 -> 400",
                   dict(good, nonce=True), headers=T1)

        # ---------------------------------------------------------------- #
        # 2. 验真失败先返回 200 {valid:false,reason}，不查询验证者
        # ---------------------------------------------------------------- #
        body = make_body(version=1)
        sig = crypto.sign(body, issuer_priv)

        # 未知验证者 + 失败凭证：仍 200（证明未查询验证者，否则 404）
        st, r, _ = receipt_call(
            req(body, "!!!bad!!!", did="did:example:unknown"),
            headers=T1,
        )
        check(
            "坏签名 + 未知验证者 -> 200 签名格式错误（不查验证者）",
            st == 200 and set(r) == {"valid", "reason"}
            and r.get("valid") is False
            and str(r.get("reason", "")).startswith("签名格式错误"),
        )
        tampered = json.loads(json.dumps(body))
        tampered["credential_id"] = "vc_other"
        st, r, _ = receipt_call(
            req(tampered, sig, did="did:example:unknown"),
            headers=T1,
        )
        check(
            "篡改正文 + 未知验证者 -> 200 签名校验失败（不查验证者）",
            st == 200 and r.get("valid") is False
            and str(r.get("reason", "")).startswith("签名校验失败"),
        )
        # 缺凭证字段 -> “凭证”类原因；锚点缺失 -> “锚点”类原因
        bad_field = json.loads(json.dumps(body))
        bad_field.pop("credential_id")
        st, r, _ = receipt_call(
            req(bad_field, sig, did="did:example:unknown"),
            headers=T1,
        )
        check("缺凭证字段 -> 200 凭证类原因",
              st == 200 and r.get("valid") is False
              and str(r.get("reason", "")).startswith("凭证"))
        unknown_issuer = json.loads(json.dumps(body))
        unknown_issuer["issuer_did"] = "did:web:nope.example"
        sig_unknown = crypto.sign(unknown_issuer, issuer_priv)
        st, r, _ = receipt_call(
            req(unknown_issuer, sig_unknown, did="did:example:unknown"),
            headers=T1,
        )
        check("锚点缺失 -> 200 锚点类原因",
              st == 200 and r.get("valid") is False
              and str(r.get("reason", "")).startswith("锚点"))
        # body 非对象（外层键集合法）-> 200 请求类原因
        st, r, _ = receipt_call(
            {"body": [], "signature": sig,
             "verifier_did": "did:example:unknown", "nonce": "n"},
            headers=T1,
        )
        check("body 非对象 -> 200 请求类原因（沿用既有规则）",
              st == 200 and set(r) == {"valid", "reason"}
              and r.get("valid") is False
              and str(r.get("reason", "")).startswith("请求"))

        # ---------------------------------------------------------------- #
        # 3. 验真成功才查验证者：未知/跨租户 404、停用 409
        # ---------------------------------------------------------------- #
        st, r, _ = receipt_call(req(body, sig, did="did:example:missing"),
                                headers=T1)
        check("未知验证者 -> 404 仅 error",
              st == 404 and set(r) == {"error"} and r["error"])

        # 他租户 DID 不可探测
        st, foreign, _ = _http("POST", f"{base}/v1/dids",
                               {"method": "example",
                                "public_key": "foreign-verifier-key"},
                               headers=T2)
        check("T2 注册验证者 DID -> 201", st == 201)
        st, r, _ = receipt_call(req(body, sig, did=foreign["did"]),
                                headers=T1)
        check("跨租户验证者 -> 404 仅 error",
              st == 404 and set(r) == {"error"} and r["error"])

        # 停用的验证者 -> 409
        st, deactivated, _ = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "deactivated-verifier"},
            headers=T1,
        )
        check("注册待停用验证者 -> 201", st == 201)
        st, _r, _ = _http(
            "POST",
            f"{base}/v1/dids/{deactivated['did']}/deactivate",
            {"reason": "验证者业务终止"}, headers=T1,
        )
        check("停用验证者 -> 200", st == 200)
        st, r, _ = receipt_call(req(body, sig, did=deactivated["did"]),
                                headers=T1)
        check("已停用验证者 -> 409 仅 error",
              st == 409 and set(r) == {"error"} and r["error"])

        # ---------------------------------------------------------------- #
        # 4. 成功回执：键序、摘要、签名全部正确
        # ---------------------------------------------------------------- #
        nonce = "nonce-回执-中文"
        st, r, raw_body = receipt_call(req(body, sig, nonce=nonce),
                                       headers=T1)
        check("成功 -> 200", st == 200)
        check("顶层键序恰为 valid,receipt,receipt_signature",
              list(r.keys()) == ["valid", "receipt", "receipt_signature"])
        check("valid 为 true", r.get("valid") is True)
        receipt = r["receipt"]
        check("receipt 键序恰为七键", list(receipt.keys()) == RECEIPT_KEYS)
        check("receipt.credential_id 取自 body",
              receipt["credential_id"] == cred_id)
        check("receipt.issuer_did 取自 body",
              receipt["issuer_did"] == issuer_did)
        check("receipt.issuer_key_version 为正整数 1",
              receipt["issuer_key_version"] == 1)
        check("receipt.verifier_did 回显",
              receipt["verifier_did"] == verifier_did)
        check("receipt.verifier_key_version 为正整数 1",
              receipt["verifier_key_version"] == 1)
        check("receipt.nonce 原样回显", receipt["nonce"] == nonce)
        check("credential_digest 为 64 位小写 hex",
              isinstance(receipt["credential_digest"], str)
              and bool(_SHA256_HEX_RE.fullmatch(receipt["credential_digest"])))

        expected_digest = hashlib.sha256(
            crypto.canonicalize({"body": body, "signature": sig})
        ).hexdigest()
        check("credential_digest == SHA256(canonical{body,signature})",
              receipt["credential_digest"] == expected_digest)

        # receipt_signature 用验证者当前公钥可验，且覆盖 receipt 规范化 JSON
        try:
            crypto.verify(receipt, r["receipt_signature"], verifier_pub_v1)
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("receipt_signature 经验证者当前公钥 ES256 验签通过", sig_ok)
        check("receipt_signature 为非空字符串",
              isinstance(r["receipt_signature"], str)
              and bool(r["receipt_signature"]))

        # ECDSA 每次签名可变：两次调用签名不同但都可验
        st, r2, _ = receipt_call(req(body, sig, nonce=nonce), headers=T1)
        check("重复回执均成功且签名可不同",
              st == 200 and r2["valid"] is True
              and r2["receipt"] == receipt
              and r2["receipt_signature"] != r["receipt_signature"])

        # 篡改 receipt 任一字段后验签失败
        forged = json.loads(json.dumps(receipt))
        forged["nonce"] = "forged"
        try:
            crypto.verify(forged, r["receipt_signature"], verifier_pub_v1)
            forged_ok = True
        except crypto.InvalidSignature:
            forged_ok = False
        check("篡改 receipt 后签名校验失败", forged_ok is False)

        # nonce 恰好 256 码点（含多字节中文）成功
        nonce_256 = "中" * 256
        st, r, _ = receipt_call(req(body, sig, nonce=nonce_256),
                                headers=T1)
        check("nonce 256 码点 -> 200 且回显",
              st == 200 and r["valid"] is True
              and r["receipt"]["nonce"] == nonce_256)

        # 省略 issuer_key_version -> receipt 内按 1，摘要仍覆盖原 body
        body_no_ver = make_body(version=None)
        sig_no_ver = crypto.sign(body_no_ver, issuer_priv)
        st, r, _ = receipt_call(req(body_no_ver, sig_no_ver), headers=T1)
        check("省略 issuer_key_version 验真成功且回执版本为 1",
              st == 200 and r["valid"] is True
              and r["receipt"]["issuer_key_version"] == 1)
        digest_no_ver = hashlib.sha256(
            crypto.canonicalize(
                {"body": body_no_ver, "signature": sig_no_ver}
            )
        ).hexdigest()
        check("省略版本时摘要覆盖不含版本的 body 原文",
              r["receipt"]["credential_digest"] == digest_no_ver)

        # ---------------------------------------------------------------- #
        # 5. 验证者轮换密钥：verifier_key_version=2，签名用 v2 公钥验
        # ---------------------------------------------------------------- #
        st, verifier_v2, _ = _http(
            "POST",
            f"{base}/v1/dids/{verifier_did}/keys/rotate",
            {"key_handle": "verifier-key-v2"}, headers=T1,
        )
        check("验证者轮换 -> 200 版本 2",
              st == 200 and verifier_v2["key_version"] == 2)
        st, r, _ = receipt_call(req(body, sig), headers=T1)
        check("轮换后回执 verifier_key_version=2",
              st == 200 and r["valid"] is True
              and r["receipt"]["verifier_key_version"] == 2)
        try:
            crypto.verify(r["receipt"], r["receipt_signature"],
                          verifier_v2["public_key"])
            v2_ok = True
        except Exception:  # noqa: BLE001
            v2_ok = False
        check("轮换后回执签名经 v2 当前公钥验签通过", v2_ok)
        # v1 公钥不再验得过当前签名（以极大的概率；ECDSA 不会误中）
        try:
            crypto.verify(r["receipt"], r["receipt_signature"],
                          verifier_pub_v1)
            v1_match = True
        except crypto.InvalidSignature:
            v1_match = False
        check("轮换后签名不再由 v1 公钥验证", v1_match is False)

        # ---------------------------------------------------------------- #
        # 6. 纯只读：不记审计、不落盘、不登记凭证
        # ---------------------------------------------------------------- #
        st, before, _ = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            receipt_call(req(body, sig), headers=T1)                       # 成功
            receipt_call(req(body, "bad-sig"), headers=T1)                # 200 失败
            receipt_call(req(body, sig, did="did:example:missing"),
                        headers=T1)                                        # 404
            receipt_call(req(body, sig, did=deactivated["did"]),
                        headers=T1)                                        # 409
        st, after, _ = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("回执（含成功与各失败分支）不记审计",
              len(after["events"]) == n_before)
        st, _r, _ = _http("GET", f"{base}/v1/credentials/{cred_id}",
                          headers=T1)
        check("回执不登记外部凭证（GET 仍 404）", st == 404)

        # ---------------------------------------------------------------- #
        # 7. 跨租户隔离：T2 无签发锚点 -> 200 valid:false
        # ---------------------------------------------------------------- #
        st, r, _ = receipt_call(req(body, sig), headers=T2)
        check("T2 无签发锚点 -> 200 valid:false（锚点）",
              st == 200 and set(r) == {"valid", "reason"}
              and r.get("valid") is False
              and str(r.get("reason", "")).startswith("锚点"))

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
