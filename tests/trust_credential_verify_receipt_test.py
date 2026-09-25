#!/usr/bin/env python3
"""跨系统凭证验真签名回执 POST /v1/trust/credentials/verify-receipt 的端到端测试。

直接运行：python3 tests/trust_credential_verify_receipt_test.py
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
    port = 8981
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
    verify_path = "/v1/trust/credentials/verify"
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

        T1 = {"X-Tenant-ID": "rcp-a"}
        T2 = {"X-Tenant-ID": "rcp-b"}

        # ---- 准备：外部签发者锚点 + 本地验证者 DID ----
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
        check("验证者当前版本为 1", r["key_version"] == 1)

        cred_id = "vc_receipt_0001"

        def make_body(version=1, extra=None):
            body = {
                "credential_id": cred_id,
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin", "nested": {"city": "北京"}},
                "issued_at": "2026-09-21T00:00:00Z",
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        body = make_body(version=1)
        sig = crypto.sign(body, issuer_priv)
        nonce = "nonce-挑战-001"
        good_payload = {
            "body": body,
            "signature": sig,
            "verifier_did": verifier_did,
            "nonce": nonce,
        }

        # 1. 成功回执：结构、键序、摘要、签名
        st, r = receipt(good_payload, headers=T1)
        check("成功回执 -> 200", st == 200)
        check(
            "顶层键序恰为 valid,receipt,receipt_signature",
            list(r.keys()) == ["valid", "receipt", "receipt_signature"],
        )
        check("valid 为 true", r.get("valid") is True)
        rcpt = r.get("receipt")
        check(
            "receipt 键序恰为七键",
            isinstance(rcpt, dict)
            and list(rcpt.keys()) == [
                "credential_id",
                "issuer_did",
                "issuer_key_version",
                "credential_digest",
                "verifier_did",
                "verifier_key_version",
                "nonce",
            ],
        )
        if isinstance(rcpt, dict):
            check("receipt.credential_id", rcpt.get("credential_id") == cred_id)
            check("receipt.issuer_did", rcpt.get("issuer_did") == issuer_did)
            check("receipt.issuer_key_version 为正整数 1",
                  rcpt.get("issuer_key_version") == 1)
            check("receipt.verifier_did",
                  rcpt.get("verifier_did") == verifier_did)
            check("receipt.verifier_key_version 为正整数 1",
                  rcpt.get("verifier_key_version") == 1)
            check("receipt.nonce 原样返回", rcpt.get("nonce") == nonce)
            want_digest = hashlib.sha256(
                crypto.canonicalize({"body": body, "signature": sig})
            ).hexdigest()
            check(
                "credential_digest 为 {body,signature} 规范化 JSON 的"
                " SHA-256 小写 hex",
                rcpt.get("credential_digest") == want_digest
                and len(want_digest) == 64
                and want_digest == want_digest.lower(),
            )
            # 回执签名可用验证者当前公钥验签
            try:
                crypto.verify(rcpt, r["receipt_signature"], verifier_pub)
                sig_ok = True
            except Exception:  # noqa: BLE001
                sig_ok = False
            check("receipt_signature 通过验证者当前公钥 ES256 验签", sig_ok)

        # 2. 省略 issuer_key_version 时回执版本按 1
        body_nov = make_body(version=None)
        sig_nov = crypto.sign(body_nov, issuer_priv)
        st, r = receipt(
            {"body": body_nov, "signature": sig_nov,
             "verifier_did": verifier_did, "nonce": "n1"},
            headers=T1,
        )
        check(
            "省略 issuer_key_version 时回执版本为 1",
            st == 200 and r.get("receipt", {}).get("issuer_key_version") == 1,
        )

        # 3. 验证者轮换密钥后回执版本前进并以新当前私钥签名
        st, rot = _http(
            "POST", f"{base}/v1/dids/{verifier_did}/keys/rotate",
            {"key_handle": "verifier-handle-a-v2"},
            headers=T1,
        )
        check("轮换验证者密钥 -> 200", st == 200 and rot["key_version"] == 2)
        verifier_pub_v2 = rot["public_key"]
        st, r = receipt(good_payload, headers=T1)
        check(
            "轮换后 verifier_key_version=2 且签名可由 v2 公钥验证",
            st == 200
            and r["receipt"]["verifier_key_version"] == 2,
        )
        if st == 200:
            try:
                crypto.verify(r["receipt"], r["receipt_signature"],
                              verifier_pub_v2)
                v2_ok = True
            except Exception:  # noqa: BLE001
                v2_ok = False
            check("回执签名为 v2 当前私钥所签", v2_ok)
            # v1 公钥应验不过（R||S 同一消息不同密钥）
            try:
                crypto.verify(r["receipt"], r["receipt_signature"],
                              verifier_pub)
                v1_ok = True
            except Exception:  # noqa: BLE001
                v1_ok = False
            check("v1 公钥不能验证 v2 回执签名", not v1_ok)

        # 4. nonce 边界：1 与 256 码点（含 Unicode）成功；257 失败
        for n, label in [("中", "1 个 Unicode 码点"), ("中" * 256,
                                                       "256 个 Unicode 码点")]:
            st, r = receipt(
                {"body": body, "signature": sig,
                 "verifier_did": verifier_did, "nonce": n},
                headers=T1,
            )
            check(f"nonce {label} -> 200", st == 200 and r.get("valid") is True)
        st, r = receipt(
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": "中" * 257},
            headers=T1,
        )
        check(
            "nonce 257 码点 -> 400 仅 {error}",
            st == 400 and set(r.keys()) == {"error"} and r["error"],
        )

        # 5. 400 系列：非法 JSON、非对象、键集、verifier_did、nonce
        def expect_400_only_error(name, payload=None, raw=None, headers=None):
            st, r = receipt(payload=payload, raw=raw, headers=headers)
            check(
                name,
                st == 400 and set(r.keys()) == {"error"}
                and isinstance(r["error"], str) and r["error"],
            )

        expect_400_only_error("空请求体 -> 400", raw=b"")
        expect_400_only_error("非法 JSON -> 400", raw=b"not-json")
        expect_400_only_error("非对象（数组） -> 400", raw=b"[1,2]")
        expect_400_only_error("非对象（null） -> 400", raw=b"null")
        expect_400_only_error("缺 body -> 400",
                              {"signature": sig, "verifier_did": verifier_did,
                               "nonce": "n"})
        expect_400_only_error("缺 signature -> 400",
                              {"body": body, "verifier_did": verifier_did,
                               "nonce": "n"})
        expect_400_only_error("缺 verifier_did -> 400",
                              {"body": body, "signature": sig, "nonce": "n"})
        expect_400_only_error("缺 nonce -> 400",
                              {"body": body, "signature": sig,
                               "verifier_did": verifier_did})
        expect_400_only_error(
            "多余字段 -> 400",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": "n", "x": 1},
            headers=T1,
        )
        expect_400_only_error(
            "verifier_did 空串 -> 400",
            {"body": body, "signature": sig, "verifier_did": "",
             "nonce": "n"},
            headers=T1,
        )
        expect_400_only_error(
            "verifier_did 非字符串 -> 400",
            {"body": body, "signature": sig, "verifier_did": 123,
             "nonce": "n"},
            headers=T1,
        )
        expect_400_only_error(
            "nonce 空串 -> 400",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": ""},
            headers=T1,
        )
        expect_400_only_error(
            "nonce 非字符串 -> 400",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": 123},
            headers=T1,
        )
        # 显式空租户头 400
        st, r = receipt(good_payload, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"})

        # 6. 外部凭证验真失败：200 + {valid:false,reason}，原因与
        #    /v1/trust/credentials/verify 完全一致；且不查询验证者——
        #    未知/停用验证者也不改变结论与状态码。
        def expect_invalid_same_as_verify(name, payload, headers=T1):
            st1, r1 = receipt(payload, headers=headers)
            st2, r2 = _http(
                "POST", f"{base}{verify_path}",
                {"body": payload["body"], "signature": payload["signature"]},
                headers=headers,
            )
            check(
                name,
                st1 == 200
                and list(r1.keys()) == ["valid", "reason"]
                and r1.get("valid") is False
                and r1.get("reason") == r2.get("reason")
                and st2 == 200,
            )

        unknown_verifier_payload = dict(good_payload,
                                        verifier_did="did:example:unknown")
        # 坏签名 + 未知验证者：仍是 200/签名校验失败（而非 404）
        expect_invalid_same_as_verify(
            "坏签名 + 未知验证者：200 且沿用原原因、不查验证者",
            dict(unknown_verifier_payload, signature="!!!bad!!!"),
        )
        expect_invalid_same_as_verify(
            "篡改正文：200 且原因与单项验真一致",
            dict(
                good_payload,
                body=dict(body, credential_id="vc_other"),
            ),
        )
        expect_invalid_same_as_verify(
            "body 非对象：200 请求类原因",
            {"body": [], "signature": sig,
             "verifier_did": verifier_did, "nonce": "n"},
        )
        expect_invalid_same_as_verify(
            "锚点未知：200 锚点类原因",
            dict(
                good_payload,
                body=dict(body, issuer_did="did:web:nope.example"),
                signature=crypto.sign(
                    dict(body, issuer_did="did:web:nope.example"),
                    issuer_priv,
                ),
            ),
        )
        # 已过期凭证同样 200/凭证已过期
        expired_body = make_body(version=1, extra={
            "expires_at": "2000-01-01T00:00:00Z"})
        expect_invalid_same_as_verify(
            "已过期凭证：200/凭证已过期",
            {"body": expired_body,
             "signature": crypto.sign(expired_body, issuer_priv),
             "verifier_did": verifier_did, "nonce": "n"},
        )

        # 7. 仅验真成功才查验证者：未知 404、跨租户 404、停用 409
        st, r = receipt(unknown_verifier_payload, headers=T1)
        check("未知验证者 DID -> 404 仅 {error}",
              st == 404 and set(r.keys()) == {"error"} and r["error"])
        # T2 注册同句柄 DID；T1 验证者对 T2 不可探测
        st, r_t2did = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-handle-b"},
            headers=T2,
        )
        check("T2 注册 DID -> 201", st == 201)
        t2_did = r_t2did["did"]
        st, r = receipt(
            dict(good_payload, verifier_did=t2_did), headers=T1
        )
        check("跨租户验证者 DID -> 404", st == 404)
        # 成功回执也不记审计、不落盘
        st, before_ok = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before_ok = len(before_ok["events"])
        receipt(good_payload, headers=T1)
        receipt(
            {"body": body_nov, "signature": sig_nov,
             "verifier_did": verifier_did, "nonce": "n2"},
            headers=T1,
        )
        st, after_ok = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("成功回执不记审计", len(after_ok["events"]) == n_before_ok)

        # 停用验证者 -> 409
        st, _ = _http(
            "POST", f"{base}/v1/dids/{verifier_did}/deactivate",
            {"reason": "验证者业务终止"},
            headers=T1,
        )
        check("停用验证者 DID -> 200", st == 200)
        st, r = receipt(good_payload, headers=T1)
        check("已停用验证者 -> 409 仅 {error}",
              st == 409 and set(r.keys()) == {"error"} and r["error"])
        # 停用不影响验真失败的 200 路径
        expect_invalid_same_as_verify(
            "验证者停用时凭证坏签名仍 200（不查验证者）",
            dict(good_payload, signature="!!!bad!!!"),
        )

        # 8. 租户隔离：T2 的活动验证者 + T2 自己的锚点才能出回执
        # T2 无 issuer 锚点 -> 即使用 T2 的验证者，验真先失败返回 200
        st, r = receipt(
            dict(good_payload, verifier_did=t2_did), headers=T2
        )
        check("T2 无签发锚点：先验真失败 200，不到 404",
              st == 200 and r.get("valid") is False
              and str(r.get("reason", "")).startswith("锚点"))
        # 在 T2 注册同 issuer_did 的锚点（不同公钥），用 T2 私钥签
        t2_issuer_priv, t2_issuer_pub = gen_keypair()
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": t2_issuer_pub,
             "key_version": 1},
            headers=T2,
        )
        check("T2 注册签发锚点 -> 201", st == 201)
        t2_body = make_body(version=1)
        t2_sig = crypto.sign(t2_body, t2_issuer_priv)
        st, r = receipt(
            {"body": t2_body, "signature": t2_sig,
             "verifier_did": t2_did, "nonce": "租户二"},
            headers=T2,
        )
        check(
            "T2 成功出回执，verifier 为 T2 DID",
            st == 200 and r.get("valid") is True
            and r["receipt"]["verifier_did"] == t2_did,
        )

        # 9. 纯只读：不落盘、不审计（在 T1 验证者停用前，先记录审计基线；
        #    这里成功回执全部发生在停用之前，统计成功+失败总调用前后差）
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(2):
            receipt(good_payload, headers=T1)  # 停用 -> 409
            receipt(unknown_verifier_payload, headers=T1)  # 404
            receipt(
                dict(good_payload, signature="bad"), headers=T1
            )  # 200 invalid
            expect_400_payload = {"body": body}
            receipt(expect_400_payload, headers=T1)  # 400
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("回执端点任何结果均不记审计",
              len(after["events"]) == n_before)
        # 未登记凭证
        st, _ = _http("GET", f"{base}/v1/credentials/{cred_id}", headers=T1)
        check("回执端点不登记本地凭证（404）", st == 404)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 10. 跨重启：状态持久化，回执字段（除签名字节外）稳定、可验签
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T2 = {"X-Tenant-ID": "rcp-b"}
        # 用 T2 的活动验证者（T1 验证者已停用）；同句柄注册幂等取回 DID
        # 与当前公钥。
        t2_body = make_body(version=1)
        st, r_t2did = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-handle-b"},
            headers=T2,
        )
        t2_did = r_t2did["did"]
        t2_pub = r_t2did["public_key"]
        t2_issuer_priv2 = t2_issuer_priv  # 上面生成的私钥本进程仍持有
        t2_sig = crypto.sign(t2_body, t2_issuer_priv2)
        st, r = receipt(
            {"body": t2_body, "signature": t2_sig,
             "verifier_did": t2_did, "nonce": "重启"},
            headers=T2,
        )
        check("重启后仍可成功出回执", st == 200 and r.get("valid") is True)
        if st == 200:
            check(
                "重启后回执字段稳定",
                r["receipt"]["credential_id"] == cred_id
                and r["receipt"]["issuer_did"] == issuer_did
                and r["receipt"]["verifier_did"] == t2_did
                and r["receipt"]["nonce"] == "重启"
                and r["receipt"]["credential_digest"]
                == hashlib.sha256(
                    crypto.canonicalize(
                        {"body": t2_body, "signature": t2_sig})
                ).hexdigest(),
            )
            try:
                crypto.verify(r["receipt"], r["receipt_signature"], t2_pub)
                restart_sig_ok = True
            except Exception:  # noqa: BLE001
                restart_sig_ok = False
            check("重启后回执签名可验真", restart_sig_ok)
        # T1 停用状态跨重启保留
        st, r_t1did = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-handle-a"},
            headers={"X-Tenant-ID": "rcp-a"},
        )
        v_did = r_t1did["did"]
        st, r = receipt(
            {"body": body, "signature": sig,
             "verifier_did": v_did, "nonce": "n"},
            headers={"X-Tenant-ID": "rcp-a"},
        )
        check("重启后 T1 验证者仍停用 -> 409", st == 409)
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
