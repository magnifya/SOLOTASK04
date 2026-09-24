#!/usr/bin/env python3
"""外部凭证导入/读取端到端测试。

POST /v1/trust/credentials/import
GET  /v1/trust/credentials/imported/{credential_id}?issuer_did=...

直接运行：python3 tests/trust_credential_import_test.py
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
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


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
    port = 8967
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    imp_path = "/v1/trust/credentials/import"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def call(method, path, payload=None, raw=None, headers=None):
        st, text = _http(
            method, f"{base}{path}", payload=payload, raw=raw,
            headers=headers,
        )
        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError:
            parsed = None
        return st, parsed, text

    def post_import(payload=None, raw=None, headers=None):
        return call("POST", imp_path, payload=payload, raw=raw,
                    headers=headers)

    def get_imported(credential_id, query="", headers=None):
        suffix = f"?{query}" if query else ""
        return call(
            "GET",
            f"/v1/trust/credentials/imported/{credential_id}{suffix}",
            headers=headers,
        )

    def expect_400(name, payload=None, raw=None, headers=None,
                   method="POST", path=imp_path):
        st, parsed, _ = call(method, path, payload=payload, raw=raw,
                             headers=headers)
        check(
            name,
            st == 400
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"error"}
            and isinstance(parsed["error"], str)
            and parsed["error"],
        )

    def expect_invalid(name, payload=None, raw=None, headers=None):
        st, parsed, _ = post_import(
            payload=payload, raw=raw, headers=headers
        )
        check(
            name,
            st == 200
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"valid", "reason"}
            and parsed.get("valid") is False
            and isinstance(parsed.get("reason"), str)
            and parsed["reason"],
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "imp-a"}
        T2 = {"X-Tenant-ID": "imp-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:importer.example"
        did_rev = "did:web:revoked.example"
        cred_id = "vc_import_0001"

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("注册 active 锚点 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did_rev, "public_key": pub2, "key_version": 1},
            headers=T1,
        )
        check("注册将吊销锚点 -> 201", st == 201)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did_rev}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销锚点 -> 200", st == 200)

        def make_body(cred=cred_id, issuer=did, version=1, extra=None,
                      issued_at="2026-09-20T00:00:00Z"):
            body = {
                "credential_id": cred,
                "issuer_did": issuer,
                "subject_did": "did:web:holder.example",
                "claims": {"level": 7, "note": "外部凭证"},
                "issued_at": issued_at,
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        body1 = make_body()
        sig1 = crypto.sign(body1, priv1)

        # ---- 显式空 X-Tenant-ID：POST/GET 均 400 ----
        expect_400(
            "POST 显式空 X-Tenant-ID -> 400",
            payload={"body": body1, "signature": sig1},
            headers={"X-Tenant-ID": ""},
        )
        st, parsed, _ = get_imported(
            cred_id, "issuer_did=x", headers={"X-Tenant-ID": ""}
        )
        check("GET 显式空 X-Tenant-ID -> 400", st == 400)

        # ---- 请求/字段错误 -> 400 仅 {error} ----
        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("JSON 数组 -> 400", raw=b"[1]")
        expect_400("缺 body -> 400", {"signature": sig1}, headers=T1)
        expect_400("缺 signature -> 400", {"body": body1}, headers=T1)
        expect_400(
            "多余字段 -> 400",
            {"body": body1, "signature": sig1, "x": 1}, headers=T1,
        )
        expect_400("空对象 -> 400", {}, headers=T1)
        expect_400(
            "body 非对象 -> 400",
            {"body": "x", "signature": sig1}, headers=T1,
        )
        expect_400(
            "signature 空串 -> 400",
            {"body": body1, "signature": ""}, headers=T1,
        )
        expect_400(
            "signature 非字符串 -> 400",
            {"body": body1, "signature": 123}, headers=T1,
        )
        for field in ("credential_id", "issuer_did", "subject_did",
                      "claims", "issued_at"):
            bad = json.loads(json.dumps(body1))
            bad.pop(field)
            expect_400(
                f"body 缺字段 {field} -> 400",
                {"body": bad, "signature": sig1}, headers=T1,
            )
        expect_400(
            "claims 非对象 -> 400",
            {"body": dict(body1, claims=[]), "signature": sig1},
            headers=T1,
        )
        expect_400(
            "issuer_key_version 非法 -> 400",
            {"body": dict(body1, issuer_key_version=0),
             "signature": sig1},
            headers=T1,
        )

        # ---- 锚点/签名失败 -> 200 {valid:false,reason} 且不写入 ----
        body_no_anchor = make_body(issuer="did:web:nope.example")
        sig_no_anchor = crypto.sign(body_no_anchor, priv1)
        expect_invalid(
            "锚点缺失 -> 200 valid:false",
            {"body": body_no_anchor, "signature": sig_no_anchor},
            headers=T1,
        )
        body_rev = make_body(issuer=did_rev)
        sig_rev = crypto.sign(body_rev, priv2)
        expect_invalid(
            "锚点已吊销 -> 200 valid:false",
            {"body": body_rev, "signature": sig_rev}, headers=T1,
        )
        expect_invalid(
            "签名格式错 -> 200 valid:false",
            {"body": body1, "signature": "!!!bad!!!"}, headers=T1,
        )
        expect_invalid(
            "验签失败 -> 200 valid:false",
            {"body": body1, "signature": crypto.sign(body1, priv2)},
            headers=T1,
        )
        tampered = json.loads(json.dumps(body1))
        tampered["claims"]["level"] = 999
        expect_invalid(
            "篡改正文 -> 200 valid:false",
            {"body": tampered, "signature": sig1}, headers=T1,
        )
        body_expired = make_body(
            cred="vc_expired",
            extra={"expires_at": "2000-01-01T00:00:00Z"},
        )
        sig_expired = crypto.sign(body_expired, priv1)
        expect_invalid(
            "已过期凭证 -> 200 valid:false",
            {"body": body_expired, "signature": sig_expired}, headers=T1,
        )
        # 所有失败均不写入
        st, _, _ = get_imported(cred_id, f"issuer_did={did}", headers=T1)
        check("失败导入不写入（GET 404）", st == 404)
        st, _, _ = get_imported(
            "vc_expired", f"issuer_did={did}", headers=T1
        )
        check("过期凭证不写入（GET 404）", st == 404)

        # ---- 首次导入 -> 201，键序 imported,issuer_did,credential_id,
        #      body,signature，imported=true ----
        st, parsed, text = post_import(
            {"body": body1, "signature": sig1}, headers=T1
        )
        check("首次导入 -> 201", st == 201)
        check(
            "201 响应恰含五键且键序正确",
            parsed is not None
            and list(parsed.keys())
            == ["imported", "issuer_did", "credential_id",
                "body", "signature"]
            and list(json.loads(text).keys())
            == ["imported", "issuer_did", "credential_id",
                "body", "signature"],
        )
        check(
            "201 响应内容正确",
            parsed.get("imported") is True
            and parsed.get("issuer_did") == did
            and parsed.get("credential_id") == cred_id
            and parsed.get("body") == body1
            and parsed.get("signature") == sig1,
        )
        first_response = text

        # ---- 同内容重放 -> 200 原响应（除状态码外内容一致）----
        st, parsed, text = post_import(
            {"body": body1, "signature": sig1}, headers=T1
        )
        check("同内容重放 -> 200", st == 200 and text == first_response)

        # ---- 不同内容 -> 409 仅 {error}，不覆盖 ----
        changed = json.loads(json.dumps(body1))
        changed["claims"]["note"] = "被篡改的新内容"
        sig_changed = crypto.sign(changed, priv1)
        st, parsed, _ = post_import(
            {"body": changed, "signature": sig_changed}, headers=T1
        )
        check(
            "不同 body -> 409 仅 {error}",
            st == 409
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"error"}
            and isinstance(parsed["error"], str) and parsed["error"],
        )
        # 同 body 重新签名（ECDSA 随机化 -> 不同但有效的 signature）
        sig_resign = crypto.sign(body1, priv1)
        if sig_resign != sig1:
            st, parsed, _ = post_import(
                {"body": body1, "signature": sig_resign}, headers=T1
            )
            check(
                "同 body 不同签名 -> 409 仅 {error}",
                st == 409 and set(parsed.keys()) == {"error"},
            )
        else:
            check("同 body 不同签名 -> 409 仅 {error}（签名随机性未触发）",
                  False)
        # 原记录未被覆盖
        st, parsed, _ = get_imported(
            cred_id, f"issuer_did={did}", headers=T1
        )
        check(
            "冲突后原记录保持不变",
            st == 200
            and parsed.get("body") == body1
            and parsed.get("signature") == sig1,
        )

        # ---- GET 查询参数：缺失/重复/空值 -> 400 ----
        st, parsed, _ = get_imported(cred_id, headers=T1)
        check("GET 缺 issuer_did -> 400",
              st == 400 and set(parsed.keys()) == {"error"})
        st, _, _ = get_imported(
            cred_id, f"issuer_did={did}&issuer_did={did}", headers=T1
        )
        check("GET issuer_did 重复 -> 400", st == 400)
        st, _, _ = get_imported(cred_id, "issuer_did=", headers=T1)
        check("GET issuer_did 空值 -> 400", st == 400)

        # ---- GET 404：未导入 / 跨租户 / issuer_did 不匹配 ----
        st, _, _ = get_imported(
            "vc_not_here", f"issuer_did={did}", headers=T1
        )
        check("GET 未导入凭证 -> 404", st == 404)
        st, _, _ = get_imported(
            cred_id, "issuer_did=did:web:other.example", headers=T1
        )
        check("GET issuer_did 不匹配 -> 404", st == 404)
        st, _, _ = get_imported(cred_id, f"issuer_did={did}", headers=T2)
        check("GET 跨租户 -> 404", st == 404)

        # ---- GET 成功 -> 200 键序 issuer_did,credential_id,body,
        #      signature ----
        st, parsed, text = get_imported(
            cred_id, f"issuer_did={did}", headers=T1
        )
        check("GET 已导入凭证 -> 200", st == 200)
        check(
            "GET 响应恰含四键且键序正确",
            isinstance(parsed, dict)
            and list(parsed.keys())
            == ["issuer_did", "credential_id", "body", "signature"]
            and list(json.loads(text).keys())
            == ["issuer_did", "credential_id", "body", "signature"],
        )
        check(
            "GET 响应内容与导入一致",
            parsed.get("issuer_did") == did
            and parsed.get("credential_id") == cred_id
            and parsed.get("body") == body1
            and parsed.get("signature") == sig1,
        )

        # ---- 缺省租户 default：无头也能独立导入/读取 ----
        body_def = make_body(cred="vc_default_tenant")
        sig_def = crypto.sign(body_def, priv1)
        # default 租户无该锚点 -> 先失败
        expect_invalid(
            "default 租户无锚点 -> valid:false",
            {"body": body_def, "signature": sig_def},
        )
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        check("default 租户注册锚点 -> 201", st == 201)
        st, parsed, _ = post_import(
            {"body": body_def, "signature": sig_def}
        )
        check("缺省租户导入 -> 201", st == 201 and parsed.get("imported")
              is True)
        st, parsed, _ = get_imported(
            "vc_default_tenant", f"issuer_did={did}"
        )
        check("缺省租户读取 -> 200",
              st == 200 and parsed.get("body") == body_def)

        # ---- 跨租户独立导入同一双键（T2 注册自己的锚点）----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1},
            headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        body_t2 = make_body()
        sig_t2 = crypto.sign(body_t2, priv2)
        st, parsed, _ = post_import(
            {"body": body_t2, "signature": sig_t2}, headers=T2
        )
        check("T2 独立导入同双键 -> 201",
              st == 201 and parsed.get("imported") is True)
        # T1 记录不受影响
        st, parsed, _ = get_imported(
            cred_id, f"issuer_did={did}", headers=T1
        )
        check(
            "T1 记录与 T2 隔离（签名仍为 sig1）",
            st == 200 and parsed.get("signature") == sig1,
        )

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 持久化：重启后可读，重放仍为 200 ----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "imp-a"}
        st, parsed, _ = get_imported(
            cred_id, f"issuer_did={did}", headers=T1
        )
        check(
            "重启后 GET 已导入凭证 -> 200 且内容一致",
            st == 200
            and parsed.get("issuer_did") == did
            and parsed.get("credential_id") == cred_id
            and parsed.get("body") == body1
            and parsed.get("signature") == sig1,
        )
        st, parsed, text = post_import(
            {"body": body1, "signature": sig1}, headers=T1
        )
        check(
            "重启后同内容重放 -> 200 原响应",
            st == 200
            and parsed.get("imported") is True
            and list(parsed.keys())
            == ["imported", "issuer_did", "credential_id",
                "body", "signature"],
        )
        st, _, _ = get_imported(
            "vc_never_imported", f"issuer_did={did}", headers=T1
        )
        check("重启后未导入凭证仍 404", st == 404)
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
