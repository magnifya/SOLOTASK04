#!/usr/bin/env python3
"""信任锚点用途白名单（uses）能力的端到端测试。

直接运行：python3 tests/trust_anchor_uses_test.py
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


failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def main():
    port = 9021
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        assert wait_up(port), "服务启动超时"
        T1 = {"X-Tenant-ID": "uses-a"}
        T2 = {"X-Tenant-ID": "uses-b"}
        priv1, pub1 = gen_keypair()
        did = "did:web:uses.example"

        def register(uses=None, **kw):
            body = {"did": did, "public_key": pub1, "key_version": 1}
            body.update(kw)
            if uses is not None:
                body["uses"] = uses
            return _http("POST", f"{base}/v1/trust/anchors", body, headers=T1)

        # ---- 非法 uses -> 400 ----
        for bad in ([], ["vc", "vc"], ["nope"], ["vc", ""], "vc", 5,
                    [1, 2]):
            st, r = register(uses=bad)
            check(f"非法 uses={bad!r} -> 400", st == 400 and "error" in r)

        # uses:null 显式 null -> 400（须用裸 JSON，构造器会省略 None）
        raw = json.dumps({"did": did, "public_key": pub1,
                          "key_version": 1, "uses": None}).encode()
        st, r = _http("POST", f"{base}/v1/trust/anchors", raw=raw,
                      headers=T1)
        check("uses:null -> 400", st == 400)

        # 多余字段
        body = {"did": did, "public_key": pub1, "key_version": 1,
                "uses": ["vc"], "extra": 1}
        st, _ = _http("POST", f"{base}/v1/trust/anchors", body, headers=T1)
        check("多余字段 -> 400", st == 400)

        # ---- 注册仅 vc 用途（乱序输入规范化）----
        st, r = register(uses=["status", "vc"], key_version=1)
        check("注册 uses 201", st == 201)
        check("注册响应不增键",
              r == {"did": did, "public_key": pub1, "key_version": 1,
                    "status": "active", "updated_at": None})

        # ---- GET uses：规范序 ----
        st, r = _http("GET",
                      f"{base}/v1/trust/anchors/{did}/1/uses", headers=T1)
        check("GET uses 200 且规范序",
              st == 200 and list(r.keys()) == ["did", "key_version", "uses"]
              and r["uses"] == ["vc", "status"] and r["did"] == did
              and r["key_version"] == 1)

        # GET uses 路径版本非法 400
        for bad in ("0", "-1", "1.0", "a", "true"):
            st, r = _http(
                "GET",
                f"{base}/v1/trust/anchors/{did}/{bad}/uses",
                headers=T1,
            )
            check(f"GET uses 版本 {bad!r} -> 400", st == 400)
        # Unicode 数字（百分号编码后仍非 ASCII 数字）-> 400
        st, r = _http(
            "GET",
            f"{base}/v1/trust/anchors/{did}/%D9%A1/uses",
            headers=T1,
        )
        check("GET uses 版本 Unicode 数字 -> 400", st == 400)
        # 空版本段 -> 版本解析 400
        st, r = _http(
            "GET",
            f"{base}/v1/trust/anchors/{did}//uses",
            headers=T1,
        )
        check("GET uses 空版本段 -> 400", st == 400)

        # GET uses 未知版本 / 跨租户 404
        st, _ = _http("GET",
                      f"{base}/v1/trust/anchors/{did}/99/uses", headers=T1)
        check("GET uses 未知版本 -> 404", st == 404)
        st, _ = _http("GET",
                      f"{base}/v1/trust/anchors/{did}/1/uses", headers=T2)
        check("GET uses 跨租户 -> 404", st == 404)

        # ---- 幂等：同 PEM 同 uses 200；uses 不同 409 ----
        st, r = register(uses=["vc", "status"], key_version=1)
        check("同用途幂等 200", st == 200 and r["key_version"] == 1)
        st, _ = register(uses=["vc"], key_version=1)
        check("不同用途 -> 409", st == 409)
        st, _ = register(key_version=1)
        check("省略（全用途）vs 受限 -> 409", st == 409)

        # ---- 轮换继承 uses ----
        priv2, pub2 = gen_keypair()
        st, r = _http(
            "POST", f"{base}/v1/trust/anchors/{did}/rotate",
            {"from_key_version": 1, "public_key": pub2}, headers=T1)
        check("轮换 201", st == 201 and r["key_version"] == 2)
        st, r = _http("GET",
                      f"{base}/v1/trust/anchors/{did}/2/uses", headers=T1)
        check("轮换版本继承 uses（规范序）",
              st == 200 and r["uses"] == ["vc", "status"])

        # ---- 用途拦截：vc 入口成功，generic 入口“锚点不可用”----
        body = {
            "credential_id": "c1", "issuer_did": did,
            "subject_did": "did:web:s", "claims": {"k": "v"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 2,
        }
        sig = crypto.sign(body, priv2)
        st, r = _http("POST", f"{base}/v1/trust/credentials/verify",
                      {"body": body, "signature": sig}, headers=T1)
        check("含 vc 用途 -> 凭证验真成功", st == 200 and r.get("valid") is True)

        msg = {"a": 1}
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {"issuer_did": did, "issuer_key_version": 2,
                       "a": 1, "signature": crypto.sign(msg, priv2)},
                      headers=T1)
        check("缺 generic 用途 -> 200 valid:false 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        # proof/vp/did/status/deactivation 入口同样拦截
        predicates = [{"path": "/age", "op": "exists"}]
        proof = {
            "proof_id": "zp_" + "a" * 32,
            "credential_id": "c1", "issuer_did": did,
            "issuer_key_version": 2,
            "predicates": predicates, "results": [True],
            "challenge": "c", "expires_at": "2099-01-01T00:00:00Z",
        }
        proof_signed = dict(proof)
        proof_signed["proof"] = crypto.sign(
            {**proof, "tenant_id": "uses-a"}, priv2)
        st, r = _http(
            "POST", f"{base}/v1/trust/proofs/verify",
            {"proof": proof_signed, "challenge": "c",
             "source_tenant_id": "uses-a"}, headers=T1)
        check("缺 proof 用途 -> 锚点不可用",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "锚点不可用")

        status_body = {
            "issuer_did": did, "credential_id": "c1", "status": "active",
            "updated_at": "2026-09-21T00:00:00Z", "issuer_key_version": 2,
        }
        st, r = _http(
            "POST", f"{base}/v1/trust/credential-status/sync",
            {"body": status_body,
             "signature": crypto.sign(status_body, priv2)}, headers=T1)
        check("含 status 用途 -> 状态同步 201",
              st == 201 and r.get("status") == "active")

        deact_body = {
            "did": did, "key_version": 2, "reason": "r",
            "deactivated_at": "2026-09-21T00:00:00Z",
        }
        st, r = _http(
            "POST", f"{base}/v1/trust/dids/deactivate-sync",
            {"body": deact_body,
             "signature": crypto.sign(deact_body, priv2)}, headers=T1)
        check("缺 deactivation 用途 -> 锚点不可用且不写入",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        # manifest verify 缺 deactivation -> 锚点不可用
        filters = {"after": 0, "limit": None, "did": None,
                   "key_version": None, "from": None, "to": None}
        signed = {
            "snapshot": 0, "filters": filters, "count": 0,
            "alg": "SHA-256",
            "digest": hashlib.sha256(b"").hexdigest(),
            "signer_did": did, "key_version": 2,
        }
        manifest = dict(signed)
        manifest["signature"] = crypto.sign(signed, priv2)
        st, r = _http(
            "POST",
            f"{base}/v1/trust/dids/deactivations/manifest/verify",
            {"manifest": manifest, "ndjson": ""}, headers=T1)
        check("manifest verify 缺 deactivation -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        # ---- 全用途（省略）旧记录行为：另一租户省略注册全通过 ----
        _, pub3 = gen_keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub3, "key_version": 1},
                      headers=T2)
        st, r = _http("GET",
                      f"{base}/v1/trust/anchors/{did}/1/uses", headers=T2)
        all7 = ["generic", "vc", "vp", "proof", "did", "status",
                "deactivation"]
        check("省略 uses -> 全用途", st == 200 and r["uses"] == all7)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
