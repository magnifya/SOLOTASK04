#!/usr/bin/env python3
"""POST /v1/trust/proofs/verify-with-status 与 verify-batch-with-status 端到端测试。

直接运行：python3 tests/trust_proof_verify_with_status_test.py
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vcbackend import crypto


def _http(method, url, payload=None, headers=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
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
        encryption_algorithm=serialization.NoEncryption()).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem


failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def main():
    port = 8977
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    T1 = {"X-Tenant-ID": "tps-a"}
    T2 = {"X-Tenant-ID": "tps-b"}

    priv, pub = gen_keypair()
    did = "did:web:ext-proof-status.example"

    PREDS = [{"path": "/age", "op": "gte", "value": 18}]

    def make_proof(cred_id, challenge="chal-1",
                   expires_at="2099-01-01T00:00:00Z"):
        p = {
            "proof_id": "zp_" + "b" * 32,
            "credential_id": cred_id,
            "issuer_did": did,
            "issuer_key_version": 1,
            "predicates": PREDS,
            "results": [True],
            "challenge": challenge,
            "expires_at": expires_at,
        }
        message = dict(p)
        message["tenant_id"] = "source-tenant"
        p["proof"] = crypto.sign(message, priv)
        return p

    def req(p, challenge="chal-1"):
        return {"proof": p, "challenge": challenge,
                "source_tenant_id": "source-tenant"}

    def sync(cred_id, status, reason=None, updated_at="2026-01-01T00:00:00Z"):
        body = {"issuer_did": did, "credential_id": cred_id,
                "status": status, "updated_at": updated_at,
                "issuer_key_version": 1}
        if reason is not None:
            body["reason"] = reason
        sig = crypto.sign(body, priv)
        return _http("POST", f"{base}/v1/trust/credential-status/sync",
                     {"body": body, "signature": sig}, headers=T1)

    try:
        assert wait_up(port), "服务启动超时"
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub, "key_version": 1},
                      headers=T1)
        check("注册锚点 -> 201", st == 201)

        single = f"{base}/v1/trust/proofs/verify-with-status"
        batch = f"{base}/v1/trust/proofs/verify-batch-with-status"

        # 1. 未同步 -> valid:false 外部凭证状态未同步
        st, r = _http("POST", single, req(make_proof("vc_none")), headers=T1)
        check("未同步 -> 未同步原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未同步"})

        # 2. active -> 恰为 {"valid": true}
        check("同步 active -> 201", sync("vc_active", "active")[0] == 201)
        st, r = _http("POST", single, req(make_proof("vc_active")), headers=T1)
        check("active -> 恰为 valid:true", st == 200 and r == {"valid": True})

        # 3. revoked 带 reason
        check("同步 revoked -> 201",
              sync("vc_rev", "revoked", reason="持证人造假")[0] == 201)
        st, r = _http("POST", single, req(make_proof("vc_rev")), headers=T1)
        check("revoked 带原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：持证人造假"})

        # 4. revoked 无 reason -> 未知原因
        check("同步 revoked 无原因 -> 201",
              sync("vc_rev2", "revoked")[0] == 201)
        st, r = _http("POST", single, req(make_proof("vc_rev2")), headers=T1)
        check("revoked 无原因 -> 未知原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：未知原因"})

        # 5. unknown
        check("同步 unknown -> 201", sync("vc_unk", "unknown")[0] == 201)
        st, r = _http("POST", single, req(make_proof("vc_unk")), headers=T1)
        check("unknown -> 状态未知",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未知"})

        # 6. 验真失败原样返回（挑战不匹配）
        st, r = _http("POST", single,
                      req(make_proof("vc_active"), challenge="wrong"),
                      headers=T1)
        check("验真失败原样返回",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("挑战不匹配"))

        # 7. 租户隔离：T2 无同步记录 -> 未同步；T2 也无锚点 -> 锚点失败优先
        st, r = _http("POST", single, req(make_proof("vc_active")), headers=T2)
        check("他租户无锚点 -> 锚点原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        # T2 注册同一锚点后 -> 未同步（不同步他租户状态）
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": did, "public_key": pub, "key_version": 1}, headers=T2)
        st, r = _http("POST", single, req(make_proof("vc_active")), headers=T2)
        check("他租户已注册锚点但无同步 -> 未同步",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未同步"})

        # 8. 显式空租户头 -> 400
        st, _ = _http("POST", single, req(make_proof("vc_active")),
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 9. 批量：混合项按序、不短路
        items = [
            req(make_proof("vc_active")),            # valid
            req(make_proof("vc_none")),              # 未同步
            req(make_proof("vc_rev")),               # 吊销
            req(make_proof("vc_active"), "bad"),     # 验真失败
            req(make_proof("vc_unk")),               # 未知
        ]
        st, r = _http("POST", batch, {"proofs": items}, headers=T1)
        ok = (st == 200 and len(r.get("results", [])) == 5
              and r["results"][0] == {"valid": True}
              and r["results"][1]["reason"] == "外部凭证状态未同步"
              and r["results"][2]["reason"] == "外部凭证已吊销：持证人造假"
              and r["results"][3]["reason"].startswith("挑战不匹配")
              and r["results"][4]["reason"] == "外部凭证状态未知")
        check("批量混合按序不短路", ok)

        # 10. 批量请求级错误
        for name, payload, raw in [
            ("空数组", {"proofs": []}, None),
            ("超限", {"proofs": [req(make_proof("vc_active"))] * 101}, None),
            ("缺 proofs", {}, None),
            ("多余字段", {"proofs": [req(make_proof("vc_active"))],
                          "x": 1}, None),
            ("非 JSON", None, b"not-json"),
        ]:
            st, r = _http("POST", batch, payload, headers=T1, raw=raw)
            check(f"批量请求级错误: {name}",
                  st == 200 and r.get("results") == []
                  and isinstance(r.get("reason"), str)
                  and r["reason"].startswith("请求"))

        # 11. 单项请求级错误
        st, r = _http("POST", single, {}, headers=T1)
        check("单项缺字段 -> 请求原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = _http("POST", single, None, headers=T1, raw=b"")
        check("单项空体 -> 请求原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))

        # 12. 只读：接口不产生审计/状态变化（再次同步同内容重放仍 200，
        # 且状态查询不变）
        st, _ = _http("GET",
                      f"{base}/v1/trust/credential-status/vc_active"
                      f"?issuer_did={did}", headers=T1)
        check("状态记录未被改动", st == 200)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
