#!/usr/bin/env python3
"""外部谓词证明验真并合并同步状态：

- POST /v1/trust/proofs/verify-with-status
- POST /v1/trust/proofs/verify-batch-with-status

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
    port = 8961
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify_status(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}/v1/trust/proofs/verify-with-status",
                     payload, headers=headers, raw=raw)

    def verify_batch_status(payload=None, headers=None, raw=None):
        return _http(
            "POST", f"{base}/v1/trust/proofs/verify-batch-with-status",
            payload, headers=headers, raw=raw)

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tps-a"}
        T2 = {"X-Tenant-ID": "tps-b"}

        priv1, pub1 = gen_keypair()
        did = "did:web:proof-status.example"
        cred_id = "vc_proof_status_1"

        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册锚点 -> 201", st == 201)

        def make_proof(credential_id=cred_id, challenge="chal-s"):
            return {
                "proof_id": "zp_" + "b" * 32,
                "credential_id": credential_id,
                "issuer_did": did,
                "issuer_key_version": 1,
                "predicates": [{"path": "/age", "op": "gte", "value": 18}],
                "results": [True],
                "challenge": challenge,
                "expires_at": "2099-01-01T00:00:00Z",
            }

        def sign_proof(p, source="source-tenant"):
            message = dict(p)
            message["tenant_id"] = source
            p["proof"] = crypto.sign(message, priv1)
            return p

        def req(p, challenge="chal-s", source="source-tenant"):
            return {"proof": p, "challenge": challenge,
                    "source_tenant_id": source}

        def sync_status(status, reason=None, credential_id=cred_id,
                        updated="2026-09-21T00:00:00Z", headers=T1):
            body = {
                "issuer_did": did,
                "credential_id": credential_id,
                "status": status,
                "updated_at": updated,
                "issuer_key_version": 1,
            }
            if reason is not None:
                body["reason"] = reason
            payload = {"body": body, "signature": crypto.sign(body, priv1)}
            return _http("POST", f"{base}/v1/trust/credential-status/sync",
                         payload, headers=headers)

        # ---- 单项 /v1/trust/proofs/verify-with-status ----

        # 1. 验真失败原样返回（挑战不匹配），不进入状态合并
        st, r = verify_status(req(sign_proof(make_proof()),
                                  challenge="other"), headers=T1)
        check("验真失败原样返回（挑战不匹配）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("挑战不匹配"))

        # 2. 验真通过但未同步
        st, r = verify_status(req(sign_proof(make_proof())), headers=T1)
        check("验真通过但未同步 -> 外部凭证状态未同步",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未同步"})

        # 3. 同步 active -> 仅 {"valid": true}
        st, _ = sync_status("active")
        check("同步 active -> 201", st == 201)
        st, r = verify_status(req(sign_proof(make_proof())), headers=T1)
        check("active -> 仅 {\"valid\": true}",
              st == 200 and r == {"valid": True})

        # 4. 同步 revoked（带 reason）
        st, _ = sync_status("revoked", reason="密钥泄漏",
                            updated="2026-09-22T00:00:00Z")
        check("同步 revoked -> 200", st == 200)
        st, r = verify_status(req(sign_proof(make_proof())), headers=T1)
        check("revoked -> 外部凭证已吊销：<reason>",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：密钥泄漏"})

        # 5. 同步 revoked（无 reason）-> 未知原因（用另一 credential_id）
        st, _ = sync_status("revoked", credential_id="vc_no_reason")
        check("同步 revoked 无 reason -> 201", st == 201)
        st, r = verify_status(
            req(sign_proof(make_proof(credential_id="vc_no_reason"))),
            headers=T1)
        check("revoked 无 reason -> 未知原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：未知原因"})

        # 6. 同步 unknown
        st, _ = sync_status("unknown", credential_id="vc_unknown")
        check("同步 unknown -> 201", st == 201)
        st, r = verify_status(
            req(sign_proof(make_proof(credential_id="vc_unknown"))),
            headers=T1)
        check("unknown -> 外部凭证状态未知",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未知"})

        # 7. 租户隔离：T2 未同步
        st, r = verify_status(req(sign_proof(make_proof())), headers=T2)
        check("他租户未同步 -> 锚点不存在（验真阶段失败）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点不存在"))

        # 8. 请求级错误与单项 verify 一致（200 + valid:false）
        st, r = verify_status(raw=b"", headers=T1)
        check("空请求体 -> 200 valid:false", st == 200
              and r.get("valid") is False and r.get("reason"))
        st, r = verify_status(payload={"proof": {}}, headers=T1)
        check("缺字段 -> 200 valid:false", st == 200
              and r.get("valid") is False
              and r.get("reason", "").startswith("请求缺少字段"))

        # 9. 显式空租户头 400
        st, _ = verify_status(req(sign_proof(make_proof())),
                              headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # ---- 批量 /v1/trust/proofs/verify-batch-with-status ----

        # 10. 混合批次：active / revoked / 未同步 / 验真失败，按序不短路
        st, _ = sync_status("active", credential_id="vc_active")
        check("同步 vc_active active -> 201", st == 201)
        items = [
            req(sign_proof(make_proof(credential_id="vc_active"))),  # active
            req(sign_proof(make_proof(credential_id="vc_no_reason"))),  # revoked
            req(sign_proof(make_proof(credential_id="vc_unknown"))),  # unknown
            req(sign_proof(make_proof(credential_id="vc_never"))),    # 未同步
            req(sign_proof(make_proof()), challenge="bad"),           # 验真失败
        ]
        st, r = verify_batch_status({"proofs": items}, headers=T1)
        results = r.get("results")
        check("混合批次 -> 200 且等长同序",
              st == 200 and isinstance(results, list) and len(results) == 5)
        check("批次[0] active -> valid:true", results[0] == {"valid": True})
        check("批次[1] revoked 未知原因",
              results[1] == {"valid": False,
                             "reason": "外部凭证已吊销：未知原因"})
        check("批次[2] unknown",
              results[2] == {"valid": False, "reason": "外部凭证状态未知"})
        check("批次[3] 未同步",
              results[3] == {"valid": False, "reason": "外部凭证状态未同步"})
        check("批次[4] 验真失败原样返回",
              results[4].get("valid") is False
              and results[4].get("reason", "").startswith("挑战不匹配"))

        # 11. 请求级错误：{"results": [], "reason": "请求..."}
        st, r = verify_batch_status({"proofs": []}, headers=T1)
        check("空数组 -> results 空 + 请求原因",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求"))
        st, r = verify_batch_status({"proofs": [req(sign_proof(make_proof()))] * 101},
                                    headers=T1)
        check("超过 100 项 -> 请求级失败",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求"))
        st, r = verify_batch_status(raw=b"not-json", headers=T1)
        check("非法 JSON -> 请求级失败",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求"))
        st, r = verify_batch_status({"proofs": items, "extra": 1}, headers=T1)
        check("多余字段 -> 请求级失败",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求含多余字段"))

        # 12. 缺省租户头可用（default 租户未同步该锚点 -> 验真失败）
        st, r = verify_status(req(sign_proof(make_proof())))
        check("缺省 X-Tenant-ID -> default 租户",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点不存在"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    if failures:
        print(f"\n{len(failures)} 项失败")
        return 1
    print("\n全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
