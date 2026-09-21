#!/usr/bin/env python3
"""外部凭证验真+状态判定 POST /v1/trust/credentials/verify-with-status
的端到端测试。

直接运行：python3 tests/trust_credential_verify_with_status_test.py
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

PATH = "/v1/trust/credentials/verify-with-status"
SYNC_PATH = "/v1/trust/credential-status/sync"


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


def start_server(port, env):
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc


def main():
    port = 8961
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = start_server(port, env)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{PATH}", payload, headers=headers,
                     raw=raw)

    def sync_status(cred_id, status, updated_at, priv, reason=None,
                    headers=None, did=None):
        body = {
            "issuer_did": did or DID,
            "credential_id": cred_id,
            "status": status,
            "updated_at": updated_at,
            "issuer_key_version": 1,
        }
        if reason is not None:
            body["reason"] = reason
        sig = crypto.sign(body, priv)
        return _http("POST", f"{base}{SYNC_PATH}",
                     {"body": body, "signature": sig}, headers=headers)

    def cred_body(cred_id, extra=None):
        body = {
            "credential_id": cred_id,
            "issuer_did": DID,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        if extra:
            body.update(extra)
        return body

    def signed(cred_id, priv, extra=None):
        body = cred_body(cred_id, extra=extra)
        return body, crypto.sign(body, priv)

    DID = "did:web:external.example"
    T1 = {"X-Tenant-ID": "tcvs-a"}
    T2 = {"X-Tenant-ID": "tcvs-b"}
    priv1, pub1 = gen_keypair()

    try:
        assert wait_up(port), "服务启动超时"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify({"body": {}, "signature": "x"},
                       headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": DID, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册外部锚点 v1 -> 201", st == 201)

        cred1 = "vc_ws_0001"

        # 1. 验签通过但未同步 -> 外部凭证状态未同步
        body, sig = signed(cred1, priv1)
        st, r = verify({"body": body, "signature": sig}, headers=T1)
        check("验签通过但未同步 -> 状态未同步",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证状态未同步")

        # 2. 请求/验真失败保持既有优先级（先于状态判定）
        st, r = verify(raw=b"", headers=T1)
        check("空请求体 -> 请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = verify(raw=b"not-json", headers=T1)
        check("非法 JSON -> 请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = verify({"body": body}, headers=T1)
        check("缺 signature -> 请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = verify({"body": body, "signature": sig, "extra": 1},
                       headers=T1)
        check("多余字段 -> 请求类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = verify({"body": body, "signature": "!!!bad!!!"}, headers=T1)
        check("签名格式错误保持原协议",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名格式错误"))

        # 3. 同步 active -> 仅 {"valid": true}
        st, _ = sync_status(cred1, "active", "2026-09-20T00:00:00Z", priv1,
                            headers=T1)
        check("同步 active -> 201", st == 201)
        st, r = verify({"body": body, "signature": sig}, headers=T1)
        check("active -> 仅返回 valid:true",
              st == 200 and r == {"valid": True})

        # 4. 严格更新为 revoked（带 reason）
        st, _ = sync_status(cred1, "revoked", "2026-09-21T00:00:00Z", priv1,
                            reason="密钥已泄露", headers=T1)
        check("更新为 revoked -> 200", st == 200)
        st, r = verify({"body": body, "signature": sig}, headers=T1)
        check("revoked -> 外部凭证已吊销：保存原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证已吊销：密钥已泄露")

        # 5. revoked 无 reason -> 未知原因
        cred2 = "vc_ws_0002"
        body2, sig2 = signed(cred2, priv1)
        st, _ = sync_status(cred2, "revoked", "2026-09-20T00:00:00Z", priv1,
                            headers=T1)
        check("同步 revoked（无 reason）-> 201", st == 201)
        st, r = verify({"body": body2, "signature": sig2}, headers=T1)
        check("revoked 无 reason -> 未知原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证已吊销：未知原因")

        # 6. unknown -> 外部凭证状态未知
        cred3 = "vc_ws_0003"
        body3, sig3 = signed(cred3, priv1)
        st, _ = sync_status(cred3, "unknown", "2026-09-20T00:00:00Z", priv1,
                            headers=T1)
        check("同步 unknown -> 201", st == 201)
        st, r = verify({"body": body3, "signature": sig3}, headers=T1)
        check("unknown -> 外部凭证状态未知",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证状态未知")

        # 7. 验真失败优先于状态判定：已同步 active 的凭证被篡改仍报验签
        cred4 = "vc_ws_0004"
        body4, sig4 = signed(cred4, priv1)
        st, _ = sync_status(cred4, "active", "2026-09-20T00:00:00Z", priv1,
                            headers=T1)
        check("同步 cred4 active -> 201", st == 201)
        tampered = json.loads(json.dumps(body4))
        tampered["claims"]["role"] = "root"
        st, r = verify({"body": tampered, "signature": sig4}, headers=T1)
        check("篡改已同步凭证 -> 签名校验失败（先于状态）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 过期优先于状态判定
        body_exp, sig_exp = signed(
            cred4, priv1, extra={"expires_at": "2020-01-01T00:00:00Z"}
        )
        st, r = verify({"body": body_exp, "signature": sig_exp}, headers=T1)
        check("已过期 -> 凭证已过期（先于状态）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已过期")

        # 8. 只读：不登记凭证、不改同步记录、不记审计
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify({"body": body, "signature": sig}, headers=T1)
            verify({"body": body3, "signature": sig3}, headers=T1)
            verify({"body": tampered, "signature": sig4}, headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("合并查询不记审计", len(after["events"]) == n_before)
        st, _ = _http("GET", f"{base}/v1/credentials/{cred1}", headers=T1)
        check("合并查询不登记本地凭证", st == 404)
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/{cred1}?issuer_did={DID}",
            headers=T1,
        )
        check("合并查询不改同步记录",
              st == 200 and r.get("status") == "revoked"
              and r.get("reason") == "密钥已泄露")

        # 9. 租户隔离：T2 有锚点但无同步记录 -> 状态未同步；
        #    缺省 default 租户无锚点 -> 锚点不存在
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": DID, "public_key": pub1, "key_version": 1},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        st, r = verify({"body": body, "signature": sig}, headers=T2)
        check("T2 无同步记录 -> 状态未同步",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证状态未同步")
        st, r = verify({"body": body, "signature": sig})
        check("缺省 default 租户 -> 锚点不存在",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 10. 重启持久化：同步记录与锚点保留，状态判定结果不变
    proc = start_server(port, env)
    try:
        assert wait_up(port), "服务重启超时"
        st, r = verify({"body": body, "signature": sig}, headers=T1)
        check("重启后 revoked 判定保留",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证已吊销：密钥已泄露")
        st, r = verify({"body": body3, "signature": sig3}, headers=T1)
        check("重启后 unknown 判定保留",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证状态未知")
        cred5 = "vc_ws_0005"
        body5, sig5 = signed(cred5, priv1)
        st, r = verify({"body": body5, "signature": sig5}, headers=T1)
        check("重启后未同步凭证仍报未同步",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部凭证状态未同步")
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
