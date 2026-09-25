#!/usr/bin/env python3
"""信任锚点用途白名单（uses）的端到端测试。

直接运行：python3 tests/trust_anchor_uses_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]


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
    port = 8959
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

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "uses-a"}
        T2 = {"X-Tenant-ID": "uses-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:example.com:uses"

        # 1. 省略 uses 注册 -> 201，响应不增键
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("省略 uses 注册 201", st == 201)
        check("201 响应不增键",
              r == {"did": did, "public_key": pub1, "key_version": 1,
                    "status": "active", "updated_at": None})

        # 2. 省略 uses 的锚点为全用途
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/1/uses",
                      headers=T1)
        check("GET uses 200", st == 200)
        check("GET uses 恰返 did/key_version/uses 且全用途",
              r == {"did": did, "key_version": 1, "uses": ALL_USES})
        check("GET uses 键序", list(r) == ["did", "key_version", "uses"])

        # 3. 省略注册的锚点 + 显式全用途重放 -> 幂等 200（等价）
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1,
                       "uses": ALL_USES}, headers=T1)
        check("省略后显式全用途重放 -> 200", st == 200)
        check("200 响应不增键",
              r == {"did": did, "public_key": pub1, "key_version": 1,
                    "status": "active", "updated_at": None})

        # 4. 显式全用途后省略重放 -> 幂等 200
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("显式全用途后省略重放 -> 200", st == 200)

        # 5. 同锚点不同 uses -> 409
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1,
                       "uses": ["generic"]}, headers=T1)
        check("同锚点不同 uses -> 409", st == 409)
        check("409 仅含非空中文 error",
              set(r) == {"error"} and isinstance(r["error"], str)
              and bool(r["error"]))

        # 6. 带 uses 注册 -> 201，响应不增键
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2,
                       "uses": ["generic", "vc"]}, headers=T1)
        check("带 uses 注册 201", st == 201)
        check("带 uses 201 响应不增键",
              r == {"did": did, "public_key": pub2, "key_version": 2,
                    "status": "active", "updated_at": None})

        # 7. 相同 uses 幂等 200
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2,
                       "uses": ["generic", "vc"]}, headers=T1)
        check("相同 uses 幂等 200", st == 200)

        # 8. 不同 uses 409；PEM 不同也 409
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2,
                       "uses": ["vc"]}, headers=T1)
        check("uses 子集不同 -> 409", st == 409)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2,
                       "uses": ["generic", "vc"]}, headers=T1)
        check("PEM 不同 -> 409", st == 409)

        # 9. GET uses 返回注册时的规范序
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/2/uses",
                      headers=T1)
        check("GET uses 返回注册用途",
              r == {"did": did, "key_version": 2,
                    "uses": ["generic", "vc"]})

        # 10. uses 非法一律 400 且仅含非空中文 error
        bad_uses = [
            None,                        # 显式 null
            "generic",                   # 非数组
            [],                          # 空数组
            [1],                         # 非字符串元素
            ["generic", "generic"],      # 重复
            ["all"],                     # 非法值
            ["vc", "generic"],           # 非规范序
            ["generic", "ALL"],          # 大小写非法
            [""],                        # 空串非法值
        ]
        for i, bad in enumerate(bad_uses):
            st, r = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": f"did:web:bad{i}", "public_key": pub1,
                           "key_version": 1, "uses": bad}, headers=T1)
            check(f"非法 uses[{i}] -> 400", st == 400)
            check(f"非法 uses[{i}] 仅含非空中文 error",
                  set(r) == {"error"} and isinstance(r["error"], str)
                  and bool(r["error"]))

        # 11. 非法 uses 不写入：随后省略 uses 注册同键应 201
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "did:web:bad0", "public_key": pub1,
                       "key_version": 1}, headers=T1)
        check("非法 uses 不写入", st == 201)

        # 12. GET uses 版本参数非法 -> 400
        for bad_ver in ["0", "-1", "1.0", "abc", "", "１２", "+1", " 1"]:
            st, r = _http("GET",
                          f"{base}/v1/trust/anchors/{did}/"
                          f"{urllib.parse.quote(bad_ver)}/uses",
                          headers=T1)
            check(f"GET uses 版本 {bad_ver!r} -> 400", st == 400)
            check(f"GET uses 版本 {bad_ver!r} 仅含 error",
                  set(r) == {"error"} and bool(r.get("error")))

        # 13. GET uses 未知/跨租户 -> 404
        st, _ = _http("GET", f"{base}/v1/trust/anchors/{did}/99/uses",
                      headers=T1)
        check("未知版本 -> 404", st == 404)
        st, _ = _http("GET", f"{base}/v1/trust/anchors/did:web:none/1/uses",
                      headers=T1)
        check("未知 DID -> 404", st == 404)
        st, _ = _http("GET", f"{base}/v1/trust/anchors/{did}/1/uses",
                      headers=T2)
        check("跨租户 -> 404", st == 404)

        # 14. 轮换继承前置 uses
        st, r = _http("POST", f"{base}/v1/trust/anchors/{did}/rotate",
                      {"from_key_version": 2, "public_key": pub1},
                      headers=T1)
        check("轮换 201", st == 201 and r["key_version"] == 3)
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/3/uses",
                      headers=T1)
        check("轮换继承前置 uses",
              r == {"did": did, "key_version": 3,
                    "uses": ["generic", "vc"]})

        # 15. 用途门控：uses=["generic","vc"] 的锚点（版本 2/3）
        #     generic 入口可用，vp/proof/did/status/deactivation 不可用
        message = {"issuer_did": did, "issuer_key_version": 3,
                   "nonce": "n1"}
        sig = crypto.sign(message, priv1)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": sig}, headers=T1)
        check("generic 用途锚点过 generic 入口", r.get("valid") is True)

        # vc 入口（凭证验真）：版本 2 锚点 uses 含 vc -> 可验
        body = {"credential_id": "cred-u1", "issuer_did": did,
                "subject_did": "did:web:sub", "claims": {"a": 1},
                "issued_at": "2026-01-01T00:00:00Z",
                "issuer_key_version": 2}
        sig = crypto.sign(body, priv2)
        st, r = _http("POST", f"{base}/v1/trust/credentials/verify",
                      {"body": body, "signature": sig}, headers=T1)
        check("vc 用途锚点过 vc 入口", r.get("valid") is True)

        # vp 入口：同一锚点无 vp 用途 -> 锚点不可用（按锚点不存在）
        pres = {"presentation_id": "p1", "credential_id": "cred-u1",
                "issuer_did": did, "issuer_key_version": 2,
                "disclose": [], "claims": {"a": 1}, "challenge": "c1",
                "expires_at": "2030-01-01T00:00:00Z", "proof": "x"}
        st, r = _http("POST", f"{base}/v1/trust/presentations/verify",
                      {"presentation": pres, "challenge": "c1"}, headers=T1)
        check("无 vp 用途 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        check("无 vp 用途按锚点不存在",
              r.get("reason") == f"锚点不存在: {did}#2")

        # generic 入口：版本 1 全用途锚点签名但版本 2 锚点无 generic? 有。
        # 用仅 vc 用途锚点验证 generic 拒绝：
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "did:web:vc-only", "public_key": pub2,
                       "key_version": 1, "uses": ["vc"]}, headers=T1)
        check("注册 vc-only 锚点 201", st == 201)
        message = {"issuer_did": "did:web:vc-only", "issuer_key_version": 1}
        sig = crypto.sign(message, priv2)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": sig}, headers=T1)
        check("vc-only 锚点过 generic 入口被拒",
              r.get("valid") is False
              and r.get("reason") == "信任锚点不存在: did:web:vc-only#1")

        # did 入口：verify-document 用 vc-only 锚点 -> 锚点不存在
        doc = {"did": "did:web:vc-only", "current_key_version": 1,
               "verification_methods": [
                   {"key_version": 1, "key_handle": "k1",
                    "public_key": pub2}],
               "document_proof": "x"}
        st, r = _http("POST", f"{base}/v1/trust/dids/verify-document",
                      {"document": doc}, headers=T1)
        check("vc-only 锚点过 did 入口被拒",
              r.get("valid") is False
              and r.get("reason") == "锚点不存在: did:web:vc-only#1")

        # status 入口：credential-status/sync 用 vc-only 锚点 -> 锚点不存在
        sync_body = {"issuer_did": "did:web:vc-only",
                     "credential_id": "cred-s1", "status": "revoked",
                     "updated_at": "2026-01-01T00:00:00Z",
                     "issuer_key_version": 1}
        sig = crypto.sign(sync_body, priv2)
        st, r = _http("POST", f"{base}/v1/trust/credential-status/sync",
                      {"body": sync_body, "signature": sig}, headers=T1)
        check("vc-only 锚点过 status 入口被拒",
              r.get("valid") is False
              and r.get("reason") == "锚点不存在: did:web:vc-only#1")

        # deactivation 入口：deactivate-sync 用 vc-only 锚点 -> 锚点不可用
        deact_body = {"did": "did:web:vc-only", "key_version": 1,
                      "reason": "测试",
                      "deactivated_at": "2026-01-01T00:00:00Z"}
        sig = crypto.sign(deact_body, priv2)
        st, r = _http("POST", f"{base}/v1/trust/dids/deactivate-sync",
                      {"body": deact_body, "signature": sig}, headers=T1)
        check("vc-only 锚点过 deactivation 入口被拒",
              r.get("valid") is False
              and r.get("reason") == "锚点不可用")

        # 较早错误优先：请求体非法时即使锚点无用途也先报请求错误
        st, r = _http("POST", f"{base}/v1/trust/credentials/verify",
                      {"body": {"issuer_did": "did:web:vc-only"},
                       "signature": "x"}, headers=T1)
        check("较早错误优先（字段缺失先于用途检查）",
              r.get("valid") is False
              and r.get("reason", "").startswith("凭证缺少字段"))

        # 16. 失败不写入：deactivation 被拒后未登记通告
        st, r = _http("GET", f"{base}/v1/trust/dids/deactivations",
                      headers=T1)
        check("deactivation 被拒不写入",
              st == 200 and r.get("events") == [])

        # 17. 吊销锚点的 uses 仍可查
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/2/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 200", st == 200)
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/2/uses",
                      headers=T1)
        check("吊销后 uses 仍可查",
              r == {"did": did, "key_version": 2,
                    "uses": ["generic", "vc"]})

        # 18. 其他接口响应不变：GET 锚点列表不含 uses 键
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        check("锚点列表不增键",
              all(set(item) == {"did", "public_key", "key_version",
                                "status", "updated_at"} for item in r))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 19. 重启后 uses 稳定
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/3/uses",
                      headers=T1)
        check("重启后 uses 稳定",
              r == {"did": did, "key_version": 3,
                    "uses": ["generic", "vc"]})
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}/1/uses",
                      headers=T1)
        check("重启后全用途稳定",
              r == {"did": did, "key_version": 1, "uses": ALL_USES})
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
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
    sys.exit(main())
