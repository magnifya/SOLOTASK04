#!/usr/bin/env python3
"""POST /v1/trust/credentials/verify 跨系统凭证验真端到端验证。"""

import base64
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


def check(name, cond, detail=""):
    if cond:
        print(f"PASS {name}")
    else:
        failures.append(name)
        print(f"FAIL {name} {detail}")


def main():
    port = 8953
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    url = f"{base}/v1/trust/credentials/verify"
    try:
        if not wait_up(port):
            print("服务启动失败")
            return 1

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        _, pub_other = gen_keypair()
        did_ext = "did:web:external.example"
        tenant_a = {"X-Tenant-ID": "tenant-a"}

        # 无需登记 DID/凭证：直接注册信任锚点（外部签发者）
        st, resp = _http("POST", f"{base}/v1/trust/anchors",
                         {"did": did_ext, "public_key": pub1,
                          "key_version": 1}, headers=tenant_a)
        check("注册 v1 锚点 201", st == 201, resp)
        st, resp = _http("POST", f"{base}/v1/trust/anchors/did:web:external.example/rotate",
                         {"from_key_version": 1, "public_key": pub2},
                         headers=tenant_a)
        check("轮换 v2 锚点 201", st == 201, resp)

        def make_body(version=None, extra=None):
            body = {
                "credential_id": "vc_external_001",
                "issuer_did": did_ext,
                "subject_did": "did:example:subject",
                "claims": {"role": "admin", "level": 7},
                "issued_at": "2026-09-20T00:00:00Z",
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        def verify_req(body, priv_pem, headers=None, raw=None, sign=True):
            if raw is not None:
                return _http("POST", url, raw=raw, headers=headers)
            sig = crypto.sign(body, priv_pem) if sign else "not-a-signature"
            return _http("POST", url, {"body": body, "signature": sig},
                         headers=headers)

        # ---------- 成功路径 ----------
        body = make_body()
        st, resp = verify_req(body, priv1, headers=tenant_a)
        check("省略 issuer_key_version 按 v1 验签成功",
              st == 200 and resp == {"valid": True}, resp)

        body = make_body(version=1)
        st, resp = verify_req(body, priv1, headers=tenant_a)
        check("显式 v1 验签成功", st == 200 and resp == {"valid": True}, resp)

        body = make_body(version=2)
        st, resp = verify_req(body, priv2, headers=tenant_a)
        check("显式 v2 用轮换后公钥验签成功",
              st == 200 and resp == {"valid": True}, resp)

        # 扩展字段参与签名：携带并正确签名 -> 成功
        body = make_body(extra={"ext_dept": "eng", "ext_nested": {"a": 1}})
        st, resp = verify_req(body, priv1, headers=tenant_a)
        check("扩展字段参与签名仍成功",
              st == 200 and resp == {"valid": True}, resp)

        # 篡改扩展字段（签名仍覆盖原值）-> 签名校验失败
        body = make_body(extra={"ext_dept": "eng"})
        sig = crypto.sign(body, priv1)
        tampered = dict(body)
        tampered["ext_dept"] = "sales"
        st, resp = _http("POST", url,
                         {"body": tampered, "signature": sig},
                         headers=tenant_a)
        check("扩展字段被改动 -> 签名校验失败前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("签名校验失败"), resp)

        # 篡改 claims 内部（签名仍覆盖原 claims）-> 签名校验失败
        body = make_body()
        sig = crypto.sign(body, priv1)
        bad = json.loads(json.dumps(body))
        bad["claims"]["role"] = "root"
        st, resp = _http("POST", url,
                         {"body": bad, "signature": sig},
                         headers=tenant_a)
        check("claims 内部被改动 -> 签名校验失败",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("签名校验失败"), resp)

        # 用其他私钥签名 -> 签名校验失败
        st, resp = verify_req(make_body(), _other_priv(), headers=tenant_a)
        check("非锚点私钥签名 -> 签名校验失败",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("签名校验失败"), resp)

        # 签名格式错误：非法 base64url / 长度不对
        st, resp = _http("POST", url,
                         {"body": make_body(), "signature": "@@@bad@@@"},
                         headers=tenant_a)
        check("非法 base64url -> 签名格式错误前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("签名格式错误"), resp)
        short = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()
        st, resp = _http("POST", url,
                         {"body": make_body(), "signature": short},
                         headers=tenant_a)
        check("32 字节签名 -> 签名格式错误前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("签名格式错误"), resp)

        # ---------- 请求结构错误（前缀“请求”） ----------
        def expect_prefix(name, raw=None, payload=None, prefix="请求"):
            st, resp = _http("POST", url, raw=raw, payload=payload,
                             headers=tenant_a)
            ok = (st == 200 and resp.get("valid") is False
                  and isinstance(resp.get("reason"), str)
                  and resp["reason"].startswith(prefix)
                  and resp["reason"].strip())
            check(name, ok, resp)

        expect_prefix("空请求体", raw=b"")
        expect_prefix("非法 JSON", raw=b"{not json")
        expect_prefix("非法 UTF-8", raw=b'{"body":\xff}')
        expect_prefix("顶层为数组", raw=b"[]")
        expect_prefix("顶层为字符串", raw=b'"x"')
        expect_prefix("缺 body", payload={"signature": "abc"})
        expect_prefix("缺 signature",
                      payload={"body": make_body()})
        expect_prefix("多余字段",
                      payload={"body": make_body(), "signature": "abc",
                               "bogus": 1})
        expect_prefix("body 为数组",
                      payload={"body": [], "signature": "abc"})
        expect_prefix("body 为 null",
                      payload={"body": None, "signature": "abc"})
        expect_prefix("signature 为空串",
                      payload={"body": make_body(), "signature": ""})
        expect_prefix("signature 为数字",
                      payload={"body": make_body(), "signature": 123})

        # ---------- 凭证字段错误（前缀“凭证”） ----------
        def bad_body(mut):
            b = make_body()
            mut(b)
            return {"body": b, "signature": crypto.sign(b, priv1)}

        def drop(key):
            def m(b):
                del b[key]
            return m

        for f in ("credential_id", "issuer_did", "subject_did", "issued_at"):
            st, resp = _http("POST", url, bad_body(drop(f)), headers=tenant_a)
            check(f"缺 {f} -> 凭证前缀",
                  st == 200 and resp.get("valid") is False
                  and resp.get("reason", "").startswith("凭证"), resp)

        st, resp = _http("POST", url, bad_body(lambda b: b.update(claims=[])),
                         headers=tenant_a)
        check("claims 非对象 -> 凭证前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("凭证"), resp)

        st, resp = _http("POST", url,
                         bad_body(lambda b: b.update(credential_id="")),
                         headers=tenant_a)
        check("credential_id 空串 -> 凭证前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("凭证"), resp)

        for badv in (True, 0, -3, 1.5, "1"):
            st, resp = _http(
                "POST", url,
                bad_body(lambda b, v=badv: b.update(issuer_key_version=v)),
                headers=tenant_a)
            check(f"issuer_key_version={badv!r} -> 凭证前缀",
                  st == 200 and resp.get("valid") is False
                  and resp.get("reason", "").startswith("凭证"), resp)

        # ---------- 锚点错误（前缀“锚点”） ----------
        body = make_body()
        body["issuer_did"] = "did:web:unknown.example"
        st, resp = verify_req(body, priv1, headers=tenant_a)
        check("未知签发者 -> 锚点前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("锚点"), resp)

        body = make_body(version=9)
        st, resp = verify_req(body, priv1, headers=tenant_a)
        check("未知版本 -> 锚点前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("锚点"), resp)

        # 吊销 v1 后再验 -> 锚点已吊销
        st, resp = _http("PUT",
                         f"{base}/v1/trust/anchors/{did_ext}/1/status",
                         {"status": "revoked"}, headers=tenant_a)
        check("吊销 v1 200", st == 200, resp)
        st, resp = verify_req(make_body(), priv1, headers=tenant_a)
        check("已吊销锚点 -> 锚点前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("锚点"), resp)
        # v2 仍可验
        st, resp = verify_req(make_body(version=2), priv2, headers=tenant_a)
        check("吊销 v1 不影响 v2 验签",
              st == 200 and resp == {"valid": True}, resp)

        # ---------- 跨租户：使用各自锚点 ----------
        st, resp = verify_req(make_body(version=2), priv2)  # default 租户
        check("default 租户无锚点 -> 锚点前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("锚点"), resp)
        st, resp = _http("POST", f"{base}/v1/trust/anchors",
                         {"did": did_ext, "public_key": pub1,
                          "key_version": 1},
                         headers={"X-Tenant-ID": "tenant-b"})
        check("tenant-b 注册同名 v1 锚点 201", st == 201, resp)
        st, resp = verify_req(make_body(version=1), priv1,
                              headers={"X-Tenant-ID": "tenant-b"})
        check("tenant-b 用各自锚点验签成功",
              st == 200 and resp == {"valid": True}, resp)

        # ---------- 只读：不写凭证、不记审计 ----------
        st, resp = _http("GET", f"{base}/v1/audit?limit=50",
                         headers=tenant_a)
        # 仅锚点注册/轮换/吊销事件，不应出现任何凭证或验真事件
        actions = {e["action"] for e in resp.get("events", [])}
        check("验真不记审计",
              st == 200 and not any(
                  a for a in actions
                  if "credential" in a or a.endswith("verify")),
              actions)
        st, resp = _http("GET",
                         f"{base}/v1/credentials/vc_external_001",
                         headers=tenant_a)
        check("验真不写凭证（GET 404）", st == 404, resp)

        # ---------- 显式空租户头仍 400（不进入验真流程） ----------
        st, resp = _http("POST", url,
                         payload={"body": make_body(), "signature": "x"},
                         headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400, resp)

    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # ---------- 跨重启：锚点持久化后行为不变 ----------
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_up(port):
            print("重启失败")
            return 1
        body = {
            "credential_id": "vc_external_001",
            "issuer_did": did_ext,
            "subject_did": "did:example:subject",
            "claims": {"role": "admin", "level": 7},
            "issued_at": "2026-09-20T00:00:00Z",
            "issuer_key_version": 2,
        }
        st, resp = verify_req(body, priv2,
                              headers={"X-Tenant-ID": "tenant-a"})
        check("重启后 v2 验签仍成功",
              st == 200 and resp == {"valid": True}, resp)
        st, resp = verify_req(make_body(), priv1,
                              headers={"X-Tenant-ID": "tenant-a"})
        check("重启后吊销状态保留 -> 锚点前缀",
              st == 200 and resp.get("valid") is False
              and resp.get("reason", "").startswith("锚点"), resp)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    print()
    if failures:
        print(f"{len(failures)} 项失败: {failures}")
        return 1
    print("全部通过")
    return 0


def _other_priv():
    p, _ = gen_keypair()
    return p


if __name__ == "__main__":
    sys.exit(main())
