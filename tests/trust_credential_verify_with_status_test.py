#!/usr/bin/env python3
"""外部凭证验真并合并状态判定 POST /v1/trust/credentials/verify-with-status。

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
from datetime import datetime, timedelta, timezone
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


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    port = 8954
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/verify-with-status"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"
        T1 = {"X-Tenant-ID": "tvws-a"}
        T2 = {"X-Tenant-ID": "tvws-b"}

        priv1, pub1 = gen_keypair()
        _, pub_other = gen_keypair()
        did = "did:web:ext-ws.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册锚点 -> 201", st == 201)

        def make_body(cred_id="vc_ws", **extra):
            body = {
                "credential_id": cred_id,
                "issuer_did": did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin"},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
            body.update(extra)
            return body

        def call(body, priv=priv1, headers=T1, bad_sig=False):
            sig = crypto.sign(body, priv)
            if bad_sig:
                sig = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
            return _http("POST", f"{base}{path}",
                         {"body": body, "signature": sig}, headers=headers)

        def sync(cred_id, status, reason=_DELETE, updated_at=None):
            sb = {
                "issuer_did": did,
                "credential_id": cred_id,
                "status": status,
                "updated_at": updated_at or utc_z(timedelta(days=-1)),
                "issuer_key_version": 1,
            }
            if reason is not _DELETE:
                sb["reason"] = reason
            return _http("POST",
                         f"{base}/v1/trust/credential-status/sync",
                         {"body": sb, "signature": crypto.sign(sb, priv1)},
                         headers=T1)

        # 显式空租户头在进入验签流程前 400
        st, _ = _http("POST", f"{base}{path}",
                      {"body": {}, "signature": "x"},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 未同步
        st, r = call(make_body("vc_nosync"))
        check("未同步", st == 200
              and r == {"valid": False, "reason": "外部凭证状态未同步"})

        # active
        check("同步 active -> 201", sync("vc_active", "active")[0] == 201)
        st, r = call(make_body("vc_active"))
        check("active 仅返回 valid:true", st == 200 and r == {"valid": True})

        # revoked 带 reason
        check("同步 revoked 带原因 -> 201",
              sync("vc_rev", "revoked", reason="持证人违规")[0] == 201)
        st, r = call(make_body("vc_rev"))
        check("revoked 带保存原因",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部凭证已吊销：持证人违规"})

        # revoked 无 reason
        check("同步 revoked 不带 reason -> 201",
              sync("vc_rev_nr", "revoked")[0] == 201)
        st, r = call(make_body("vc_rev_nr"))
        check("revoked 无原因用未知原因",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部凭证已吊销：未知原因"})

        # unknown
        check("同步 unknown -> 201",
              sync("vc_unk", "unknown")[0] == 201)
        st, r = call(make_body("vc_unk"))
        check("unknown", st == 200
              and r == {"valid": False, "reason": "外部凭证状态未知"})

        # 优先级：请求错误 > 凭证/锚点 > 签名 > 过期 > 状态
        st, r = _http("POST", f"{base}{path}",
                      {"body": {}, "signature": ""}, headers=T1)
        check("请求错误返回 200/请求前缀",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = _http("POST", f"{base}{path}",
                      {"body": make_body("vc_active"), "signature": "x",
                       "extra": 1}, headers=T1)
        check("多余字段 -> 请求前缀",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求"))
        st, r = call(make_body("vc_active"), priv=priv1, bad_sig=True)
        check("签名失败优先于 active 状态",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        body_other = make_body("vc_active")
        st, r = call(body_other, priv=priv1)  # 先用正确签名对照
        check("对照 active 成功", st == 200 and r == {"valid": True})
        # 用他租户视角：锚点不存在，且不能探测他租户已同步状态
        st, r = call(make_body("vc_active"), headers=T2)
        check("他租户无锚点 -> 锚点不存在",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点不存在"))

        # 过期优先于状态判定
        st, r = call(make_body("vc_active", expires_at=utc_z(timedelta(hours=-1))))
        check("已过期优先于 active",
              st == 200 and r == {"valid": False, "reason": "凭证已过期"})
        st, r = call(make_body("vc_active", expires_at=utc_z(timedelta(days=2))))
        check("未到期 active 成功",
              st == 200 and r == {"valid": True})
        st, r = call(make_body("vc_active", expires_at="2030-01-01"))
        check("非法 expires_at 沿用验真原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证字段 expires_at"))

        # 省略 issuer_key_version：按版本 1 且签名覆盖不含该字段的 body
        body_no_ver = {k: v for k, v in make_body("vc_active").items()
                       if k != "issuer_key_version"}
        sig = crypto.sign(body_no_ver, priv1)
        st, r = _http("POST", f"{base}{path}",
                      {"body": body_no_ver, "signature": sig}, headers=T1)
        check("省略版本按 1 验签 + active",
              st == 200 and r == {"valid": True})
        injected = dict(body_no_ver, issuer_key_version=1)
        st, r = _http("POST", f"{base}{path}",
                      {"body": body_no_ver,
                       "signature": crypto.sign(injected, priv1)},
                      headers=T1)
        check("注入版本签名不能通过",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # 扩展字段参与签名
        body_ext = make_body("vc_active", ext_a="x", ext_b=[1, 2])
        st, r = call(body_ext)
        check("扩展字段随验真通过且 active",
              st == 200 and r == {"valid": True})

        # 只读：不新增审计、不改变同步记录
        _, before = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                          headers=T1)
        for cid in ("vc_active", "vc_nosync", "vc_rev", "vc_unk"):
            call(make_body(cid))
        _, after_pages = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                               headers=T1)
        check("只读：不新增审计",
              len(before.get("events", []))
              == len(after_pages.get("events", [])))
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/vc_rev?issuer_did={did}",
            headers=T1)
        check("同步记录保持不变",
              st == 200 and r.get("status") == "revoked"
              and r.get("reason") == "持证人违规")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 重启持久化：同一状态文件新起服务，revoked 结论与原因保持一致。
    port2 = port + 100
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port2), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base2 = f"http://127.0.0.1:{port2}"
    try:
        assert wait_up(port2), "重启服务启动超时"
        body = make_body("vc_rev")
        sig = crypto.sign(body, priv1)
        st, r = _http("POST", f"{base2}{path}",
                      {"body": body, "signature": sig}, headers=T1)
        check("重启后 revoked 结论持久化",
              st == 200 and r == {
                  "valid": False,
                  "reason": "外部凭证已吊销：持证人违规"})
        body_act = make_body("vc_active")
        st, r = _http("POST", f"{base2}{path}",
                      {"body": body_act, "signature": crypto.sign(body_act, priv1)},
                      headers=T1)
        check("重启后 active 结论持久化",
              st == 200 and r == {"valid": True})
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


_DELETE = object()


if __name__ == "__main__":
    main()
