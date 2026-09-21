#!/usr/bin/env python3
"""跨系统持有者绑定演示验真 POST /v1/trust/presentations/verify 端到端测试。

直接运行：python3 tests/trust_presentation_verify_holder_binding_test.py
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


ISSUER_DID = "did:web:external-issuer.example"
HOLDER_DID = "did:web:external-holder.example"
SOURCE_TENANT = "tenant-source-1"


def make_bound_presentation(challenge="chal-1",
                            expires_at="2099-01-01T00:00:00Z"):
    return {
        "presentation_id": "vp_" + "b" * 32,
        "credential_id": "vc_external_0002",
        "issuer_did": ISSUER_DID,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin"},
        "challenge": challenge,
        "expires_at": expires_at,
        "holder_did": HOLDER_DID,
        "holder_key_version": 1,
    }


def sign_bound(p, issuer_priv, holder_priv, tenant_id=SOURCE_TENANT):
    """issuer proof 不覆盖 holder_*；holder_proof 覆盖去掉 proof、
    holder_proof 的绑定对象并加入 tenant_id。"""
    issuer_msg = {k: v for k, v in p.items()
                  if k != "proof" and not k.startswith("holder_")}
    p["proof"] = crypto.sign(issuer_msg, issuer_priv)
    holder_msg = {k: v for k, v in p.items()
                  if k not in ("proof", "holder_proof")}
    holder_msg["tenant_id"] = tenant_id
    p["holder_proof"] = crypto.sign(holder_msg, holder_priv)
    return p


def main():
    port = 8955
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/presentations/verify"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload, headers=headers,
                     raw=raw)

    def invalid_with_prefix(name, prefix, payload=None, raw=None,
                            headers=None):
        st, r = verify(payload=payload, raw=raw, headers=headers)
        check(
            name,
            st == 200
            and r.get("valid") is False
            and isinstance(r.get("reason"), str)
            and r["reason"]
            and r["reason"].startswith(prefix),
        )

    issuer_priv, issuer_pub = gen_keypair()
    holder_priv, holder_pub = gen_keypair()
    other_priv, _ = gen_keypair()
    T1 = {"X-Tenant-ID": "tpvb-a"}
    T2 = {"X-Tenant-ID": "tpvb-b"}

    try:
        assert wait_up(port), "服务启动超时"

        # 显式空租户头仍按通用协议 400
        st, _ = verify(
            payload={"presentation": {}, "challenge": "x",
                     "source_tenant_id": SOURCE_TENANT},
            headers={"X-Tenant-ID": ""},
        )
        check("绑定请求显式空 X-Tenant-ID -> 400", st == 400)

        # 注册签发者与持有者锚点（均用验证租户 T1 的锚点）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": issuer_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": holder_pub,
                       "key_version": 1}, headers=T1)
        check("注册持有者锚点 -> 201", st == 201)

        def good(**kw):
            return sign_bound(make_bound_presentation(**kw),
                              issuer_priv, holder_priv)

        def good_request(**kw):
            return {"presentation": good(**kw), "challenge": "chal-1",
                    "source_tenant_id": SOURCE_TENANT}

        # 1. 成功：响应恰为 {"valid": true}
        st, r = verify(good_request(), headers=T1)
        check("绑定演示验签成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})

        pres = good()

        # 2. 请求结构错误（前缀“请求”）
        invalid_with_prefix(
            "绑定缺 challenge", "请求",
            {"presentation": pres, "source_tenant_id": SOURCE_TENANT},
            headers=T1)
        invalid_with_prefix(
            "绑定缺 presentation", "请求",
            {"challenge": "chal-1", "source_tenant_id": SOURCE_TENANT},
            headers=T1)
        invalid_with_prefix(
            "绑定含多余字段", "请求",
            {"presentation": pres, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT, "extra": 1}, headers=T1)
        invalid_with_prefix(
            "source_tenant_id 为空串", "请求",
            {"presentation": pres, "challenge": "chal-1",
             "source_tenant_id": ""}, headers=T1)
        invalid_with_prefix(
            "source_tenant_id 为数字", "请求",
            {"presentation": pres, "challenge": "chal-1",
             "source_tenant_id": 7}, headers=T1)
        invalid_with_prefix(
            "source_tenant_id 为 null", "请求",
            {"presentation": pres, "challenge": "chal-1",
             "source_tenant_id": None}, headers=T1)

        # 3. 演示字段错误（前缀“演示”）
        unbound = {k: v for k, v in pres.items()
                   if not k.startswith("holder_")}
        invalid_with_prefix(
            "绑定请求配未绑定九字段演示", "演示",
            {"presentation": unbound, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        for field in ("holder_did", "holder_key_version", "holder_proof"):
            p = dict(pres)
            p.pop(field)
            invalid_with_prefix(
                f"绑定演示缺 {field}", "演示",
                {"presentation": p, "challenge": "chal-1",
                 "source_tenant_id": SOURCE_TENANT}, headers=T1)
        p = dict(pres)
        p["holder_extra"] = "x"
        invalid_with_prefix(
            "绑定演示含多余 holder 字段", "演示",
            {"presentation": p, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        for bad, label in [("", "空串"), (123, "数字"), (None, "null")]:
            p = dict(pres)
            p["holder_did"] = bad
            invalid_with_prefix(
                f"holder_did 非法（{label}）", "演示",
                {"presentation": p, "challenge": "chal-1",
                 "source_tenant_id": SOURCE_TENANT}, headers=T1)
        for bad, label in [(True, "布尔"), (0, "零"), (-1, "负数"),
                           (1.5, "小数"), ("1", "字符串")]:
            p = dict(pres)
            p["holder_key_version"] = bad
            invalid_with_prefix(
                f"holder_key_version 非法（{label}）", "演示",
                {"presentation": p, "challenge": "chal-1",
                 "source_tenant_id": SOURCE_TENANT}, headers=T1)
        for bad, label in [("", "空串"), (123, "数字")]:
            p = dict(pres)
            p["holder_proof"] = bad
            invalid_with_prefix(
                f"holder_proof 非法（{label}）", "演示",
                {"presentation": p, "challenge": "chal-1",
                 "source_tenant_id": SOURCE_TENANT}, headers=T1)

        # 4. 挑战不匹配（前缀“挑战”）
        invalid_with_prefix(
            "绑定请求 challenge 与演示不一致", "挑战",
            {"presentation": pres, "challenge": "chal-2",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)

        # 5. 两类锚点区分
        p = sign_bound(make_bound_presentation(), issuer_priv, holder_priv)
        p["issuer_did"] = "did:web:unknown-issuer.example"
        p["proof"] = crypto.sign(
            {k: v for k, v in p.items()
             if k != "proof" and not k.startswith("holder_")}, issuer_priv)
        invalid_with_prefix(
            "签发者锚点不存在", "锚点不存在",
            {"presentation": p, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        p = sign_bound(make_bound_presentation(), issuer_priv, holder_priv)
        p["holder_did"] = "did:web:unknown-holder.example"
        holder_msg = {k: v for k, v in p.items()
                      if k not in ("proof", "holder_proof")}
        holder_msg["tenant_id"] = SOURCE_TENANT
        p["holder_proof"] = crypto.sign(holder_msg, holder_priv)
        st, r = verify({"presentation": p, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("持有者锚点不存在（区别于签发者锚点）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("持有者锚点不存在"))
        # 吊销用例使用独立持有者 DID（吊销单向，不影响后续用例）
        REVOKED_HOLDER_DID = "did:web:revoked-holder.example"
        revoked_priv, revoked_pub = gen_keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": REVOKED_HOLDER_DID, "public_key": revoked_pub,
                       "key_version": 1}, headers=T1)
        check("注册待吊销持有者锚点 -> 201", st == 201)
        st, _ = _http(
            "PUT",
            f"{base}/v1/trust/anchors/{REVOKED_HOLDER_DID}/1/status",
            {"status": "revoked"}, headers=T1)
        check("吊销持有者锚点 -> 200", st == 200)
        p = make_bound_presentation()
        p["holder_did"] = REVOKED_HOLDER_DID
        sign_bound(p, issuer_priv, revoked_priv)
        st, r = verify({"presentation": p, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("持有者锚点已吊销",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("持有者锚点已吊销"))
        # 顺序：签发者签名失败优先于持有者锚点缺失
        p = sign_bound(make_bound_presentation(), issuer_priv, holder_priv)
        p["holder_did"] = "did:web:unknown-holder.example"
        p["proof"] = "!!!bad!!!"
        invalid_with_prefix(
            "签发者签名格式优先于持有者锚点", "签名格式错误",
            {"presentation": p, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)

        # 6. 两类签名区分
        p = dict(good())
        p["proof"] = "!!!bad!!!"
        invalid_with_prefix(
            "绑定演示 issuer proof 格式错误", "签名格式错误",
            {"presentation": p, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        p = good()
        p["holder_proof"] = "!!!bad!!!"
        st, r = verify({"presentation": p, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("holder_proof 格式错误（区别于 issuer）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名格式错误: holder_proof"))
        p = good()
        p["claims"] = {"role": "user"}  # 篡改 issuer 覆盖内容
        invalid_with_prefix(
            "篡改 issuer 覆盖内容", "签名校验失败",
            {"presentation": p, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        # 错误持有者私钥签名
        p = make_bound_presentation()
        issuer_msg = {k: v for k, v in p.items()
                      if k != "proof" and not k.startswith("holder_")}
        p["proof"] = crypto.sign(issuer_msg, issuer_priv)
        holder_msg = dict(p)
        holder_msg["tenant_id"] = SOURCE_TENANT
        p["holder_proof"] = crypto.sign(holder_msg, other_priv)
        st, r = verify({"presentation": p, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("holder_proof 私钥不匹配（区别于 issuer）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith(
                  "签名校验失败: holder_proof"))
        # tenant_id 不匹配（用别的租户名签名）
        p = sign_bound(make_bound_presentation(), issuer_priv, holder_priv,
                       tenant_id="tenant-other")
        st, r = verify({"presentation": p, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("holder_proof tenant_id 不匹配 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith(
                  "签名校验失败: holder_proof"))
        # source_tenant_id 改变需重新签名，匹配则通过
        p = sign_bound(make_bound_presentation(), issuer_priv, holder_priv,
                       tenant_id="tenant-source-2")
        st, r = verify({"presentation": p, "challenge": "chal-1",
                        "source_tenant_id": "tenant-source-2"}, headers=T1)
        check("holder_proof 按请求 source_tenant_id 验证通过",
              st == 200 and r == {"valid": True})

        # 7. 期限：过期在最后
        expired = good(expires_at="2020-01-01T00:00:00Z")
        st, r = verify({"presentation": expired, "challenge": "chal-1",
                        "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("绑定演示已过期", st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已过期")
        expired_bad_holder = dict(expired)
        expired_bad_holder["holder_proof"] = "!!!bad!!!"
        invalid_with_prefix(
            "holder_proof 格式优先于过期", "签名格式错误",
            {"presentation": expired_bad_holder, "challenge": "chal-1",
             "source_tenant_id": SOURCE_TENANT}, headers=T1)

        # 8. 只读：不登记、不记审计
        st, _ = _http("GET", f"{base}/v1/credentials/vc_external_0002",
                      headers=T1)
        check("验签后凭证仍未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(good_request(), headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("绑定验签不记审计", len(after["events"]) == n_before)

        # 9. 跨租户：T2 无锚点 -> 签发者锚点失败；只注册签发者锚点 ->
        # 持有者锚点失败
        invalid_with_prefix(
            "T2 无签发者锚点", "锚点不存在", good_request(), headers=T2)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": issuer_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册签发者锚点 -> 201", st == 201)
        st, r = verify(good_request(), headers=T2)
        check("T2 缺持有者锚点 -> 持有者锚点不存在",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("持有者锚点不存在"))
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 10. 跨重启：结论一致
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tpvb-a"}
        p = sign_bound(make_bound_presentation(), issuer_priv, holder_priv)
        st, r = _http("POST", f"{base}{path}",
                      {"presentation": p, "challenge": "chal-1",
                       "source_tenant_id": SOURCE_TENANT}, headers=T1)
        check("重启后绑定演示仍可验签", st == 200 and r == {"valid": True})
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
