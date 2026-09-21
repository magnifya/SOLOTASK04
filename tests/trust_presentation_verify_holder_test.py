#!/usr/bin/env python3
"""外部持有者绑定演示验真 POST /v1/trust/presentations/verify 的端到端测试。

覆盖：绑定请求结构、绑定演示十二字段、挑战、签发者/持有者两类锚点、
两类签名、期限，以及只读与跨租户隔离。未绑定协议由
trust_presentation_verify_test.py 覆盖，此处不重复。

直接运行：python3 tests/trust_presentation_verify_holder_test.py
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


ISSUER_DID = "did:web:issuer.external"
HOLDER_DID = "did:web:holder.external"
SOURCE_TENANT = "source-tenant-1"


def make_bound(expires_at="2099-01-01T00:00:00Z", challenge="chal-1"):
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
    """按协议签名：issuer 覆盖去掉 proof/holder_* 的八字段；holder 覆盖
    去掉 proof/holder_proof 的绑定对象并加入 tenant_id。"""
    p = dict(p)
    unsigned = {
        k: v for k, v in p.items()
        if k != "proof" and not k.startswith("holder_")
    }
    p["proof"] = crypto.sign(unsigned, issuer_priv)
    holder_msg = dict(unsigned)
    holder_msg["holder_did"] = p["holder_did"]
    holder_msg["holder_key_version"] = p["holder_key_version"]
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

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tpvh-a"}
        T2 = {"X-Tenant-ID": "tpvh-b"}

        iss_priv, iss_pub = gen_keypair()
        hold_priv, hold_pub = gen_keypair()
        other_priv, other_pub = gen_keypair()

        # 注册签发者与持有者锚点（验证租户本地锚点）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": hold_pub,
                       "key_version": 1}, headers=T1)
        check("注册持有者锚点 -> 201", st == 201)

        good = sign_bound(make_bound(), iss_priv, hold_priv)

        def req(p, tenant=SOURCE_TENANT, challenge="chal-1"):
            return {"presentation": p, "challenge": challenge,
                    "source_tenant_id": tenant}

        # 1. 绑定演示验签成功，响应恰为 {"valid": true}
        st, r = verify(req(good), headers=T1)
        check("绑定演示验签成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})

        # 2. 请求结构错误（前缀“请求”）
        invalid_with_prefix("绑定请求缺 presentation", "请求",
                            {"challenge": "chal-1",
                             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        invalid_with_prefix("绑定请求缺 challenge", "请求",
                            {"presentation": good,
                             "source_tenant_id": SOURCE_TENANT}, headers=T1)
        invalid_with_prefix("绑定请求含多余字段", "请求",
                            {**req(good), "extra": 1}, headers=T1)
        invalid_with_prefix("source_tenant_id 为空串", "请求",
                            req(good, tenant=""), headers=T1)
        invalid_with_prefix("source_tenant_id 为数字", "请求",
                            req(good, tenant=123), headers=T1)
        invalid_with_prefix("source_tenant_id 为 null", "请求",
                            req(good, tenant=None), headers=T1)

        # 3. 演示字段错误（前缀“演示”）
        def pres_with(**changes):
            p = json.loads(json.dumps(good))
            for key, value in changes.items():
                if value is _DELETE:
                    p.pop(key, None)
                else:
                    p[key] = value
            return p

        for field in ("holder_did", "holder_key_version", "holder_proof"):
            invalid_with_prefix(
                f"绑定演示缺 {field}", "演示",
                req(pres_with(**{field: _DELETE})), headers=T1)
        invalid_with_prefix("绑定演示含多余字段", "演示",
                            req(pres_with(extra_field=1)), headers=T1)
        invalid_with_prefix("holder_did 为空串", "演示",
                            req(pres_with(holder_did="")), headers=T1)
        invalid_with_prefix("holder_did 为数字", "演示",
                            req(pres_with(holder_did=1)), headers=T1)
        for bad, label in [(True, "布尔"), (0, "零"), (-1, "负数"),
                           (1.5, "小数"), ("1", "字符串")]:
            invalid_with_prefix(
                f"holder_key_version 非法（{label}）", "演示",
                req(pres_with(holder_key_version=bad)), headers=T1)
        invalid_with_prefix("holder_proof 为空串", "演示",
                            req(pres_with(holder_proof="")), headers=T1)
        invalid_with_prefix("holder_proof 为数字", "演示",
                            req(pres_with(holder_proof=1)), headers=T1)

        # 4. 挑战不匹配（前缀“挑战”）
        invalid_with_prefix("绑定请求 challenge 不一致", "挑战",
                            req(good, challenge="chal-2"), headers=T1)

        # 5. 锚点错误：签发者（前缀“锚点”）与持有者（前缀“持有者锚点”）
        unknown_issuer = sign_bound(
            make_bound(), iss_priv, hold_priv)
        unknown_issuer["issuer_did"] = "did:web:nobody"
        unknown_issuer = sign_bound(
            {k: v for k, v in unknown_issuer.items()
             if k not in ("proof", "holder_proof")},
            iss_priv, hold_priv)
        invalid_with_prefix("未知签发者锚点", "锚点",
                            req(unknown_issuer), headers=T1)

        unknown_holder = make_bound()
        unknown_holder["holder_did"] = "did:web:nobody-holder"
        unknown_holder = sign_bound(unknown_holder, iss_priv, hold_priv)
        st, r = verify(req(unknown_holder), headers=T1)
        check("未知持有者锚点 -> 持有者锚点不存在",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("持有者锚点不存在"))

        # 吊销不可逆，故用独立持有者 DID 做吊销用例，不影响主持有者
        REVOKED_HOLDER = "did:web:holder-revoked"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": REVOKED_HOLDER, "public_key": hold_pub,
                       "key_version": 1}, headers=T1)
        check("注册待吊销持有者锚点 -> 201", st == 201)
        revoked_pres = make_bound()
        revoked_pres["holder_did"] = REVOKED_HOLDER
        revoked_pres = sign_bound(revoked_pres, iss_priv, hold_priv)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{REVOKED_HOLDER}/1/status",
            {"status": "revoked"}, headers=T1)
        check("吊销持有者锚点 -> 200", st == 200)
        st, r = verify(req(revoked_pres), headers=T1)
        check("持有者锚点已吊销",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("持有者锚点已吊销"))
        # 持有者锚点校验先于其签名格式：坏 holder_proof 仍返回锚点类原因
        bad_hold = dict(revoked_pres)
        bad_hold["holder_proof"] = "!!!bad!!!"
        st, r = verify(req(bad_hold), headers=T1)
        check("持有者锚点校验优先于 holder_proof 格式",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("持有者锚点"))

        # 6. 签名错误：两类签名可区分
        bad_iss = dict(good)
        bad_iss["proof"] = "!!!bad!!!"
        invalid_with_prefix("issuer proof 格式错误", "签名格式错误: 不是",
                            req(bad_iss), headers=T1)
        invalid_with_prefix("holder_proof 格式错误", "签名格式错误: holder_proof",
                            req(pres_with(holder_proof="!!!bad!!!")),
                            headers=T1)
        wrong_iss = make_bound()
        wrong_iss = sign_bound(wrong_iss, other_priv, hold_priv)
        invalid_with_prefix("issuer 签名不匹配", "签名校验失败，演示内容",
                            req(wrong_iss), headers=T1)
        wrong_hold = sign_bound(make_bound(), iss_priv, other_priv)
        st, r = verify(req(wrong_hold), headers=T1)
        check("holder_proof 签名不匹配",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith(
                  "签名校验失败: holder_proof"))
        # tenant_id 计入 holder_proof 覆盖：签名用别的 tenant_id 即失败
        wrong_tenant = sign_bound(make_bound(), iss_priv, hold_priv,
                                  tenant_id="other-tenant")
        st, r = verify(req(wrong_tenant), headers=T1)
        check("holder_proof 覆盖 tenant_id=source_tenant_id",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith(
                  "签名校验失败: holder_proof"))
        # source_tenant_id 不同但签名按其生成 -> 成功
        other_tenant_pres = sign_bound(make_bound(), iss_priv, hold_priv,
                                       tenant_id="another-source")
        st, r = verify(req(other_tenant_pres, tenant="another-source"),
                       headers=T1)
        check("按请求 source_tenant_id 验 holder_proof 成功",
              st == 200 and r == {"valid": True})

        # 7. 期限：过期判定在持有者验签之后
        expired = sign_bound(make_bound(expires_at="2020-01-01T00:00:00Z"),
                             iss_priv, hold_priv)
        st, r = verify(req(expired), headers=T1)
        check("绑定演示已过期", st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已过期")
        expired_bad_hold = dict(expired)
        expired_bad_hold["holder_proof"] = "!!!bad!!!"
        invalid_with_prefix("持有者签名优先于过期", "签名格式错误: holder_proof",
                            req(expired_bad_hold), headers=T1)

        # 8. 只读：不登记任何资源、不记审计
        st, _ = _http("GET", f"{base}/v1/credentials/vc_external_0002",
                      headers=T1)
        check("验签后凭证仍未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(req(good), headers=T1)
            verify(req(wrong_hold), headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("绑定验签（含失败）不记审计",
              len(after["events"]) == n_before)

        # 9. 跨租户：T2 无任何锚点 -> 签发者锚点失败；只注册持有者锚点
        # 仍签发者锚点失败；只用验证租户锚点。
        invalid_with_prefix("T2 无锚点 -> 签发者锚点不存在", "锚点",
                            req(good), headers=T2)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": hold_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册持有者锚点 -> 201", st == 201)
        invalid_with_prefix("T2 仍缺签发者锚点", "锚点",
                            req(good), headers=T2)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=T2)
        check("T2 注册签发者锚点 -> 201", st == 201)
        st, r = verify(req(good), headers=T2)
        check("T2 按自己的锚点验绑定演示成功",
              st == 200 and r == {"valid": True})
        # T2 持有者锚点换成别的公钥 -> 持有者签名失败
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": other_pub,
                       "key_version": 2}, headers=T2)
        check("T2 注册持有者锚点 v2 -> 201", st == 201)
        t2_pres = sign_bound(make_bound(), iss_priv, hold_priv)
        t2_pres["holder_key_version"] = 2
        t2_pres = sign_bound(
            {k: v for k, v in t2_pres.items()
             if k not in ("proof", "holder_proof")},
            iss_priv, hold_priv)
        st, r = verify(req(t2_pres), headers=T2)
        check("T2 持有者锚点公钥不同 -> holder_proof 失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith(
                  "签名校验失败: holder_proof"))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 10. 跨重启：锚点状态持久化，绑定验签结论一致
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tpvh-a"}
        good = sign_bound(make_bound(), iss_priv, hold_priv)
        st, r = _http("POST", f"{base}{path}",
                      {"presentation": good, "challenge": "chal-1",
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


_DELETE = object()


if __name__ == "__main__":
    raise SystemExit(main())
