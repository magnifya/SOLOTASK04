#!/usr/bin/env python3
"""跨系统演示验真 POST /v1/trust/presentations/verify 的端到端测试。

直接运行：python3 tests/trust_presentation_verify_test.py
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
    path = "/v1/trust/presentations/verify"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload, headers=headers, raw=raw)

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

        T1 = {"X-Tenant-ID": "tpv-a"}
        T2 = {"X-Tenant-ID": "tpv-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:external.example"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify(
            payload={"presentation": {}, "challenge": "x"},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 直接注册信任锚点：无需登记 DID/凭证/演示
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册外部锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册外部锚点 v2 -> 201", st == 201)

        def make_presentation(version=2, challenge="chal-1",
                              expires_at="2099-01-01T00:00:00Z", extra=None):
            p = {
                "presentation_id": "vp_" + "a" * 32,
                "credential_id": "vc_external_0001",
                "issuer_did": did,
                "issuer_key_version": version,
                "disclose": ["/role", "/addr/city"],
                "claims": {"role": "admin", "addr": {"city": "北京"}},
                "challenge": challenge,
                "expires_at": expires_at,
            }
            if extra:
                p.update(extra)
            return p

        def sign_presentation(p, priv):
            message = {k: v for k, v in p.items() if k != "proof"}
            return crypto.sign(message, priv)

        def signed(version=2, priv=None, **kwargs):
            p = make_presentation(version=version, **kwargs)
            p["proof"] = sign_presentation(p, priv or priv2)
            return p

        # 1. 成功：九字段未绑定演示，v2 锚点验签，响应恰为 {"valid": true}
        pres = signed()
        st, r = verify({"presentation": pres, "challenge": "chal-1"},
                       headers=T1)
        check("外部演示验签成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})

        # 2. 请求结构错误（前缀“请求”）
        invalid_with_prefix("空请求体", "请求", raw=b"")
        invalid_with_prefix("非法 JSON", "请求", raw=b"not-json")
        invalid_with_prefix("UTF-8 非法", "请求", raw=b"\xff\xfe")
        invalid_with_prefix("JSON 数组非对象", "请求", raw=b"[1,2]")
        invalid_with_prefix("JSON null 非对象", "请求", raw=b"null")
        invalid_with_prefix("缺 presentation", "请求",
                            {"challenge": "chal-1"}, headers=T1)
        invalid_with_prefix("缺 challenge", "请求",
                            {"presentation": pres}, headers=T1)
        invalid_with_prefix("多余字段", "请求",
                            {"presentation": pres, "challenge": "chal-1",
                             "extra": 1}, headers=T1)
        invalid_with_prefix("空对象", "请求", {}, headers=T1)
        invalid_with_prefix("presentation 为数组", "请求",
                            {"presentation": [], "challenge": "chal-1"},
                            headers=T1)
        invalid_with_prefix("presentation 为字符串", "请求",
                            {"presentation": "x", "challenge": "chal-1"},
                            headers=T1)
        invalid_with_prefix("presentation 为 null", "请求",
                            {"presentation": None, "challenge": "chal-1"},
                            headers=T1)
        invalid_with_prefix("challenge 为空串", "请求",
                            {"presentation": pres, "challenge": ""},
                            headers=T1)
        invalid_with_prefix("challenge 为数字", "请求",
                            {"presentation": pres, "challenge": 123},
                            headers=T1)
        invalid_with_prefix("challenge 为 null", "请求",
                            {"presentation": pres, "challenge": None},
                            headers=T1)

        # 3. 演示字段错误（前缀“演示”）
        def pres_with(**changes):
            p = json.loads(json.dumps(pres))
            for key, value in changes.items():
                if value is _DELETE:
                    p.pop(key, None)
                else:
                    p[key] = value
            return p

        for field in ("presentation_id", "credential_id", "issuer_did",
                      "issuer_key_version", "disclose", "claims",
                      "challenge", "expires_at", "proof"):
            invalid_with_prefix(
                f"缺演示字段 {field}", "演示",
                {"presentation": pres_with(**{field: _DELETE}),
                 "challenge": "chal-1"}, headers=T1,
            )
        invalid_with_prefix("演示含多余字段", "演示",
                            {"presentation": pres_with(extra_field=1),
                             "challenge": "chal-1"}, headers=T1)
        # holder_* 字段出现即失败（即使签名覆盖完整对象）
        bound = pres_with(holder_did="did:web:holder.example",
                          holder_key_version=1, holder_proof="x")
        bound["proof"] = sign_presentation(bound, priv2)
        invalid_with_prefix("含 holder_* 字段即失败", "演示",
                            {"presentation": bound, "challenge": "chal-1"},
                            headers=T1)
        for field in ("presentation_id", "credential_id", "issuer_did",
                      "challenge", "expires_at", "proof"):
            invalid_with_prefix(
                f"演示字段 {field} 为空串", "演示",
                {"presentation": pres_with(**{field: ""}),
                 "challenge": "chal-1"}, headers=T1,
            )
            invalid_with_prefix(
                f"演示字段 {field} 非字符串", "演示",
                {"presentation": pres_with(**{field: 123}),
                 "challenge": "chal-1"}, headers=T1,
            )
        for bad_version, label in [
            (True, "布尔 true"),
            (False, "布尔 false"),
            (0, "零"),
            (-1, "负数"),
            (1.5, "小数"),
            ("2", "字符串"),
        ]:
            invalid_with_prefix(
                f"issuer_key_version 非法（{label}）", "演示",
                {"presentation": pres_with(issuer_key_version=bad_version),
                 "challenge": "chal-1"}, headers=T1,
            )
        invalid_with_prefix("disclose 非数组", "演示",
                            {"presentation": pres_with(disclose="/role"),
                             "challenge": "chal-1"}, headers=T1)
        invalid_with_prefix("disclose 含非字符串", "演示",
                            {"presentation": pres_with(disclose=["/role", 1]),
                             "challenge": "chal-1"}, headers=T1)
        invalid_with_prefix("claims 为数组", "演示",
                            {"presentation": pres_with(claims=[]),
                             "challenge": "chal-1"}, headers=T1)
        invalid_with_prefix("claims 为字符串", "演示",
                            {"presentation": pres_with(claims="x"),
                             "challenge": "chal-1"}, headers=T1)

        # 演示字段校验先于锚点：字段缺失时即便锚点不存在也返回“演示”
        bad = pres_with(issuer_did="did:web:nope",
                        credential_id=_DELETE)
        st, r = verify({"presentation": bad, "challenge": "chal-1"},
                       headers=T1)
        check("演示字段校验优先于锚点查找",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("演示"))

        # 4. 挑战不匹配（前缀“挑战”）
        invalid_with_prefix("请求 challenge 与演示不一致", "挑战",
                            {"presentation": pres, "challenge": "chal-2"},
                            headers=T1)
        other_challenge = signed(challenge="chal-9")
        invalid_with_prefix("演示 challenge 改变后仍不一致", "挑战",
                            {"presentation": other_challenge,
                             "challenge": "chal-1"}, headers=T1)
        # 一致时通过
        st, r = verify(
            {"presentation": other_challenge, "challenge": "chal-9"},
            headers=T1,
        )
        check("challenge 一致时验签成功", st == 200 and r == {"valid": True})

        # 5. 锚点错误（前缀“锚点”）
        unknown = signed(extra=None)
        unknown["issuer_did"] = "did:web:unknown.example"
        unknown["proof"] = sign_presentation(unknown, priv2)
        invalid_with_prefix("未知签发者锚点", "锚点",
                            {"presentation": unknown, "challenge": "chal-1"},
                            headers=T1)
        v9 = signed(version=9)
        invalid_with_prefix("未知版本锚点（v9）", "锚点",
                            {"presentation": v9, "challenge": "chal-1"},
                            headers=T1)
        # 吊销 v1：正确签名也失败，且返回锚点类原因
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        v1 = signed(version=1, priv=priv1)
        invalid_with_prefix("已吊销锚点（v1）", "锚点",
                            {"presentation": v1, "challenge": "chal-1"},
                            headers=T1)
        # 锚点查找先于签名校验：吊销锚点 + 坏签名仍返回“锚点”
        bad_sig_v1 = dict(v1)
        bad_sig_v1["proof"] = "!!!bad!!!"
        invalid_with_prefix("锚点校验优先于签名格式", "锚点",
                            {"presentation": bad_sig_v1,
                             "challenge": "chal-1"}, headers=T1)

        # 6. 签名格式错误（前缀“签名格式错误”）；v2 仍 active
        fmt_bad = dict(pres)
        fmt_bad["proof"] = "!!!not-b64!!!"
        invalid_with_prefix("非 base64url proof", "签名格式错误",
                            {"presentation": fmt_bad, "challenge": "chal-1"},
                            headers=T1)
        too_short = dict(pres)
        too_short["proof"] = pres["proof"][:-2]  # 解码后不足 64 字节
        invalid_with_prefix("proof 长度不足", "签名格式错误",
                            {"presentation": too_short,
                             "challenge": "chal-1"}, headers=T1)

        # 7. 签名校验失败（前缀“签名校验失败”）
        wrong_key = make_presentation()
        wrong_key["proof"] = sign_presentation(wrong_key, priv1)  # v1 私钥签 v2
        invalid_with_prefix("错误私钥签名", "签名校验失败",
                            {"presentation": wrong_key,
                             "challenge": "chal-1"}, headers=T1)
        tampered = pres_with(credential_id="vc_other")
        invalid_with_prefix("篡改 credential_id", "签名校验失败",
                            {"presentation": tampered,
                             "challenge": "chal-1"}, headers=T1)
        tampered_claims = json.loads(json.dumps(pres))
        tampered_claims["claims"]["addr"]["city"] = "上海"
        invalid_with_prefix("篡改 claims 内部", "签名校验失败",
                            {"presentation": tampered_claims,
                             "challenge": "chal-1"}, headers=T1)

        # 8. 期限：格式非法（前缀“演示”）与已过期（“演示已过期”）
        bad_exp = signed(expires_at="2099-01-01")
        invalid_with_prefix("expires_at 非 Z 秒精度", "演示",
                            {"presentation": bad_exp, "challenge": "chal-1"},
                            headers=T1)
        bad_exp2 = signed(expires_at="2099-01-01T00:00:00+08:00")
        invalid_with_prefix("expires_at 带时区偏移", "演示",
                            {"presentation": bad_exp2, "challenge": "chal-1"},
                            headers=T1)
        bad_exp3 = signed(expires_at="2099-13-01T00:00:00Z")
        invalid_with_prefix("expires_at 非法时刻", "演示",
                            {"presentation": bad_exp3, "challenge": "chal-1"},
                            headers=T1)
        expired = signed(expires_at="2020-01-01T00:00:00Z")
        st, r = verify({"presentation": expired, "challenge": "chal-1"},
                       headers=T1)
        check("已过期演示 -> 演示已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已过期")
        # 过期判定在验签之后：坏签名 + 已过期仍返回签名类原因
        expired_bad_sig = dict(expired)
        expired_bad_sig["proof"] = "!!!bad!!!"
        invalid_with_prefix("签名格式优先于过期", "签名格式错误",
                            {"presentation": expired_bad_sig,
                             "challenge": "chal-1"}, headers=T1)

        # 9. 只读：不登记凭证/演示、不写状态、不记审计
        st, _ = _http("GET", f"{base}/v1/credentials/vc_external_0001",
                      headers=T1)
        check("验签后凭证仍未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify({"presentation": pres, "challenge": "chal-1"}, headers=T1)
            verify({"presentation": unknown, "challenge": "chal-1"},
                   headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("验签（含失败）不记审计",
              len(after["events"]) == n_before)

        # 10. 跨租户：各自使用本租户锚点
        invalid_with_prefix("T2 无锚点 -> 锚点不存在", "锚点",
                            {"presentation": pres, "challenge": "chal-1"},
                            headers=T2)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        t2_pres = make_presentation()
        t2_pres["proof"] = sign_presentation(t2_pres, priv1)
        st, r = verify({"presentation": t2_pres, "challenge": "chal-1"},
                       headers=T2)
        check("T2 按自己的锚点验签成功", st == 200 and r == {"valid": True})
        invalid_with_prefix("同一签名在 T1 公钥不匹配 -> 失败", "签名校验失败",
                            {"presentation": t2_pres, "challenge": "chal-1"},
                            headers=T1)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 11. 跨重启：锚点与吊销状态持久化，结论一致
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tpv-a"}

        def make_presentation(version=2, challenge="chal-1",
                              expires_at="2099-01-01T00:00:00Z"):
            return {
                "presentation_id": "vp_" + "a" * 32,
                "credential_id": "vc_external_0001",
                "issuer_did": did,
                "issuer_key_version": version,
                "disclose": ["/role", "/addr/city"],
                "claims": {"role": "admin", "addr": {"city": "北京"}},
                "challenge": challenge,
                "expires_at": expires_at,
            }

        p2 = make_presentation()
        msg = {k: v for k, v in p2.items() if k != "proof"}
        p2["proof"] = crypto.sign(msg, priv2)
        st, r = _http("POST", f"{base}{path}",
                      {"presentation": p2, "challenge": "chal-1"},
                      headers=T1)
        check("重启后 active v2 仍可验签", st == 200 and r == {"valid": True})
        p1 = make_presentation(version=1)
        msg1 = {k: v for k, v in p1.items() if k != "proof"}
        p1["proof"] = crypto.sign(msg1, priv1)
        st, r = _http("POST", f"{base}{path}",
                      {"presentation": p1, "challenge": "chal-1"},
                      headers=T1)
        check("重启后吊销 v1 状态保留 -> 锚点失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        st, _ = _http("GET", f"{base}/v1/credentials/vc_external_0001",
                      headers=T1)
        check("重启后凭证仍未登记", st == 404)
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
