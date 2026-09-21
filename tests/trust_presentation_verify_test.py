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


PORT = 8963
BASE = f"http://127.0.0.1:{PORT}"
PATH = "/v1/trust/presentations/verify"

T1 = {"X-Tenant-ID": "tpv-a"}
T2 = {"X-Tenant-ID": "tpv-b"}

DID = "did:web:external-issuer.example"
FUTURE = "2099-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def verify(payload=None, headers=None, raw=None):
    return _http(
        "POST", f"{BASE}{PATH}", payload,
        headers=headers if headers is not None else T1,
        raw=raw,
    )


def invalid_with_prefix(name, prefix, payload=None, raw=None, headers=None):
    st, r = verify(payload=payload, raw=raw, headers=headers)
    check(
        name,
        st == 200
        and r.get("valid") is False
        and isinstance(r.get("reason"), str)
        and r["reason"]
        and r["reason"].startswith(prefix),
    )


def make_pres(priv, version=2, expires_at=FUTURE, challenge="chal-001",
              mutate=None):
    pres = {
        "presentation_id": "vp_external_0001",
        "credential_id": "vc_external_0001",
        "issuer_did": DID,
        "issuer_key_version": version,
        "disclose": ["/role", "/nested"],
        "claims": {"role": "admin", "nested": {"city": "北京"}},
        "challenge": challenge,
        "expires_at": expires_at,
    }
    if mutate:
        mutate(pres)
    message = {k: v for k, v in pres.items() if k != "proof"}
    pres["proof"] = crypto.sign(message, priv)
    return pres


def audit_count(headers):
    st, r = _http("GET", f"{BASE}/v1/audit?limit=200", headers=headers)
    assert st == 200, r
    return len(r["events"])


def main():
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(PORT), "服务启动超时"
        run_checks()
        # 重启后结论一致
        proc.terminate()
        proc.wait(timeout=10)
        proc2 = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(PORT), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            assert wait_up(PORT), "服务重启超时"
            run_restart_checks()
        finally:
            proc2.terminate()
            proc2.wait(timeout=10)
    finally:
        if proc.poll() is None:
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


# 重启前后共用的密钥（模块级，重启后重新生成会导致结论不同，
# 因此整个进程生命周期内固定）。
PRIV1, PUB1 = gen_keypair()
PRIV2, PUB2 = gen_keypair()
PRIV_T2, PUB_T2 = gen_keypair()


def run_checks():
    # 显式空租户头仍按通用协议 400（在进入验签流程前判定）
    st, _ = verify(
        payload={"presentation": {}, "challenge": "x"},
        headers={"X-Tenant-ID": ""},
    )
    check("显式空 X-Tenant-ID -> 400", st == 400)

    # 注册信任锚点：T1 有 v1/v2，T2 仅有同 DID 的另一把密钥
    st, r = _http("POST", f"{BASE}/v1/trust/anchors",
                  {"did": DID, "public_key": PUB1, "key_version": 1},
                  headers=T1)
    check("T1 注册锚点 v1 -> 201", st == 201)
    st, r = _http("POST", f"{BASE}/v1/trust/anchors",
                  {"did": DID, "public_key": PUB2, "key_version": 2},
                  headers=T1)
    check("T1 注册锚点 v2 -> 201", st == 201)
    st, r = _http("POST", f"{BASE}/v1/trust/anchors",
                  {"did": DID, "public_key": PUB_T2, "key_version": 2},
                  headers=T2)
    check("T2 注册锚点 v2 -> 201", st == 201)

    audits_before = audit_count(T1)

    # 1. 成功：v2 锚点验签，响应恰为 {"valid": true}
    pres = make_pres(PRIV2)
    st, r = verify({"presentation": pres, "challenge": "chal-001"})
    check("合法演示验真成功且响应恰为 valid:true",
          st == 200 and r == {"valid": True})

    # 2. 请求结构错误（前缀“请求”）
    invalid_with_prefix("空请求体", "请求", raw=b"")
    invalid_with_prefix("非法 JSON", "请求", raw=b"not-json")
    invalid_with_prefix("UTF-8 非法", "请求", raw=b"\xff\xfe")
    invalid_with_prefix("JSON 数组非对象", "请求", raw=b"[1,2]")
    invalid_with_prefix("JSON null 非对象", "请求", raw=b"null")
    invalid_with_prefix("空对象", "请求", {})
    invalid_with_prefix("缺 presentation", "请求", {"challenge": "chal-001"})
    invalid_with_prefix("缺 challenge", "请求", {"presentation": pres})
    invalid_with_prefix(
        "多余字段", "请求",
        {"presentation": pres, "challenge": "chal-001", "extra": 1},
    )
    invalid_with_prefix("presentation 为数组", "请求",
                        {"presentation": [], "challenge": "chal-001"})
    invalid_with_prefix("challenge 为空串", "请求",
                        {"presentation": pres, "challenge": ""})
    invalid_with_prefix("challenge 非字符串", "请求",
                        {"presentation": pres, "challenge": 1})

    # 3. 演示字段错误（前缀“演示”）
    def bad_pres(name, mutate, prefix="演示"):
        p = make_pres(PRIV2)
        mutate(p)
        # 变更后重签，确保失败原因来自字段校验而非签名
        message = {k: v for k, v in p.items() if k != "proof"}
        p["proof"] = crypto.sign(message, PRIV2)
        invalid_with_prefix(
            name, prefix, {"presentation": p, "challenge": "chal-001"}
        )

    bad_pres("含 holder_did 即失败",
             lambda p: p.update(holder_did="did:web:h"))
    bad_pres("含 holder_proof 即失败",
             lambda p: p.update(holder_proof="x"))
    bad_pres("缺 presentation_id", lambda p: p.pop("presentation_id"))
    bad_pres("缺 expires_at", lambda p: p.pop("expires_at"))
    bad_pres("多余字段", lambda p: p.update(extra=1))
    bad_pres("presentation_id 为空", lambda p: p.update(presentation_id=""))
    bad_pres("credential_id 非字符串",
             lambda p: p.update(credential_id=1))
    bad_pres("issuer_did 为空", lambda p: p.update(issuer_did=""))
    bad_pres("issuer_key_version 为布尔",
             lambda p: p.update(issuer_key_version=True))
    bad_pres("issuer_key_version 为 0",
             lambda p: p.update(issuer_key_version=0))
    bad_pres("issuer_key_version 为字符串",
             lambda p: p.update(issuer_key_version="2"))
    bad_pres("disclose 非数组", lambda p: p.update(disclose="/role"))
    bad_pres("disclose 元素非字符串",
             lambda p: p.update(disclose=["/role", 1]))
    bad_pres("claims 非对象", lambda p: p.update(claims=[]))
    bad_pres("演示 challenge 为空", lambda p: p.update(challenge=""))
    # proof 须在重签之后置空，否则会被辅助函数重新签名覆盖
    p = make_pres(PRIV2)
    p["proof"] = ""
    invalid_with_prefix("proof 为空", "演示",
                        {"presentation": p, "challenge": "chal-001"})

    # 4. 挑战不匹配（前缀“挑战”）；即使锚点不存在也优先报挑战
    invalid_with_prefix(
        "请求 challenge 与演示不一致", "挑战",
        {"presentation": pres, "challenge": "chal-002"},
    )
    unknown_pres = make_pres(
        PRIV2, mutate=lambda p: p.update(issuer_did="did:web:unknown")
    )
    invalid_with_prefix(
        "挑战校验优先于锚点", "挑战",
        {"presentation": unknown_pres, "challenge": "chal-002"},
    )

    # 5. 锚点错误（前缀“锚点”）
    invalid_with_prefix(
        "锚点不存在", "锚点",
        {"presentation": unknown_pres, "challenge": "chal-001"},
    )
    missing_ver = make_pres(PRIV2, version=9)
    invalid_with_prefix(
        "锚点版本不存在", "锚点",
        {"presentation": missing_ver, "challenge": "chal-001"},
    )
    # 跨租户：T2 锚点公钥不同 -> 签名校验失败而非锚点缺失
    st, r = verify({"presentation": pres, "challenge": "chal-001"},
                   headers=T2)
    check("跨租户用各自锚点 -> 签名校验失败",
          st == 200 and r.get("valid") is False
          and r.get("reason", "").startswith("签名校验失败"))
    # 吊销锚点 v1 后，v1 演示验真报锚点已吊销
    st, _ = _http("PUT", f"{BASE}/v1/trust/anchors/{DID}/1/status",
                  {"status": "revoked"}, headers=T1)
    check("吊销锚点 v1 -> 200", st == 200)
    pres_v1 = make_pres(PRIV1, version=1)
    invalid_with_prefix(
        "锚点已吊销", "锚点",
        {"presentation": pres_v1, "challenge": "chal-001"},
    )

    # 6. 签名格式错误（前缀“签名格式错误”）
    p = make_pres(PRIV2)
    p["proof"] = "!!!not-base64url!!!"
    invalid_with_prefix("proof 非 base64url", "签名格式错误",
                        {"presentation": p, "challenge": "chal-001"})
    p = make_pres(PRIV2)
    p["proof"] = "AQID"  # 可解码但非 64 字节
    invalid_with_prefix("proof 非 64 字节", "签名格式错误",
                        {"presentation": p, "challenge": "chal-001"})

    # 7. 签名校验失败（前缀“签名校验失败”）：篡改任意被签字段
    def tampered(name, mutate):
        p = make_pres(PRIV2)
        mutate(p)
        invalid_with_prefix(name, "签名校验失败",
                            {"presentation": p, "challenge": "chal-001"})

    tampered("篡改 claims", lambda p: p["claims"].update(role="user"))
    tampered("篡改 disclose", lambda p: p.update(disclose=["/role"]))
    tampered("篡改 presentation_id",
             lambda p: p.update(presentation_id="vp_other"))
    tampered("篡改 expires_at",
             lambda p: p.update(expires_at="2099-06-01T00:00:00Z"))
    # 用 v1 私钥签但声称 v2
    p = make_pres(PRIV1, version=2)
    invalid_with_prefix("错误私钥签名", "签名校验失败",
                        {"presentation": p, "challenge": "chal-001"})

    # 8. 期限（最后判定）
    # expires_at 形状非法但签名合法 -> 演示字段 expires_at 原因
    p = make_pres(PRIV2, expires_at="2099-01-01 00:00:00")
    invalid_with_prefix("expires_at 形状非法", "演示字段",
                        {"presentation": p, "challenge": "chal-001"})
    p = make_pres(PRIV2, expires_at="2099-13-01T00:00:00Z")
    invalid_with_prefix("expires_at 时刻非法", "演示字段",
                        {"presentation": p, "challenge": "chal-001"})
    # 已过期（签名合法）
    p = make_pres(PRIV2, expires_at=PAST)
    invalid_with_prefix("演示已过期", "演示已过期",
                        {"presentation": p, "challenge": "chal-001"})

    # 9. 只读：全部验真调用不产生新审计、不登记演示
    check("验真不产生审计", audit_count(T1) == audits_before + 1)  # +1 为吊销
    st, _ = _http("GET", f"{BASE}/v1/credentials/vc_external_0001",
                  headers=T1)
    check("未登记任何凭证", st == 404)


def run_restart_checks():
    # 重启后：合法演示仍有效，过期演示仍过期，吊销锚点状态保留
    pres = make_pres(PRIV2)
    st, r = verify({"presentation": pres, "challenge": "chal-001"})
    check("重启后合法演示仍验真成功", st == 200 and r == {"valid": True})
    p = make_pres(PRIV2, expires_at=PAST)
    st, r = verify({"presentation": p, "challenge": "chal-001"})
    check("重启后过期演示仍判过期",
          st == 200 and r.get("valid") is False
          and r.get("reason") == "演示已过期")
    pres_v1 = make_pres(PRIV1, version=1)
    st, r = verify({"presentation": pres_v1, "challenge": "chal-001"})
    check("重启后吊销锚点状态保留",
          st == 200 and r.get("valid") is False
          and r.get("reason", "").startswith("锚点"))


if __name__ == "__main__":
    raise SystemExit(main())
