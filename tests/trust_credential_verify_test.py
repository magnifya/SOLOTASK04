#!/usr/bin/env python3
"""跨系统凭证验真 POST /v1/trust/credentials/verify 的端到端测试。

直接运行：python3 tests/trust_credential_verify_test.py
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
    path = "/v1/trust/credentials/verify"
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

        T1 = {"X-Tenant-ID": "tcv-a"}
        T2 = {"X-Tenant-ID": "tcv-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        _, pub_other = gen_keypair()
        did = "did:web:external.example"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify(
            payload={"body": {}, "signature": "x"},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 直接注册信任锚点：无需登记 DID/凭证
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册外部锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册外部锚点 v2 -> 201", st == 201)

        cred_id = "vc_external_0001"

        def make_body(version=1, extra=None):
            body = {
                "credential_id": cred_id,
                "issuer_did": did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin", "level": 3,
                           "nested": {"city": "北京"}},
                "issued_at": "2026-09-21T00:00:00Z",
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        # 1. 成功：带 issuer_key_version=2，v2 公钥验签
        body = make_body(version=2)
        sig = crypto.sign(body, priv2)
        st, r = verify({"body": body, "signature": sig}, headers=T1)
        check("v2 外部凭证验签成功", st == 200 and r == {"valid": True})

        # 2. 成功：省略 issuer_key_version，按版本 1 查锚点；
        #    签名覆盖的 body 不含该字段
        body_v1 = make_body(version=None)
        sig_v1 = crypto.sign(body_v1, priv1)
        st, r = verify({"body": body_v1, "signature": sig_v1}, headers=T1)
        check("省略 issuer_key_version 按 v1 验签成功",
              st == 200 and r == {"valid": True})

        # 3. 省略版本时服务端不得注入签名正文：若按“注入版本 1”的正文
        #    签名，应当验签失败（证明覆盖的是请求里的完整 body 原文）
        injected = dict(body_v1, issuer_key_version=1)
        sig_injected = crypto.sign(injected, priv1)
        st, r = verify(
            {"body": body_v1, "signature": sig_injected}, headers=T1
        )
        check(
            "省略版本时注入版签名不能通过",
            st == 200
            and r.get("valid") is False
            and r.get("reason", "").startswith("签名校验失败"),
        )

        # 4. 扩展字段允许且全部参与签名
        body_ext = make_body(version=2, extra={"ext_a": "x", "ext_b": [1, 2]})
        sig_ext = crypto.sign(body_ext, priv2)
        st, r = verify({"body": body_ext, "signature": sig_ext}, headers=T1)
        check("扩展字段参与签名时验签成功", st == 200 and r == {"valid": True})
        tampered = dict(body_ext)
        tampered["ext_a"] = "y"
        st, r = verify(
            {"body": tampered, "signature": sig_ext}, headers=T1
        )
        check(
            "篡改扩展字段 -> 签名校验失败",
            st == 200
            and r.get("valid") is False
            and r.get("reason", "").startswith("签名校验失败"),
        )
        # claims 内部任何字段改动也失败
        tampered2 = json.loads(json.dumps(body_ext))
        tampered2["claims"]["nested"]["city"] = "上海"
        st, r = verify(
            {"body": tampered2, "signature": sig_ext}, headers=T1
        )
        check("篡改 claims 内部 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # 5. 请求结构错误（前缀“请求”）
        invalid_with_prefix("空请求体", "请求", raw=b"")
        invalid_with_prefix("非法 JSON", "请求", raw=b"not-json")
        invalid_with_prefix("UTF-8 非法", "请求", raw=b"\xff\xfe")
        invalid_with_prefix("JSON 数组非对象", "请求", raw=b"[1,2]")
        invalid_with_prefix("JSON 字符串非对象", "请求", raw=b'"x"')
        invalid_with_prefix("JSON 数字非对象", "请求", raw=b"123")
        invalid_with_prefix("JSON null 非对象", "请求", raw=b"null")
        invalid_with_prefix("JSON true 非对象", "请求", raw=b"true")
        invalid_with_prefix("缺 body", "请求", {"signature": sig})
        invalid_with_prefix("缺 signature", "请求", {"body": body})
        invalid_with_prefix(
            "多余字段", "请求",
            {"body": body, "signature": sig, "extra": 1},
            headers=T1,
        )
        invalid_with_prefix("空对象", "请求", {})
        invalid_with_prefix("body 为数组", "请求",
                            {"body": [], "signature": sig})
        invalid_with_prefix("body 为字符串", "请求",
                            {"body": "x", "signature": sig})
        invalid_with_prefix("body 为 null", "请求",
                            {"body": None, "signature": sig})
        invalid_with_prefix("signature 为空串", "请求",
                            {"body": body, "signature": ""})
        invalid_with_prefix("signature 为数字", "请求",
                            {"body": body, "signature": 123})
        invalid_with_prefix("signature 为 null", "请求",
                            {"body": body, "signature": None})

        # 6. 凭证字段错误（前缀“凭证”）
        def body_with(**changes):
            b = json.loads(json.dumps(make_body(version=2)))
            for key, value in changes.items():
                if value is _DELETE:
                    b.pop(key, None)
                else:
                    b[key] = value
            return b

        for field in ("credential_id", "issuer_did", "subject_did",
                      "claims", "issued_at"):
            invalid_with_prefix(
                f"缺凭证字段 {field}", "凭证",
                {"body": body_with(**{field: _DELETE}), "signature": sig},
                headers=T1,
            )
        for field in ("credential_id", "issuer_did", "subject_did",
                      "issued_at"):
            invalid_with_prefix(
                f"凭证字段 {field} 为空串", "凭证",
                {"body": body_with(**{field: ""}), "signature": sig},
                headers=T1,
            )
            invalid_with_prefix(
                f"凭证字段 {field} 非字符串", "凭证",
                {"body": body_with(**{field: 123}), "signature": sig},
                headers=T1,
            )
        invalid_with_prefix("claims 为数组", "凭证",
                            {"body": body_with(claims=[]), "signature": sig},
                            headers=T1)
        invalid_with_prefix("claims 为字符串", "凭证",
                            {"body": body_with(claims="x"),
                             "signature": sig}, headers=T1)
        for bad_version, label in [
            (True, "布尔 true"),
            (False, "布尔 false"),
            (0, "零"),
            (-1, "负数"),
            (1.5, "小数"),
            ("1", "字符串"),
        ]:
            invalid_with_prefix(
                f"issuer_key_version 非法（{label}）", "凭证",
                {"body": body_with(issuer_key_version=bad_version),
                 "signature": sig},
                headers=T1,
            )

        # 凭证字段校验先于锚点：字段缺失时即便锚点不存在也返回“凭证”
        st, r = verify(
            {"body": body_with(issuer_did="did:web:nope",
                               credential_id=_DELETE),
             "signature": sig},
            headers=T1,
        )
        check("凭证校验优先于锚点查找",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证"))

        # 7. 锚点错误（前缀“锚点”）
        body_unknown = make_body(version=2)
        body_unknown["issuer_did"] = "did:web:unknown.example"
        sig_unknown = crypto.sign(body_unknown, priv2)
        invalid_with_prefix(
            "未知签发者锚点", "锚点",
            {"body": body_unknown, "signature": sig_unknown}, headers=T1,
        )
        body_v3 = make_body(version=9)
        sig_v3 = crypto.sign(body_v3, priv2)
        invalid_with_prefix(
            "未知版本锚点（v9）", "锚点",
            {"body": body_v3, "signature": sig_v3}, headers=T1,
        )
        # 吊销 v1：正确签名也失败，且返回锚点类原因
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        invalid_with_prefix(
            "已吊销锚点（省略版本按 v1）", "锚点",
            {"body": body_v1, "signature": sig_v1}, headers=T1,
        )
        # 锚点查找先于签名校验：吊销锚点 + 坏签名仍返回“锚点”
        invalid_with_prefix(
            "锚点校验优先于签名格式", "锚点",
            {"body": body_v1, "signature": "!!!bad!!!"}, headers=T1,
        )

        # 8. 签名格式错误（前缀“签名格式错误”）；v2 仍 active
        invalid_with_prefix(
            "非 base64url 签名", "签名格式错误",
            {"body": body, "signature": "!!!not-b64!!!"}, headers=T1,
        )
        too_short = crypto.sign(body, priv2)[:-2]  # 解码后不足 64 字节
        invalid_with_prefix(
            "签名长度不足", "签名格式错误",
            {"body": body, "signature": too_short}, headers=T1,
        )

        # 9. 签名校验失败（前缀“签名校验失败”）
        # 用错误私钥（v1 私钥签 v2 正文）
        sig_wrong_key = crypto.sign(body, priv1)
        invalid_with_prefix(
            "错误私钥签名", "签名校验失败",
            {"body": body, "signature": sig_wrong_key}, headers=T1,
        )
        # 其他锚点公钥也不匹配
        sig_other = crypto.sign(body, priv1)
        invalid_with_prefix(
            "签名与锚点公钥不匹配", "签名校验失败",
            {"body": body, "signature": sig_other}, headers=T1,
        )
        tampered3 = json.loads(json.dumps(body))
        tampered3["credential_id"] = "vc_other"
        invalid_with_prefix(
            "篡改 credential_id", "签名校验失败",
            {"body": tampered3, "signature": sig}, headers=T1,
        )

        # 10. 只读：不登记凭证/DID、不写状态、不记审计
        st, _ = _http(
            "GET", f"{base}/v1/credentials/{cred_id}", headers=T1
        )
        check("验签后凭证仍未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify({"body": body_unknown, "signature": sig_unknown},
                   headers=T1)
            verify({"body": body, "signature": "bad"}, headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("验签（含失败）不记审计",
              len(after["events"]) == n_before)
        # 凭证集合无变化：GET 仍 404
        st, _ = _http(
            "GET", f"{base}/v1/credentials/{cred_id}", headers=T1
        )
        check("多次验签后凭证仍未登记", st == 404)

        # 11. 跨租户：各自使用本租户锚点
        # T2 未注册该 DID -> 锚点不存在；T1 的 v2 成功不受影响
        invalid_with_prefix(
            "T2 无锚点 -> 锚点不存在", "锚点",
            {"body": body, "signature": sig}, headers=T2,
        )
        # T2 注册同 DID 的 v2 为 pub1（与 T1 的 pub2 不同），
        # 用 priv1 签的签名在 T2 成功、在 T1 失败
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        sig_t2 = crypto.sign(body, priv1)
        st, r = verify({"body": body, "signature": sig_t2}, headers=T2)
        check("T2 按自己的锚点验签成功", st == 200 and r == {"valid": True})
        invalid_with_prefix(
            "同一签名在 T1 公钥不匹配 -> 失败", "签名校验失败",
            {"body": body, "signature": sig_t2}, headers=T1,
        )

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 12. 跨重启：锚点与吊销状态持久化，行为不变
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tcv-a"}
        body_v2 = make_body(version=2)
        sig_v2 = crypto.sign(body_v2, priv2)
        st, r = verify(
            {"body": body_v2, "signature": sig_v2}, headers=T1
        )
        check("重启后 active v2 仍可验签", st == 200 and r == {"valid": True})
        body_no_v = make_body(version=None)
        sig_no_v = crypto.sign(body_no_v, priv1)
        st, r = verify(
            {"body": body_no_v, "signature": sig_no_v}, headers=T1
        )
        check("重启后吊销 v1 状态保留 -> 锚点失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        # 重启后仍未登记凭证、无新增审计（只读性质跨重启不变）
        st, _ = _http(
            "GET", f"{base}/v1/credentials/{cred_id}", headers=T1
        )
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
