#!/usr/bin/env python3
"""跨系统模式约束验真 POST /v1/trust/credentials/verify-with-schema 测试。

直接运行：python3 tests/trust_credential_verify_with_schema_test.py
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

PORT = 8979
BASE = f"http://127.0.0.1:{PORT}"
PATH = "/v1/trust/credentials/verify-with-schema"
INVALID_REQUEST = {"valid": False, "reason": "请求参数无效"}


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


def wait_up(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"{BASE}/health")
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
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{BASE}{PATH}", payload, headers=headers,
                     raw=raw)

    def invalid_request(name, payload=None, raw=None, headers=None):
        st, r = verify(payload=payload, raw=raw, headers=headers)
        check(name, st == 200 and r == INVALID_REQUEST)

    def invalid_with_reason(name, reason, payload, headers=None,
                            exact=False):
        st, r = verify(payload, headers=headers)
        ok = (
            st == 200
            and r.get("valid") is False
            and isinstance(r.get("reason"), str)
            and (r["reason"] == reason if exact
                 else r["reason"].startswith(reason))
        )
        check(name, ok)

    T1 = {"X-Tenant-ID": "vws-a"}
    T2 = {"X-Tenant-ID": "vws-b"}

    try:
        assert wait_up(), "服务启动超时"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify(
            payload={"body": {}, "signature": "x",
                     "schema_id": "kyc_basic", "schema_version": 1},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # ---------------------------------------------------------- #
        # 准备：DID、模式、锚点
        # ---------------------------------------------------------- #
        def create_did(headers, public_key):
            st, r = _http("POST", f"{BASE}/v1/dids",
                          {"method": "example", "public_key": public_key},
                          headers=headers)
            assert st == 201, (st, r)
            return r["did"]

        issuer1 = create_did(T1, "issuer-1")   # 主用：模式 + active 锚点
        issuer2 = create_did(T1, "issuer-2")   # 有模式、无锚点
        issuer3 = create_did(T1, "issuer-3")   # 外部停用通告用
        issuer4 = create_did(T1, "issuer-4")   # 锚点吊销用
        issuer_b = create_did(T2, "issuer-b")  # 他租户同名模式

        claim_types_v1 = {
            "/name": "string",
            "/age": "integer",
            "/addr/city": "string",
        }
        required_v1 = ["/name", "/age"]

        def register_schema(headers, issuer, version,
                            claim_types=None, required=None):
            st, r = _http(
                "POST", f"{BASE}/v1/credential-schemas",
                {
                    "schema_id": "kyc_basic",
                    "version": version,
                    "issuer_did": issuer,
                    "claim_types": claim_types or claim_types_v1,
                    "required_claims": (
                        required if required is not None else required_v1
                    ),
                },
                headers=headers,
            )
            assert st == 201, (st, r)
            return r["digest"]

        digest_v1 = register_schema(T1, issuer1, 1)
        digest_v2 = register_schema(
            T1, issuer1, 2,
            claim_types={"/name": "string"}, required=["/name"],
        )
        assert digest_v1 != digest_v2
        digest_i2 = register_schema(T1, issuer2, 1)
        digest_i3 = register_schema(T1, issuer3, 1)
        digest_i4 = register_schema(T1, issuer4, 1)
        digest_b = register_schema(T2, issuer_b, 1)

        priv1, pub1 = gen_keypair()
        priv3, pub3 = gen_keypair()
        priv4, pub4 = gen_keypair()

        def register_anchor(headers, did, pub, version=1):
            st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                          {"did": did, "public_key": pub,
                           "key_version": version}, headers=headers)
            assert st == 201, (did, st)

        register_anchor(T1, issuer1, pub1)
        register_anchor(T1, issuer3, pub3)
        register_anchor(T1, issuer4, pub4)

        cred_id = "vc_external_schema_0001"

        def make_body(issuer=issuer1, schema_id="kyc_basic", version=1,
                      digest=None, claims=None, extra=None,
                      key_version=1, drop=()):
            body = {
                "credential_id": cred_id,
                "issuer_did": issuer,
                "subject_did": "did:web:subject.example",
                "claims": claims if claims is not None else {
                    "name": "张三", "age": 30,
                    "addr": {"city": "北京"},
                },
                "issued_at": "2026-09-21T00:00:00Z",
                "schema_id": schema_id,
                "schema_version": version,
                "schema_digest": digest if digest is not None else digest_v1,
            }
            if key_version is not None:
                body["issuer_key_version"] = key_version
            if extra:
                body.update(extra)
            for field in drop:
                body.pop(field, None)
            return body

        def signed(payload_body, priv=priv1, schema_id="kyc_basic",
                   version=1):
            return {
                "body": payload_body,
                "signature": crypto.sign(payload_body, priv),
                "schema_id": schema_id,
                "schema_version": version,
            }

        # ---------------------------------------------------------- #
        # 1. 成功：仅 {"valid": true}
        # ---------------------------------------------------------- #
        body = make_body()
        st, r = verify(signed(body), headers=T1)
        check("模式约束验真成功仅返 valid:true",
              st == 200 and r == {"valid": True})

        # 未声明的额外 claims 保留（不判失败）
        body_extra_claims = make_body(
            claims={"name": "张三", "age": 30, "extra": [1, 2],
                    "addr": {"city": "北京"}},
        )
        st, r = verify(signed(body_extra_claims), headers=T1)
        check("未声明的额外 claims 不影响验真",
              st == 200 and r == {"valid": True})

        # 声明但非必填的路径缺失视为可选
        body_optional = make_body(claims={"name": "张三", "age": 30})
        st, r = verify(signed(body_optional), headers=T1)
        check("可选声明路径缺失仍成功", st == 200 and r == {"valid": True})

        # 省略 issuer_key_version 按 v1 查锚点且不注入正文
        body_no_kv = make_body(key_version=None)
        st, r = verify(signed(body_no_kv), headers=T1)
        check("省略 issuer_key_version 按 v1 验真成功",
              st == 200 and r == {"valid": True})

        # ---------------------------------------------------------- #
        # 2. 请求与模式参数：统一 {"valid":false,"reason":"请求参数无效"}
        # ---------------------------------------------------------- #
        invalid_request("空请求体", raw=b"")
        invalid_request("非法 JSON", raw=b"not-json")
        invalid_request("UTF-8 非法", raw=b"\xff\xfe")
        invalid_request("JSON 数组非对象", raw=b"[1,2]")
        invalid_request("JSON 字符串非对象", raw=b'"x"')
        invalid_request("JSON 数字非对象", raw=b"123")
        invalid_request("JSON null 非对象", raw=b"null")
        invalid_request("JSON true 非对象", raw=b"true")
        invalid_request("空对象", {})
        for field in ("body", "signature", "schema_id", "schema_version"):
            payload = dict(signed(body))
            payload.pop(field)
            invalid_request(f"缺字段 {field}", payload, headers=T1)
        invalid_request("多余字段",
                        dict(signed(body), extra=1), headers=T1)
        invalid_request("body 为数组",
                        dict(signed(body), body=[]), headers=T1)
        invalid_request("body 为 null",
                        dict(signed(body), body=None), headers=T1)
        invalid_request("signature 为空串",
                        dict(signed(body), signature=""), headers=T1)
        invalid_request("signature 为数字",
                        dict(signed(body), signature=123), headers=T1)
        invalid_request("schema_id 为空串",
                        dict(signed(body), schema_id=""), headers=T1)
        invalid_request("schema_id 为数字",
                        dict(signed(body), schema_id=1), headers=T1)
        invalid_request("schema_id 为 null",
                        dict(signed(body), schema_id=None), headers=T1)
        for bad_version, label in [
            (True, "布尔 true"), (False, "布尔 false"), (0, "零"),
            (-1, "负数"), (1.5, "小数"), ("1", "字符串"), (None, "null"),
        ]:
            invalid_request(
                f"schema_version 非法（{label}）",
                dict(signed(body), schema_version=bad_version),
                headers=T1,
            )
        # 请求参数校验优先于凭证字段：多余字段 + 缺 credential_id
        bad = make_body(drop=("credential_id",))
        invalid_request(
            "请求参数无效优先于凭证字段错误",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1, "x": 1},
            headers=T1,
        )

        # ---------------------------------------------------------- #
        # 3. body 基础字段：沿用“凭证”分类原因，且优先于模式查找
        # ---------------------------------------------------------- #
        for field in ("credential_id", "issuer_did", "subject_did",
                      "claims", "issued_at"):
            bad = make_body(drop=(field,))
            invalid_with_reason(
                f"缺凭证字段 {field}", "凭证",
                {"body": bad, "signature": crypto.sign(bad, priv1),
                 "schema_id": "kyc_basic", "schema_version": 1},
                headers=T1,
            )
        bad = make_body()
        bad["claims"] = []
        invalid_with_reason(
            "claims 非对象", "凭证",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        bad = make_body(key_version=0)
        invalid_with_reason(
            "issuer_key_version 为 0", "凭证",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        # 凭证字段错误优先于模式查找：模式不存在仍返回“凭证”
        bad = make_body(drop=("credential_id",))
        invalid_with_reason(
            "凭证字段校验优先于模式查找", "凭证",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "nope", "schema_version": 1},
            headers=T1,
        )

        # ---------------------------------------------------------- #
        # 4. 模式查找：查不到（含跨租户同名）-> 凭证模式不存在
        # ---------------------------------------------------------- #
        invalid_with_reason(
            "模式未注册", "凭证模式不存在",
            signed(body, schema_id="nope"), headers=T1, exact=True,
        )
        invalid_with_reason(
            "模式版本未注册", "凭证模式不存在",
            signed(body, version=9), headers=T1, exact=True,
        )
        # 跨租户：T2 有 issuer_b 的同名模式，T1 查 issuer_b 按不存在
        body_b = make_body(issuer=issuer_b, digest=digest_b)
        invalid_with_reason(
            "跨租户同名模式按不存在", "凭证模式不存在",
            {"body": body_b, "signature": crypto.sign(body_b, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # 反向：T1 有 issuer1 的模式，T2 查 issuer1 按不存在
        invalid_with_reason(
            "T2 查 T1 模式按不存在", "凭证模式不存在",
            signed(body), headers=T2, exact=True,
        )
        # 模式查找优先于模式绑定：模式不存在 + 摘要错误
        body_bad_digest = make_body(digest="0" * 64)
        invalid_with_reason(
            "模式查找优先于绑定校验", "凭证模式不存在",
            {"body": body_bad_digest,
             "signature": crypto.sign(body_bad_digest, priv1),
             "schema_id": "nope", "schema_version": 1},
            headers=T1, exact=True,
        )

        # ---------------------------------------------------------- #
        # 5. 模式绑定：三字段缺失或不一致 -> 凭证模式绑定不一致
        # ---------------------------------------------------------- #
        for field in ("schema_id", "schema_version", "schema_digest"):
            bad = make_body(drop=(field,))
            invalid_with_reason(
                f"body 缺 {field}", "凭证模式绑定不一致",
                {"body": bad, "signature": crypto.sign(bad, priv1),
                 "schema_id": "kyc_basic", "schema_version": 1},
                headers=T1, exact=True,
            )
        bad = make_body(schema_id="other_schema")
        invalid_with_reason(
            "body schema_id 与请求不一致", "凭证模式绑定不一致",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        bad = make_body(version=2, digest=digest_v2)
        invalid_with_reason(
            "body 绑定 v2 但请求 v1", "凭证模式绑定不一致",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # 不得借用其他版本摘要：body 绑 v1 标识但塞 v2 摘要
        bad = make_body(digest=digest_v2)
        invalid_with_reason(
            "借用其他版本摘要", "凭证模式绑定不一致",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # 请求 v2 但 body 绑 v1
        invalid_with_reason(
            "请求 v2 但 body 绑 v1", "凭证模式绑定不一致",
            signed(body, version=2), headers=T1, exact=True,
        )
        # body schema_version 为布尔（true != 1）
        bad = make_body()
        bad["schema_version"] = True
        invalid_with_reason(
            "body schema_version 为布尔", "凭证模式绑定不一致",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # 绑定校验优先于 claims：摘要不一致 + 缺必填路径
        bad = make_body(digest=digest_v2, claims={"age": 30})
        invalid_with_reason(
            "绑定校验优先于 claims 校验", "凭证模式绑定不一致",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )

        # ---------------------------------------------------------- #
        # 6. claims 约束：缺必填路径/类型不符 -> schema validation failed
        # ---------------------------------------------------------- #
        bad = make_body(claims={"age": 30})
        invalid_with_reason(
            "claims 缺必填路径 /name", "schema validation failed",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        bad = make_body(claims={"name": "张三", "age": "30"})
        invalid_with_reason(
            "claims 路径类型不符", "schema validation failed",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        bad = make_body(claims={"name": "张三", "age": 30,
                                "addr": {"city": 123}})
        invalid_with_reason(
            "嵌套声明路径类型不符", "schema validation failed",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # claims 校验优先于锚点：issuer2 无锚点但 claims 先失败
        bad = make_body(issuer=issuer2, digest=digest_i2,
                        claims={"age": 30})
        invalid_with_reason(
            "claims 校验优先于锚点", "schema validation failed",
            {"body": bad, "signature": crypto.sign(bad, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )

        # ---------------------------------------------------------- #
        # 7. 锚点：缺失/吊销/无 vc 用途沿用现有原因，优先于签名格式
        # ---------------------------------------------------------- #
        body_i2 = make_body(issuer=issuer2, digest=digest_i2)
        invalid_with_reason(
            "锚点不存在", "锚点不存在",
            {"body": body_i2, "signature": crypto.sign(body_i2, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        # 锚点校验优先于签名格式
        invalid_with_reason(
            "锚点校验优先于签名格式", "锚点不存在",
            {"body": body_i2, "signature": "!!!bad!!!",
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        st, _ = _http("PUT", f"{BASE}/v1/trust/anchors/{issuer4}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 issuer4 锚点 -> 200", st == 200)
        body_i4 = make_body(issuer=issuer4, digest=digest_i4)
        invalid_with_reason(
            "锚点已吊销", "锚点已吊销",
            {"body": body_i4, "signature": crypto.sign(body_i4, priv4),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )

        # ---------------------------------------------------------- #
        # 8. 签名格式与密码学验签
        # ---------------------------------------------------------- #
        invalid_with_reason(
            "非 base64url 签名", "签名格式错误",
            {"body": body, "signature": "!!!not-b64!!!",
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        too_short = crypto.sign(body, priv1)[:-2]
        invalid_with_reason(
            "签名长度不足", "签名格式错误",
            {"body": body, "signature": too_short,
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        invalid_with_reason(
            "错误私钥签名", "签名校验失败",
            signed(body, priv=priv3), headers=T1,
        )
        tampered = json.loads(json.dumps(body))
        tampered["claims"]["name"] = "李四"
        invalid_with_reason(
            "篡改 claims（仍满足模式）-> 签名校验失败", "签名校验失败",
            {"body": tampered, "signature": crypto.sign(body, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        tampered_digest = json.loads(json.dumps(body))
        tampered_digest["schema_digest"] = digest_v2
        invalid_with_reason(
            "篡改摘要先命中绑定不一致", "凭证模式绑定不一致",
            {"body": tampered_digest, "signature": crypto.sign(body, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )

        # ---------------------------------------------------------- #
        # 9. 有效期
        # ---------------------------------------------------------- #
        body_exp = make_body(extra={"expires_at": "2020-01-01T00:00:00Z"})
        invalid_with_reason(
            "凭证已过期", "凭证已过期",
            {"body": body_exp, "signature": crypto.sign(body_exp, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        body_future = make_body(extra={"expires_at": "2099-01-01T00:00:00Z"})
        st, r = verify(
            {"body": body_future,
             "signature": crypto.sign(body_future, priv1),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        check("未过期凭证验真成功", st == 200 and r == {"valid": True})

        # ---------------------------------------------------------- #
        # 10. 模式版本 deprecated/revoked 不追溯失效
        # ---------------------------------------------------------- #
        body_v2 = make_body(version=2, digest=digest_v2,
                            claims={"name": "张三"})
        st, r = verify(signed(body_v2, version=2), headers=T1)
        check("v2 模式验真成功", st == 200 and r == {"valid": True})
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/kyc_basic/2/status",
            {"issuer_did": issuer1, "status": "deprecated"}, headers=T1,
        )
        check("deprecated v2 -> 201", st == 201)
        st, r = verify(signed(body_v2, version=2), headers=T1)
        check("deprecated 后历史外部凭证仍按原摘要验真",
              st == 200 and r == {"valid": True})
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/kyc_basic/2/status",
            {"issuer_did": issuer1, "status": "revoked"}, headers=T1,
        )
        check("revoked v2 -> 201", st == 201)
        st, r = verify(signed(body_v2, version=2), headers=T1)
        check("revoked 后历史外部凭证仍按原摘要验真",
              st == 200 and r == {"valid": True})

        # ---------------------------------------------------------- #
        # 11. 只读：不登记凭证、不记审计、不改模式
        # ---------------------------------------------------------- #
        st, before = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(signed(body), headers=T1)
            verify({"body": body, "signature": "bad",
                    "schema_id": "kyc_basic", "schema_version": 1},
                   headers=T1)
            verify(raw=b"not-json", headers=T1)
        st, after = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T1)
        check("验真（含失败）不记审计",
              len(after["events"]) == n_before)
        st, _ = _http("GET", f"{BASE}/v1/credentials/{cred_id}", headers=T1)
        check("验真后凭证仍未登记（GET 404）", st == 404)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1"
            f"?issuer_did={issuer1}",
            headers=T1,
        )
        check("模式内容未被改动",
              st == 200 and r.get("digest") == digest_v1)

        # ---------------------------------------------------------- #
        # 12. 外部签发 DID 停用通告（最后判定，先于其的过期仍优先）
        # ---------------------------------------------------------- #
        body_i3 = make_body(issuer=issuer3, digest=digest_i3)
        st, r = verify(
            {"body": body_i3, "signature": crypto.sign(body_i3, priv3),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1,
        )
        check("停用通告前验真成功", st == 200 and r == {"valid": True})
        notice = {
            "did": issuer3,
            "key_version": 1,
            "reason": "机构业务终止",
            "deactivated_at": "2026-09-20T10:00:00Z",
        }
        st, _ = _http(
            "POST", f"{BASE}/v1/trust/dids/deactivate-sync",
            {"body": notice, "signature": crypto.sign(notice, priv3)},
            headers=T1,
        )
        check("登记外部停用通告 -> 201", st == 201)
        invalid_with_reason(
            "外部签发 DID 已停用", "外部签发DID已停用：机构业务终止",
            {"body": body_i3, "signature": crypto.sign(body_i3, priv3),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # 有效期判定先于停用通告
        body_i3_exp = make_body(issuer=issuer3, digest=digest_i3,
                                extra={"expires_at": "2020-01-01T00:00:00Z"})
        invalid_with_reason(
            "过期优先于停用通告", "凭证已过期",
            {"body": body_i3_exp,
             "signature": crypto.sign(body_i3_exp, priv3),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        # 仅他租户有通告不影响本租户结论：T2 无 issuer3 通告，但 T2 也
        # 无 issuer3 模式 -> 仍为模式不存在（隔离）
        invalid_with_reason(
            "他租户通告不泄漏且模式隔离", "凭证模式不存在",
            {"body": body_i3, "signature": crypto.sign(body_i3, priv3),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T2, exact=True,
        )

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 13. 跨重启：模式、锚点、停用通告持久化，结论不变
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(), "服务重启超时"
        body = make_body()
        st, r = verify(signed(body), headers=T1)
        check("重启后 v1 验真仍成功", st == 200 and r == {"valid": True})
        body_v2 = make_body(version=2, digest=digest_v2,
                            claims={"name": "张三"})
        st, r = verify(signed(body_v2, version=2), headers=T1)
        check("重启后 revoked 模式版本仍按原摘要验真",
              st == 200 and r == {"valid": True})
        body_i3 = make_body(issuer=issuer3, digest=digest_i3)
        invalid_with_reason(
            "重启后停用通告仍生效", "外部签发DID已停用：机构业务终止",
            {"body": body_i3, "signature": crypto.sign(body_i3, priv3),
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T1, exact=True,
        )
        invalid_with_reason(
            "重启后跨租户模式仍不可见", "凭证模式不存在",
            signed(body), headers=T2, exact=True,
        )
        st, _ = _http("GET", f"{BASE}/v1/credentials/{cred_id}", headers=T1)
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


if __name__ == "__main__":
    raise SystemExit(main())
