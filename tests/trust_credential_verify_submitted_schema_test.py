#!/usr/bin/env python3
"""随请求提交模式的只读验真 POST /v1/trust/credentials/verify-with-schema
（额外 schema 对象）测试。

直接运行：python3 tests/trust_credential_verify_submitted_schema_test.py
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
from vcbackend import store as store_mod  # noqa: E402

PORT = 8981
BASE = f"http://127.0.0.1:{PORT}"
PATH = "/v1/trust/credentials/verify-with-schema"
INVALID_REQUEST = {"valid": False, "reason": "请求参数无效"}
SCHEMA_INVALID = {"valid": False, "reason": "凭证模式非法"}
BINDING_MISMATCH = {"valid": False, "reason": "凭证模式绑定不一致"}
CLAIMS_FAILED = {"valid": False, "reason": "schema validation failed"}


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


def make_schema(schema_id, version, issuer_did, claim_types, required):
    content = {
        "schema_id": schema_id,
        "version": version,
        "issuer_did": issuer_did,
        "claim_types": claim_types,
        "required_claims": required,
    }
    schema = dict(content)
    schema["digest"] = store_mod.schema_content_digest(content)
    return schema


CLAIM_TYPES = {
    "/name": "string",
    "/age": "integer",
    "/addr/city": "string",
    "/tags/0": "string",
    "/vip": "boolean",
}
REQUIRED = ["/name", "/age"]


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

    def expect(name, payload, want, headers=None):
        st, r = verify(payload, headers=headers)
        check(name, st == 200 and r == want)

    T1 = {"X-Tenant-ID": "vss-a"}
    T2 = {"X-Tenant-ID": "vss-b"}

    try:
        assert wait_up(), "服务启动超时"

        # 外部签发者：本租户只有锚点，无本地 DID、无本地模式
        ext_issuer = "did:web:external-issuer.example"
        priv, pub = gen_keypair()
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ext_issuer, "public_key": pub,
                       "key_version": 1}, headers=T1)
        assert st == 201, st
        priv2, pub2 = gen_keypair()

        schema = make_schema("kyc_basic", 1, ext_issuer,
                             CLAIM_TYPES, REQUIRED)
        digest = schema["digest"]

        cred_id = "vc_submitted_schema_0001"

        def make_body(issuer=ext_issuer, schema_id="kyc_basic", version=1,
                      dgst=None, claims=None, extra=None, drop=()):
            body = {
                "credential_id": cred_id,
                "issuer_did": issuer,
                "subject_did": "did:web:subject.example",
                "claims": claims if claims is not None else {
                    "name": "张三", "age": 30, "addr": {"city": "北京"},
                    "tags": ["vip"], "vip": False,
                },
                "issued_at": "2026-09-21T00:00:00Z",
                "schema_id": schema_id,
                "schema_version": version,
                "schema_digest": dgst if dgst is not None else digest,
            }
            if extra:
                body.update(extra)
            for field in drop:
                body.pop(field, None)
            return body

        def signed(body_obj, schema_obj=None, schema_id="kyc_basic",
                   version=1, key=priv):
            payload = {
                "body": body_obj,
                "signature": crypto.sign(body_obj, key),
                "schema_id": schema_id,
                "schema_version": version,
            }
            if schema_obj is not None:
                payload["schema"] = schema_obj
            return payload

        # ---------------------------------------------------------- #
        # 1. 提交模式成功：issuer 无本地 DID/模式，仅锚点
        # ---------------------------------------------------------- #
        body = make_body()
        st, r = verify(signed(body, schema), headers=T1)
        check("提交模式验真成功仅返 valid:true",
              st == 200 and r == {"valid": True})

        # 可选路径缺失仍成功；未声明额外 claims 不影响
        body_opt = make_body(claims={"name": "张三", "age": 30,
                                     "extra": {"x": 1}})
        st, r = verify(signed(body_opt, schema), headers=T1)
        check("可选路径缺失+额外 claims 仍成功",
              st == 200 and r == {"valid": True})

        # 布尔不作为数字/整数：vip 声明 boolean，age 给布尔判失败
        body_bool = make_body(claims={"name": "张三", "age": True})
        expect("布尔不作为 integer", signed(body_bool, schema),
               CLAIMS_FAILED, headers=T1)

        # 数组索引与 RFC6901 转义：tags/0 类型不符
        body_arr = make_body(claims={"name": "张三", "age": 30,
                                     "tags": [1]})
        expect("数组索引路径类型不符", signed(body_arr, schema),
               CLAIMS_FAILED, headers=T1)

        # ---------------------------------------------------------- #
        # 2. 外层请求：schema 非对象/多余字段 -> 请求参数无效
        # ---------------------------------------------------------- #
        for bad_schema, label in [
            ([], "数组"), ("x", "字符串"), (1, "数字"), (None, "null"),
            (True, "布尔"),
        ]:
            st, r = verify(dict(signed(body, schema), schema=bad_schema),
                           headers=T1)
            check(f"schema 为{label} -> 请求参数无效",
                  st == 200 and r == INVALID_REQUEST)
        st, r = verify(dict(signed(body, schema), extra=1), headers=T1)
        check("schema + 多余字段 -> 请求参数无效",
              st == 200 and r == INVALID_REQUEST)
        # 显式空租户头仍 400
        st, _ = verify(signed(body, schema), headers={"X-Tenant-ID": ""})
        check("提交模式时显式空 X-Tenant-ID -> 400", st == 400)
        # 外层非法优先于模式内容：schema 非对象 + body 缺字段
        bad_body = make_body(drop=("credential_id",))
        st, r = verify({"body": bad_body,
                        "signature": crypto.sign(bad_body, priv),
                        "schema_id": "kyc_basic", "schema_version": 1,
                        "schema": []}, headers=T1)
        check("外层非法优先于凭证字段", st == 200 and r == INVALID_REQUEST)

        # ---------------------------------------------------------- #
        # 3. 模式内容：缺/多字段、内容非法、摘要格式或重算不符
        # ---------------------------------------------------------- #
        for field in ("schema_id", "version", "issuer_did",
                      "claim_types", "required_claims", "digest"):
            bad = dict(schema)
            bad.pop(field)
            expect(f"模式缺字段 {field}", signed(body, bad),
                   SCHEMA_INVALID, headers=T1)
        expect("模式多余字段", signed(body, dict(schema, x=1)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 schema_id 格式非法",
               signed(body, make_schema("KYC", 1, ext_issuer,
                                        CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 version 为 0",
               signed(body, make_schema("kyc_basic", 0, ext_issuer,
                                        CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 version 为布尔",
               signed(body, dict(schema, version=True)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 issuer_did 为空",
               signed(body, make_schema("kyc_basic", 1, "",
                                        CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 claim_types 为空",
               signed(body, make_schema("kyc_basic", 1, ext_issuer,
                                        {}, REQUIRED)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 claim_types 类型非法",
               signed(body, make_schema(
                   "kyc_basic", 1, ext_issuer,
                   dict(CLAIM_TYPES, **{"/age": "str"}), REQUIRED)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 required 不在 claim_types",
               signed(body, make_schema("kyc_basic", 1, ext_issuer,
                                        CLAIM_TYPES, ["/name", "/nope"])),
               SCHEMA_INVALID, headers=T1)
        expect("模式 digest 非字符串", signed(body, dict(schema, digest=1)),
               SCHEMA_INVALID, headers=T1)
        expect("模式 digest 大写 hex",
               signed(body, dict(schema, digest=digest.upper())),
               SCHEMA_INVALID, headers=T1)
        expect("模式 digest 长度不足",
               signed(body, dict(schema, digest=digest[:-1])),
               SCHEMA_INVALID, headers=T1)
        expect("模式 digest 重算不符",
               signed(body, dict(schema, digest="0" * 64)),
               SCHEMA_INVALID, headers=T1)
        # 模式内容非法优先于绑定：schema_id 格式非法 + 与外层不一致
        expect("模式内容非法优先于绑定",
               signed(make_body(schema_id="KYC", dgst=digest),
                      make_schema("KYC", 1, ext_issuer,
                                  CLAIM_TYPES, REQUIRED),
                      schema_id="KYC"),
               SCHEMA_INVALID, headers=T1)

        # ---------------------------------------------------------- #
        # 4. 绑定：签发者/标识/版本/正文摘要缺失或不一致
        # ---------------------------------------------------------- #
        expect("模式签发者与正文不一致",
               signed(body, make_schema("kyc_basic", 1,
                                        "did:web:other.example",
                                        CLAIM_TYPES, REQUIRED)),
               BINDING_MISMATCH, headers=T1)
        expect("模式标识与外层不一致",
               signed(body, make_schema("other_schema", 1, ext_issuer,
                                        CLAIM_TYPES, REQUIRED)),
               BINDING_MISMATCH, headers=T1)
        expect("模式版本与外层不一致",
               signed(body, make_schema("kyc_basic", 2, ext_issuer,
                                        CLAIM_TYPES, REQUIRED)),
               BINDING_MISMATCH, headers=T1)
        for field in ("schema_id", "schema_version", "schema_digest"):
            bad = make_body(drop=(field,))
            expect(f"正文缺 {field}", signed(bad, schema),
                   BINDING_MISMATCH, headers=T1)
        expect("正文摘要与提交摘要不符",
               signed(make_body(dgst="0" * 64), schema),
               BINDING_MISMATCH, headers=T1)
        bad = make_body()
        bad["schema_version"] = True
        expect("正文 schema_version 为布尔", signed(bad, schema),
               BINDING_MISMATCH, headers=T1)
        # 绑定优先于 claims：绑定不一致 + 缺必填路径
        expect("绑定优先于 claims",
               signed(make_body(dgst="0" * 64, claims={"age": 30}), schema),
               BINDING_MISMATCH, headers=T1)

        # ---------------------------------------------------------- #
        # 5. claims：缺必填/类型不符 -> schema validation failed
        # ---------------------------------------------------------- #
        expect("缺必填路径", signed(make_body(claims={"age": 30}), schema),
               CLAIMS_FAILED, headers=T1)
        expect("声明路径类型不符",
               signed(make_body(claims={"name": "张三", "age": "30"}),
                      schema),
               CLAIMS_FAILED, headers=T1)
        expect("嵌套路径类型不符",
               signed(make_body(claims={"name": "张三", "age": 30,
                                        "addr": {"city": 1}}), schema),
               CLAIMS_FAILED, headers=T1)
        # claims 优先于锚点：错误私钥签名但 claims 先失败
        bad = make_body(claims={"age": 30})
        expect("claims 优先于锚点/签名",
               {"body": bad, "signature": crypto.sign(bad, priv2),
                "schema_id": "kyc_basic", "schema_version": 1,
                "schema": schema},
               CLAIMS_FAILED, headers=T1)

        # ---------------------------------------------------------- #
        # 6. 锚点/签名/有效期沿用既有原因
        # ---------------------------------------------------------- #
        other_issuer = "did:web:no-anchor.example"
        schema_other = make_schema("kyc_basic", 1, other_issuer,
                                   CLAIM_TYPES, REQUIRED)
        body_other = make_body(issuer=other_issuer,
                               dgst=schema_other["digest"])
        st, r = verify({"body": body_other,
                        "signature": crypto.sign(body_other, priv),
                        "schema_id": "kyc_basic", "schema_version": 1,
                        "schema": schema_other}, headers=T1)
        check("锚点不存在", st == 200 and r["valid"] is False
              and r["reason"].startswith("锚点不存在"))
        st, r = verify({"body": body, "signature": "!!!bad!!!",
                        "schema_id": "kyc_basic", "schema_version": 1,
                        "schema": schema}, headers=T1)
        check("签名格式错误", st == 200 and r["valid"] is False
              and r["reason"].startswith("签名格式错误"))
        st, r = verify(signed(body, schema, key=priv2), headers=T1)
        check("错误私钥 -> 签名校验失败", st == 200
              and r["valid"] is False
              and r["reason"].startswith("签名校验失败"))
        body_exp = make_body(extra={"expires_at": "2020-01-01T00:00:00Z"})
        st, r = verify(signed(body_exp, schema), headers=T1)
        check("凭证已过期", st == 200
              and r == {"valid": False, "reason": "凭证已过期"})

        # ---------------------------------------------------------- #
        # 7. 本地模式不影响提交模式验真（不同内容/弃用/吊销/跨租户）
        # ---------------------------------------------------------- #
        # 本租户注册同名同版本但内容不同的本地模式（本地 DID 签发）
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "local-1"},
                      headers=T1)
        assert st == 201, (st, r)
        local_issuer = r["did"]
        st, r = _http("POST", f"{BASE}/v1/credential-schemas",
                      {"schema_id": "kyc_basic", "version": 1,
                       "issuer_did": local_issuer,
                       "claim_types": {"/name": "string"},
                       "required_claims": ["/name"]},
                      headers=T1)
        assert st == 201, (st, r)
        local_digest = r["digest"]
        assert local_digest != digest
        st, r = verify(signed(body, schema), headers=T1)
        check("本地同名异内容模式不影响提交模式验真",
              st == 200 and r == {"valid": True})
        # 本地模式弃用/吊销不影响
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/kyc_basic/1/status",
            {"issuer_did": local_issuer, "status": "revoked"}, headers=T1)
        check("吊销本地模式 -> 201", st == 201)
        st, r = verify(signed(body, schema), headers=T1)
        check("本地模式吊销后提交模式验真仍成功",
              st == 200 and r == {"valid": True})
        # 他租户同名模式不被借用：T2 无任何本地数据，提交模式独立成立
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ext_issuer, "public_key": pub,
                       "key_version": 1}, headers=T2)
        assert st == 201, st
        st, r = verify(signed(body, schema), headers=T2)
        check("他租户提交同一模式独立验真成功",
              st == 200 and r == {"valid": True})
        # 提交模式不回退本地：T1 有 local_issuer 的本地模式，但提交
        # 模式内容非法时不回退用本地内容验真
        expect("提交模式非法不回退本地同名模式",
               signed(body, dict(schema, digest="0" * 64)),
               SCHEMA_INVALID, headers=T1)

        # ---------------------------------------------------------- #
        # 8. 只读：不登记模式/凭证、不记审计
        # ---------------------------------------------------------- #
        st, before = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(signed(body, schema), headers=T1)
            verify(signed(make_body(claims={"age": 30}), schema),
                   headers=T1)
            verify(dict(signed(body, schema), schema="x"), headers=T1)
        st, after = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T1)
        check("提交模式验真（含失败）不记审计",
              len(after["events"]) == n_before)
        st, _ = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1"
            f"?issuer_did={ext_issuer}",
            headers=T1,
        )
        check("提交的模式未被登记（GET 404）", st == 404)
        st, _ = _http("GET", f"{BASE}/v1/credentials/{cred_id}", headers=T1)
        check("验真后凭证仍未登记（GET 404）", st == 404)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1"
            f"?issuer_did={local_issuer}",
            headers=T1,
        )
        check("本地模式内容未被提交模式覆盖",
              st == 200 and r.get("digest") == local_digest)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 9. 跨重启：提交模式验真结论不变（不依赖任何持久化模式）
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(), "服务重启超时"
        schema = make_schema("kyc_basic", 1, ext_issuer,
                             CLAIM_TYPES, REQUIRED)
        body = make_body()
        st, r = verify(signed(body, schema), headers=T1)
        check("重启后提交模式验真仍成功", st == 200 and r == {"valid": True})
        st, _ = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1"
            f"?issuer_did={ext_issuer}",
            headers=T1,
        )
        check("重启后提交的模式仍未登记", st == 404)
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
