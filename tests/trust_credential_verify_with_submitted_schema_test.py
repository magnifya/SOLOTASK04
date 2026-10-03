#!/usr/bin/env python3
"""随请求提交模式的只读验真 POST /v1/trust/credentials/verify-with-schema 测试。

覆盖：请求额外包含 schema 对象（模式查询响应六字段格式）时只采用提交
模式验真，无需在验证租户预先登记模式或签发者 DID；省略 schema 时保持
原行为（由 trust_credential_verify_with_schema_test.py 覆盖）。

直接运行：python3 tests/trust_credential_verify_with_submitted_schema_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
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

PORT = 8980
BASE = f"http://127.0.0.1:{PORT}"
PATH = "/v1/trust/credentials/verify-with-schema"
INVALID_REQUEST = {"valid": False, "reason": "请求参数无效"}
SCHEMA_INVALID = {"valid": False, "reason": "凭证模式非法"}
BINDING_MISMATCH = {"valid": False, "reason": "凭证模式绑定不一致"}
CLAIMS_FAILED = {"valid": False, "reason": "schema validation failed"}
DEACTIVATED = {"valid": False, "reason": "外部签发DID已停用：机构业务终止"}


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


def make_schema(schema_id, version, issuer_did, claim_types, required_claims,
                digest=None):
    """构造六字段提交模式；digest 缺省按五字段规范化 JSON 重算。"""
    content = {
        "schema_id": schema_id,
        "version": version,
        "issuer_did": issuer_did,
        "claim_types": claim_types,
        "required_claims": required_claims,
    }
    if digest is None:
        digest = hashlib.sha256(crypto.canonicalize(content)).hexdigest()
    return dict(content, digest=digest)


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

    def expect(name, payload, wanted, headers=None):
        st, r = verify(payload, headers=headers)
        check(name, st == 200 and r == wanted)

    T1 = {"X-Tenant-ID": "vws-sub-a"}
    T2 = {"X-Tenant-ID": "vws-sub-b"}

    # 外部签发者：不在验证租户登记 DID、不登记模式，仅登记信任锚点。
    ISSUER = "did:example:external-issuer"
    ISSUER_NO_ANCHOR = "did:example:external-no-anchor"
    SCHEMA_ID = "kyc_basic"
    CLAIM_TYPES = {
        "/name": "string",
        "/age": "integer",
        "/score": "number",
        "/addr/city": "string",
        "/tags/0": "string",
        "/a~0b": "string",
        "/m~1n": "boolean",
    }
    REQUIRED = ["/name", "/age"]
    SCHEMA = make_schema(SCHEMA_ID, 1, ISSUER, CLAIM_TYPES, REQUIRED)
    DIGEST = SCHEMA["digest"]

    try:
        assert wait_up(), "服务启动超时"

        priv, pub = gen_keypair()
        priv_other, _ = gen_keypair()
        priv_local, pub_local = gen_keypair()

        # 显式空租户头仍 400（带 schema 也一样，在进入验签前判定）
        st, _ = verify(
            payload={"body": {}, "signature": "x", "schema_id": SCHEMA_ID,
                     "schema_version": 1, "schema": SCHEMA},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID（带 schema）-> 400", st == 400)

        # 登记锚点（无需登记 DID）；T2 不登记任何锚点
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ISSUER, "public_key": pub, "key_version": 1},
                      headers=T1)
        check("登记外部签发者锚点 -> 201", st == 201)

        # 本地签发者：本地 DID + 同名同版本但内容不同的本地模式 + 锚点，
        # 用于验证提交模式不回退/不覆盖本地同名版本。
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "local-issuer"},
                      headers=T1)
        assert st == 201, (st, r)
        ISSUER_LOCAL = r["did"]
        st, r = _http(
            "POST", f"{BASE}/v1/credential-schemas",
            {"schema_id": SCHEMA_ID, "version": 1,
             "issuer_did": ISSUER_LOCAL,
             "claim_types": {"/name": "string"},
             "required_claims": ["/name"]},
            headers=T1,
        )
        assert st == 201, (st, r)
        local_digest = r["digest"]
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ISSUER_LOCAL, "public_key": pub_local,
                       "key_version": 1}, headers=T1)
        check("登记本地签发者锚点 -> 201", st == 201)
        SCHEMA_LOCAL = make_schema(SCHEMA_ID, 1, ISSUER_LOCAL,
                                   {"/name": "string", "/age": "integer"},
                                   ["/name", "/age"])
        assert SCHEMA_LOCAL["digest"] != local_digest

        cred_id = "vc_external_submitted_schema_0001"

        def make_body(issuer=ISSUER, schema_id=SCHEMA_ID, version=1,
                      digest=DIGEST, claims=None, extra=None,
                      key_version=1, drop=(), cid=cred_id):
            body = {
                "credential_id": cid,
                "issuer_did": issuer,
                "subject_did": "did:web:subject.example",
                "claims": claims if claims is not None else {
                    "name": "张三", "age": 30, "score": 98.5,
                    "addr": {"city": "北京"}, "tags": ["vip"],
                    "a~b": "x", "m/n": True,
                },
                "issued_at": "2026-09-21T00:00:00Z",
                "schema_id": schema_id,
                "schema_version": version,
                "schema_digest": digest,
            }
            if key_version is not None:
                body["issuer_key_version"] = key_version
            if extra:
                body.update(extra)
            for field in drop:
                body.pop(field, None)
            return body

        def signed(payload_body, priv_key=priv, schema_id=SCHEMA_ID,
                   version=1, schema=SCHEMA):
            payload = {
                "body": payload_body,
                "signature": crypto.sign(payload_body, priv_key),
                "schema_id": schema_id,
                "schema_version": version,
            }
            if schema is not None:
                payload["schema"] = schema
            return payload

        body = make_body()

        # ---------------------------------------------------------- #
        # 1. 成功：随请求提交模式，无需登记模式或签发者 DID
        # ---------------------------------------------------------- #
        st, r = verify(signed(body), headers=T1)
        check("提交模式验真成功仅返 valid:true",
              st == 200 and r == {"valid": True})

        # 可选声明路径缺失仍成功；未声明的额外 claims 不影响
        body_optional = make_body(claims={"name": "张三", "age": 30,
                                          "extra": [1, 2]})
        st, r = verify(signed(body_optional), headers=T1)
        check("可选路径缺失+额外 claims 仍成功",
              st == 200 and r == {"valid": True})

        # 数组索引与 RFC6901 转义路径类型校验生效
        body_escape = make_body(claims={"name": "张三", "age": 30,
                                        "tags": ["vip"], "a~b": "ok",
                                        "m/n": False})
        st, r = verify(signed(body_escape), headers=T1)
        check("数组索引与转义路径命中且类型正确",
              st == 200 and r == {"valid": True})

        # 省略 issuer_key_version 按 v1 验真且不注入正文
        body_no_kv = make_body(key_version=None)
        st, r = verify(signed(body_no_kv), headers=T1)
        check("省略 issuer_key_version 按 v1 验真成功",
              st == 200 and r == {"valid": True})

        # ---------------------------------------------------------- #
        # 2. 外层请求：schema 非对象/多余字段等 -> 请求参数无效
        # ---------------------------------------------------------- #
        for bad_schema, label in [
            ([], "数组"), ("x", "字符串"), (1, "数字"), (True, "布尔"),
        ]:
            expect(f"schema 为{label} -> 请求参数无效",
                   signed(body, schema=bad_schema), INVALID_REQUEST, T1)
        expect("schema 为null -> 请求参数无效",
               dict(signed(body), schema=None), INVALID_REQUEST, T1)
        expect("带 schema 仍拒绝多余字段",
               dict(signed(body), extra=1), INVALID_REQUEST, T1)
        for field in ("body", "signature", "schema_id", "schema_version"):
            payload = dict(signed(body))
            payload.pop(field)
            expect(f"带 schema 缺字段 {field} -> 请求参数无效",
                   payload, INVALID_REQUEST, T1)
        # 外层非法优先于模式内容非法
        expect("外层非法优先于模式内容非法",
               dict(signed(body, schema={"bogus": 1}), extra=1),
               INVALID_REQUEST, T1)
        # 正文基础字段错误优先于模式内容非法
        expect("正文基础字段优先于模式内容",
               signed(make_body(drop=("credential_id",)),
                      schema=dict(SCHEMA, extra=1)),
               {"valid": False, "reason": "凭证缺少字段: credential_id"},
               T1)

        # ---------------------------------------------------------- #
        # 3. 模式内容：字段缺失/多余、内容非法、摘要格式或重算不符
        #    -> 凭证模式非法
        # ---------------------------------------------------------- #
        for field in ("schema_id", "version", "issuer_did", "claim_types",
                      "required_claims", "digest"):
            bad_schema = dict(SCHEMA)
            bad_schema.pop(field)
            expect(f"提交模式缺字段 {field}", signed(body, schema=bad_schema),
                   SCHEMA_INVALID, T1)
        expect("提交模式含多余字段",
               signed(body, schema=dict(SCHEMA, extra=1)),
               SCHEMA_INVALID, T1)
        expect("提交模式 schema_id 形式非法",
               signed(body, schema=make_schema("Bad_ID", 1, ISSUER,
                                               CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, T1)
        expect("提交模式 version 为 0",
               signed(body, schema=make_schema(SCHEMA_ID, 0, ISSUER,
                                               CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, T1)
        expect("提交模式 version 为布尔",
               signed(body, schema=make_schema(SCHEMA_ID, True, ISSUER,
                                               CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, T1)
        expect("提交模式 issuer_did 为空",
               signed(body, schema=make_schema(SCHEMA_ID, 1, "",
                                               CLAIM_TYPES, REQUIRED)),
               SCHEMA_INVALID, T1)
        expect("提交模式 claim_types 为空对象",
               signed(body, schema=make_schema(SCHEMA_ID, 1, ISSUER,
                                               {}, REQUIRED)),
               SCHEMA_INVALID, T1)
        expect("提交模式 claim_types 类型值非法",
               signed(body, schema=make_schema(
                   SCHEMA_ID, 1, ISSUER, {"/name": "text"}, ["/name"])),
               SCHEMA_INVALID, T1)
        expect("提交模式 required_claims 含未声明路径",
               signed(body, schema=make_schema(
                   SCHEMA_ID, 1, ISSUER, {"/name": "string"},
                   ["/name", "/age"])),
               SCHEMA_INVALID, T1)
        expect("提交模式 digest 非小写十六进制（大写）",
               signed(body, schema=make_schema(SCHEMA_ID, 1, ISSUER,
                                               CLAIM_TYPES, REQUIRED,
                                               digest=DIGEST.upper())),
               SCHEMA_INVALID, T1)
        expect("提交模式 digest 长度不足",
               signed(body, schema=make_schema(SCHEMA_ID, 1, ISSUER,
                                               CLAIM_TYPES, REQUIRED,
                                               digest="0" * 63)),
               SCHEMA_INVALID, T1)
        expect("提交模式 digest 非字符串",
               signed(body, schema=make_schema(SCHEMA_ID, 1, ISSUER,
                                               CLAIM_TYPES, REQUIRED,
                                               digest=123)),
               SCHEMA_INVALID, T1)
        expect("提交模式 digest 重算不符",
               signed(body, schema=make_schema(SCHEMA_ID, 1, ISSUER,
                                               CLAIM_TYPES, REQUIRED,
                                               digest="0" * 64)),
               SCHEMA_INVALID, T1)
        # 模式内容非法优先于绑定不一致（digest 错 + 绑定标识错）
        expect("模式内容非法优先于绑定不一致",
               signed(make_body(schema_id="other"),
                      schema=make_schema(SCHEMA_ID, 1, ISSUER,
                                         CLAIM_TYPES, REQUIRED,
                                         digest="0" * 64)),
               SCHEMA_INVALID, T1)
        # 模式内容非法优先于 claims 违规
        expect("模式内容非法优先于 claims 校验",
               signed(make_body(claims={"age": 30}),
                      schema=dict(SCHEMA, extra=1)),
               SCHEMA_INVALID, T1)

        # ---------------------------------------------------------- #
        # 4. 绑定：提交模式与外层/正文不一致 -> 凭证模式绑定不一致
        # ---------------------------------------------------------- #
        expect("提交模式 schema_id 与外层不一致",
               signed(body, schema=make_schema("other_schema", 1, ISSUER,
                                               CLAIM_TYPES, REQUIRED)),
               BINDING_MISMATCH, T1)
        expect("提交模式 version 与外层不一致",
               signed(body, schema=make_schema(SCHEMA_ID, 2, ISSUER,
                                               CLAIM_TYPES, REQUIRED)),
               BINDING_MISMATCH, T1)
        expect("提交模式 issuer_did 与正文不一致",
               signed(body, schema=make_schema(SCHEMA_ID, 1, "did:example:x",
                                               CLAIM_TYPES, REQUIRED)),
               BINDING_MISMATCH, T1)
        expect("正文 schema_digest 与提交摘要不一致",
               signed(make_body(digest="f" * 64)), BINDING_MISMATCH, T1)
        expect("正文缺 schema_digest",
               signed(make_body(drop=("schema_digest",))),
               BINDING_MISMATCH, T1)
        expect("正文 schema_id 与外层不一致",
               signed(make_body(schema_id="other_schema")),
               BINDING_MISMATCH, T1)
        expect("正文 schema_version 与外层不一致",
               signed(make_body(version=2)), BINDING_MISMATCH, T1)
        # 绑定不一致优先于 claims 违规
        expect("绑定不一致优先于 claims 校验",
               signed(make_body(digest="f" * 64, claims={"age": 30})),
               BINDING_MISMATCH, T1)

        # ---------------------------------------------------------- #
        # 5. claims 约束：必填路径、数组索引、转义、类型语义
        # ---------------------------------------------------------- #
        expect("claims 缺必填路径 /name",
               signed(make_body(claims={"age": 30})), CLAIMS_FAILED, T1)
        expect("claims 路径类型不符（integer 收到字符串）",
               signed(make_body(claims={"name": "张三", "age": "30"})),
               CLAIMS_FAILED, T1)
        expect("布尔不作为数字（integer 收到 true）",
               signed(make_body(claims={"name": "张三", "age": True})),
               CLAIMS_FAILED, T1)
        expect("布尔不作为数字（number 收到 false）",
               signed(make_body(claims={"name": "张三", "age": 30,
                                        "score": False})),
               CLAIMS_FAILED, T1)
        expect("数组索引路径类型不符",
               signed(make_body(claims={"name": "张三", "age": 30,
                                        "tags": [123]})),
               CLAIMS_FAILED, T1)
        expect("数组越界视为可选路径缺失",
               signed(make_body(claims={"name": "张三", "age": 30,
                                        "tags": []})),
               {"valid": True}, T1)
        expect("转义路径类型不符",
               signed(make_body(claims={"name": "张三", "age": 30,
                                        "a~b": 1})),
               CLAIMS_FAILED, T1)
        expect("嵌套声明路径类型不符",
               signed(make_body(claims={"name": "张三", "age": 30,
                                        "addr": {"city": 123}})),
               CLAIMS_FAILED, T1)
        # claims 校验优先于锚点：无锚点签发者但 claims 先失败
        schema_no_anchor = make_schema(SCHEMA_ID, 1, ISSUER_NO_ANCHOR,
                                       CLAIM_TYPES, REQUIRED)
        expect("claims 校验优先于锚点",
               signed(make_body(issuer=ISSUER_NO_ANCHOR,
                                digest=schema_no_anchor["digest"],
                                claims={"age": 30}),
                      schema=schema_no_anchor),
               CLAIMS_FAILED, T1)

        # ---------------------------------------------------------- #
        # 6. 锚点/签名/有效期：沿用既有原因与优先级
        # ---------------------------------------------------------- #
        body_no_anchor = make_body(issuer=ISSUER_NO_ANCHOR,
                                   digest=schema_no_anchor["digest"])
        st, r = verify({"body": body_no_anchor,
                        "signature": crypto.sign(body_no_anchor, priv),
                        "schema_id": SCHEMA_ID, "schema_version": 1,
                        "schema": schema_no_anchor}, headers=T1)
        check("锚点不存在", st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点不存在"))
        st, r = verify({"body": body, "signature": "!!!bad!!!",
                        "schema_id": SCHEMA_ID, "schema_version": 1,
                        "schema": SCHEMA}, headers=T1)
        check("签名格式错误", st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名格式错误"))
        st, r = verify(signed(body, priv_key=priv_other), headers=T1)
        check("错误私钥 -> 签名校验失败", st == 200
              and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        body_exp = make_body(extra={"expires_at": "2020-01-01T00:00:00Z"})
        expect("凭证已过期", signed(body_exp),
               {"valid": False, "reason": "凭证已过期"}, T1)

        # ---------------------------------------------------------- #
        # 7. 只采用提交模式：不回退/不覆盖本地同名版本，不借用他租户
        # ---------------------------------------------------------- #
        # 本地同名同版本但内容不同的模式存在时，提交模式仍验真成功
        body_local = make_body(issuer=ISSUER_LOCAL,
                               digest=SCHEMA_LOCAL["digest"],
                               claims={"name": "张三", "age": 30},
                               cid="vc_external_submitted_schema_0002")
        st, r = verify(
            {"body": body_local,
             "signature": crypto.sign(body_local, priv_local),
             "schema_id": SCHEMA_ID, "schema_version": 1,
             "schema": SCHEMA_LOCAL}, headers=T1)
        check("本地同名不同内容模式时提交模式验真成功",
              st == 200 and r == {"valid": True})
        # 提交模式内容不满足本地模式约束也无关（本地要求 /name 必填，
        # 提交模式要求 /name+/age；此处按提交模式判定）
        # 本地同名版本弃用/吊销不影响提交模式验真
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/{SCHEMA_ID}/1/status",
            {"issuer_did": ISSUER_LOCAL, "status": "deprecated"},
            headers=T1)
        check("deprecated 本地同名版本 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/{SCHEMA_ID}/1/status",
            {"issuer_did": ISSUER_LOCAL, "status": "revoked"}, headers=T1)
        check("revoked 本地同名版本 -> 201", st == 201)
        st, r = verify(
            {"body": body_local,
             "signature": crypto.sign(body_local, priv_local),
             "schema_id": SCHEMA_ID, "schema_version": 1,
             "schema": SCHEMA_LOCAL}, headers=T1)
        check("本地同名版本 revoked 不影响提交模式验真",
              st == 200 and r == {"valid": True})
        # 本地模式内容未被提交模式覆盖
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/{SCHEMA_ID}/1"
            f"?issuer_did={ISSUER_LOCAL}",
            headers=T1,
        )
        check("本地模式内容未被提交模式覆盖",
              st == 200 and r.get("digest") == local_digest)
        # 省略 schema 时保持原行为：同正文按本地模式判定 -> 绑定不一致
        st, r = verify(
            {"body": body_local,
             "signature": crypto.sign(body_local, priv_local),
             "schema_id": SCHEMA_ID, "schema_version": 1}, headers=T1)
        check("省略 schema 保持原行为（按本地模式判定绑定）",
              st == 200 and r == BINDING_MISMATCH)
        # 省略 schema 且本地无该模式 -> 凭证模式不存在
        st, r = verify(signed(body, schema=None), headers=T1)
        check("省略 schema 且本地无模式 -> 凭证模式不存在",
              st == 200 and r == {"valid": False, "reason": "凭证模式不存在"})
        # 不借用其他租户数据：T2 无锚点，提交同样模式 -> 锚点不存在
        st, r = verify(signed(body), headers=T2)
        check("他租户锚点不可借用", st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点不存在"))

        # ---------------------------------------------------------- #
        # 8. 外部停用通告：登记后命中，过期仍优先
        # ---------------------------------------------------------- #
        notice = {
            "did": ISSUER,
            "key_version": 1,
            "reason": "机构业务终止",
            "deactivated_at": "2026-09-20T10:00:00Z",
        }
        st, _ = _http(
            "POST", f"{BASE}/v1/trust/dids/deactivate-sync",
            {"body": notice, "signature": crypto.sign(notice, priv)},
            headers=T1,
        )
        check("登记外部停用通告 -> 201", st == 201)
        expect("外部签发 DID 已停用", signed(make_body()), DEACTIVATED, T1)
        expect("过期优先于停用通告", signed(body_exp),
               {"valid": False, "reason": "凭证已过期"}, T1)

        # ---------------------------------------------------------- #
        # 9. 只读：不登记 DID/模式/凭证，不记审计
        # ---------------------------------------------------------- #
        st, before = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T2)
        n_before = len(before["events"])
        for _ in range(3):
            verify(signed(body), headers=T2)
            verify(signed(body, schema=dict(SCHEMA, extra=1)), headers=T2)
            verify(raw=b"not-json", headers=T2)
        st, after = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T2)
        check("提交模式验真（含失败）不记审计",
              len(after["events"]) == n_before)
        st, _ = _http("GET", f"{BASE}/v1/credentials/{cred_id}", headers=T1)
        check("验真后凭证仍未登记（GET 404）", st == 404)
        st, _ = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/{SCHEMA_ID}/1"
            f"?issuer_did={ISSUER}",
            headers=T1,
        )
        check("提交模式未被登记（GET 404）", st == 404)
        st, _ = _http("GET", f"{BASE}/v1/dids/{ISSUER}", headers=T1)
        check("签发者 DID 仍未登记（GET 404）", st == 404)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 10. 跨重启：提交模式验真无状态，结论一致
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(), "服务重启超时"
        st, r = verify(
            {"body": body, "signature": crypto.sign(body, priv),
             "schema_id": SCHEMA_ID, "schema_version": 1, "schema": SCHEMA},
            headers=T1,
        )
        check("重启后提交模式验真结论一致（停用通告仍生效）",
              st == 200 and r == DEACTIVATED)
        st, _ = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/{SCHEMA_ID}/1"
            f"?issuer_did={ISSUER}",
            headers=T1,
        )
        check("重启后提交模式仍未登记", st == 404)
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
