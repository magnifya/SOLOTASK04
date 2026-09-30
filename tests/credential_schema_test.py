#!/usr/bin/env python3
"""凭证模式注册与约束签发（credential-schemas）能力的端到端测试。

覆盖：
- POST /v1/credential-schemas：schema_id/version/claim_types/
  required_claims 校验（400），未知或跨租户 issuer_did（404），
  不写入、不审计；同内容重复注册 200 原记录，异内容 409；首次 201
  并审计；digest 为五字段规范化 JSON 的 SHA-256 小写 hex；
- GET /v1/credential-schemas/{schema_id}/{version}?issuer_did=...：
  命中 200，缺失或跨租户 404，非法路径/参数 400；
- POST /v1/credentials 可选 schema_id/schema_version：同现同缺，
  claims 必填路径与声明类型校验（400），模式缺失或跨租户（404），
  失败不保存不审计；成功正文与响应含 schema 三字段并参与 ES256；
- verify：绑定凭证正常 valid:true；签名合法但模式校验失败固定
  200/{"valid":false,"reason":"schema validation failed"}；未签名
  篡改仍先报签名校验失败；模式行消失后同因；旧凭证行为完全不变；
- 选择性披露不泄露隐藏 claims（回归）；
- 模式与绑定凭证随状态文件持久化，跨重启结论一致。

直接运行：python3 tests/credential_schema_test.py
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

from vcbackend import crypto  # noqa: E402

PORT = 8988
BASE = f"http://127.0.0.1:{PORT}"
SCHEMA_FAILED = "schema validation failed"


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

    T = {"X-Tenant-ID": "schema-a"}
    T2 = {"X-Tenant-ID": "schema-b"}
    bound_cid = {"id": None}
    issuer_did = {"v": None}

    try:
        assert wait_up(), "服务启动超时"

        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-sch"},
                      headers=T)
        assert st == 201, (st, r)
        issuer = r["did"]
        issuer_did["v"] = issuer
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "subject-sch"},
                      headers=T)
        assert st == 201, (st, r)
        subject = r["did"]
        # 租户 B 注册同名签发者，用于跨租户不可见判定
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-other"},
                      headers=T2)
        assert st == 201, (st, r)
        issuer_b = r["did"]

        schema_url = f"{BASE}/v1/credential-schemas"

        def register(payload, headers=T):
            return _http("POST", schema_url, payload, headers=headers)

        def schema_get(sid, version, iss, headers=T, extra=""):
            url = (
                f"{BASE}/v1/credential-schemas/{sid}/{version}"
                f"?issuer_did={iss}{extra}"
            )
            return _http("GET", url, headers=headers)

        audit_url = f"{BASE}/v1/audit?limit=200"

        schema = {
            "schema_id": "kyc_basic",
            "version": 1,
            "issuer_did": issuer,
            "claim_types": {
                "/name": "string",
                "/age": "integer",
                "/score": "number",
                "/active": "boolean",
                "/addr": "object",
                "/addr/city": "string",
                "/tags": "array",
                "/tags/0": "string",
            },
            "required_claims": ["/name", "/age"],
        }

        def expected_digest(payload):
            content = {
                "schema_id": payload["schema_id"],
                "version": payload["version"],
                "issuer_did": payload["issuer_did"],
                "claim_types": payload["claim_types"],
                "required_claims": payload["required_claims"],
            }
            return hashlib.sha256(
                crypto.canonicalize(content)
            ).hexdigest()

        # -------------------------------------------------------------- #
        # 1. 注册：内容非法 -> 400，不写入不审计
        # -------------------------------------------------------------- #
        st, n_before = _http("GET", audit_url, headers=T)
        invalid_payloads = [
            ("schema_id 数字开头", dict(schema, schema_id="1abc")),
            ("schema_id 大写", dict(schema, schema_id="Kyc")),
            ("schema_id 点号", dict(schema, schema_id="a.b")),
            ("schema_id 空", dict(schema, schema_id="")),
            ("schema_id 65 字符", dict(schema, schema_id="a" * 65)),
            ("version 为 0", dict(schema, version=0)),
            ("version 为负", dict(schema, version=-1)),
            ("version 为字符串", dict(schema, version="1")),
            ("version 为布尔", dict(schema, version=True)),
            ("issuer_did 空", dict(schema, issuer_did="")),
            ("claim_types 空对象",
             dict(schema, claim_types={}, required_claims=[])),
            ("claim_types 101 项",
             dict(schema, schema_id="big1",
                  claim_types={f"/p{i}": "string" for i in range(101)},
                  required_claims=[])),
            ("claim_types 非对象", dict(schema, claim_types=[])),
            ("类型名非法",
             dict(schema, schema_id="bad1",
                  claim_types={"/name": "str"}, required_claims=[])),
            ("路径不以 / 开头",
             dict(schema, schema_id="bad2",
                  claim_types={"name": "string"}, required_claims=[])),
            ("根路径",
             dict(schema, schema_id="bad3",
                  claim_types={"": "string"}, required_claims=[])),
            ("非法转义",
             dict(schema, schema_id="bad4",
                  claim_types={"/a~2": "string"}, required_claims=[])),
            ("required_claims 非数组", dict(schema, required_claims={})),
            ("required 重复",
             dict(schema, required_claims=["/name", "/name"])),
            ("required 非子集",
             dict(schema, required_claims=["/nope"])),
            ("required 元素非字符串",
             dict(schema, required_claims=[1])),
            ("缺字段",
             {k: v for k, v in schema.items() if k != "version"}),
            ("多字段", dict(schema, extra=1)),
        ]
        for label, payload in invalid_payloads:
            st, r = register(payload)
            check(f"非法注册（{label}）-> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        st, n_after = _http("GET", audit_url, headers=T)
        check("非法注册不写审计",
              len(n_after["events"]) == len(n_before["events"]))

        # 未知 / 跨租户 / 空 issuer_did -> 404（存在性不可探测）
        st, r = register(dict(schema, issuer_did="did:x:ghost"))
        check("未知 issuer_did -> 404", st == 404)
        st, r = register(dict(schema, issuer_did=issuer_b), headers=T)
        check("他租户 issuer_did -> 404", st == 404)
        st, r = register(schema, headers=T2)
        # schema 内 issuer 属于租户 A：在租户 B 查不到 -> 404
        check("跨租户注册 -> 404", st == 404)
        st, n_after2 = _http("GET", audit_url, headers=T)
        check("404 注册不写审计",
              len(n_after2["events"]) == len(n_before["events"]))

        # -------------------------------------------------------------- #
        # 2. 首次注册 201、digest 正确、审计
        # -------------------------------------------------------------- #
        st, r = register(schema)
        check("首次注册 -> 201", st == 201)
        digest = r.get("digest")
        check("响应六字段与键序",
              list(r) == ["schema_id", "version", "issuer_did",
                          "claim_types", "required_claims", "digest"])
        check("digest 为 64 位小写 hex",
              isinstance(digest, str) and len(digest) == 64
              and digest == digest.lower()
              and all(c in "0123456789abcdef" for c in digest))
        check("digest 为规范化 JSON 的 SHA-256",
              digest == expected_digest(schema))
        check("响应内容回显",
              r["schema_id"] == schema["schema_id"]
              and r["version"] == 1
              and r["issuer_did"] == issuer
              and r["claim_types"] == schema["claim_types"]
              and r["required_claims"] == schema["required_claims"])

        st, ev = _http("GET", audit_url, headers=T)
        reg_events = [
            e for e in ev["events"]
            if e["action"] == "credential.schema.registered"
            and e["resource_id"] == f"{issuer}:kyc_basic:1"
        ]
        check("首次注册记一次审计", len(reg_events) == 1)
        check("审计 resource_type=credential_schema",
              reg_events and reg_events[0]["resource_type"]
              == "credential_schema")
        check("审计六字段", reg_events and set(reg_events[0]) == {
            "seq", "timestamp", "tenant_id", "action",
            "resource_type", "resource_id"})

        # 同内容重复注册 -> 200 原记录，不再审计
        st, r2 = register(schema)
        check("同内容重复注册 -> 200", st == 200)
        check("200 返回原记录（digest 相同）", r2["digest"] == digest)
        st, ev = _http("GET", audit_url, headers=T)
        check("重复注册不追加审计",
              len([e for e in ev["events"]
                   if e["action"] == "credential.schema.registered"
                   and e["resource_id"] == f"{issuer}:kyc_basic:1"]) == 1)

        # 异内容（同 schema_id/version/issuer）-> 409
        other = dict(schema, required_claims=["/name"])
        st, r = register(other)
        check("异内容重复注册 -> 409", st == 409)
        other = dict(schema,
                     claim_types=dict(schema["claim_types"],
                                      **{"/extra": "string"}))
        st, r = register(other)
        check("异内容（claim_types 不同）-> 409", st == 409)
        # 原记录保持不变
        st, r = register(schema)
        check("冲突后原记录仍可幂等读取", st == 200 and r["digest"] == digest)

        # 不同 version 可各自注册
        st, r = register(dict(schema, version=2,
                              required_claims=["/name"]))
        check("同 schema_id 新版本 -> 201", st == 201)
        digest_v2 = r["digest"]

        # 已停用 issuer 不得注册模式 -> 409
        st, r = _http("POST", f"{BASE}/v1/dids/{issuer_b}/deactivate",
                      {"reason": "停用"}, headers=T2)
        assert st == 200, (st, r)
        st, r = register(dict(schema, issuer_did=issuer_b), headers=T2)
        check("停用 issuer 注册模式 -> 409", st == 409)

        # -------------------------------------------------------------- #
        # 3. GET 模式
        # -------------------------------------------------------------- #
        st, r = schema_get("kyc_basic", 1, issuer)
        check("GET 命中 -> 200", st == 200 and r["digest"] == digest)
        st, r = schema_get("kyc_basic", 2, issuer)
        check("GET v2 -> 200", st == 200 and r["digest"] == digest_v2)
        st, r = schema_get("kyc_basic", 9, issuer)
        check("GET 缺失版本 -> 404", st == 404)
        st, r = schema_get("missing", 1, issuer)
        check("GET 缺失 schema_id -> 404", st == 404)
        st, r = schema_get("kyc_basic", 1, issuer, headers=T2)
        check("GET 跨租户 -> 404", st == 404)
        st, r = schema_get("kyc_basic", 1, "did:x:ghost")
        check("GET 未知 issuer -> 404", st == 404)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1"
            f"?issuer_did={issuer}&issuer_did={issuer}",
            headers=T)
        check("issuer_did 重复 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1?issuer_did=",
            headers=T)
        check("issuer_did 空值 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1",
            headers=T)
        check("缺 issuer_did -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/x?issuer_did={issuer}",
            headers=T)
        check("version 非数字 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/0?issuer_did={issuer}",
            headers=T)
        check("version 为 0 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/BAD/1?issuer_did={issuer}",
            headers=T)
        check("schema_id 非法 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic?issuer_did={issuer}",
            headers=T)
        check("路径段数不足 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1/2"
            f"?issuer_did={issuer}",
            headers=T)
        check("路径段数过多 -> 400", st == 400)
        st, r = schema_get("kyc_basic", 1, issuer, extra="&limit=1")
        check("未知查询参数 -> 400", st == 400)

        # -------------------------------------------------------------- #
        # 4. 签发绑定凭证
        # -------------------------------------------------------------- #
        good_claims = {
            "name": "Alice",
            "age": 30,
            "score": 9.5,
            "active": True,
            "addr": {"city": "Shanghai"},
            "tags": ["vip"],
        }

        def issue(claims=good_claims, sid="kyc_basic", ver=1, **over):
            payload = {
                "issuer_did": issuer,
                "subject_did": subject,
                "claims": claims,
            }
            if sid is not None:
                payload["schema_id"] = sid
            if ver is not None:
                payload["schema_version"] = ver
            payload.update(over)
            return _http("POST", f"{BASE}/v1/credentials", payload,
                         headers=over.pop("_headers", T))

        st, n_cred_before = _http("GET", audit_url, headers=T)
        st, r = issue()
        check("绑定凭证签发 -> 201", st == 201)
        check("签发响应三字段不变",
              set(r) == {"credential_id", "signature",
                         "issuer_key_version"})
        cid = r["credential_id"]
        bound_cid["id"] = cid
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}", headers=T)
        check("GET 绑定凭证 -> 200", st == 200)
        body, signature = got["body"], got["signature"]
        check("正文含 schema 三字段",
              body.get("schema_id") == "kyc_basic"
              and body.get("schema_version") == 1
              and body.get("schema_digest") == digest)
        check("正文其余字段不变",
              set(body) == {
                  "credential_id", "issuer_did", "subject_did", "claims",
                  "issued_at", "issuer_key_version",
                  "schema_id", "schema_version", "schema_digest"})

        # 非法签发请求 -> 400/404
        st, r = issue(claims={"name": "A"})
        check("缺必填路径 -> 400", st == 400)
        st, r = issue(claims=dict(good_claims, age="30"))
        check("integer 不符（字符串）-> 400", st == 400)
        st, r = issue(claims=dict(good_claims, age=True))
        check("integer 不符（布尔）-> 400", st == 400)
        st, r = issue(claims=dict(good_claims, score=True))
        check("number 不符（布尔）-> 400", st == 400)
        st, r = issue(claims=dict(good_claims, active="yes"))
        check("boolean 不符 -> 400", st == 400)
        st, r = issue(claims=dict(good_claims, addr="x"))
        check("object 不符 -> 400", st == 400)
        st, r = issue(claims=dict(good_claims, addr={"city": 1}))
        check("嵌套路径类型不符 -> 400", st == 400)
        st, r = issue(claims=dict(good_claims, tags={}))
        check("array 不符 -> 400", st == 400)
        st, r = issue(claims=dict(good_claims, tags=[1]))
        check("数组元素路径类型不符 -> 400", st == 400)
        st, r = issue(sid="kyc_basic", ver=9)
        check("模式版本缺失 -> 404", st == 404)
        st, r = issue(sid="nope", ver=1)
        check("模式缺失 -> 404", st == 404)
        # 跨租户：在租户 B 用 B 自己的活动 DID，模式仅存在于 A -> 404。
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-b-active"},
                      headers=T2)
        assert st == 201, (st, r)
        issuer_b_active = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "subject-b"},
                      headers=T2)
        assert st == 201, (st, r)
        subject_b = r["did"]
        payload_cross = {
            "issuer_did": issuer_b_active,
            "subject_did": subject_b,
            "claims": good_claims,
            "schema_id": "kyc_basic",
            "schema_version": 1,
        }
        st, r = _http("POST", f"{BASE}/v1/credentials", payload_cross,
                      headers=T2)
        check("跨租户模式签发 -> 404", st == 404)
        payload_cross_a = {
            "issuer_did": issuer,
            "subject_did": subject,
            "claims": good_claims,
            "schema_id": "kyc_basic",
            "schema_version": 1,
        }
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {k: v for k, v in payload_cross_a.items()
             if k != "schema_version"}, headers=T)
        check("仅 schema_id -> 400", st == 400)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {k: v for k, v in payload_cross_a.items()
             if k != "schema_id"}, headers=T)
        check("仅 schema_version -> 400", st == 400)
        st, r = issue(sid=None, ver=1)
        check("schema_id 为 null -> 400", st == 400)

        # 失败不保存：仅成功的一张绑定凭证
        st, ev = _http("GET", audit_url, headers=T)
        check("失败签发不记 credential.issued 审计",
              len([e for e in ev["events"]
                   if e["action"] == "credential.issued"]) == 1)

        # schema 字段参与签名：篡改 digest 未重签 -> 签名校验失败
        tampered = json.loads(json.dumps(body))
        tampered["schema_digest"] = "0" * 64
        st, r = _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                      {"body": tampered, "signature": signature}, headers=T)
        check("篡改 schema_digest -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # 无模式旧凭证签发与验签保持不变
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject,
             "claims": {"anything": [1, 2]}}, headers=T)
        check("旧形态凭证签发 -> 201", st == 201)
        old_cid = r["credential_id"]
        st, old = _http("GET", f"{BASE}/v1/credentials/{old_cid}",
                        headers=T)
        check("旧形态正文无 schema 字段",
              "schema_id" not in old["body"]
              and "schema_version" not in old["body"]
              and "schema_digest" not in old["body"])
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{old_cid}/verify",
            {"body": old["body"], "signature": old["signature"]},
            headers=T)
        check("旧凭证 verify valid:true", st == 200 and r == {"valid": True})

        # 绑定凭证正常 verify
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": body, "signature": signature}, headers=T)
        check("绑定凭证 verify valid:true",
              st == 200 and r == {"valid": True})

        # -------------------------------------------------------------- #
        # 5. verify：签名合法但模式校验失败
        # -------------------------------------------------------------- #
        # 从状态文件取签发者当前私钥，构造“签名合法但 claims 不符模式”
        raw = json.load(open(store_path, encoding="utf-8"))
        issuer_priv = raw["tenants"]["schema-a"]["dids"][issuer][
            "private_key_pem"]

        def signed_body(mutator):
            b = json.loads(json.dumps(body))
            mutator(b)
            return b, crypto.sign(b, issuer_priv)

        b, sg = signed_body(lambda x: x["claims"].__setitem__("age", "x"))
        st, r = _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                      {"body": b, "signature": sg}, headers=T)
        check("合法签名+类型错误 -> schema validation failed",
              st == 200 and r.get("valid") is False
              and r.get("reason") == SCHEMA_FAILED)

        b, sg = signed_body(lambda x: x["claims"].__delitem__("age"))
        st, r = _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                      {"body": b, "signature": sg}, headers=T)
        check("合法签名+缺必填 -> schema validation failed",
              st == 200 and r.get("valid") is False
              and r.get("reason") == SCHEMA_FAILED)

        b, sg = signed_body(lambda x: x.__setitem__("schema_digest",
                                                    "f" * 64))
        st, r = _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                      {"body": b, "signature": sg}, headers=T)
        check("合法签名+digest 不符 -> schema validation failed",
              st == 200 and r.get("valid") is False
              and r.get("reason") == SCHEMA_FAILED)

        b, sg = signed_body(lambda x: x.__setitem__("schema_version", 2))
        st, r = _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                      {"body": b, "signature": sg}, headers=T)
        check("合法签名+版本引用不符 -> schema validation failed",
              st == 200 and r.get("valid") is False
              and r.get("reason") == SCHEMA_FAILED)

        # verify 只读不记审计
        st, ev1 = _http("GET", audit_url, headers=T)
        for _ in range(2):
            _http("POST", f"{BASE}/v1/credentials/{cid}/verify",
                  {"body": b, "signature": sg}, headers=T)
        st, ev2 = _http("GET", audit_url, headers=T)
        check("verify 模式失败不记审计",
              len(ev1["events"]) == len(ev2["events"]))

        # -------------------------------------------------------------- #
        # 6. 选择性披露不泄露隐藏 claims（绑定凭证回归）
        # -------------------------------------------------------------- #
        st, pres = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"disclose": ["/name"]}, headers=T)
        check("绑定凭证生成演示 -> 201", st == 201)
        check("披露仅含所选叶子 claim",
              pres["claims"] == {"name": "Alice"})
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{pres['presentation_id']}/verify",
            {"presentation": pres,
             "challenge": pres["challenge"]}, headers=T)
        check("绑定凭证演示 verify valid:true",
              st == 200 and r == {"valid": True})

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 7. 跨重启：模式与绑定凭证持久化
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(), "服务重启超时"
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_basic/1"
            f"?issuer_did={issuer_did['v']}",
            headers=T)
        check("重启后模式仍存在", st == 200 and "digest" in r)
        cid = bound_cid["id"]
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}", headers=T)
        assert st == 200
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": got["body"], "signature": got["signature"]},
            headers=T)
        check("重启后绑定凭证 verify valid:true",
              st == 200 and r == {"valid": True})

        # 删除模式行后重启：已绑定凭证 verify 返回固定模式失败原因
        raw = json.load(open(store_path, encoding="utf-8"))
        del raw["tenants"]["schema-a"]["credential_schemas"][
            issuer_did["v"]]["kyc_basic"]
        with open(store_path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, ensure_ascii=False)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(), "服务第二次重启超时"
        cid = bound_cid["id"]
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}", headers=T)
        assert st == 200
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": got["body"], "signature": got["signature"]},
            headers=T)
        check("模式行缺失 -> verify schema validation failed",
              st == 200 and r.get("valid") is False
              and r.get("reason") == SCHEMA_FAILED)
        # 模式缺失后同约束无法再签发新绑定凭证 -> 404
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer_did["v"],
             "subject_did": got["body"]["subject_did"],
             "claims": {"name": "A", "age": 1},
             "schema_id": "kyc_basic", "schema_version": 1},
            headers=T)
        check("模式缺失后签发 -> 404", st == 404)
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
