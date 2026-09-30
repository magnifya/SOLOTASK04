#!/usr/bin/env python3
"""凭证模式注册与模式约束签发能力的端到端测试。

覆盖：
- POST /v1/credential-schemas：schema_id/version/claim_types/
  required_claims/issuer_did 的 400 形状校验；未知、跨租户或已停用
  issuer_did 返回 404 且不写入、不审计；同内容重放 200 返原记录、
  不追加审计；异内容 409 不写入、不审计；首次 201 并记
  credential_schema.registered；
- GET /v1/credential-schemas/{schema_id}/{version}?issuer_did=...：
  命中 200、缺失/跨租户 404、非法路径/查询 400；
- POST /v1/credentials 可选 schema_id/schema_version：同时出现或同时
  省略；模式缺失/跨租户 404、参数不完整或 claims 不符 400，均不保
  存、不审计；成功 body 增加三元组，schema_digest 为 canonical JSON
  的 SHA-256 小写 hex；现有字段、ES256 与响应兼容；
- verify：签名合法但模式校验失败返回 200/valid:false/reason
  恰为 "schema validation failed"；旧凭证、选择性披露不泄露隐藏
  claims 等既有语义不变；
- 模式注册与约束签发随状态文件持久化，重启后结论一致；租户严格隔离。

直接运行：python3 tests/credential_schema_test.py
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

SCHEMA_FAIL_REASON = "schema validation failed"


def _http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
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


def main():
    port = 8989
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []
    TA = {"X-Tenant-ID": "schema-a"}
    TB = {"X-Tenant-ID": "schema-b"}

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def register(payload, headers=TA):
        return _http("POST", f"{base}/v1/credential-schemas",
                     payload, headers=headers)

    def schema_get(schema_id, version, issuer, headers=TA):
        return _http(
            "GET",
            f"{base}/v1/credential-schemas/{schema_id}/{version}"
            f"?issuer_did={issuer}",
            headers=headers,
        )

    def audit(headers=TA):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200, r
        return r["events"]

    def issue(payload, headers=TA):
        return _http("POST", f"{base}/v1/credentials", payload,
                     headers=headers)

    def verify(cid, body, signature, headers=TA):
        return _http(
            "POST", f"{base}/v1/credentials/{cid}/verify",
            {"body": body, "signature": signature}, headers=headers,
        )

    created_cid = {"id": None}

    try:
        assert wait_up(port), "服务启动超时"

        st, r = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "iss-handle-a"},
                       headers=TA)
        assert st == 201, r
        issuer_a = r["did"]
        st, r = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "sub-handle-a"},
                       headers=TA)
        assert st == 201, r
        subject_a = r["did"]
        st, r = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "iss-handle-b"},
                       headers=TB)
        assert st == 201, r
        issuer_b = r["did"]

        base_schema = {
            "schema_id": "kyc_v1",
            "version": 1,
            "issuer_did": issuer_a,
            "claim_types": {
                "/name": "string",
                "/age": "integer",
                "/score": "number",
                "/active": "boolean",
                "/meta": "object",
                "/tags": "array",
                "/items/0/id": "string",
            },
            "required_claims": ["/name", "/age", "/items/0/id"],
        }

        # -------------------------------------------------------------- #
        # 1. 首次注册：201 + 审计
        # -------------------------------------------------------------- #
        events_before = audit()
        st, r = register(base_schema)
        check("首次注册模式 -> 201", st == 201)
        check("注册响应字段集合",
              set(r) == {"schema_id", "version", "issuer_did",
                         "claim_types", "required_claims"})
        check("注册响应原样回显",
              r["schema_id"] == "kyc_v1" and r["version"] == 1
              and r["issuer_did"] == issuer_a
              and r["claim_types"] == base_schema["claim_types"]
              and r["required_claims"] == base_schema["required_claims"])
        events_after = audit()
        reg_events = [e for e in events_after[len(events_before):]
                      if e["action"] == "credential_schema.registered"]
        check("首次注册记 credential_schema.registered",
              len(reg_events) == 1
              and reg_events[0]["resource_type"] == "credential_schema"
              and reg_events[0]["resource_id"]
              == f"{issuer_a}#kyc_v1#1")

        # -------------------------------------------------------------- #
        # 2. 同内容重放：200 原记录、不追加审计
        # -------------------------------------------------------------- #
        st, r = register(dict(base_schema))
        check("同内容重放 -> 200", st == 200)
        check("重放返回原记录",
              r["claim_types"] == base_schema["claim_types"]
              and r["required_claims"] == base_schema["required_claims"])
        events_replay = audit()
        check("重放不追加审计",
              len(events_replay) == len(events_after))

        # -------------------------------------------------------------- #
        # 3. 异内容：409，不写入、不审计；GET 仍返回首次内容
        # -------------------------------------------------------------- #
        diff_required = dict(base_schema, required_claims=["/name"])
        st, r = register(diff_required)
        check("异 required_claims -> 409", st == 409)
        diff_types = dict(base_schema)
        diff_types["claim_types"] = dict(base_schema["claim_types"],
                                         **{"/extra_only": "string"})
        st, r = register(diff_types)
        check("异 claim_types -> 409", st == 409)
        diff_version = dict(base_schema, version=2)
        st, r = register(diff_version)
        check("另一版本可独立注册 -> 201", st == 201)
        st, got = schema_get("kyc_v1", 1, issuer_a)
        check("冲突后 GET 仍为首次内容",
              st == 200
              and got["required_claims"] == base_schema["required_claims"])
        check("409 不追加审计", len(audit()) == len(events_replay) + 1)

        # -------------------------------------------------------------- #
        # 4. 非法内容：400，不写入、不审计
        # -------------------------------------------------------------- #
        bad_cases = [
            ("schema_id 大写开头", {"schema_id": "Kyc"}, None),
            ("schema_id 点号", {"schema_id": "a.b"}, None),
            ("schema_id 65 位", {"schema_id": "a" + "b" * 64}, None),
            ("schema_id 数字开头", {"schema_id": "1abc"}, None),
            ("schema_id 下划线开头", {"schema_id": "_a"}, None),
            ("schema_id 空串", {"schema_id": ""}, None),
            ("schema_id 非字符串", {"schema_id": 1}, None),
            ("version 0", {"version": 0}, None),
            ("version 负数", {"version": -1}, None),
            ("version 布尔", {"version": True}, None),
            ("version 字符串", {"version": "1"}, None),
            ("issuer_did 空", {"issuer_did": ""}, None),
            ("issuer_did 非字符串", {"issuer_did": 1}, None),
            ("claim_types 非对象", {"claim_types": []}, None),
            ("claim_types 空对象", {"claim_types": {}}, None),
            ("claim_types 101 项", None, "many_types"),
            ("类型名非法", {"claim_types": {"/a": "str"}}, None),
            ("路径非字符串", {"claim_types": {1: "string"}}, None),
            ("路径无根引导", {"claim_types": {"a": "string"}}, None),
            ("路径为根", {"claim_types": {"": "string"}}, None),
            ("路径非法转义", {"claim_types": {"/a~2": "string"}}, None),
            ("required 非数组", {"required_claims": {}}, None),
            ("required 越界", {"required_claims": ["/nope"]}, None),
            ("required 重复", {"required_claims": ["/name", "/name"]}, None),
            ("required 元素非字符串", {"required_claims": [1]}, None),
            ("多余字段", None, "extra_field"),
            ("缺字段", None, "missing_field"),
        ]
        audit_len_before = len(audit())
        for label, overrides, special in bad_cases:
            payload = dict(base_schema, version=3)
            if special == "many_types":
                payload["claim_types"] = {
                    f"/p{i:03d}": "string" for i in range(101)
                }
            elif special == "extra_field":
                payload["unexpected"] = 1
            elif special == "missing_field":
                del payload["required_claims"]
            elif overrides is not None:
                payload.update(overrides)
            st, r = register(payload)
            check(f"非法注册（{label}）-> 400", st == 400 and r.get("error"))
        check("非法注册不追加审计", len(audit()) == audit_len_before)
        st, _ = schema_get("kyc_v1", 3, issuer_a)
        check("非法注册不写入", st == 404)

        # -------------------------------------------------------------- #
        # 5. issuer_did：未知/跨租户 404，不写入、不审计
        # -------------------------------------------------------------- #
        st, r = register(dict(base_schema,
                              schema_id="ext-x", version=1,
                              issuer_did="did:example:does-not-exist"))
        check("未知 issuer_did -> 404", st == 404)
        st, r = register(dict(base_schema,
                              schema_id="ext-x", version=1,
                              issuer_did=issuer_b))
        check("跨租户 issuer_did -> 404", st == 404)
        st, _ = schema_get("ext-x", 1, "did:example:does-not-exist")
        check("未知 issuer 不写入", st == 404)
        st, _ = schema_get("kyc_v1", 1, issuer_a, headers=TB)
        check("跨租户 GET -> 404", st == 404)

        # 停用后的活动 DID 判定：deactivate 后注册/签发均 404
        st, _ = _http("POST", f"{base}/v1/dids/{issuer_b}/deactivate",
                       {"reason": "停用"}, headers=TB)
        assert st == 200, st
        st, r = register(dict(base_schema,
                              schema_id="ext-y", version=1,
                              issuer_did=issuer_b))
        check("已停用 issuer_did（他租户）仍 404", st == 404)

        # -------------------------------------------------------------- #
        # 6. GET 路径与查询校验
        # -------------------------------------------------------------- #
        st, got = schema_get("kyc_v1", 1, issuer_a)
        check("GET 命中 -> 200", st == 200 and got == {
            "schema_id": "kyc_v1", "version": 1, "issuer_did": issuer_a,
            "claim_types": base_schema["claim_types"],
            "required_claims": base_schema["required_claims"],
        })
        st, _ = schema_get("kyc_v1", 9, issuer_a)
        check("GET 缺失版本 -> 404", st == 404)
        st, _ = schema_get("nope", 1, issuer_a)
        check("GET 缺失 schema -> 404", st == 404)
        st, _ = _http(
            "GET",
            f"{base}/v1/credential-schemas/kyc_v1/0?issuer_did={issuer_a}",
            headers=TA)
        check("GET version=0 -> 400", st == 400)
        st, _ = _http(
            "GET",
            f"{base}/v1/credential-schemas/kyc_v1/abc?issuer_did={issuer_a}",
            headers=TA)
        check("GET version 非数字 -> 400", st == 400)
        st, _ = _http(
            "GET", f"{base}/v1/credential-schemas/kyc_v1/1", headers=TA)
        check("GET 缺 issuer_did -> 400", st == 400)
        st, _ = _http(
            "GET",
            f"{base}/v1/credential-schemas/kyc_v1/1"
            f"?issuer_did={issuer_a}&issuer_did={issuer_a}",
            headers=TA)
        check("GET issuer_did 重复 -> 400", st == 400)
        st, _ = _http(
            "GET",
            f"{base}/v1/credential-schemas/kyc_v1/1?issuer_did=",
            headers=TA)
        check("GET issuer_did 空 -> 400", st == 400)
        st, _ = _http(
            "GET", f"{base}/v1/credential-schemas/kyc_v1", headers=TA)
        check("GET 缺 version 段 -> 404", st == 404)

        # -------------------------------------------------------------- #
        # 7. 模式约束签发：成功路径
        # -------------------------------------------------------------- #
        good_claims = {
            "name": "alice",
            "age": 30,
            "score": 9.5,
            "active": True,
            "meta": {"k": "v"},
            "tags": [1, 2, 3],
            "items": [{"id": "sku-1", "qty": 2}],
            "secret": "hide-me",
        }
        issue_payload = {
            "issuer_did": issuer_a,
            "subject_did": subject_a,
            "claims": good_claims,
            "schema_id": "kyc_v1",
            "schema_version": 1,
        }
        st, r = issue(issue_payload)
        check("模式签发 -> 201", st == 201)
        check("签发响应含三元组",
              {"schema_id", "schema_version", "schema_digest"}
              <= set(r))
        check("schema_digest 为 64 位小写 hex",
              isinstance(r.get("schema_digest"), str)
              and all(c in "0123456789abcdef" for c in r["schema_digest"])
              and len(r["schema_digest"]) == 64)
        cid = r["credential_id"]
        created_cid["id"] = cid
        st, got = _http("GET", f"{base}/v1/credentials/{cid}", headers=TA)
        check("GET 模式凭证 -> 200", st == 200)
        body, signature = got["body"], got["signature"]
        check("正文含模式三元组",
              body.get("schema_id") == "kyc_v1"
              and body.get("schema_version") == 1
              and body.get("schema_digest") == r["schema_digest"])
        expected_digest = hashlib.sha256(
            crypto.canonicalize(
                {k: v for k, v in body.items() if k != "schema_digest"}
            )
        ).hexdigest()
        check("schema_digest 为除 digest 外正文 canonical JSON 的 SHA-256",
              body["schema_digest"] == expected_digest)
        st, vr = verify(cid, body, signature)
        check("合规模式凭证 verify valid:true",
              st == 200 and vr == {"valid": True})

        # 额外未声明 claims 允许存在
        st, r_extra = issue(dict(
            issue_payload,
            claims=dict(good_claims, extra_unclaimed=123),
        ))
        check("未声明额外 claims 允许 -> 201", st == 201)
        cid_extra = r_extra["credential_id"]
        st, got = _http("GET",
                        f"{base}/v1/credentials/{cid_extra}", headers=TA)
        st, vr = verify(cid_extra, got["body"], got["signature"])
        check("额外 claims 凭证 verify valid:true",
              st == 200 and vr == {"valid": True})

        # 非必填声明路径允许缺失；integer/number/boolean 严格区分
        loose = dict(good_claims)
        del loose["score"]
        del loose["tags"]
        st, r = issue(dict(issue_payload, claims=loose,
                           schema_id="kyc_v1", schema_version=2))
        check("非必填路径缺失 -> 201", st == 201)
        # version=2 schema 与 v1 内容相同（同内容不同版本各自注册成功）
        for bad_value, label in [
            (30.0, "age 浮点非 integer"),
            (True, "age 布尔非 integer"),
            ("9.5", "score 字符串非 number"),
            (1, "active 整数非 boolean"),
            ([], "meta 数组非 object"),
            ({}, "tags 对象非 array"),
        ]:
            claims = dict(good_claims)
            field = label.split()[0]
            claims[field] = bad_value
            st, r = issue(dict(issue_payload, claims=claims))
            check(f"{label} -> 400", st == 400 and r.get("error"))
        # 数组索引路径：越界/类型错误
        st, r = issue(dict(
            issue_payload,
            claims=dict(good_claims, items=[{"id": 1}]),
        ))
        check("数组路径值类型错误 -> 400", st == 400)
        st, r = issue(dict(
            issue_payload,
            claims={k: v for k, v in good_claims.items() if k != "items"},
        ))
        check("缺必填数组路径 -> 400", st == 400)
        st, r = issue(dict(
            issue_payload,
            claims=dict(good_claims, items=[]),
        ))
        check("空数组致必填索引越界 -> 400", st == 400)

        # -------------------------------------------------------------- #
        # 8. 模式签发失败：400/404 且不保存、不审计
        # -------------------------------------------------------------- #
        audit_before = audit()
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": {"name": "alice"},
            "schema_id": "kyc_v1",
        })
        check("仅 schema_id -> 400", st == 400)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": {"name": "alice"},
            "schema_version": 1,
        })
        check("仅 schema_version -> 400", st == 400)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": {"name": "alice", "age": "x"},
            "schema_id": "kyc_v1", "schema_version": 1,
        })
        check("claims 类型不符 -> 400", st == 400)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": {"age": 1},
            "schema_id": "kyc_v1", "schema_version": 1,
        })
        check("缺必填路径 -> 400", st == 400)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": good_claims,
            "schema_id": "kyc_v1", "schema_version": 99,
        })
        check("模式版本缺失 -> 404", st == 404)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": good_claims,
            "schema_id": "nope", "schema_version": 1,
        })
        check("模式标识缺失 -> 404", st == 404)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": good_claims,
            "schema_id": "kyc_v1", "schema_version": 1,
            "unexpected": 1,
        })
        check("多余字段 -> 400", st == 400)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": good_claims,
            "schema_id": 1, "schema_version": 1,
        })
        check("schema_id 非字符串 -> 400", st == 400)
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": good_claims,
            "schema_id": "kyc_v1", "schema_version": "1",
        })
        check("schema_version 非整数 -> 400", st == 400)
        check("失败签发不追加审计", len(audit()) == len(audit_before))

        # 跨租户引用本租户 DID 的模式：他租户桶内无模式 -> 404
        st, r = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": issuer_a, "subject_did": subject_a,
             "claims": good_claims,
             "schema_id": "kyc_v1", "schema_version": 1},
            headers=TB)
        check("跨租户模式签发 -> 404", st == 404)

        # 未知 issuer_did 走既有 400 协议（既有行为不变）
        st, r = issue({
            "issuer_did": "did:example:nope", "subject_did": subject_a,
            "claims": {},
        })
        check("未知 issuer（无模式）既有 400 行为不变", st == 400)

        # -------------------------------------------------------------- #
        # 9. verify：签名合法但模式校验失败 -> 统一原因
        # -------------------------------------------------------------- #
        state = json.loads(Path(store).read_text(encoding="utf-8"))
        issuer_priv = state["tenants"]["schema-a"]["dids"][issuer_a][
            "private_key_pem"
        ]

        def resign_with_claims(tampered_claims, recompute_digest=True):
            tb = dict(body)
            tb["claims"] = tampered_claims
            if recompute_digest:
                tb["schema_digest"] = hashlib.sha256(
                    crypto.canonicalize(
                        {k: v for k, v in tb.items()
                         if k != "schema_digest"}
                    )
                ).hexdigest()
            return tb, crypto.sign(tb, issuer_priv)

        # 缺必填（重签并自洽 digest）
        tb, sig = resign_with_claims({"name": "mallory"})
        st, vr = verify(cid, tb, sig)
        check("缺必填且签名合法 -> 200/schema validation failed",
              st == 200 and vr == {"valid": False,
                                    "reason": SCHEMA_FAIL_REASON})
        # 已声明路径类型错误
        tb, sig = resign_with_claims(
            dict(good_claims, age="not-an-int"))
        st, vr = verify(cid, tb, sig)
        check("类型错误且签名合法 -> schema validation failed",
              st == 200 and vr.get("reason") == SCHEMA_FAIL_REASON)
        # digest 不自洽但签名合法
        tb, sig = resign_with_claims({"name": "mallory"},
                                     recompute_digest=False)
        st, vr = verify(cid, tb, sig)
        check("digest 篡改且签名合法 -> schema validation failed",
              st == 200 and vr.get("reason") == SCHEMA_FAIL_REASON)
        # 改写模式绑定三元组（自洽 digest 重算）但与存储锚定不一致
        tb = dict(body)
        tb["schema_version"] = 2
        tb["schema_digest"] = hashlib.sha256(
            crypto.canonicalize(
                {k: v for k, v in tb.items() if k != "schema_digest"}
            )
        ).hexdigest()
        st, vr = verify(cid, tb, crypto.sign(tb, issuer_priv))
        check("模式绑定被改写且签名合法 -> schema validation failed",
              st == 200 and vr.get("reason") == SCHEMA_FAIL_REASON)
        # 签名非法优先于模式判定
        tb, sig = resign_with_claims({"name": "mallory"})
        st, vr = verify(cid, tb, signature)
        check("签名错误优先 -> 签名校验失败",
              st == 200 and vr.get("valid") is False
              and vr.get("reason", "").startswith("签名校验失败"))
        # 未篡改原凭证仍有效
        st, vr = verify(cid, body, signature)
        check("模式失败判定不影响合规凭证", vr == {"valid": True})

        # -------------------------------------------------------------- #
        # 10. 旧凭证与选择性披露回归
        # -------------------------------------------------------------- #
        st, r = issue({
            "issuer_did": issuer_a, "subject_did": subject_a,
            "claims": good_claims,
        })
        check("无模式旧流程签发 -> 201", st == 201)
        check("旧流程响应字段不变",
              set(r) == {"credential_id", "signature", "issuer_key_version"})
        old_cid = r["credential_id"]
        st, got = _http("GET",
                        f"{base}/v1/credentials/{old_cid}", headers=TA)
        check("旧凭证正文无模式三元组",
              "schema_id" not in got["body"]
              and "schema_version" not in got["body"]
              and "schema_digest" not in got["body"])
        st, vr = verify(old_cid, got["body"], got["signature"])
        check("旧凭证 verify valid:true 且响应无 reason",
              st == 200 and vr == {"valid": True})

        # 模式凭证的选择性披露：隐藏 claims 不泄露
        st, pres = _http(
            "POST", f"{base}/v1/credentials/{cid}/present",
            {"disclose": ["/name"], "challenge": "ch-schema"},
            headers=TA)
        check("模式凭证生成演示 -> 201", st == 201)
        check("投影仅含披露路径",
              set(pres["claims"].keys()) == {"name"})
        vp_id = pres["presentation_id"]
        st, vr = _http(
            "POST", f"{base}/v1/presentations/{vp_id}/verify",
            {"presentation": pres, "challenge": "ch-schema"},
            headers=TA)
        check("披露演示 verify valid:true 且隐藏 claims 不泄露",
              st == 200 and vr == {"valid": True}
              and "secret" not in json.dumps(pres, ensure_ascii=False)
              and "age" not in pres["claims"])

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 11. 跨重启：模式与模式凭证持久化
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        cid = created_cid["id"]
        st, got = _http("GET", f"{base}/v1/credentials/{cid}", headers=TA)
        assert st == 200, got
        b, sig = got["body"], got["signature"]
        iss = b["issuer_did"]
        st, r = schema_get("kyc_v1", 1, iss)
        check("重启后模式仍可查", st == 200
              and r["claim_types"]["/age"] == "integer")
        st, vr = verify(cid, b, sig)
        check("重启后模式凭证 verify valid:true",
              st == 200 and vr == {"valid": True})
        # 重启后篡改仍判 schema validation failed
        state = json.loads(Path(store).read_text(encoding="utf-8"))
        issuer_priv = state["tenants"]["schema-a"]["dids"][iss][
            "private_key_pem"
        ]
        tb = dict(b)
        tb["claims"] = {"name": "mallory"}
        tb["schema_digest"] = hashlib.sha256(
            crypto.canonicalize(
                {k: v for k, v in tb.items() if k != "schema_digest"}
            )
        ).hexdigest()
        st, vr = verify(cid, tb, crypto.sign(tb, issuer_priv))
        check("重启后篡改仍判 schema validation failed",
              st == 200 and vr.get("reason") == SCHEMA_FAIL_REASON)
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
