#!/usr/bin/env python3
"""跨系统模式约束验真
POST /v1/trust/credentials/verify-with-schema 的端到端测试。

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
from datetime import datetime, timezone
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
    port = 8971
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/verify-with-schema"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def expect_invalid_param(name, payload=None, raw=None, headers=None):
        st, r = verify(payload=payload, raw=raw, headers=headers)
        check(
            name,
            st == 200 and r == {"valid": False, "reason": "请求参数无效"},
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tvs-a"}
        T2 = {"X-Tenant-ID": "tvs-b"}

        priv1, pub1 = gen_keypair()
        priv_other, _ = gen_keypair()

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify(
            payload={"body": {}, "signature": "x",
                     "schema_id": "s", "schema_version": 1},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 注册本地 DID（模式注册要求 issuer_did 为同租户活动 DID）
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "web", "public_key": "issuer-handle-1"},
                      headers=T1)
        check("注册本地 DID -> 201", st == 201)
        did = r["did"]

        # 同一 DID 注册外部信任锚点（v1，pub1）
        st, r_anchor = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("注册外部锚点 -> 201", st == 201)

        # 注册模式 v1：/role string 必填，/level integer 可选，
        # /addr/city string 必填
        schema_id = "id_card"
        claim_types = {
            "/role": "string",
            "/level": "integer",
            "/addr/city": "string",
        }
        required_claims = ["/role", "/addr/city"]
        st, r = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": schema_id, "version": 1, "issuer_did": did,
             "claim_types": claim_types, "required_claims": required_claims},
            headers=T1,
        )
        check("注册模式 v1 -> 201", st == 201)
        digest_v1 = r["digest"]

        def make_body(claims=None, version=1, digest=digest_v1, extra=None):
            body = {
                "credential_id": "vc_external_schema_0001",
                "issuer_did": did,
                "subject_did": "did:web:subject.example",
                "claims": claims if claims is not None else {
                    "role": "admin",
                    "level": 3,
                    "addr": {"city": "北京"},
                },
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
                "schema_id": schema_id,
                "schema_version": version,
                "schema_digest": digest,
            }
            if extra:
                body.update(extra)
            return body

        def request_for(body, priv=priv1, **overrides):
            req = {"body": body, "signature": crypto.sign(body, priv),
                   "schema_id": schema_id, "schema_version": 1}
            req.update(overrides)
            return req

        # 1. 成功
        body = make_body()
        st, r = verify(request_for(body), headers=T1)
        check("合法绑定凭证验真成功", st == 200 and r == {"valid": True})

        # 2. 请求参数无效：缺失/多余/非法 JSON/非对象/模式参数类型错误
        sig = crypto.sign(body, priv1)
        expect_invalid_param("空请求体", raw=b"")
        expect_invalid_param("非法 JSON", raw=b"not-json")
        expect_invalid_param("UTF-8 非法", raw=b"\xff\xfe")
        expect_invalid_param("JSON 数组非对象", raw=b"[1,2]")
        expect_invalid_param("JSON 字符串非对象", raw=b'"x"')
        expect_invalid_param("JSON 数字非对象", raw=b"123")
        expect_invalid_param("JSON null 非对象", raw=b"null")
        expect_invalid_param("JSON true 非对象", raw=b"true")
        expect_invalid_param("缺 body",
                             {"signature": sig, "schema_id": schema_id,
                              "schema_version": 1})
        expect_invalid_param("缺 signature",
                             {"body": body, "schema_id": schema_id,
                              "schema_version": 1})
        expect_invalid_param("缺 schema_id",
                             {"body": body, "signature": sig,
                              "schema_version": 1})
        expect_invalid_param("缺 schema_version",
                             {"body": body, "signature": sig,
                              "schema_id": schema_id})
        expect_invalid_param("多余字段",
                             {"body": body, "signature": sig,
                              "schema_id": schema_id,
                              "schema_version": 1, "extra": 1},
                             headers=T1)
        expect_invalid_param("body 为数组",
                             {"body": [], "signature": sig,
                              "schema_id": schema_id, "schema_version": 1})
        expect_invalid_param("body 为 null",
                             {"body": None, "signature": sig,
                              "schema_id": schema_id, "schema_version": 1})
        expect_invalid_param("signature 为空串",
                             {"body": body, "signature": "",
                              "schema_id": schema_id, "schema_version": 1})
        expect_invalid_param("signature 为数字",
                             {"body": body, "signature": 1,
                              "schema_id": schema_id, "schema_version": 1})
        expect_invalid_param("schema_id 为空串",
                             {"body": body, "signature": sig,
                              "schema_id": "", "schema_version": 1})
        expect_invalid_param("schema_id 为数字",
                             {"body": body, "signature": sig,
                              "schema_id": 1, "schema_version": 1})
        for bad_version, label in [
            (True, "布尔 true"), (False, "布尔 false"), (0, "零"),
            (-1, "负数"), (1.5, "小数"), ("1", "字符串"),
            (None, "null"),
        ]:
            expect_invalid_param(
                f"schema_version 非法（{label}）",
                {"body": body, "signature": sig,
                 "schema_id": schema_id, "schema_version": bad_version},
            )

        # 3. body 基础字段错误沿用“凭证”分类，且先于模式查找
        b_missing = json.loads(json.dumps(body))
        b_missing.pop("credential_id")
        st, r = verify(request_for(b_missing), headers=T1)
        check("缺 credential_id -> 凭证类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证"))
        b_bad_claims = json.loads(json.dumps(body))
        b_bad_claims["claims"] = []
        st, r = verify(request_for(b_bad_claims), headers=T1)
        check("claims 非对象 -> 凭证类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证"))
        # 即使模式版本不存在，body 字段错误仍先报“凭证”
        st, r = verify(
            {"body": b_missing, "signature": sig,
             "schema_id": schema_id, "schema_version": 99},
            headers=T1,
        )
        check("body 字段校验先于模式查找",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证"))

        # 4. 模式查找
        st, r = verify(
            {"body": body, "signature": sig,
             "schema_id": schema_id, "schema_version": 2},
            headers=T1,
        )
        check("未注册版本 -> 凭证模式不存在",
              st == 200 and r == {"valid": False, "reason": "凭证模式不存在"})
        st, r = verify(
            {"body": body, "signature": sig,
             "schema_id": "other_schema", "schema_version": 1},
            headers=T1,
        )
        check("未注册 schema_id -> 凭证模式不存在",
              st == 200 and r == {"valid": False, "reason": "凭证模式不存在"})
        # body 的 issuer_did 与模式归属不一致也按不存在
        b_other_issuer = json.loads(json.dumps(body))
        b_other_issuer["issuer_did"] = "did:web:someone-else"
        sig_other_issuer = crypto.sign(b_other_issuer, priv1)
        st, r = verify(
            {"body": b_other_issuer, "signature": sig_other_issuer,
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("跨 issuer 模式按不存在",
              st == 200 and r == {"valid": False, "reason": "凭证模式不存在"})
        # 跨租户同名模式按不存在
        st, r = verify(request_for(body), headers=T2)
        check("T2 无模式 -> 凭证模式不存在",
              st == 200 and r == {"valid": False, "reason": "凭证模式不存在"})
        # 模式查找先于绑定：完全合法的 body 绑定 v1，请求却指向不
        # 存在的 v9，应先报模式不存在而非绑定不一致
        st, r = verify(
            {"body": body, "signature": sig,
             "schema_id": schema_id, "schema_version": 99},
            headers=T1,
        )
        check("模式查找先于绑定（缺失版本报不存在）",
              st == 200 and r.get("reason") == "凭证模式不存在")

        # 5. 模式绑定不一致
        def body_variant(**changes):
            b = json.loads(json.dumps(body))
            for key, value in changes.items():
                if value is _DELETE:
                    b.pop(key, None)
                else:
                    b[key] = value
            return b

        for field in ("schema_id", "schema_version", "schema_digest"):
            b = body_variant(**{field: _DELETE})
            st, r = verify(request_for(b), headers=T1)
            check(f"body 缺 {field} -> 绑定不一致",
                  st == 200
                  and r == {"valid": False, "reason": "凭证模式绑定不一致"})

        b = body_variant(schema_id="other_schema")
        st, r = verify(
            {"body": b, "signature": crypto.sign(b, priv1),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("body schema_id 与请求不符 -> 绑定不一致",
              st == 200
              and r == {"valid": False, "reason": "凭证模式绑定不一致"})
        b = body_variant(schema_version=2)
        st, r = verify(
            {"body": b, "signature": crypto.sign(b, priv1),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("body schema_version 与请求不符 -> 绑定不一致",
              st == 200
              and r == {"valid": False, "reason": "凭证模式绑定不一致"})
        b = body_variant(schema_digest="0" * 64)
        st, r = verify(request_for(b), headers=T1)
        check("schema_digest 与模式内容摘要不符 -> 绑定不一致",
              st == 200
              and r == {"valid": False, "reason": "凭证模式绑定不一致"})
        b = body_variant(schema_version=True)
        st, r = verify(
            {"body": b, "signature": crypto.sign(b, priv1),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("body schema_version 为布尔 -> 绑定不一致",
              st == 200
              and r == {"valid": False, "reason": "凭证模式绑定不一致"})

        # 注册 v2（不同内容），借用其他版本摘要不得通过
        st, r = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": schema_id, "version": 2, "issuer_did": did,
             "claim_types": {"/role": "string"},
             "required_claims": ["/role"]},
            headers=T1,
        )
        check("注册模式 v2 -> 201", st == 201)
        digest_v2 = r["digest"]
        b = body_variant(schema_version=1, schema_digest=digest_v2)
        st, r = verify(
            {"body": b, "signature": crypto.sign(b, priv1),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("不得借用 v2 摘要验 v1 -> 绑定不一致",
              st == 200
              and r == {"valid": False, "reason": "凭证模式绑定不一致"})

        # 6. claims 约束
        b = body_variant(claims={"role": "admin", "level": 3})
        st, r = verify(request_for(b), headers=T1)
        check("缺必填路径 /addr/city -> schema validation failed",
              st == 200
              and r == {"valid": False,
                        "reason": "schema validation failed"})
        b = body_variant(claims={"role": 9, "addr": {"city": "北京"}})
        st, r = verify(request_for(b), headers=T1)
        check("声明路径类型不符 -> schema validation failed",
              st == 200
              and r == {"valid": False,
                        "reason": "schema validation failed"})
        b = body_variant(claims={"role": "admin", "level": True,
                                 "addr": {"city": "北京"}})
        st, r = verify(request_for(b), headers=T1)
        check("bool 不计入 integer -> schema validation failed",
              st == 200
              and r == {"valid": False,
                        "reason": "schema validation failed"})
        b = body_variant(claims={"role": "admin",
                                 "addr": {"city": "北京", "zip": 100000}})
        st, r = verify(request_for(b), headers=T1)
        check("未声明的额外 claims 保留且通过",
              st == 200 and r == {"valid": True})
        # claims 校验先于密码学验签：坏签名 + 缺必填仍报 schema
        b = body_variant(claims={"role": "admin"})
        st, r = verify(
            {"body": b, "signature": "!!!bad!!!",
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("claims 校验先于签名",
              st == 200
              and r == {"valid": False,
                        "reason": "schema validation failed"})

        # 7. 锚点、签名格式、密码学验签、有效期
        # 吊销锚点 -> 锚点类原因
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销锚点 -> 200", st == 200)
        st, r = verify(request_for(body), headers=T1)
        check("已吊销锚点 -> 锚点类原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        # 恢复锚点状态以便后续：重新注册不行（锚点不可恢复），改用 v2
        # 锚点与 v2 凭证
        _, pub1b = gen_keypair()  # 仅用于占位，实际仍用新密钥
        priv3, pub3 = gen_keypair()
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub3, "key_version": 3},
            headers=T1,
        )
        check("注册锚点 v3 -> 201", st == 201)
        body_v3 = make_body()
        body_v3["issuer_key_version"] = 3
        st, r = verify(
            {"body": body_v3, "signature": crypto.sign(body_v3, priv3),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("v3 锚点验签成功", st == 200 and r == {"valid": True})
        # 签名格式错误先于密码学验签
        st, r = verify(
            {"body": body_v3, "signature": "!!!not-b64!!!",
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("坏签名格式 -> 签名格式错误",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名格式错误"))
        # 密码学验签失败
        st, r = verify(
            {"body": body_v3,
             "signature": crypto.sign(body_v3, priv_other),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("错误私钥 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 篡改 claims（类型仍正确）破坏签名
        b = json.loads(json.dumps(body_v3))
        b["claims"]["role"] = "user"
        st, r = verify(
            {"body": b, "signature": crypto.sign(body_v3, priv3),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("篡改 claims -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 有效期
        b_exp = make_body(extra={"expires_at": "2020-01-01T00:00:00Z"})
        b_exp["issuer_key_version"] = 3
        st, r = verify(
            {"body": b_exp, "signature": crypto.sign(b_exp, priv3),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("已过期 -> 凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已过期")

        # 8. 外部签发 DID 停用通告
        now_z = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        notice_body = {
            "did": did, "key_version": 3, "reason": "密钥疑似泄露",
            "deactivated_at": now_z,
        }
        st, r = _http(
            "POST", f"{base}/v1/trust/dids/deactivate-sync",
            {"body": notice_body,
             "signature": crypto.sign(notice_body, priv3)},
            headers=T1,
        )
        check("登记外部 DID 停用通告 -> 201", st in (200, 201))
        st, r = verify(
            {"body": body_v3, "signature": crypto.sign(body_v3, priv3),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("命中停用通告 -> 外部签发DID已停用",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("外部签发DID已停用："))
        # T2 无通告：因无模式先报“凭证模式不存在”，证明租户隔离
        st, r = verify(request_for(body_v3), headers=T2)
        check("T2 隔离：先报模式不存在",
              st == 200 and r.get("reason") == "凭证模式不存在")

        # 9. 模式版本 deprecated/revoked 后历史凭证仍按原摘要验真。
        # 停用通告会拦截，故改用另一个干净 DID/锚点/模式做生命周期验证。
        priv_b, pub_b = gen_keypair()
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "web", "public_key": "issuer-handle-b"},
                      headers=T1)
        did_b = r["did"]
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": did_b, "public_key": pub_b, "key_version": 1},
              headers=T1)
        st, r = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": "membership", "version": 1, "issuer_did": did_b,
             "claim_types": {"/tier": "string"},
             "required_claims": ["/tier"]},
            headers=T1,
        )
        check("注册 did_b 模式 -> 201", st == 201)
        digest_b = r["digest"]
        body_b = {
            "credential_id": "vc_b_1",
            "issuer_did": did_b,
            "subject_did": "did:web:subject.example",
            "claims": {"tier": "gold", "bonus": 42},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
            "schema_id": "membership",
            "schema_version": 1,
            "schema_digest": digest_b,
        }
        sig_b = crypto.sign(body_b, priv_b)
        st, r = verify(
            {"body": body_b, "signature": sig_b,
             "schema_id": "membership", "schema_version": 1},
            headers=T1,
        )
        check("did_b 凭证验真成功（含额外 claim）",
              st == 200 and r == {"valid": True})
        st, _ = _http(
            "POST", f"{base}/v1/credential-schemas/membership/1/status",
            {"issuer_did": did_b, "status": "deprecated"}, headers=T1,
        )
        check("弃用模式 -> 201/200", st in (200, 201))
        st, r = verify(
            {"body": body_b, "signature": sig_b,
             "schema_id": "membership", "schema_version": 1},
            headers=T1,
        )
        check("deprecated 后历史凭证仍按原摘要验真",
              st == 200 and r == {"valid": True})
        st, _ = _http(
            "POST", f"{base}/v1/credential-schemas/membership/1/status",
            {"issuer_did": did_b, "status": "revoked"}, headers=T1,
        )
        check("吊销模式 -> 201/200", st in (200, 201))
        st, r = verify(
            {"body": body_b, "signature": sig_b,
             "schema_id": "membership", "schema_version": 1},
            headers=T1,
        )
        check("revoked 后历史凭证仍按原摘要验真",
              st == 200 and r == {"valid": True})

        # 10. 只读：不登记凭证、不记审计
        st, _ = _http(
            "GET", f"{base}/v1/credentials/vc_external_schema_0001",
            headers=T1,
        )
        check("外部凭证未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(request_for(body), headers=T1)
            verify(raw=b"{bad json", headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("验真（含失败）不记审计",
              len(after["events"]) == n_before)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 11. 跨重启结论不变
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tvs-a"}
        st, r = verify(
            {"body": body_b, "signature": sig_b,
             "schema_id": "membership", "schema_version": 1},
            headers=T1,
        )
        check("重启后 revoked 模式历史凭证仍验真成功",
              st == 200 and r == {"valid": True})
        st, r = verify(
            {"body": body_v3, "signature": crypto.sign(body_v3, priv3),
             "schema_id": schema_id, "schema_version": 1},
            headers=T1,
        )
        check("重启后停用通告仍生效",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("外部签发DID已停用："))
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
