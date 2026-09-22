#!/usr/bin/env python3
"""跨系统谓词证明验真 POST /v1/trust/proofs/verify 的端到端测试。

直接运行：python3 tests/trust_proof_verify_test.py
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


_DELETE = object()
SRC = "src-tenant"


def main():
    port = 8958
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/proofs/verify"
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
        T1 = {"X-Tenant-ID": "tzp-a"}
        T2 = {"X-Tenant-ID": "tzp-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:prover.example"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify(
            payload={"proof": {}, "challenge": "x", "source_tenant_id": "s"},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 直接注册信任锚点：无需登记 DID/凭证/证明
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册外部锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册外部锚点 v2 -> 201", st == 201)

        def make_proof(version=2, challenge="chal-1",
                       expires_at="2099-01-01T00:00:00Z",
                       predicates=None, results=None):
            if predicates is None:
                predicates = [
                    {"path": "/age", "op": "gte", "value": 18},
                    {"path": "/role", "op": "eq", "value": "admin"},
                    {"path": "/name", "op": "exists"},
                ]
            if results is None:
                results = [True, False, True]
            return {
                "proof_id": "zp_" + "b" * 32,
                "credential_id": "vc_external_0001",
                "issuer_did": did,
                "issuer_key_version": version,
                "predicates": predicates,
                "results": results,
                "challenge": challenge,
                "expires_at": expires_at,
            }

        def sign_proof(p, priv, tenant=SRC):
            message = {k: v for k, v in p.items() if k != "proof"}
            message["tenant_id"] = tenant
            return crypto.sign(message, priv)

        def signed(version=2, priv=None, tenant=SRC, **kwargs):
            p = make_proof(version=version, **kwargs)
            p["proof"] = sign_proof(p, priv or priv2, tenant)
            return p

        def req(proof_obj, challenge="chal-1", source=SRC):
            return {"proof": proof_obj, "challenge": challenge,
                    "source_tenant_id": source}

        # 1. 成功：九字段证明，v2 锚点验签，响应恰为 {"valid": true}
        proof = signed()
        st, r = verify(req(proof), headers=T1)
        check("外部证明验签成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})

        # results 不重算：exists 谓词结果为 false 也可验真（只看签名）
        odd = signed(predicates=[{"path": "/name", "op": "exists"}],
                     results=[False])
        st, r = verify(req(odd), headers=T1)
        check("results 不重算（exists=false 仍有效）",
              st == 200 and r == {"valid": True})

        # 不校验 claims 命中与数组路径：语法合法即可
        noclaims = signed(
            predicates=[{"path": "/no/such/attr", "op": "exists"},
                        {"path": "/arr/0", "op": "eq", "value": 1}],
            results=[True, True])
        st, r = verify(req(noclaims), headers=T1)
        check("不校验 claims 命中与数组路径",
              st == 200 and r == {"valid": True})

        # 2. 请求结构错误（前缀“请求”）
        invalid_with_prefix("空请求体", "请求", raw=b"")
        invalid_with_prefix("非法 JSON", "请求", raw=b"not-json")
        invalid_with_prefix("UTF-8 非法", "请求", raw=b"\xff\xfe")
        invalid_with_prefix("JSON 数组非对象", "请求", raw=b"[1,2]")
        invalid_with_prefix("JSON null 非对象", "请求", raw=b"null")
        invalid_with_prefix("缺 proof", "请求",
                            {"challenge": "c", "source_tenant_id": SRC},
                            headers=T1)
        invalid_with_prefix("缺 challenge", "请求",
                            {"proof": proof, "source_tenant_id": SRC},
                            headers=T1)
        invalid_with_prefix("缺 source_tenant_id", "请求",
                            {"proof": proof, "challenge": "chal-1"},
                            headers=T1)
        invalid_with_prefix("多余字段", "请求",
                            dict(req(proof), extra=1), headers=T1)
        invalid_with_prefix("空对象", "请求", {}, headers=T1)
        invalid_with_prefix("proof 为数组", "请求",
                            req([], ), headers=T1)
        invalid_with_prefix("proof 为字符串", "请求",
                            req("x"), headers=T1)
        invalid_with_prefix("proof 为 null", "请求",
                            req(None), headers=T1)
        invalid_with_prefix("challenge 为空串", "请求",
                            req(proof, challenge=""), headers=T1)
        invalid_with_prefix("challenge 为数字", "请求",
                            req(proof, challenge=123), headers=T1)
        invalid_with_prefix("challenge 为 null", "请求",
                            req(proof, challenge=None), headers=T1)
        invalid_with_prefix("source_tenant_id 为空串", "请求",
                            req(proof, source=""), headers=T1)
        invalid_with_prefix("source_tenant_id 为数字", "请求",
                            req(proof, source=7), headers=T1)
        invalid_with_prefix("source_tenant_id 为 null", "请求",
                            req(proof, source=None), headers=T1)

        # 3. 证明字段错误（前缀“证明”）
        def proof_with(**changes):
            p = json.loads(json.dumps(proof))
            for key, value in changes.items():
                if value is _DELETE:
                    p.pop(key, None)
                else:
                    p[key] = value
            return p

        for field in ("proof_id", "credential_id", "issuer_did",
                      "issuer_key_version", "predicates", "results",
                      "challenge", "expires_at", "proof"):
            invalid_with_prefix(
                f"缺证明字段 {field}", "证明",
                req(proof_with(**{field: _DELETE})), headers=T1,
            )
        invalid_with_prefix("证明含多余字段", "证明",
                            req(proof_with(extra_field=1)), headers=T1)
        for field in ("proof_id", "credential_id", "issuer_did",
                      "challenge", "expires_at", "proof"):
            invalid_with_prefix(
                f"证明字段 {field} 为空串", "证明",
                req(proof_with(**{field: ""})), headers=T1,
            )
            invalid_with_prefix(
                f"证明字段 {field} 非字符串", "证明",
                req(proof_with(**{field: 123})), headers=T1,
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
                f"issuer_key_version 非法（{label}）", "证明",
                req(proof_with(issuer_key_version=bad_version)), headers=T1,
            )
        invalid_with_prefix("predicates 非数组", "证明",
                            req(proof_with(predicates="/age")), headers=T1)
        invalid_with_prefix("predicates 为空数组", "证明",
                            req(proof_with(predicates=[], results=[])),
                            headers=T1)
        invalid_with_prefix("results 非数组", "证明",
                            req(proof_with(results="x")), headers=T1)
        invalid_with_prefix("results 含非布尔", "证明",
                            req(proof_with(results=[True, 1, True])),
                            headers=T1)
        invalid_with_prefix("results 含 null", "证明",
                            req(proof_with(results=[True, None, True])),
                            headers=T1)
        invalid_with_prefix("results 长度不一致", "证明",
                            req(proof_with(results=[True, False])),
                            headers=T1)

        # 谓词项结构（前缀“证明”）
        def pred_proof(preds):
            return proof_with(predicates=preds,
                              results=[True] * len(preds))

        invalid_with_prefix("谓词元素非对象", "证明",
                            req(pred_proof(["/age"])), headers=T1)
        invalid_with_prefix("谓词缺 path", "证明",
                            req(pred_proof([{"op": "exists"}])), headers=T1)
        invalid_with_prefix("谓词缺 op", "证明",
                            req(pred_proof([{"path": "/age"}])), headers=T1)
        invalid_with_prefix("谓词含多余字段", "证明",
                            req(pred_proof([{"path": "/age", "op": "exists",
                                             "foo": 1}])), headers=T1)
        invalid_with_prefix("谓词 op 非法", "证明",
                            req(pred_proof([{"path": "/age", "op": "lt",
                                             "value": 1}])), headers=T1)
        invalid_with_prefix("exists 禁 value", "证明",
                            req(pred_proof([{"path": "/age", "op": "exists",
                                             "value": 1}])), headers=T1)
        invalid_with_prefix("eq 缺 value", "证明",
                            req(pred_proof([{"path": "/age", "op": "eq"}])),
                            headers=T1)
        invalid_with_prefix("gte 缺 value", "证明",
                            req(pred_proof([{"path": "/age", "op": "gte"}])),
                            headers=T1)
        invalid_with_prefix("lte 缺 value", "证明",
                            req(pred_proof([{"path": "/age", "op": "lte"}])),
                            headers=T1)
        invalid_with_prefix("gte value 为布尔", "证明",
                            req(pred_proof([{"path": "/age", "op": "gte",
                                             "value": True}])), headers=T1)
        invalid_with_prefix("lte value 为字符串", "证明",
                            req(pred_proof([{"path": "/age", "op": "lte",
                                             "value": "18"}])), headers=T1)
        invalid_with_prefix("path 非字符串", "证明",
                            req(pred_proof([{"path": 1, "op": "exists"}])),
                            headers=T1)
        invalid_with_prefix("path 不以 / 开头", "证明",
                            req(pred_proof([{"path": "age",
                                             "op": "exists"}])), headers=T1)
        invalid_with_prefix("path 根路径", "证明",
                            req(pred_proof([{"path": "", "op": "exists"}])),
                            headers=T1)
        invalid_with_prefix("path 非法转义", "证明",
                            req(pred_proof([{"path": "/a~2b",
                                             "op": "exists"}])), headers=T1)
        invalid_with_prefix("path 尾部 ~", "证明",
                            req(pred_proof([{"path": "/a~",
                                             "op": "exists"}])), headers=T1)
        invalid_with_prefix("path 重复", "证明",
                            req(pred_proof([{"path": "/age", "op": "exists"},
                                            {"path": "/age",
                                             "op": "exists"}])), headers=T1)
        # 转义 token "a/b" 与两段路径 /a/b 不重叠：字段校验通过，
        # 签名有效即验真成功
        mixed = signed(predicates=[{"path": "/a~1b", "op": "exists"},
                                   {"path": "/a/b", "op": "exists"}],
                       results=[True, True])
        st, r = verify(req(mixed), headers=T1)
        check("转义 token 与嵌套路径不判重叠",
              st == 200 and r == {"valid": True})
        invalid_with_prefix("path 祖先重叠", "证明",
                            req(pred_proof([{"path": "/a", "op": "exists"},
                                            {"path": "/a/b",
                                             "op": "exists"}])), headers=T1)
        invalid_with_prefix("path 后代重叠", "证明",
                            req(pred_proof([{"path": "/a/b", "op": "exists"},
                                            {"path": "/a",
                                             "op": "exists"}])), headers=T1)

        # 合法转义与 eq 任意类型 value 可通过字段校验（签名仍有效）
        escaped = signed(predicates=[{"path": "/a~0b~1c", "op": "eq",
                                      "value": {"x": [1, "y", None]}}],
                         results=[True])
        st, r = verify(req(escaped), headers=T1)
        check("合法转义与任意 eq value 验签成功",
              st == 200 and r == {"valid": True})

        # 4. 挑战不一致（前缀“挑战”）
        invalid_with_prefix("挑战不一致", "挑战",
                            req(proof, challenge="other"), headers=T1)

        # 5. 锚点（前缀“锚点”）
        invalid_with_prefix("锚点不存在（未知 DID）", "锚点",
                            req(proof_with(issuer_did="did:web:unknown")),
                            headers=T1)
        invalid_with_prefix("锚点不存在（未知版本）", "锚点",
                            req(proof_with(issuer_key_version=9)),
                            headers=T1)
        st, r = verify(req(proof), headers=T2)
        check("跨租户锚点不可探测",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        v1proof = signed(version=1, priv=priv1)
        invalid_with_prefix("锚点已吊销", "锚点", req(v1proof), headers=T1)

        # 6. 签名格式错误（前缀“签名格式错误”）
        invalid_with_prefix("签名非 base64url", "签名格式错误",
                            req(proof_with(proof="!!!")), headers=T1)
        invalid_with_prefix("签名长度非法", "签名格式错误",
                            req(proof_with(proof="AQID")), headers=T1)

        # 7. 签名校验失败（前缀“签名校验失败”）
        tampered = proof_with(results=[False, False, True])
        invalid_with_prefix("篡改 results", "签名校验失败",
                            req(tampered), headers=T1)
        wrong_key = signed(priv=priv1)  # v2 对象用 v1 私钥签
        invalid_with_prefix("错误私钥签名", "签名校验失败",
                            req(wrong_key), headers=T1)
        wrong_tenant = signed(tenant="other-tenant")
        invalid_with_prefix("tenant_id 不匹配", "签名校验失败",
                            req(wrong_tenant), headers=T1)
        wrong_source = req(proof, source="other-tenant")
        invalid_with_prefix("source_tenant_id 与签名不符", "签名校验失败",
                            wrong_source, headers=T1)

        # 8. 期限（前缀“证明”/“证明已过期”）：格式用例须重新签名，
        # 使签名校验通过后进入期限检查
        bad_fmt1 = signed(expires_at="2099-01-01 00:00:00")
        invalid_with_prefix("expires_at 非 Z 格式", "证明",
                            req(bad_fmt1), headers=T1)
        bad_fmt2 = signed(expires_at="2099-01-01T00:00:00.000Z")
        invalid_with_prefix("expires_at 含毫秒", "证明",
                            req(bad_fmt2), headers=T1)
        bad_fmt3 = signed(expires_at="2099-13-01T00:00:00Z")
        invalid_with_prefix("expires_at 非法时刻", "证明",
                            req(bad_fmt3), headers=T1)
        expired = signed(expires_at="2000-01-01T00:00:00Z")
        st, r = verify(req(expired), headers=T1)
        check("过期证明返回 证明已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "证明已过期")

        # 9. 只读：不消费、不记审计（审计仅两条锚点注册 + 一条吊销）
        st, r = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                      headers=T1)
        actions = [e["action"] for e in r.get("events", [])]
        check("验真不记审计",
              st == 200 and actions == ["trust.anchor.registered",
                                        "trust.anchor.registered",
                                        "trust.anchor.revoked"])
        # 同一证明可重复验真（不消费）
        st, r = verify(req(proof), headers=T1)
        check("重复验真仍 valid:true（不消费）",
              st == 200 and r == {"valid": True})

        # 10. 重启后结论一致
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, r = verify(req(proof), headers=T1)
        check("重启后验签结论一致", st == 200 and r == {"valid": True})
        st, r = verify(req(expired), headers=T1)
        check("重启后过期结论一致",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "证明已过期")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"FAILED: {len(failures)} 项未通过")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
