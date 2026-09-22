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


def main():
    port = 8955
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/proofs/verify"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload, headers=headers, raw=raw)

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

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tpr-a"}
        T2 = {"X-Tenant-ID": "tpr-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:external-proof.example"

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

        DEFAULT_PREDS = [
            {"path": "/age", "op": "gte", "value": 18},
            {"path": "/role", "op": "eq", "value": "admin"},
            {"path": "/name", "op": "exists"},
        ]

        def make_proof(version=2, challenge="chal-1",
                       expires_at="2099-01-01T00:00:00Z",
                       predicates=None, results=None,
                       issuer=did, source="source-tenant"):
            return {
                "proof_id": "zp_" + "a" * 32,
                "credential_id": "vc_external_proof_1",
                "issuer_did": issuer,
                "issuer_key_version": version,
                "predicates": (
                    DEFAULT_PREDS if predicates is None else predicates
                ),
                "results": (
                    [True, True, True] if results is None else results
                ),
                "challenge": challenge,
                "expires_at": expires_at,
                "_source": source,
            }

        def sign_proof(p, priv):
            source = p.pop("_source")
            message = {k: v for k, v in p.items() if k != "proof"}
            message["tenant_id"] = source
            p["proof"] = crypto.sign(message, priv)
            return p

        def signed(version=2, priv=None, **kwargs):
            p = make_proof(version=version, **kwargs)
            return sign_proof(p, priv or priv2)

        def req(p, challenge="chal-1", source="source-tenant"):
            return {"proof": p, "challenge": challenge,
                    "source_tenant_id": source}

        # 1. 成功：九字段证明，v2 锚点验签，响应恰为 {"valid": true}
        proof = signed()
        st, r = verify(req(proof), headers=T1)
        check("外部证明验签成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})

        # 2. 请求结构错误（前缀“请求”）
        invalid_with_prefix("空请求体", "请求", raw=b"")
        invalid_with_prefix("非法 JSON", "请求", raw=b"not-json")
        invalid_with_prefix("UTF-8 非法", "请求", raw=b"\xff\xfe")
        invalid_with_prefix("JSON 数组非对象", "请求", raw=b"[1,2]")
        invalid_with_prefix("JSON null 非对象", "请求", raw=b"null")
        invalid_with_prefix("缺 proof", "请求",
                            {"challenge": "chal-1", "source_tenant_id": "s"},
                            headers=T1)
        invalid_with_prefix("缺 challenge", "请求",
                            {"proof": proof, "source_tenant_id": "s"},
                            headers=T1)
        invalid_with_prefix("缺 source_tenant_id", "请求",
                            {"proof": proof, "challenge": "chal-1"},
                            headers=T1)
        invalid_with_prefix("多余字段", "请求",
                            {"proof": proof, "challenge": "chal-1",
                             "source_tenant_id": "s", "extra": 1}, headers=T1)
        invalid_with_prefix("空对象", "请求", {}, headers=T1)
        invalid_with_prefix("proof 为数组", "请求",
                            {"proof": [], "challenge": "chal-1",
                             "source_tenant_id": "s"}, headers=T1)
        invalid_with_prefix("proof 为字符串", "请求",
                            {"proof": "x", "challenge": "chal-1",
                             "source_tenant_id": "s"}, headers=T1)
        invalid_with_prefix("proof 为 null", "请求",
                            {"proof": None, "challenge": "chal-1",
                             "source_tenant_id": "s"}, headers=T1)
        for field in ("challenge", "source_tenant_id"):
            invalid_with_prefix(f"{field} 为空串", "请求",
                                {"proof": proof, "challenge": "chal-1",
                                 "source_tenant_id": "s",
                                 field: ""}, headers=T1)
            invalid_with_prefix(f"{field} 为数字", "请求",
                                {"proof": proof, "challenge": "chal-1",
                                 "source_tenant_id": "s",
                                 field: 123}, headers=T1)
            invalid_with_prefix(f"{field} 为 null", "请求",
                                {"proof": proof, "challenge": "chal-1",
                                 "source_tenant_id": "s",
                                 field: None}, headers=T1)

        # 3. 证明字段错误（前缀“证明”）
        def proof_with(**changes):
            p = json.loads(json.dumps(proof))
            source = changes.pop("_source", "source-tenant")
            for key, value in changes.items():
                if value is _DELETE:
                    p.pop(key, None)
                else:
                    p[key] = value
            if "proof" not in p or "proof" in changes:
                # 删除/直接篡改 proof 时不重签，保留其目标形态
                return p
            p.pop("proof", None)
            p["_source"] = source
            return sign_proof(p, priv2)

        nine = ("proof_id", "credential_id", "issuer_did",
                "issuer_key_version", "predicates", "results",
                "challenge", "expires_at", "proof")
        for field in nine:
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
            (True, "布尔 true"), (False, "布尔 false"), (0, "零"),
            (-1, "负数"), (1.5, "小数"), ("2", "字符串"),
        ]:
            invalid_with_prefix(
                f"issuer_key_version 非法（{label}）", "证明",
                req(proof_with(issuer_key_version=bad_version)), headers=T1,
            )

        # predicates 结构
        invalid_with_prefix("predicates 非数组", "证明",
                            req(proof_with(predicates="/age", results=[])),
                            headers=T1)
        invalid_with_prefix("predicates 为空数组", "证明",
                            req(proof_with(predicates=[], results=[])),
                            headers=T1)
        invalid_with_prefix("predicate 非对象", "证明",
                            req(proof_with(predicates=[1], results=[True])),
                            headers=T1)
        invalid_with_prefix("predicate 缺 path", "证明",
                            req(proof_with(
                                predicates=[{"op": "exists"}],
                                results=[True])), headers=T1)
        invalid_with_prefix("predicate 缺 op", "证明",
                            req(proof_with(
                                predicates=[{"path": "/a"}],
                                results=[True])), headers=T1)
        invalid_with_prefix("predicate 多余字段", "证明",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "exists",
                                             "x": 1}],
                                results=[True])), headers=T1)
        invalid_with_prefix("op 非法", "证明",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "contains"}],
                                results=[True])), headers=T1)
        invalid_with_prefix("exists 带 value", "证明",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "exists",
                                             "value": 1}],
                                results=[True])), headers=T1)
        for op in ("eq", "gte", "lte"):
            invalid_with_prefix(f"{op} 缺 value", "证明",
                                req(proof_with(
                                    predicates=[{"path": "/a", "op": op}],
                                    results=[True])), headers=T1)
        invalid_with_prefix("gte value 为布尔", "证明",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "gte",
                                             "value": True}],
                                results=[True])), headers=T1)
        invalid_with_prefix("lte value 为字符串", "证明",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "lte",
                                             "value": "x"}],
                                results=[True])), headers=T1)
        invalid_with_prefix("path 不以 / 开头", "证明 predicates",
                            req(proof_with(
                                predicates=[{"path": "age", "op": "exists"}],
                                results=[True])), headers=T1)
        invalid_with_prefix("path 非法转义 ~2", "证明 predicates",
                            req(proof_with(
                                predicates=[{"path": "/a~2", "op": "exists"}],
                                results=[True])), headers=T1)
        invalid_with_prefix("path 重复", "证明 predicates",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "exists"},
                                            {"path": "/a", "op": "exists"}],
                                results=[True, True])), headers=T1)
        invalid_with_prefix("path 祖先重叠", "证明 predicates",
                            req(proof_with(
                                predicates=[{"path": "/a", "op": "exists"},
                                            {"path": "/a/b", "op": "exists"}],
                                results=[True, True])), headers=T1)
        # 不校验 claims 命中：指向不存在属性的存在谓词也可验真
        miss = signed(predicates=[{"path": "/zzz", "op": "exists"}],
                      results=[False])
        st, r = verify(req(miss), headers=T1)
        check("不校验 claims 命中（不存在路径仍验真成功）",
              st == 200 and r == {"valid": True})
        # 不校验数组路径
        arr = signed(predicates=[{"path": "/tags/0", "op": "exists"}],
                     results=[True])
        st, r = verify(req(arr), headers=T1)
        check("不校验数组路径", st == 200 and r == {"valid": True})
        # gte 命中值类型不校验（外部无 claims 可查），仅校验谓词 value
        gte_ok = signed(
            predicates=[{"path": "/name", "op": "gte", "value": 1}],
            results=[False])
        st, r = verify(req(gte_ok), headers=T1)
        check("gte 不校验命中值类型", st == 200 and r == {"valid": True})

        # results 结构
        invalid_with_prefix("results 非数组", "证明",
                            req(proof_with(results=True)), headers=T1)
        invalid_with_prefix("results 长度不符", "证明",
                            req(proof_with(results=[True, True])), headers=T1)
        invalid_with_prefix("results 含非布尔", "证明",
                            req(proof_with(results=[True, "x", True])),
                            headers=T1)
        invalid_with_prefix("results 含数字", "证明",
                            req(proof_with(results=[1, 0, True])),
                            headers=T1)
        # 不重算 results：与谓词语义相反但签名合法的结果仍判有效
        lie = signed(results=[False, False, False])
        st, r = verify(req(lie), headers=T1)
        check("不重算 results（结果造假仍验签通过）",
              st == 200 and r == {"valid": True})

        # 字段校验先于锚点
        bad = proof_with(issuer="did:web:nope", credential_id=_DELETE)
        st, r = verify(req(bad), headers=T1)
        check("证明字段校验优先于锚点查找",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("证明"))

        # 4. 挑战不匹配（前缀“挑战”）
        invalid_with_prefix("请求 challenge 与证明不一致", "挑战",
                            req(proof, challenge="chal-2"), headers=T1)
        other = signed(challenge="chal-9")
        invalid_with_prefix("证明 challenge 改变后仍不一致", "挑战",
                            req(other, challenge="chal-1"), headers=T1)
        st, r = verify(req(other, challenge="chal-9"), headers=T1)
        check("challenge 一致时验签成功", st == 200 and r == {"valid": True})

        # 5. 锚点错误（前缀“锚点”）
        unknown = signed(issuer="did:web:unknown.example")
        invalid_with_prefix("未知签发者锚点", "锚点",
                            req(unknown), headers=T1)
        invalid_with_prefix("未知版本锚点（v9）", "锚点",
                            req(signed(version=9, priv=priv1)), headers=T1)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        v1 = signed(version=1, priv=priv1)
        invalid_with_prefix("已吊销锚点（v1）", "锚点",
                            req(v1), headers=T1)
        bad_sig_v1 = json.loads(json.dumps(v1))
        bad_sig_v1["proof"] = "!!!bad!!!"
        invalid_with_prefix("锚点校验优先于签名格式", "锚点",
                            req(bad_sig_v1), headers=T1)

        # 6. 签名格式错误（前缀“签名格式错误”）；v2 仍 active
        fmt_bad = json.loads(json.dumps(proof))
        fmt_bad["proof"] = "!!!not-b64!!!"
        invalid_with_prefix("非 base64url proof", "签名格式错误",
                            req(fmt_bad), headers=T1)
        too_short = json.loads(json.dumps(proof))
        too_short["proof"] = proof["proof"][:-2]
        invalid_with_prefix("proof 长度不足", "签名格式错误",
                            req(too_short), headers=T1)

        # 7. 签名校验失败（前缀“签名校验失败”）
        wrong_key = make_proof()
        wrong_key.pop("_source")
        msg = {k: v for k, v in wrong_key.items() if k != "proof"}
        msg["tenant_id"] = "source-tenant"
        wrong_key["proof"] = crypto.sign(msg, priv1)  # v1 私钥签 v2
        invalid_with_prefix("错误私钥签名", "签名校验失败",
                            req(wrong_key), headers=T1)
        # tenant_id 必须等于 source_tenant_id
        other_src = signed(source="other-tenant")
        invalid_with_prefix("签名 tenant_id 与 source_tenant_id 不一致",
                            "签名校验失败",
                            req(other_src, source="source-tenant"),
                            headers=T1)
        st, r = verify(req(other_src, source="other-tenant"), headers=T1)
        check("tenant_id 与 source_tenant_id 一致时通过",
              st == 200 and r == {"valid": True})
        tampered = json.loads(json.dumps(proof))
        tampered["credential_id"] = "vc_other"
        invalid_with_prefix("篡改 credential_id", "签名校验失败",
                            req(tampered), headers=T1)
        tampered_r = json.loads(json.dumps(proof))
        tampered_r["results"] = [False, True, True]
        invalid_with_prefix("篡改 results", "签名校验失败",
                            req(tampered_r), headers=T1)

        # 8. 期限：格式非法（前缀“证明”）与已过期（“证明已过期”）
        invalid_with_prefix("expires_at 非 Z 秒精度", "证明",
                            req(signed(expires_at="2099-01-01")), headers=T1)
        invalid_with_prefix("expires_at 带时区偏移", "证明",
                            req(signed(expires_at="2099-01-01T00:00:00+08:00")),
                            headers=T1)
        invalid_with_prefix("expires_at 非法时刻", "证明",
                            req(signed(expires_at="2099-13-01T00:00:00Z")),
                            headers=T1)
        expired = signed(expires_at="2020-01-01T00:00:00Z")
        st, r = verify(req(expired), headers=T1)
        check("已过期证明 -> 证明已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "证明已过期")
        expired_bad_sig = json.loads(json.dumps(expired))
        expired_bad_sig["proof"] = "!!!bad!!!"
        invalid_with_prefix("签名格式优先于过期", "签名格式错误",
                            req(expired_bad_sig), headers=T1)

        # 9. 只读：不登记证明/凭证、不消费、不记审计
        st, _ = _http("GET", f"{base}/v1/credentials/vc_external_proof_1",
                      headers=T1)
        check("验签后凭证仍未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify(req(proof), headers=T1)  # 可重复成功（不消费）
            verify(req(unknown), headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("验签（含失败与重复成功）不记审计",
              len(after["events"]) == n_before)
        st, r = verify(req(proof), headers=T1)
        check("重复验签始终成功（不消费）",
              st == 200 and r == {"valid": True})

        # 10. 跨租户：各自使用本租户锚点
        invalid_with_prefix("T2 无锚点 -> 锚点不存在", "锚点",
                            req(proof), headers=T2)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        t2_proof = make_proof()
        t2_proof.pop("_source")
        t2_msg = {k: v for k, v in t2_proof.items() if k != "proof"}
        t2_msg["tenant_id"] = "source-tenant"
        t2_proof["proof"] = crypto.sign(t2_msg, priv1)
        st, r = verify(req(t2_proof), headers=T2)
        check("T2 按自己的锚点验签成功", st == 200 and r == {"valid": True})
        invalid_with_prefix("同一签名在 T1 公钥不匹配 -> 失败",
                            "签名校验失败", req(t2_proof), headers=T1)

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
        T1 = {"X-Tenant-ID": "tpr-a"}

        p2 = make_proof()
        p2.pop("_source")
        msg = {k: v for k, v in p2.items() if k != "proof"}
        msg["tenant_id"] = "source-tenant"
        p2["proof"] = crypto.sign(msg, priv2)
        st, r = _http("POST", f"{base}{path}",
                      {"proof": p2, "challenge": "chal-1",
                       "source_tenant_id": "source-tenant"}, headers=T1)
        check("重启后 active v2 仍可验签", st == 200 and r == {"valid": True})
        p1 = make_proof(version=1)
        p1.pop("_source")
        msg1 = {k: v for k, v in p1.items() if k != "proof"}
        msg1["tenant_id"] = "source-tenant"
        p1["proof"] = crypto.sign(msg1, priv1)
        st, r = _http("POST", f"{base}{path}",
                      {"proof": p1, "challenge": "chal-1",
                       "source_tenant_id": "source-tenant"}, headers=T1)
        check("重启后吊销 v1 状态保留 -> 锚点失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        st, _ = _http("GET", f"{base}/v1/credentials/vc_external_proof_1",
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


if __name__ == "__main__":
    raise SystemExit(main())
