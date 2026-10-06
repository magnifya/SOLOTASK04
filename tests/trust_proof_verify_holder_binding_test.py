#!/usr/bin/env python3
"""跨系统谓词证明验真（POST /v1/trust/proofs/verify 与 verify-batch）
可选持有者绑定（holder_binding）的端到端测试。

直接运行：python3 tests/trust_proof_verify_holder_binding_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- holder_binding 缺省/false 保持九字段协议；true 要求 prove 返回的
  十二字段绑定对象；非布尔 -> “请求参数无效”；
- 绑定模式字段集非十二字段或持有者字段类型非法 -> “持有者绑定格式
  错误”；未绑定出现 holder_* 仍按多余字段失败；
- 基础字段、谓词、挑战校验沿用既有原因；issuer 签名覆盖去掉 proof
  及 holder_* 的对象，holder_proof 覆盖去掉 proof/holder_proof 且
  保留持有者字段的对象，均追加 tenant_id=source_tenant_id；
- 持有者锚点缺失/吊销/用途不符/公钥不可用 -> “持有者锚点不可用”；
  持有者签名编码错误/验签失败 -> “持有者签名格式错误”/“持有者签名
  校验失败”；
- 判定顺序：请求 -> 证明结构 -> 挑战 -> 签发者锚点/签名 -> 持有者
  锚点/签名 -> 期限 -> 签发者停用 -> 持有者停用；
- verify-batch 逐项接受两种形态，外层协议不变；
- 只读不消费不记审计；消费/状态合并接口不接受 holder_binding；
- prove 生成的真实绑定证明跨系统验真成功。
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

PORT = 8955
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"
VERIFY = "/v1/trust/proofs/verify"
VERIFY_BATCH = "/v1/trust/proofs/verify-batch"

ISSUER_DID = "did:web:hb-proof-issuer.example"
HOLDER_DID = "did:web:hb-proof-holder.example"
SOURCE = "source-tenant"

NINE = ("proof_id", "credential_id", "issuer_did", "issuer_key_version",
        "predicates", "results", "challenge", "expires_at", "proof")
HOLDER_KEYS = ("holder_did", "holder_key_version", "holder_proof")

PREDS = [
    {"path": "/age", "op": "gte", "value": 18},
    {"path": "/name", "op": "exists"},
]

_DELETE = object()


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


def make_bound(challenge="chal-1", expires_at="2099-01-01T00:00:00Z",
               predicates=None, results=None, holder=HOLDER_DID,
               holder_version=1, issuer=ISSUER_DID, version=1):
    return {
        "proof_id": "zp_" + "a" * 32,
        "credential_id": "vc_hb_proof_1",
        "issuer_did": issuer,
        "issuer_key_version": version,
        "predicates": PREDS if predicates is None else predicates,
        "results": [True, True] if results is None else results,
        "challenge": challenge,
        "expires_at": expires_at,
        "holder_did": holder,
        "holder_key_version": holder_version,
    }


def sign_bound(p, issuer_priv, holder_priv, tenant=SOURCE):
    """按协议签名：issuer 覆盖去掉 proof 及 holder_* 的对象并加入
    tenant_id；holder 覆盖去掉 proof/holder_proof 且保留持有者字段
    的对象并加入 tenant_id。"""
    p = dict(p)
    issuer_msg = {
        k: v for k, v in p.items()
        if k != "proof" and not k.startswith("holder_")
    }
    issuer_msg["tenant_id"] = tenant
    p["proof"] = crypto.sign(issuer_msg, issuer_priv)
    holder_msg = {
        k: v for k, v in p.items()
        if k not in ("proof", "holder_proof")
    }
    holder_msg["tenant_id"] = tenant
    p["holder_proof"] = crypto.sign(holder_msg, holder_priv)
    return p


def main():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
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
        return _http("POST", f"{BASE}{VERIFY}", payload, headers=headers,
                     raw=raw)

    def invalid_exact(name, reason, payload=None, headers=None):
        st, r = verify(payload=payload, headers=headers)
        check(name, st == 200 and r == {"valid": False, "reason": reason})

    def invalid_with_prefix(name, prefix, payload=None, headers=None):
        st, r = verify(payload=payload, headers=headers)
        check(
            name,
            st == 200
            and r.get("valid") is False
            and isinstance(r.get("reason"), str)
            and r["reason"].startswith(prefix),
        )

    try:
        assert wait_up(PORT), "服务启动超时"

        TV = {"X-Tenant-ID": "tpvhb-v"}
        TO = {"X-Tenant-ID": "tpvhb-other"}

        iss_priv, iss_pub = gen_keypair()
        hold_priv, hold_pub = gen_keypair()
        other_priv, other_pub = gen_keypair()

        # 验证租户登记签发者与持有者锚点（省略 uses -> 全用途）
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1}, headers=TV)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": hold_pub,
                       "key_version": 1}, headers=TV)
        check("注册持有者锚点 -> 201", st == 201)

        good = sign_bound(make_bound(), iss_priv, hold_priv)

        def req(p, binding=True, challenge="chal-1", source=SOURCE):
            r = {"proof": p, "challenge": challenge,
                 "source_tenant_id": source}
            if binding is not _DELETE:
                r["holder_binding"] = binding
            return r

        # 1. 绑定验真成功：响应恰为 {"valid": true}
        st, r = verify(req(good), headers=TV)
        check("绑定证明验真成功且响应恰为 valid:true",
              st == 200 and r == {"valid": True})
        # results 含 false 不影响验真结论
        false_results = sign_bound(
            make_bound(results=[False, True]), iss_priv, hold_priv)
        st, r = verify(req(false_results), headers=TV)
        check("results 含 false 仍 valid:true", st == 200 and r == {"valid": True})

        # 2. holder_binding 缺省/false 保持九字段协议
        nine_proof = sign_bound(make_bound(), iss_priv, hold_priv)
        for key in HOLDER_KEYS:
            nine_proof.pop(key)
        st, r = verify(req(nine_proof, binding=_DELETE), headers=TV)
        check("缺省 holder_binding 九字段证明 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(req(nine_proof, binding=False), headers=TV)
        check("holder_binding=false 九字段证明 valid:true",
              st == 200 and r == {"valid": True})
        # 未绑定（缺省或 false）出现 holder_* 仍按多余字段失败
        invalid_with_prefix("缺省 holder_binding 出现 holder_* -> 多余字段",
                            "证明含多余字段",
                            req(good, binding=_DELETE), headers=TV)
        invalid_with_prefix("holder_binding=false 出现 holder_* -> 多余字段",
                            "证明含多余字段",
                            req(good, binding=False), headers=TV)

        # 3. holder_binding 非布尔 -> 请求参数无效（恰为该原因）
        for bad in ("true", 1, 0, None, [], {}):
            invalid_exact(f"holder_binding 非布尔 {bad!r} -> 请求参数无效",
                          "请求参数无效", req(nine_proof, binding=bad),
                          headers=TV)

        # 4. 绑定模式字段集/持有者字段类型 -> 持有者绑定格式错误
        invalid_exact("绑定模式九字段证明 -> 持有者绑定格式错误",
                      "持有者绑定格式错误", req(nine_proof), headers=TV)
        for key in HOLDER_KEYS:
            p = json.loads(json.dumps(good))
            p.pop(key)
            invalid_exact(f"绑定缺 {key} -> 持有者绑定格式错误",
                          "持有者绑定格式错误", req(p), headers=TV)
        p = json.loads(json.dumps(good))
        p["extra_field"] = 1
        invalid_exact("绑定含多余字段 -> 持有者绑定格式错误",
                      "持有者绑定格式错误", req(p), headers=TV)
        for field, bad_values in (
            ("holder_did", ("", 123, None, True)),
            ("holder_proof", ("", 123, None)),
            ("holder_key_version", (True, False, 0, -1, 1.5, "2", None)),
        ):
            for bad in bad_values:
                p = json.loads(json.dumps(good))
                p[field] = bad
                invalid_exact(
                    f"{field}={bad!r} -> 持有者绑定格式错误",
                    "持有者绑定格式错误", req(p), headers=TV)

        # 5. 绑定模式基础字段/谓词/挑战沿用既有校验
        p = json.loads(json.dumps(good))
        p["predicates"] = []
        p["results"] = []
        invalid_with_prefix("绑定 predicates 空数组沿用既有原因", "证明",
                            req(p), headers=TV)
        p = json.loads(json.dumps(good))
        p["predicates"] = [{"path": "/a", "op": "contains"}]
        invalid_with_prefix("绑定 op 非法沿用既有原因", "证明 predicates",
                            req(p), headers=TV)
        p = json.loads(json.dumps(good))
        p["issuer_key_version"] = 0
        invalid_with_prefix("绑定 issuer_key_version 非法沿用既有原因",
                            "证明", req(p), headers=TV)
        invalid_with_prefix("绑定挑战不匹配", "挑战",
                            req(good, challenge="chal-2"), headers=TV)

        # 6. 持有者锚点不可用：缺失/吊销/用途不符
        unknown_holder = sign_bound(
            make_bound(holder="did:web:hb-proof-unknown.example"),
            iss_priv, hold_priv)
        invalid_exact("持有者锚点缺失 -> 持有者锚点不可用",
                      "持有者锚点不可用", req(unknown_holder), headers=TV)
        revoked_holder = "did:web:hb-proof-holder-revoked.example"
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": revoked_holder, "public_key": hold_pub,
                       "key_version": 1}, headers=TV)
        check("注册待吊销持有者锚点 -> 201", st == 201)
        st, _ = _http(
            "PUT", f"{BASE}/v1/trust/anchors/{revoked_holder}/1/status",
            {"status": "revoked"}, headers=TV)
        check("吊销持有者锚点 -> 200", st == 200)
        revoked_proof = sign_bound(make_bound(holder=revoked_holder),
                                   iss_priv, hold_priv)
        invalid_exact("持有者锚点已吊销 -> 持有者锚点不可用",
                      "持有者锚点不可用", req(revoked_proof), headers=TV)
        # 用途不符：登记 uses 不含 proof 的持有者锚点版本
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": HOLDER_DID, "public_key": hold_pub,
                       "key_version": 2, "uses": ["vc"]}, headers=TV)
        check("注册无 proof 用途的持有者锚点 v2 -> 201", st == 201)
        wrong_use = sign_bound(make_bound(holder_version=2),
                               iss_priv, hold_priv)
        invalid_exact("持有者锚点用途不符 -> 持有者锚点不可用",
                      "持有者锚点不可用", req(wrong_use), headers=TV)

        # 7. 持有者签名：编码错误/验签失败
        p = json.loads(json.dumps(good))
        p["holder_proof"] = "!!!not-b64!!!"
        invalid_exact("holder_proof 编码非法 -> 持有者签名格式错误",
                      "持有者签名格式错误", req(p), headers=TV)
        p = json.loads(json.dumps(good))
        p["holder_proof"] = good["holder_proof"][:-2]
        invalid_exact("holder_proof 长度不足 -> 持有者签名格式错误",
                      "持有者签名格式错误", req(p), headers=TV)
        wrong_key = sign_bound(make_bound(), iss_priv, other_priv)
        invalid_exact("错误持有者私钥签名 -> 持有者签名校验失败",
                      "持有者签名校验失败", req(wrong_key), headers=TV)
        # 篡改 holder_did 为另一已登记 active 持有者：锚点命中但签名不符
        holder2 = "did:web:hb-proof-holder2.example"
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": holder2, "public_key": other_pub,
                       "key_version": 1}, headers=TV)
        check("注册第二持有者锚点 -> 201", st == 201)
        p = json.loads(json.dumps(good))
        p["holder_did"] = holder2
        invalid_exact("篡改 holder_did -> 持有者签名校验失败",
                      "持有者签名校验失败", req(p), headers=TV)
        p = json.loads(json.dumps(good))
        p["holder_key_version"] = 2
        invalid_exact("篡改 holder_key_version -> 持有者锚点不可用",
                      "持有者锚点不可用", req(p), headers=TV)

        # 8. 签发者签名覆盖不含 holder_*：篡改基础字段仍签发者验签失败
        p = json.loads(json.dumps(good))
        p["credential_id"] = "vc_other"
        invalid_with_prefix("篡改 credential_id -> 签发者签名校验失败",
                            "签名校验失败", req(p), headers=TV)
        # issuer 签名若把 holder_* 纳入覆盖范围则无法通过
        p = make_bound()
        msg = {k: v for k, v in p.items() if k != "proof"}
        msg["tenant_id"] = SOURCE
        p["proof"] = crypto.sign(msg, iss_priv)  # 错误地覆盖 holder_*
        holder_msg = {k: v for k, v in p.items()
                      if k not in ("proof", "holder_proof")}
        holder_msg["tenant_id"] = SOURCE
        p["holder_proof"] = crypto.sign(holder_msg, hold_priv)
        invalid_with_prefix("issuer 签名误覆盖 holder_* -> 签名校验失败",
                            "签名校验失败", req(p), headers=TV)

        # 9. 判定顺序：持有者锚点先于期限；期限先于停用
        expired = sign_bound(
            make_bound(expires_at="2020-01-01T00:00:00Z",
                       holder="did:web:hb-proof-unknown.example"),
            iss_priv, hold_priv)
        invalid_exact("持有者锚点缺失优先于过期",
                      "持有者锚点不可用", req(expired), headers=TV)
        expired = sign_bound(
            make_bound(expires_at="2020-01-01T00:00:00Z"),
            iss_priv, hold_priv)
        invalid_exact("绑定证明过期 -> 证明已过期",
                      "证明已过期", req(expired), headers=TV)

        # 10. 外部 DID 停用：先签发者后持有者
        def sync_deactivation(did, version, priv, reason, headers):
            body = {"did": did, "key_version": version, "reason": reason,
                    "deactivated_at": "2026-01-01T00:00:00Z"}
            return _http("POST", f"{BASE}/v1/trust/dids/deactivate-sync",
                         {"body": body,
                          "signature": crypto.sign(body, priv)},
                         headers=headers)

        st, r = sync_deactivation(HOLDER_DID, 1, hold_priv, "持有者密钥泄露",
                                  TV)
        check("同步持有者停用通告 -> 201", st == 201)
        invalid_exact("持有者停用 -> 外部持有者DID已停用",
                      "外部持有者DID已停用：持有者密钥泄露",
                      req(good), headers=TV)
        st, r = sync_deactivation(ISSUER_DID, 1, iss_priv, "签发者违规", TV)
        check("同步签发者停用通告 -> 201", st == 201)
        invalid_exact("签发者停用优先于持有者停用",
                      "外部签发DID已停用：签发者违规",
                      req(good), headers=TV)
        # 仅他租户有通告不影响本租户结论
        st, r = verify(req(good), headers=TO)
        check("他租户无锚点 -> 锚点原因而非停用",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))

        # 11. 批量：逐项接受两种形态，失败不短路（全新租户，无停用通告）
        TVB = {"X-Tenant-ID": "tpvhb-vb"}
        for did, pub in ((ISSUER_DID, iss_pub), (HOLDER_DID, hold_pub)):
            st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                          {"did": did, "public_key": pub, "key_version": 1},
                          headers=TVB)
            check("批量租户登记锚点 -> 201", st == 201)
        batch_payload = {
            "proofs": [
                req(good),                       # 绑定成功
                req(nine_proof, binding=_DELETE),  # 未绑定成功
                req(nine_proof, binding="yes"),  # 非布尔
                req(unknown_holder),             # 持有者锚点不可用
                req(good, binding=False),        # 未绑定出现 holder_*
            ]
        }
        st, r = _http("POST", f"{BASE}{VERIFY_BATCH}", batch_payload,
                      headers=TO)  # TO 无锚点：首项应锚点失败
        check("批量他租户逐项独立判定",
              st == 200 and len(r.get("results", [])) == 5
              and r["results"][2] == {"valid": False, "reason": "请求参数无效"})
        st, r = _http("POST", f"{BASE}{VERIFY_BATCH}", batch_payload,
                      headers=TVB)
        results = r.get("results")
        check("批量响应仅含 results 且长度一致",
              st == 200 and set(r) == {"results"} and len(results) == 5)
        check("批量绑定项成功", results[0] == {"valid": True})
        check("批量未绑定项成功", results[1] == {"valid": True})
        check("批量非布尔 holder_binding 项",
              results[2] == {"valid": False, "reason": "请求参数无效"})
        check("批量持有者锚点不可用项",
              results[3] == {"valid": False, "reason": "持有者锚点不可用"})
        check("批量未绑定 holder_* 多余字段项",
              results[4].get("valid") is False
              and results[4].get("reason", "").startswith("证明含多余字段"))
        # 外层协议不变
        st, r = _http("POST", f"{BASE}{VERIFY_BATCH}", {"proofs": []},
                      headers=TV)
        check("批量空数组仍按请求级失败",
              st == 200 and r.get("results") == []
              and isinstance(r.get("reason"), str) and r["reason"])
        st, r = _http("POST", f"{BASE}{VERIFY_BATCH}",
                      {"proofs": [req(good)], "extra": 1}, headers=TV)
        check("批量多余外层字段仍按请求级失败",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求"))

        # 12. 只读：重复验真不消费、不记审计
        st, before = _http("GET", f"{BASE}/v1/audit?limit=200", headers=TV)
        n_before = len(before["events"])
        for _ in range(3):
            st, r = verify(req(good), headers=TV)
            assert st == 200
        st, after = _http("GET", f"{BASE}/v1/audit?limit=200", headers=TV)
        check("重复验真不记审计", len(after["events"]) == n_before)
        check("重复验真不消费（停用后返回停用原因而非已消费）",
              r.get("reason", "").startswith("外部签发DID已停用"))

        # 13. 消费与状态合并接口不接受 holder_binding（保持原行为）
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/consume",
                      req(nine_proof, binding=False), headers=TV)
        check("consume 出现 holder_binding -> 多余字段",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求含多余字段"))
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/verify-with-status",
                      req(nine_proof, binding=True), headers=TV)
        check("verify-with-status 出现 holder_binding -> 多余字段",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求含多余字段"))

        # 14. 租户头：显式空 400；缺省 default 独立锚点空间
        st, _ = verify(req(good), headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)
        st, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ISSUER_DID, "public_key": iss_pub,
                       "key_version": 1})
        st2, _ = _http("POST", f"{BASE}/v1/trust/anchors",
                       {"did": HOLDER_DID, "public_key": hold_pub,
                        "key_version": 1})
        check("default 租户注册双锚点 -> 201", st == 201 and st2 == 201)
        st, r = verify(req(good))
        check("缺省租户头按 default 验真成功",
              st == 200 and r == {"valid": True})

        # 15. 真实 prove 绑定证明跨系统验真
        TS = {"X-Tenant-ID": "tpvhb-source"}
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "hb-issuer"},
                      headers=TS)
        check("来源租户注册签发者 DID -> 201", st == 201)
        src_issuer = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "hb-subject"},
                      headers=TS)
        src_subject = r["did"]
        check("来源租户注册持有者 DID -> 201", st == 201)
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": src_issuer, "subject_did": src_subject,
                       "claims": {"age": 30, "name": "Alice"}}, headers=TS)
        check("来源租户签发凭证 -> 201", st == 201)
        cred = r["credential_id"]
        st, r = _http("POST", f"{BASE}/v1/credentials/{cred}/prove",
                      {"predicates": PREDS, "challenge": "e2e-chal",
                       "holder_binding": True}, headers=TS)
        check("prove holder_binding=true -> 201", st == 201)
        check("prove 响应恰为十二字段",
              set(r) == set(NINE) | set(HOLDER_KEYS))
        bound_proof = r
        # 验证租户经 DID 文档登记双方锚点
        TV2 = {"X-Tenant-ID": "tpvhb-v2"}
        for did in (src_issuer, src_subject):
            st, doc = _http("GET", f"{BASE}/v1/dids/{did}/document",
                            headers=TS)
            check("读取来源 DID 文档 -> 200", st == 200)
            for vm in doc["verification_methods"]:
                st, _ = _http(
                    "POST", f"{BASE}/v1/trust/anchors",
                    {"did": did, "public_key": vm["public_key"],
                     "key_version": vm["key_version"]}, headers=TV2)
                check("登记外部锚点 -> 201", st == 201)
        st, r = verify({"proof": bound_proof, "challenge": "e2e-chal",
                        "source_tenant_id": "tpvhb-source",
                        "holder_binding": True}, headers=TV2)
        check("真实绑定证明跨系统验真 valid:true",
              st == 200 and r == {"valid": True})
        # 删掉绑定字段不能通过
        stripped = {k: v for k, v in bound_proof.items()
                    if not k.startswith("holder_")}
        invalid_exact("真实证明删掉 holder_* 后绑定模式失败",
                      "持有者绑定格式错误",
                      {"proof": stripped, "challenge": "e2e-chal",
                       "source_tenant_id": "tpvhb-source",
                       "holder_binding": True}, headers=TV2)
        # 未绑定 prove 证明沿用九字段协议
        st, r = _http("POST", f"{BASE}/v1/credentials/{cred}/prove",
                      {"predicates": PREDS, "challenge": "e2e-chal-2"},
                      headers=TS)
        check("prove 未绑定 -> 201 且恰为九字段",
              st == 201 and set(r) == set(NINE))
        st, r = verify({"proof": r, "challenge": "e2e-chal-2",
                        "source_tenant_id": "tpvhb-source"}, headers=TV2)
        check("真实未绑定证明跨系统验真 valid:true",
              st == 200 and r == {"valid": True})

        # 16. 直连 store：持有者锚点公钥不可用 -> 持有者锚点不可用
        from vcbackend.store import VCStore

        direct_path = tempfile.mktemp(suffix=".json")
        try:
            store = VCStore(direct_path)
            store.register_trust_anchor("t1", ISSUER_DID, iss_pub, 1)
            store.register_trust_anchor("t1", HOLDER_DID, hold_pub, 1)
            bucket = store._tenants["t1"]  # noqa: SLF001 测试直查内部状态
            bucket["trust_anchors"][HOLDER_DID]["1"]["public_key"] = "bad"
            valid, reason = store.verify_trust_proof(
                "t1", req(good), allow_holder_binding=True)
            check("直连: 持有者锚点公钥不可用 -> 持有者锚点不可用",
                  not valid and reason == "持有者锚点不可用")
            # 未开启开关时 holder_binding 按多余字段拒绝（其余入口不变）
            valid, reason = store.verify_trust_proof("t1", req(nine_proof))
            check("直连: 未开启开关 holder_binding 按多余字段失败",
                  not valid and reason.startswith("请求含多余字段"))
        finally:
            if os.path.exists(direct_path):
                os.unlink(direct_path)
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
