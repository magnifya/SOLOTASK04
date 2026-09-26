#!/usr/bin/env python3
"""POST /v1/trust/proofs/verify-synced 以同步锚点验真外部谓词证明测试。

直接运行：python3 tests/trust_proof_verify_synced_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/proof/challenge/source_tenant_id（非空
  字符串、非布尔非负整数、对象、非空字符串、非空字符串）；空体、非法
  JSON、非对象、键集或类型错误均 400 且仅 {"error": 非空中文}；显式
  空租户头 400；
- 404/409：signer_did 未同步或跨租户 404 同形；at 超过检查点 409
  同形且优先于证明字段错误；
- 200 失败：证明九字段/谓词/results/challenge/expires_at 规则沿用
  /v1/trust/proofs/verify；同步锚点缺失/非 active/uses 无 proof 均为
  “同步锚点不可用”；签名格式错误/签名校验失败/证明已过期，较早错误
  优先；失败响应键序恰为 valid、reason；
- 成功仅 {"valid":true}；
- 纯只读：不推进检查点、不改同步页/锚点/证明/状态、不记审计；
  重启一致；租户隔离。
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

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
VERIFY_PATH = "/v1/trust/proofs/verify-synced"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
NO_PROOF_USES = ["generic", "vc", "vp", "did", "status", "deactivation"]
CHALLENGE = "chal-1"
SOURCE_TENANT = "source-tenant"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


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
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


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
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def make_event(cursor, did, key_version=1, action="registered",
               status="active", uses=None, pub="pem"):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": key_version,
        "public_key": pub,
        "status": status,
        "uses": list(uses if uses is not None else ALL_USES),
    }


def build_changes(events, after, did, signer_priv):
    signed = {
        "events": events,
        "next_after": events[-1]["cursor"] if events else after,
        "signer_did": did,
        "signer_key_version": 1,
    }
    signature = crypto.sign(signed, signer_priv)
    changes = dict(signed)
    changes["signature"] = signature
    return {"changes": changes, "after": after}


DEFAULT_PREDS = [
    {"path": "/age", "op": "gte", "value": 18},
    {"path": "/role", "op": "eq", "value": "admin"},
    {"path": "/name", "op": "exists"},
]


def make_proof(issuer_did, version=1, **overrides):
    p = {
        "proof_id": "zp_" + "a" * 32,
        "credential_id": "vc-ext-1",
        "issuer_did": issuer_did,
        "issuer_key_version": version,
        "predicates": DEFAULT_PREDS,
        "results": [True, True, True],
        "challenge": CHALLENGE,
        "expires_at": "2999-01-01T00:00:00Z",
    }
    p.update(overrides)
    return p


def sign_proof(p, priv, source=SOURCE_TENANT):
    message = {k: v for k, v in p.items() if k != "proof"}
    message["tenant_id"] = source
    signed = dict(p)
    signed["proof"] = crypto.sign(message, priv)
    return signed


def test_http():
    port = 9178
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

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
    TA = {"X-Tenant-ID": "tenant-a"}
    TB = {"X-Tenant-ID": "tenant-b"}
    TC = {"X-Tenant-ID": "tenant-c"}

    signer_did = "did:web:remote-signer"
    signer_priv, signer_pub = gen_keypair()
    issuer_did = "did:web:issuer"
    issuer_priv, issuer_pub = gen_keypair()
    issuer_priv2, issuer_pub2 = gen_keypair()

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers if headers is not None else TA,
                     raw=raw)

    def expect_error(name, st, raw, status):
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(
            name,
            st == status
            and isinstance(body, dict)
            and set(body) == {"error"}
            and isinstance(body["error"], str)
            and body["error"].strip() != "",
        )

    def expect_400(name, payload=None, headers=None, raw=None):
        st, resp = verify(payload=payload, headers=headers or TA, raw=raw)
        expect_error(name, st, resp, 400)

    def expect_invalid(name, payload, reason, headers=None):
        st, raw = verify(payload=payload, headers=headers or TA)
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(
            name,
            st == 200
            and isinstance(body, dict)
            and list(body.keys()) == ["valid", "reason"]
            and body["valid"] is False
            and body["reason"] == reason,
        )

    def signed_payload(p, priv, at, signer=signer_did,
                       challenge=CHALLENGE, source=SOURCE_TENANT):
        return {
            "signer_did": signer,
            "at": at,
            "proof": sign_proof(p, priv, source=source),
            "challenge": challenge,
            "source_tenant_id": source,
        }

    try:
        # 登记签名方锚点（两个租户），供 sync 验真通过
        for headers in (TA, TB):
            st, raw = _http(
                "POST",
                f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": signer_pub,
                 "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # 同步两页（tenant-a 检查点=4；tenant-b 仅首页，检查点=2）
        # c1: issuer#1 注册(active, 全用途)；c2: noproof#1 注册(无 proof)
        # c3: issuer#1 吊销；c4: issuer#2 轮换(active)
        page1 = build_changes(
            [
                make_event(1, issuer_did, 1, pub=issuer_pub),
                make_event(2, "did:web:noproof", 1,
                           uses=NO_PROOF_USES, pub=issuer_pub),
            ],
            0, signer_did, signer_priv,
        )
        page2 = build_changes(
            [
                make_event(3, issuer_did, 1, action="revoked",
                           status="revoked", pub=issuer_pub),
                make_event(4, issuer_did, 2, action="rotated",
                           pub=issuer_pub2),
            ],
            2, signer_did, signer_priv,
        )
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TA)
        assert st == 201
        st, _ = _http("POST", base + SYNC_PATH, page2, headers=TA)
        assert st == 200
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TB)
        assert st == 201

        good_proof = make_proof(issuer_did)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议
        # ---------------------------------------------------------- #
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("空体 400", raw=b"")
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "proof": {}, "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("缺 at 400",
                   payload={"signer_did": signer_did, "proof": {},
                            "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("缺 proof 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("缺 challenge 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("缺 source_tenant_id 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "challenge": CHALLENGE})
        expect_400("多余字段 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT, "extra": 1})
        expect_400("signer_did 空串 400",
                   payload={"signer_did": "", "at": 1, "proof": {},
                            "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("signer_did 非字符串 400",
                   payload={"signer_did": 1, "at": 1, "proof": {},
                            "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("at 布尔 400",
                   payload={"signer_did": signer_did, "at": True,
                            "proof": {}, "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("at 负数 400",
                   payload={"signer_did": signer_did, "at": -1,
                            "proof": {}, "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("at 字符串 400",
                   payload={"signer_did": signer_did, "at": "1",
                            "proof": {}, "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("at 小数 400",
                   payload={"signer_did": signer_did, "at": 1.5,
                            "proof": {}, "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("proof 非对象 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": [],
                            "challenge": CHALLENGE,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("challenge 空串 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "challenge": "",
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("challenge 非字符串 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "challenge": 1,
                            "source_tenant_id": SOURCE_TENANT})
        expect_400("source_tenant_id 空串 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "challenge": CHALLENGE, "source_tenant_id": ""})
        expect_400("source_tenant_id 非字符串 400",
                   payload={"signer_did": signer_did, "at": 1, "proof": {},
                            "challenge": CHALLENGE, "source_tenant_id": 1})
        expect_400("显式空租户头 400",
                   payload=signed_payload(good_proof, issuer_priv, 1),
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户
        # ---------------------------------------------------------- #
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 1,
                                                signer="did:web:nobody"),
                         headers=TA)
        expect_error("未知签名方 404", st, raw, 404)
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 1),
                         headers=TC)
        expect_error("跨租户未同步 404", st, raw, 404)

        # ---------------------------------------------------------- #
        # 3. 409：at 超过检查点（优先于证明字段错误）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 5),
                         headers=TA)
        expect_error("at 超过检查点 409", st, raw, 409)
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 3),
                         headers=TB)
        expect_error("tenant-b at 超过其检查点 409", st, raw, 409)
        st, raw = verify(
            payload={"signer_did": signer_did, "at": 5, "proof": {},
                     "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            headers=TA)
        expect_error("at 超检查点优先于证明字段错误 409", st, raw, 409)

        # ---------------------------------------------------------- #
        # 4. 200：证明字段与 challenge 沿用 verify 的分类原因
        # ---------------------------------------------------------- #
        no_pid = make_proof(issuer_did)
        del no_pid["proof_id"]
        expect_invalid("缺 proof_id",
                       signed_payload(no_pid, issuer_priv, 1),
                       "证明缺少字段: proof_id")
        expect_invalid(
            "多余证明字段",
            signed_payload(make_proof(issuer_did, foo=1), issuer_priv, 1),
            "证明含多余字段: foo",
        )
        expect_invalid(
            "proof_id 空串",
            signed_payload(make_proof(issuer_did, proof_id=""),
                           issuer_priv, 1),
            "证明字段 proof_id 必须为非空字符串",
        )
        expect_invalid(
            "issuer_key_version 非正整数",
            signed_payload(make_proof(issuer_did, issuer_key_version=0),
                           issuer_priv, 1),
            "证明字段 issuer_key_version 必须为正整数",
        )
        expect_invalid(
            "predicates 空数组",
            signed_payload(make_proof(issuer_did, predicates=[]),
                           issuer_priv, 1),
            "证明字段 predicates 必须为非空数组",
        )
        expect_invalid(
            "predicates 元素非对象",
            signed_payload(make_proof(issuer_did, predicates=[1]),
                           issuer_priv, 1),
            "证明 predicates 元素必须为 JSON 对象",
        )
        expect_invalid(
            "predicate op 非法",
            signed_payload(
                make_proof(
                    issuer_did,
                    predicates=[{"path": "/age", "op": "near", "value": 1}]),
                issuer_priv, 1),
            "证明 predicates 元素 op 非法: 'near'（仅支持 exists/eq/gte/lte）",
        )
        expect_invalid(
            "results 长度不符",
            signed_payload(make_proof(issuer_did, results=[True]),
                           issuer_priv, 1),
            "证明字段 results 必须为与 predicates 等长的数组",
        )
        expect_invalid(
            "results 含非布尔",
            signed_payload(make_proof(issuer_did, results=[True, 1, True]),
                           issuer_priv, 1),
            "证明字段 results 仅能包含布尔值",
        )
        empty_proof = sign_proof(good_proof, issuer_priv)
        empty_proof["proof"] = ""
        expect_invalid(
            "proof 空串",
            {"signer_did": signer_did, "at": 1, "proof": empty_proof,
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            "证明字段 proof 必须为非空字符串",
        )
        expect_invalid(
            "挑战不匹配",
            signed_payload(good_proof, issuer_priv, 1,
                           challenge="other-challenge"),
            "挑战不匹配: 请求 challenge 与证明 challenge 不一致",
        )

        # ---------------------------------------------------------- #
        # 5. 200：同步锚点不可用
        # ---------------------------------------------------------- #
        expect_invalid(
            "issuer 不在同步事件",
            signed_payload(make_proof("did:web:unknown"), issuer_priv, 1),
            "同步锚点不可用",
        )
        expect_invalid(
            "at 之前锚点尚未注册",
            signed_payload(make_proof(issuer_did, version=2),
                           issuer_priv2, 2),
            "同步锚点不可用",
        )
        expect_invalid(
            "末事件为吊销",
            signed_payload(make_proof(issuer_did), issuer_priv, 3),
            "同步锚点不可用",
        )
        expect_invalid(
            "uses 无 proof",
            signed_payload(make_proof("did:web:noproof"), issuer_priv, 2),
            "同步锚点不可用",
        )
        # tenant-b 仅同步首页：issuer#2 在其视图中不存在
        expect_invalid(
            "他租户视图无该版本",
            signed_payload(make_proof(issuer_did, version=2),
                           issuer_priv2, 2),
            "同步锚点不可用",
            headers=TB,
        )

        # ---------------------------------------------------------- #
        # 6. 200：签名格式错误 / 签名校验失败 / 证明已过期
        # ---------------------------------------------------------- #
        bad_proof = dict(sign_proof(good_proof, issuer_priv))
        bad_proof["proof"] = "not-a-signature"
        expect_invalid(
            "签名格式错误",
            {"signer_did": signer_did, "at": 1, "proof": bad_proof,
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            "签名格式错误",
        )
        tampered = dict(sign_proof(good_proof, issuer_priv))
        tampered["results"] = [False, True, True]
        expect_invalid(
            "证明被篡改签名校验失败",
            {"signer_did": signer_did, "at": 1, "proof": tampered,
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            "签名校验失败",
        )
        wrong_key = signed_payload(good_proof, issuer_priv2, 1)
        expect_invalid("错误密钥签名校验失败", wrong_key, "签名校验失败")
        wrong_scope = {
            "signer_did": signer_did,
            "at": 1,
            # 签名覆盖 tenant_id=other-tenant，请求却声明 source-tenant
            "proof": sign_proof(good_proof, issuer_priv,
                                source="other-tenant"),
            "challenge": CHALLENGE,
            "source_tenant_id": SOURCE_TENANT,
        }
        expect_invalid("tenant_id 作用域不符签名校验失败",
                       wrong_scope, "签名校验失败")
        expired = make_proof(issuer_did,
                             expires_at="2020-01-01T00:00:00Z")
        expect_invalid("证明已过期",
                       signed_payload(expired, issuer_priv, 1),
                       "证明已过期")
        bad_exp = make_proof(issuer_did,
                             expires_at="2020-01-01 00:00:00")
        expect_invalid(
            "expires_at 格式非法",
            signed_payload(bad_exp, issuer_priv, 1),
            "证明字段 expires_at 必须为 UTC 秒精度 Z 格式"
            "（YYYY-MM-DDTHH:MM:SSZ）",
        )
        # 较早错误优先：锚点不可用优先于签名格式错误
        bad_anchor_proof = dict(
            sign_proof(make_proof("did:web:unknown"), issuer_priv)
        )
        bad_anchor_proof["proof"] = "not-a-signature"
        expect_invalid(
            "锚点不可用优先于签名格式错误",
            {"signer_did": signer_did, "at": 1, "proof": bad_anchor_proof,
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            "同步锚点不可用",
        )

        # ---------------------------------------------------------- #
        # 7. 成功：仅 {"valid":true}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 1))
        body = json.loads(raw)
        check("v1 成功仅 valid:true",
              st == 200 and list(body.keys()) == ["valid"]
              and body["valid"] is True)
        st, raw = verify(
            payload=signed_payload(make_proof(issuer_did, version=2),
                                   issuer_priv2, 4))
        body = json.loads(raw)
        check("v2 成功",
              st == 200 and body == {"valid": True})
        # tenant-b 视图内 v1 仍 active（其检查点=2）
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 2),
                         headers=TB)
        check("tenant-b 视图内验真成功",
              st == 200 and json.loads(raw) == {"valid": True})
        # 缺省租户头：隔离于显式租户，未同步应 404
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 1),
                         headers={})
        expect_error("缺省租户与显式租户隔离 404", st, raw, 404)

        # ---------------------------------------------------------- #
        # 8. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=signed_payload(good_proof, issuer_priv, 1))
        verify(payload=signed_payload(good_proof, issuer_priv, 3))
        verify(payload=signed_payload(good_proof, issuer_priv, 5))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        # 检查点未推进：重放第二页仍 accepted=0
        st, raw = _http("POST", base + SYNC_PATH, page2, headers=TA)
        check("验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 9. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(
            payload=signed_payload(good_proof, issuer_priv, 1))
        st, na_before = verify(
            payload=signed_payload(good_proof, issuer_priv, 3))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 1))
        check("重启后成功响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 3))
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == na_before)
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 5),
                         headers=TA)
        expect_error("重启后 at 超检查点仍 409", st, raw, 409)
        st, raw = verify(payload=signed_payload(good_proof, issuer_priv, 1),
                         headers=TC)
        expect_error("重启后跨租户仍 404", st, raw, 404)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def main():
    test_http()
    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
