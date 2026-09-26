#!/usr/bin/env python3
"""POST /v1/trust/presentations/verify-synced-with-status 持有者绑定扩展测试。

直接运行：python3 tests/trust_presentation_verify_synced_with_status_holder_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 未绑定请求不变：恰含 signer_did/at/presentation/challenge，验真与
  状态合并行为同扩展前；
- 绑定请求协议：原四键外恰加非空字符串 source_tenant_id；空串/非
  字符串 400，多余第六键 400，缺键 400，均仅 {"error": 非空中文}；
  404/409 语义不变；
- 绑定演示恰为十二字段；holder_did/holder_key_version/holder_proof
  类型错误沿用字段分类原因；
- 双锚点均取 signer_did 来源 cursor<=at 的 (DID,版本) 末事件，须
  active 且 uses 含 vp：签发者不可用为“同步锚点不可用”，持有者
  不可用为“同步持有者锚点不可用”；
- issuer proof 覆盖去掉 proof 及 holder_* 的八字段；holder_proof
  覆盖去掉 proof、holder_proof 的对象并加入
  tenant_id=source_tenant_id；均为 ES256 64 字节裸 R||S 无填充
  base64url；持有者格式、验签失败恰为“持有者签名格式错误”
  “持有者签名校验失败”；
- 校验顺序：演示、挑战、签发锚点/格式/验签、持有者锚点/格式/验签、
  期限，较早错误优先；
- 通过后按请求初始原子快照查 (issuer_did, credential_id)：未同步/
  revoked/unknown/active 四种结论沿用 with-status 协议；成功仅
  {"valid":true}，失败键序 valid、reason；
- 纯只读：不推进检查点、不改同步视图、不记审计；重启一致；租户隔离。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
STATUS_SYNC_PATH = "/v1/trust/credential-status/sync"
VERIFY_PATH = "/v1/trust/presentations/verify-synced-with-status"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
CHALLENGE = "chal-bound-synced-status"
SOURCE_TENANT = "tenant-source"

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


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def make_bound_presentation(cred_id, issuer_did, holder_did, **overrides):
    pres = {
        "presentation_id": "vp-ext-bound-1",
        "credential_id": cred_id,
        "issuer_did": issuer_did,
        "issuer_key_version": 1,
        "disclose": ["/role"],
        "claims": {"role": "admin"},
        "challenge": CHALLENGE,
        "expires_at": "2999-01-01T00:00:00Z",
        "holder_did": holder_did,
        "holder_key_version": 1,
    }
    pres.update(overrides)
    return pres


def sign_bound_presentation(pres, issuer_priv, holder_priv,
                            source_tenant=SOURCE_TENANT):
    issuer_message = {
        k: v
        for k, v in pres.items()
        if k != "proof" and not k.startswith("holder_")
    }
    holder_message = {
        k: v for k, v in pres.items() if k not in ("proof", "holder_proof")
    }
    holder_message["tenant_id"] = source_tenant
    signed = dict(pres)
    signed["proof"] = crypto.sign(issuer_message, issuer_priv)
    signed["holder_proof"] = crypto.sign(holder_message, holder_priv)
    return signed


def test_http():
    port = 9217
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
    holder_did = "did:web:holder"
    holder_priv, holder_pub = gen_keypair()
    holder_priv2, holder_pub2 = gen_keypair()
    novp_holder_did = "did:web:novp-holder"

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

    def bound_payload(pres, at=3, signer=signer_did, challenge=CHALLENGE,
                      source=SOURCE_TENANT, issuer_priv=issuer_priv,
                      holder_priv=holder_priv):
        return {
            "signer_did": signer,
            "at": at,
            "presentation": sign_bound_presentation(
                pres, issuer_priv, holder_priv, source
            ),
            "challenge": challenge,
            "source_tenant_id": source,
        }

    def sync_status(cred_id, status, reason=None, headers=TA):
        sb = {
            "issuer_did": issuer_did,
            "credential_id": cred_id,
            "status": status,
            "updated_at": utc_z(timedelta(days=-1)),
            "issuer_key_version": 1,
        }
        if reason is not None:
            sb["reason"] = reason
        return _http("POST", base + STATUS_SYNC_PATH,
                     {"body": sb, "signature": crypto.sign(sb, issuer_priv)},
                     headers=headers)

    try:
        # 签名方锚点（sync 验真）与签发者锚点（status sync 验签），
        # tenant-a 与 tenant-b 均登记
        for headers in (TA, TB):
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": signer_pub,
                 "key_version": 1}, headers,
            )
            assert st in (200, 201), raw
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": issuer_did, "public_key": issuer_pub,
                 "key_version": 1}, headers,
            )
            assert st in (200, 201), raw

        # 同步锚点变更页：c1 issuer#1(active, 全用途)；
        # c2 holder#1(active, 全用途)；c3 novp-holder#1(无 vp)。
        # tenant-a 与 tenant-b 检查点均为 3；tenant-c 不同步。
        page1 = build_changes(
            [
                make_event(1, issuer_did, 1, pub=issuer_pub),
                make_event(2, holder_did, 1, pub=holder_pub),
                make_event(3, novp_holder_did, 1,
                           uses=["generic", "vc"], pub=holder_pub),
            ],
            0, signer_did, signer_priv,
        )
        for headers in (TA, TB):
            st, _ = _http("POST", base + SYNC_PATH, page1, headers=headers)
            assert st == 201

        # tenant-a 同步凭证状态；tenant-b 不同步（隔离验证）
        check("同步 active -> 201",
              sync_status("vp_active", "active")[0] == 201)
        check("同步 revoked 带原因 -> 201",
              sync_status("vp_rev", "revoked", reason="持证人违规")[0] == 201)
        check("同步 revoked 无原因 -> 201",
              sync_status("vp_rev_nr", "revoked")[0] == 201)
        check("同步 unknown -> 201",
              sync_status("vp_unk", "unknown")[0] == 201)

        good_pres = make_bound_presentation("vp_active", issuer_did,
                                            holder_did)

        # ---------------------------------------------------------- #
        # 1. 400 族：绑定请求协议
        # ---------------------------------------------------------- #
        expect_400("绑定 source_tenant_id 空串 400",
                   payload=bound_payload(good_pres, source=""))
        expect_400("绑定 source_tenant_id 非字符串 400",
                   payload=bound_payload(good_pres, source=1))
        six_keys = bound_payload(good_pres)
        six_keys["extra"] = 1
        expect_400("绑定多余第六键 400", payload=six_keys)
        missing_challenge = bound_payload(good_pres)
        del missing_challenge["challenge"]
        expect_400("绑定缺 challenge 400", payload=missing_challenge)
        missing_at = bound_payload(good_pres)
        del missing_at["at"]
        expect_400("绑定缺 at 400", payload=missing_at)
        bad_type = bound_payload(good_pres)
        bad_type["at"] = "3"
        expect_400("绑定 at 类型错误 400", payload=bad_type)
        st, raw = verify(payload=bound_payload(good_pres),
                         headers={"X-Tenant-ID": ""})
        expect_error("绑定显式空租户头 400", st, raw, 400)

        # ---------------------------------------------------------- #
        # 2. 404/409：绑定请求沿用请求级语义
        # ---------------------------------------------------------- #
        st, raw = verify(payload=bound_payload(good_pres,
                                               signer="did:web:nobody"))
        expect_error("绑定未知签名方 404", st, raw, 404)
        st, raw = verify(payload=bound_payload(good_pres), headers=TC)
        expect_error("绑定跨租户未同步 404", st, raw, 404)
        st, raw = verify(payload=bound_payload(good_pres, at=4))
        expect_error("绑定 at 超过检查点 409", st, raw, 409)

        # ---------------------------------------------------------- #
        # 3. 200：绑定演示十二字段与字段类型
        # ---------------------------------------------------------- #
        no_holder_proof = make_bound_presentation("vp_active", issuer_did,
                                                  holder_did)
        signed = sign_bound_presentation(no_holder_proof, issuer_priv,
                                         holder_priv)
        del signed["holder_proof"]
        expect_invalid(
            "绑定缺 holder_proof",
            {"signer_did": signer_did, "at": 3, "presentation": signed,
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            "演示缺少字段: holder_proof",
        )
        no_holder_did = make_bound_presentation("vp_active", issuer_did,
                                                holder_did)
        del no_holder_did["holder_did"]
        expect_invalid(
            "绑定缺 holder_did",
            bound_payload(no_holder_did),
            "演示缺少字段: holder_did",
        )
        expect_invalid(
            "绑定多余演示字段",
            bound_payload(make_bound_presentation(
                "vp_active", issuer_did, holder_did, foo=1)),
            "演示含多余字段: foo",
        )
        expect_invalid(
            "holder_did 空串",
            bound_payload(make_bound_presentation(
                "vp_active", issuer_did, "")),
            "演示字段 holder_did 必须为非空字符串",
        )
        expect_invalid(
            "holder_key_version 非正整数",
            bound_payload(make_bound_presentation(
                "vp_active", issuer_did, holder_did, holder_key_version=0)),
            "演示字段 holder_key_version 必须为正整数",
        )
        empty_hp = sign_bound_presentation(good_pres, issuer_priv,
                                           holder_priv)
        empty_hp["holder_proof"] = ""
        expect_invalid(
            "holder_proof 空串",
            {"signer_did": signer_did, "at": 3, "presentation": empty_hp,
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            "演示字段 holder_proof 必须为非空字符串",
        )
        expect_invalid(
            "绑定挑战不匹配",
            bound_payload(good_pres, challenge="other-challenge"),
            "挑战不匹配: 请求 challenge 与演示 challenge 不一致",
        )

        # ---------------------------------------------------------- #
        # 4. 200：双同步锚点
        # ---------------------------------------------------------- #
        expect_invalid(
            "绑定签发锚点不可用",
            bound_payload(make_bound_presentation(
                "vp_active", "did:web:unknown-issuer", holder_did)),
            "同步锚点不可用",
        )
        expect_invalid(
            "绑定持有者锚点未同步",
            bound_payload(make_bound_presentation(
                "vp_active", issuer_did, "did:web:unknown-holder")),
            "同步持有者锚点不可用",
        )
        expect_invalid(
            "绑定持有者锚点 uses 无 vp",
            bound_payload(make_bound_presentation(
                "vp_active", issuer_did, novp_holder_did)),
            "同步持有者锚点不可用",
        )
        # 签发锚点不可用优先于持有者锚点不可用
        expect_invalid(
            "签发锚点不可用优先于持有者锚点",
            bound_payload(make_bound_presentation(
                "vp_active", "did:web:unknown-issuer",
                "did:web:unknown-holder")),
            "同步锚点不可用",
        )

        # ---------------------------------------------------------- #
        # 5. 200：签名格式/验签，顺序为签发先于持有者
        # ---------------------------------------------------------- #
        bad_issuer_proof = sign_bound_presentation(good_pres, issuer_priv,
                                                   holder_priv)
        bad_issuer_proof["proof"] = "not-a-signature"
        expect_invalid(
            "绑定签发签名格式错误",
            {"signer_did": signer_did, "at": 3,
             "presentation": bad_issuer_proof, "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},
            "签名格式错误",
        )
        tampered_claims = sign_bound_presentation(good_pres, issuer_priv,
                                                  holder_priv)
        tampered_claims["claims"] = {"role": "root"}
        expect_invalid(
            "绑定演示被篡改签名校验失败",
            {"signer_did": signer_did, "at": 3,
             "presentation": tampered_claims, "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},
            "签名校验失败",
        )
        bad_holder_proof = sign_bound_presentation(good_pres, issuer_priv,
                                                   holder_priv)
        bad_holder_proof["holder_proof"] = "not-a-signature"
        expect_invalid(
            "持有者签名格式错误",
            {"signer_did": signer_did, "at": 3,
             "presentation": bad_holder_proof, "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},
            "持有者签名格式错误",
        )
        # 持有者锚点不可用优先于持有者签名格式错误
        bad_hp_no_anchor = sign_bound_presentation(
            make_bound_presentation("vp_active", issuer_did,
                                    "did:web:unknown-holder"),
            issuer_priv, holder_priv)
        bad_hp_no_anchor["holder_proof"] = "not-a-signature"
        expect_invalid(
            "持有者锚点不可用优先于格式错误",
            {"signer_did": signer_did, "at": 3,
             "presentation": bad_hp_no_anchor, "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},
            "同步持有者锚点不可用",
        )
        # 错误持有者密钥签名 -> 持有者签名校验失败
        expect_invalid(
            "错误持有者密钥签名校验失败",
            bound_payload(good_pres, holder_priv=holder_priv2),
            "持有者签名校验失败",
        )
        # tenant_id 被篡改（签名时用了别的来源租户）-> 持有者签名校验失败
        other_tenant_signed = sign_bound_presentation(
            good_pres, issuer_priv, holder_priv, "tenant-other")
        expect_invalid(
            "holder_proof 来源租户不匹配",
            {"signer_did": signer_did, "at": 3,
             "presentation": other_tenant_signed, "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},
            "持有者签名校验失败",
        )
        # 签发验签失败优先于持有者格式错误
        both_bad = sign_bound_presentation(good_pres, issuer_priv,
                                           holder_priv)
        both_bad["claims"] = {"role": "root"}
        both_bad["holder_proof"] = "not-a-signature"
        expect_invalid(
            "签发验签失败优先于持有者格式错误",
            {"signer_did": signer_did, "at": 3,
             "presentation": both_bad, "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},
            "签名校验失败",
        )
        expect_invalid(
            "绑定演示已过期",
            bound_payload(make_bound_presentation(
                "vp_active", issuer_did, holder_did,
                expires_at="2020-01-01T00:00:00Z")),
            "演示已过期",
        )

        # ---------------------------------------------------------- #
        # 6. 200：状态合并（四种结论）与成功形态
        # ---------------------------------------------------------- #
        expect_invalid(
            "绑定状态未同步",
            bound_payload(make_bound_presentation(
                "vp_nosync", issuer_did, holder_did)),
            "外部凭证状态未同步",
        )
        expect_invalid(
            "绑定状态 revoked 带原因",
            bound_payload(make_bound_presentation(
                "vp_rev", issuer_did, holder_did)),
            "外部凭证已吊销：持证人违规",
        )
        expect_invalid(
            "绑定状态 revoked 无原因",
            bound_payload(make_bound_presentation(
                "vp_rev_nr", issuer_did, holder_did)),
            "外部凭证已吊销：未知原因",
        )
        expect_invalid(
            "绑定状态 unknown",
            bound_payload(make_bound_presentation(
                "vp_unk", issuer_did, holder_did)),
            "外部凭证状态未知",
        )
        st, raw = verify(payload=bound_payload(good_pres))
        body = json.loads(raw)
        check("绑定 active 成功仅 valid:true",
              st == 200 and list(body.keys()) == ["valid"]
              and body["valid"] is True)
        # 验真失败优先于状态查询
        tampered_active = sign_bound_presentation(good_pres, issuer_priv,
                                                  holder_priv)
        tampered_active["claims"] = {"role": "root"}
        st, raw = verify(
            payload={"signer_did": signer_did, "at": 3,
                     "presentation": tampered_active, "challenge": CHALLENGE,
                     "source_tenant_id": SOURCE_TENANT})
        check("绑定验真失败不查状态",
              st == 200 and json.loads(raw) == {
                  "valid": False, "reason": "签名校验失败"})

        # tenant-b：锚点已同步但状态未同步 -> 外部凭证状态未同步
        st, raw = verify(payload=bound_payload(good_pres), headers=TB)
        check("tenant-b 状态隔离（未同步）",
              st == 200 and json.loads(raw) == {
                  "valid": False, "reason": "外部凭证状态未同步"})

        # ---------------------------------------------------------- #
        # 7. 未绑定请求不变：四键验真 + 状态合并
        # ---------------------------------------------------------- #
        unbound_pres = {
            "presentation_id": "vp-ext-1",
            "credential_id": "vp_active",
            "issuer_did": issuer_did,
            "issuer_key_version": 1,
            "disclose": ["/role"],
            "claims": {"role": "admin"},
            "challenge": CHALLENGE,
            "expires_at": "2999-01-01T00:00:00Z",
        }
        unbound_signed = dict(unbound_pres)
        unbound_signed["proof"] = crypto.sign(unbound_pres, issuer_priv)
        st, raw = verify(
            payload={"signer_did": signer_did, "at": 3,
                     "presentation": unbound_signed, "challenge": CHALLENGE})
        check("未绑定请求仍成功",
              st == 200 and json.loads(raw) == {"valid": True})
        # 未绑定请求出现 holder_* 字段仍失败
        holder_marked = dict(unbound_signed)
        holder_marked["holder_did"] = holder_did
        st, raw = verify(
            payload={"signer_did": signer_did, "at": 3,
                     "presentation": holder_marked, "challenge": CHALLENGE})
        check("未绑定 holder_* 禁令不变",
              st == 200 and json.loads(raw) == {
                  "valid": False,
                  "reason": "演示字段不合法: 不得包含持有者绑定字段 holder_did"})

        # ---------------------------------------------------------- #
        # 8. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=bound_payload(good_pres))
        verify(payload=bound_payload(good_pres, at=4))
        verify(payload=bound_payload(
            make_bound_presentation("vp_rev", issuer_did, holder_did)))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("绑定验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("绑定验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        st, raw = _http("POST", base + SYNC_PATH, page1, headers=TA)
        check("绑定验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 9. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(payload=bound_payload(good_pres))
        st, rev_before = verify(payload=bound_payload(
            make_bound_presentation("vp_rev", issuer_did, holder_did)))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=bound_payload(good_pres))
        check("重启后绑定成功响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=bound_payload(
            make_bound_presentation("vp_rev", issuer_did, holder_did)))
        check("重启后绑定吊销响应逐字节一致",
              st == 200 and raw == rev_before)
        st, raw = verify(payload=bound_payload(good_pres, at=4))
        expect_error("重启后绑定 at 超检查点仍 409", st, raw, 409)
        st, raw = verify(payload=bound_payload(good_pres), headers=TC)
        expect_error("重启后绑定跨租户仍 404", st, raw, 404)
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
