#!/usr/bin/env python3
"""POST /v1/trust/credentials/verify-synced 以同步锚点验真外部凭证测试。

直接运行：python3 tests/trust_credential_verify_synced_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/body/signature（非空字符串、非布尔非负
  整数、对象、非空字符串）；非法 JSON、非对象、键集或类型错误均 400
  且仅 {"error": 非空中文}；显式空租户头 400；
- 404/409：signer_did 未同步或跨租户 404 同形；at 超过检查点 409 同形；
- 200 失败：凭证字段错误沿用“凭证”分类原因；同步锚点缺失/非 active/
  uses 无 vc 均为“同步锚点不可用”；签名格式错误/签名校验失败/凭证
  已过期；失败响应键序恰为 valid、reason；
- 成功仅 {"valid":true}；issuer_key_version 省略按 1 且不注入正文；
- 纯只读：不推进检查点、不改同步页/锚点/凭证/状态、不记审计；重启一致。
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
VERIFY_PATH = "/v1/trust/credentials/verify-synced"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]

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


def make_body(issuer_did, **overrides):
    body = {
        "credential_id": "vc-ext-1",
        "issuer_did": issuer_did,
        "subject_did": "did:web:holder",
        "claims": {"role": "admin"},
        "issued_at": "2026-01-01T00:00:00Z",
    }
    body.update(overrides)
    return body


def test_http():
    port = 9087
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

    def signed_payload(body, priv, at, signer=signer_did):
        return {
            "signer_did": signer,
            "at": at,
            "body": body,
            "signature": crypto.sign(body, priv),
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
        # c1: issuer#1 注册(active, 全用途)；c2: novc#1 注册(无 vc)
        # c3: issuer#1 吊销；c4: issuer#2 轮换(active)
        page1 = build_changes(
            [
                make_event(1, issuer_did, 1, pub=issuer_pub),
                make_event(2, "did:web:novc", 1,
                           uses=["generic"], pub=issuer_pub),
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

        good_body = make_body(issuer_did)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议
        # ---------------------------------------------------------- #
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("空体 400", raw=b"")
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "body": {}, "signature": "x"})
        expect_400("缺 at 400",
                   payload={"signer_did": signer_did, "body": {},
                            "signature": "x"})
        expect_400("缺 body 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "signature": "x"})
        expect_400("缺 signature 400",
                   payload={"signer_did": signer_did, "at": 1, "body": {}})
        expect_400("多余字段 400",
                   payload={"signer_did": signer_did, "at": 1, "body": {},
                            "signature": "x", "extra": 1})
        expect_400("signer_did 空串 400",
                   payload={"signer_did": "", "at": 1, "body": {},
                            "signature": "x"})
        expect_400("signer_did 非字符串 400",
                   payload={"signer_did": 1, "at": 1, "body": {},
                            "signature": "x"})
        expect_400("at 布尔 400",
                   payload={"signer_did": signer_did, "at": True,
                            "body": {}, "signature": "x"})
        expect_400("at 负数 400",
                   payload={"signer_did": signer_did, "at": -1,
                            "body": {}, "signature": "x"})
        expect_400("at 字符串 400",
                   payload={"signer_did": signer_did, "at": "1",
                            "body": {}, "signature": "x"})
        expect_400("at 小数 400",
                   payload={"signer_did": signer_did, "at": 1.5,
                            "body": {}, "signature": "x"})
        expect_400("body 非对象 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "body": [], "signature": "x"})
        expect_400("signature 空串 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "body": {}, "signature": ""})
        expect_400("signature 非字符串 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "body": {}, "signature": 1})
        expect_400("显式空租户头 400",
                   payload=signed_payload(good_body, issuer_priv, 1),
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户
        # ---------------------------------------------------------- #
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 1,
                                                signer="did:web:nobody"),
                         headers=TA)
        expect_error("未知签名方 404", st, raw, 404)
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 1),
                         headers=TC)
        expect_error("跨租户未同步 404", st, raw, 404)

        # ---------------------------------------------------------- #
        # 3. 409：at 超过检查点（优先于凭证字段错误）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 5),
                         headers=TA)
        expect_error("at 超过检查点 409", st, raw, 409)
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 3),
                         headers=TB)
        expect_error("tenant-b at 超过其检查点 409", st, raw, 409)
        st, raw = verify(payload=signed_payload({}, issuer_priv, 5),
                         headers=TA)
        expect_error("at 超检查点优先于字段错误 409", st, raw, 409)

        # ---------------------------------------------------------- #
        # 4. 200：凭证字段错误沿用“凭证”分类原因
        # ---------------------------------------------------------- #
        expect_invalid(
            "缺 credential_id",
            signed_payload(make_body(issuer_did, credential_id=""),
                           issuer_priv, 1),
            "凭证字段 credential_id 必须为非空字符串",
        )
        no_claims = make_body(issuer_did)
        del no_claims["claims"]
        expect_invalid("缺 claims",
                       signed_payload(no_claims, issuer_priv, 1),
                       "凭证缺少字段: claims")
        expect_invalid(
            "claims 非对象",
            signed_payload(make_body(issuer_did, claims=[]),
                           issuer_priv, 1),
            "凭证字段 claims 必须为 JSON 对象",
        )
        expect_invalid(
            "issuer_key_version 非正整数",
            signed_payload(make_body(issuer_did, issuer_key_version=0),
                           issuer_priv, 1),
            "凭证字段 issuer_key_version 必须为正整数",
        )

        # ---------------------------------------------------------- #
        # 5. 200：同步锚点不可用
        # ---------------------------------------------------------- #
        expect_invalid(
            "issuer 不在同步事件",
            signed_payload(make_body("did:web:unknown"), issuer_priv, 1),
            "同步锚点不可用",
        )
        expect_invalid(
            "at 之前锚点尚未注册",
            signed_payload(
                make_body(issuer_did, issuer_key_version=2),
                issuer_priv2, 2),
            "同步锚点不可用",
        )
        expect_invalid(
            "末事件为吊销",
            signed_payload(make_body(issuer_did), issuer_priv, 3),
            "同步锚点不可用",
        )
        expect_invalid(
            "uses 无 vc",
            signed_payload(make_body("did:web:novc"), issuer_priv, 2),
            "同步锚点不可用",
        )
        # tenant-b 仅同步首页：issuer#2 在其视图中不存在
        expect_invalid(
            "他租户视图无该版本",
            signed_payload(
                make_body(issuer_did, issuer_key_version=2),
                issuer_priv2, 2),
            "同步锚点不可用",
            headers=TB,
        )

        # ---------------------------------------------------------- #
        # 6. 200：签名格式错误 / 签名校验失败 / 凭证已过期
        # ---------------------------------------------------------- #
        expect_invalid(
            "签名格式错误",
            {"signer_did": signer_did, "at": 1, "body": good_body,
             "signature": "not-a-signature"},
            "签名格式错误",
        )
        tampered = dict(good_body)
        tampered["claims"] = {"role": "root"}
        payload = signed_payload(good_body, issuer_priv, 1)
        payload["body"] = tampered
        expect_invalid("正文被篡改签名校验失败", payload, "签名校验失败")
        wrong_key = signed_payload(good_body, issuer_priv2, 1)
        expect_invalid("错误密钥签名校验失败", wrong_key, "签名校验失败")
        expired = make_body(issuer_did, expires_at="2020-01-01T00:00:00Z")
        expect_invalid("凭证已过期",
                       signed_payload(expired, issuer_priv, 1),
                       "凭证已过期")
        bad_exp = make_body(issuer_did, expires_at="2020-01-01 00:00:00")
        expect_invalid(
            "expires_at 格式非法",
            signed_payload(bad_exp, issuer_priv, 1),
            "凭证字段 expires_at 必须为 UTC 秒精度 Z 格式"
            "（YYYY-MM-DDTHH:MM:SSZ）",
        )

        # ---------------------------------------------------------- #
        # 7. 成功：仅 {"valid":true}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 1))
        body = json.loads(raw)
        check("v1 省略 issuer_key_version 成功仅 valid:true",
              st == 200 and list(body.keys()) == ["valid"]
              and body["valid"] is True)
        st, raw = verify(
            payload=signed_payload(
                make_body(issuer_did, issuer_key_version=2),
                issuer_priv2, 4))
        body = json.loads(raw)
        check("v2 显式 issuer_key_version 成功",
              st == 200 and body == {"valid": True})
        future = make_body(issuer_did, expires_at="2999-01-01T00:00:00Z")
        st, raw = verify(payload=signed_payload(future, issuer_priv, 1))
        check("未到期 expires_at 成功",
              st == 200 and json.loads(raw) == {"valid": True})
        # tenant-b 视图内 v1 仍 active（其检查点=2）
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 2),
                         headers=TB)
        check("tenant-b 视图内验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 8. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=signed_payload(good_body, issuer_priv, 1))
        verify(payload=signed_payload(good_body, issuer_priv, 3))
        verify(payload=signed_payload(good_body, issuer_priv, 5))

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
            payload=signed_payload(good_body, issuer_priv, 1))
        st, na_before = verify(
            payload=signed_payload(good_body, issuer_priv, 3))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 1))
        check("重启后成功响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 3))
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == na_before)
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 5),
                         headers=TA)
        expect_error("重启后 at 超检查点仍 409", st, raw, 409)
        st, raw = verify(payload=signed_payload(good_body, issuer_priv, 1),
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
