#!/usr/bin/env python3
"""POST /v1/trust/credentials/verify-synced 以同步锚点验真外部凭证测试。

直接运行：python3 tests/trust_credential_verify_synced_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/body/signature，依次为非空字符串、
  非布尔非负整数、对象、非空字符串；非法 JSON、非对象、键集或类
  型错均 400 且仅 {"error": 非空中文}；显式空租户头 400；
- 404/409：signer_did 未同步或跨租户 404 同形；at 超过检查点 409
  同形；
- 凭证字段：沿用 /v1/trust/credentials/verify 的“凭证”分类原因；
- 同步锚点：取该来源 cursor<=at 的 (issuer_did,版本) 末事件，缺
  失、非 active 或 uses 无 vc 均 200 恰返
  {"valid": false, "reason": "同步锚点不可用"}；
- 签名：ES256 64 字节裸 R||S 无填充 base64url；格式错/验签错/到
  期分别返“签名格式错误”/“签名校验失败”/“凭证已过期”类原因；
  issuer_key_version 省略按 1 且不注入正文；成功仅 {"valid": true}；
- 只读：不改同步页、检查点、锚点、凭证、状态或审计；重启一致。
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
VERIFY_PATH = "/v1/trust/credentials/verify-synced"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    data = raw_body
    if data is None and payload is not None:
        data = json.dumps(payload).encode()
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


def make_body(issuer_did, cred_id="cred-1", key_version=None,
              expires=None, **overrides):
    body = {
        "credential_id": cred_id,
        "issuer_did": issuer_did,
        "subject_did": "did:web:subject",
        "claims": {"role": "dev"},
        "issued_at": "2026-01-01T00:00:00Z",
    }
    if key_version is not None:
        body["issuer_key_version"] = key_version
    if expires is not None:
        body["expires_at"] = expires
    body.update(overrides)
    return body


def test_http():
    port = 9052
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

    signer_did = "did:web:remote-signer"
    spriv, spub = gen_keypair()
    apriv1, apub1 = gen_keypair()   # issuer-a 版本 1
    apriv2, apub2 = gen_keypair()   # issuer-a 版本 2
    _, bpub = gen_keypair()         # issuer-b（uses 无 vc）

    ISSUER_A = "did:web:issuer-a"
    ISSUER_B = "did:web:issuer-b"

    def post_verify(payload, headers=None, raw_body=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers, raw_body=raw_body)

    def expect_error(name, status, payload=None, headers=None,
                     raw_body=None):
        st, raw = post_verify(payload, headers=headers, raw_body=raw_body)
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

    def expect_invalid(name, payload, reason=None, headers=TA):
        st, raw = post_verify(payload, headers=headers)
        body = json.loads(raw)
        ok = (
            st == 200
            and list(body.keys()) == ["valid", "reason"]
            and body["valid"] is False
            and isinstance(body["reason"], str)
            and body["reason"].strip() != ""
        )
        if reason is not None:
            ok = ok and body["reason"] == reason
        check(name, ok)
        return body

    def good_payload(at=4, body=None, sig="x"):
        return {
            "signer_did": signer_did,
            "at": at,
            "body": body if body is not None else make_body(ISSUER_A),
            "signature": sig,
        }

    try:
        # 登记签名方锚点（tenant-a / tenant-b），供 sync 验真通过
        for headers in (TA, TB):
            st, raw = _http(
                "POST",
                f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": spub, "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # ---------------------------------------------------------- #
        # 1. 400 族：请求体协议
        # ---------------------------------------------------------- #
        expect_error("非法 JSON 400", 400, raw_body=b"{not json",
                     headers=TA)
        expect_error("非对象 JSON 400", 400, raw_body=b"[1,2]",
                     headers=TA)
        expect_error("空体 400", 400, headers=TA)
        expect_error("缺 signer_did 400", 400,
                     {"at": 1, "body": {}, "signature": "x"}, headers=TA)
        expect_error("缺 at 400", 400,
                     {"signer_did": signer_did, "body": {},
                      "signature": "x"}, headers=TA)
        expect_error("缺 body 400", 400,
                     {"signer_did": signer_did, "at": 1,
                      "signature": "x"}, headers=TA)
        expect_error("缺 signature 400", 400,
                     {"signer_did": signer_did, "at": 1, "body": {}},
                     headers=TA)
        expect_error("多余字段 400", 400,
                     dict(good_payload(), extra=1), headers=TA)
        expect_error("signer_did 空串 400", 400,
                     dict(good_payload(), signer_did=""), headers=TA)
        expect_error("signer_did 非字符串 400", 400,
                     dict(good_payload(), signer_did=7), headers=TA)
        expect_error("at 布尔 400", 400,
                     dict(good_payload(), at=True), headers=TA)
        expect_error("at 负数 400", 400,
                     dict(good_payload(), at=-1), headers=TA)
        expect_error("at 小数 400", 400,
                     dict(good_payload(), at=1.5), headers=TA)
        expect_error("at 字符串 400", 400,
                     dict(good_payload(), at="4"), headers=TA)
        expect_error("body 非对象 400", 400,
                     dict(good_payload(), body="x"), headers=TA)
        expect_error("signature 空串 400", 400,
                     dict(good_payload(), sig=""), headers=TA)
        expect_error("signature 非字符串 400", 400,
                     dict(good_payload(), sig=64), headers=TA)
        expect_error("显式空租户头 400", 400, good_payload(),
                     headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户（同步前）
        # ---------------------------------------------------------- #
        expect_error("未同步签名方 404", 404, good_payload(), headers=TA)
        expect_error("未知签名方 404", 404,
                     dict(good_payload(), signer_did="did:web:nobody"),
                     headers=TA)
        expect_error("默认租户未同步 404", 404, good_payload())

        # ---------------------------------------------------------- #
        # 3. 同步两页（tenant-a）：检查点推进到 4
        #    c1: a#1 active 全用途；c2: b#1 active 但 uses 无 vc
        #    c3: a#1 吊销；c4: a#2 轮换 active
        # ---------------------------------------------------------- #
        page1 = build_changes(
            [
                make_event(1, ISSUER_A, 1, pub=apub1),
                make_event(2, ISSUER_B, 1, uses=["generic"], pub=bpub),
            ],
            0, signer_did, spriv,
        )
        page2 = build_changes(
            [
                make_event(3, ISSUER_A, 1, action="revoked",
                           status="revoked", pub=apub1),
                make_event(4, ISSUER_A, 2, action="rotated", pub=apub2),
            ],
            2, signer_did, spriv,
        )
        st, raw = _http("POST", base + SYNC_PATH, page1, headers=TA)
        assert st == 201, raw
        st, raw = _http("POST", base + SYNC_PATH, page2, headers=TA)
        assert st == 200, raw

        # 跨租户：tenant-b 已登记锚点但从未同步该来源
        expect_error("跨租户未同步 404", 404, good_payload(), headers=TB)

        # ---------------------------------------------------------- #
        # 4. 409：at 超过检查点（检查点=4）
        # ---------------------------------------------------------- #
        expect_error("at 超过检查点 409", 409, good_payload(at=5),
                     headers=TA)

        # ---------------------------------------------------------- #
        # 5. 凭证字段错误：沿用“凭证”分类原因（200 valid:false）
        # ---------------------------------------------------------- #
        body = make_body(ISSUER_A)
        del body["subject_did"]
        expect_invalid("凭证缺 subject_did",
                       good_payload(body=body),
                       "凭证缺少字段: subject_did")
        expect_invalid("claims 非对象",
                       good_payload(body=make_body(ISSUER_A, claims="x")),
                       "凭证字段 claims 必须为 JSON 对象")
        expect_invalid("issuer_key_version 为 0",
                       good_payload(
                           body=make_body(ISSUER_A, key_version=0)),
                       "凭证字段 issuer_key_version 必须为正整数")
        expect_invalid("issuer_key_version 布尔",
                       good_payload(
                           body=make_body(ISSUER_A, key_version=True)),
                       "凭证字段 issuer_key_version 必须为正整数")
        expect_invalid("issuer_did 空串",
                       good_payload(body=make_body("")),
                       "凭证字段 issuer_did 必须为非空字符串")

        # ---------------------------------------------------------- #
        # 6. 同步锚点不可用：缺失 / 非 active / uses 无 vc
        # ---------------------------------------------------------- #
        expect_invalid("未知 issuer 锚点不可用",
                       good_payload(body=make_body("did:web:ghost")),
                       "同步锚点不可用")
        expect_invalid("无此版本锚点不可用",
                       good_payload(
                           body=make_body(ISSUER_A, key_version=3)),
                       "同步锚点不可用")
        expect_invalid("uses 无 vc 锚点不可用",
                       good_payload(body=make_body(ISSUER_B)),
                       "同步锚点不可用")
        # at=4 时 a#1 末事件为吊销（c3）
        expect_invalid("末事件吊销锚点不可用",
                       good_payload(at=4, body=make_body(ISSUER_A)),
                       "同步锚点不可用")
        # at=0 尚无任何事件
        expect_invalid("at=0 无事件锚点不可用",
                       good_payload(at=0, body=make_body(ISSUER_A)),
                       "同步锚点不可用")
        # 恰返 {"valid": false, "reason": "同步锚点不可用"}（键序）
        st, raw = post_verify(good_payload(body=make_body("did:web:ghost")),
                              headers=TA)
        check("锚点不可用响应键序恰为 valid/reason",
              st == 200
              and list(json.loads(raw).keys()) == ["valid", "reason"])

        # ---------------------------------------------------------- #
        # 7. 签名格式 / 验签 / 到期
        # ---------------------------------------------------------- #
        # at=1：a#1 当时 active，可进入签名校验
        body_a1 = make_body(ISSUER_A)
        expect_invalid("签名格式错误",
                       good_payload(at=1, body=body_a1, sig="!!!"),
                       "签名格式错误: 不是合法的 ES256 签名编码")
        # 用版本 2 的私钥签版本 1 的正文 -> 验签失败
        wrong_sig = crypto.sign(body_a1, apriv2)
        expect_invalid("签名校验失败",
                       good_payload(at=1, body=body_a1, sig=wrong_sig),
                       "签名校验失败，凭证正文或签名可能被改动")
        # 到期
        expired_body = make_body(ISSUER_A, expires="2020-01-01T00:00:00Z")
        expired_sig = crypto.sign(expired_body, apriv1)
        expect_invalid("凭证已过期",
                       good_payload(at=1, body=expired_body,
                                    sig=expired_sig),
                       "凭证已过期")
        # expires_at 格式错（沿用“凭证”分类）
        bad_exp_body = make_body(ISSUER_A, expires="2020-01-01")
        bad_exp_sig = crypto.sign(bad_exp_body, apriv1)
        st, raw = post_verify(good_payload(at=1, body=bad_exp_body,
                                           sig=bad_exp_sig), headers=TA)
        body = json.loads(raw)
        check("expires_at 格式错沿用凭证分类原因",
              st == 200 and body["valid"] is False
              and body["reason"].startswith("凭证字段 expires_at"))

        # ---------------------------------------------------------- #
        # 8. 成功：仅 {"valid": true}
        # ---------------------------------------------------------- #
        # a#2（c4，active）：显式 issuer_key_version=2
        body_v2 = make_body(ISSUER_A, key_version=2)
        sig_v2 = crypto.sign(body_v2, apriv2)
        st, raw = post_verify(good_payload(at=4, body=body_v2,
                                           sig=sig_v2), headers=TA)
        check("a#2 验真成功仅返 valid:true",
              st == 200 and json.loads(raw) == {"valid": True}
              and list(json.loads(raw).keys()) == ["valid"])

        # a#1 在 at=1 时点 active：省略 issuer_key_version 按版本 1
        sig_v1 = crypto.sign(body_a1, apriv1)
        st, raw = post_verify(good_payload(at=1, body=body_a1,
                                           sig=sig_v1), headers=TA)
        check("省略 issuer_key_version 按版本 1 验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

        # 未来 expires_at 不影响到期判定
        future_body = make_body(ISSUER_A, key_version=2,
                                expires="2099-01-01T00:00:00Z")
        future_sig = crypto.sign(future_body, apriv2)
        st, raw = post_verify(good_payload(at=4, body=future_body,
                                           sig=future_sig), headers=TA)
        check("未到期凭证验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 9. 只读：不推进检查点、不记审计；重启一致
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=500", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))

        # 记录重启前响应字节
        st, raw_ok = post_verify(good_payload(at=4, body=body_v2,
                                              sig=sig_v2), headers=TA)
        assert st == 200
        st, raw_na = post_verify(
            good_payload(at=4, body=make_body(ISSUER_A)), headers=TA)
        assert st == 200

        # 重放同步页：检查点未被验真请求推进（仍按幂等重放处理）
        st, raw = _http("POST", base + SYNC_PATH, page2, headers=TA)
        body = json.loads(raw)
        check("验真后重放同步页仍 accepted=0（检查点未变）",
              st == 200 and body["accepted"] == 0
              and body["next_after"] == 4)

        st, raw = _http("GET", f"{base}/v1/audit?limit=500", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("验真不记审计", audit_after == audit_before)

        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = post_verify(good_payload(at=4, body=body_v2,
                                           sig=sig_v2), headers=TA)
        check("重启后成功响应逐字节一致", st == 200 and raw == raw_ok)
        st, raw = post_verify(
            good_payload(at=4, body=make_body(ISSUER_A)), headers=TA)
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == raw_na)
        expect_error("重启后 at 超过检查点仍 409", 409,
                     good_payload(at=5), headers=TA)
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
