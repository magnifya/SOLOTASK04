#!/usr/bin/env python3
"""POST /v1/trust/credentials/verify-synced-batch 批量同步锚点验真测试。

直接运行：python3 tests/trust_credential_verify_synced_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/credentials（非空字符串、非布尔非负
  整数、1..100 项数组）；空体、非法 JSON、非对象、键集/类型错误、
  空数组或超限均 400 且仅 {"error":"请求非法"}；显式空租户头 400；
- 404/409：来源未同步或跨租户 404 仅 {"error":"同步来源不存在"}；
  at 超检查点 409 仅 {"error":"同步游标冲突"}；
- 200：仅 {"results":[...]}，逐项不短路、等长同序；项须恰含 body
  对象与非空 signature，否则 {"valid":false,"reason":"请求项非法"}；
  合法项沿用单条 verify-synced 规则（凭证字段、锚点、签名、有效期），
  成功项仅 {"valid":true}，失败项键序 valid、reason；
- 纯只读：不推进检查点、不改同步视图、不记审计；重启一致。
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
BATCH_PATH = "/v1/trust/credentials/verify-synced-batch"
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
    port = 9097
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
        return _http("POST", base + BATCH_PATH, payload,
                     headers=headers if headers is not None else TA,
                     raw=raw)

    def expect_exact(name, st, raw, status, expect):
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(name, st == status and body == expect)

    def expect_400(name, payload=None, headers=None, raw=None):
        st, resp = verify(payload=payload, headers=headers or TA, raw=raw)
        expect_exact(name, st, resp, 400, {"error": "请求非法"})

    def item(body, priv):
        return {"body": body, "signature": crypto.sign(body, priv)}

    def batch(items, at=4, signer=signer_did):
        return {"signer_did": signer, "at": at, "credentials": items}

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
        good_item = item(good_body, issuer_priv)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议，响应恰为 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        expect_400("空体 400", raw=b"")
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "credentials": [good_item]})
        expect_400("缺 at 400",
                   payload={"signer_did": signer_did,
                            "credentials": [good_item]})
        expect_400("缺 credentials 400",
                   payload={"signer_did": signer_did, "at": 1})
        expect_400("多余字段 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "credentials": [good_item], "extra": 1})
        expect_400("signer_did 空串 400",
                   payload=batch([good_item], signer=""))
        expect_400("signer_did 非字符串 400",
                   payload=batch([good_item], signer=1))
        expect_400("at 布尔 400",
                   payload={"signer_did": signer_did, "at": True,
                            "credentials": [good_item]})
        expect_400("at 负数 400",
                   payload=batch([good_item], at=-1))
        expect_400("at 字符串 400",
                   payload=batch([good_item], at="1"))
        expect_400("at 小数 400",
                   payload=batch([good_item], at=1.5))
        expect_400("credentials 非数组 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "credentials": good_item})
        expect_400("credentials 空数组 400", payload=batch([]))
        expect_400("credentials 超限 400",
                   payload=batch([good_item] * 101))
        st, raw = verify(payload=batch([good_item] * 100))
        check("credentials 恰 100 项合法",
              st == 200 and len(json.loads(raw)["results"]) == 100)
        st, raw = verify(payload=batch([good_item]),
                         headers={"X-Tenant-ID": ""})
        try:
            err_body = json.loads(raw.decode() or "{}")
        except ValueError:
            err_body = None
        check("显式空租户头 400",
              st == 400 and isinstance(err_body, dict)
              and set(err_body) == {"error"}
              and isinstance(err_body["error"], str)
              and err_body["error"].strip() != "")

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户，恰为 {"error":"同步来源不存在"}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=batch([good_item],
                                       signer="did:web:nobody"))
        expect_exact("未知签名方 404", st, raw, 404,
                     {"error": "同步来源不存在"})
        st, raw = verify(payload=batch([good_item]), headers=TC)
        expect_exact("跨租户未同步 404", st, raw, 404,
                     {"error": "同步来源不存在"})

        # ---------------------------------------------------------- #
        # 3. 409：at 超检查点，恰为 {"error":"同步游标冲突"}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=batch([good_item], at=5))
        expect_exact("at 超检查点 409", st, raw, 409,
                     {"error": "同步游标冲突"})
        st, raw = verify(payload=batch([good_item], at=3), headers=TB)
        expect_exact("tenant-b at 超其检查点 409", st, raw, 409,
                     {"error": "同步游标冲突"})

        # ---------------------------------------------------------- #
        # 4. 200：逐项不短路、等长同序
        # ---------------------------------------------------------- #
        no_claims = make_body(issuer_did)
        del no_claims["claims"]
        tampered = item(good_body, issuer_priv)
        tampered["body"] = dict(good_body, claims={"role": "root"})
        expired = make_body(issuer_did, expires_at="2020-01-01T00:00:00Z")
        items = [
            good_item,                                             # valid
            {"body": good_body},                                   # 项非法
            {"body": good_body, "signature": ""},                  # 项非法
            {"body": [], "signature": "x"},                        # 项非法
            {"body": good_body, "signature": "x", "extra": 1},     # 项非法
            "not-an-object",                                       # 项非法
            item(no_claims, issuer_priv),                          # 凭证字段
            item(make_body("did:web:unknown"), issuer_priv),       # 锚点
            item(make_body("did:web:novc"), issuer_priv),          # 锚点
            {"body": good_body, "signature": "not-a-signature"},   # 格式
            tampered,                                              # 验签
            item(expired, issuer_priv),                            # 过期
            item(make_body(issuer_did, issuer_key_version=2),
                 issuer_priv2),                                    # at=2 无 v2
        ]
        # at=2：issuer#1 active（c3 吊销未到）、issuer#2 尚未注册
        st, raw = verify(payload=batch(items, at=2))
        body = json.loads(raw)
        expect_results = [
            {"valid": True},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "凭证缺少字段: claims"},
            {"valid": False, "reason": "同步锚点不可用"},
            {"valid": False, "reason": "同步锚点不可用"},
            {"valid": False, "reason": "签名格式错误"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": False, "reason": "凭证已过期"},
            {"valid": False, "reason": "同步锚点不可用"},
        ]
        check("混合批量等长同序逐项结论",
              st == 200 and body == {"results": expect_results})
        # 失败项键序恰为 valid、reason；成功项仅 valid
        if st == 200:
            key_order_ok = all(
                list(r.keys()) == (["valid"] if r["valid"]
                                   else ["valid", "reason"])
                for r in body["results"]
            )
            check("结果项键序 valid[,reason]", key_order_ok)
        # at=4：issuer#2 已轮换为 active，v2 项验真成功
        st, raw = verify(payload=batch(
            [item(make_body(issuer_did, issuer_key_version=2),
                  issuer_priv2)], at=4))
        check("at=4 v2 项验真成功",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": True}]})

        # at 视图影响逐项结论：at=1 时 issuer#1 仍 active、#2 未注册
        st, raw = verify(payload=batch(
            [good_item,
             item(make_body(issuer_did, issuer_key_version=2),
                  issuer_priv2)], at=1))
        check("at=1 快照视图逐项结论",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": True},
                  {"valid": False, "reason": "同步锚点不可用"}]})
        # at=3 时 issuer#1 末事件为吊销
        st, raw = verify(payload=batch([good_item], at=3))
        check("at=3 末事件吊销锚点不可用",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": False, "reason": "同步锚点不可用"}]})
        # tenant-b 视图（检查点=2）：v1 仍 active
        st, raw = verify(payload=batch([good_item], at=2), headers=TB)
        check("tenant-b 视图内验真成功",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": True}]})
        # 缺省租户头按 default：未同步 404
        st, raw = _http("POST", base + BATCH_PATH, batch([good_item]))
        expect_exact("缺省租户未同步 404", st, raw, 404,
                     {"error": "同步来源不存在"})

        # ---------------------------------------------------------- #
        # 5. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=batch(items))
        verify(payload=batch([good_item], at=5))
        verify(payload=batch([good_item], signer="did:web:nobody"))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("批量验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("批量验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        st, raw = _http("POST", base + SYNC_PATH, page2, headers=TA)
        check("批量验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 6. 重启一致
        # ---------------------------------------------------------- #
        st, ok_raw = verify(payload=batch(items))
        st, na_raw = verify(payload=batch([good_item], at=3))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=batch(items))
        check("重启后混合批量响应逐字节一致",
              st == 200 and raw == ok_raw)
        st, raw = verify(payload=batch([good_item], at=3))
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == na_raw)
        st, raw = verify(payload=batch([good_item], at=5))
        expect_exact("重启后 at 超检查点仍 409", st, raw, 409,
                     {"error": "同步游标冲突"})
        st, raw = verify(payload=batch([good_item]), headers=TC)
        expect_exact("重启后跨租户仍 404", st, raw, 404,
                     {"error": "同步来源不存在"})
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
