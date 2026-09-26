#!/usr/bin/env python3
"""POST /v1/trust/anchor-changes/verify 跨系统信任锚点变更流只读验真测试。

直接运行：python3 tests/trust_anchor_changes_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400 族：请求体恰含 changes（对象）、after（非布尔非负整数），
  缺漏/多余字段、changes 非对象、after 为布尔/负数/小数/字符串/null
  均 400 且仅 {"error": 非空中文}；显式空租户头 400；
- 外层合法后任何失败均 HTTP 200，按键序恰返 valid:false、reason，
  原因依次为“变更流非法”（五键集、事件键/类型/动作/状态/用途、
  events 至多 200、cursor 严格递增且均大于 after、next_after 规则）、
  “锚点不可用”（未知/他租户/吊销/无 generic 用途）、“签名格式错误”、
  “签名校验失败”；成功仅 {"valid":true}；
- 不依赖本地事件：合成事件（snapshot 动作、cursor 与本地流无关、
  200 项）照样验真；纯只读：不写状态/游标、不记审计；
- 租户隔离与缺省 default；重启稳定；GET 变更流入口不受影响。
"""

import copy
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

GET_PATH = "/v1/trust/anchor-changes"
VERIFY_PATH = "/v1/trust/anchor-changes/verify"
RESP_KEYS = [
    "events", "next_after", "signer_did",
    "signer_key_version", "signature",
]
EVENT_KEYS = [
    "cursor", "action", "did", "key_version",
    "public_key", "status", "uses",
]
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
_UNSET = object()


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = json.dumps(payload).encode() if payload is not None else None
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


def main():
    port = 9041
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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify_post(payload, headers=None, raw_body=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers, raw_body=raw_body)

    def expect_reason(name, payload, reason, headers=None):
        st, raw = verify_post(payload, headers=headers)
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        check(name, st == 200 and body == {"valid": False, "reason": reason})

    def expect_valid(name, payload, headers=None):
        st, raw = verify_post(payload, headers=headers)
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        check(name, st == 200 and body == {"valid": True})

    def add_anchor(did, pub, version, headers, uses=None):
        payload = {"did": did, "public_key": pub, "key_version": version}
        if uses is not None:
            payload["uses"] = uses
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        payload, headers)
        assert st in (200, 201), raw
        return json.loads(raw)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # 远端签名者密钥对：仅把公钥注册为本租户锚点，验真不依赖
        # 本地 DID 或本地变更事件。
        signer_did = "did:web:remote-signer"
        priv, pub = gen_keypair()
        add_anchor(signer_did, pub, 1, TA)

        # 仅 vc 用途（无 generic）的活动锚点
        did_vc = "did:web:vc-only"
        priv_vc, pub_vc = gen_keypair()
        add_anchor(did_vc, pub_vc, 1, TA, uses=["vc"])

        # 已吊销锚点
        did_rev = "did:web:revoked-signer"
        priv_rev, pub_rev = gen_keypair()
        add_anchor(did_rev, pub_rev, 1, TA)
        st, raw = _http("PUT",
                        f"{base}/v1/trust/anchors/{did_rev}/1/status",
                        {"status": "revoked"}, TA)
        assert st == 200, raw

        other_priv, other_pub = gen_keypair()

        def event(cursor, did=signer_did, version=1, public_key=pub,
                  action="registered", status="active", uses=None):
            return {
                "cursor": cursor,
                "action": action,
                "did": did,
                "key_version": version,
                "public_key": public_key,
                "status": status,
                "uses": list(ALL_USES if uses is None else uses),
            }

        def build(events, after, did=signer_did, version=1,
                  signer_priv=priv, next_after=_UNSET):
            signed = {
                "events": events,
                "next_after": (
                    events[-1]["cursor"] if events else after
                ) if next_after is _UNSET else next_after,
                "signer_did": did,
                "signer_key_version": version,
            }
            signature = crypto.sign(signed, signer_priv)
            changes = dict(signed)
            changes["signature"] = signature
            return {"changes": changes, "after": after}

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        valid_body = build([event(10), event(11)], after=5)

        def expect_400(name, payload=None, headers=None, raw_body=None):
            st, raw = verify_post(payload, headers=headers,
                                  raw_body=raw_body)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"])
                  and any(ord(ch) > 127 for ch in r["error"]))

        expect_400("空体", raw_body=b"")
        expect_400("非对象", raw_body=b"[1,2]")
        expect_400("非法 JSON", raw_body=b"{")
        expect_400("两键皆缺", {})
        expect_400("缺 changes", {"after": 0})
        expect_400("缺 after", {"changes": {}})
        expect_400("多余字段", {"changes": {}, "after": 0, "x": 1})
        expect_400("changes 为数组", {"changes": [], "after": 0})
        expect_400("changes 为字符串", {"changes": "x", "after": 0})
        expect_400("changes 为 null", {"changes": None, "after": 0})
        expect_400("changes 为数字", {"changes": 1, "after": 0})
        good_changes = valid_body["changes"]
        expect_400("after 为 true", {"changes": good_changes, "after": True})
        expect_400("after 为 false", {"changes": good_changes, "after": False})
        expect_400("after 为负数", {"changes": good_changes, "after": -1})
        expect_400("after 为小数", {"changes": good_changes, "after": 1.5})
        expect_400("after 为字符串", {"changes": good_changes, "after": "0"})
        expect_400("after 为 null", {"changes": good_changes, "after": None})
        expect_400("after 为数组", {"changes": good_changes, "after": [0]})
        expect_400("显式空租户头", valid_body,
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 变更流非法（锚点存在且含 generic，排除后续阶段）
        # ---------------------------------------------------------- #
        def malformed(name, mutate):
            payload = copy.deepcopy(valid_body)
            mutate(payload["changes"])
            expect_reason(f"变更流非法：{name}", payload, "变更流非法",
                          headers=TA)

        malformed("changes 缺 signature 键",
                  lambda c: c.pop("signature"))
        malformed("changes 缺 events 键（且签名键顶替）",
                  lambda c: c.pop("events"))
        malformed("changes 多余键",
                  lambda c: c.update({"extra": 1}))

        def first_event(c):
            return c["events"][0]

        malformed("事件缺键",
                  lambda c: first_event(c).pop("uses"))
        malformed("事件多余键",
                  lambda c: first_event(c).update({"x": 1}))
        malformed("cursor 为字符串",
                  lambda c: first_event(c).__setitem__("cursor", "10"))
        malformed("cursor 为布尔",
                  lambda c: first_event(c).__setitem__("cursor", True))
        malformed("cursor 不大于 after",
                  lambda c: (first_event(c).__setitem__("cursor", 5),
                             c.__setitem__("next_after", 11)))
        malformed("cursor 非严格递增",
                  lambda c: (first_event(c).__setitem__("cursor", 11),
                             c.__setitem__("next_after", 11)))
        malformed("未知 action",
                  lambda c: first_event(c).__setitem__("action", "bogus"))
        malformed("did 为空",
                  lambda c: first_event(c).__setitem__("did", ""))
        malformed("key_version 为 0",
                  lambda c: first_event(c).__setitem__("key_version", 0))
        malformed("key_version 为布尔",
                  lambda c: first_event(c).__setitem__("key_version", True))
        malformed("public_key 为空",
                  lambda c: first_event(c).__setitem__("public_key", ""))
        malformed("status 非法",
                  lambda c: first_event(c).__setitem__("status", "pending"))
        malformed("uses 为空数组",
                  lambda c: first_event(c).__setitem__("uses", []))
        malformed("uses 含未知用途",
                  lambda c: first_event(c).__setitem__(
                      "uses", ["generic", "nope"]))
        malformed("uses 重复",
                  lambda c: first_event(c).__setitem__(
                      "uses", ["generic", "generic"]))
        malformed("uses 非规范序",
                  lambda c: first_event(c).__setitem__(
                      "uses", ["vc", "generic"]))
        malformed("uses 非数组",
                  lambda c: first_event(c).__setitem__("uses", "generic"))
        malformed("signer_key_version 为 0",
                  lambda c: c.__setitem__("signer_key_version", 0))
        malformed("signer_did 为空",
                  lambda c: c.__setitem__("signer_did", ""))
        malformed("signature 为空串",
                  lambda c: c.__setitem__("signature", ""))
        malformed("非空 next_after 不等于末项 cursor",
                  lambda c: c.__setitem__("next_after", 999))

        # 空事件流：next_after 必须等于 after
        empty_bad = build([], after=7, next_after=8)
        expect_reason("变更流非法：空流 next_after!=after",
                      empty_bad, "变更流非法", headers=TA)

        # events 超过 200 项（结构非法，先于其他阶段）
        big = build([event(cursor=i) for i in range(1, 202)], after=0)
        expect_reason("变更流非法：201 项事件", big, "变更流非法",
                      headers=TA)

        # ---------------------------------------------------------- #
        # 3. 锚点不可用
        # ---------------------------------------------------------- #
        expect_reason("未知签名 DID",
                      build([event(10)], after=5, did="did:web:nobody"),
                      "锚点不可用", headers=TA)
        expect_reason("他租户锚点",
                      build([event(10)], after=5),
                      "锚点不可用", headers=TB)
        expect_reason("锚点已吊销",
                      build([event(10, did=did_rev), event(11, did=did_rev)],
                            after=5, did=did_rev, signer_priv=priv_rev),
                      "锚点不可用", headers=TA)
        expect_reason("锚点无 generic 用途",
                      build([event(10, did=did_vc)], after=5,
                            did=did_vc, signer_priv=priv_vc),
                      "锚点不可用", headers=TA)

        # ---------------------------------------------------------- #
        # 4. 签名格式错误 / 5. 签名校验失败
        # ---------------------------------------------------------- #
        bad_fmt = copy.deepcopy(valid_body)
        bad_fmt["changes"]["signature"] = "not-base64!!!"
        expect_reason("签名格式错误：字母表外字符", bad_fmt,
                      "签名格式错误", headers=TA)
        bad_fmt["changes"]["signature"] = "A" * 87
        expect_reason("签名格式错误：长度 87", bad_fmt,
                      "签名格式错误", headers=TA)
        bad_fmt["changes"]["signature"] = "A" * 85 + "="
        expect_reason("签名格式错误：含填充", bad_fmt,
                      "签名格式错误", headers=TA)

        wrong_key = build([event(10), event(11)], after=5,
                          signer_priv=other_priv)
        expect_reason("签名校验失败：他钥签名", wrong_key,
                      "签名校验失败", headers=TA)
        tampered = copy.deepcopy(valid_body)
        tampered["changes"]["events"][0]["status"] = "revoked"
        expect_reason("签名校验失败：事件被篡改", tampered,
                      "签名校验失败", headers=TA)
        tampered_next = copy.deepcopy(valid_body)
        # 保持 next_after 合法（=末项 cursor），篡改末项 did 使结构仍合法
        tampered_next["changes"]["events"][1]["did"] = "did:web:other"
        expect_reason("签名校验失败：事件 did 被篡改",
                      tampered_next, "签名校验失败", headers=TA)

        # ---------------------------------------------------------- #
        # 6. 成功：空流、非空流、恰 200 项、合成事件
        # ---------------------------------------------------------- #
        st, raw = verify_post(valid_body, headers=TA)
        body = json.loads(raw)
        check("非空流验真成功键序", st == 200 and body == {"valid": True})

        expect_valid("空流验真成功（next_after=after）",
                     build([], after=7), headers=TA)

        exactly_200 = build(
            [event(cursor=i, action="snapshot", did="did:web:foreign",
                   public_key=other_pub) for i in range(500, 700)],
            after=499,
        )
        expect_valid("恰 200 项合成 snapshot 事件验真成功",
                     exactly_200, headers=TA)

        # 不依赖本地事件：事件 cursor/内容与本地变更流完全无关
        synthetic = build(
            [event(cursor=9001, action="uses.updated",
                   did="did:web:never-seen-locally", version=42,
                   public_key=other_pub, uses=["vc", "vp"])],
            after=9000,
        )
        expect_valid("与本地事件无关的合成事件验真成功",
                     synthetic, headers=TA)

        # after=0、cursor 从 1 起的最小流
        expect_valid("after=0 单事件", build([event(1)], after=0),
                     headers=TA)

        # ---------------------------------------------------------- #
        # 7. 纯只读：审计与本地变更流游标不变
        # ---------------------------------------------------------- #
        def make_did(label, headers):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st in (200, 201), raw
            return json.loads(raw)["did"]

        local_signer = make_did("local-signer", TA)

        def local_page():
            st, raw = _http("GET",
                            f"{base}{GET_PATH}?signer_did={local_signer}",
                            headers=TA)
            assert st == 200, raw
            page = json.loads(raw)
            page.pop("signature", None)  # ECDSA 每次签名带随机因子
            return page

        page_before = local_page()
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw)["events"])

        verify_post(valid_body, headers=TA)
        verify_post(build([], after=0), headers=TA)
        verify_post(bad_fmt, headers=TA)
        verify_post(wrong_key, headers=TA)
        verify_post(big, headers=TA)
        check("验真不写本地变更游标/事件", local_page() == page_before)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("验真不记审计",
              len(json.loads(raw)["events"]) == audit_before)

        # ---------------------------------------------------------- #
        # 8. 租户隔离与缺省 default
        # ---------------------------------------------------------- #
        default_priv, default_pub = gen_keypair()
        default_did = "did:web:default-signer"
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        {"did": default_did, "public_key": default_pub,
                         "key_version": 1})
        assert st in (200, 201), raw
        expect_valid("缺省租户 default 验真成功",
                     build([event(10, did=default_did,
                                  public_key=default_pub)], after=5,
                           did=default_did, signer_priv=default_priv))
        # 同 payload 在 tenant-a 中锚点不可用（隔离）
        expect_reason("default 锚点对 tenant-a 不可见",
                      build([event(10, did=default_did,
                                   public_key=default_pub)], after=5,
                            did=default_did, signer_priv=default_priv),
                      "锚点不可用", headers=TA)

        # ---------------------------------------------------------- #
        # 9. GET 变更流入口不受影响
        # ---------------------------------------------------------- #
        st, raw = _http("GET",
                        f"{base}{GET_PATH}?signer_did={local_signer}",
                        headers=TA)
        got = json.loads(raw)
        check("GET 变更流键序不变",
              st == 200 and list(got.keys()) == RESP_KEYS)

        # ---------------------------------------------------------- #
        # 10. 重启稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        expect_valid("重启后验真仍成功", valid_body, headers=TA)
        expect_reason("重启后吊销锚点仍不可用",
                      build([event(10, did=did_rev)], after=5,
                            did=did_rev, signer_priv=priv_rev),
                      "锚点不可用", headers=TA)
        expect_reason("重启后坏签名仍失败", bad_fmt, "签名格式错误",
                      headers=TA)
        check("重启后本地变更流不变", local_page() == page_before)
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
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
