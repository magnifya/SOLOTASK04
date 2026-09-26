#!/usr/bin/env python3
"""POST /v1/trust/anchor-changes/sync 跨系统信任锚点变更流同步接收测试。

直接运行：python3 tests/trust_anchor_changes_sync_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400 族：请求体恰含 changes（对象）、after（非布尔非负整数），
  缺漏/多余字段、changes 非对象、after 为布尔/负数/小数/字符串/null
  均 400 且仅 {"error": 非空中文}；显式空租户头 400；
- 验真阶段完整复用 /verify：四类失败（变更流非法/锚点不可用/签名格式
  错误/签名校验失败）均 200 {"valid":false,"reason"} 且不写入；
- 检查点键 (租户, signer_did)：首个非空页须 after=0（201），续页须
  等于已存 next_after（200）；同 after 且 changes 字节相同为幂等重放
  （200、accepted=0、不推进）；旧页/跳页/同位异内容均 409 仅
  {"error":"同步游标冲突"}；
- 成功响应键序恰为 valid、signer_did、next_after、accepted，新页
  accepted 为 events 长度，重放或空页为 0；空页 200 不推进；
- 同步不记审计、不写本地变更流；租户隔离与缺省 default；重启后结论
  不变；GET 变更流与 /verify 入口不受影响。
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
SYNC_PATH = "/v1/trust/anchor-changes/sync"
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
    port = 9051
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

    def sync_post(payload, headers=None, raw_body=None):
        return _http("POST", base + SYNC_PATH, payload,
                     headers=headers, raw_body=raw_body)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        signer_did = "did:web:remote-signer"
        priv, pub = gen_keypair()
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        {"did": signer_did, "public_key": pub,
                         "key_version": 1}, TA)
        assert st in (200, 201), raw

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
        page1 = build([event(1), event(2)], after=0)

        def expect_400(name, payload=None, headers=None, raw_body=None):
            st, raw = sync_post(payload, headers=headers, raw_body=raw_body)
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
        expect_400("changes 为 null", {"changes": None, "after": 0})
        good_changes = page1["changes"]
        expect_400("after 为 true", {"changes": good_changes, "after": True})
        expect_400("after 为负数", {"changes": good_changes, "after": -1})
        expect_400("after 为小数", {"changes": good_changes, "after": 1.5})
        expect_400("after 为字符串", {"changes": good_changes, "after": "0"})
        expect_400("after 为 null", {"changes": good_changes, "after": None})
        expect_400("显式空租户头", page1, headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 验真四类失败：200 {valid:false,reason} 且不写入
        # ---------------------------------------------------------- #
        def expect_reason(name, payload, reason, headers=None):
            st, raw = sync_post(payload, headers=headers)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            check(name, st == 200 and body == {"valid": False,
                                               "reason": reason})

        malformed = copy.deepcopy(page1)
        malformed["changes"]["events"][0].pop("uses")
        expect_reason("变更流非法", malformed, "变更流非法", headers=TA)
        expect_reason("锚点不可用",
                      build([event(1)], after=0, did="did:web:nobody"),
                      "锚点不可用", headers=TA)
        bad_fmt = copy.deepcopy(page1)
        bad_fmt["changes"]["signature"] = "not-base64!!!"
        expect_reason("签名格式错误", bad_fmt, "签名格式错误", headers=TA)
        wrong_key = build([event(1), event(2)], after=0,
                          signer_priv=other_priv)
        expect_reason("签名校验失败", wrong_key, "签名校验失败", headers=TA)

        # 失败不写入：首个非空页 after=0 仍为 201
        st, raw = sync_post(page1, headers=TA)
        body = json.loads(raw)
        check("首个非空页 201 键序",
              st == 201 and list(body.keys()) == [
                  "valid", "signer_did", "next_after", "accepted"])
        check("首个非空页取值",
              body == {"valid": True, "signer_did": signer_did,
                       "next_after": 2, "accepted": 2})

        # ---------------------------------------------------------- #
        # 3. 幂等重放 / 同位异内容 / 旧页 / 跳页
        # ---------------------------------------------------------- #
        st, raw = sync_post(page1, headers=TA)
        body = json.loads(raw)
        check("幂等重放 200 accepted=0",
              st == 200 and body == {"valid": True,
                                     "signer_did": signer_did,
                                     "next_after": 2, "accepted": 0})

        # 同 after 同事件但重签（ECDSA 随机因子 -> 字节不同）为同位异内容
        resigned = build([event(1), event(2)], after=0)
        assert resigned["changes"]["signature"] != page1["changes"]["signature"]
        st, raw = sync_post(resigned, headers=TA)
        check("同位异内容（重签）409", st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # 同 after 不同事件
        altered = build([event(1), event(2, action="rotated")], after=0)
        st, raw = sync_post(altered, headers=TA)
        check("同位异内容（改事件）409", st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # 跳页：after 超过已存 next_after
        st, raw = sync_post(build([event(5)], after=4), headers=TA)
        check("跳页 409", st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # 续页推进
        page2 = build([event(3), event(4), event(5)], after=2)
        st, raw = sync_post(page2, headers=TA)
        body = json.loads(raw)
        check("续页 200 accepted=3",
              st == 200 and body == {"valid": True,
                                     "signer_did": signer_did,
                                     "next_after": 5, "accepted": 3})

        # 旧页：after 落后于已存末页 after（即使字节与首页相同也 409）
        st, raw = sync_post(page1, headers=TA)
        check("旧页 409", st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})
        # 末页仍可幂等重放
        st, raw = sync_post(page2, headers=TA)
        check("末页重放 200 accepted=0",
              st == 200 and json.loads(raw) == {
                  "valid": True, "signer_did": signer_did,
                  "next_after": 5, "accepted": 0})
        # 中间位置（after 介于末页 after 与 next_after 之间）409
        st, raw = sync_post(build([event(4), event(5)], after=3), headers=TA)
        check("页内位置 409", st == 409)

        # ---------------------------------------------------------- #
        # 4. 空页：200、accepted=0、不推进
        # ---------------------------------------------------------- #
        st, raw = sync_post(build([], after=5), headers=TA)
        check("空页 200 accepted=0",
              st == 200 and json.loads(raw) == {
                  "valid": True, "signer_did": signer_did,
                  "next_after": 5, "accepted": 0})
        # 空页不推进：续页仍须 after=5
        st, raw = sync_post(build([event(7)], after=6), headers=TA)
        check("空页不推进（跳页仍 409）", st == 409)
        page3 = build([event(6)], after=5)
        st, raw = sync_post(page3, headers=TA)
        check("空页后续页 200",
              st == 200 and json.loads(raw) == {
                  "valid": True, "signer_did": signer_did,
                  "next_after": 6, "accepted": 1})

        # ---------------------------------------------------------- #
        # 5. 不记审计、不写本地变更流
        # ---------------------------------------------------------- #
        def make_did(label, headers):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st in (200, 201), raw
            return json.loads(raw)["did"]

        local_signer = make_did("sync-local-signer", TA)

        def local_page():
            st, raw = _http("GET",
                            f"{base}{GET_PATH}?signer_did={local_signer}",
                            headers=TA)
            assert st == 200, raw
            page = json.loads(raw)
            page.pop("signature", None)
            return page

        page_before = local_page()
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw)["events"])
        sync_post(build([event(7)], after=6), headers=TA)
        sync_post(page3, headers=TA)
        sync_post(build([], after=7), headers=TA)
        check("同步不写本地变更流", local_page() == page_before)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("同步不记审计",
              len(json.loads(raw)["events"]) == audit_before)

        # ---------------------------------------------------------- #
        # 6. 租户隔离与缺省 default
        # ---------------------------------------------------------- #
        # 他租户无锚点：验真阶段即失败
        expect_reason("他租户锚点不可用", page1, "锚点不可用", headers=TB)
        priv_b, pub_b = gen_keypair()
        did_b = "did:web:signer-b"
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        {"did": did_b, "public_key": pub_b,
                         "key_version": 1}, TB)
        assert st in (200, 201), raw
        # B 租户独立检查点：首个非空页须 after=0
        st, raw = sync_post(
            build([event(4, did=did_b, public_key=pub_b)], after=3,
                  did=did_b, signer_priv=priv_b),
            headers=TB)
        check("B 租户首非空页 after!=0 409", st == 409)
        st, raw = sync_post(
            build([event(1, did=did_b, public_key=pub_b)], after=0,
                  did=did_b, signer_priv=priv_b),
            headers=TB)
        check("B 租户首非空页 201", st == 201
              and json.loads(raw)["accepted"] == 1)
        # A 租户检查点不受 B 影响
        page4 = build([event(8)], after=7)
        st, raw = sync_post(page4, headers=TA)
        check("A 租户续页不受 B 影响", st == 200)

        # 缺省 default 租户
        priv_d, pub_d = gen_keypair()
        did_d = "did:web:default-signer"
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        {"did": did_d, "public_key": pub_d,
                         "key_version": 1})
        assert st in (200, 201), raw
        st, raw = sync_post(
            build([event(1, did=did_d, public_key=pub_d)], after=0,
                  did=did_d, signer_priv=priv_d))
        check("缺省 default 租户首页 201", st == 201)

        # ---------------------------------------------------------- #
        # 7. 重启后结论不变
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = sync_post(page4, headers=TA)
        check("重启后末页重放 200 accepted=0",
              st == 200 and json.loads(raw) == {
                  "valid": True, "signer_did": signer_did,
                  "next_after": 8, "accepted": 0})
        st, raw = sync_post(build([event(10)], after=9), headers=TA)
        check("重启后跳页仍 409", st == 409)
        st, raw = sync_post(build([event(8, action="rotated")], after=7),
                            headers=TA)
        check("重启后同位异内容仍 409", st == 409)
        st, raw = sync_post(build([event(9)], after=8), headers=TA)
        check("重启后续页 200",
              st == 200 and json.loads(raw) == {
                  "valid": True, "signer_did": signer_did,
                  "next_after": 9, "accepted": 1})

        # ---------------------------------------------------------- #
        # 8. GET 变更流与 /verify 入口不受影响
        # ---------------------------------------------------------- #
        st, raw = _http("GET",
                        f"{base}{GET_PATH}?signer_did={local_signer}",
                        headers=TA)
        check("GET 变更流不受影响", st == 200
              and list(json.loads(raw).keys()) == [
                  "events", "next_after", "signer_did",
                  "signer_key_version", "signature"])
        st, raw = _http("POST", base + VERIFY_PATH, page1, headers=TA)
        check("verify 入口不受影响",
              st == 200 and json.loads(raw) == {"valid": True})
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
