#!/usr/bin/env python3
"""POST /v1/trust/anchor-changes/verify 跨系统锚点变更流只读验真测试。

直接运行：python3 tests/trust_anchor_changes_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求体须恰含 changes、after：非 JSON/非对象/缺键/多键、changes 非
  对象、after 布尔/负数/字符串/小数均 400 且仅 {"error":非空中文}；
  显式空租户头 400；
- 外层合法后失败均 HTTP 200 且键序恰为 valid,reason：
  变更流非法（键集/事件协议/events 超 200/cursor 非严格递增或不大于
  after/next_after 不一致）-> 锚点不可用（未知/他租户/吊销/无
  generic 用途）-> 签名格式错误 -> 签名校验失败；
- 成功仅 {"valid":true}（含空页 next_after=after 形态）；
- 纯只读（不记审计、游标不变）、租户隔离、重启后结论稳定。
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

CHANGES_PATH = "/v1/trust/anchor-changes"
VERIFY_PATH = "/v1/trust/anchor-changes/verify"
EVENT_KEYS = [
    "cursor", "action", "did", "key_version",
    "public_key", "status", "uses",
]


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


def gen_pub_pem():
    priv = crypto.generate_private_key_pem()
    return crypto.public_key_pem_from_private(priv)


def main():
    port = 9032
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

    def verify_post(payload=None, headers=None, raw_body=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers, raw_body=raw_body)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def make_did(label, headers):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st in (200, 201), raw
            body = json.loads(raw)
            return body["did"], body["public_key"]

        def add_anchor(did, pub, version, headers, uses=None):
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors",
                            payload, headers)
            assert st in (200, 201), raw
            return json.loads(raw)

        signer_did, signer_pub = make_did("changes-verify-signer", TA)
        # 签名 DID 的 active 锚点（含 generic 用途）
        add_anchor(signer_did, signer_pub, 1, TA)
        # 制造更多变更事件
        pem_x = gen_pub_pem()
        add_anchor("did:web:other-anchor", pem_x, 1, TA, uses=["vc", "vp"])

        def fetch_changes(after=None, headers=TA):
            qs = f"signer_did={signer_did}"
            if after is not None:
                qs += f"&after={after}"
            st, raw = _http("GET", f"{base}{CHANGES_PATH}?{qs}",
                            headers=headers)
            assert st == 200, raw
            return json.loads(raw)

        good = fetch_changes()
        assert good["events"], "前置：变更流应有事件"

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, payload=None, headers=TA, raw_body=None):
            st, raw = verify_post(payload, headers=headers,
                                  raw_body=raw_body)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("空请求体", raw_body=b"")
        expect_400("非法 JSON", raw_body=b"{not json")
        expect_400("请求体非对象", raw_body=b"[1,2]")
        expect_400("缺 changes", {"after": 0})
        expect_400("缺 after", {"changes": good})
        expect_400("多余字段", {"changes": good, "after": 0, "x": 1})
        expect_400("changes 非对象", {"changes": [1], "after": 0})
        expect_400("changes 为 null", {"changes": None, "after": 0})
        expect_400("after 布尔", {"changes": good, "after": True})
        expect_400("after 负数", {"changes": good, "after": -1})
        expect_400("after 字符串", {"changes": good, "after": "0"})
        expect_400("after 小数", {"changes": good, "after": 1.5})
        st, _ = verify_post({"changes": good, "after": 0},
                            headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 变更流非法：200 + 键序 valid,reason
        # ---------------------------------------------------------- #
        def expect_invalid(name, changes, after=0, reason="变更流非法"):
            st, raw = verify_post({"changes": changes, "after": after},
                                  headers=TA)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"200 {reason}: {name}",
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        def mutated(**overrides):
            body = dict(good)
            body.update(overrides)
            return body

        expect_invalid("changes 缺键",
                       {k: v for k, v in good.items() if k != "events"})
        expect_invalid("changes 多键", mutated(extra=1))
        expect_invalid("events 非数组", mutated(events={}))
        too_many = [dict(ev) for ev in good["events"] for _ in range(1)]
        while len(too_many) <= 200:
            too_many.extend(dict(ev) for ev in good["events"])
        expect_invalid("events 超 200 项",
                       mutated(events=too_many[:201],
                               next_after=too_many[200]["cursor"]))
        expect_invalid("事件缺键",
                       mutated(events=[{"cursor": 9}], next_after=9))
        bad_event = dict(good["events"][0])
        bad_event["extra"] = 1
        expect_invalid("事件多键",
                       mutated(events=[bad_event],
                               next_after=bad_event["cursor"]))
        for field, value in [
            ("cursor", 0), ("cursor", True), ("cursor", "1"),
            ("action", "unknown"), ("did", ""), ("did", 1),
            ("key_version", 0), ("key_version", False),
            ("public_key", ""), ("status", "unknown"),
            ("uses", []), ("uses", ["nope"]),
            ("uses", ["vc", "vc"]), ("uses", ["vc", "generic"]),
        ]:
            bad_event = dict(good["events"][0])
            bad_event[field] = value
            expect_invalid(f"事件字段 {field}={value!r}",
                           mutated(events=[bad_event],
                                   next_after=bad_event.get("cursor", 1)
                                   if isinstance(bad_event.get("cursor"),
                                                 int)
                                   else 1))
        # cursor 不严格递增
        two = [dict(good["events"][0]), dict(good["events"][0])]
        expect_invalid("cursor 重复非递增", mutated(events=two,
                                                    next_after=two[-1]
                                                    ["cursor"]))
        # cursor 不大于 after
        first_cursor = good["events"][0]["cursor"]
        expect_invalid("cursor 不大于 after",
                       good, after=first_cursor)
        # next_after 不等于末项 cursor
        expect_invalid("next_after 与末项不一致",
                       mutated(next_after=good["next_after"] + 1))
        # 空 events 时 next_after 须等于 after
        expect_invalid("空页 next_after 不等于 after",
                       mutated(events=[], next_after=1), after=0)
        expect_invalid("next_after 布尔",
                       mutated(next_after=True))
        expect_invalid("signer_did 空", mutated(signer_did=""))
        expect_invalid("signer_key_version 布尔",
                       mutated(signer_key_version=True))
        expect_invalid("signer_key_version 零",
                       mutated(signer_key_version=0))
        expect_invalid("signature 非字符串", mutated(signature=1))
        expect_invalid("signature 空串", mutated(signature=""))

        # ---------------------------------------------------------- #
        # 3. 锚点不可用
        # ---------------------------------------------------------- #
        expect_invalid("未知 signer_did",
                       mutated(signer_did="did:web:unknown"),
                       reason="锚点不可用")
        expect_invalid("未知签名版本",
                       mutated(signer_key_version=99),
                       reason="锚点不可用")
        # 他租户：同一 changes 在 tenant-b 无对应锚点
        st, raw = verify_post({"changes": good, "after": 0}, headers=TB)
        r = json.loads(raw)
        check("他租户锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        # 无 generic 用途的锚点
        add_anchor("did:web:vc-only", gen_pub_pem(), 1, TA, uses=["vc"])
        expect_invalid("锚点不含 generic 用途",
                       mutated(signer_did="did:web:vc-only",
                               signer_key_version=1),
                       reason="锚点不可用")
        # 已吊销锚点
        st, raw = _http("PUT",
                        f"{base}/v1/trust/anchors/did:web:vc-only/1/status",
                        {"status": "revoked"}, TA)
        assert st == 200, raw
        expect_invalid("锚点已吊销",
                       mutated(signer_did="did:web:vc-only",
                               signer_key_version=1),
                       reason="锚点不可用")

        # ---------------------------------------------------------- #
        # 4. 签名格式错误
        # ---------------------------------------------------------- #
        expect_invalid("签名非 86 字符", mutated(signature="abc"),
                       reason="签名格式错误")
        expect_invalid("签名含填充", mutated(signature="A" * 86 + "=="),
                       reason="签名格式错误")
        expect_invalid("签名含字母表外字符",
                       mutated(signature="!" + "A" * 85),
                       reason="签名格式错误")

        # ---------------------------------------------------------- #
        # 5. 签名校验失败
        # ---------------------------------------------------------- #
        other_priv = crypto.generate_private_key_pem()
        signed = {k: good[k] for k in
                  ("events", "next_after", "signer_did",
                   "signer_key_version")}
        wrong_sig = crypto.sign(signed, other_priv)
        expect_invalid("他钥签名", mutated(signature=wrong_sig),
                       reason="签名校验失败")
        tampered = mutated(events=[dict(ev) for ev in good["events"]])
        tampered["events"][0]["did"] = "did:web:tampered"
        tampered["next_after"] = tampered["events"][-1]["cursor"]
        expect_invalid("篡改事件后原签名", tampered,
                       reason="签名校验失败")

        # ---------------------------------------------------------- #
        # 6. 成功：仅 {"valid":true}（含空页形态）
        # ---------------------------------------------------------- #
        st, raw = verify_post({"changes": good, "after": 0}, headers=TA)
        r = json.loads(raw)
        check("验真成功仅 valid:true",
              st == 200 and list(r.keys()) == ["valid"]
              and r["valid"] is True)

        fresh = fetch_changes()
        empty_page = fetch_changes(after=fresh["next_after"])
        assert empty_page["events"] == []
        st, raw = verify_post({"changes": empty_page,
                               "after": fresh["next_after"]}, headers=TA)
        r = json.loads(raw)
        check("空页验真成功", st == 200 and r == {"valid": True})

        # ---------------------------------------------------------- #
        # 7. 纯只读：审计与游标不变
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_n = len(json.loads(raw)["events"])
        verify_post({"changes": good, "after": 0}, headers=TA)
        verify_post({"changes": mutated(signature="abc"), "after": 0},
                    headers=TA)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("验真不记审计",
              len(json.loads(raw)["events"]) == audit_n)
        check("验真不改变更流游标",
              fetch_changes()["next_after"] == fresh["next_after"])

        # ---------------------------------------------------------- #
        # 8. 重启后结论稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify_post({"changes": good, "after": 0}, headers=TA)
        r = json.loads(raw)
        check("重启后验真仍成功", st == 200 and r == {"valid": True})
        st, raw = verify_post({"changes": good, "after": 0}, headers=TB)
        r = json.loads(raw)
        check("重启后他租户仍锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
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
