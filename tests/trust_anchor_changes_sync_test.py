#!/usr/bin/env python3
"""POST /v1/trust/anchor-changes/sync 跨系统信任锚点变更流同步接收测试。

直接运行：python3 tests/trust_anchor_changes_sync_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400 族：请求体恰含 changes（对象）、after（非布尔非负整数），
  缺失/非法 JSON/非对象/键集或类型错误均 400 且仅 {"error": 非空中文}；
  显式空租户头 400；
- 完整复用 /verify 的四类失败响应（变更流非法 -> 锚点不可用 ->
  签名格式错误 -> 签名校验失败），失败不写入；
- 检查点键 (租户, signer_did)：首个非空页须 after=0，续页须等于已存
  next_after；同 after 且 changes 规范化字节相同为幂等重放；旧页、
  跳页、同位异内容均 409 且仅 {"error":"同步游标冲突"}；
- 首个非空页 201、后续新页 200；重放或空页 200 且不推进；成功响应
  键序恰为 valid、signer_did、next_after、accepted，新页 accepted
  为 events 长度、重放或空页为 0；
- 新页原子落盘（原始 events、摘要、检查点），重启后结论不变；
  同步不记审计；租户隔离。
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
    port = 9042
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

    def add_anchor(did, pub, version, headers, uses=None):
        payload = {"did": did, "public_key": pub, "key_version": version}
        if uses is not None:
            payload["uses"] = uses
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        payload, headers)
        assert st in (200, 201), raw

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        signer_did = "did:web:remote-signer"
        priv, pub = gen_keypair()
        add_anchor(signer_did, pub, 1, TA)
        add_anchor(signer_did, pub, 1, TB)

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

        def expect_success(name, payload, status, next_after, accepted,
                           headers=None):
            st, raw = sync_post(payload, headers=headers)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            ok = (
                st == status
                and isinstance(body, dict)
                and list(body.keys())
                == ["valid", "signer_did", "next_after", "accepted"]
                and body["valid"] is True
                and body["signer_did"] == signer_did
                and body["next_after"] == next_after
                and body["accepted"] == accepted
            )
            check(name, ok)

        def expect_conflict(name, payload, headers=None):
            st, raw = sync_post(payload, headers=headers)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            check(name, st == 409 and body == {"error": "同步游标冲突"})

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, payload=None, headers=None, raw_body=None):
            st, raw = sync_post(payload, headers=headers,
                                raw_body=raw_body)
            try:
                body = json.loads(raw.decode() or "{}")
            except ValueError:
                body = None
            check(
                name,
                st == 400
                and isinstance(body, dict)
                and set(body) == {"error"}
                and isinstance(body["error"], str)
                and body["error"].strip() != "",
            )

        page1 = build([event(1), event(2)], after=0)
        expect_400("空体 400", raw_body=b"")
        expect_400("非法 JSON 400", raw_body=b"{not json")
        expect_400("非对象 400", raw_body=b"[1,2]")
        expect_400("缺 changes 400", payload={"after": 0})
        expect_400("缺 after 400", payload={"changes": page1["changes"]})
        expect_400("多余字段 400",
                   payload=dict(page1, extra=1))
        expect_400("changes 非对象 400",
                   payload={"changes": [1], "after": 0})
        expect_400("after 布尔 400",
                   payload={"changes": page1["changes"], "after": True})
        expect_400("after 负数 400",
                   payload={"changes": page1["changes"], "after": -1})
        expect_400("after 字符串 400",
                   payload={"changes": page1["changes"], "after": "0"})
        expect_400("显式空租户头 400", payload=page1,
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 复用 /verify 失败响应，失败不写入
        # ---------------------------------------------------------- #
        bad = build([event(1)], after=0, did="did:web:unknown")
        st, raw = sync_post(bad, headers=TA)
        body = json.loads(raw)
        check("锚点不可用 200 valid:false",
              st == 200 and body == {"valid": False,
                                     "reason": "锚点不可用"})
        malformed = build([event(1)], after=0)
        malformed["changes"]["signature"] = "!!!"
        st, raw = sync_post(malformed, headers=TA)
        check("签名格式错误 200 valid:false",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "签名格式错误"})
        wrong = build([event(1)], after=0, signer_priv=gen_keypair()[0])
        st, raw = sync_post(wrong, headers=TA)
        check("签名校验失败 200 valid:false",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "签名校验失败"})
        ill = build([event(1)], after=0)
        del ill["changes"]["signer_key_version"]
        st, raw = sync_post(ill, headers=TA)
        check("变更流非法 200 valid:false",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "变更流非法"})

        # ---------------------------------------------------------- #
        # 3. 检查点推进、幂等重放与冲突
        # ---------------------------------------------------------- #
        expect_conflict("首个非空页 after!=0 跳页 409",
                        build([event(3)], after=2), headers=TA)

        expect_success("空页 200 accepted=0 不推进",
                       build([], after=0), 200, 0, 0, headers=TA)

        expect_success("首个非空页 201", page1, 201, 2, 2, headers=TA)
        expect_success("幂等重放 200 accepted=0", page1, 200, 2, 0,
                       headers=TA)

        # 同 after 不同内容（同位异内容）409
        alt = build([event(1), event(2, action="rotated")], after=0)
        expect_conflict("同位异内容 409", alt, headers=TA)
        # 旧页 409
        expect_conflict("旧页 409",
                        build([event(1)], after=0), headers=TA)
        # 跳页 409
        expect_conflict("跳页 409",
                        build([event(4)], after=3), headers=TA)

        page2 = build([event(3), event(4)], after=2)
        expect_success("续页 200", page2, 200, 4, 2, headers=TA)
        expect_success("续页重放 200", page2, 200, 4, 0, headers=TA)
        expect_conflict("旧页（首页面）重放按同位异内容 409",
                        page1, headers=TA)
        expect_success("空页对齐游标 200 不推进",
                       build([], after=4), 200, 4, 0, headers=TA)

        # ---------------------------------------------------------- #
        # 4. 租户隔离：同 signer 在他租户有独立检查点
        # ---------------------------------------------------------- #
        expect_success("他租户首页 201", page1, 201, 2, 2, headers=TB)
        expect_conflict("他租户跳页 409",
                        build([event(4)], after=3), headers=TB)

        # ---------------------------------------------------------- #
        # 5. 同步不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit", headers=TA)
        audit = json.loads(raw)
        events_logged = audit.get("events", audit if isinstance(
            audit, list) else [])
        check("同步不记审计",
              not any("sync" in json.dumps(e, ensure_ascii=False)
                      and "anchor" in json.dumps(e, ensure_ascii=False)
                      for e in events_logged))

        # ---------------------------------------------------------- #
        # 6. 重启后结论不变
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        expect_success("重启后续页重放 200", page2, 200, 4, 0, headers=TA)
        expect_conflict("重启后旧页 409", page1, headers=TA)
        page3 = build([event(5)], after=4)
        expect_success("重启后续页推进 200", page3, 200, 5, 1, headers=TA)
        expect_success("重启后他租户重放 200", page1, 200, 2, 0,
                       headers=TB)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
