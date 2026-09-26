#!/usr/bin/env python3
"""GET /v1/trust/anchor-changes/synced-state 锚点变更同步时点汇聚状态视图测试。

直接运行：python3 tests/trust_anchor_changes_synced_state_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 参数协议：仅 signer_did/at/limit/after 四项且唯一；signer_did 必填
  非空；at 缺省取检查点、非负；limit 缺省 50、限 1–200；after 缺省
  0、非负；空值、重复、符号、Unicode 数字、越界、after>at、未知参
  数均 400 且仅 {"error": 非空中文}；显式空租户头 400；
- 404/409：未同步或跨租户 404 同形；at 超过检查点 409 同形；
- 200 键序恰为 signer_did/at/anchors/next_after；取 cursor<=at 事
  件以 (did,key_version) 末项为准，按 last_cursor>after 升序取
  limit 项，项键序恰为 did/key_version/public_key/status/uses/
  last_action/last_cursor；空页 next_after==after；
- at 分页不受后续同步影响（显式 at 响应逐字节不变）；只读：不推进
  检查点、不记审计；重启逐字节一致。
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
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None):
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


def test_http():
    port = 9044
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
    priv, pub = gen_keypair()

    def get_state(query, headers=None):
        return _http("GET", base + STATE_PATH + query, headers=headers)

    def expect_error(name, query, status, headers=None):
        st, raw = get_state(query, headers=headers)
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

    def expect_400(name, query, headers=None):
        expect_error(name, query, 400, headers=headers)

    try:
        # 登记签名方锚点（两个租户），供 sync 验真通过
        for headers in (TA, TB):
            st, raw = _http(
                "POST",
                f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": pub, "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # ---------------------------------------------------------- #
        # 1. 400 族：参数协议
        # ---------------------------------------------------------- #
        expect_400("缺 signer_did 400", "?at=1")
        expect_400("空 signer_did 400", "?signer_did=")
        expect_400("重复 signer_did 400", "?signer_did=a&signer_did=b")
        expect_400("重复 at 400", f"?signer_did={signer_did}&at=1&at=2")
        expect_400("重复 limit 400",
                   f"?signer_did={signer_did}&limit=1&limit=2")
        expect_400("重复 after 400",
                   f"?signer_did={signer_did}&after=1&after=2")
        expect_400("未知参数 400", f"?signer_did={signer_did}&foo=1")
        expect_400("空 at 400", f"?signer_did={signer_did}&at=")
        expect_400("空 limit 400", f"?signer_did={signer_did}&limit=")
        expect_400("空 after 400", f"?signer_did={signer_did}&after=")
        expect_400("at 符号 400", f"?signer_did={signer_did}&at=%2B5")
        expect_400("after 负号 400", f"?signer_did={signer_did}&after=-1")
        expect_400("at 小数 400", f"?signer_did={signer_did}&at=1.5")
        expect_400("limit 布尔词 400",
                   f"?signer_did={signer_did}&limit=true")
        expect_400("at 空白 400", f"?signer_did={signer_did}&at=%2050")
        expect_400("at Unicode 数字 400",
                   f"?signer_did={signer_did}&at=%EF%BC%95")
        expect_400("after Unicode 数字 400",
                   f"?signer_did={signer_did}&after=%D9%A1")
        expect_400("limit 越界 0 400", f"?signer_did={signer_did}&limit=0")
        expect_400("limit 越界 201 400",
                   f"?signer_did={signer_did}&limit=201")
        expect_400("after>at 400",
                   f"?signer_did={signer_did}&at=2&after=3")
        expect_400("显式空租户头 400",
                   f"?signer_did={signer_did}",
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 未知签名方（同步前）
        # ---------------------------------------------------------- #
        expect_error("未同步签名方 404", f"?signer_did={signer_did}",
                     404, headers=TA)
        expect_error("未知签名方 404", "?signer_did=did:web:nobody",
                     404, headers=TA)

        # ---------------------------------------------------------- #
        # 3. 同步三页（tenant-a），tenant-b 仅同步首页
        # ---------------------------------------------------------- #
        # e1: a#1 注册(active) c1；e2: b#1 注册(active, 部分用途) c2
        # e3: a#1 吊销 c3；e4: a#2 轮换 c4；e5: c#1 注册 c5
        page1_events = [
            make_event(1, "did:web:a", 1, pub=pub),
            make_event(2, "did:web:b", 1, uses=["generic", "vc"], pub=pub),
        ]
        page2_events = [
            make_event(3, "did:web:a", 1, action="revoked",
                       status="revoked", pub=pub),
            make_event(4, "did:web:a", 2, action="rotated", pub=pub),
        ]
        page3_events = [make_event(5, "did:web:c", 1, pub=pub)]
        pages_payload = [
            build_changes(page1_events, 0, signer_did, priv),
            build_changes(page2_events, 2, signer_did, priv),
            build_changes(page3_events, 4, signer_did, priv),
        ]
        for idx, payload in enumerate(pages_payload):
            st, raw = _http("POST", base + SYNC_PATH, payload, headers=TA)
            assert st == [201, 200, 200][idx], (idx, raw)
        st, raw = _http("POST", base + SYNC_PATH, pages_payload[0],
                        headers=TB)
        assert st == 201, raw

        # 跨租户：tenant-b 尚未同步该签名方之外的对象；他租户同步不可见
        expect_error("跨租户签名方 404", "?signer_did=did:web:other",
                     404, headers=TA)
        expect_error("他租户签名方在本租户未同步 404",
                     "?signer_did=did:web:other", 404, headers=TB)

        # ---------------------------------------------------------- #
        # 4. 409：at 超过检查点（检查点=5）
        # ---------------------------------------------------------- #
        expect_error("at 超过检查点 409",
                     f"?signer_did={signer_did}&at=6", 409, headers=TA)
        expect_error("tenant-b at 超过其检查点 409",
                     f"?signer_did={signer_did}&at=3", 409, headers=TB)

        # ---------------------------------------------------------- #
        # 5. 200：键序、汇聚、分页
        # ---------------------------------------------------------- #
        st, raw = get_state(f"?signer_did={signer_did}", headers=TA)
        body = json.loads(raw)
        check("200 顶层键序恰为 signer_did/at/anchors/next_after",
              st == 200
              and list(body.keys())
              == ["signer_did", "at", "anchors", "next_after"])
        check("at 缺省取检查点 5",
              body["signer_did"] == signer_did
              and body["at"] == 5
              and isinstance(body["at"], int))
        check("默认 limit=50 返回全部 4 项且 next_after 为末项游标",
              len(body["anchors"]) == 4 and body["next_after"] == 5)
        check("anchors 项键序恰为 did/key_version/public_key/status/"
              "uses/last_action/last_cursor",
              all(
                  list(item.keys())
                  == ["did", "key_version", "public_key", "status",
                      "uses", "last_action", "last_cursor"]
                  for item in body["anchors"]
              ))
        check("以 (did,key_version) 末项为准且按 last_cursor 升序",
              [(i["did"], i["key_version"], i["last_action"],
                i["status"], i["last_cursor"]) for i in body["anchors"]]
              == [("did:web:b", 1, "registered", "active", 2),
                  ("did:web:a", 1, "revoked", "revoked", 3),
                  ("did:web:a", 2, "rotated", "active", 4),
                  ("did:web:c", 1, "registered", "active", 5)])
        check("uses 保持规范序字符串数组",
              body["anchors"][0]["uses"] == ["generic", "vc"]
              and body["anchors"][1]["uses"] == ALL_USES)
        check("字段类型：key_version/last_cursor 正整数、public_key/"
              "last_action 字符串",
              all(
                  isinstance(i["key_version"], int)
                  and i["key_version"] >= 1
                  and isinstance(i["last_cursor"], int)
                  and i["last_cursor"] >= 1
                  and isinstance(i["public_key"], str)
                  and isinstance(i["last_action"], str)
                  and i["status"] in ("active", "revoked")
                  for i in body["anchors"]
              ))

        # at 时点截断：at=3 仅见 c1..c3，a#1 以吊销末项为准
        st, raw = get_state(f"?signer_did={signer_did}&at=3", headers=TA)
        body = json.loads(raw)
        check("at=3 仅汇聚 cursor<=3 的事件",
              st == 200
              and body["at"] == 3
              and [(i["did"], i["last_cursor"]) for i in body["anchors"]]
              == [("did:web:b", 2), ("did:web:a", 3)]
              and body["next_after"] == 3)

        # after 过滤
        st, raw = get_state(f"?signer_did={signer_did}&at=3&after=2",
                            headers=TA)
        body = json.loads(raw)
        check("at=3&after=2 仅取 last_cursor>2 的项",
              st == 200
              and [(i["did"], i["last_cursor"]) for i in body["anchors"]]
              == [("did:web:a", 3)]
              and body["next_after"] == 3)

        # 空页：next_after 等于 after
        st, raw = get_state(f"?signer_did={signer_did}&at=3&after=3",
                            headers=TA)
        body = json.loads(raw)
        check("空页 next_after 等于 after",
              st == 200 and body["anchors"] == []
              and body["next_after"] == 3)

        # limit 截断
        st, raw = get_state(f"?signer_did={signer_did}&limit=2", headers=TA)
        body = json.loads(raw)
        check("limit=2 取前 2 项且 next_after 为末项 last_cursor",
              st == 200
              and [i["last_cursor"] for i in body["anchors"]] == [2, 3]
              and body["next_after"] == 3)

        # after + limit 组合翻页
        st, raw = get_state(
            f"?signer_did={signer_did}&after=3&limit=1", headers=TA)
        body = json.loads(raw)
        check("after=3&limit=1 取单项",
              st == 200
              and [i["last_cursor"] for i in body["anchors"]] == [4]
              and body["next_after"] == 4)

        # 边界 limit
        st, raw = get_state(f"?signer_did={signer_did}&limit=200",
                            headers=TA)
        check("limit=200 合法", st == 200)
        st, raw = get_state(f"?signer_did={signer_did}&limit=1",
                            headers=TA)
        check("limit=1 合法",
              st == 200 and len(json.loads(raw)["anchors"]) == 1)

        # 显式 at 等于检查点与缺省一致
        st, raw_default = get_state(f"?signer_did={signer_did}", headers=TA)
        st, raw_at5 = get_state(f"?signer_did={signer_did}&at=5",
                                headers=TA)
        check("显式 at=5 与缺省一致", raw_default == raw_at5)

        # 租户隔离：tenant-b 仅首页（检查点=2）
        st, raw = get_state(f"?signer_did={signer_did}", headers=TB)
        body = json.loads(raw)
        check("租户隔离：tenant-b 仅 2 项、at=2",
              st == 200
              and body["at"] == 2
              and [(i["did"], i["last_cursor"], i["status"])
                   for i in body["anchors"]]
              == [("did:web:a", 1, "active"), ("did:web:b", 2, "active")]
              and body["next_after"] == 2)

        # ---------------------------------------------------------- #
        # 6. at 分页不受后续同步影响；只读：不推进检查点、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))

        # 记录 at=5 视图字节，随后同步第四页推进检查点到 6
        frozen_at5 = raw_at5
        page4 = build_changes(
            [make_event(6, "did:web:b", 1, action="revoked",
                        status="revoked", uses=["generic", "vc"], pub=pub)],
            5, signer_did, priv)
        st, raw = _http("POST", base + SYNC_PATH, page4, headers=TA)
        assert st == 200, raw

        st, raw = get_state(f"?signer_did={signer_did}&at=5", headers=TA)
        check("后续同步不影响显式 at=5 视图（逐字节一致）",
              st == 200 and raw == frozen_at5)

        st, raw = get_state(f"?signer_did={signer_did}", headers=TA)
        body = json.loads(raw)
        check("缺省 at 跟随新检查点 6，b#1 末项为吊销",
              st == 200
              and body["at"] == 6
              and body["anchors"][-1]["did"] == "did:web:b"
              and body["anchors"][-1]["last_action"] == "revoked"
              and body["anchors"][-1]["status"] == "revoked"
              and body["anchors"][-1]["last_cursor"] == 6
              and body["next_after"] == 6)

        # 只读：检查点未被查询推进（重放仍 accepted=0）
        st, raw = _http("POST", base + SYNC_PATH, page4, headers=TA)
        body = json.loads(raw)
        check("查询后重放仍 200 accepted=0（检查点未推进）",
              st == 200 and body["accepted"] == 0
              and body["next_after"] == 6)

        # 只读：不记审计
        st, raw = get_state(f"?signer_did={signer_did}&limit=1", headers=TA)
        assert st == 200
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("查询不记审计", audit_after == audit_before)

        # ---------------------------------------------------------- #
        # 7. 重启逐字节一致
        # ---------------------------------------------------------- #
        st, raw_default6 = get_state(f"?signer_did={signer_did}",
                                     headers=TA)
        st, raw_at3 = get_state(f"?signer_did={signer_did}&at=3",
                                headers=TA)
        assert st == 200
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = get_state(f"?signer_did={signer_did}", headers=TA)
        check("重启后缺省视图逐字节一致",
              st == 200 and raw == raw_default6)
        st, raw = get_state(f"?signer_did={signer_did}&at=5", headers=TA)
        check("重启后显式 at=5 视图逐字节一致",
              st == 200 and raw == frozen_at5)
        st, raw = get_state(f"?signer_did={signer_did}&at=3", headers=TA)
        check("重启后 at=3 视图逐字节一致",
              st == 200 and raw == raw_at3)
        st, raw = get_state(f"?signer_did={signer_did}", headers=TB)
        check("重启后 tenant-b 视图一致",
              st == 200
              and json.loads(raw)["at"] == 2
              and len(json.loads(raw)["anchors"]) == 2)
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
