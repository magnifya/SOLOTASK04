#!/usr/bin/env python3
"""GET /v1/trust/anchor-changes/synced-state 锚点变更同步视图测试。

直接运行：python3 tests/trust_anchor_changes_synced_state_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 参数协议：仅 signer_did/at/limit/after 四项且不重复；signer_did 必填
  非空；at 缺省检查点、非负 ASCII 十进制；limit 缺省 50、限 1–200；
  after 缺省 0、非负；空值、重复、符号、Unicode 数字、越界、未知参数
  或 after>at 均 400 且仅 {"error": 非空中文}；显式空租户头 400；
- 404：来源未同步（含跨租户）同形；409：at 超过检查点同形；
- 200 键序恰为 signer_did/at/anchors/next_after；anchors 项键序恰为
  did/key_version/public_key/status/uses/last_action/last_cursor；
  取 cursor<=at 的事件按 (did,key_version) 以末项为准，按
  last_cursor>after 升序取 limit 项；空页 next_after==after；
- at 分页不受后续同步影响；只读（不推进检查点、不记审计）；
  重启逐字节一致；租户隔离。
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
from vcbackend.store import (  # noqa: E402
    ConflictError,
    NotFoundError,
    ValidationError,
    VCStore,
)

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


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


def make_event(cursor, did, key_version, pub, action="registered",
               status="active", uses=None):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": key_version,
        "public_key": pub,
        "status": status,
        "uses": list(ALL_USES) if uses is None else list(uses),
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
    did_a = "did:web:anchor-a"
    did_b = "did:web:anchor-b"
    did_c = "did:web:anchor-c"
    priv, pub = gen_keypair()

    def get_state(query, headers=None):
        return _http("GET", base + STATE_PATH + query, headers=headers)

    def expect_error(status):
        def inner(name, query, headers=None):
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
        return inner

    expect_400 = expect_error(400)
    expect_404 = expect_error(404)
    expect_409 = expect_error(409)

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
        expect_400("at 负号 400", f"?signer_did={signer_did}&at=-1")
        expect_400("at 小数 400", f"?signer_did={signer_did}&at=1.5")
        expect_400("at 布尔词 400", f"?signer_did={signer_did}&at=true")
        expect_400("at 空白 400", f"?signer_did={signer_did}&at=%205")
        expect_400("at Unicode 数字 400",
                   f"?signer_did={signer_did}&at=%D9%A1")
        expect_400("limit 符号 400", f"?signer_did={signer_did}&limit=%2B5")
        expect_400("limit 小数 400", f"?signer_did={signer_did}&limit=1.5")
        expect_400("limit Unicode 数字 400",
                   f"?signer_did={signer_did}&limit=%EF%BC%95%EF%BC%90")
        expect_400("after 负号 400", f"?signer_did={signer_did}&after=-1")
        expect_400("after Unicode 数字 400",
                   f"?signer_did={signer_did}&after=%EF%BC%91")
        expect_400("limit 越界 0 400", f"?signer_did={signer_did}&limit=0")
        expect_400("limit 越界 201 400",
                   f"?signer_did={signer_did}&limit=201")
        expect_400("after>at 400",
                   f"?signer_did={signer_did}&at=2&after=3")
        expect_400("显式空租户头 400", f"?signer_did={signer_did}",
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404：来源未同步 / 跨租户
        # ---------------------------------------------------------- #
        expect_404("未同步签名方 404", f"?signer_did={signer_did}",
                   headers=TA)
        expect_404("未知签名方 404", "?signer_did=did:web:nobody",
                   headers=TA)

        # ---------------------------------------------------------- #
        # 3. 同步三页（tenant-a），tenant-b 仅同步首页
        # ---------------------------------------------------------- #
        page1_events = [
            make_event(1, did_a, 1, pub),
            make_event(2, did_b, 1, pub),
        ]
        page2_events = [
            make_event(3, did_a, 1, pub, action="uses.updated",
                       uses=["generic", "vc"]),
            make_event(4, did_a, 2, pub, action="rotated"),
        ]
        page3_events = [
            make_event(5, did_b, 1, pub, action="revoked",
                       status="revoked"),
        ]
        pages_payload = [
            build_changes(page1_events, 0, signer_did, priv),
            build_changes(page2_events, 2, signer_did, priv),
            build_changes(page3_events, 4, signer_did, priv),
        ]
        for idx, payload in enumerate(pages_payload):
            st, raw = _http("POST", base + SYNC_PATH, payload, headers=TA)
            assert st == (201 if idx == 0 else 200), (idx, raw)
        st, raw = _http("POST", base + SYNC_PATH, pages_payload[0],
                        headers=TB)
        assert st == 201, raw

        # 跨租户：tenant-b 已同步首页，tenant-a 查未知签名方仍 404
        expect_404("跨租户签名方 404", "?signer_did=did:web:other",
                   headers=TA)

        # ---------------------------------------------------------- #
        # 4. 409：at 超过检查点
        # ---------------------------------------------------------- #
        expect_409("at 超过检查点 409",
                   f"?signer_did={signer_did}&at=6", headers=TA)
        expect_409("at 远超检查点 409",
                   f"?signer_did={signer_did}&at=999", headers=TA)
        expect_409("tenant-b 检查点独立 409",
                   f"?signer_did={signer_did}&at=3", headers=TB)

        # ---------------------------------------------------------- #
        # 5. 200：键序、合并、分页
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
        check("默认合并视图三项按 last_cursor 升序",
              [(a["did"], a["key_version"], a["last_cursor"])
               for a in body["anchors"]]
              == [(did_a, 1, 3), (did_a, 2, 4), (did_b, 1, 5)])
        item_keys_ok = all(
            list(a.keys())
            == ["did", "key_version", "public_key", "status", "uses",
                "last_action", "last_cursor"]
            for a in body["anchors"]
        )
        check("anchors 项键序恰为七键", item_keys_ok)
        check("末项为准：did_a v1 为 uses.updated 且 uses 规范序",
              body["anchors"][0]["last_action"] == "uses.updated"
              and body["anchors"][0]["uses"] == ["generic", "vc"]
              and body["anchors"][0]["status"] == "active")
        check("末项为准：did_b v1 为 revoked",
              body["anchors"][2]["last_action"] == "revoked"
              and body["anchors"][2]["status"] == "revoked")
        check("did_a v2 为 rotated",
              body["anchors"][1]["last_action"] == "rotated"
              and body["anchors"][1]["uses"] == ALL_USES)
        types_ok = all(
            isinstance(a["did"], str)
            and isinstance(a["key_version"], int)
            and a["key_version"] >= 1
            and isinstance(a["public_key"], str)
            and a["status"] in ("active", "revoked")
            and isinstance(a["uses"], list)
            and all(isinstance(u, str) for u in a["uses"])
            and isinstance(a["last_action"], str)
            and isinstance(a["last_cursor"], int)
            and a["last_cursor"] >= 1
            for a in body["anchors"]
        )
        check("anchors 项类型合法", types_ok)
        check("next_after 取末项 last_cursor", body["next_after"] == 5)

        # at 截断：at=2 仅首页事件
        st, raw = get_state(f"?signer_did={signer_did}&at=2", headers=TA)
        body = json.loads(raw)
        check("at=2 视图仅含首页末态",
              st == 200
              and body["at"] == 2
              and [(a["did"], a["last_action"], a["last_cursor"])
                   for a in body["anchors"]]
              == [(did_a, "registered", 1), (did_b, "registered", 2)]
              and body["next_after"] == 2)

        # at=4：did_b 尚未吊销
        st, raw = get_state(f"?signer_did={signer_did}&at=4", headers=TA)
        body = json.loads(raw)
        check("at=4 视图 did_b 仍为 registered",
              st == 200
              and [(a["did"], a["key_version"], a["last_cursor"])
                   for a in body["anchors"]]
              == [(did_b, 1, 2), (did_a, 1, 3), (did_a, 2, 4)]
              and body["next_after"] == 4)

        # after 过滤
        st, raw = get_state(f"?signer_did={signer_did}&after=3", headers=TA)
        body = json.loads(raw)
        check("after=3 仅取 last_cursor>3 的项",
              st == 200
              and [a["last_cursor"] for a in body["anchors"]] == [4, 5]
              and body["next_after"] == 5)

        # limit 截断
        st, raw = get_state(f"?signer_did={signer_did}&limit=1",
                            headers=TA)
        body = json.loads(raw)
        check("limit=1 取首项且 next_after 为其 last_cursor",
              st == 200
              and len(body["anchors"]) == 1
              and body["anchors"][0]["last_cursor"] == 3
              and body["next_after"] == 3)

        # after + at + limit 组合
        st, raw = get_state(
            f"?signer_did={signer_did}&at=4&after=2&limit=1", headers=TA)
        body = json.loads(raw)
        check("at=4&after=2&limit=1 组合",
              st == 200
              and [a["last_cursor"] for a in body["anchors"]] == [3]
              and body["next_after"] == 3)

        # 空页
        st, raw = get_state(f"?signer_did={signer_did}&after=5", headers=TA)
        body = json.loads(raw)
        check("空页 next_after 等于 after",
              st == 200
              and body["anchors"] == []
              and body["next_after"] == 5)
        st, raw = get_state(f"?signer_did={signer_did}&at=0", headers=TA)
        body = json.loads(raw)
        check("at=0 空页 next_after 等于 after(0)",
              st == 200
              and body["at"] == 0
              and body["anchors"] == []
              and body["next_after"] == 0)
        st, raw = get_state(f"?signer_did={signer_did}&at=5&after=5",
                            headers=TA)
        check("after==at 空页 200", st == 200)

        # 边界 limit
        st, raw = get_state(f"?signer_did={signer_did}&limit=200",
                            headers=TA)
        check("limit=200 合法", st == 200 and len(json.loads(raw)["anchors"]) == 3)

        # 租户隔离：tenant-b 检查点为 2
        st, raw = get_state(f"?signer_did={signer_did}", headers=TB)
        body = json.loads(raw)
        check("租户隔离：tenant-b at 缺省为 2 且仅两项",
              st == 200
              and body["at"] == 2
              and [(a["did"], a["last_cursor"]) for a in body["anchors"]]
              == [(did_a, 1), (did_b, 2)]
              and body["next_after"] == 2)

        # ---------------------------------------------------------- #
        # 6. at 分页不受后续同步影响；只读
        # ---------------------------------------------------------- #
        st, raw_at4_before = get_state(
            f"?signer_did={signer_did}&at=4", headers=TA)
        assert st == 200
        page4 = build_changes(
            [make_event(6, did_c, 1, pub)], 5, signer_did, priv)
        st, raw = _http("POST", base + SYNC_PATH, page4, headers=TA)
        body = json.loads(raw)
        check("续页同步 200 accepted=1",
              st == 200 and body["accepted"] == 1
              and body["next_after"] == 6)
        st, raw_at4_after = get_state(
            f"?signer_did={signer_did}&at=4", headers=TA)
        check("后续同步不影响 at=4 视图（逐字节一致）",
              st == 200 and raw_at4_after == raw_at4_before)
        st, raw = get_state(f"?signer_did={signer_did}", headers=TA)
        body = json.loads(raw)
        check("后续同步后缺省 at 为新检查点 6",
              st == 200
              and body["at"] == 6
              and body["anchors"][-1]["did"] == did_c
              and body["next_after"] == 6)

        # 只读：不推进检查点（重放仍 accepted=0）、不记审计
        st, raw = _http("POST", base + SYNC_PATH, page4, headers=TA)
        body = json.loads(raw)
        check("查询后重放仍 200 accepted=0（检查点未推进）",
              st == 200 and body["accepted"] == 0
              and body["next_after"] == 6)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit = json.loads(raw)
        audit_events = (
            audit.get("events", []) if isinstance(audit, dict) else []
        )
        check("查询不记审计",
              not any("synced-state" in json.dumps(e, ensure_ascii=False)
                      for e in audit_events))

        # ---------------------------------------------------------- #
        # 7. 重启逐字节一致
        # ---------------------------------------------------------- #
        queries = [
            f"?signer_did={signer_did}",
            f"?signer_did={signer_did}&at=4",
            f"?signer_did={signer_did}&at=4&after=2&limit=1",
            f"?signer_did={signer_did}&after=6",
        ]
        before = []
        for query in queries:
            st, raw = get_state(query, headers=TA)
            assert st == 200, (query, raw)
            before.append(raw)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        for query, expected in zip(queries, before):
            st, raw = get_state(query, headers=TA)
            check(f"重启后逐字节一致 {query}",
                  st == 200 and raw == expected)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def test_store():
    """直连 VCStore：404/409/400 与合并视图。"""
    TENANT = "synced-state-ta"
    signer = "did:web:store-signer"
    path = tempfile.mktemp(suffix=".json")
    try:
        store = VCStore(path)

        def event(cursor, did, version, action="registered",
                  status="active"):
            return {
                "cursor": cursor,
                "action": action,
                "did": did,
                "key_version": version,
                "public_key": "pem",
                "status": status,
                "uses": list(ALL_USES),
            }

        try:
            store.get_anchor_changes_synced_state(TENANT, signer)
            check("未同步抛 NotFoundError", False)
        except NotFoundError:
            check("未同步抛 NotFoundError", True)

        import hashlib

        def digest(tag):
            return hashlib.sha256(tag.encode()).hexdigest()

        store.sync_anchor_changes(
            TENANT, signer, 0, digest("p1"),
            [event(1, "did:web:a", 1), event(2, "did:web:b", 1)], 2)
        store.sync_anchor_changes(
            TENANT, signer, 2, digest("p2"),
            [event(3, "did:web:a", 1, action="revoked",
                   status="revoked")], 3)

        at, anchors, next_after = store.get_anchor_changes_synced_state(
            TENANT, signer)
        check("缺省 at 取检查点",
              at == 3 and next_after == 3)
        check("合并视图末项为准",
              [(a["did"], a["last_action"], a["last_cursor"])
               for a in anchors]
              == [("did:web:b", "registered", 2),
                  ("did:web:a", "revoked", 3)]
              and anchors[1]["status"] == "revoked")

        at1, anchors1, next_after1 = store.get_anchor_changes_synced_state(
            TENANT, signer, at=1)
        check("at=1 仅首事件",
              at1 == 1
              and [(a["did"], a["last_cursor"]) for a in anchors1]
              == [("did:web:a", 1)]
              and next_after1 == 1)

        try:
            store.get_anchor_changes_synced_state(TENANT, signer, at=4)
            check("at 超过检查点抛 ConflictError", False)
        except ConflictError:
            check("at 超过检查点抛 ConflictError", True)
        try:
            store.get_anchor_changes_synced_state(TENANT, signer, after=4)
            check("after>at(检查点) 抛 ValidationError", False)
        except ValidationError:
            check("after>at(检查点) 抛 ValidationError", True)
        try:
            store.get_anchor_changes_synced_state("did:web:none", signer)
            check("跨租户抛 NotFoundError", False)
        except NotFoundError:
            check("跨租户抛 NotFoundError", True)

        # 只读：检查点不被推进
        created, na, accepted = store.sync_anchor_changes(
            TENANT, signer, 2, digest("p2"),
            [event(3, "did:web:a", 1, action="revoked",
                   status="revoked")], 3)
        check("查询后重放仍不推进（accepted=0）",
              (created, na, accepted) == (False, 3, 0))

        # 重启一致
        reopened = VCStore(path)
        at2, anchors2, next_after2 = (
            reopened.get_anchor_changes_synced_state(TENANT, signer)
        )
        check("重启后视图一致",
              (at2, anchors2, next_after2) == (at, anchors, next_after))
    finally:
        if os.path.exists(path):
            os.unlink(path)


def main():
    test_http()
    test_store()
    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
