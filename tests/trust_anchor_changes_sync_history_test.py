#!/usr/bin/env python3
"""GET /v1/trust/anchor-changes/sync-history 与同步保存失败回滚测试。

直接运行：python3 tests/trust_anchor_changes_sync_history_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 参数协议：仅 signer_did/limit/after 三项且唯一；signer_did 必填非空；
  limit 缺省 50、限 1–200；after 缺省 0、非负；空值、重复、符号、
  Unicode 数字、越界、未知参数均 400 且仅 {"error": 非空中文}；
  显式空租户头 400；
- 404：该签名方未接收非空页、跨租户均 404 同形；
- 200 键序恰为 signer_did/pages/next_after；页键序恰为
  after/next_after/digest/events（after<next_after，digest 为 64 位
  小写 hex，events 值/顺序/键序不变）；按来源 next_after 升序取
  next_after>after 的前 limit 页；空页 next_after==after；
- 只读：不推进检查点（重放/续页行为不变）、不记审计、重启一致；
- 保存失败回滚（直连 VCStore）：检查点、页面、租户桶与临时容器均
  恢复到调用前，内存与重载状态一致，重试从原游标继续。
"""

import copy
import hashlib
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
    StorageError,
    VCStore,
)

SYNC_PATH = "/v1/trust/anchor-changes/sync"
HISTORY_PATH = "/v1/trust/anchor-changes/sync-history"
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


def make_event(cursor, did, pub, action="registered"):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": 1,
        "public_key": pub,
        "status": "active",
        "uses": list(ALL_USES),
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
    port = 9043
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

    def get_history(query, headers=None):
        return _http("GET", base + HISTORY_PATH + query, headers=headers)

    def expect_400(name, query, headers=None):
        st, raw = get_history(query, headers=headers)
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

    def expect_404(name, query, headers=None):
        st, raw = get_history(query, headers=headers)
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(
            name,
            st == 404
            and isinstance(body, dict)
            and set(body) == {"error"}
            and isinstance(body["error"], str)
            and body["error"].strip() != "",
        )

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
        expect_400("缺 signer_did 400", "?limit=10")
        expect_400("空 signer_did 400", "?signer_did=")
        expect_400("重复 signer_did 400",
                   "?signer_did=a&signer_did=b")
        expect_400("重复 limit 400",
                   f"?signer_did={signer_did}&limit=1&limit=2")
        expect_400("重复 after 400",
                   f"?signer_did={signer_did}&after=1&after=2")
        expect_400("未知参数 400",
                   f"?signer_did={signer_did}&foo=1")
        expect_400("空 limit 400", f"?signer_did={signer_did}&limit=")
        expect_400("空 after 400", f"?signer_did={signer_did}&after=")
        expect_400("limit 符号 400", f"?signer_did={signer_did}&limit=%2B5")
        expect_400("after 负号 400", f"?signer_did={signer_did}&after=-1")
        expect_400("limit 小数 400", f"?signer_did={signer_did}&limit=1.5")
        expect_400("limit 布尔词 400",
                   f"?signer_did={signer_did}&limit=true")
        expect_400("limit 空白 400", f"?signer_did={signer_did}&limit=%2050")
        expect_400("limit Unicode 数字 400",
                   f"?signer_did={signer_did}&limit=%EF%BC%95%EF%BC%90")
        expect_400("after Unicode 数字 400",
                   f"?signer_did={signer_did}&after=%D9%A1")
        expect_400("limit 越界 0 400", f"?signer_did={signer_did}&limit=0")
        expect_400("limit 越界 201 400",
                   f"?signer_did={signer_did}&limit=201")
        expect_400("显式空租户头 400",
                   f"?signer_did={signer_did}",
                   headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404：未接收非空页 / 跨租户
        # ---------------------------------------------------------- #
        expect_404("未同步签名方 404", f"?signer_did={signer_did}",
                   headers=TA)
        expect_404("未知签名方 404", "?signer_did=did:web:nobody",
                   headers=TA)

        # ---------------------------------------------------------- #
        # 3. 同步三页（tenant-a），tenant-b 仅同步首页
        # ---------------------------------------------------------- #
        page1_events = [make_event(1, signer_did, pub),
                        make_event(2, signer_did, pub)]
        page2_events = [make_event(3, signer_did, pub),
                        make_event(4, signer_did, pub, action="rotated")]
        page3_events = [make_event(5, signer_did, pub)]
        pages_payload = [
            build_changes(page1_events, 0, signer_did, priv),
            build_changes(page2_events, 2, signer_did, priv),
            build_changes(page3_events, 4, signer_did, priv),
        ]
        expected_status = [201, 200, 200]
        for idx, payload in enumerate(pages_payload):
            st, raw = _http("POST", base + SYNC_PATH, payload, headers=TA)
            assert st == expected_status[idx], (idx, raw)
        st, raw = _http("POST", base + SYNC_PATH, pages_payload[0],
                        headers=TB)
        assert st == 201, raw

        def digest_of(payload):
            return hashlib.sha256(
                crypto.canonicalize(payload["changes"])
            ).hexdigest()

        # 跨租户：tenant-b 只有首页，查 tenant-b 得 1 页；查他租户签名方
        # 在 tenant-a 不可见
        expect_404("跨租户签名方 404", "?signer_did=did:web:other",
                   headers=TA)

        # ---------------------------------------------------------- #
        # 4. 200：键序、分页、摘要与事件原文
        # ---------------------------------------------------------- #
        st, raw = get_history(f"?signer_did={signer_did}", headers=TA)
        body = json.loads(raw)
        check("200 顶层键序恰为 signer_did/pages/next_after",
              st == 200
              and list(body.keys()) == ["signer_did", "pages", "next_after"])
        check("默认 limit=50 返回全部 3 页",
              body["signer_did"] == signer_did
              and len(body["pages"]) == 3
              and body["next_after"] == 5)
        key_order_ok = all(
            list(page.keys()) == ["after", "next_after", "digest", "events"]
            for page in body["pages"]
        )
        check("页键序恰为 after/next_after/digest/events", key_order_ok)
        shape_ok = all(
            isinstance(page["after"], int)
            and isinstance(page["next_after"], int)
            and 0 <= page["after"] < page["next_after"]
            and isinstance(page["digest"], str)
            and len(page["digest"]) == 64
            and all(ch in "0123456789abcdef" for ch in page["digest"])
            for page in body["pages"]
        )
        check("页 after/next_after 非负且递增、digest 64 位小写 hex",
              shape_ok)
        check("页 digest 与 changes 规范化摘要一致",
              [page["digest"] for page in body["pages"]]
              == [digest_of(p) for p in pages_payload])
        check("events 值与顺序不变",
              [page["events"] for page in body["pages"]]
              == [page1_events, page2_events, page3_events])
        check("events 项键序不变",
              all(
                  list(event.keys())
                  == ["cursor", "action", "did", "key_version",
                      "public_key", "status", "uses"]
                  for page in body["pages"] for event in page["events"]
              ))
        check("页按来源 next_after 升序",
              [page["next_after"] for page in body["pages"]] == [2, 4, 5])

        # limit 截断
        st, raw = get_history(
            f"?signer_did={signer_did}&limit=2", headers=TA)
        body = json.loads(raw)
        check("limit=2 取前 2 页且 next_after 为末页游标",
              st == 200
              and [p["next_after"] for p in body["pages"]] == [2, 4]
              and body["next_after"] == 4)

        # after 过滤
        st, raw = get_history(
            f"?signer_did={signer_did}&after=2", headers=TA)
        body = json.loads(raw)
        check("after=2 仅取 next_after>2 的页",
              st == 200
              and [p["next_after"] for p in body["pages"]] == [4, 5]
              and body["next_after"] == 5)

        # after + limit 组合
        st, raw = get_history(
            f"?signer_did={signer_did}&after=2&limit=1", headers=TA)
        body = json.loads(raw)
        check("after=2&limit=1 取单页",
              st == 200
              and [p["next_after"] for p in body["pages"]] == [4]
              and body["next_after"] == 4)

        # 空页
        st, raw = get_history(
            f"?signer_did={signer_did}&after=5", headers=TA)
        body = json.loads(raw)
        check("空页 next_after 等于 after",
              st == 200 and body["pages"] == [] and body["next_after"] == 5)

        # 边界 limit
        st, raw = get_history(
            f"?signer_did={signer_did}&limit=200", headers=TA)
        check("limit=200 合法", st == 200)
        st, raw = get_history(
            f"?signer_did={signer_did}&limit=1", headers=TA)
        check("limit=1 合法", st == 200 and len(json.loads(raw)["pages"]) == 1)

        # 租户隔离：tenant-b 仅首页
        st, raw = get_history(f"?signer_did={signer_did}", headers=TB)
        body = json.loads(raw)
        check("租户隔离：tenant-b 仅 1 页",
              st == 200
              and len(body["pages"]) == 1
              and body["next_after"] == 2)

        # ---------------------------------------------------------- #
        # 5. 只读：不推进检查点、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("POST", base + SYNC_PATH, pages_payload[2],
                        headers=TA)
        body = json.loads(raw)
        check("查询后重放仍 200 accepted=0（检查点未推进）",
              st == 200 and body["accepted"] == 0
              and body["next_after"] == 5)
        page4 = build_changes([make_event(6, signer_did, pub)],
                              5, signer_did, priv)
        st, raw = _http("POST", base + SYNC_PATH, page4, headers=TA)
        body = json.loads(raw)
        check("查询后续页从原游标继续 200 accepted=1",
              st == 200 and body["accepted"] == 1
              and body["next_after"] == 6)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit = json.loads(raw)
        audit_events = audit.get("events", []) if isinstance(audit, dict) else []
        check("查询不记审计",
              not any("sync-history" in json.dumps(e, ensure_ascii=False)
                      for e in audit_events))

        # ---------------------------------------------------------- #
        # 6. 重启一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = get_history(f"?signer_did={signer_did}", headers=TA)
        body = json.loads(raw)
        check("重启后历史一致（4 页，next_after=6）",
              st == 200
              and len(body["pages"]) == 4
              and body["next_after"] == 6
              and [p["next_after"] for p in body["pages"]] == [2, 4, 5, 6])
        st, raw = get_history(
            f"?signer_did={signer_did}&after=4&limit=1", headers=TA)
        body = json.loads(raw)
        check("重启后分页一致",
              st == 200
              and [p["next_after"] for p in body["pages"]] == [5]
              and body["next_after"] == 5)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def test_rollback():
    """保存失败回滚：直连 VCStore。"""
    TENANT = "sync-hist-ta"
    FRESH = "sync-hist-fresh"
    signer = "did:web:rollback-signer"

    def events(*cursors):
        return [
            {
                "cursor": cursor,
                "action": "registered",
                "did": signer,
                "key_version": 1,
                "public_key": "pem",
                "status": "active",
                "uses": list(ALL_USES),
            }
            for cursor in cursors
        ]

    def capture(store):
        return {
            "tenants": copy.deepcopy(store._tenants),  # noqa: SLF001
            "checkpoints": copy.deepcopy(  # noqa: SLF001
                store._anchor_changes_sync_checkpoints
            ),
        }

    path = tempfile.mktemp(suffix=".json")
    try:
        store = VCStore(path)
        digest1 = hashlib.sha256(b"page1").hexdigest()
        created, next_after, accepted = store.sync_anchor_changes(
            TENANT, signer, 0, digest1, events(1, 2), 2
        )
        check("回滚基线：首页 201 推进",
              (created, next_after, accepted) == (True, 2, 2))

        baseline = capture(store)
        disk0 = Path(path).read_bytes()

        def install_boom():
            def _boom():
                raise OSError("模拟落盘失败: 磁盘已满")

            store._save_locked = _boom  # type: ignore[assignment]

        def expect_storage_error(name, fn):
            try:
                fn()
            except StorageError:
                check(f"{name}：抛 StorageError", True)
                return
            except Exception as exc:  # noqa: BLE001
                check(f"{name}：抛 StorageError（实际 {exc!r}）", False)
                return
            check(f"{name}：抛 StorageError", False)

        # 1) 续页保存失败：检查点/页面/租户桶全部回到调用前
        install_boom()
        digest2 = hashlib.sha256(b"page2").hexdigest()
        expect_storage_error(
            "续页保存失败",
            lambda: store.sync_anchor_changes(
                TENANT, signer, 2, digest2, events(3, 4), 4
            ),
        )
        check("续页失败：内存状态等于调用前", capture(store) == baseline)
        check("续页失败：磁盘文件字节不变",
              Path(path).read_bytes() == disk0)
        pages = store._tenants[TENANT]["synced_anchor_change_pages"][signer]  # noqa: SLF001
        check("续页失败：页面容器仅首页", len(pages) == 1)

        # 2) 新租户首页保存失败：不残留租户桶/检查点/临时容器
        digest_f = hashlib.sha256(b"fresh").hexdigest()
        expect_storage_error(
            "新租户首页保存失败",
            lambda: store.sync_anchor_changes(
                FRESH, signer, 0, digest_f, events(1), 1
            ),
        )
        check("新租户失败：不残留租户桶",
              FRESH not in store._tenants)  # noqa: SLF001
        check("新租户失败：不残留检查点",
              FRESH not in store._anchor_changes_sync_checkpoints)  # noqa: SLF001
        check("新租户失败：内存状态等于调用前", capture(store) == baseline)

        # 3) 重载状态与调用前一致
        reopened = VCStore(path)
        check("失败后重载状态一致",
              capture(reopened) == baseline)

        # 4) 移除故障：重试从原游标继续
        del store._save_locked  # type: ignore[attr-defined]
        created, next_after, accepted = store.sync_anchor_changes(
            TENANT, signer, 2, digest2, events(3, 4), 4
        )
        check("移除故障后重试续页成功（原游标）",
              (created, next_after, accepted) == (False, 4, 2))
        created, next_after, accepted = store.sync_anchor_changes(
            FRESH, signer, 0, digest_f, events(1), 1
        )
        check("新租户重试首页成功",
              (created, next_after, accepted) == (True, 1, 1))

        # 5) 历史查询只读：不推进检查点
        pages_out, next_after = store.list_anchor_changes_sync_history(
            TENANT, signer, 0, 50
        )
        check("历史查询返回两页且 next_after 为末页",
              len(pages_out) == 2 and next_after == 4)
        check("历史查询页内容",
              [p["next_after"] for p in pages_out] == [2, 4]
              and pages_out[0]["digest"] == digest1
              and pages_out[1]["digest"] == digest2)
        try:
            store.list_anchor_changes_sync_history(TENANT, "did:web:none")
            check("未知签名方历史 404", False)
        except NotFoundError:
            check("未知签名方历史 404", True)
        try:
            store.list_anchor_changes_sync_history("did:web:none", signer)
            check("跨租户历史 404", False)
        except NotFoundError:
            check("跨租户历史 404", True)

        # 6) 冲突路径不产生残留
        try:
            store.sync_anchor_changes(
                "sync-hist-never", signer, 3, digest1, events(4), 4
            )
            check("跳页冲突抛 ConflictError", False)
        except ConflictError:
            check("跳页冲突抛 ConflictError", True)
        check("冲突路径不残留租户桶",
              "sync-hist-never" not in store._tenants)  # noqa: SLF001
        check("冲突路径不残留检查点",
              "sync-hist-never"
              not in store._anchor_changes_sync_checkpoints)  # noqa: SLF001

        # 7) 重启后历史与检查点一致
        reopened = VCStore(path)
        pages_out, next_after = reopened.list_anchor_changes_sync_history(
            TENANT, signer, 0, 50
        )
        check("重启后历史两页一致",
              len(pages_out) == 2 and next_after == 4)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def main():
    test_http()
    test_rollback()
    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
