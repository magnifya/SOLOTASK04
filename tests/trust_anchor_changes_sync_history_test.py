#!/usr/bin/env python3
"""GET /v1/trust/anchor-changes/sync-history 同步历史查询与同步落盘失败回滚测试。

直接运行：python3 tests/trust_anchor_changes_sync_history_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400 族：查询参数仅允许 signer_did、limit、after 且各唯一；
  signer_did 必填非空；limit 缺省 50、须为 ASCII 十进制 1..200；
  after 缺省 0、须为 ASCII 非负整数。空值、重复、符号、Unicode
  数字、越界或未知参数均 400 且仅 {"error": 非空中文}；
  显式空租户头 400；
- 404 族：未接收该签名方非空页、跨租户均 404 且仅 {"error"}；
- 200 键序恰为 signer_did、pages、next_after；pages 按来源
  next_after 升序取 next_after>after 的前 limit 项，每项键序恰为
  after、next_after、digest、events，事件值/顺序/键序不变；
  空页 next_after 等于 after，否则等于末页 next_after；
- 只读：不推进检查点、不记审计，重启后结论一致；
- 同步落盘失败（直连 VCStore）：检查点、同步页、租户桶与临时容器
  全部回滚，内存与重载状态均等于调用前，磁盘字节不变，移除故障后
  重试从原游标继续。
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
from vcbackend.store import StorageError, VCStore  # noqa: E402

SYNC_PATH = "/v1/trust/anchor-changes/sync"
HISTORY_PATH = "/v1/trust/anchor-changes/sync-history"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
_UNSET = object()

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


def http_tests():
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

    def get_history(query, headers=None):
        return _http("GET", base + HISTORY_PATH + query, headers=headers)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        signer_did = "did:web:remote-signer"
        priv, pub = gen_keypair()
        for headers in (TA, TB):
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": pub, "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        def event(cursor):
            return {
                "cursor": cursor,
                "action": "registered",
                "did": signer_did,
                "key_version": 1,
                "public_key": pub,
                "status": "active",
                "uses": list(ALL_USES),
            }

        def build(events, after):
            signed = {
                "events": events,
                "next_after": (
                    events[-1]["cursor"] if events else after
                ),
                "signer_did": signer_did,
                "signer_key_version": 1,
            }
            signature = crypto.sign(signed, priv)
            changes = dict(signed)
            changes["signature"] = signature
            return {"changes": changes, "after": after}

        def sync(payload, headers):
            return _http("POST", base + SYNC_PATH, payload, headers=headers)

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {"error": 非空中文}
        # ---------------------------------------------------------- #
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

        q = f"?signer_did={signer_did}"
        expect_400("缺 signer_did 400", "?limit=10")
        expect_400("空 signer_did 400", "?signer_did=")
        expect_400("重复 signer_did 400",
                   f"?signer_did=a&signer_did={signer_did}")
        expect_400("未知参数 400", f"{q}&foo=1")
        expect_400("空 limit 400", f"{q}&limit=")
        expect_400("limit=0 越界 400", f"{q}&limit=0")
        expect_400("limit=201 越界 400", f"{q}&limit=201")
        expect_400("limit 带符号 400", f"{q}&limit=%2B5")
        expect_400("limit 负号 400", f"{q}&limit=-1")
        expect_400("limit 小数 400", f"{q}&limit=1.5")
        expect_400("limit Unicode 数字 400", f"{q}&limit=%D9%A5")
        expect_400("limit 非数字 400", f"{q}&limit=abc")
        expect_400("重复 limit 400", f"{q}&limit=1&limit=2")
        expect_400("空 after 400", f"{q}&after=")
        expect_400("after 负号 400", f"{q}&after=-1")
        expect_400("after 带符号 400", f"{q}&after=%2B1")
        expect_400("after 小数 400", f"{q}&after=0.5")
        expect_400("after Unicode 数字 400", f"{q}&after=%D9%A2")
        expect_400("重复 after 400", f"{q}&after=0&after=1")
        expect_400("显式空租户头 400", q, headers={"X-Tenant-ID": ""})

        # ---------------------------------------------------------- #
        # 2. 404 族：未接收非空页、跨租户
        # ---------------------------------------------------------- #
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

        expect_404("未接收任何页 404", q, headers=TA)
        # 空页不产生历史
        st, _ = sync(build([], 0), TA)
        assert st == 200
        expect_404("仅空页仍 404", q, headers=TA)

        # ---------------------------------------------------------- #
        # 3. 同步三页后查询
        # ---------------------------------------------------------- #
        page1 = build([event(1), event(2)], 0)
        page2 = build([event(3), event(4)], 2)
        page3 = build([event(5)], 4)
        st, _ = sync(page1, TA)
        assert st == 201
        st, _ = sync(page2, TA)
        assert st == 200
        st, _ = sync(page3, TA)
        assert st == 200
        # 他租户未接收 -> 404（跨租户隔离）
        expect_404("跨租户 404", q, headers=TB)

        def expect_pages(name, query, expect_list, expect_next,
                         headers=None):
            st, raw = get_history(query, headers=headers)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            ok = (
                st == 200
                and isinstance(body, dict)
                and list(body.keys()) == ["signer_did", "pages",
                                          "next_after"]
                and body["signer_did"] == signer_did
                and body["next_after"] == expect_next
                and isinstance(body["pages"], list)
                and len(body["pages"]) == len(expect_list)
            )
            if ok:
                for got, (exp_after, exp_next, exp_events) in zip(
                    body["pages"], expect_list
                ):
                    ok = ok and (
                        list(got.keys())
                        == ["after", "next_after", "digest", "events"]
                        and got["after"] == exp_after
                        and got["next_after"] == exp_next
                        and isinstance(got["after"], int)
                        and isinstance(got["next_after"], int)
                        and got["after"] < got["next_after"]
                        and isinstance(got["digest"], str)
                        and len(got["digest"]) == 64
                        and all(c in "0123456789abcdef"
                                for c in got["digest"])
                        and got["events"] == exp_events
                    )
            check(name, ok)

        ev = [[event(1), event(2)], [event(3), event(4)], [event(5)]]
        expect_pages(
            "缺省 limit=50 全量三页", q,
            [(0, 2, ev[0]), (2, 4, ev[1]), (4, 5, ev[2])], 5,
            headers=TA,
        )
        expect_pages(
            "limit=2 取前两页", f"{q}&limit=2",
            [(0, 2, ev[0]), (2, 4, ev[1])], 4,
            headers=TA,
        )
        expect_pages(
            "limit=1 单页", f"{q}&limit=1",
            [(0, 2, ev[0])], 2,
            headers=TA,
        )
        expect_pages(
            "after=2 跳过首页", f"{q}&after=2",
            [(2, 4, ev[1]), (4, 5, ev[2])], 5,
            headers=TA,
        )
        expect_pages(
            "after=2&limit=1", f"{q}&after=2&limit=1",
            [(2, 4, ev[1])], 4,
            headers=TA,
        )
        expect_pages("after=5 空页 next_after=after", f"{q}&after=5",
                     [], 5, headers=TA)
        expect_pages("after=99 空页", f"{q}&after=99", [], 99,
                     headers=TA)
        expect_pages("limit=200 边界", f"{q}&limit=200",
                     [(0, 2, ev[0]), (2, 4, ev[1]), (4, 5, ev[2])], 5,
                     headers=TA)

        # ---------------------------------------------------------- #
        # 4. 只读：不推进检查点、不记审计
        # ---------------------------------------------------------- #
        st, raw = sync(build([event(6)], 5), TA)
        body = json.loads(raw)
        check("查询后检查点未推进（续页仍从 5 衔接）",
              st == 200 and body.get("next_after") == 6
              and body.get("accepted") == 1)
        st, raw = _http("GET", f"{base}/v1/audit", headers=TA)
        audit = json.loads(raw)
        events_logged = audit.get("events", audit if isinstance(
            audit, list) else [])
        check("查询不记审计",
              not any("sync-history" in json.dumps(e, ensure_ascii=False)
                      or "sync_history" in json.dumps(e, ensure_ascii=False)
                      for e in events_logged))

        # ---------------------------------------------------------- #
        # 5. 重启后结论一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        expect_pages(
            "重启后缺省查询一致", q,
            [(0, 2, ev[0]), (2, 4, ev[1]), (4, 5, ev[2]),
             (5, 6, [event(6)])], 6,
            headers=TA,
        )
        expect_404("重启后跨租户仍 404", q, headers=TB)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def rollback_tests():
    """同步落盘失败：内存与重载状态均等于调用前，重试从原游标继续。"""
    path = tempfile.mktemp(suffix=".json")
    store = VCStore(path)
    tenant = "sync-rollback"
    signer = "did:web:sync-rollback-signer"

    def page_events(*cursors):
        return [
            {
                "cursor": c,
                "action": "registered",
                "did": signer,
                "key_version": 1,
                "public_key": "pem",
                "status": "active",
                "uses": list(ALL_USES),
            }
            for c in cursors
        ]

    digest1 = "a" * 64
    digest2 = "b" * 64
    digest3 = "c" * 64

    # 基线：首个非空页落盘成功
    created, next_after, accepted = store.sync_anchor_changes(
        tenant, signer, 0, digest1, page_events(1, 2), 2
    )
    check("回滚基线：首页 (True, 2, 2)",
          (created, next_after, accepted) == (True, 2, 2))

    def capture(s):
        return {
            "tenants": copy.deepcopy(s._tenants),  # noqa: SLF001
            "checkpoints": copy.deepcopy(  # noqa: SLF001
                s._anchor_changes_sync_checkpoints
            ),
        }

    baseline = capture(store)
    disk0 = Path(path).read_bytes()

    def install_boom(s):
        def _boom():
            raise OSError("模拟落盘失败: 磁盘已满")

        s._save_locked = _boom  # type: ignore[assignment]

    def expect_storage_error(name, fn):
        try:
            fn()
        except StorageError:
            check(f"{name}：抛 StorageError", True)
            return
        except Exception as exc:  # noqa: BLE001
            check(f"{name}：抛 StorageError（实际 {type(exc).__name__}）",
                  False)
            return
        check(f"{name}：抛 StorageError", False)

    install_boom(store)

    # 1. 既有租户续页失败：检查点/页面/租户桶全部回滚
    expect_storage_error(
        "续页落盘失败",
        lambda: store.sync_anchor_changes(
            tenant, signer, 2, digest2, page_events(3, 4), 4
        ),
    )
    check("续页失败：内存状态等于调用前", capture(store) == baseline)
    check("续页失败：磁盘字节不变", Path(path).read_bytes() == disk0)
    pages = store._tenants[tenant]["synced_anchor_change_pages"]  # noqa: SLF001
    check("续页失败：同步页不残留", list(pages[signer]) and
          len(pages[signer]) == 1)
    reopened = VCStore(path)
    check("续页失败：重载状态等于调用前", capture(reopened) == baseline)

    # 2. 新租户首页失败：不残留租户桶、检查点与临时容器
    expect_storage_error(
        "新租户首页落盘失败",
        lambda: store.sync_anchor_changes(
            "fresh-tenant", signer, 0, digest3, page_events(1), 1
        ),
    )
    check("新租户首页失败：不残留租户桶",
          "fresh-tenant" not in store._tenants)  # noqa: SLF001
    check("新租户首页失败：不残留检查点",
          "fresh-tenant"
          not in store._anchor_changes_sync_checkpoints)  # noqa: SLF001
    check("新租户首页失败：内存状态等于调用前",
          capture(store) == baseline)
    check("新租户首页失败：重载状态等于调用前",
          capture(VCStore(path)) == baseline)

    # 3. 既有租户新签名方首页失败：不残留签名方页面容器与检查点项
    expect_storage_error(
        "新签名方首页落盘失败",
        lambda: store.sync_anchor_changes(
            tenant, "did:web:other-signer", 0, digest3,
            page_events(1), 1
        ),
    )
    check("新签名方首页失败：不残留页面容器",
          "did:web:other-signer"
          not in store._tenants[tenant][  # noqa: SLF001
              "synced_anchor_change_pages"])
    check("新签名方首页失败：不残留检查点项",
          "did:web:other-signer"
          not in store._anchor_changes_sync_checkpoints[  # noqa: SLF001
              tenant])
    check("新签名方首页失败：内存状态等于调用前",
          capture(store) == baseline)

    # 4. 移除故障后重试：从原游标继续，结论与未失败一致
    del store._save_locked  # type: ignore[attr-defined]
    created, next_after, accepted = store.sync_anchor_changes(
        tenant, signer, 2, digest2, page_events(3, 4), 4
    )
    check("重试：续页从原游标继续 (False, 4, 2)",
          (created, next_after, accepted) == (False, 4, 2))
    created, next_after, accepted = store.sync_anchor_changes(
        "fresh-tenant", signer, 0, digest3, page_events(1), 1
    )
    check("重试：新租户首页从 0 继续 (True, 1, 1)",
          (created, next_after, accepted) == (True, 1, 1))

    # 历史查询反映重试后的状态
    pages, na = store.list_anchor_changes_sync_history(
        tenant, signer, 0, 50
    )
    check("重试后历史两页且 next_after=4",
          na == 4 and [p["next_after"] for p in pages] == [2, 4]
          and [p["after"] for p in pages] == [0, 2]
          and [p["digest"] for p in pages] == [digest1, digest2])

    # 重载后状态与内存一致
    reopened2 = VCStore(path)
    check("重试后重载状态一致", capture(reopened2) == capture(store))
    pages2, na2 = reopened2.list_anchor_changes_sync_history(
        tenant, signer, 0, 50
    )
    check("重载后历史一致", (pages2, na2) == (pages, na))

    # 只读校验：历史查询不推进检查点（重放仍按幂等处理）
    store.list_anchor_changes_sync_history(tenant, signer, 0, 1)
    created, next_after, accepted = store.sync_anchor_changes(
        tenant, signer, 2, digest2, page_events(3, 4), 4
    )
    check("历史查询不推进检查点（重放 accepted=0）",
          (created, next_after, accepted) == (False, 4, 0))

    if os.path.exists(path):
        os.remove(path)


def main():
    http_tests()
    rollback_tests()
    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
