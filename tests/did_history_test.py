#!/usr/bin/env python3
"""DID 生命周期历史（只读）端到端测试。

覆盖 GET /v1/dids/{did}/history?limit=&after=：
- 200 响应恰含 did、events、next_after；事件恰含
  {action,status,reason,updated_at,audit_seq,audit_timestamp,cursor}，
  按 cursor 升序；
- 注册追加 did.created/active/reason:null（updated_at 取 created_at），
  首次停用追加 did.deactivated/deactivated/首次裁剪 reason；幂等注册、
  重复停用、400/404 等失败路径不追加；
- audit_seq/audit_timestamp 关联对应审计事件，audit_timestamp 与
  updated_at 为同一 Unix 秒；
- cursor 租户内跨 DID 持久递增、租户间各自从 1 计起，并与其他历史
  （密钥生命周期等）游标空间隔离；
- limit/after 仅允许这两个参数：缺省 50/0、limit 1..200、after 非负，
  重复/空值/空白/符号/小数/布尔词/Unicode 数字/未知参数均 400；空页
  next_after=after；
- 未知/跨租户 DID 404，显式空租户头 400，缺省 default；
- 纯只读不记审计；跨重启事件与 cursor 稳定；
- 旧状态按 (created_at, did, 动作) 稳定补事件，补录项 audit 为 null；
  无写重启 cursor 稳定；
- 注册/停用变更与历史、游标、审计同锁原子落盘，失败全回滚。

直接运行：python3 tests/did_history_test.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8991
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

HISTORY_FIELDS = {"did", "events", "next_after"}
EVENT_FIELDS = {
    "action", "status", "reason", "updated_at",
    "audit_seq", "audit_timestamp", "cursor",
}


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def start_server(store=STORE, port=PORT):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def main():
    failures = []

    def check(name, cond):
        if cond:
            print("PASS:", name)
        else:
            print("FAIL:", name)
            failures.append(name)

    proc = start_server()
    try:
        T = {}
        OT = {"X-Tenant-ID": "other"}
        EMPTY_TENANT = {"X-Tenant-ID": ""}

        def register(handle, headers=T):
            st, r = _http(
                "POST", f"{BASE}/v1/dids",
                {"method": "example", "public_key": handle},
                headers=headers,
            )
            assert st == 201, (st, r)
            return r

        def history(did, query="", headers=T):
            suffix = f"?{query}" if query else ""
            return _http(
                "GET", f"{BASE}/v1/dids/{did}/history{suffix}",
                headers=headers,
            )

        def deact(did, payload=None, headers=T):
            return _http(
                "POST", f"{BASE}/v1/dids/{did}/deactivate",
                payload=payload if payload is not None else {},
                headers=headers,
            )

        def audit(after=0, limit=200, headers=T):
            st, r = _http(
                "GET",
                f"{BASE}/v1/audit?limit={limit}&after={after}",
                headers=headers,
            )
            assert st == 200, (st, r)
            return r["events"]

        def unix_seconds(ztext):
            return int(
                datetime.strptime(ztext, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc).timestamp()
            )

        # ---------------------------------------------------------- #
        # 1. 注册事件
        # ---------------------------------------------------------- #
        a = register("hist-a")
        alice = a["did"]
        st, got = _http("GET", f"{BASE}/v1/dids/{alice}")
        assert st == 200
        created_at = got["created_at"]
        st, r = history(alice)
        check("注册后 200 且响应恰含三键",
              st == 200 and set(r) == HISTORY_FIELDS
              and r["did"] == alice and r["next_after"] == 1)
        evs = r["events"]
        check("注册后恰一条事件、事件七键、cursor=1",
              len(evs) == 1 and set(evs[0]) == EVENT_FIELDS
              and evs[0]["cursor"] == 1)
        created_ev = evs[0]
        check("注册事件 did.created/active/null/created_at",
              created_ev["action"] == "did.created"
              and created_ev["status"] == "active"
              and created_ev["reason"] is None
              and created_ev["updated_at"] == created_at
              and Z_RE.match(created_ev["updated_at"]))
        check("注册事件关联 did.created 审计且同秒",
              isinstance(created_ev["audit_seq"], int)
              and isinstance(created_ev["audit_timestamp"], int)
              and created_ev["audit_timestamp"]
              == unix_seconds(created_ev["updated_at"]))
        audit_created = [
            e for e in audit()
            if e["seq"] == created_ev["audit_seq"]
        ]
        check("audit_seq 指向 did.created 审计",
              len(audit_created) == 1
              and audit_created[0]["action"] == "did.created"
              and audit_created[0]["timestamp"]
              == created_ev["audit_timestamp"])

        # 同句柄幂等注册不追加历史（但仍记审计）
        st, r2 = _http(
            "POST", f"{BASE}/v1/dids",
            {"method": "example", "public_key": "hist-a"},
        )
        assert st == 201 and r2["did"] == alice
        st, r = history(alice)
        check("幂等注册不追加历史", len(r["events"]) == 1)

        # ---------------------------------------------------------- #
        # 2. 首次停用事件
        # ---------------------------------------------------------- #
        st, dr = deact(alice, {"reason": "  业务终止  "})
        assert st == 200, dr
        check("停用响应首次裁剪原因", dr["reason"] == "业务终止")
        st, r = history(alice)
        evs = r["events"]
        check("停用后恰两条事件、按 cursor 升序",
              st == 200 and len(evs) == 2
              and [e["cursor"] for e in evs] == [1, 2]
              and r["next_after"] == 2)
        deact_ev = evs[1]
        check("停用事件 did.deactivated/deactivated/首次原因/首次时间",
              set(deact_ev) == EVENT_FIELDS
              and deact_ev["action"] == "did.deactivated"
              and deact_ev["status"] == "deactivated"
              and deact_ev["reason"] == "业务终止"
              and deact_ev["updated_at"] == dr["updated_at"]
              and Z_RE.match(deact_ev["updated_at"]))
        check("停用事件关联 did.deactivated 审计且同秒",
              isinstance(deact_ev["audit_seq"], int)
              and deact_ev["audit_seq"] > created_ev["audit_seq"]
              and deact_ev["audit_timestamp"]
              == unix_seconds(deact_ev["updated_at"]))
        audit_deact = [
            e for e in audit() if e["seq"] == deact_ev["audit_seq"]
        ]
        check("audit_seq 指向 did.deactivated 审计",
              len(audit_deact) == 1
              and audit_deact[0]["action"] == "did.deactivated"
              and audit_deact[0]["timestamp"]
              == deact_ev["audit_timestamp"])

        # 重复停用（含非法 reason）不追加历史
        seq_before = audit()[-1]["seq"]
        for body in ({"reason": "新理由"}, {"reason": None}, {}):
            st2, _ = deact(alice, body)
            assert st2 == 200
        st, r = history(alice)
        check("重复停用不追加历史",
              len(r["events"]) == 2 and r["events"][1]["reason"] == "业务终止")
        check("重复停用仍记审计（历史接口本身不记）",
              len(audit(after=seq_before)) == 3)

        # ---------------------------------------------------------- #
        # 3. 失败路径不追加
        # ---------------------------------------------------------- #
        bob = register("hist-b")["did"]
        unknown = "did:example:" + "0" * 32
        check("未知 DID 404", history(unknown)[0] == 404)
        check("跨租户 DID 404", history(alice, headers=OT)[0] == 404)
        check("显式空租户头 400",
              history(bob, headers=EMPTY_TENANT)[0] == 400)
        st, _ = deact(bob, {"reason": None})
        check("非法停用 400", st == 400)
        st, r = history(bob)
        check("非法停用不追加（仅注册事件）",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["action"] == "did.created")

        # ---------------------------------------------------------- #
        # 4. 参数校验（仅 limit、after）
        # ---------------------------------------------------------- #
        bad_queries = [
            "limit=", "after=", "limit=%201", "after=%200", "limit=0",
            "limit=201", "limit=-1", "limit=1.5",
            "limit=true", "limit=abc", "limit=1%2b", "limit=%e0%a5%91",
            "after=-1", "after=1.0", "after=x", "after=%ef%bc%90",
            "limit=1&limit=2", "after=0&after=1",
            "limit=1&foo=2", "foo=1", "version=1",
        ]
        for query in bad_queries:
            st2, r2 = history(bob, query)
            check(f"非法参数 400: ?{query}",
                  st2 == 400 and "error" in r2)

        # 合法缺省/边界
        st, r = history(bob)
        check("缺省参数 200 返回注册事件",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["action"] == "did.created"
              and r["next_after"] == r["events"][0]["cursor"])
        st, r = history(bob, "after=999")
        check("空页 next_after=after",
              st == 200 and r["events"] == [] and r["next_after"] == 999)
        st, r = history(bob, "limit=1&after=0")
        check("limit=1 注册事件",
              st == 200 and len(r["events"]) == 1
              and r["next_after"] == r["events"][0]["cursor"])
        st, r = history(alice, "after=1")
        check("after 排除 ≤ 游标（仅停用事件）",
              st == 200 and [e["action"] for e in r["events"]]
              == ["did.deactivated"] and r["next_after"] == 2)
        st, r = history(alice, "after=2")
        check("空页 next_after=after",
              st == 200 and r["events"] == [] and r["next_after"] == 2)
        st, r = history(alice, "limit=1&after=0")
        check("limit=1 只取首页", len(r["events"]) == 1
              and r["events"][0]["action"] == "did.created")
        st, r = history(alice, "limit=200")
        check("limit=200 合法", st == 200 and len(r["events"]) == 2)

        # ---------------------------------------------------------- #
        # 5. 游标：租户内跨 DID 递增、租户间独立、与其他历史隔离
        # ---------------------------------------------------------- #
        carol = register("hist-c")["did"]
        st, r = history(carol)
        check("租户内跨 DID 游标持续递增（carol cursor=4）",
              r["events"][0]["cursor"] == 4 and r["next_after"] == 4)

        other_alice = register("other-a", headers=OT)["did"]
        st, r = history(other_alice, headers=OT)
        check("他租户游标独立从 1 计起",
              r["events"][0]["cursor"] == 1 and r["next_after"] == 1)

        # 与密钥生命周期历史游标隔离：轮换 bob 后，DID 历史只有注册事件，
        # keys/history 的 v2 游标与 DID 历史游标互不影响。
        st, _ = _http(
            "POST", f"{BASE}/v1/dids/{bob}/keys/rotate",
            {"key_handle": "hist-b-v2"},
        )
        assert st == 200
        st, _ = _http(
            "POST", f"{BASE}/v1/dids/{bob}/keys/1/revoke",
            {"reason": "旧版停用"},
        )
        assert st == 200
        st, r = history(bob)
        check("密钥轮换/吊销不写入 DID 历史",
              [e["action"] for e in r["events"]] == ["did.created"]
              and r["events"][0]["cursor"] == 3)
        st, kh = _http(
            "GET", f"{BASE}/v1/dids/{bob}/keys/history?limit=50&after=0")
        assert st == 200
        check("密钥生命周期历史独立游标空间",
              [e["cursor"] for e in kh["events"]] == [2, 4, 5])

        # ---------------------------------------------------------- #
        # 6. 纯只读：GET 前后审计不增加
        # ---------------------------------------------------------- #
        seq_now = audit()[-1]["seq"]
        history(alice, "limit=1&after=0")
        history(alice, "after=999")
        history(unknown)
        check("历史查询不记审计", audit(after=seq_now) == [])

        # 记录重启前的期望快照
        st, before = history(alice, "limit=200")
        assert st == 200
        st, before_b = history(bob, "limit=200")
        assert st == 200
        st, before_c = history(carol, "limit=200")
        assert st == 200

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 7. 重启持久化：事件与 cursor 稳定
    # -------------------------------------------------------------- #
    proc2 = start_server()
    try:
        st, after_restart = history(alice, "limit=200")
        check("重启后 alice 事件与 cursor 稳定",
              st == 200 and after_restart == before)
        st, after_b = history(bob, "limit=200")
        check("重启后 bob DID 历史不受密钥操作影响",
              st == 200 and after_b == before_b)
        st, after_c = history(carol, "limit=200")
        check("重启后 carol cursor 稳定", st == 200 and after_c == before_c)

        # 重启后新注册的 DID 游标继续递增（不与重建 cursor 冲突）
        dave = register("hist-d")["did"]
        st, r = history(dave)
        check("重启后新 DID 游标继续持久递增",
              r["events"][0]["cursor"] == 5)
    finally:
        proc2.terminate()
        proc2.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 8. 旧状态兼容：旧文件无 did_history 时稳定补录
    # -------------------------------------------------------------- #
    from vcbackend.store import VCStore  # noqa: E402

    p_old = tempfile.mktemp(suffix=".json")
    s_old = VCStore(p_old)
    d1 = s_old.create_did("t", "example", "old-1")
    d2 = s_old.create_did("t", "example", "old-2")
    s_old.deactivate_did("t", d1.did, reason="旧停用原因")
    bucket = s_old._bucket_locked("t")  # noqa: SLF001
    # 手工删除历史与游标，模拟旧版本状态文件
    bucket["did_history"] = {}
    del s_old._did_history_cursors["t"]  # noqa: SLF001
    s_old._save_locked()  # noqa: SLF001

    s_reload = VCStore(p_old)
    evs1, na1 = s_reload.list_did_history("t", d1.did, 0, 50)
    evs2, _ = s_reload.list_did_history("t", d2.did, 0, 50)
    check("旧状态补 did.created 与 did.deactivated",
          [(e.action, e.status) for e in evs1]
          == [("did.created", "active"),
              ("did.deactivated", "deactivated")]
          and evs1[1].reason == "旧停用原因"
          and evs1[0].updated_at == d1.created_at
          and [(e.action, e.status) for e in evs2]
          == [("did.created", "active")])
    check("补录项 audit 两字段为 null",
          all(e.audit_seq is None and e.audit_timestamp is None
              for e in evs1 + evs2))
    cursors_first_load = sorted(
        e.cursor for e in evs1 + evs2
    )
    check("补录 cursor 为租户内正整数且唯一",
          cursors_first_load == [1, 2, 3])

    # 无写操作再次重启：cursor 按相同顺序重建为相同值
    s_reload2 = VCStore(p_old)
    got = []
    for did in (d1.did, d2.did):
        rows, _ = s_reload2.list_did_history("t", did, 0, 50)
        got.extend((did, e.action, e.cursor) for e in rows)
    check("无写重启补录 cursor 稳定",
          sorted(c for _, _, c in got) == [1, 2, 3])

    # 补录顺序按 (created_at, did)：用直接存储层构造 created_at 乱序
    p_old2 = tempfile.mktemp(suffix=".json")
    s_old2 = VCStore(p_old2)
    x = s_old2.create_did("t", "example", "order-x")
    y = s_old2.create_did("t", "example", "order-y")
    b2 = s_old2._bucket_locked("t")  # noqa: SLF001
    # 让后创建的 y 拥有更早的 created_at
    b2["dids"][y.did]["created_at"] = "2000-01-01T00:00:00Z"
    b2["did_history"] = {}
    s_old2._did_history_cursors = {}  # noqa: SLF001
    s_old2._save_locked()  # noqa: SLF001
    s_o2 = VCStore(p_old2)
    ex, _ = s_o2.list_did_history("t", x.did, 0, 50)
    ey, _ = s_o2.list_did_history("t", y.did, 0, 50)
    check("补录按 (created_at, did) 排序分配 cursor",
          ey[0].cursor == 1 and ex[0].cursor == 2)

    # -------------------------------------------------------------- #
    # 9. 落盘失败：状态、历史、游标、审计全回滚
    # -------------------------------------------------------------- #
    p_rb = tempfile.mktemp(suffix=".json")
    s_rb = VCStore(p_rb)
    d = s_rb.create_did("t", "example", "rb-did")

    def _boom():
        raise OSError("模拟落盘失败")

    s_rb._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        s_rb.deactivate_did("t", d.did, reason="回滚原因")
    except OSError:
        raised = True
    check("停用落盘失败抛错", raised)
    rows, _ = s_rb.list_did_history("t", d.did, 0, 50)
    check("落盘失败历史不追加",
          [e.action for e in rows] == ["did.created"])
    check("落盘失败游标不前进",
          s_rb._did_history_cursors.get("t") == 1)  # noqa: SLF001
    check("落盘失败不记 did.deactivated 审计",
          all(e.action != "did.deactivated"
              for e in s_rb.list_audit("t", 0, 200)[0]))
    rec = s_rb._bucket_locked("t")["dids"][d.did]  # noqa: SLF001
    check("落盘失败停用状态回滚（仍 active）",
          rec.get("status") != "deactivated")

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
