#!/usr/bin/env python3
"""DID 注册/停用历史（只读）端到端测试。

覆盖 GET /v1/dids/{did}/history?limit=&after=：
- 200 响应恰含 did、events、next_after；事件恰含
  {action,status,reason,updated_at,audit_seq,audit_timestamp,cursor}，
  按 cursor 升序；
- 注册事件 did.created/active/null/UTC 秒 Z；首次停用事件
  did.deactivated/deactivated/首次裁剪 reason/首次 UTC 秒 Z；二者均关联
  审计 seq、audit_timestamp 与 updated_at 同秒；
- 幂等注册/重复停用（仍记审计）与失败路径不追加，停用事件保持首次值；
- cursor 租户内跨 DID 持久递增、租户间各自从 1 计起，并与密钥生命周期
  等其他历史游标空间隔离；
- limit/after 分页：缺省 50/0，仅允许 limit、after，重复/空白/符号/
  小数/布尔词/Unicode 数字/未知参数一律 400；空页 next_after=after；
- 未知/跨租户 DID 404，显式空租户头 400，缺省 default；
- 纯只读：不记审计、不触发落盘；跨重启事件与 cursor 稳定；
- 旧状态按 (created_at, did, 动作) 稳定补 did.created/did.deactivated，
  补录项 audit 两字段为 null，无写重启 cursor 稳定；
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

PORT = 8993
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


def start_server(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def unix_seconds(z_text):
    return int(
        datetime.strptime(z_text, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc).timestamp()
    )


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "dh-a"}
    T2 = {"X-Tenant-ID": "dh-b"}

    def history(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/history"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def audit(headers=None, query="limit=200"):
        return _http("GET", f"{base}/v1/audit?{query}", headers=headers)

    try:
        # ---- 准备：T1 注册 A、B；A 轮换一次（验证游标空间隔离）----
        st, a = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "dh-handle-a"},
                      headers=T1)
        assert st == 201, a
        did_a = a["did"]
        st, ag = _http("GET", f"{base}/v1/dids/{did_a}", headers=T1)
        assert st == 200, ag
        created_at_a = ag["created_at"]
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                      {"key_handle": "dh-handle-a-v2"}, headers=T1)
        assert st == 200

        st, b = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "dh-handle-b"},
                      headers=T1)
        assert st == 201, b
        did_b = b["did"]

        st, c = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "dh-handle-c"},
                      headers=T2)
        assert st == 201, c
        did_c = c["did"]

        # ---- 1. 活动 DID：仅一条 did.created，结构/字段/键序严格 ----
        st, h = history(did_a, headers=T1)
        ok = (
            st == 200 and set(h) == HISTORY_FIELDS and h["did"] == did_a
            and len(h["events"]) == 1
            and all(set(e) == EVENT_FIELDS for e in h["events"])
        )
        check("200 恰含 did/events/next_after，活动 DID 1 事件且七字段", ok)
        raw_text = json.dumps(h, ensure_ascii=False)
        check("顶层键序 did、events、next_after",
              list(h.keys()) == ["did", "events", "next_after"])
        check("事件键序 action、status、reason、updated_at、audit_seq、"
              "audit_timestamp、cursor",
              list(h["events"][0].keys())
              == ["action", "status", "reason", "updated_at",
                  "audit_seq", "audit_timestamp", "cursor"])
        e = h["events"][0]
        check("注册事件 did.created/active/null/created_at(UTC 秒 Z)",
              e["action"] == "did.created" and e["status"] == "active"
              and e["reason"] is None and e["updated_at"] == created_at_a
              and bool(Z_RE.match(e["updated_at"]))
              and isinstance(e["cursor"], int) and e["cursor"] >= 1)
        check("next_after 为末项 cursor", h["next_after"] == e["cursor"])

        # ---- 2. audit 关联且同秒 ----
        st, au = audit(headers=T1)
        assert st == 200
        ev = {x["seq"]: x for x in au["events"]}.get(e["audit_seq"])
        check("注册事件关联 did.created 审计且 timestamp/updated_at 同秒",
              isinstance(e["audit_seq"], int) and ev is not None
              and ev["action"] == "did.created"
              and e["audit_timestamp"] == ev["timestamp"]
              and unix_seconds(e["updated_at"]) == ev["timestamp"])

        # ---- 3. 首次停用追加 did.deactivated（首次裁剪 reason/时间）----
        st, d = _http("POST", f"{base}/v1/dids/{did_a}/deactivate",
                      {"reason": "  业务关停  "}, headers=T1)
        assert st == 200, d
        first_at = d["updated_at"]
        st, h = history(did_a, headers=T1)
        check("首次停用后共 2 条事件、按 cursor 升序",
              st == 200 and len(h["events"]) == 2
              and [x["cursor"] for x in h["events"]]
              == sorted(x["cursor"] for x in h["events"]))
        e1, e2 = h["events"]
        check("停用事件 did.deactivated/deactivated/裁剪 reason/首次时间",
              e2["action"] == "did.deactivated"
              and e2["status"] == "deactivated"
              and e2["reason"] == "业务关停"
              and e2["updated_at"] == first_at
              and bool(Z_RE.match(e2["updated_at"])))
        ev2 = {x["seq"]: x for x in au["events"]}
        st, au2 = audit(headers=T1)
        ev2 = {x["seq"]: x for x in au2["events"]}.get(e2["audit_seq"])
        check("停用事件关联 did.deactivated 审计且同秒",
              isinstance(e2["audit_seq"], int) and ev2 is not None
              and ev2["action"] == "did.deactivated"
              and e2["audit_timestamp"] == ev2["timestamp"]
              and unix_seconds(e2["updated_at"]) == ev2["timestamp"]
              and e2["cursor"] > e1["cursor"])

        # ---- 4. 幂等注册/重复停用（仍记审计）不追加；失败路径不追加 ----
        st, _ = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "dh-handle-a"},
                      headers=T1)
        assert st in (200, 201)
        for body in ({"reason": "新理由"}, {"reason": None},
                     {"reason": "   "}, {}):
            st2, _ = _http("POST", f"{base}/v1/dids/{did_a}/deactivate",
                           body, headers=T1)
            assert st2 == 200, (body, st2)
        # 失败路径：未知 DID 停用 404、活动 DID 非法 reason 400
        unknown = "did:example:" + "0" * 32
        check("未知 DID 停用 404",
              _http("POST", f"{base}/v1/dids/{unknown}/deactivate", {},
                    headers=T1)[0] == 404)
        check("活动 DID 非法 reason 400",
              _http("POST", f"{base}/v1/dids/{did_b}/deactivate",
                    {"reason": 123}, headers=T1)[0] == 400)
        st, h2 = history(did_a, headers=T1)
        check("幂等注册/重复停用/失败后仍为 2 条事件",
              st == 200 and len(h2["events"]) == 2)
        check("停用事件保持首次 reason/时间/cursor",
              (h2["events"][1]["reason"],
               h2["events"][1]["updated_at"],
               h2["events"][1]["cursor"])
              == ("业务关停", first_at, e2["cursor"]))
        st, hb = history(did_b, headers=T1)
        check("活动 DID B 仅 did.created 一条",
              st == 200 and len(hb["events"]) == 1
              and hb["events"][0]["action"] == "did.created")

        # 幂等重试确实仍记审计（历史不追加）
        deact_audits = [x for x in audit(headers=T1)[1]["events"]
                        if x["action"] == "did.deactivated"
                        and x["resource_id"] == did_a]
        check("4 次重复停用每次记 did.deactivated 审计（共 5）",
              len(deact_audits) == 5)

        # ---- 5. cursor 租户内跨 DID 递增、与密钥生命周期隔离、租户独立 ----
        cursor_a = [x["cursor"] for x in h2["events"]]
        cursor_b = hb["events"][0]["cursor"]
        check("租户内跨 DID cursor 按追加顺序递增（B 注册晚于 A 创建、"
              "早于 A 停用）",
              cursor_a == [1, 3] and cursor_b == 2)
        st, kl = _http("GET", f"{base}/v1/dids/{did_a}/keys/history",
                       headers=T1)
        check("DID 历史与密钥生命周期游标空间隔离",
              st == 200 and [x["cursor"] for x in kl["events"]] == [1, 2]
              and cursor_a == [1, 3])
        st, hc = history(did_c, headers=T2)
        check("另一租户 cursor 从 1 重新计起",
              st == 200 and hc["events"][0]["cursor"] == 1)
        check("跨租户 DID 不可探测 -> 404",
              history(did_a, headers=T2)[0] == 404)
        check("显式空 X-Tenant-ID -> 400",
              history(did_a, headers={"X-Tenant-ID": ""})[0] == 400)
        check("未知 DID -> 404", history(unknown, headers=T1)[0] == 404)
        st, d0 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "dh-default"})
        assert st == 201
        st, h0 = history(d0["did"])
        check("缺省租户头按 default，游标独立从 1 起",
              st == 200 and h0["events"][0]["cursor"] == 1)

        # ---- 6. 分页与参数校验 ----
        st, page = history(did_a, headers=T1, query="limit=1")
        check("limit=1 返回 1 项且 next_after 为该项 cursor",
              st == 200 and [x["cursor"] for x in page["events"]]
              == cursor_a[:1] and page["next_after"] == cursor_a[0])
        st, page = history(did_a, headers=T1,
                           query=f"limit=1&after={cursor_a[0]}")
        check("after 排除 cursor 不大于其值的事件",
              st == 200 and [x["cursor"] for x in page["events"]]
              == [cursor_a[1]] and page["next_after"] == cursor_a[1])
        st, page = history(did_a, headers=T1, query="after=999999")
        check("空页 events=[] 且 next_after 等于 after",
              st == 200 and page["events"] == []
              and page["next_after"] == 999999)
        st, page = history(did_b, headers=T1, query="after=5")
        check("无命中时空页 next_after=after",
              st == 200 and page["events"] == []
              and page["next_after"] == 5)
        st, page = history(did_a, headers=T1)
        check("缺省 limit=50 单 DID 事件一页返回",
              st == 200 and len(page["events"]) == 2
              and page["next_after"] == cursor_a[-1])

        def p400(query, name):
            st2, r = history(did_a, headers=T1, query=query)
            check(name, st2 == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        p400("limit=0", "limit=0 -> 400")
        p400("limit=201", "limit=201 -> 400")
        p400("limit=1&limit=2", "重复 limit -> 400")
        p400("after=1&after=2", "重复 after -> 400")
        p400("limit=", "空 limit -> 400")
        p400("after=", "空 after -> 400")
        p400("limit=%201", "前导空白 limit -> 400")
        p400("limit=1.5", "小数 limit -> 400")
        p400("limit=true", "布尔词 limit -> 400")
        p400("limit=-1", "符号 limit -> 400")
        p400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        p400("after=-1", "负 after -> 400")
        p400("after=abc", "字母 after -> 400")
        p400("foo=1", "未知参数 -> 400")
        p400("limit=1&foo=1", "夹带未知参数 -> 400")
        p400("status=active", "其他历史允许的 status 在本端点未知 -> 400")

        # ---- 7. 只读：不记审计、不触发落盘 ----
        st, before = audit(headers=T1)
        n_before = len(before["events"])
        mtime_before = os.path.getmtime(store_path)
        for query in ("", "limit=1", f"after={cursor_a[1]}",
                      "limit=1&after=0", "foo="):
            history(did_a, headers=T1, query=query)
        history(did_b, headers=T1)
        history(unknown, headers=T1)
        time.sleep(0.05)
        check("历史查询不记审计",
              len(audit(headers=T1)[1]["events"]) == n_before)
        check("只读查询不触发落盘（文件 mtime 不变）",
              os.path.getmtime(store_path) == mtime_before)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 跨重启：事件与 cursor 稳定，新注册/停用接续递增 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = history(did_a, headers=T1)
        saved = [x["cursor"] for x in h["events"]]
        check("重启后 A 的事件与 cursor 稳定",
              st == 200 and len(h["events"]) == 2 and saved == [1, 3]
              and [x["action"] for x in h["events"]]
              == ["did.created", "did.deactivated"])
        st, dd = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "dh-handle-d"},
                       headers=T1)
        assert st == 201
        st, hd = history(dd["did"], headers=T1)
        check("重启后新注册 cursor 接续旧最大值",
              hd["events"][0]["cursor"] == 4)
        st, _ = _http("POST", f"{base}/v1/dids/{dd['did']}/deactivate",
                      {"reason": "d 关停"}, headers=T1)
        assert st == 200
        st, hd = history(dd["did"], headers=T1)
        check("重启后首次停用 cursor 继续递增、关联审计",
              [x["cursor"] for x in hd["events"]] == [4, 5]
              and hd["events"][1]["action"] == "did.deactivated"
              and hd["events"][1]["reason"] == "d 关停"
              and hd["events"][1]["audit_seq"] is not None)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 旧状态迁移：按 (created_at, did, 动作) 稳定补录 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "legacy"}
    try:
        st, ld = _http("POST", f"{lbase}/v1/dids",
                       {"method": "example", "public_key": "leg-a"},
                       headers=L)
        assert st == 201
        leg_did = ld["did"]
        st, _ = _http("POST", f"{lbase}/v1/dids/{leg_did}/deactivate",
                      {"reason": "旧停用"}, headers=L)
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    raw = json.load(open(legacy_path, encoding="utf-8"))
    lbucket = raw["tenants"]["legacy"]
    # 手工加入两个旧 DID：字典序更靠后的 B 时间更早，验证按 created_at
    # 而非 did 排序；A 活动、B 已停用（B 需补 created+deactivated 两条）。
    did_early = "did:example:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    did_late = "did:example:cccccccccccccccccccccccccccccccc"

    def legacy_row(created_at, deactivated=False):
        row = {
            "method": "example",
            "public_key": "PUB",
            "submitted_public_key": "h",
            "created_at": created_at,
            "private_key_pem": "priv",
            "key_mode": "server",
            "key_handle": "h",
            "key_version": 1,
            "key_history": [
                {"version": 1, "key_handle": "h", "public_key": "PUB",
                 "private_key_pem": "priv"}
            ],
        }
        if deactivated:
            row["status"] = "deactivated"
            row["deactivate_reason"] = "旧状态停用"
            row["deactivated_at"] = "2025-02-02T00:00:00Z"
        return row

    lbucket["dids"][did_early] = legacy_row(
        "2025-01-01T00:00:00Z", deactivated=True)
    lbucket["dids"][did_late] = legacy_row(
        "2025-03-03T00:00:00Z", deactivated=False)
    # 删除 DID 历史命名空间与游标，模拟旧版本状态文件
    lbucket["did_history"] = {}
    raw.pop("did_history_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        # leg_did（2026 现在）也缺历史；补录顺序应为：
        # early created/deactivated（01-01）、late created（03-03）、
        # leg_did created/deactivated（当前时间最晚）
        st, he = _http(
            "GET", f"{lbase}/v1/dids/{did_early}/history", headers=L
        )
        check("旧停用 DID 补 created+deactivated 两条、audit=null、cursor 1/2",
              st == 200 and len(he["events"]) == 2
              and [(x["action"], x["status"]) for x in he["events"]]
              == [("did.created", "active"),
                  ("did.deactivated", "deactivated")]
              and [x["cursor"] for x in he["events"]] == [1, 2]
              and he["events"][0]["updated_at"] == "2025-01-01T00:00:00Z"
              and he["events"][0]["reason"] is None
              and he["events"][1]["reason"] == "旧状态停用"
              and he["events"][1]["updated_at"] == "2025-02-02T00:00:00Z"
              and all(x["audit_seq"] is None
                      and x["audit_timestamp"] is None for x in he["events"]))
        st, hl = _http(
            "GET", f"{lbase}/v1/dids/{did_late}/history", headers=L
        )
        check("旧活动 DID 补一条 created，按 created_at 排在 B 两条之后",
              st == 200 and len(hl["events"]) == 1
              and hl["events"][0]["cursor"] == 3
              and hl["events"][0]["updated_at"] == "2025-03-03T00:00:00Z")
        st, hg = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/history", headers=L
        )
        check("当前时间注册的旧 DID 补录排在最后（cursor 4/5）",
              st == 200 and [x["cursor"] for x in hg["events"]] == [4, 5]
              and [x["action"] for x in hg["events"]]
              == ["did.created", "did.deactivated"]
              and all(x["audit_seq"] is None for x in hg["events"]))
        saved_early = [x["cursor"] for x in he["events"]]
        saved_late = [x["cursor"] for x in hl["events"]]
        saved_leg = [x["cursor"] for x in hg["events"]]
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 不触发任何写操作直接重启：cursor 必须重建为相同值，GET 不落盘
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, he = _http(
            "GET", f"{lbase}/v1/dids/{did_early}/history", headers=L)
        st2, hl = _http(
            "GET", f"{lbase}/v1/dids/{did_late}/history", headers=L)
        st3, hg = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/history", headers=L)
        check("无写重启后补录 cursor 全部稳定",
              [x["cursor"] for x in he["events"]] == saved_early
              and [x["cursor"] for x in hl["events"]] == saved_late
              and [x["cursor"] for x in hg["events"]] == saved_leg)
        raw2 = json.load(open(legacy_path, encoding="utf-8"))
        check("只读查询不触发落盘（内存补录未写入）",
              "did_history_cursors" not in raw2
              and raw2["tenants"]["legacy"]["did_history"] == {})
        # 触发一次写：补录随原子写落盘，新事件 cursor 接续为 6
        st, nx = _http("POST", f"{lbase}/v1/dids",
                       {"method": "example", "public_key": "leg-new"},
                       headers=L)
        assert st == 201
        st, hn = _http(
            "GET", f"{lbase}/v1/dids/{nx['did']}/history", headers=L)
        check("写后补录落盘且新注册 cursor 接续为 6",
              st == 200 and hn["events"][0]["cursor"] == 6
              and hn["events"][0]["audit_seq"] is not None)
        raw3 = json.load(open(legacy_path, encoding="utf-8"))
        check("补录已随原子写落盘",
              "did_history_cursors" in raw3
              and raw3["did_history_cursors"].get("legacy") == 6)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 10. 直连 store：落盘失败时状态/历史/游标/审计全回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    dstore = VCStore(direct_path)
    d = dstore.create_did("rb", "example", "rb-handle")
    events, _ = dstore.list_did_history("rb", d.did, 0, 50)
    assert len(events) == 1 and events[0].cursor == 1

    def _boom():
        raise OSError("模拟落盘失败")

    dstore._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        dstore.deactivate_did("rb", d.did, reason="停用回滚测试")
    except OSError:
        raised = True
    check("停用落盘失败抛错", raised)
    check("回滚后 DID 仍 active",
          dstore.get_did_status("rb", d.did).status == "active")
    events, _ = dstore.list_did_history("rb", d.did, 0, 50)
    check("回滚后 DID 历史仍仅 did.created 一条",
          len(events) == 1 and events[0].action == "did.created")
    check("回滚后 DID 历史游标未前进（仍 1）",
          dstore._did_history_cursors.get("rb", 0) == 1)  # noqa: SLF001
    check("回滚后不记 did.deactivated 审计",
          all(x.action != "did.deactivated"
              for x in dstore.list_audit("rb", 0, 200)[0]))

    del dstore._save_locked
    rec = dstore.deactivate_did("rb", d.did, reason="停用回滚测试")
    check("恢复后停用成功并返回首次原因",
          rec.status == "deactivated" and rec.reason == "停用回滚测试")
    events, _ = dstore.list_did_history("rb", d.did, 0, 50)
    check("恢复后历史含 did.deactivated 且 cursor=2",
          [(x.action, x.cursor) for x in events]
          == [("did.created", 1), ("did.deactivated", 2)]
          and events[1].reason == "停用回滚测试"
          and events[1].audit_seq is not None)

    dp = start_server(PORT + 2, direct_path)
    try:
        db = f"http://127.0.0.1:{PORT + 2}"
        st, h = _http("GET", f"{db}/v1/dids/{d.did}/history",
                      headers={"X-Tenant-ID": "rb"})
        check("回滚场景重启后历史与 cursor 一致",
              st == 200 and [x["cursor"] for x in h["events"]] == [1, 2]
              and [x["action"] for x in h["events"]]
              == ["did.created", "did.deactivated"])
    finally:
        dp.terminate()
        dp.wait(timeout=10)

    # ---- 11. 现有入口行为保持不变（抽查 status / keys/history）----
    proc = start_server(PORT, store_path)
    try:
        st, s = _http("GET", f"{base}/v1/dids/{did_a}/status", headers=T1)
        check("GET status 行为不变",
              st == 200 and s == {
                  "did": did_a, "status": "deactivated",
                  "reason": "业务关停", "updated_at": first_at})
        st, kl = _http("GET",
                       f"{base}/v1/dids/{did_a}/keys/history", headers=T1)
        check("keys/history 行为与游标空间不变（1/2）",
              st == 200 and [x["cursor"] for x in kl["events"]] == [1, 2]
              and [x["action"] for x in kl["events"]]
              == ["did.created", "key.rotated"])
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("DID 注册/停用历史测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
