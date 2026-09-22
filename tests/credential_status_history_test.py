#!/usr/bin/env python3
"""GET /v1/credentials/{credential_id}/status/history 只读凭证状态历史
的端到端测试（兼容既有签发、验签、状态与吊销协议）。

覆盖：
- 未知凭证 404、跨租户 404、显式空 X-Tenant-ID 400；凭证存在但从未
  登记状态返回空页（events:[]、next_after 取 after）；
- 响应恰含 credential_id/events/next_after；事件按 updated_at、cursor
  升序，每项恰含 status、reason、updated_at、revoked_at、audit_seq、
  audit_timestamp、cursor；active 的 reason/revoked_at 为 null，revoked
  保存裁剪 reason 与 revoked_at（updated_at 与 revoked_at 一致）；
- 仅首次 active 登记与首次 revoke 各追加一条：重复登记/吊销（含非法
  reason）与失败路径（首次非法 reason 400、已吊销再登记 409）不追加；
- cursor 为租户内跨凭证共享的持久化正整数，不同租户各自从 1 计起；
- audit_seq/audit_timestamp 关联 status.updated / credential.revoked
  审计；历史查询只读不记审计；
- limit 默认 50/限 1–200，after 默认 0/须非负，二者仅可出现一次且
  须为非空 ASCII 十进制数字（重复、空白、符号、小数、布尔词、Unicode
  数字均 400）；after 排除 cursor 不大于其值的事件，空页 next_after
  等于 after；
- 跨重启历史与 cursor 稳定；旧状态有状态无历史时按稳定顺序补兼容
  事件（audit 为 null），无写重启 cursor 稳定，新事件接续游标；
- 首次 active / 首次 revoke 落盘失败时状态、历史、游标、审计共同
  回滚；
- GET .../status 与既有签发/吊销协议不受影响（路由 /status/history
  优先于 /status 匹配）。

直接运行：python3 tests/credential_status_history_test.py
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8987
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

HISTORY_FIELDS = {"credential_id", "events", "next_after"}
EVENT_FIELDS = {
    "status", "reason", "updated_at", "revoked_at",
    "audit_seq", "audit_timestamp", "cursor",
}
DEFAULT_REVOKE_REASON = "持证人主动吊销"


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


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "cs-a"}
    T2 = {"X-Tenant-ID": "cs-b"}

    def issue(headers, handle, base_url=None):
        base_url = base_url or base
        st, did_body = _http(
            "POST", f"{base_url}/v1/dids",
            {"method": "example", "public_key": handle}, headers=headers,
        )
        assert st == 201, did_body
        did = did_body["did"]
        st, cred_body = _http(
            "POST", f"{base_url}/v1/credentials",
            {"issuer_did": did, "subject_did": did,
             "claims": {"role": "admin"}},
            headers=headers,
        )
        assert st == 201, cred_body
        return cred_body["credential_id"]

    def history(cid, headers=None, query=None, base_url=None):
        base_url = base_url or base
        url = f"{base_url}/v1/credentials/{cid}/status/history"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def set_active(cid, headers=None, base_url=None):
        base_url = base_url or base
        return _http(
            "PUT", f"{base_url}/v1/credentials/{cid}/status",
            {"status": "active"}, headers=headers,
        )

    def revoke(cid, payload=None, headers=None, base_url=None):
        base_url = base_url or base
        return _http(
            "POST", f"{base_url}/v1/credentials/{cid}/revoke",
            payload, headers=headers,
        )

    try:
        cid_a = issue(T1, "cs-handle-a")
        cid_b = issue(T1, "cs-handle-b")
        cid_c = issue(T2, "cs-handle-c")
        hist_a = None  # 供后续分页使用

        # ---- 1. 未知/跨租户/空租户头；无状态空历史 ----
        st, body = history("vc_00000000000000000000000000000000", headers=T1)
        check("未知凭证历史 -> 404", st == 404)
        st, body = history(cid_a, headers=T2)
        check("跨租户历史不可探测 -> 404", st == 404)
        st, body = history(cid_a, headers={"X-Tenant-ID": ""})
        check("显式空租户头历史 -> 400", st == 400)

        st, h = history(cid_a, headers=T1)
        check(
            "有凭证无状态返空页、响应恰三字段、next_after=0",
            st == 200 and h == {
                "credential_id": cid_a, "events": [], "next_after": 0,
            },
        )
        st, h = history(cid_a, headers=T1, query="after=7")
        check("空页 next_after 等于 after",
              st == 200 and h["events"] == [] and h["next_after"] == 7)

        # /status 路由仍正常（/status/history 优先匹配不影响原路由）
        st, s = _http(
            "GET", f"{base}/v1/credentials/{cid_a}/status", headers=T1)
        check("GET .../status 协议不变（无状态 active/null）",
              st == 200 and s == {
                  "credential_id": cid_a, "status": "active",
                  "updated_at": None,
              })

        # 只读查询不记审计
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        history(cid_a, headers=T1)
        history(cid_a, headers=T1)
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("空历史查询只读不记审计",
              len(audit_after["events"]) == n_before)

        # ---- 2. 首次 active：事件字段、null 值、审计关联 ----
        st, body = set_active(cid_a, headers=T1)
        check("首次 active 登记 201", st == 201)
        first_active_at = body["updated_at"]
        # 重复登记 200，不追加历史
        st, body = set_active(cid_a, headers=T1)
        check("重复 active 登记 200 且保持首次 updated_at",
              st == 200 and body["updated_at"] == first_active_at)

        st, h = history(cid_a, headers=T1)
        active_ev = None
        ok_active = (
            st == 200 and set(h) == HISTORY_FIELDS
            and h["credential_id"] == cid_a and len(h["events"]) == 1
        )
        if ok_active:
            active_ev = h["events"][0]
            ok_active = (
                set(active_ev) == EVENT_FIELDS
                and active_ev["status"] == "active"
                and active_ev["reason"] is None
                and active_ev["revoked_at"] is None
                and active_ev["updated_at"] == first_active_at
                and bool(Z_RE.match(active_ev["updated_at"]))
                and isinstance(active_ev["cursor"], int)
                and active_ev["cursor"] >= 1
                and isinstance(active_ev["audit_seq"], int)
                and isinstance(active_ev["audit_timestamp"], int)
                and h["next_after"] == active_ev["cursor"]
            )
        check("首次 active 事件恰七字段、null/null 且带审计关联", ok_active)
        hist_a = h

        # 审计关联：seq 指向 status.updated（首次登记的那一条）
        audit_map = {e["seq"]: e for e in audit_after["events"]}
        # 重新取一次审计以包含登记事件
        st, audit_full = _http("GET", f"{base}/v1/audit?limit=200",
                               headers=T1)
        audit_map = {e["seq"]: e for e in audit_full["events"]}
        linked = audit_map.get(active_ev["audit_seq"]) if active_ev else None
        check(
            "active 事件关联 status.updated 审计且 timestamp 一致",
            linked is not None and linked["action"] == "status.updated"
            and linked["resource_type"] == "credential"
            and linked["resource_id"] == cid_a
            and linked["timestamp"] == active_ev["audit_timestamp"],
        )

        # ---- 3. 首次 revoke：裁剪 reason、revoked_at，仅追加一次 ----
        time.sleep(1)
        st, body = revoke(cid_a, {"reason": "  持证人造假  "}, headers=T1)
        check("首次 revoke 200 且返回裁剪 reason",
              st == 200 and body["status"] == "revoked"
              and body["reason"] == "持证人造假")
        revoked_at = body["revoked_at"]
        check("revoked_at 为秒级 Z 时间且 updated_at 一致",
              bool(Z_RE.match(revoked_at or ""))
              and body["updated_at"] == revoked_at)

        # 重复吊销携带不同/非法 reason：均 200 返回首次结果
        st, body = revoke(cid_a, {"reason": "另一个原因"}, headers=T1)
        check("重复吊销返回首次 reason/revoked_at",
              st == 200 and body["reason"] == "持证人造假"
              and body["revoked_at"] == revoked_at)
        st, body = revoke(cid_a, {"reason": 123}, headers=T1)
        check("重复吊销时非法 reason 被忽略",
              st == 200 and body["reason"] == "持证人造假")

        st, h = history(cid_a, headers=T1)
        revoke_ev = None
        ok_two = (
            st == 200 and len(h["events"]) == 2
            and h["next_after"] == h["events"][-1]["cursor"]
        )
        if ok_two:
            ev0, ev1 = h["events"]
            revoke_ev = ev1
            ok_two = (
                all(set(e) == EVENT_FIELDS for e in h["events"])
                and [e["status"] for e in h["events"]] == [
                    "active", "revoked"]
                and ev0["cursor"] < ev1["cursor"]
                and ev0["updated_at"] <= ev1["updated_at"]
                and ev1["reason"] == "持证人造假"
                and ev1["revoked_at"] == revoked_at
                and ev1["updated_at"] == revoked_at
                and isinstance(ev1["audit_seq"], int)
            )
        check("历史恰两条：active -> revoked，按 updated_at/cursor 升序",
              ok_two)

        linked = audit_map.get(revoke_ev["audit_seq"]) if revoke_ev else None
        # 审计需重新拉取（上面重复吊销也各记一条 credential.revoked）
        st, audit_full = _http("GET", f"{base}/v1/audit?limit=200",
                               headers=T1)
        audit_map = {e["seq"]: e for e in audit_full["events"]}
        linked = audit_map.get(revoke_ev["audit_seq"]) if revoke_ev else None
        check(
            "revoke 事件关联首次 credential.revoked 审计",
            linked is not None and linked["action"] == "credential.revoked"
            and linked["resource_id"] == cid_a
            and linked["timestamp"] == revoke_ev["audit_timestamp"],
        )

        # 失败路径不追加：已吊销再登记 active -> 409；首次非法 reason 400
        st, _ = set_active(cid_a, headers=T1)
        check("已吊销再登记 active -> 409", st == 409)
        st, _ = revoke(cid_b, {"reason": "   "}, headers=T1)
        check("首次吊销空白 reason -> 400", st == 400)
        st, _ = revoke(cid_b, {"reason": 9}, headers=T1)
        check("首次吊销非字符串 reason -> 400", st == 400)
        st, h = history(cid_a, headers=T1)
        check("409 失败不追加历史", len(h["events"]) == 2)
        st, hb = history(cid_b, headers=T1)
        check("400 失败不追加历史（空页）",
              st == 200 and hb["events"] == [])

        # 历史查询仍不记审计（含重复查询已吊销凭证）
        n_now = len(audit_full["events"])
        history(cid_a, headers=T1)
        history(cid_b, headers=T1)
        st, audit_later = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("历史查询始终只读不记审计",
              len(audit_later["events"]) == n_now)

        # ---- 4. cursor 租户内跨凭证共享；不同租户各自从 1 计起 ----
        st, body = set_active(cid_b, headers=T1)
        assert st == 201, body
        st, hb = history(cid_b, headers=T1)
        cursor_b = hb["events"][0]["cursor"]
        check(
            "cursor 租户内跨凭证递增",
            st == 200 and len(hb["events"]) == 1
            and cursor_b == revoke_ev["cursor"] + 1,
        )
        # T2 独立游标空间
        st, body = set_active(cid_c, headers=T2)
        assert st == 201, body
        st, hc = history(cid_c, headers=T2)
        check("不同租户 cursor 各自从 1 计起",
              st == 200 and len(hc["events"]) == 1
              and hc["events"][0]["cursor"] == 1)

        # 未先登记 active 直接吊销：仅一条 revoked 事件，默认原因
        cid_d = issue(T2, "cs-handle-d")
        st, body = revoke(cid_d, headers=T2)
        check("省略 reason 吊销使用默认原因",
              st == 200 and body["reason"] == DEFAULT_REVOKE_REASON)
        st, hd = history(cid_d, headers=T2)
        check(
            "未登记 active 直接吊销仅一条 revoked 事件且 cursor 租户内递增",
            st == 200 and len(hd["events"]) == 1
            and hd["events"][0]["status"] == "revoked"
            and hd["events"][0]["reason"] == DEFAULT_REVOKE_REASON
            and hd["events"][0]["revoked_at"] is not None
            and hd["events"][0]["cursor"] == 2,
        )

        # ---- 5. 分页与非法参数 ----
        def hist_400(query, name):
            st, r = history(cid_a, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        st, pg = history(cid_a, headers=T1, query="limit=1")
        check("limit=1 仅返回首项",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["status"] == "active"
              and pg["next_after"] == pg["events"][0]["cursor"])
        c0 = pg["events"][0]["cursor"]
        st, pg = history(cid_a, headers=T1, query=f"limit=1&after={c0}")
        check("after 排除 cursor 不大于其值的事件",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["status"] == "revoked"
              and pg["next_after"] == revoke_ev["cursor"])
        st, pg = history(cid_a, headers=T1, query=f"after={revoke_ev['cursor']}")
        check("末项之后空页且 next_after 等于 after",
              pg["events"] == [] and pg["next_after"] == revoke_ev["cursor"])
        st, _ = history(cid_a, headers=T1, query="limit=200")
        check("limit=200 合法", st == 200)
        st, _ = history(cid_a, headers=T1)
        check("无参数默认 limit=50/after=0 返回全部 2 条",
              st == 200 and len(_["events"]) == 2)

        hist_400("limit=0", "limit=0 -> 400")
        hist_400("limit=201", "limit=201 -> 400")
        hist_400("limit=-1", "limit=-1 -> 400")
        hist_400("limit=+1", "limit=+1 -> 400")
        hist_400("limit=1.5", "limit=1.5 -> 400")
        hist_400("limit=true", "limit=true -> 400")
        hist_400("limit=", "空 limit -> 400")
        hist_400("limit=%20", "空白 limit -> 400")
        hist_400("limit=1%20", "尾随空白 limit -> 400")
        hist_400("limit=abc", "字母 limit -> 400")
        hist_400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        hist_400("limit=1&limit=2", "重复 limit -> 400")
        hist_400("after=-1", "after=-1 -> 400")
        hist_400("after=+1", "after=+1 -> 400")
        hist_400("after=1.0", "after=1.0 -> 400")
        hist_400("after=true", "after=true -> 400")
        hist_400("after=abc", "字母 after -> 400")
        hist_400("after=", "空 after -> 400")
        hist_400("after=%20", "空白 after -> 400")
        hist_400("after=%E0%A5%91", "Unicode 数字 after -> 400")
        hist_400("after=0&after=1", "重复 after -> 400")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 6. 跨重启：历史、审计关联与 cursor 稳定 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = history(cid_a, headers=T1)
        ok_restart = (
            st == 200 and [e["status"] for e in h["events"]] == [
                "active", "revoked"]
            and h["events"][1]["reason"] == "持证人造假"
            and h["events"][0]["reason"] is None
            and h["events"][0]["revoked_at"] is None
            and all(isinstance(e["audit_seq"], int)
                    and isinstance(e["audit_timestamp"], int)
                    for e in h["events"])
        )
        check("重启后历史事件与审计关联稳定", ok_restart)
        saved_cursors = [e["cursor"] for e in h["events"]]
        st, hb = history(cid_b, headers=T1)
        check("重启后跨凭证 cursor 稳定",
              st == 200 and [e["cursor"] for e in hb["events"]]
              == [saved_cursors[-1] + 1])
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 7. 旧状态兼容：有状态无历史补兼容事件，cursor 稳定 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "legacy"}
    try:
        leg_active = issue(L, "leg-active", lbase)
        leg_revoked = issue(L, "leg-revoked2", lbase)
        st, _ = _http(
            "PUT", f"{lbase}/v1/credentials/{leg_active}/status",
            {"status": "active"}, headers=L,
        )
        assert st == 201
        time.sleep(1)
        st, rv = _http(
            "POST", f"{lbase}/v1/credentials/{leg_revoked}/revoke",
            {"reason": "旧状态吊销"}, headers=L,
        )
        assert st == 200, rv
        leg_revoked_at = rv["revoked_at"]
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 手工删除本地凭证状态历史命名空间与游标计数，模拟旧版本状态文件
    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["local_credential_status_history"] = {}
    raw.pop("local_credential_status_history_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, hr = history(leg_revoked, headers=L, base_url=lbase)
        st2, ha = history(leg_active, headers=L, base_url=lbase)
        # credential_id 字典序决定补录顺序
        ordered_ids = sorted([leg_active, leg_revoked])
        expected = {
            leg_active: 1 if leg_active == ordered_ids[0] else 2,
            leg_revoked: 1 if leg_revoked == ordered_ids[0] else 2,
        }
        ok_compat = (
            st == 200 and st2 == 200
            and set(hr) == HISTORY_FIELDS and set(ha) == HISTORY_FIELDS
            and len(hr["events"]) == 1 and len(ha["events"]) == 1
        )
        if ok_compat:
            er, ea = hr["events"][0], ha["events"][0]
            ok_compat = (
                set(er) == EVENT_FIELDS and set(ea) == EVENT_FIELDS
                and er["status"] == "revoked"
                and er["reason"] == "旧状态吊销"
                and er["revoked_at"] == leg_revoked_at
                and er["updated_at"] == leg_revoked_at
                and er["audit_seq"] is None
                and er["audit_timestamp"] is None
                and er["cursor"] == expected[leg_revoked]
                and ea["status"] == "active"
                and ea["reason"] is None and ea["revoked_at"] is None
                and ea["audit_seq"] is None
                and ea["audit_timestamp"] is None
                and ea["cursor"] == expected[leg_active]
            )
        check("旧状态按稳定顺序补兼容事件（active null、revoked 裁剪原因、audit null）",
              ok_compat)
        compat_cursors = {
            leg_active: ha["events"][0]["cursor"],
            leg_revoked: hr["events"][0]["cursor"],
        }

        # 兼容事件可按 after 分页
        st, hp = history(
            leg_revoked, headers=L,
            query=f"after={compat_cursors[leg_revoked]}",
            base_url=lbase,
        )
        check("兼容事件按 cursor 分页、空页保持 after",
              st == 200 and hp["events"] == []
              and hp["next_after"] == compat_cursors[leg_revoked])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 不触发任何写操作直接重启：兼容 cursor 必须重建为相同值
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, hr = history(leg_revoked, headers=L, base_url=lbase)
        st2, ha = history(leg_active, headers=L, base_url=lbase)
        check(
            "无写操作重启后兼容 cursor 稳定",
            st == 200 and st2 == 200
            and hr["events"][0]["cursor"] == compat_cursors[leg_revoked]
            and ha["events"][0]["cursor"] == compat_cursors[leg_active],
        )
        # 触发一次新状态变更：兼容项随原子写落盘，新 cursor 接续
        st, _ = revoke(leg_active, {"reason": "兼容后吊销"}, headers=L,
                       base_url=lbase)
        assert st == 200
        st, h = history(leg_active, headers=L, base_url=lbase)
        new_cursor = max(compat_cursors.values()) + 1
        check(
            "补录后新吊销事件在租户最大 cursor 之后接续",
            st == 200 and len(h["events"]) == 2
            and [e["status"] for e in h["events"]] == ["active", "revoked"]
            and h["events"][1]["cursor"] == new_cursor
            and h["events"][1]["audit_seq"] is not None,
        )
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 再次重启：兼容项已落盘，全部 cursor 持久稳定
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = history(leg_active, headers=L, base_url=lbase)
        st2, hr = history(leg_revoked, headers=L, base_url=lbase)
        check(
            "落盘后重启兼容与新增 cursor 全部稳定",
            st == 200 and st2 == 200
            and [e["cursor"] for e in h["events"]]
            == [compat_cursors[leg_active],
                max(compat_cursors.values()) + 1]
            and [e["cursor"] for e in hr["events"]]
            == [compat_cursors[leg_revoked]],
        )
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 8. 直连 store：首次 active / 首次 revoke 落盘失败全回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("dt", "example", "rollback-cs")
    cred = store.create_credential("dt", d.did, d.did, {"role": "x"})
    dcid = cred.credential_id

    def _boom():
        raise OSError("模拟落盘失败")

    # 首次 active 落盘失败
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.set_credential_active("dt", dcid)
    except OSError:
        raised = True
    check("首次 active 落盘失败时抛错", raised)
    rec = store.get_credential_status("dt", dcid)
    check("回滚后状态仍为无状态（active/null updated_at）",
          rec.status == "active" and rec.updated_at is None)
    events, next_after = store.list_credential_status_history("dt", dcid)
    check("回滚后历史为空页、next_after 保持 0",
          events == [] and next_after == 0)
    audit_events = store.list_audit("dt", 0, 200)[0]
    check("回滚后不记 status.updated 审计",
          all(e.action != "status.updated" for e in audit_events))
    check("回滚后租户游标未前进",
          store._local_credential_status_history_cursors.get("dt", 0) == 0)  # noqa: SLF001

    # 恢复后首次 active 成功：状态/历史/游标/审计一并落盘
    del store._save_locked
    rec, created = store.set_credential_active("dt", dcid)
    check("恢复后首次 active 成功",
          created and rec.status == "active"
          and rec.updated_at is not None)
    events, _ = store.list_credential_status_history("dt", dcid)
    check("恢复后历史仅一条 active 且 cursor 从 1 开始",
          len(events) == 1 and events[0].status == "active"
          and events[0].cursor == 1
          and events[0].reason is None
          and events[0].revoked_at is None)

    # 首次 revoke 落盘失败：active 历史保留，revoke 全部回滚
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.revoke_credential("dt", dcid, reason="回滚吊销")
    except OSError:
        raised = True
    check("首次 revoke 落盘失败时抛错", raised)
    rec = store.get_credential_status("dt", dcid)
    check("回滚后状态仍为 active", rec.status == "active")
    events, _ = store.list_credential_status_history("dt", dcid)
    check("回滚后历史仍仅 active 一条、游标不前进",
          len(events) == 1 and events[0].status == "active"
          and events[0].cursor == 1)
    audit_events = store.list_audit("dt", 0, 200)[0]
    check("回滚后不记 credential.revoked 审计",
          all(e.action != "credential.revoked" for e in audit_events))
    check("回滚后租户游标停在 1",
          store._local_credential_status_history_cursors.get("dt") == 1)  # noqa: SLF001

    del store._save_locked
    rec = store.revoke_credential("dt", dcid, reason="回滚吊销")
    check("恢复后首次 revoke 成功",
          rec.status == "revoked" and rec.reason == "回滚吊销")
    events, _ = store.list_credential_status_history("dt", dcid)
    check("恢复后历史为 active+revoked、revoke cursor=2",
          [e.status for e in events] == ["active", "revoked"]
          and events[1].cursor == 2
          and events[1].reason == "回滚吊销"
          and events[1].revoked_at == events[1].updated_at)
    audit_events = store.list_audit("dt", 0, 200)[0]
    check("恢复后审计各仅一条",
          [e.action for e in audit_events].count("status.updated") == 1
          and [e.action for e in audit_events].count(
              "credential.revoked") == 1)

    # 跨进程重启验证回滚场景持久化
    dp = start_server(PORT + 2, direct_path)
    try:
        db = f"http://127.0.0.1:{PORT + 2}"
        st, h = _http(
            "GET", f"{db}/v1/credentials/{dcid}/status/history",
            headers={"X-Tenant-ID": "dt"})
        check("回滚场景重启后历史一致（active=1、revoked=2）",
              st == 200 and [e["status"] for e in h["events"]] == [
                  "active", "revoked"]
              and [e["cursor"] for e in h["events"]] == [1, 2])
    finally:
        dp.terminate()
        dp.wait(timeout=10)

    # ---- 9. 直连 store：默认 limit=50 边界（合成历史行）----
    synth_path = tempfile.mktemp(suffix=".json")
    synth = VCStore(synth_path)
    sd = synth.create_did("syn", "example", "synth-handle")
    sc = synth.create_credential("syn", sd.did, sd.did, {"k": "v"})
    bucket = synth._ensure_bucket_locked("syn")  # noqa: SLF001
    entries = bucket["local_credential_status_history"].setdefault(
        sc.credential_id, [])
    with synth._lock:  # noqa: SLF001
        for idx in range(1, 56):
            cursor = synth._next_local_credential_status_cursor_locked("syn")  # noqa: SLF001
            entries.append({
                "status": "active",
                "reason": None,
                "updated_at": f"2026-01-01T00:{idx // 60:02d}:{idx % 60:02d}Z",
                "revoked_at": None,
                "cursor": cursor,
                "audit_seq": None,
                "audit_timestamp": None,
            })
    page, next_after = synth.list_credential_status_history("syn", sc.credential_id)
    check("默认 limit=50 返回 50 条、next_after=50",
          len(page) == 50 and next_after == 50)
    page, next_after = synth.list_credential_status_history(
        "syn", sc.credential_id, after=50)
    check("after=50 返回剩余 5 条、next_after=55",
          len(page) == 5 and [e.cursor for e in page] == list(range(51, 56))
          and next_after == 55)

    for path in (store_path, legacy_path, direct_path, synth_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("凭证状态历史测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
