#!/usr/bin/env python3
"""DID 密钥版本状态查询与吊销历史的端到端测试。

覆盖：
- GET /v1/dids/{did}/keys/{ver}/status：路径版本须为 ASCII 正整数
  （非法 400）；DID/版本不存在（含跨租户）404；200 恰返
  {did,key_version,status,reason,updated_at}，active 为 null/null，
  revoked 为首次原因与 UTC 秒 Z 时间；
- GET /v1/dids/{did}/keys/revocations?limit=&after=：响应恰含
  did/events/next_after；仅首次成功吊销追加（重复、400/404/409 失败
  不追加）；事件恰含 {key_version,reason,updated_at,cursor}，cursor
  为租户内持久化正整数、跨 DID 共享且升序；limit 默认 50/限 1–200，
  after 默认 0/须非负，二者仅可出现一次且须为非空 ASCII 数字；
  after 排除不大于其值的 cursor，next_after 取末项，空页等于 after；
  已有 DID 无历史空页，未知/跨租户 DID 404；只读不记审计；
- 跨重启历史与 cursor 稳定；旧吊销状态无历史时补兼容事件且 cursor
  跨重启稳定；首次吊销状态/历史/审计原子落盘，失败全回滚；
- DID 文档、密钥历史与幂等吊销响应不受影响。

直接运行：python3 tests/key_revocation_status_history_test.py
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

PORT = 8981
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

STATUS_FIELDS = {"did", "key_version", "status", "reason", "updated_at"}
HISTORY_FIELDS = {"did", "events", "next_after"}
EVENT_FIELDS = {"key_version", "reason", "updated_at", "cursor"}


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
    T1 = {"X-Tenant-ID": "kr-a"}
    T2 = {"X-Tenant-ID": "kr-b"}

    def status(did, version, headers=None):
        return _http(
            "GET",
            f"{base}/v1/dids/{did}/keys/{version}/status",
            headers=headers,
        )

    def revocations(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/keys/revocations"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def revoke(did, version, payload=None, headers=None):
        return _http(
            "POST",
            f"{base}/v1/dids/{did}/keys/{version}/revoke",
            payload, headers=headers,
        )

    try:
        # ---- 准备：A/B 两个 DID，各自轮换出 v2，吊销 A 的 v1 ----
        st, a = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kr-handle-a"}, headers=T1,
        )
        assert st == 201, a
        did_a = a["did"]
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
            {"key_handle": "kr-handle-a-v2"}, headers=T1,
        )
        assert st == 200

        st, b = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kr-handle-b"}, headers=T1,
        )
        assert st == 201, b
        did_b = b["did"]
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_b}/keys/rotate",
            {"key_handle": "kr-handle-b-v2"}, headers=T1,
        )
        assert st == 200

        st, c = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "kr-handle-c"}, headers=T2,
        )
        assert st == 201, c
        did_c = c["did"]

        # ---- 1. 状态：未吊销的旧版本 active，null/null ----
        st, r = status(did_b, 1, headers=T1)
        check(
            "active 旧版本 200 且字段恰为五项、null/null",
            st == 200
            and set(r) == STATUS_FIELDS
            and r == {
                "did": did_b, "key_version": 1, "status": "active",
                "reason": None, "updated_at": None,
            },
        )
        st, r = status(did_b, 2, headers=T1)
        check("当前版本同样 active、null/null",
              st == 200 and r["status"] == "active"
              and r["reason"] is None and r["updated_at"] is None)

        # ---- 2. 首次吊销后 revoked 状态为首次原因/UTC 秒 Z 时间 ----
        st, rv = revoke(did_a, 1, {"reason": "  v1 疑似泄漏  "}, headers=T1)
        assert st == 200, rv
        first_reason = "v1 疑似泄漏"
        first_updated = rv["updated_at"]
        check(
            "首次吊销 200 返回裁剪原因与秒级 Z 时间",
            rv["reason"] == first_reason
            and bool(Z_RE.match(first_updated or "")),
        )
        st, r = status(did_a, 1, headers=T1)
        check(
            "status 查询 revoked 恰五字段、首次原因/时间",
            st == 200 and set(r) == STATUS_FIELDS
            and r == {
                "did": did_a, "key_version": 1, "status": "revoked",
                "reason": first_reason, "updated_at": first_updated,
            },
        )
        # 重复吊销携带不同 reason：状态仍返回首次结果
        st, rv2 = revoke(did_a, 1, {"reason": "另一个原因"}, headers=T1)
        check("重复吊销返回首次 reason/updated_at",
              st == 200 and rv2["reason"] == first_reason
              and rv2["updated_at"] == first_updated)
        st, r = status(did_a, 1, headers=T1)
        check("重复吊销不改变 status 查询结果",
              r["reason"] == first_reason
              and r["updated_at"] == first_updated)

        # ---- 3. 路径版本非法 -> 400 ----
        def status_400(version, name):
            st, r = status(did_a, version, headers=T1)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        status_400("0", "status 版本 0 -> 400")
        status_400("-1", "status 版本 -1 -> 400")
        status_400("+1", "status 版本 +1 -> 400")
        status_400("1.5", "status 版本 1.5 -> 400")
        status_400("abc", "status 版本字母 -> 400")
        status_400("true", "status 版本布尔词 -> 400")
        status_400("%20", "status 版本空白 -> 400")
        status_400("%E0%A5%91", "status Unicode 数字 -> 400")
        status_400("1%20", "status 版本尾随空白 -> 400")

        # ---- 4. DID/版本不存在（含跨租户）-> 404 ----
        st, _ = status("did:example:00000000000000000000000000000000", 1,
                       headers=T1)
        check("未知 DID status -> 404", st == 404)
        st, _ = status(did_a, 99, headers=T1)
        check("版本不存在 status -> 404", st == 404)
        st, _ = status(did_a, 1, headers=T2)
        check("跨租户 status 不可探测 -> 404", st == 404)
        st, _ = status(did_a, 1, headers={"X-Tenant-ID": ""})
        check("显式空租户头 status -> 400", st == 400)

        # ---- 5. 吊销历史：恰三字段，事件恰四字段，cursor 租户内共享 ----
        st, h = revocations(did_a, headers=T1)
        cursor_a = None
        ok_hist = False
        if st == 200 and set(h) == HISTORY_FIELDS and h["did"] == did_a:
            if len(h["events"]) == 1:
                ev = h["events"][0]
                cursor_a = ev["cursor"]
                ok_hist = (
                    set(ev) == EVENT_FIELDS
                    and ev["key_version"] == 1
                    and ev["reason"] == first_reason
                    and ev["updated_at"] == first_updated
                    and isinstance(ev["cursor"], int) and ev["cursor"] >= 1
                    and h["next_after"] == ev["cursor"]
                )
        check("历史响应/事件字段恰如协议且取首次原因时间", ok_hist)

        # 重复吊销不追加（上面已重复一次）
        st, h = revocations(did_a, headers=T1)
        check("重复吊销不追加历史",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["cursor"] == cursor_a)

        # 失败吊销不追加：当前版本 409、坏版本 400、未知 DID 404
        st, _ = revoke(did_a, 2, {"reason": "x"}, headers=T1)
        check("吊销当前版本 -> 409", st == 409)
        st, _ = revoke(did_a, 0, {"reason": "x"}, headers=T1)
        check("吊销坏版本 -> 400", st == 400)
        st, _ = revoke("did:example:00000000000000000000000000000000", 1,
                       {"reason": "x"}, headers=T1)
        check("吊销未知 DID -> 404", st == 404)
        st, h = revocations(did_a, headers=T1)
        check("失败吊销不追加历史", len(h["events"]) == 1)

        # 同租户第二个 DID 首次吊销：cursor 在租户内继续递增
        st, _ = revoke(did_b, 1, {"reason": "b 的 v1 吊销"}, headers=T1)
        check("B 首次吊销 -> 200", st == 200)
        st, ha = revocations(did_a, headers=T1)
        st, hb = revocations(did_b, headers=T1)
        cursor_b = hb["events"][0]["cursor"] if hb.get("events") else None
        check(
            "cursor 为租户内跨 DID 共享的持久化正整数且升序",
            st == 200
            and len(ha["events"]) == 1 and len(hb["events"]) == 1
            and isinstance(cursor_b, int) and cursor_b == cursor_a + 1
            and hb["events"][0]["reason"] == "b 的 v1 吊销",
        )

        # ---- 6. 已有 DID 无历史返空页；未知/跨租户 404 ----
        # did_c 在 T2，仅注册未吊销；在 T2 查应为空页
        st, h = revocations(did_c, headers=T2)
        check("已有 DID 无历史返空页、next_after=0",
              st == 200 and h == {"did": did_c, "events": [],
                                  "next_after": 0})
        st, _ = revocations("did:example:00000000000000000000000000000000",
                            headers=T1)
        check("未知 DID 历史 -> 404", st == 404)
        st, _ = revocations(did_a, headers=T2)
        check("跨租户历史不可探测 -> 404", st == 404)
        st, _ = revocations(did_a, headers={"X-Tenant-ID": ""})
        check("显式空租户头历史 -> 400", st == 400)

        # ---- 7. 分页：limit/after/next_after ----
        # 让 did_a 拥有两条历史：轮换到 v3 后吊销 v2
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
            {"key_handle": "kr-handle-a-v3"}, headers=T1,
        )
        assert st == 200
        st, rv3 = revoke(did_a, 2, {"reason": "v2 停用"}, headers=T1)
        assert st == 200
        st, h = revocations(did_a, headers=T1)
        cursors = [e["cursor"] for e in h["events"]]
        check("两条历史按 cursor 升序",
              st == 200 and len(h["events"]) == 2
              and cursors == sorted(cursors)
              and [e["key_version"] for e in h["events"]] == [1, 2]
              and h["next_after"] == cursors[-1])

        st, pg = revocations(did_a, headers=T1, query="limit=1")
        check("limit=1 仅返回首项",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["cursor"] == cursors[0]
              and pg["next_after"] == cursors[0])
        st, pg = revocations(
            did_a, headers=T1, query=f"limit=1&after={cursors[0]}")
        check("after 排除不大于其值的 cursor",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["cursor"] == cursors[1]
              and pg["next_after"] == cursors[1])
        st, pg = revocations(did_a, headers=T1, query="after=999999")
        check("空页 next_after 等于 after",
              st == 200 and pg["events"] == []
              and pg["next_after"] == 999999)
        st, pg = revocations(did_a, headers=T1, query="after=0")
        check("after=0 返回全部",
              st == 200 and len(pg["events"]) == 2)
        st, _ = revocations(did_a, headers=T1, query="limit=200")
        check("limit=200 合法", st == 200)

        def hist_400(query, name):
            st, r = revocations(did_a, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        hist_400("limit=0", "limit=0 -> 400")
        hist_400("limit=201", "limit=201 -> 400")
        hist_400("limit=-1", "limit=-1 -> 400")
        hist_400("limit=1.5", "limit=1.5 -> 400")
        hist_400("limit=true", "limit=true -> 400")
        hist_400("limit=", "空 limit -> 400")
        hist_400("limit=%20", "空白 limit -> 400")
        hist_400("limit=abc", "字母 limit -> 400")
        hist_400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        hist_400("limit=1&limit=2", "重复 limit -> 400")
        hist_400("after=-1", "after=-1 -> 400")
        hist_400("after=1.0", "after=1.0 -> 400")
        hist_400("after=abc", "字母 after -> 400")
        hist_400("after=", "空 after -> 400")
        hist_400("after=%20", "空白 after -> 400")
        hist_400("after=0&after=1", "重复 after -> 400")

        # ---- 8. 只读：查询不记审计 ----
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        for _ in range(3):
            status(did_a, 1, headers=T1)
            revocations(did_a, headers=T1)
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("status/history 查询只读、不记审计",
              len(audit_after["events"]) == n_before)
        # 首次与重复吊销均记 key.revoked（至少 3 次：A v1 两次 + A v2，
        # B v1 在另一资源上）
        rev_events = [e for e in audit_after["events"]
                      if e["action"] == "key.revoked"]
        check("吊销审计 resource_id 为 <did>#<ver>",
              all(e["resource_type"] == "did" and "#" in e["resource_id"]
                  for e in rev_events) and len(rev_events) >= 3)

        # ---- 9. DID 文档与密钥历史不受影响 ----
        st, doc = _http("GET", f"{base}/v1/dids/{did_a}/document",
                        headers=T1)
        check("DID 文档仍公开被吊销版本的历史公钥",
              st == 200
              and [m["key_version"] for m in doc["verification_methods"]]
              == [1, 2, 3]
              and all("public_key" in m and "key_handle" in m
                      for m in doc["verification_methods"]))
        st, got = _http("GET", f"{base}/v1/dids/{did_a}", headers=T1)
        check("GET DID key_version 仍为当前版本",
              st == 200 and got["key_version"] == 3)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 跨重启：历史与 cursor 稳定，新吊销 cursor 继续递增 ----
    proc = start_server(PORT, store_path)
    try:
        st, h1 = revocations(did_a, headers=T1)
        st2, h2 = revocations(did_b, headers=T1)
        ok_restart = (
            st == 200 and st2 == 200
            and [e["key_version"] for e in h1["events"]] == [1, 2]
            and h1["events"][0]["reason"] == first_reason
            and h1["events"][0]["updated_at"] == first_updated
            and len(h2["events"]) == 1
            and h2["events"][0]["cursor"] == cursor_a + 1
        )
        check("重启后历史与 cursor 稳定", ok_restart)
        saved_cursor_a = [e["cursor"] for e in h1["events"]]

        # 再轮换并吊销：cursor 在租户最大值之后继续
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_b}/keys/rotate",
            {"key_handle": "kr-handle-b-v3"}, headers=T1,
        )
        assert st == 200
        st, _ = revoke(did_b, 2, {"reason": "b v2 停用"}, headers=T1)
        assert st == 200
        st, hb2 = revocations(did_b, headers=T1)
        check("重启后新吊销 cursor 继续租户内递增",
              st == 200 and len(hb2["events"]) == 2
              and hb2["events"][1]["cursor"] > saved_cursor_a[-1]
              and hb2["events"][1]["cursor"] > hb2["events"][0]["cursor"])
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 11. 旧状态缺吊销历史：补兼容事件，cursor 跨重启稳定 ----
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
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
              {"key_handle": "leg-a2"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/1/revoke",
              {"reason": "旧吊销"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
              {"key_handle": "leg-a3"}, headers=L)
        _http("POST", f"{lbase}/v1/dids/{leg_did}/keys/2/revoke",
              {"reason": "旧吊销2"}, headers=L)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 手工删除吊销历史命名空间与游标计数，模拟旧版本状态文件
    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["key_revocations"] = {}
    raw.pop("key_revocation_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/revocations",
            headers=L,
        )
        compat_cursors = None
        ok_compat = (
            st == 200 and set(h) == HISTORY_FIELDS
            and len(h["events"]) == 2
            and [e["key_version"] for e in h["events"]] == [1, 2]
            and all(set(e) == EVENT_FIELDS for e in h["events"])
            and h["events"][0]["reason"] == "旧吊销"
            and h["events"][1]["reason"] == "旧吊销2"
            and all(bool(Z_RE.match(e["updated_at"]))
                    for e in h["events"])
        )
        if ok_compat:
            compat_cursors = [e["cursor"] for e in h["events"]]
            ok_compat = (
                compat_cursors == [1, 2]
                and all(isinstance(c, int) for c in compat_cursors)
            )
        check("旧吊销状态补兼容事件（按版本升序、租户内 cursor）", ok_compat)

        # 兼容项可按 after 分页
        st, hp = _http(
            "GET",
            f"{lbase}/v1/dids/{leg_did}/keys/revocations"
            f"?after={compat_cursors[-1]}",
            headers=L,
        )
        check("兼容事件按 cursor 分页、空页保持 after",
              st == 200 and hp["events"] == []
              and hp["next_after"] == compat_cursors[-1])

        # status 同样读旧吊销标记
        st, s1 = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/1/status", headers=L)
        check("旧状态 status 仍为 revoked/首次原因",
              st == 200 and s1["status"] == "revoked"
              and s1["reason"] == "旧吊销")
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 不触发任何写操作直接重启：兼容 cursor 必须重建为相同值
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/revocations",
            headers=L,
        )
        check(
            "无写操作重启后兼容 cursor 稳定",
            st == 200
            and [e["cursor"] for e in h["events"]] == compat_cursors,
        )
        # 触发一次新吊销：先轮换到 v4（v3 为当前版本不可吊销），
        # 兼容项随原子写落盘且新 cursor 接续
        st, _ = _http(
            "POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
            {"key_handle": "leg-a4"}, headers=L,
        )
        assert st == 200
        st, body = _http(
            "POST", f"{lbase}/v1/dids/{leg_did}/keys/3/revoke",
            {"reason": "新吊销"}, headers=L,
        )
        assert st == 200, body
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/revocations",
            headers=L,
        )
        check("新吊销 cursor 在兼容项之后接续",
              st == 200 and len(h["events"]) == 3
              and [e["cursor"] for e in h["events"]]
              == compat_cursors + [3])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 再次重启：全部持久化
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/revocations",
            headers=L,
        )
        check("落盘后重启 cursor 全部稳定",
              st == 200
              and [e["cursor"] for e in h["events"]] == [1, 2, 3]
              and [e["key_version"] for e in h["events"]] == [1, 2, 3])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 12. 直连 store：首次吊销落盘失败全回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("dt", "example", "rollback-kr")
    store.rotate_key("dt", d.did, "rollback-kr2")

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.revoke_key_version("dt", d.did, 1, reason="回滚测试")
    except OSError:
        raised = True
    check("落盘失败时首次吊销抛错", raised)

    rec = store.get_key_version_status("dt", d.did, 1)
    check("回滚后 status 查询仍为 active/null/null",
          rec.status == "active" and rec.reason is None
          and rec.updated_at is None)
    events, next_after = store.list_key_revocations("dt", d.did, 0, 50)
    check("回滚后历史为空页、next_after 保持 0",
          events == [] and next_after == 0)
    audit_events = store.list_audit("dt", 0, 200)[0]
    check("回滚后不记 key.revoked 审计",
          all(e.action != "key.revoked" for e in audit_events))
    bucket = store._bucket_locked("dt")  # noqa: SLF001
    check("回滚后租户游标未前进",
          store._key_revocation_cursors.get("dt", 0) == 0)  # noqa: SLF001

    # 恢复落盘能力后吊销成功：状态/历史/审计一并落盘
    del store._save_locked
    rec = store.revoke_key_version("dt", d.did, 1, reason="回滚测试")
    check("恢复后首次吊销成功",
          rec.status == "revoked" and rec.reason == "回滚测试")
    events, _ = store.list_key_revocations("dt", d.did, 0, 50)
    check("恢复后历史仅一条且 cursor 从 1 开始",
          len(events) == 1 and events[0].cursor == 1
          and events[0].reason == "回滚测试")
    audit_events = store.list_audit("dt", 0, 200)[0]
    check("恢复后仅记一次 key.revoked",
          [e.action for e in audit_events].count("key.revoked") == 1)

    # 跨进程重启验证回滚场景的持久化
    dp = start_server(PORT + 2, direct_path)
    try:
        db = f"http://127.0.0.1:{PORT + 2}"
        st, s1 = _http(
            "GET", f"{db}/v1/dids/{d.did}/keys/1/status",
            headers={"X-Tenant-ID": "dt"})
        st2, h = _http(
            "GET", f"{db}/v1/dids/{d.did}/keys/revocations",
            headers={"X-Tenant-ID": "dt"})
        check("回滚场景重启后状态与历史一致",
              st == 200 and s1["status"] == "revoked"
              and st2 == 200 and len(h["events"]) == 1
              and h["events"][0]["cursor"] == 1)
    finally:
        dp.terminate()
        dp.wait(timeout=10)

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("密钥版本状态与吊销历史测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
