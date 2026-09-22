#!/usr/bin/env python3
"""GET /v1/credentials/{credential_id}/status/history 只读本地状态历史
查询的端到端测试（含与签发/登记/吊销语义的兼容）。

直接运行：python3 tests/credential_status_history_test.py
不依赖第三方测试框架，仅用标准库。
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
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is None:
        data = json.dumps(payload).encode() if payload is not None else None
    else:
        data = raw
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


def wait_up(proc, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def start_server(port, env):
    return subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


EVENT_KEYS = {
    "status", "reason", "updated_at", "revoked_at",
    "audit_seq", "audit_timestamp", "cursor",
}


def main():
    port = 8963
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = start_server(port, env)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def history(credential_id, headers=None, query=None):
        url = (f"{base}/v1/credentials/"
               f"{quote(credential_id)}/status/history")
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    T1 = {"X-Tenant-ID": "local-hist-a"}
    T2 = {"X-Tenant-ID": "local-hist-b"}

    def make_credential(headers, tag):
        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": f"issuer-{tag}"},
            headers=headers,
        )
        assert st == 201, r
        issuer = r["did"]
        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": f"subject-{tag}"},
            headers=headers,
        )
        assert st == 201, r
        subject = r["did"]
        st, r = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject,
             "claims": {"role": tag}},
            headers=headers,
        )
        assert st == 201, r
        return r["credential_id"]

    try:
        assert wait_up(proc, port), "服务启动超时"

        cred = make_credential(T1, "one")

        # ---- 1. 无状态：空历史，next_after 保持 after ----
        st, h = history(cred, headers=T1)
        check("无状态空历史且响应恰含三键",
              st == 200 and set(h) == {"credential_id", "events", "next_after"}
              and h["credential_id"] == cred
              and h["events"] == [] and h["next_after"] == 0)
        st, h = history(cred, headers=T1, query="after=7")
        check("无状态空页 next_after 等于 after",
              st == 200 and h["events"] == [] and h["next_after"] == 7)

        # ---- 2. 首次 active 登记追加一条，字段齐全且关联审计 ----
        st, _ = _http("PUT", f"{base}/v1/credentials/{cred}/status",
                      {"status": "active"}, headers=T1)
        check("首次登记 -> 201", st == 201)
        st, audit0 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        reg_events = [
            e for e in audit0["events"]
            if e["action"] == "status.updated"
            and e["resource_id"] == cred
        ]
        st, h = history(cred, headers=T1)
        first_cursor = None
        ok_first = False
        if st == 200 and len(h["events"]) == 1:
            ev = h["events"][0]
            first_cursor = ev["cursor"]
            linked = reg_events[-1]
            ok_first = (
                set(ev) == EVENT_KEYS
                and ev["status"] == "active"
                and ev["reason"] is None
                and ev["revoked_at"] is None
                and isinstance(ev["updated_at"], str)
                and ev["updated_at"].endswith("Z")
                and isinstance(ev["cursor"], int) and ev["cursor"] >= 1
                and ev["audit_seq"] == linked["seq"]
                and ev["audit_timestamp"] == linked["timestamp"]
                and h["next_after"] == ev["cursor"]
            )
        check("首次 active 事件字段齐全且关联登记审计", ok_first)

        # ---- 3. 重复登记不追加 ----
        st, _ = _http("PUT", f"{base}/v1/credentials/{cred}/status",
                      {"status": "active"}, headers=T1)
        check("重复登记 -> 200", st == 200)
        st, h = history(cred, headers=T1)
        check("重复登记不追加历史",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["cursor"] == first_cursor)

        # ---- 4. 失败路径不追加：非法 reason、未知凭证、已吊销后登记 ----
        cred_bad = make_credential(T1, "bad")
        st, _ = _http("POST", f"{base}/v1/credentials/{cred_bad}/revoke",
                      {"reason": "   "}, headers=T1)
        check("非法 reason 吊销 -> 400", st == 400)
        st, h = history(cred_bad, headers=T1)
        check("失败吊销不追加历史",
              st == 200 and h["events"] == [] and h["next_after"] == 0)
        st, _ = _http("POST", f"{base}/v1/credentials/vc_nope/revoke",
                      {}, headers=T1)
        check("未知凭证吊销 -> 404", st == 404)

        # ---- 5. 首次吊销追加一条：裁剪 reason、保留 revoked_at、关联审计 ----
        st, r = _http("POST", f"{base}/v1/credentials/{cred}/revoke",
                      {"reason": "  违规使用  "}, headers=T1)
        check("首次吊销 -> 200", st == 200 and r["reason"] == "违规使用")
        st, audit1 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        rev_events = [
            e for e in audit1["events"]
            if e["action"] == "credential.revoked"
            and e["resource_id"] == cred
        ]
        st, h = history(cred, headers=T1)
        ok_rev = False
        second_cursor = None
        if st == 200 and len(h["events"]) == 2:
            e1, e2 = h["events"]
            second_cursor = e2["cursor"]
            linked = rev_events[-1]
            ok_rev = (
                set(e2) == EVENT_KEYS
                and e1["status"] == "active"
                and e2["status"] == "revoked"
                and e2["reason"] == "违规使用"
                and e2["revoked_at"] == e2["updated_at"]
                and isinstance(e2["revoked_at"], str)
                and e2["cursor"] > e1["cursor"]
                and e2["audit_seq"] == linked["seq"]
                and e2["audit_timestamp"] == linked["timestamp"]
                and h["next_after"] == e2["cursor"]
            )
        check("首次吊销追加且字段/审计关联正确", ok_rev)

        # ---- 6. 重复吊销与吊销后登记冲突均不追加 ----
        st, _ = _http("POST", f"{base}/v1/credentials/{cred}/revoke",
                      {"reason": "再次"}, headers=T1)
        check("重复吊销 -> 200", st == 200)
        st, _ = _http("PUT", f"{base}/v1/credentials/{cred}/status",
                      {"status": "active"}, headers=T1)
        check("已吊销再登记 -> 409", st == 409)
        st, h = history(cred, headers=T1)
        check("重复吊销与冲突登记不追加历史",
              st == 200 and len(h["events"]) == 2
              and h["events"][-1]["cursor"] == second_cursor)

        # ---- 7. 只读路径不追加：状态查询/凭证查询/验签 ----
        _http("GET", f"{base}/v1/credentials/{cred}/status", headers=T1)
        _http("GET", f"{base}/v1/credentials/{cred}", headers=T1)
        st, h = history(cred, headers=T1)
        check("只读路径不追加历史", st == 200 and len(h["events"]) == 2)

        # ---- 8. 分页：limit/after/next_after，空页保持 after ----
        st, pg = history(cred, headers=T1, query="limit=1")
        check("limit=1 返回 1 项",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["cursor"] == first_cursor
              and pg["next_after"] == first_cursor)
        st, pg2 = history(cred, headers=T1,
                          query=f"limit=1&after={first_cursor}")
        check("after 排除 <=cursor 记录",
              st == 200 and len(pg2["events"]) == 1
              and pg2["events"][0]["cursor"] == second_cursor
              and pg2["next_after"] == second_cursor)
        st, pge = history(cred, headers=T1, query="after=999999")
        check("空页 next_after 保持 after",
              st == 200 and pge["events"] == []
              and pge["next_after"] == 999999)
        st, pg0 = history(cred, headers=T1)
        check("limit 缺省 50（全量返回）",
              st == 200 and len(pg0["events"]) == 2)

        # ---- 9. 查询参数校验 -> 400 ----
        def expect_400(name, query):
            st, r = history(cred, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        expect_400("limit=0", "limit=0")
        expect_400("limit=201", "limit=201")
        expect_400("limit=-1", "limit=-1")
        expect_400("limit=1.5", "limit=1.5")
        expect_400("limit=true", "limit=true")
        expect_400("limit 空白", "limit=%20")
        expect_400("limit 空值", "limit=")
        expect_400("重复 limit", "limit=1&limit=2")
        expect_400("limit Unicode 数字", "limit=%EF%BC%91%EF%BC%92")
        expect_400("after=-1", "after=-1")
        expect_400("after=1.0", "after=1.0")
        expect_400("after 非数字", "after=abc")
        expect_400("after 空白", "after=%20")
        expect_400("重复 after", "after=0&after=1")
        expect_400("after Unicode 数字", "after=%EF%BC%91")
        st, _ = history(cred, headers=T1, query="limit=1")
        check("limit=1 合法", st == 200)
        st, _ = history(cred, headers=T1, query="limit=200")
        check("limit=200 合法", st == 200)
        st, _ = history(cred, headers=T1, query="after=0")
        check("after=0 合法", st == 200)

        # ---- 10. 未知 / 跨租户 / 租户头 ----
        st, _ = history("vc_unknown", headers=T1)
        check("未知凭证 -> 404", st == 404)
        st, _ = history(cred, headers=T2)
        check("跨租户不可探测 -> 404", st == 404)
        st, _ = history(cred, headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400", st == 400)

        # ---- 11. 只读：历史查询不记审计 ----
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        for _ in range(3):
            history(cred, headers=T1)
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("历史查询只读、不记审计",
              len(audit_after["events"]) == n_before)

        # ---- 12. 跨租户独立历史与游标空间 ----
        cred_t2 = make_credential(T2, "two")
        st, _ = _http("PUT", f"{base}/v1/credentials/{cred_t2}/status",
                      {"status": "active"}, headers=T2)
        check("T2 独立登记 -> 201", st == 201)
        st, h2 = history(cred_t2, headers=T2)
        check("租户历史隔离",
              st == 200 and len(h2["events"]) == 1
              and h2["events"][0]["status"] == "active")
        st, h1 = history(cred, headers=T1)
        check("T1 历史不受 T2 影响",
              st == 200 and len(h1["events"]) == 2)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 13. 跨重启持久化：cursor 与历史保留，新事件继续递增 ----
    proc = start_server(port, env)
    try:
        assert wait_up(proc, port), "服务重启超时"
        st, h = history(cred, headers=T1)
        cursors = [e["cursor"] for e in h["events"]]
        check("重启后历史与 cursor 保留",
              st == 200 and len(h["events"]) == 2
              and [e["status"] for e in h["events"]] == ["active", "revoked"]
              and cursors == sorted(cursors))
        cred3 = make_credential(T1, "three")
        st, _ = _http("PUT", f"{base}/v1/credentials/{cred3}/status",
                      {"status": "active"}, headers=T1)
        check("重启后登记 -> 201", st == 201)
        st, h3 = history(cred3, headers=T1)
        check("重启后 cursor 在既有最大值之后继续递增",
              st == 200 and len(h3["events"]) == 1
              and h3["events"][0]["cursor"] > max(cursors)
              and h3["events"][0]["audit_seq"] is not None)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 14. 旧状态缺历史：补兼容项（audit 为 null，cursor 持久化）----
    legacy_path = tempfile.mktemp(suffix=".json")
    legacy_env = dict(os.environ, VCBACKEND_STORE=legacy_path)
    lp = start_server(port + 1, legacy_env)
    lbase = f"http://127.0.0.1:{port + 1}"
    L = {"X-Tenant-ID": "legacy-local"}
    try:
        assert wait_up(lp, port + 1), "旧状态服务启动超时"
        st, r = _http(
            "POST", f"{lbase}/v1/dids",
            {"method": "example", "public_key": "legacy-issuer"}, headers=L,
        )
        assert st == 201, r
        issuer = r["did"]
        st, r = _http(
            "POST", f"{lbase}/v1/dids",
            {"method": "example", "public_key": "legacy-subject"}, headers=L,
        )
        assert st == 201, r
        subject = r["did"]
        st, r = _http(
            "POST", f"{lbase}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject,
             "claims": {"k": "v"}},
            headers=L,
        )
        assert st == 201, r
        legacy_active = r["credential_id"]
        st, r = _http(
            "POST", f"{lbase}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject,
             "claims": {"k": "w"}},
            headers=L,
        )
        assert st == 201, r
        legacy_revoked = r["credential_id"]
        st, _ = _http(
            "PUT", f"{lbase}/v1/credentials/{legacy_active}/status",
            {"status": "active"}, headers=L,
        )
        assert st == 201
        st, _ = _http(
            "POST", f"{lbase}/v1/credentials/{legacy_revoked}/revoke",
            {"reason": "  旧凭证吊销  "}, headers=L,
        )
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 手工删除历史命名空间与游标计数，模拟旧版本状态文件
    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["credential_status_events"] = {}
    raw.pop("credential_status_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(port + 1, legacy_env)
    try:
        assert wait_up(lp, port + 1), "旧状态服务重启超时"
        st, h = _http(
            "GET",
            f"{lbase}/v1/credentials/{legacy_active}/status/history",
            headers=L,
        )
        compat_active_cursor = None
        ok_active = (
            st == 200 and len(h["events"]) == 1
            and set(h["events"][0]) == EVENT_KEYS
            and h["events"][0]["status"] == "active"
            and h["events"][0]["reason"] is None
            and h["events"][0]["revoked_at"] is None
            and isinstance(h["events"][0]["updated_at"], str)
            and h["events"][0]["audit_seq"] is None
            and h["events"][0]["audit_timestamp"] is None
            and isinstance(h["events"][0]["cursor"], int)
            and h["events"][0]["cursor"] >= 1
        )
        if ok_active:
            compat_active_cursor = h["events"][0]["cursor"]
        check("旧 active 状态补兼容项：audit null、cursor 正整数",
              ok_active)

        st, h = _http(
            "GET",
            f"{lbase}/v1/credentials/{legacy_revoked}/status/history",
            headers=L,
        )
        ok_revoked = (
            st == 200 and len(h["events"]) == 1
            and h["events"][0]["status"] == "revoked"
            and h["events"][0]["reason"] == "旧凭证吊销"
            and h["events"][0]["revoked_at"] is not None
            and h["events"][0]["audit_seq"] is None
            and h["events"][0]["audit_timestamp"] is None
            and h["events"][0]["cursor"] != compat_active_cursor
        )
        check("旧 revoked 状态补兼容项：裁剪 reason 与 revoked_at 保留",
              ok_revoked)

        # 兼容项仍可按 cursor 分页
        st, hp = _http(
            "GET",
            f"{lbase}/v1/credentials/{legacy_active}/status/history"
            f"?after={compat_active_cursor or 0}",
            headers=L,
        )
        check("audit 为 null 的兼容项仍按 cursor 分页",
              st == 200 and hp["events"] == []
              and hp["next_after"] == compat_active_cursor)

        # 触发一次吊销，使兼容项随原子写落盘
        st, _ = _http(
            "POST", f"{lbase}/v1/credentials/{legacy_active}/revoke",
            {"reason": "重启后吊销"}, headers=L,
        )
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 再重启：兼容项 cursor 持久化不变，新事件 cursor 更大且关联审计
    lp = start_server(port + 1, legacy_env)
    try:
        assert wait_up(lp, port + 1), "旧状态服务二次重启超时"
        st, h = _http(
            "GET",
            f"{lbase}/v1/credentials/{legacy_active}/status/history",
            headers=L,
        )
        check(
            "兼容项随原子写持久化、cursor 稳定，新事件追加在后",
            st == 200 and len(h["events"]) == 2
            and h["events"][0]["cursor"] == compat_active_cursor
            and h["events"][0]["audit_seq"] is None
            and h["events"][1]["status"] == "revoked"
            and h["events"][1]["reason"] == "重启后吊销"
            and h["events"][1]["cursor"] > compat_active_cursor
            and h["events"][1]["audit_seq"] is not None,
        )
        # 无状态凭证不受补录影响
        st, r = _http(
            "POST", f"{lbase}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject,
             "claims": {"k": "z"}},
            headers=L,
        )
        assert st == 201, r
        st, h = _http(
            "GET",
            f"{lbase}/v1/credentials/{r['credential_id']}/status/history",
            headers=L,
        )
        check("新签发无状态凭证仍为空历史",
              st == 200 and h["events"] == [] and h["next_after"] == 0)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    for path in (store_path, legacy_path):
        if os.path.exists(path):
            os.remove(path)

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
