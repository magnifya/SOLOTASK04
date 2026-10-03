#!/usr/bin/env python3
"""单请求历史查询（GET /v1/presentation-requests/{request_id}/history）端到端测试。

覆盖：创建/首次取消/首次成功消费三类事件的字段、顺序与审计序号/时间
对齐；消费沿用演示消费审计不另记；重复取消/消费、验真失败、生成演示
与自然到期不追加历史；旧请求（无对应审计）返回空数组不补造；limit/
after 分页与全部非法参数 400；租户头缺省/显式空/跨租户；参数与租户
头先于资源校验；只读（不改状态不记审计）；重启前后结果一致。

直接运行：python3 tests/presentation_request_history_test.py
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

from vcbackend.store import VCStore  # noqa: E402

PORT = 8971
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

EVENT_KEYS = {
    "action", "status", "reason", "presentation_id",
    "audit_seq", "audit_timestamp", "cursor",
}


def http(method, url, payload=None, headers=None, raw=None):
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


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def start_server():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(PORT), "服务启动超时"
    return proc


def history(request_id, query="", headers=None):
    suffix = f"?{query}" if query else ""
    return http(
        "GET",
        f"{BASE}/v1/presentation-requests/{request_id}/history{suffix}",
        headers=headers,
    )


def tenant_audits(tenant):
    st, body = http("GET", f"{BASE}/v1/audit?limit=200",
                    headers={"X-Tenant-ID": tenant})
    assert st == 200, body
    return body["events"]


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    proc = start_server()
    try:
        # 预置签发者/主体/凭证，供 request_id 模式生成并消费演示。
        st, iss = http("POST", f"{BASE}/v1/dids",
                       {"method": "example", "public_key": "hist-issuer"})
        assert st == 201, iss
        issuer = iss["did"]
        st, sub = http("POST", f"{BASE}/v1/dids",
                       {"method": "example", "public_key": "hist-subject"})
        assert st == 201, sub
        subject = sub["did"]
        st, cr = http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"role": "admin"}})
        assert st == 201, cr
        cred = cr["credential_id"]

        # ---------------- 创建即有一条 created 事件 ----------------
        st, req = http("POST", f"{BASE}/v1/presentation-requests",
                       {"challenge": "hist-cancel", "expires_in": 600})
        assert st == 201, req
        rid = req["request_id"]
        st, body = history(rid)
        check("创建后历史 200", st == 200)
        check("响应正文恰含三键",
              set(body) == {"request_id", "events", "next_after"})
        check("request_id 回显", body.get("request_id") == rid)
        events = body["events"]
        check("创建后恰一条事件", len(events) == 1)
        ev = events[0]
        check("事件恰含七键", set(ev) == EVENT_KEYS)
        check("created 事件字段",
              ev["action"] == "presentation.request.created"
              and ev["status"] == "pending"
              and ev["reason"] is None
              and ev["presentation_id"] is None)
        check("cursor 等于 audit_seq",
              ev["cursor"] == ev["audit_seq"]
              and isinstance(ev["audit_seq"], int))
        check("audit_timestamp 为整数 Unix 秒",
              isinstance(ev["audit_timestamp"], int)
              and abs(ev["audit_timestamp"] - time.time()) < 60)
        check("next_after 为末项 cursor",
              body["next_after"] == ev["cursor"])
        # 与审计流水对齐
        audits = tenant_audits("default")
        created_audit = next(
            e for e in audits
            if e["action"] == "presentation.request.created"
            and e["resource_id"] == rid)
        check("事件 audit_seq/timestamp 与审计一致",
              ev["audit_seq"] == created_audit["seq"]
              and ev["audit_timestamp"] == created_audit["timestamp"])

        # ---------------- 取消追加 cancelled（含首次原因） ----------------
        st, c = http("POST",
                     f"{BASE}/v1/presentation-requests/{rid}/cancel",
                     {"reason": "  不需要展示了  "})
        assert st == 200, c
        st, body = history(rid)
        events = body["events"]
        check("取消后两条事件且按 cursor 升序",
              len(events) == 2
              and events[0]["cursor"] < events[1]["cursor"])
        check("cancelled 事件字段",
              events[1]["action"] == "presentation.request.cancelled"
              and events[1]["status"] == "cancelled"
              and events[1]["reason"] == "不需要展示了"
              and events[1]["presentation_id"] is None)
        cancel_audit = next(
            e for e in tenant_audits("default")
            if e["action"] == "presentation.request.cancelled"
            and e["resource_id"] == rid)
        check("cancelled 事件对齐取消审计",
              events[1]["audit_seq"] == cancel_audit["seq"]
              and events[1]["audit_timestamp"]
              == cancel_audit["timestamp"])

        # 重复取消（幂等）不追加历史
        st, again = http(
            "POST", f"{BASE}/v1/presentation-requests/{rid}/cancel",
            {"reason": "另一个原因"})
        assert st == 200 and again["cancel_reason"] == "不需要展示了"
        st, body2 = history(rid)
        check("重复取消不追加历史", body2["events"] == events)

        # ---------------- 消费沿用演示消费审计 ----------------
        st, req2 = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "hist-consume", "expires_in": 600,
                         "disclose": ["/role"]})
        assert st == 201, req2
        rid2 = req2["request_id"]
        st, vp = http("POST", f"{BASE}/v1/credentials/{cred}/present",
                      {"request_id": rid2})
        assert st == 201, vp
        pid = vp["presentation_id"]
        # 生成演示不追加请求历史
        st, body = history(rid2)
        check("生成演示不追加历史",
              [e["action"] for e in body["events"]]
              == ["presentation.request.created"])
        # 验真失败不追加历史（先取消另一个请求再对其验真）
        st, req3 = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "hist-fail", "expires_in": 600})
        rid3 = req3["request_id"]
        st, vp3 = http("POST", f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": rid3})
        assert st == 201, vp3
        http("POST", f"{BASE}/v1/presentation-requests/{rid3}/cancel", {})
        st, vr = http(
            "POST", f"{BASE}/v1/presentations/{vp3['presentation_id']}/verify",
            {"presentation": vp3, "request_id": rid3})
        assert st == 200 and vr == {"valid": False,
                                    "reason": "展示请求已取消"}, vr
        st, body = history(rid3)
        check("验真失败不追加历史",
              [e["action"] for e in body["events"]]
              == ["presentation.request.created",
                  "presentation.request.cancelled"])
        # 首次成功消费
        st, vr = http(
            "POST", f"{BASE}/v1/presentations/{pid}/verify",
            {"presentation": vp, "request_id": rid2})
        assert vr == {"valid": True}, vr
        st, body = history(rid2)
        events = body["events"]
        check("消费后两条事件",
              [e["action"] for e in events]
              == ["presentation.request.created",
                  "presentation.consumed"])
        check("consumed 事件字段",
              events[1]["status"] == "consumed"
              and events[1]["reason"] is None
              and events[1]["presentation_id"] == pid)
        consumed_audit = next(
            e for e in tenant_audits("default")
            if e["action"] == "presentation.consumed"
            and e["resource_id"] == pid)
        check("consumed 事件沿用演示消费审计",
              events[1]["audit_seq"] == consumed_audit["seq"]
              and events[1]["audit_timestamp"]
              == consumed_audit["timestamp"])
        # 重复消费（验真）不追加历史
        st, vr = http(
            "POST", f"{BASE}/v1/presentations/{pid}/verify",
            {"presentation": vp, "request_id": rid2})
        assert st == 200 and vr.get("valid") is False
        st, body2 = history(rid2)
        check("重复消费不追加历史", body2["events"] == events)

        # ---------------- 自然到期不追加历史 ----------------
        st, req4 = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "hist-expire", "expires_in": 1})
        rid4 = req4["request_id"]
        time.sleep(1.2)
        st, body = history(rid4)
        check("自然到期不追加历史",
              [e["action"] for e in body["events"]]
              == ["presentation.request.created"])

        # ---------------- 分页：limit/after/next_after ----------------
        st, body = history(rid2, "limit=1")
        check("limit=1 仅首条",
              st == 200 and len(body["events"]) == 1
              and body["events"][0]["action"]
              == "presentation.request.created")
        first_cursor = body["events"][0]["cursor"]
        check("首页 next_after 为末项 cursor",
              body["next_after"] == first_cursor)
        st, body = history(rid2, f"limit=1&after={first_cursor}")
        check("after 翻页取次条",
              st == 200 and len(body["events"]) == 1
              and body["events"][0]["action"] == "presentation.consumed"
              and body["next_after"] == body["events"][0]["cursor"])
        last_cursor = body["next_after"]
        st, body = history(rid2, f"after={last_cursor}")
        check("空页 events 为空且 next_after 保持 after",
              st == 200 and body["events"] == []
              and body["next_after"] == last_cursor)
        st, body = history(rid2, "after=999999")
        check("超出末项空页保持 after",
              st == 200 and body["events"] == []
              and body["next_after"] == 999999)
        st, body = history(rid2, "limit=200&after=0")
        check("limit=200 合法上限", st == 200 and len(body["events"]) == 2)
        st, body = history(rid2, "limit=1&after=0")
        check("after=0 显式合法", st == 200 and len(body["events"]) == 1)

        # ---------------- 非法参数一律 400（先于资源校验） ----------------
        unknown = "pr_" + "0" * 32
        for name, query in (
            ("limit 为 0", "limit=0"),
            ("limit 超 200", "limit=201"),
            ("limit 非数字", "limit=abc"),
            ("limit 空值", "limit="),
            ("limit 小数", "limit=1.5"),
            ("limit 带符号", "limit=+1"),
            ("limit 带空白", "limit=%201"),
            ("limit 重复", "limit=1&limit=2"),
            ("after 为负", "after=-1"),
            ("after 非数字", "after=x"),
            ("after 空值", "after="),
            ("after 重复", "after=0&after=1"),
            ("未知参数", "foo=1"),
            ("未知参数空值", "foo="),
        ):
            st, r = history(rid2, query)
            check(f"非法参数 400: {name}",
                  st == 400 and set(r) == {"error"}
                  and isinstance(r["error"], str) and r["error"])
            st, r = history(unknown, query)
            check(f"未知请求非法参数仍 400: {name}", st == 400)

        # ---------------- 404 与租户隔离 ----------------
        st, r = history(unknown)
        check("未知请求 404",
              st == 404 and set(r) == {"error"}
              and isinstance(r["error"], str) and r["error"])
        st, r = history(rid2, headers={"X-Tenant-ID": "other"})
        check("跨租户同 ID 404", st == 404 and set(r) == {"error"})
        st, r = history(rid2, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400 and set(r) == {"error"})
        st, r = history(unknown, headers={"X-Tenant-ID": ""})
        check("空租户头先于资源校验 400", st == 400)
        # 他租户自有请求互不可见
        st, oreq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "hist-other"},
                        headers={"X-Tenant-ID": "other"})
        assert st == 201, oreq
        st, body = history(oreq["request_id"],
                           headers={"X-Tenant-ID": "other"})
        check("他租户自身历史可查",
              st == 200 and len(body["events"]) == 1)
        st, r = history(oreq["request_id"])
        check("他租户请求对本租户 404", st == 404)

        # ---------------- 只读：不改状态、不记审计 ----------------
        audits_before = len(tenant_audits("default"))
        st, before = http("GET", f"{BASE}/v1/presentation-requests/{rid2}")
        assert st == 200
        history(rid2)
        history(rid2, "limit=1")
        history(rid2, "after=1")
        st, after_get = http("GET", f"{BASE}/v1/presentation-requests/{rid2}")
        check("历史查询不修改请求对象", before == after_get)
        check("历史查询不追加审计",
              len(tenant_audits("default")) == audits_before)

        # ---------------- 重启前快照 ----------------
        st, snap_cancel = history(rid)
        st, snap_consume = history(rid2)
        assert st == 200
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---------------- 注入无审计的旧请求行（模拟历史数据） ----------------
    old_rid = "pr_" + "1" * 32
    dstore = VCStore(STORE)
    with dstore._lock:
        bucket = dstore._ensure_bucket_locked("default")
        bucket["presentation_requests"][old_rid] = {
            "request_id": old_rid,
            "challenge": "legacy",
            "expires_at": "2030-01-01T00:00:00Z",
            "disclose": [],
            "issuer_dids": None,
            "holder_binding": False,
            "status": "pending",
        }
        dstore._save_locked()
    del dstore

    proc = start_server()
    try:
        st, body = history(old_rid)
        check("旧请求历史 200 且事件为空",
              st == 200 and body["events"] == []
              and body["next_after"] == 0)
        st, body = history(old_rid, "after=7&limit=10")
        check("旧请求空页保持 after",
              st == 200 and body["events"] == []
              and body["next_after"] == 7)
        check("重启后取消历史一致", history(rid)[1] == snap_cancel)
        check("重启后消费历史一致", history(rid2)[1] == snap_consume)
        # 旧请求后续生命周期事件正常追加
        st, c = http(
            "POST", f"{BASE}/v1/presentation-requests/{old_rid}/cancel",
            {"reason": "旧请求取消"})
        assert st == 200, c
        st, body = history(old_rid)
        check("旧请求仅返回有对应审计的事件",
              [e["action"] for e in body["events"]]
              == ["presentation.request.cancelled"]
              and body["events"][0]["reason"] == "旧请求取消")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
