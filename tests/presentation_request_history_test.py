#!/usr/bin/env python3
"""展示请求历史查询（GET /v1/presentation-requests/{request_id}/history）端到端测试。

覆盖：
- 生命周期：创建/首次取消/request_id 模式首次成功消费各追加一条历史
  （action/status/reason/presentation_id 与审计 seq、整数 Unix 秒、
  cursor==audit_seq），重复取消/消费、验真失败、保存失败、生成演示与
  自然到期均不追加；
- 分页：limit/after 默认值、边界与非法值（重复/未知/空值/符号/小数/
  Unicode 数字）400，参数校验先于资源校验，空页 next_after 保持
  after；
- 租户：缺省 default、显式空 X-Tenant-ID 400、未知或他租户请求 404，
  400/404 正文均为仅含非空中文 error 的对象；
- 只读：查询不改请求对象、不追加审计；重启前后结果一致；
- 旧请求（状态文件无对应审计）返回空数组，不补造事件；
- 既有 GET 查询与取消行为不变。

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

from vcbackend.store import (  # noqa: E402
    AUDIT_PRESENTATION_CONSUMED,
    AUDIT_PRESENTATION_REQUEST_CANCELLED,
    AUDIT_PRESENTATION_REQUEST_CREATED,
    VCStore,
)

PORT = 8968
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

EVENT_KEYS = [
    "action", "status", "reason", "presentation_id",
    "audit_seq", "audit_timestamp", "cursor",
]


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


def history_url(request_id, query=""):
    return (
        f"{BASE}/v1/presentation-requests/{request_id}/history"
        + (f"?{query}" if query else "")
    )


def audit_events(tenant, action=None, resource_id=None):
    store = VCStore(STORE)
    return [
        event for event in store._audit
        if event.get("tenant_id") == tenant
        and (action is None or event.get("action") == action)
        and (resource_id is None or event.get("resource_id") == resource_id)
    ]


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
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
                       "claims": {"role": "admin", "age": 30}})
        assert st == 201, cr
        cred = cr["credential_id"]

        # ---------------- 生命周期：创建 -> 首次取消 ----------------
        st, req = http("POST", f"{BASE}/v1/presentation-requests",
                       {"challenge": "hist-cancel", "expires_in": 600,
                        "disclose": ["/role"]})
        assert st == 201, req
        rid = req["request_id"]

        st, h = http("GET", history_url(rid))
        check("创建后历史 200", st == 200)
        check("响应恰含 request_id/events/next_after",
              list(h) == ["request_id", "events", "next_after"])
        check("request_id 回显", h.get("request_id") == rid)
        check("创建后恰一条事件", len(h.get("events", [])) == 1)
        ev = h["events"][0]
        check("事件键序恰为契约七键", list(ev) == EVENT_KEYS)
        created_audit = audit_events(
            "default", AUDIT_PRESENTATION_REQUEST_CREATED, rid)
        check("创建审计恰一条", len(created_audit) == 1)
        check("创建事件字段",
              ev["action"] == "presentation.request.created"
              and ev["status"] == "pending"
              and ev["reason"] is None
              and ev["presentation_id"] is None)
        check("创建事件 cursor==audit_seq 且为审计序号",
              ev["cursor"] == ev["audit_seq"]
              and ev["audit_seq"] == created_audit[0]["seq"])
        check("创建事件 audit_timestamp 为审计整数 Unix 秒",
              isinstance(ev["audit_timestamp"], int)
              and ev["audit_timestamp"] == created_audit[0]["timestamp"])
        check("单事件页 next_after 为末项 cursor",
              h["next_after"] == ev["cursor"])

        # 生成演示（未消费）不追加历史
        st, vp = http("POST", f"{BASE}/v1/credentials/{cred}/present",
                      {"request_id": rid})
        assert st == 201, vp
        st, h2 = http("GET", history_url(rid))
        check("生成演示不追加历史",
              st == 200 and len(h2["events"]) == 1 and h2 == h)

        # 验真失败（篡改）不追加历史
        tampered = dict(vp)
        tampered["proof"] = "x"
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{vp['presentation_id']}/verify",
            {"presentation": tampered, "request_id": rid})
        assert st == 200 and r.get("valid") is False, r
        st, h3 = http("GET", history_url(rid))
        check("验真失败不追加历史", st == 200 and h3 == h)

        # 首次取消追加一条；幂等重复取消不追加
        st, c = http("POST",
                     f"{BASE}/v1/presentation-requests/{rid}/cancel",
                     {"reason": "  计划变更  "})
        assert st == 200 and c.get("cancel_reason") == "计划变更", c
        st, h = http("GET", history_url(rid))
        check("取消后恰两条事件", st == 200 and len(h["events"]) == 2)
        ev_cancel = h["events"][1]
        cancel_audit = audit_events(
            "default", AUDIT_PRESENTATION_REQUEST_CANCELLED, rid)
        check("取消审计恰一条", len(cancel_audit) == 1)
        check("取消事件字段（reason 为保存的首次原因）",
              ev_cancel["action"] == "presentation.request.cancelled"
              and ev_cancel["status"] == "cancelled"
              and ev_cancel["reason"] == "计划变更"
              and ev_cancel["presentation_id"] is None
              and ev_cancel["audit_seq"] == cancel_audit[0]["seq"]
              and ev_cancel["audit_timestamp"]
              == cancel_audit[0]["timestamp"]
              and ev_cancel["cursor"] == cancel_audit[0]["seq"])
        check("事件按 cursor 升序",
              h["events"][0]["cursor"] < h["events"][1]["cursor"])
        check("取消后 next_after 为取消事件 cursor",
              h["next_after"] == ev_cancel["cursor"])
        st, c2 = http("POST",
                      f"{BASE}/v1/presentation-requests/{rid}/cancel",
                      {"reason": "另一个原因"})
        assert st == 200, c2
        st, h4 = http("GET", history_url(rid))
        check("重复取消不追加历史", st == 200 and h4 == h)
        check("重复取消不追加取消审计",
              len(audit_events(
                  "default", AUDIT_PRESENTATION_REQUEST_CANCELLED, rid))
              == 1)

        # ---------------- 生命周期：创建 -> 首次成功消费 ----------------
        st, qreq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "hist-consume", "expires_in": 600,
                         "disclose": ["/role"]})
        assert st == 201, qreq
        qid = qreq["request_id"]
        st, qvp = http("POST", f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": qid})
        assert st == 201, qvp
        qpid = qvp["presentation_id"]
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{qpid}/verify",
            {"presentation": qvp, "request_id": qid})
        assert r == {"valid": True}, r
        st, h = http("GET", history_url(qid))
        check("消费后恰两条事件", st == 200 and len(h["events"]) == 2)
        ev_consumed = h["events"][1]
        consumed_audit = audit_events(
            "default", AUDIT_PRESENTATION_CONSUMED, qpid)
        check("消费沿用演示消费审计（恰一条，不另记请求消费审计）",
              len(consumed_audit) == 1
              and consumed_audit[0]["resource_type"] == "presentation")
        check("消费事件字段（presentation_id 为实际演示 ID）",
              ev_consumed["action"] == "presentation.consumed"
              and ev_consumed["status"] == "consumed"
              and ev_consumed["reason"] is None
              and ev_consumed["presentation_id"] == qpid
              and ev_consumed["audit_seq"] == consumed_audit[0]["seq"]
              and ev_consumed["audit_timestamp"]
              == consumed_audit[0]["timestamp"]
              and ev_consumed["cursor"] == consumed_audit[0]["seq"])
        check("消费事件 cursor 大于创建事件",
              h["events"][0]["cursor"] < ev_consumed["cursor"])

        # 重复消费（演示已消费）与 consumed 后取消 409 均不追加历史
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{qpid}/verify",
            {"presentation": qvp, "request_id": qid})
        assert st == 200 and r.get("valid") is False, r
        st, r = http("POST",
                     f"{BASE}/v1/presentation-requests/{qid}/cancel", {})
        check("consumed 取消 409", st == 409 and r == {"error": "展示请求已消费"})
        st, h5 = http("GET", history_url(qid))
        check("重复消费与 409 取消不追加历史", st == 200 and h5 == h)
        check("消费审计仍恰一条",
              len(audit_events(
                  "default", AUDIT_PRESENTATION_CONSUMED, qpid)) == 1)

        # ---------------- 自然到期不追加历史 ----------------
        st, ereq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "hist-expire", "expires_in": 1})
        assert st == 201, ereq
        eid = ereq["request_id"]
        time.sleep(1.3)
        st, h = http("GET", history_url(eid))
        check("自然到期不追加历史",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["action"]
              == "presentation.request.created")

        # ---------------- 分页 ----------------
        st, h = http("GET", history_url(qid, "limit=1"))
        check("limit=1 返回首条且 next_after 为其 cursor",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["action"]
              == "presentation.request.created"
              and h["next_after"] == h["events"][0]["cursor"])
        first_cursor = h["events"][0]["cursor"]
        st, h = http("GET", history_url(qid, f"limit=1&after={first_cursor}"))
        check("after 续页返回次条",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["action"] == "presentation.consumed"
              and h["next_after"] == h["events"][0]["cursor"])
        last_cursor = h["events"][0]["cursor"]
        st, h = http("GET", history_url(qid, f"after={last_cursor}"))
        check("空页 events 为空且 next_after 保持 after",
              st == 200 and h["events"] == []
              and h["next_after"] == last_cursor)
        st, h = http("GET", history_url(qid, "after=0&limit=200"))
        check("after=0 从头返回全部",
              st == 200 and len(h["events"]) == 2)
        st, h = http("GET", history_url(qid, "after=999999"))
        check("after 超过全部 cursor 返回空页且保持 after",
              st == 200 and h["events"] == [] and h["next_after"] == 999999)

        # 参数非法一律 400（且先于资源校验：对未知请求同样 400）
        unknown = f"pr_{'0' * 32}"
        for name, query in (
            ("未知参数", "foo=1"),
            ("limit 重复", "limit=1&limit=2"),
            ("after 重复", "after=1&after=2"),
            ("limit 空值", "limit="),
            ("after 空值", "after="),
            ("limit 为 0", "limit=0"),
            ("limit 为 201", "limit=201"),
            ("limit 负数", "limit=-1"),
            ("after 负数", "after=-1"),
            ("limit 小数", "limit=1.5"),
            ("after 小数", "after=0.5"),
            ("limit 字母", "limit=abc"),
            ("after 空白", "after=%20"),
            ("limit 布尔词", "limit=true"),
            ("after Unicode 数字", "after=%D9%A1"),
            ("limit 加号", "limit=%2B1"),
        ):
            st, r = http("GET", history_url(qid, query))
            check(f"非法参数 400: {name}",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"] and list(r) == ["error"])
            st, r = http("GET", history_url(unknown, query))
            check(f"未知资源非法参数仍 400（先于资源校验）: {name}",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"] and list(r) == ["error"])

        # ---------------- 租户与 404 ----------------
        st, r = http("GET", history_url(qid),
                     headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400",
              st == 400 and isinstance(r.get("error"), str)
              and r["error"] and list(r) == ["error"])
        st, r = http("GET", history_url(unknown))
        check("未知请求 404 且正文仅含非空中文 error",
              st == 404 and list(r) == ["error"]
              and isinstance(r["error"], str) and r["error"])
        st, other = http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "hist-other"},
                         headers={"X-Tenant-ID": "tenant-b"})
        assert st == 201, other
        oid = other["request_id"]
        st, r = http("GET", history_url(oid))
        check("他租户请求 404", st == 404 and list(r) == ["error"])
        st, h = http("GET", history_url(oid),
                     headers={"X-Tenant-ID": "tenant-b"})
        check("本租户（tenant-b）可查且仅见本租户事件",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["action"]
              == "presentation.request.created")
        st, h = http("GET", history_url(qid),
                     headers={"X-Tenant-ID": "tenant-b"})
        check("tenant-b 查 default 请求 404", st == 404)

        # ---------------- 只读：查询不改请求、不追加审计 ----------------
        before_audits = len(VCStore(STORE)._audit)
        st, before_obj = http("GET", f"{BASE}/v1/presentation-requests/{qid}")
        assert st == 200
        st, h_first = http("GET", history_url(qid))
        st, h_second = http("GET", history_url(qid))
        check("重复查询结果一致", st == 200 and h_second == h_first)
        st, after_obj = http("GET", f"{BASE}/v1/presentation-requests/{qid}")
        check("查询不改请求对象", after_obj == before_obj)
        check("查询不追加审计", len(VCStore(STORE)._audit) == before_audits)
        check("历史不泄露挑战与披露内容",
              all("challenge" not in e and "disclose" not in e
                  for e in h_first["events"]))

        # ---------------- 既有 GET 与取消行为不变 ----------------
        st, got = http("GET", f"{BASE}/v1/presentation-requests/{qid}")
        check("既有 GET 查询对象不变",
              st == 200 and got.get("status") == "consumed"
              and got.get("consumed_presentation_id") == qpid
              and "events" not in got and "next_after" not in got)

        # ---------------- 重启持久化 ----------------
        keep = h_first
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, h = http("GET", history_url(qid))
        check("重启后历史一致", st == 200 and h == keep)
        st, h = http("GET", history_url(rid))
        check("重启后取消历史一致",
              st == 200 and len(h["events"]) == 2
              and h["events"][1]["reason"] == "计划变更")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    legacy_ok = test_legacy_request_without_audit()
    if not legacy_ok:
        failures.append("旧请求无审计返回空数组")

    rollback_ok = test_save_failure_no_history()
    if not rollback_ok:
        failures.append("保存失败不追加历史")

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


def test_legacy_request_without_audit():
    """旧请求（状态文件中有请求行但无对应审计）返回空数组，不补造。"""
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    path = tempfile.mktemp(suffix=".json")
    legacy_id = f"pr_{'1' * 32}"
    data = {
        "tenants": {
            "default": {
                "presentation_requests": {
                    legacy_id: {
                        "request_id": legacy_id,
                        "challenge": "legacy",
                        "expires_at": "2099-01-01T00:00:00Z",
                        "disclose": [],
                        "issuer_dids": None,
                        "holder_binding": False,
                        "status": "pending",
                    }
                }
            }
        },
        "audit": [],
        "audit_seq": 0,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)

    port = PORT + 100
    env = dict(os.environ, VCBACKEND_STORE=path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "旧数据服务启动超时"
        base = f"http://127.0.0.1:{port}"
        st, h = http(
            "GET", f"{base}/v1/presentation-requests/{legacy_id}/history")
        check("旧请求历史 200 且事件为空数组",
              st == 200 and h.get("events") == []
              and h.get("request_id") == legacy_id)
        check("旧请求空页 next_after 保持 after（缺省 0）",
              h.get("next_after") == 0)
        st, h = http(
            "GET",
            f"{base}/v1/presentation-requests/{legacy_id}/history?after=7")
        check("旧请求空页 next_after 保持显式 after",
              st == 200 and h.get("events") == []
              and h.get("next_after") == 7)
        store = VCStore(path)
        check("查询不为旧请求补造审计", store._audit == [])
        check("查询不改旧请求状态",
              store._tenants["default"]["presentation_requests"]
              [legacy_id]["status"] == "pending")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(path):
            os.unlink(path)
    return not failures


def test_save_failure_no_history():
    """取消落盘失败回滚后历史仍只有创建事件，恢复后重试正常追加。"""
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    path = tempfile.mktemp(suffix=".json")
    try:
        store = VCStore(path)
        rec = store.create_presentation_request(
            "default", challenge="hist-rb", expires_in=60, disclose=None,
            issuer_dids=None, holder_binding=False)
        rid = rec.request_id

        original_save = store._save_locked

        def fail_save():
            raise OSError("disk full")

        store._save_locked = fail_save  # type: ignore[assignment]
        raised = False
        try:
            store.cancel_presentation_request("default", rid, "原因")
        except OSError:
            raised = True
        store._save_locked = original_save  # type: ignore[assignment]
        check("落盘失败原样抛出", raised)
        events, next_after = store.list_presentation_request_history(
            "default", rid)
        check("保存失败不追加历史（仅创建事件）",
              len(events) == 1
              and events[0].action == "presentation.request.created"
              and events[0].status == "pending"
              and next_after == events[0].cursor)

        store.cancel_presentation_request("default", rid, "原因")
        events, next_after = store.list_presentation_request_history(
            "default", rid)
        check("恢复后取消事件追加",
              len(events) == 2
              and events[1].action == "presentation.request.cancelled"
              and events[1].reason == "原因"
              and next_after == events[1].cursor)
        check("直连 store 分页：after 排除首项",
              store.list_presentation_request_history(
                  "default", rid, after=events[0].cursor, limit=1
              )[0][0].action == "presentation.request.cancelled")
        check("未知请求抛 NotFoundError",
              _raises_not_found(store, rid))
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return not failures


def _raises_not_found(store, rid):
    from vcbackend.store import NotFoundError

    try:
        store.list_presentation_request_history("default", f"{rid}x")
    except NotFoundError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
