#!/usr/bin/env python3
"""验证方展示请求主动取消（cancel）端到端测试。

覆盖入口校验（空体/非法 JSON/非对象/多余字段/非法 reason/租户头/404/
409）、首次与幂等取消语义、审计仅首次追加、落盘失败回滚（直连
VCStore）、GET cancelled 对象、present request_id 模式已取消 400
（先于过期与凭证判定）、verify request_id 模式已取消 200 valid:false
（先于过期与凭证校验、不消费）、绑定/非绑定一致、重启持久化，以及
pending/consumed 与普通 challenge 模式既有行为不变。

直接运行：python3 tests/presentation_request_cancel_test.py
"""

import json
import os
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

from vcbackend.store import (  # noqa: E402
    AUDIT_PRESENTATION_REQUEST_CANCELLED,
    VCStore,
)

PORT = 8967
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"


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


def wait_expired(expires_at, slack=0.2):
    moment = datetime.strptime(
        expires_at, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc).timestamp()
    deadline = time.time() + 10
    while time.time() <= moment + slack:
        if time.time() > deadline:
            break
        time.sleep(0.05)


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


def count_cancel_audits(proc_store, tenant, request_id):
    return sum(
        1
        for event in proc_store._audit
        if event.get("tenant_id") == tenant
        and event.get("action") == AUDIT_PRESENTATION_REQUEST_CANCELLED
        and event.get("resource_id") == request_id
    )


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        st, iss = http("POST", f"{BASE}/v1/dids",
                       {"method": "example", "public_key": "cn-issuer"})
        assert st == 201, iss
        issuer = iss["did"]
        st, sub = http("POST", f"{BASE}/v1/dids",
                       {"method": "example", "public_key": "cn-subject"})
        assert st == 201, sub
        subject = sub["did"]
        st, cr = http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"role": "admin", "age": 30}})
        assert st == 201, cr
        cred = cr["credential_id"]

        # ---------------- 入口校验：先租户头与请求体，再资源 ----------------
        unknown = f"pr_{'0' * 32}"
        check("显式空 X-Tenant-ID 400",
              http("POST",
                   f"{BASE}/v1/presentation-requests/{unknown}/cancel",
                   {}, {"X-Tenant-ID": ""})[0] == 400)
        # 对未知资源，各类请求体非法仍返回 400（先校验请求体再查资源）
        for name, raw, payload in (
            ("空体", b"", None),
            ("非法 JSON", b"{bad", None),
            ("非对象 null", b"null", None),
            ("非对象 数组", b"[]", None),
            ("非对象 字符串", b'"x"', None),
            ("多余字段", None, {"reason": "x", "y": 1}),
            ("reason 非字符串 数字", None, {"reason": 1}),
            ("reason 非字符串 布尔", None, {"reason": True}),
            ("reason 为 null", None, {"reason": None}),
            ("reason 裁剪后空", None, {"reason": "   \t\n"}),
            ("reason 超 256 码点", None, {"reason": "好" * 257}),
        ):
            kwargs = {"payload": payload} if raw is None else {"raw": raw}
            st, r = http(
                "POST",
                f"{BASE}/v1/presentation-requests/{unknown}/cancel",
                **kwargs
            )
            check(f"未知资源非法请求体 400: {name}",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])
        check("未知资源合法请求体 404",
              http("POST",
                   f"{BASE}/v1/presentation-requests/{unknown}/cancel",
                   {})[0] == 404)

        st, other = http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "cn-other"},
                         headers={"X-Tenant-ID": "tenant-b"})
        assert st == 201, other
        st, r = http(
            "POST",
            f"{BASE}/v1/presentation-requests/{other['request_id']}/cancel",
            {}, headers={"X-Tenant-ID": "tenant-c"})
        check("跨租户同 ID 404", st == 404)

        # ---------------- 首次取消：默认原因 ----------------
        st, req = http("POST", f"{BASE}/v1/presentation-requests",
                       {"challenge": "cn-cancel", "expires_in": 600,
                        "disclose": ["/role"]})
        assert st == 201, req
        rid = req["request_id"]
        st, c = http("POST",
                     f"{BASE}/v1/presentation-requests/{rid}/cancel", {})
        check("首次取消 200", st == 200)
        check("status cancelled", c.get("status") == "cancelled")
        check("默认 cancel_reason",
              c.get("cancel_reason") == "展示请求主动取消")
        check("cancelled_at 秒精度 Z",
              isinstance(c.get("cancelled_at"), str)
              and c["cancelled_at"].endswith("Z")
              and len(c["cancelled_at"]) == 20)
        check("取消对象不含消费字段",
              "consumed_at" not in c
              and "consumed_presentation_id" not in c)
        check("既有字段保持不变",
              c.get("request_id") == rid
              and c.get("challenge") == "cn-cancel"
              and c.get("disclose") == ["/role"]
              and c.get("issuer_dids") is None
              and c.get("holder_binding") is False)
        check("键序：cancel_* 位于末尾",
              list(c)[-2:] == ["cancel_reason", "cancelled_at"])
        st, got = http("GET", f"{BASE}/v1/presentation-requests/{rid}")
        check("GET cancelled 同对象", st == 200 and got == c)

        # 幂等：不同原因不改首次原因/时间，不记审计
        st, again = http(
            "POST", f"{BASE}/v1/presentation-requests/{rid}/cancel",
            {"reason": "另一个原因"})
        check("有效重复取消 200 且首次结果不变",
              st == 200 and again == c)
        # 已取消请求上的非法请求体仍 400
        st, r = http("POST",
                     f"{BASE}/v1/presentation-requests/{rid}/cancel",
                     raw=b"")
        check("已取消但空体仍 400", st == 400 and bool(r.get("error")))
        st, r = http("POST",
                     f"{BASE}/v1/presentation-requests/{rid}/cancel",
                     {"reason": "   "})
        check("已取消但非法 reason 仍 400",
              st == 400 and bool(r.get("error")))

        # ---------------- 显式原因：裁剪与码点边界 ----------------
        st, r1 = http("POST", f"{BASE}/v1/presentation-requests",
                      {"challenge": "cn-reason"})
        st, c1 = http(
            "POST",
            f"{BASE}/v1/presentation-requests/{r1['request_id']}/cancel",
            {"reason": "\t 改主意了 \n"})
        check("reason 裁剪后保存",
              st == 200 and c1.get("cancel_reason") == "改主意了")
        st, r2 = http("POST", f"{BASE}/v1/presentation-requests",
                      {"challenge": "cn-256"})
        st, c2 = http(
            "POST",
            f"{BASE}/v1/presentation-requests/{r2['request_id']}/cancel",
            {"reason": "好" * 256})
        check("reason 256 码点可取消",
              st == 200 and c2.get("cancel_reason") == "好" * 256)

        # ---------------- 已过期 pending 可取消；consumed 409 ----------------
        st, ereq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-exp", "expires_in": 1})
        assert st == 201
        wait_expired(ereq["expires_at"])
        st, c = http(
            "POST",
            f"{BASE}/v1/presentation-requests/{ereq['request_id']}/cancel",
            {})
        check("已过期 pending 仍可取消",
              st == 200 and c.get("status") == "cancelled")

        st, qreq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-consume", "expires_in": 600,
                         "disclose": ["/role"]})
        st, qvp = http("POST",
                       f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": qreq["request_id"]})
        assert st == 201
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{qvp['presentation_id']}/verify",
            {"presentation": qvp, "request_id": qreq["request_id"]})
        assert r == {"valid": True}, r
        st, r = http(
            "POST",
            f"{BASE}/v1/presentation-requests/{qreq['request_id']}/cancel",
            {})
        check("consumed 取消 409 展示请求已消费",
              st == 409 and r == {"error": "展示请求已消费"})
        st, got = http(
            "GET",
            f"{BASE}/v1/presentation-requests/{qreq['request_id']}")
        check("409 后仍为 consumed 且字段不变",
              got.get("status") == "consumed"
              and got.get("consumed_presentation_id")
              == qvp["presentation_id"]
              and "cancel_reason" not in got)

        # ---------------- present：已取消请求 400（先于过期/凭证） ----------------
        st, creq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-present", "expires_in": 600,
                         "disclose": ["/role"]})
        assert st == 201
        st, cvp = http("POST",
                       f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": creq["request_id"]})
        assert st == 201
        http("POST",
             f"{BASE}/v1/presentation-requests/{creq['request_id']}/cancel",
             {})
        st, r = http("POST",
                     f"{BASE}/v1/credentials/{cred}/present",
                     {"request_id": creq["request_id"]})
        check("present 已取消 400 固定文案",
              st == 400 and r == {"error": "展示请求已取消"})
        st, r = http(
            "POST",
            f"{BASE}/v1/credentials/vc_{'0' * 32}/present",
            {"request_id": creq["request_id"]})
        check("present 已取消先于未知凭证 404",
              st == 400 and r == {"error": "展示请求已取消"})

        # 已取消且已过期：取消仍优先于过期
        st, xreq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-x", "expires_in": 1})
        wait_expired(xreq["expires_at"])
        http("POST",
             f"{BASE}/v1/presentation-requests/{xreq['request_id']}/cancel",
             {})
        st, r = http("POST",
                     f"{BASE}/v1/credentials/{cred}/present",
                     {"request_id": xreq["request_id"]})
        check("present 已取消且过期 -> 已取消",
              st == 400 and r == {"error": "展示请求已取消"})

        # ---------------- verify：已取消 200 valid:false（不消费） ----------------
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{cvp['presentation_id']}/verify",
            {"presentation": cvp, "request_id": creq["request_id"]})
        check("verify 已取消 200 valid:false 固定对象",
              st == 200 and r == {"valid": False,
                                  "reason": "展示请求已取消"})
        # 取消判定先于结构/签名校验：篡改后的演示同样返回已取消
        tampered = dict(cvp)
        tampered["proof"] = "x"
        tampered["claims"] = {"role": "root"}
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{cvp['presentation_id']}/verify",
            {"presentation": tampered, "request_id": creq["request_id"]})
        check("verify 取消先于结构/凭证校验",
              st == 200 and r == {"valid": False,
                                  "reason": "展示请求已取消"})
        st, got = http(
            "GET",
            f"{BASE}/v1/presentation-requests/{creq['request_id']}")
        check("verify 失败后请求仍 cancelled 不消费",
              got.get("status") == "cancelled"
              and "consumed_at" not in got)

        # 已过期后再取消并 verify：取消优先于过期
        st, yreq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-y", "expires_in": 1,
                         "disclose": ["/role"]})
        st, yvp = http("POST",
                       f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": yreq["request_id"]})
        assert st == 201
        wait_expired(yreq["expires_at"])
        http("POST",
             f"{BASE}/v1/presentation-requests/{yreq['request_id']}/cancel",
             {})
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{yvp['presentation_id']}/verify",
            {"presentation": yvp, "request_id": yreq["request_id"]})
        check("verify 已取消优先于过期",
              st == 200 and r.get("reason") == "展示请求已取消")

        # ---------------- 绑定展示同样适用 ----------------
        st, breq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-bound", "expires_in": 600,
                         "disclose": ["/role"], "holder_binding": True,
                         "issuer_dids": [issuer]})
        st, bvp = http("POST",
                       f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": breq["request_id"]})
        assert st == 201, bvp
        bound_body_keys = set(bvp)
        http("POST",
             f"{BASE}/v1/presentation-requests/{breq['request_id']}/cancel",
             {})
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{bvp['presentation_id']}/verify",
            {"presentation": bvp, "request_id": breq["request_id"]})
        check("绑定展示 verify 已取消",
              st == 200 and r == {"valid": False,
                                  "reason": "展示请求已取消"})
        st, r = http("POST",
                     f"{BASE}/v1/credentials/{cred}/present",
                     {"request_id": breq["request_id"]})
        check("绑定请求 present 已取消 400",
              st == 400 and r == {"error": "展示请求已取消"})
        check("既有展示正文与签名字段保留", bound_body_keys == set(bvp))

        # ---------------- 审计：仅首次成功取消追加一条 ----------------
        proc_store = VCStore(STORE)
        check("首次取消恰一条审计（幂等/失败不追加）",
              count_cancel_audits(proc_store, "default", rid) == 1)
        check("present/verify 失败不记取消审计",
              count_cancel_audits(
                  proc_store, "default", creq["request_id"]) == 1)
        check("consumed 409 不记取消审计",
              count_cancel_audits(
                  proc_store, "default", qreq["request_id"]) == 0)
        ev = next(
            e for e in proc_store._audit
            if e["tenant_id"] == "default"
            and e["action"] == AUDIT_PRESENTATION_REQUEST_CANCELLED
            and e["resource_id"] == rid)
        check("审计 resource_type 为 presentation_request",
              ev["resource_type"] == "presentation_request")
        check("审计时间与 cancelled_at 同秒",
              ev["timestamp"] == int(
                  datetime.strptime(
                      proc_store._tenants["default"]["presentation_requests"]
                      [rid]["cancelled_at"],
                      "%Y-%m-%dT%H:%M:%SZ").replace(
                          tzinfo=timezone.utc).timestamp()))

        # ---------------- 普通 challenge 模式与 pending 行为不变 ----------------
        st, plain = http("POST",
                         f"{BASE}/v1/credentials/{cred}/present",
                         {"disclose": ["/role"], "challenge": "cn-plain"})
        assert st == 201, plain
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{plain['presentation_id']}/verify",
            {"presentation": plain, "challenge": "cn-plain"})
        check("普通 challenge 模式不受取消影响",
              st == 200 and r == {"valid": True})
        st, preq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-pending"})
        st, got = http(
            "GET",
            f"{BASE}/v1/presentation-requests/{preq['request_id']}")
        check("pending 对象不含 cancel_* 字段",
              got.get("status") == "pending"
              and "cancel_reason" not in got
              and "cancelled_at" not in got)

        # ---------------- 重启持久化 ----------------
        st, kreq = http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "cn-keep", "expires_in": 600,
                         "disclose": ["/role"]})
        st, kvp = http("POST",
                       f"{BASE}/v1/credentials/{cred}/present",
                       {"request_id": kreq["request_id"]})
        assert st == 201
        http("POST",
             f"{BASE}/v1/presentation-requests/{kreq['request_id']}/cancel",
             {"reason": "重启保留"})
        keep_req = kreq["request_id"]
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, got = http(
            "GET", f"{BASE}/v1/presentation-requests/{keep_req}")
        check("重启后 cancelled 与首次原因保留",
              st == 200 and got.get("status") == "cancelled"
              and got.get("cancel_reason") == "重启保留"
              and bool(got.get("cancelled_at"))
              and "consumed_at" not in got)
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{kvp['presentation_id']}/verify",
            {"presentation": kvp, "request_id": keep_req})
        check("重启后 verify 仍返回已取消",
              st == 200 and r == {"valid": False,
                                  "reason": "展示请求已取消"})
        st, r = http("POST",
                     f"{BASE}/v1/credentials/{cred}/present",
                     {"request_id": keep_req})
        check("重启后 present 仍 400 已取消",
              st == 400 and r == {"error": "展示请求已取消"})
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    rollback_ok = test_save_rollback()
    if not rollback_ok:
        failures.append("落盘失败回滚")

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


def test_save_rollback():
    """落盘失败时回滚状态与审计序号，恢复后重试成功。"""
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    path = tempfile.mktemp(suffix=".json")
    try:
        dstore = VCStore(path)
        rec = dstore.create_presentation_request(
            "default", challenge="rb", expires_in=60, disclose=None,
            issuer_dids=None, holder_binding=False)
        rid = rec.request_id
        seq_before = dstore._audit_seq

        original_save = dstore._save_locked
        calls = {"n": 0}

        def fail_save():
            calls["n"] += 1
            raise OSError("disk full")

        dstore._save_locked = fail_save  # type: ignore[assignment]
        raised = False
        try:
            dstore.cancel_presentation_request("default", rid, "原因")
        except OSError:
            raised = True
        dstore._save_locked = original_save  # type: ignore[assignment]
        check("落盘失败原样抛出 OSError", raised)
        row_after = dstore._tenants["default"]["presentation_requests"][rid]
        check("状态回滚为 pending", row_after.get("status") == "pending"
              and "cancel_reason" not in row_after
              and "cancelled_at" not in row_after)
        check("审计序号回滚", dstore._audit_seq == seq_before)
        check("失败不残留取消审计", not any(
            e["action"] == AUDIT_PRESENTATION_REQUEST_CANCELLED
            and e["resource_id"] == rid for e in dstore._audit))
        check("故障保存确实被调用", calls["n"] == 1)

        rec2 = dstore.cancel_presentation_request("default", rid, "原因")
        check("恢复后重试取消成功",
              rec2.status == "cancelled"
              and rec2.cancel_reason == "原因"
              and bool(rec2.cancelled_at))
        check("成功后审计序号仅前进 1",
              dstore._audit_seq == seq_before + 1)

        # 从磁盘重载，状态稳定
        dstore2 = VCStore(path)
        loaded = dstore2.get_presentation_request("default", rid)
        check("重启加载取消状态",
              loaded.status == "cancelled"
              and loaded.cancel_reason == "原因"
              and loaded.cancelled_at == rec2.cancelled_at)
        check("重启后审计仍为一条",
              sum(1 for e in dstore2._audit
                  if e["action"] == AUDIT_PRESENTATION_REQUEST_CANCELLED
                  and e["resource_id"] == rid) == 1)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return not failures


if __name__ == "__main__":
    sys.exit(main())
