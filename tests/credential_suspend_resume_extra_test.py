#!/usr/bin/env python3
"""凭证暂停/恢复补充测试：重启稳定、原子回滚、过期优先级、批量回滚。"""
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
PORT = 8994


def http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def wait_up(port):
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def serve(store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_up(PORT), "服务启动超时"
    return proc


def main():
    failures = []

    def check(name, cond, extra=""):
        print(("PASS" if cond else "FAIL"), name, extra)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = serve(store_path)
    B = f"http://127.0.0.1:{PORT}"
    H = {"X-Tenant-ID": "t"}
    try:
        st, d = http("POST", f"{B}/v1/dids",
                     {"method": "example", "public_key": "k"}, H)
        did = d["did"]
        st, d = http("POST", f"{B}/v1/credentials",
                     {"issuer_did": did, "subject_did": did,
                      "claims": {"a": 1}}, H)
        vc = d["credential_id"]
        st, _ = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "调查"}, H)
        assert st == 200
        suspend_at = None
        st, g = http("GET", f"{B}/v1/credentials/{vc}/status", headers=H)
        suspend_at = g["updated_at"]
        st, h1 = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                      headers=H)
        cursors = [e["cursor"] for e in h1["events"]]
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 重启 ----
    proc = serve(store_path)
    try:
        st, g = http("GET", f"{B}/v1/credentials/{vc}/status", headers=H)
        check("重启后 suspended 状态与首次时间保留",
              st == 200 and g["status"] == "suspended"
              and g["updated_at"] == suspend_at
              and list(g) == ["credential_id", "status", "updated_at"])
        st, h2 = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                      headers=H)
        check("重启后历史与游标稳定",
              [e["cursor"] for e in h2["events"]] == cursors
              and h2["events"][0]["reason"] == "调查")

        # 恢复后历史继续接游标
        st, _ = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "active"}, H)
        st, h3 = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                      headers=H)
        check("重启后恢复事件接续游标",
              [e["status"] for e in h3["events"]] == ["suspended", "active"]
              and [e["cursor"] for e in h3["events"]] == [cursors[0],
                                                          cursors[0] + 1]
              and h3["events"][1]["reason"] is None
              and h3["events"][1]["revoked_at"] is None)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 过期优先于暂停 ----
    proc = serve(store_path)
    try:
        exp = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() + 3))
        st, d = http("POST", f"{B}/v1/credentials",
                     {"issuer_did": did, "subject_did": did,
                      "claims": {"x": 1}, "expires_at": exp}, H)
        assert st == 201, d
        vc2 = d["credential_id"]
        st, gd = http("GET", f"{B}/v1/credentials/{vc2}", headers=H)
        assert st == 200
        st, _ = http("PUT", f"{B}/v1/credentials/{vc2}/status",
                     {"status": "suspended", "reason": "暂停中"}, H)
        assert st == 200
        # 轮询等待跨过 expires_at（到期前应始终返回暂停原因，绝不应
        # 消费或给出其他结论；到期后必须转为“凭证已过期”）。
        saw_suspended = False
        expired_result = None
        deadline = time.time() + 8
        while time.time() < deadline:
            st, r = http("POST", f"{B}/v1/credentials/{vc2}/verify",
                         {"body": gd["body"], "signature": gd["signature"]}, H)
            reason = r.get("reason", "")
            if reason == "凭证已暂停：暂停中":
                saw_suspended = True
            elif reason == "凭证已过期":
                expired_result = (st, r)
                break
            time.sleep(0.2)
        check("到期前暂停期间返回暂停原因", saw_suspended)
        check("过期优先于暂停 -> 凭证已过期",
              expired_result == (200, {"valid": False,
                                       "reason": "凭证已过期"}))

        # 未过期凭证暂停 -> 暂停原因
        st, d = http("POST", f"{B}/v1/credentials",
                     {"issuer_did": did, "subject_did": did,
                      "claims": {"y": 2}}, H)
        vc3 = d["credential_id"]
        st, gd3 = http("GET", f"{B}/v1/credentials/{vc3}", headers=H)
        st, _ = http("PUT", f"{B}/v1/credentials/{vc3}/status",
                     {"status": "suspended", "reason": "仅暂停"}, H)
        st, r = http("POST", f"{B}/v1/credentials/{vc3}/verify",
                     {"body": gd3["body"], "signature": gd3["signature"]}, H)
        check("未过期暂停 -> 凭证已暂停：仅暂停",
              st == 200 and r == {"valid": False, "reason": "凭证已暂停：仅暂停"})

        # present-batch 暂停回滚：全部不创建。先恢复再签两条，再暂停
        st, _ = http("PUT", f"{B}/v1/credentials/{vc3}/status",
                     {"status": "active"}, H)
        st, r = http("POST", f"{B}/v1/credentials/{vc3}/present-batch",
                     {"presentations": [
                         {"disclose": ["/y"], "challenge": "b1"},
                         {"disclose": ["/y"], "challenge": "b2"}]}, H)
        assert st == 201 and len(r["presentations"]) == 2, r
        st, _ = http("PUT", f"{B}/v1/credentials/{vc3}/status",
                     {"status": "suspended", "reason": "再暂停"}, H)
        st, r = http("POST", f"{B}/v1/credentials/{vc3}/present-batch",
                     {"presentations": [
                         {"disclose": ["/y"], "challenge": "b3"},
                         {"disclose": ["/y"], "challenge": "b4"}]}, H)
        check("暂停后 present-batch 409 仅 error",
              st == 409 and set(r) == {"error"} and r["error"])
        # 审计：暂停后批次不产生 presentation.created
        st, aud = http("GET", f"{B}/v1/audit?limit=200", headers=H)
        created = [e for e in aud["events"]
                   if e["action"] == "presentation.created"]
        check("暂停批次不写演示（仍为 2 条创建审计）", len(created) == 2)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 落盘失败原子回滚（直连 store）----
    from vcbackend.store import VCStore
    p = tempfile.mktemp(suffix=".json")
    store = VCStore(p)
    drec = store.create_did("dt", "example", "rb")
    c = store.create_credential("dt", drec.did, drec.did, {"q": 1})

    def boom():
        raise OSError("模拟落盘失败")

    store._save_locked = boom  # type: ignore[assignment]
    raised = False
    try:
        store.set_credential_status("dt", c.credential_id,
                                    "suspended", reason="回滚暂停")
    except OSError:
        raised = True
    check("暂停落盘失败抛错", raised)
    rec = store.get_credential_status("dt", c.credential_id)
    check("回滚后仍为无状态（active/null）",
          rec.status == "active" and rec.updated_at is None
          and rec.reason is None)
    events, _ = store.list_credential_status_history("dt", c.credential_id)
    check("回滚后无历史、游标未前进",
          events == [] and
          store._local_credential_status_history_cursors.get("dt", 0) == 0)  # noqa: SLF001
    evs = store.list_audit("dt", 0, 200)[0]
    check("回滚后无 status.updated 审计",
          all(e.action != "status.updated" for e in evs))

    del store._save_locked
    rec, created = store.set_credential_status(
        "dt", c.credential_id, "active")
    check("回滚恢复后首次 active 201",
          created and rec.status == "active" and rec.updated_at)
    raised = False
    store._save_locked = boom  # type: ignore[assignment]
    try:
        store.set_credential_status("dt", c.credential_id,
                                    "suspended", reason="再次暂停")
    except OSError:
        raised = True
    check("active→暂停落盘失败抛错", raised)
    rec = store.get_credential_status("dt", c.credential_id)
    check("回滚后仍 active", rec.status == "active")
    events, _ = store.list_credential_status_history("dt", c.credential_id)
    check("回滚后历史仍仅 active 一条",
          len(events) == 1 and events[0].status == "active"
          and events[0].cursor == 1)

    for path in (store_path, p):
        if os.path.exists(path):
            os.remove(path)
    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("重启/回滚/优先级补充验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
