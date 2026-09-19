#!/usr/bin/env python3
"""租户隔离、审计日志与演示过期竞态的端到端测试。

直接运行：python3 tests/tenant_audit_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend.store import VCStore  # noqa: E402


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


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def main():
    port = 8943
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tenant-a"}
        T2 = {"X-Tenant-ID": "tenant-b"}

        # 1. 租户头：缺省 default；显式空串 400
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "def-key"})
        check("无租户头 -> default 租户 201", st == 201)
        default_did = r["did"]
        st, _ = _http("GET", f"{base}/v1/dids/{default_did}",
                      headers={"X-Tenant-ID": "default"})
        check("显式 default 可见缺省租户资源", st == 200)
        st, rr = _http("GET", f"{base}/v1/dids/did:example:x",
                       headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and isinstance(rr.get("error"), str) and rr["error"])
        st, rr = _http("GET", f"{base}/v1/audit",
                       headers={"X-Tenant-ID": ""})
        check("审计端点显式空租户头 -> 400", st == 400 and rr.get("error"))

        # 2. 同句柄跨租户注册为不同 DID
        st, r1 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "shared"},
                       headers=T1)
        check("t1 注册 shared -> 201", st == 201)
        did_a = r1["did"]
        st, r2 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "shared"},
                       headers=T2)
        check("t2 同句柄注册 -> 201 且 DID 不同",
              st == 201 and r2["did"] != did_a)
        did_b = r2["did"]
        # 租户内幂等：同句柄返回既有 DID
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "shared"},
                      headers=T1)
        check("t1 同句柄幂等返回既有 DID", st == 201 and r["did"] == did_a)

        # 3. 跨租户资源 404
        check("t1 可见本租户 DID",
              _http("GET", f"{base}/v1/dids/{did_a}", headers=T1)[0] == 200)
        check("t2 访问 t1 DID -> 404",
              _http("GET", f"{base}/v1/dids/{did_a}", headers=T2)[0] == 404)
        check("default 访问 t1 DID -> 404",
              _http("GET", f"{base}/v1/dids/{did_a}")[0] == 404)

        # 4. key_handle 仅在本租户唯一；跨租户可重用
        st, r = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                      {"key_handle": "rot"}, headers=T1)
        check("t1 轮换 rot -> 200", st == 200 and r["key_version"] == 2)
        st, rr = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                       {"key_handle": "rot"}, headers=T1)
        check("t1 重复句柄轮换 -> 400", st == 400 and "key_handle" in rr["error"])
        st, r = _http("POST", f"{base}/v1/dids/{did_b}/keys/rotate",
                      {"key_handle": "rot"}, headers=T2)
        check("t2 使用相同句柄轮换 -> 200",
              st == 200 and r["key_version"] == 2)
        check("t2 轮换 t1 DID -> 404",
              _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                    {"key_handle": "rot2"}, headers=T2)[0] == 404)

        # 5. 凭证跨租户隔离
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "a-sub"},
                     headers=T1)
        sub_a = r["did"]
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": sub_a,
            "claims": {"role": "admin"}}, headers=T1)
        check("t1 签发凭证 -> 201", st == 201)
        cid_a = r["credential_id"]
        check("t2 读 t1 凭证 -> 404",
              _http("GET", f"{base}/v1/credentials/{cid_a}",
                    headers=T2)[0] == 404)
        st, rr = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": did_b, "claims": {}},
            headers=T2)
        check("t2 引用 t1 DID 签发 -> 400 且指明 issuer_did",
              st == 400 and "issuer_did" in rr["error"])
        for suffix, method, payload in (
            ("/status", "PUT", {"status": "active"}),
            ("/revoke", "POST", {}),
            ("/verify", "POST", {"body": {}, "signature": "x"}),
            ("/present", "POST", {"disclose": []}),
        ):
            stx, _ = _http(method,
                           f"{base}/v1/credentials/{cid_a}{suffix}",
                           payload, headers=T2)
            # verify 走公开错误协议恒为 200；其余路径跨租户一律 404
            expected = 200 if suffix == "/verify" else 404
            check(f"t2 访问 t1 凭证 {suffix} -> {expected}",
                  stx == expected)

        # 6. 演示跨租户：present 404；verify 走公开协议返回 valid:false
        st, r = _http("POST", f"{base}/v1/credentials/{cid_a}/present",
                      {"disclose": ["/role"]}, headers=T1)
        check("t1 创建演示 -> 201", st == 201)
        vp_a = r
        pid_a = vp_a["presentation_id"]
        st, rr = _http("POST", f"{base}/v1/presentations/{pid_a}/verify",
                       {"presentation": vp_a, "challenge": vp_a["challenge"]},
                       headers=T2)
        check("t2 校验 t1 演示 -> 200 valid:false（资源不可见）",
              st == 200 and rr.get("valid") is False
              and "演示不存在" in rr.get("reason", ""))

        # 7. 审计：事件字段与动作映射
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("审计查询 -> 200 含 events/next_after",
              st == 200 and isinstance(audit.get("events"), list)
              and "next_after" in audit)
        evs = audit["events"]
        for ev in evs:
            check(f"审计事件字段恰为六项 {ev.get('action')}",
                  set(ev) == {"seq", "timestamp", "tenant_id", "action",
                              "resource_type", "resource_id"}
                  and ev["tenant_id"] == "tenant-a"
                  and isinstance(ev["seq"], int)
                  and isinstance(ev["timestamp"], int)
                  and abs(ev["timestamp"] - time.time()) < 300)
        check("审计事件全部属于 t1",
              all(e["tenant_id"] == "tenant-a" for e in evs))
        seqs = [e["seq"] for e in evs]
        check("t1 审计按 seq 升序",
              seqs == sorted(seqs) and len(seqs) == len(set(seqs)))

        def acts(action):
            return [e for e in evs if e["action"] == action]

        # did.created：did_a 注册 + 幂等重试 + sub_a 注册，共 3 条
        check("did.created 每次幂等成功都记录",
              len(acts("did.created")) == 3
              and all(e["resource_type"] == "did"
                      and e["resource_id"] in (did_a, sub_a)
                      for e in acts("did.created"))
              and len([e for e in acts("did.created")
                       if e["resource_id"] == did_a]) == 2)
        check("credential.issued 记录",
              len(acts("credential.issued")) == 1
              and acts("credential.issued")[0]["resource_id"] == cid_a)
        check("key.rotated 记录且 resource_type=did",
              len(acts("key.rotated")) == 1
              and acts("key.rotated")[0]["resource_id"] == did_a)
        check("presentation.created 记录",
              len(acts("presentation.created")) == 1
              and acts("presentation.created")[0]["resource_id"] == pid_a)

        # status.updated：首次与幂等都记录
        _http("PUT", f"{base}/v1/credentials/{cid_a}/status",
              {"status": "active"}, headers=T1)
        _http("PUT", f"{base}/v1/credentials/{cid_a}/status",
              {"status": "active"}, headers=T1)
        # 再签发一张用于吊销审计
        _, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": did_a, "subject_did": sub_a, "claims": {}},
            headers=T1)
        cid_rev = r["credential_id"]
        _http("POST", f"{base}/v1/credentials/{cid_rev}/revoke",
              {"reason": "测试吊销"}, headers=T1)
        _http("POST", f"{base}/v1/credentials/{cid_rev}/revoke",
              {"reason": "再次吊销"}, headers=T1)
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        evs = audit["events"]
        check("status.updated 首次 201 与幂等 200 均记录",
              len([e for e in evs if e["action"] == "status.updated"]) == 2)
        rev_events = [e for e in evs if e["action"] == "credential.revoked"]
        check("credential.revoked 首次与重试均记录",
              len(rev_events) == 2
              and all(e["resource_id"] == cid_rev for e in rev_events))

        # 凭证验签（无论成败）不记审计
        _, vc_a = _http("GET", f"{base}/v1/credentials/{cid_a}", headers=T1)
        n_before_verify = len(
            _http("GET", f"{base}/v1/audit?limit=200", headers=T1)[1]["events"])
        st, r = _http("POST", f"{base}/v1/credentials/{cid_a}/verify",
                      {"body": vc_a["body"], "signature": "@@@@"}, headers=T1)
        check("凭证验签失败仍 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = _http("POST", f"{base}/v1/credentials/{cid_a}/verify",
                      {"body": vc_a["body"], "signature": vc_a["signature"]},
                      headers=T1)
        check("凭证验签成功 valid:true", st == 200 and r.get("valid") is True)
        check("凭证验签（成功/失败）均不记审计",
              len(_http("GET", f"{base}/v1/audit?limit=200",
                        headers=T1)[1]["events"]) == n_before_verify)

        # 演示消费成功 -> consumed；失败/已消费/过期/吊销不记
        st, r = _http("POST", f"{base}/v1/presentations/{pid_a}/verify",
                      {"presentation": vp_a, "challenge": vp_a["challenge"]},
                      headers=T1)
        check("t1 演示消费 valid=true", st == 200 and r == {"valid": True})
        st, r = _http("POST", f"{base}/v1/presentations/{pid_a}/verify",
                      {"presentation": vp_a, "challenge": vp_a["challenge"]},
                      headers=T1)
        check("重复消费 -> 演示已消费",
              st == 200 and r.get("reason") == "演示已消费")
        st, r = _http("POST", f"{base}/v1/presentations/vp_nope/verify",
                      {"presentation": {}, "challenge": "x"}, headers=T1)
        check("未知演示验证失败", r.get("valid") is False)
        _, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        consumed = [e for e in audit["events"]
                    if e["action"] == "presentation.consumed"]
        check("presentation.consumed 仅成功消费记录一次",
              len(consumed) == 1 and consumed[0]["resource_id"] == pid_a)

        # 过期演示：不消费、不记审计、复查锁内过期判定
        st, r = _http("POST", f"{base}/v1/credentials/{cid_a}/present",
                      {"disclose": ["/role"], "expires_in": 1}, headers=T1)
        vp_exp = r
        # 快照取在“创建演示”之后（创建本身会记 presentation.created）
        _, snap = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before_expire = len(snap["events"])
        time.sleep(1.3)
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vp_exp['presentation_id']}/verify",
                      {"presentation": vp_exp,
                       "challenge": vp_exp["challenge"]}, headers=T1)
        check("过期演示 -> 演示已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已过期")
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vp_exp['presentation_id']}/verify",
                      {"presentation": vp_exp,
                       "challenge": vp_exp["challenge"]}, headers=T1)
        check("过期演示再次验证仍是过期（未被消费）",
              r.get("reason") == "演示已过期")
        _, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("过期验证不产生审计事件",
              len(audit["events"]) == n_before_expire)

        # 已吊销凭证的演示：验签通过但吊销，不消费不记
        st, r = _http("POST", f"{base}/v1/credentials/{cid_rev}/present",
                      {"disclose": []}, headers=T1)
        check("已吊销凭证仍可创建演示 -> 201", st == 201)
        vp_r = r
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vp_r['presentation_id']}/verify",
                      {"presentation": vp_r,
                       "challenge": vp_r["challenge"]}, headers=T1)
        check("吊销凭证演示 valid:false 附原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：测试吊销")
        _, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("吊销演示验证不产生 consumed 事件",
              len([e for e in audit["events"]
                   if e["action"] == "presentation.consumed"]) == 1)

        # 8. 审计全局 seq 跨租户连续自 1
        all_events = []
        for hdr in (T1, T2, {"X-Tenant-ID": "default"}):
            _, rr = _http("GET", f"{base}/v1/audit?limit=200", headers=hdr)
            all_events.extend(rr["events"])
        glob = sorted(e["seq"] for e in all_events)
        check("全局审计 seq 连续自 1", glob == list(range(1, len(glob) + 1)))

        # 9. 审计分页参数
        st, rr = _http("GET", f"{base}/v1/audit", headers=T1)
        check("缺省 limit=50/after=0 返回 200",
              st == 200 and len(rr["events"]) <= 50)
        st, p1 = _http("GET", f"{base}/v1/audit?limit=2&after=0", headers=T1)
        check("limit=2 页大小为 2", st == 200 and len(p1["events"]) == 2)
        cursor = p1["next_after"]
        check("next_after 为本页最后 seq",
              cursor == p1["events"][-1]["seq"])
        st, p2 = _http("GET", f"{base}/v1/audit?limit=2&after={cursor}",
                       headers=T1)
        check("after 排除不大于游标的事件",
              st == 200 and len(p2["events"]) == 2
              and all(e["seq"] > cursor for e in p2["events"])
              and p2["events"][0]["seq"] > p1["events"][-1]["seq"])
        st, empty = _http("GET", f"{base}/v1/audit?after=999999999",
                          headers=T1)
        check("空页 events=[] 且 next_after 保持 after",
              st == 200 and empty["events"] == []
              and empty["next_after"] == 999999999)
        for bad in ("limit=0", "limit=201", "limit=-1", "limit=1.5",
                    "limit=abc", "limit=true", "limit=",
                    "after=-1", "after=1.5", "after=abc", "after=false",
                    "after=", "after=%C2%B2", "limit=%D9%A0%D9%A1%D9%A2",
                    "limit=1&limit=2", "after=1&after=2"):
            stx, rrx = _http("GET", f"{base}/v1/audit?{bad}", headers=T1)
            check(f"非法审计参数 {bad} -> 400",
                  stx == 400 and isinstance(rrx.get("error"), str)
                  and rrx["error"])
        st, _ = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("limit=200 合法 -> 200", st == 200)
        st, _ = _http("GET", f"{base}/v1/audit?limit=1&after=1", headers=T1)
        check("after=1 合法 -> 200", st == 200)

        # 10. 并发消费：恰好一次 valid:true，审计恰一条 consumed
        st, r = _http("POST", f"{base}/v1/credentials/{cid_a}/present",
                      {"disclose": ["/role"]}, headers=T1)
        vp_cc = r
        pid_cc = vp_cc["presentation_id"]

        def verify_cc(_):
            return _http(
                "POST", f"{base}/v1/presentations/{pid_cc}/verify",
                {"presentation": vp_cc, "challenge": vp_cc["challenge"]},
                headers=T1)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(verify_cc, range(8)))
        oks = [rr for stx, rr in results
               if stx == 200 and rr == {"valid": True}]
        consumed_resp = [rr for stx, rr in results
                         if stx == 200 and rr.get("reason") == "演示已消费"]
        check("并发消费恰好一次成功", len(oks) == 1)
        check("并发消费其余均为演示已消费", len(consumed_resp) == 7)
        _, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        cc_events = [e for e in audit["events"]
                     if e["action"] == "presentation.consumed"
                     and e["resource_id"] == pid_cc]
        check("并发消费仅记一条 presentation.consumed", len(cc_events) == 1)

        # 11. 审计 seq 跨重启继续连续
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port), "服务重启超时"
        _, before_restart = _http("GET", f"{base}/v1/audit?limit=200",
                                  headers=T1)
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "after-restart"},
                     headers=T1)
        _, after_restart = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        new_events = [e for e in after_restart["events"]
                      if e["seq"] > before_restart["next_after"]]
        check("重启后新事件 seq 接续",
              len(new_events) == 1
              and new_events[0]["seq"] == before_restart["next_after"] + 1
              and new_events[0]["action"] == "did.created")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)

    # 12. 原子写失败：内存回滚，变更不生效且审计不记录
    rollback_path = tempfile.mktemp(suffix=".json")
    try:
        rs = VCStore(rollback_path)

        def _boom():
            raise OSError("模拟落盘失败")

        rs._save_locked = _boom  # type: ignore[assignment]
        try:
            rs.create_did("tenant-a", "example", "will-rollback")
            check("落盘失败时 create_did 抛错", False)
        except OSError:
            check("落盘失败时 create_did 抛错", True)
        events, _ = rs.list_audit("tenant-a", 0, 50)
        check("落盘失败不记审计", events == [])
        try:
            rs.get_did("tenant-a", "did:example:00000000000000000000000000000000")
            check("落盘失败变更不生效", False)
        except Exception as exc:
            check("落盘失败变更不生效（DID 不存在）",
                  type(exc).__name__ == "NotFoundError")
    finally:
        if os.path.exists(rollback_path):
            os.remove(rollback_path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("租户/审计/竞态测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
