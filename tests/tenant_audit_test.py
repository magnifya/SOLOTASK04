#!/usr/bin/env python3
"""新功能验证：租户隔离、审计、演示消费过期竞态修复。"""

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


def _http(method, url, payload=None, tenant=None, raw_tenant=False):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if tenant is not None:
        req.add_header("X-Tenant-ID", tenant)
    elif raw_tenant:
        req.add_header("X-Tenant-ID", "")
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
    port = 8944
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

        # ---- 租户头 ----
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "h1"}, raw_tenant=True)
        check("显式空 X-Tenant-ID -> 400", st == 400 and r.get("error"))

        # 租户 A 注册 DID
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "shared-key"},
                      tenant="tenant-a")
        check("租户A注册 DID -> 201", st == 201)
        did_a = r["did"]

        # 缺省租户看不到租户 A 的 DID
        st, _ = _http("GET", f"{base}/v1/dids/{did_a}")
        check("缺省租户读租户A DID -> 404", st == 404)
        # 租户 B 看不到
        st, _ = _http("GET", f"{base}/v1/dids/{did_a}", tenant="tenant-b")
        check("租户B读租户A DID -> 404", st == 404)
        # 租户 A 自己能读
        st, _ = _http("GET", f"{base}/v1/dids/{did_a}", tenant="tenant-a")
        check("租户A读自己的 DID -> 200", st == 200)

        # 同句柄可在租户 B 注册，得到不同 DID
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "shared-key"},
                      tenant="tenant-b")
        check("同句柄跨租户注册 -> 201 且 DID 不同",
              st == 201 and r["did"] != did_a)
        did_b = r["did"]
        # 同句柄同租户去重
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "shared-key"},
                      tenant="tenant-b")
        check("同句柄同租户去重 -> 201 同 DID", st == 201 and r["did"] == did_b)

        # 轮换：跨租户 404；句柄唯一性按租户判定
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                      {"key_handle": "a-v2"}, tenant="tenant-b")
        check("跨租户轮换 -> 404", st == 404)
        st, _ = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                      {"key_handle": "shared-key"}, tenant="tenant-a")
        check("本租户内句柄冲突 -> 400", st == 400)
        st, r = _http("POST", f"{base}/v1/dids/{did_a}/keys/rotate",
                      {"key_handle": "a-v2"}, tenant="tenant-a")
        check("租户A轮换 -> 200 v2", st == 200 and r["key_version"] == 2)

        # 签发：跨租户 DID 视为不存在
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": did_a, "subject_did": did_b,
                       "claims": {"role": "admin"}}, tenant="tenant-a")
        check("跨租户 subject_did -> 400", st == 400)
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "a-sub"},
                      tenant="tenant-a")
        sub_a = r["did"]
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": did_a, "subject_did": sub_a,
                       "claims": {"role": "admin"}}, tenant="tenant-a")
        check("租户A签发 -> 201", st == 201)
        vc_a = r["credential_id"]
        sig_a = r["signature"]

        st, _ = _http("GET", f"{base}/v1/credentials/{vc_a}", tenant="tenant-b")
        check("跨租户读凭证 -> 404", st == 404)
        st, r = _http("GET", f"{base}/v1/credentials/{vc_a}", tenant="tenant-a")
        check("本租户读凭证 -> 200", st == 200)
        body_a = r["body"]

        # 状态/吊销跨租户 404
        st, _ = _http("PUT", f"{base}/v1/credentials/{vc_a}/status",
                      {"status": "active"}, tenant="tenant-b")
        check("跨租户登记状态 -> 404", st == 404)
        st, _ = _http("POST", f"{base}/v1/credentials/{vc_a}/revoke",
                      None, tenant="tenant-b")
        check("跨租户吊销 -> 404", st == 404)

        # 验签跨租户按“凭证不存在”
        st, r = _http("POST", f"{base}/v1/credentials/{vc_a}/verify",
                      {"body": body_a, "signature": sig_a}, tenant="tenant-b")
        check("跨租户验签 -> 200 valid:false 凭证不存在",
              st == 200 and r.get("valid") is False
              and "凭证不存在" in r.get("reason", ""))
        st, r = _http("POST", f"{base}/v1/credentials/{vc_a}/verify",
                      {"body": body_a, "signature": sig_a}, tenant="tenant-a")
        check("本租户验签 -> valid:true", st == 200 and r.get("valid") is True)

        # 演示跨租户
        st, r = _http("POST", f"{base}/v1/credentials/{vc_a}/present",
                      {"disclose": ["/role"]}, tenant="tenant-b")
        check("跨租户创建演示 -> 404", st == 404)
        st, r = _http("POST", f"{base}/v1/credentials/{vc_a}/present",
                      {"disclose": ["/role"], "challenge": "c1"},
                      tenant="tenant-a")
        check("本租户创建演示 -> 201", st == 201)
        vp_a = r
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp_a['presentation_id']}/verify",
            {"presentation": vp_a, "challenge": "c1"}, tenant="tenant-b")
        check("跨租户验演示 -> valid:false 演示不存在",
              st == 200 and r.get("valid") is False
              and "演示不存在" in r.get("reason", ""))

        # ---- 审计 ----
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("GET /v1/audit -> 200", st == 200)
        events = r["events"]
        actions = [e["action"] for e in events]
        check("租户A审计动作序列",
              actions == ["did.created", "key.rotated",
                          "did.created", "credential.issued",
                          "presentation.created"])
        check("审计事件字段齐全",
              all(set(e) == {"seq", "timestamp", "tenant_id", "action",
                             "resource_type", "resource_id"}
                  for e in events))
        check("审计 tenant_id 正确",
              all(e["tenant_id"] == "tenant-a" for e in events))
        check("审计 timestamp 为 UTC 秒",
              all(e["timestamp"].endswith("Z") for e in events))

        # 租户 B 的审计：只有自己的 did.created
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-b")
        b_actions = [e["action"] for e in r["events"]]
        check("租户B仅见自己的事件",
              b_actions == ["did.created", "did.created"])
        # seq 全局连续自 1 起（default 租户此刻无事件）
        st, r = _http("GET", f"{base}/v1/audit")
        check("缺省租户无事件 -> 空页保持 after",
              st == 200 and r["events"] == [] and r["next_after"] == 0)
        all_seqs = sorted(
            e["seq"] for e in
            _http("GET", f"{base}/v1/audit", tenant="tenant-a")[1]["events"]
            + _http("GET", f"{base}/v1/audit", tenant="tenant-b")[1]["events"]
        )
        check("seq 全局连续自 1 起",
              all_seqs == list(range(1, len(all_seqs) + 1)))

        # 幂等成功每次记：重复登记 active、重复吊销
        _http("PUT", f"{base}/v1/credentials/{vc_a}/status",
              {"status": "active"}, tenant="tenant-a")
        _http("PUT", f"{base}/v1/credentials/{vc_a}/status",
              {"status": "active"}, tenant="tenant-a")
        _http("POST", f"{base}/v1/credentials/{vc_a}/revoke",
          {"reason": "测试吊销"}, tenant="tenant-a")
        _http("POST", f"{base}/v1/credentials/{vc_a}/revoke",
              {"reason": "第二次"}, tenant="tenant-a")
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        tail = [e["action"] for e in r["events"]][-4:]
        check("幂等成功每次记",
              tail == ["status.updated", "status.updated",
                       "credential.revoked", "credential.revoked"])

        # 失败不记：409、400、404 后审计条数不变
        before = len(r["events"])
        _http("PUT", f"{base}/v1/credentials/{vc_a}/status",
              {"status": "active"}, tenant="tenant-a")  # 已吊销 -> 409
        _http("POST", f"{base}/v1/dids",
              {"method": "BAD!", "public_key": "x"}, tenant="tenant-a")  # 400
        _http("POST", f"{base}/v1/credentials/vc_nonexistent/revoke",
              None, tenant="tenant-a")  # 404
        _http("POST", f"{base}/v1/credentials/{vc_a}/verify",
              {"body": body_a, "signature": sig_a}, tenant="tenant-a")  # 吊销->valid:false 不记
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("失败不记审计", len(r["events"]) == before)

        # 消费成功记 presentation.consumed
        st, r = _http("POST", f"{base}/v1/credentials/{vc_a}/present",
                      {"disclose": [], "challenge": "c2"}, tenant="tenant-a")
        # 凭证已吊销 -> 验演示返回吊销原因且不消费不记
        vp2 = r
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp2['presentation_id']}/verify",
            {"presentation": vp2, "challenge": "c2"}, tenant="tenant-a")
        check("吊销凭证演示不消费", st == 200 and r.get("valid") is False)
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("吊销演示不记消费",
              len(r["events"]) == before + 1  # 仅 presentation.created
              and r["events"][-1]["action"] == "presentation.created")

        # 新凭证 + 演示消费成功
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": did_a, "subject_did": sub_a,
                       "claims": {"x": 1}}, tenant="tenant-a")
        vc2 = r["credential_id"]
        st, r = _http("POST", f"{base}/v1/credentials/{vc2}/present",
                      {"disclose": [], "challenge": "c3"}, tenant="tenant-a")
        vp3 = r
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp3['presentation_id']}/verify",
            {"presentation": vp3, "challenge": "c3"}, tenant="tenant-a")
        check("演示消费成功 valid:true", st == 200 and r.get("valid") is True)
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("消费成功记 presentation.consumed",
              r["events"][-1]["action"] == "presentation.consumed"
              and r["events"][-1]["resource_type"] == "presentation"
              and r["events"][-1]["resource_id"] == vp3["presentation_id"])
        # 重复验证：已消费，不再记
        n = len(r["events"])
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp3['presentation_id']}/verify",
            {"presentation": vp3, "challenge": "c3"}, tenant="tenant-a")
        check("重复验证返回演示已消费",
              r.get("valid") is False and r.get("reason") == "演示已消费")
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("已消费不再记", len(r["events"]) == n)

        # 过期演示：不消费不记
        st, r = _http("POST", f"{base}/v1/credentials/{vc2}/present",
                      {"disclose": [], "challenge": "c4", "expires_in": 1},
                      tenant="tenant-a")
        vp4 = r
        time.sleep(1.5)
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp4['presentation_id']}/verify",
            {"presentation": vp4, "challenge": "c4"}, tenant="tenant-a")
        check("过期演示返回演示已过期",
              r.get("valid") is False and r.get("reason") == "演示已过期")
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("过期不记消费",
              r["events"][-1]["action"] == "presentation.created")

        # ---- 审计查询参数 ----
        st, _ = _http("GET", f"{base}/v1/audit?limit=0", tenant="tenant-a")
        check("limit=0 -> 400", st == 400)
        st, _ = _http("GET", f"{base}/v1/audit?limit=201", tenant="tenant-a")
        check("limit=201 -> 400", st == 400)
        st, _ = _http("GET", f"{base}/v1/audit?limit=abc", tenant="tenant-a")
        check("limit 非整数 -> 400", st == 400)
        st, _ = _http("GET", f"{base}/v1/audit?limit=1.5", tenant="tenant-a")
        check("limit 小数 -> 400", st == 400)
        st, _ = _http("GET", f"{base}/v1/audit?after=-1", tenant="tenant-a")
        check("after 负数 -> 400", st == 400)
        st, _ = _http("GET", f"{base}/v1/audit?after=x", tenant="tenant-a")
        check("after 非整数 -> 400", st == 400)

        # 分页：limit=2 翻页
        st, r1 = _http("GET", f"{base}/v1/audit?limit=2", tenant="tenant-a")
        check("limit=2 返回 2 条", len(r1["events"]) == 2)
        check("next_after 为末条 seq",
              r1["next_after"] == r1["events"][-1]["seq"])
        st, r2 = _http(
            "GET", f"{base}/v1/audit?limit=2&after={r1['next_after']}",
            tenant="tenant-a")
        check("after 翻页 seq 升序且衔接",
              r2["events"][0]["seq"] == r1["events"][-1]["seq"] + 1)
        # after 超过最大 seq -> 空页保持 after
        st, r3 = _http("GET", f"{base}/v1/audit?after=9999",
                       tenant="tenant-a")
        check("空页保持 after",
              r3["events"] == [] and r3["next_after"] == 9999)
        # limit=200 合法
        st, _ = _http("GET", f"{base}/v1/audit?limit=200", tenant="tenant-a")
        check("limit=200 -> 200", st == 200)

        # 审计跨重启保留
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "重启后服务启动超时"
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("审计跨重启保留", st == 200 and len(r["events"]) == n + 1)
        # 重启后 seq 继续递增
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "a-new"},
                      tenant="tenant-a")
        st, r = _http("GET", f"{base}/v1/audit", tenant="tenant-a")
        check("重启后 seq 继续递增",
              r["events"][-1]["seq"] == r["events"][-2]["seq"] + 1)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    if failures:
        print(f"\n{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("\n全部新功能验证通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
