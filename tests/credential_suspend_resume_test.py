#!/usr/bin/env python3
"""凭证暂停/恢复端到端测试（PUT status 状态机、verify/present/prove 拦截）。"""
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
PORT = 8993


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


def main():
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    failures = []

    def check(name, cond, extra=""):
        print(("PASS" if cond else "FAIL"), name, extra)
        if not cond:
            failures.append(name)

    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health")
                break
            except OSError:
                time.sleep(0.15)
        B = f"http://127.0.0.1:{PORT}"
        H = {"X-Tenant-ID": "susp"}
        st, d = http("POST", f"{B}/v1/dids",
                     {"method": "example", "public_key": "k1"}, H)
        assert st == 201, d
        did = d["did"]
        st, d = http("POST", f"{B}/v1/credentials",
                     {"issuer_did": did, "subject_did": did,
                      "claims": {"role": "admin", "age": 30}}, H)
        assert st == 201, d
        vc = d["credential_id"]
        st, d = http("GET", f"{B}/v1/credentials/{vc}", headers=H)
        assert st == 200, d
        cred_body, cred_sig = d["body"], d["signature"]

        # 无状态 GET：active + null updated_at
        st, r = http("GET", f"{B}/v1/credentials/{vc}/status", headers=H)
        check("无状态 GET active/null", st == 200 and r == {
            "credential_id": vc, "status": "active", "updated_at": None})

        # 非法请求体
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended"}, H)
        check("suspended 缺 reason 400", st == 400 and set(r) == {"error"}
              and r["error"])
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "   "}, H)
        check("suspended 空白 reason 400", st == 400 and bool(r.get("error")))
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": 123}, H)
        check("suspended 非字符串 reason 400",
              st == 400 and bool(r.get("error")))
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "因" * 257}, H)
        check("suspended 257 码点 reason 400",
              st == 400 and bool(r.get("error")))
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "因" * 256}, H)
        check("suspended 256 码点原因合法（无状态直接暂停 200）",
              st == 200 and r["status"] == "suspended"
              and list(r) == ["credential_id", "status", "updated_at"]
              and r["updated_at"])
        first_suspend_at = r["updated_at"]

        # 历史已有一条 suspended
        st, h = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                     headers=H)
        check("无状态直接暂停：历史仅 suspended 一条",
              st == 200 and len(h["events"]) == 1
              and h["events"][0]["status"] == "suspended"
              and h["events"][0]["reason"] == "因" * 256
              and h["events"][0]["revoked_at"] is None
              and h["events"][0]["cursor"] == 1)

        # 同状态不同原因 409
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "别的原因"}, H)
        check("同状态不同原因 409 且仅 error",
              st == 409 and set(r) == {"error"} and r["error"])
        # 409 不追加历史
        st, h = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                     headers=H)
        check("409 不追加历史", len(h["events"]) == 1)

        # 同状态同原因幂等 200，updated_at 不变
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "因" * 256}, H)
        check("同状态同原因幂等 200 时间不变",
              st == 200 and r["status"] == "suspended"
              and r["updated_at"] == first_suspend_at)
        st, h = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                     headers=H)
        check("幂等不追加历史", len(h["events"]) == 1)

        # GET 状态
        st, r = http("GET", f"{B}/v1/credentials/{vc}/status", headers=H)
        check("GET suspended 三键",
              st == 200 and r == {
                  "credential_id": vc, "status": "suspended",
                  "updated_at": first_suspend_at})

        # verify：valid:false + 暂停原因
        st, r = http("POST", f"{B}/v1/credentials/{vc}/verify",
                     {"body": cred_body, "signature": cred_sig}, H)
        check("verify 暂停 200 valid:false 原因",
              st == 200 and r == {
                  "valid": False,
                  "reason": f"凭证已暂停：{'因' * 256}"})

        # present / present-batch / prove 409
        st, r = http("POST", f"{B}/v1/credentials/{vc}/present",
                     {"disclose": ["/role"]}, H)
        check("present 暂停 409 仅 error",
              st == 409 and set(r) == {"error"} and r["error"])
        st, r = http("POST", f"{B}/v1/credentials/{vc}/present-batch",
                     {"presentations": [{"disclose": ["/role"]}]}, H)
        check("present-batch 暂停 409", st == 409 and bool(r.get("error")))
        st, r = http("POST", f"{B}/v1/credentials/{vc}/prove",
                     {"predicates": [{"path": "/age", "op": "gte",
                                      "value": 18}], "challenge": "c1"}, H)
        check("prove 暂停 409 仅 error",
              st == 409 and set(r) == {"error"} and r["error"])

        # 暂停期间不产生创建类审计
        st, aud = http("GET", f"{B}/v1/audit?limit=200", headers=H)
        actions = [e["action"] for e in aud["events"]]
        check("暂停期间无 presentation/proof 创建审计",
              "presentation.created" not in actions
              and "proof.created" not in actions)
        check("暂停变更与幂等各记一次 status.updated（1+1=2）",
              actions.count("status.updated") == 2)

        # 恢复 active：200
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "active"}, H)
        check("恢复 active 200",
              st == 200 and r["status"] == "active" and r["updated_at"]
              and list(r) == ["credential_id", "status", "updated_at"])

        # verify 恢复后 valid:true
        st, r = http("POST", f"{B}/v1/credentials/{vc}/verify",
                     {"body": cred_body, "signature": cred_sig}, H)
        check("恢复后 verify valid:true", st == 200 and r == {"valid": True})

        # 恢复后 present/prove 201
        st, vp = http("POST", f"{B}/v1/credentials/{vc}/present",
                      {"disclose": ["/role"], "challenge": "p1"}, H)
        check("恢复后 present 201", st == 201)
        st, zp = http("POST", f"{B}/v1/credentials/{vc}/prove",
                      {"predicates": [{"path": "/age", "op": "gte",
                                       "value": 18}], "challenge": "z1"}, H)
        check("恢复后 prove 201", st == 201)

        # 暂停期间已存在演示/证明：验证不消费，恢复后可用
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "二次调查"}, H)
        check("再次暂停 200", st == 200)
        st, r = http("POST", f"{B}/v1/presentations/{vp['presentation_id']}/verify",
                     {"presentation": vp, "challenge": "p1"}, H)
        check("暂停时旧演示验证 valid:false 凭证已暂停：二次调查",
              st == 200 and r == {
                  "valid": False, "reason": "凭证已暂停：二次调查"})
        st, r = http("POST", f"{B}/v1/proofs/{zp['proof_id']}/verify",
                     {"proof": zp, "challenge": "z1"}, H)
        check("暂停时旧证明验证 valid:false 凭证已暂停",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已暂停：二次调查")
        # 恢复后两者均可消费
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "active"}, H)
        check("二次恢复 200", st == 200)
        st, r = http("POST", f"{B}/v1/presentations/{vp['presentation_id']}/verify",
                     {"presentation": vp, "challenge": "p1"}, H)
        check("恢复后旧演示 valid:true（已消费）",
              st == 200 and r == {"valid": True})
        st, r = http("POST", f"{B}/v1/proofs/{zp['proof_id']}/verify",
                     {"proof": zp, "challenge": "z1"}, H)
        check("恢复后旧证明 valid:true（已消费）",
              st == 200 and r == {"valid": True})

        # 历史事件序列：suspended(256) / active(恢复) / suspended / active
        st, h = http("GET", f"{B}/v1/credentials/{vc}/status/history",
                     headers=H)
        statuses = [e["status"] for e in h["events"]]
        check("历史序列", statuses == ["suspended", "active",
                                       "suspended", "active"], str(statuses))
        check("历史游标 1..4 连续",
              [e["cursor"] for e in h["events"]] == [1, 2, 3, 4])
        check("恢复事件 reason/revoked_at 为 null、暂停事件存原因",
              all(e["reason"] is None and e["revoked_at"] is None
                  for e in h["events"] if e["status"] == "active")
              and [e["reason"] for e in h["events"]
                   if e["status"] == "suspended"] == ["因" * 256, "二次调查"])
        check("事件均关联 status.updated 审计",
              all(e["audit_seq"] and e["audit_timestamp"]
                  for e in h["events"]))

        # 吊销终态：suspended -> revoke -> 任何 PUT 409
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "终态前暂停"}, H)
        assert st == 200, r
        st, r = http("POST", f"{B}/v1/credentials/{vc}/revoke",
                     {"reason": "最终吊销"}, H)
        check("暂停后吊销 200", st == 200 and r["status"] == "revoked")
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "active"}, H)
        check("revoked 后 active 409", st == 409 and bool(r.get("error")))
        st, r = http("PUT", f"{B}/v1/credentials/{vc}/status",
                     {"status": "suspended", "reason": "x"}, H)
        check("revoked 后 suspended 409",
              st == 409 and bool(r.get("error")))

        # 第二张凭证：首次 active 201，重复 active 200
        st, d2 = http("POST", f"{B}/v1/credentials",
                      {"issuer_did": did, "subject_did": did,
                       "claims": {"k": "v"}}, H)
        vc2 = d2["credential_id"]
        st, r = http("PUT", f"{B}/v1/credentials/{vc2}/status",
                     {"status": "active"}, H)
        check("首次 active 201", st == 201)
        st, r = http("PUT", f"{B}/v1/credentials/{vc2}/status",
                     {"status": "active"}, H)
        check("重复 active 200", st == 200)

        # 跨租户 404 / 未知 404
        st, r = http("GET", f"{B}/v1/credentials/{vc}/status",
                     headers={"X-Tenant-ID": "other"})
        check("跨租户 GET 404 仅 error",
              st == 404 and set(r) == {"error"})
        st, r = http("PUT", f"{B}/v1/credentials/vc_nope/status",
                     {"status": "suspended", "reason": "x"},
                     headers={"X-Tenant-ID": "other"})
        check("未知凭证暂停 404 仅 error",
              st == 404 and set(r) == {"error"})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("暂停/恢复端到端验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
