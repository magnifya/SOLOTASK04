#!/usr/bin/env python3
"""状态与吊销功能的临时验证脚本（不改动正式测试）。"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _http(method, url, payload=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None
    )
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
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


failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


def start(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port)
    return proc


def main():
    port = 8952
    store = tempfile.mktemp(suffix=".json")
    proc = start(port, store)
    base = f"http://127.0.0.1:{port}"
    try:
        # 准备两个 DID 与两张凭证
        s, a = _http("POST", base + "/v1/dids",
                     {"method": "example", "public_key": "issuer-k"})
        s, b = _http("POST", base + "/v1/dids",
                     {"method": "example", "public_key": "subject-k"})
        s, c1 = _http("POST", base + "/v1/credentials",
                      {"issuer_did": a["did"], "subject_did": b["did"],
                       "claims": {"role": "admin"}})
        s, c2 = _http("POST", base + "/v1/credentials",
                      {"issuer_did": a["did"], "subject_did": b["did"],
                       "claims": {"role": "user"}})
        vc1, vc2 = c1["credential_id"], c2["credential_id"]

        # --- PUT status ---
        s, r = _http("PUT", f"{base}/v1/credentials/{vc1}/status",
                     {"status": "active"})
        check("PUT 首次 201 且字段齐全",
              s == 201 and r["credential_id"] == vc1
              and r["status"] == "active" and r.get("updated_at"))
        first_updated = r["updated_at"]
        s, r2 = _http("PUT", f"{base}/v1/credentials/{vc1}/status",
                      {"status": "active"})
        check("PUT 重复 200 且 updated_at 不变",
              s == 200 and r2["updated_at"] == first_updated
              and r2["status"] == "active")
        s, r = _http("PUT", f"{base}/v1/credentials/{vc1}/status",
                     {"status": "active", "x": 1})
        check("PUT 多余字段 400", s == 400 and r.get("error"))
        s, r = _http("PUT", f"{base}/v1/credentials/{vc1}/status", {})
        check("PUT 缺 status 400", s == 400 and r.get("error"))
        s, r = _http("PUT", f"{base}/v1/credentials/{vc1}/status",
                     {"status": "revoked"})
        check("PUT 非法 status 值 400", s == 400 and r.get("error"))
        s, r = _http("PUT", f"{base}/v1/credentials/{vc1}/status",
                     {"status": 1})
        check("PUT 非字符串 status 400", s == 400 and r.get("error"))
        s, r = _http("PUT", f"{base}/v1/credentials/vc_none/status",
                     {"status": "active"})
        check("PUT 未知凭证 404", s == 404 and r.get("error"))

        # --- GET status ---
        s, r = _http("GET", f"{base}/v1/credentials/{vc1}/status")
        check("GET 已登记 200", s == 200 and r["status"] == "active"
              and r["updated_at"] == first_updated)
        s, r = _http("GET", f"{base}/v1/credentials/{vc2}/status")
        check("GET 无状态按 active 且 updated_at 为 null",
              s == 200 and r["status"] == "active"
              and r["updated_at"] is None)
        s, r = _http("GET", f"{base}/v1/credentials/vc_none/status")
        check("GET 未知凭证 404", s == 404 and r.get("error"))

        # --- revoke ---
        s, r = _http("POST", f"{base}/v1/credentials/vc_none/revoke", {})
        check("revoke 未知凭证 404", s == 404 and r.get("error"))
        s, r = _http("POST", f"{base}/v1/credentials/{vc2}/revoke",
                     {"reason": 123})
        check("revoke 首次非法 reason 400", s == 400 and r.get("error"))
        s, r = _http("POST", f"{base}/v1/credentials/{vc2}/revoke",
                     {"reason": "   "})
        check("revoke 空白 reason 400", s == 400 and r.get("error"))
        s, r = _http("POST", f"{base}/v1/credentials/{vc2}/revoke",
                     {"reason": "  密钥泄露  "})
        check("revoke 裁剪 reason 200",
              s == 200 and r["reason"] == "密钥泄露"
              and r["status"] == "revoked" and r.get("revoked_at")
              and r.get("updated_at") and r["credential_id"] == vc2)
        first_revoke = r
        s, r = _http("POST", f"{base}/v1/credentials/{vc2}/revoke",
                     {"reason": 123})
        check("revoke 已吊销时非法 reason 忽略并返回首次结果",
              s == 200 and r == first_revoke)
        s, r = _http("POST", f"{base}/v1/credentials/{vc1}/revoke", {})
        check("revoke 默认 reason", s == 200
              and r["reason"] == "持证人主动吊销"
              and r["status"] == "revoked")
        first_revoke1 = r
        s, r = _http("POST", f"{base}/v1/credentials/{vc1}/revoke")
        check("revoke 无请求体也可（幂等返回首次结果）",
              s == 200 and r == first_revoke1)

        # 已吊销后 PUT status -> 409
        s, r = _http("PUT", f"{base}/v1/credentials/{vc1}/status",
                     {"status": "active"})
        check("已吊销 PUT status 409 且 error 非空",
              s == 409 and r.get("error"))
        s, r = _http("GET", f"{base}/v1/credentials/{vc1}/status")
        check("409 后状态不变", s == 200 and r["status"] == "revoked"
              and r["updated_at"] == first_revoke1["updated_at"])

        # --- verify 集成 ---
        s, cred = _http("GET", f"{base}/v1/credentials/{vc2}")
        s, r = _http("POST", f"{base}/v1/credentials/{vc2}/verify",
                     {"body": cred["body"], "signature": cred["signature"]})
        check("verify 已吊销 200 valid:false 原因含保存 reason",
              s == 200 and r["valid"] is False
              and r["reason"] == "凭证已吊销：密钥泄露")

        # 新签一张无状态凭证，verify 仍为 true
        s, c3 = _http("POST", base + "/v1/credentials",
                      {"issuer_did": a["did"], "subject_did": b["did"],
                       "claims": {"role": "guest"}})
        vc3 = c3["credential_id"]
        s, cred = _http("GET", f"{base}/v1/credentials/{vc3}")
        s, r = _http("POST", f"{base}/v1/credentials/{vc3}/verify",
                     {"body": cred["body"], "signature": cred["signature"]})
        check("verify 无状态凭证 valid:true", s == 200 and r["valid"] is True)
    finally:
        proc.terminate()
        proc.wait()

    # --- 持久化跨重启 ---
    proc = start(port, store)
    try:
        s, r = _http("GET", f"{base}/v1/credentials/{vc2}/status")
        check("重启后吊销状态保留", s == 200 and r["status"] == "revoked"
              and r["reason"] == "密钥泄露")
        s, r = _http("GET", f"{base}/v1/credentials/{vc1}/status")
        check("重启后默认 reason 吊销保留", s == 200
              and r["status"] == "revoked"
              and r["reason"] == "持证人主动吊销")
    finally:
        proc.terminate()
        proc.wait()
    os.unlink(store)

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部状态/吊销测试通过 ✔")


if __name__ == "__main__":
    main()
