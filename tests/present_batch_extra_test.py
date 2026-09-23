#!/usr/bin/env python3
"""present-batch 补充：409/400 分支与并发原子性。"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8978
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"
failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


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


def wait_up():
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/health")
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_up()
    try:
        def did(h):
            st, r = http("POST", f"{BASE}/v1/dids",
                         {"method": "example", "public_key": h})
            assert st == 201, r
            return r["did"]

        issuer = did("iss")
        holder = did("hold")

        def issue(subj, claims=None):
            st, r = http("POST", f"{BASE}/v1/credentials",
                         {"issuer_did": issuer, "subject_did": subj,
                          "claims": claims or {"a": 1}})
            assert st == 201, r
            return r["credential_id"]

        cred = issue(holder)

        # 1. 签发者停用 -> 409
        st, r = http("POST", f"{BASE}/v1/dids/{issuer}/deactivate", {})
        assert st == 200, r
        st, r = http(
            "POST", f"{BASE}/v1/credentials/{cred}/present-batch",
            {"presentations": [{"disclose": ["/a"]}]})
        check("签发者停用批量 -> 409 中文原因",
              st == 409 and bool(r.get("error")))
        # 不写入
        st, r = http("GET", f"{BASE}/v1/audit?limit=200")
        n = sum(1 for e in r["events"] if e["action"] == "presentation.created")
        check("409 批次不写审计", n == 0)

        # 2. 并发批量：全部成功且无丢失/重复（不同凭证需要新 issuer）
        issuer2 = did("iss2")
        st, r = http("POST", f"{BASE}/v1/credentials",
                     {"issuer_did": issuer2, "subject_did": holder,
                      "claims": {"a": 1}})
        cred2 = r["credential_id"]

        results = []

        def one(idx):
            return http(
                "POST", f"{BASE}/v1/credentials/{cred2}/present-batch",
                {"presentations": [
                    {"disclose": ["/a"], "challenge": f"c-{idx}-{j}"}
                    for j in range(5)]})

        with ThreadPoolExecutor(max_workers=8) as ex:
            for st, r in ex.map(one, range(20)):
                results.append((st, r))
        ok_all = all(st == 201 for st, _ in results)
        total = sum(len(r["presentations"]) for _, r in results)
        check("20 个并发批次全部 201", ok_all)
        check("共 100 条演示", total == 100)
        ids = [vp["presentation_id"] for _, r in results for vp in r["presentations"]]
        check("100 个 presentation_id 全局唯一", len(set(ids)) == 100)
        st, r = http("GET", f"{BASE}/v1/audit?limit=200")
        n = sum(1 for e in r["events"] if e["action"] == "presentation.created")
        check("审计 100 条与记录一致（原子提交）", n == 100)

        # 3. 并发混合法批：合法批全部成功、非法批 400 且无部分写入
        barrier = threading.Barrier(8)

        def mixed(idx):
            barrier.wait()
            if idx % 2 == 0:
                return http(
                    "POST", f"{BASE}/v1/credentials/{cred2}/present-batch",
                    {"presentations": [{"disclose": ["/a"],
                                        "challenge": f"m-{idx}"}]})
            return http(
                "POST", f"{BASE}/v1/credentials/{cred2}/present-batch",
                {"presentations": [{"disclose": ["/no-such"],
                                    "challenge": f"bad-{idx}"}]})

        with ThreadPoolExecutor(max_workers=8) as ex:
            mixed_results = list(ex.map(mixed, range(8)))
        statuses = sorted(st for st, _ in mixed_results)
        check("混合并发：4×201 4×400", statuses == [201] * 4 + [400] * 4)
        st, r = http("GET", f"{BASE}/v1/audit?limit=200")
        n = sum(1 for e in r["events"] if e["action"] == "presentation.created")
        check("非法并发批不留记录（100+4=104）", n == 104)

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
        print(f"{len(failures)} 个失败: {failures}")
        return 1
    print("补充验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
