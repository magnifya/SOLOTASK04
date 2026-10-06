#!/usr/bin/env python3
"""GET /v1/credential-schemas 冒烟测试（临时，验证新端点语义）。"""
import atexit
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
BASE = "http://127.0.0.1:0"
_PROCS = []


def _http(method, url, payload=None, headers=None):
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


def start_server(env):
    global BASE
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", "0", "--host", "127.0.0.1"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    _PROCS.append(proc)
    base = None
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("VCBACKEND_READY"):
            m = re.search(r"port=(\d+)", line)
            if m:
                base = f"http://127.0.0.1:{m.group(1)}"
                break
    assert base, "未取得端口"
    BASE = base
    return proc


def _cleanup():
    for p in _PROCS:
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=10)


def main():
    atexit.register(_cleanup)
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    T = {"X-Tenant-ID": "disc-a"}
    T2 = {"X-Tenant-ID": "disc-b"}
    start_server(env)

    st, r = _http("POST", f"{BASE}/v1/dids",
                  {"method": "example", "public_key": "iss1"}, headers=T)
    iss1 = r["did"]
    st, r = _http("POST", f"{BASE}/v1/dids",
                  {"method": "example", "public_key": "iss2"}, headers=T)
    iss2 = r["did"]
    st, r = _http("POST", f"{BASE}/v1/dids",
                  {"method": "example", "public_key": "issB"}, headers=T2)
    iss_b = r["did"]

    ct = {"/name": "string"}
    rq = ["/name"]

    def reg(sid, ver, issuer, headers=T):
        return _http("POST", f"{BASE}/v1/credential-schemas",
                     {"schema_id": sid, "version": ver, "issuer_did": issuer,
                      "claim_types": ct, "required_claims": rq},
                     headers=headers)

    # 注册顺序：alpha v1(iss1), beta v1(iss2), alpha v2(iss1), beta v2(iss2)
    for sid, ver, issuer in [("alpha", 1, iss1), ("beta", 1, iss2),
                             ("alpha", 2, iss1), ("beta", 2, iss2)]:
        st, r = reg(sid, ver, issuer)
        assert st == 201, (st, r)
    st, r = reg("alpha", 1, iss_b, T2)
    assert st == 201

    # 弃用 alpha v2，吊销 beta v1
    st, r = _http("POST", f"{BASE}/v1/credential-schemas/alpha/2/status",
                  {"issuer_did": iss1, "status": "deprecated"}, headers=T)
    assert st == 201
    st, r = _http("POST", f"{BASE}/v1/credential-schemas/beta/1/status",
                  {"issuer_did": iss2, "status": "revoked",
                   "reason": "坏版本"}, headers=T)
    assert st == 201

    url = f"{BASE}/v1/credential-schemas"

    # 1. 无过滤：4 项，cursor 升序，键序与字段
    st, r = _http("GET", url, headers=T)
    check("无过滤 200 且顶层恰两键",
          st == 200 and list(r) == ["schemas", "next_after"])
    check("无过滤 4 项", len(r["schemas"]) == 4)
    item_keys = ["cursor", "schema_id", "version", "issuer_did",
                 "claim_types", "required_claims", "digest",
                 "status", "reason", "updated_at"]
    check("项键序恰为十字段",
          all(list(it) == item_keys for it in r["schemas"]))
    cursors = [it["cursor"] for it in r["schemas"]]
    check("cursor 升序", cursors == sorted(cursors))
    check("cursor 为 1..4（注册事件游标）", cursors == [1, 2, 3, 4])
    check("next_after 为末项 cursor", r["next_after"] == 4)
    a1 = r["schemas"][0]
    check("active 项 reason/updated_at 为 null",
          a1["status"] == "active" and a1["reason"] is None
          and a1["updated_at"] is None)
    check("内容字段与注册一致",
          a1["schema_id"] == "alpha" and a1["version"] == 1
          and a1["issuer_did"] == iss1 and a1["claim_types"] == ct
          and a1["required_claims"] == rq
          and isinstance(a1["digest"], str) and len(a1["digest"]) == 64)
    dep = r["schemas"][2]
    check("deprecated 项状态字段",
          dep["schema_id"] == "alpha" and dep["version"] == 2
          and dep["status"] == "deprecated"
          and dep["reason"] == "模式版本已弃用"
          and isinstance(dep["updated_at"], str))
    rev = r["schemas"][1]
    check("revoked 项状态字段",
          rev["status"] == "revoked" and rev["reason"] == "坏版本")

    # cursor 与历史注册事件一致
    st, h = _http("GET",
                  f"{BASE}/v1/credential-schemas/alpha/2/history"
                  f"?issuer_did={iss1}", headers=T)
    check("cursor 与历史注册事件一致",
          h["events"][0]["cursor"] == dep["cursor"])

    # 2. 过滤
    st, r = _http("GET", f"{url}?issuer_did={iss1}", headers=T)
    check("issuer_did 过滤 2 项",
          st == 200 and len(r["schemas"]) == 2
          and all(it["issuer_did"] == iss1 for it in r["schemas"]))
    st, r = _http("GET", f"{url}?schema_id=beta", headers=T)
    check("schema_id 过滤 2 项",
          len(r["schemas"]) == 2
          and all(it["schema_id"] == "beta" for it in r["schemas"]))
    st, r = _http("GET", f"{url}?status=active", headers=T)
    check("status=active 2 项",
          len(r["schemas"]) == 2
          and all(it["status"] == "active" for it in r["schemas"]))
    st, r = _http("GET", f"{url}?status=revoked", headers=T)
    check("status=revoked 1 项", len(r["schemas"]) == 1)
    st, r = _http("GET", f"{url}?issuer_did={iss1}&status=deprecated",
                  headers=T)
    check("组合过滤 1 项",
          len(r["schemas"]) == 1 and r["schemas"][0]["version"] == 2)
    st, r = _http("GET", f"{url}?issuer_did=did:x:ghost", headers=T)
    check("未知 issuer 空结果且 next_after 保持",
          st == 200 and r["schemas"] == [] and r["next_after"] == 0)
    st, r = _http("GET", f"{url}?schema_id=ghost", headers=T)
    check("未知 schema_id 空结果", r["schemas"] == [])
    st, r = _http("GET", f"{url}?issuer_did={iss_b}", headers=T)
    check("他租户 issuer 空结果", r["schemas"] == [])

    # 3. 分页
    st, p1 = _http("GET", f"{url}?limit=2", headers=T)
    check("limit=2 首页", len(p1["schemas"]) == 2
          and p1["next_after"] == p1["schemas"][-1]["cursor"])
    st, p2 = _http("GET", f"{url}?limit=2&after={p1['next_after']}",
                   headers=T)
    check("第二页", [it["cursor"] for it in p2["schemas"]] == [3, 4])
    st, p3 = _http("GET", f"{url}?after={p2['next_after']}", headers=T)
    check("空页 next_after 保持 after",
          p3["schemas"] == [] and p3["next_after"] == 4)
    st, r = _http("GET", f"{url}?limit=1&after=2", headers=T)
    check("after 排除不大于它的项",
          len(r["schemas"]) == 1 and r["schemas"][0]["cursor"] == 3)

    # 4. 400 情形：统一 {"error": "请求非法"}
    bad_queries = [
        "foo=1", "limit=1&limit=2", "after=1&after=2",
        "issuer_did=", "schema_id=", "status=", "limit=", "after=",
        "schema_id=BAD", "schema_id=1abc", "status=ACTIVE", "status=x",
        "limit=0", "limit=201", "limit=-1", "limit=+5", "limit= 5",
        "limit=5 ", "limit=1.0", "limit=٥", "after=-1", "after=+1",
        "after= 1", "after=١", "after=1.5", "status=deprecated&status=active",
        "issuer_did=a&issuer_did=b", "schema_id=alpha&schema_id=beta",
    ]
    for q in bad_queries:
        from urllib.parse import quote
        st, r = _http("GET", f"{url}?{quote(q, safe='=&')}", headers=T)
        check(f"非法查询（{q}）-> 400 请求非法",
              st == 400 and r == {"error": "请求非法"})
    # 显式空 X-Tenant-ID
    st, r = _http("GET", url, headers={"X-Tenant-ID": ""})
    check("显式空 X-Tenant-ID -> 400 请求非法",
          st == 400 and r == {"error": "请求非法"})

    # 5. 租户隔离
    st, r = _http("GET", url, headers=T2)
    check("他租户只见自己的 1 项",
          st == 200 and len(r["schemas"]) == 1
          and r["schemas"][0]["issuer_did"] == iss_b)

    # 6. 只读：审计不变
    st, a_before = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T)
    _http("GET", url, headers=T)
    _http("GET", f"{url}?limit=2", headers=T)
    st, a_after = _http("GET", f"{BASE}/v1/audit?limit=200", headers=T)
    check("查询不记审计",
          len(a_before["events"]) == len(a_after["events"]))

    # 7. 跨重启分页稳定
    proc2 = start_server(env)
    st, r1 = _http("GET", f"{url}?limit=200", headers=T)
    proc2.terminate()
    proc2.wait(timeout=10)
    _PROCS.remove(proc2)
    start_server(env)
    st, r2 = _http("GET", f"{url}?limit=200", headers=T)
    check("跨重启分页结果稳定", r1 == r2)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
