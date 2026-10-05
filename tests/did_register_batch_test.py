#!/usr/bin/env python3
"""DID 批量注册（POST /v1/dids/register-batch）端到端测试。

覆盖：
- 请求体恰含 items（1..100 项数组）；空体、非法 JSON、非对象、缺
  items、外层多余字段、items 非数组/空/超限、项非对象、项字段集合
  或类型非法（method 格式、public_key 句柄、key_mode 取值）一律
  400 且恰含 {"error":"请求非法"}；显式空 X-Tenant-ID 同样 400；
- 同一批内句柄重复（按去空白后句柄）409 且恰含 {"error":"批内句柄重复"}；
- 成功 201 仅返 {"results":[...]}，与输入等长同序，每项恰含 did、
  public_key、key_mode、key_handle、key_version；新项为版本一的
  server P-256 密钥；本租户已登记句柄按单项幂等规则返回原 DID；
- 新项追加 did.created 审计、DID 历史与密钥生命周期 active 事件，
  幂等命中项沿用单项注册的审计行为，批内审计按输入顺序追加；
- 校验失败与落盘失败整批无副作用（DID/审计/游标完全回滚），落盘
  失败 500 且恰含 {"error":"存储失败"}，可重试；
- 同句柄跨租户各自独立、互不可见；批量注册的 DID 可经现有查询、
  DID 文档、凭证签发与验签流程使用；单项入口行为不变。

直接运行：python3 tests/did_register_batch_test.py
"""

import copy
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

from vcbackend.store import StorageError, VCStore  # noqa: E402

PORT = 8973
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

RESULT_FIELDS = {"did", "public_key", "key_mode", "key_handle", "key_version"}


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(payload).encode() if payload is not None else None
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


def start_server(store=STORE, port=PORT):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def main():
    failures = []

    def check(name, cond, extra=None):
        if cond:
            print("PASS:", name)
        else:
            print("FAIL:", name, extra if extra is not None else "")
            failures.append(name)

    proc = start_server()
    try:
        T = {}

        def batch(payload=None, headers=None, raw=None):
            return _http("POST", f"{BASE}/v1/dids/register-batch", payload,
                         headers=headers, raw=raw)

        # ---------- 形状与字段校验：400 且恰含 {"error":"请求非法"} ----------
        bad_cases = [
            ("空体", None, b""),
            ("JSON 非对象", None, b"[1,2]"),
            ("非法 JSON", None, b"{oops"),
            ("缺 items", {}, None),
            ("外层多余字段",
             {"items": [{"method": "m", "public_key": "x1"}], "x": 1}, None),
            ("items 非数组", {"items": {}}, None),
            ("items 为空", {"items": []}, None),
            ("items 超限", {"items": [
                {"method": "m", "public_key": f"lim{i}"} for i in range(101)
            ]}, None),
            ("项非对象", {"items": ["x"]}, None),
            ("项缺 method", {"items": [{"public_key": "x2"}]}, None),
            ("项缺 public_key", {"items": [{"method": "m"}]}, None),
            ("项多余字段",
             {"items": [{"method": "m", "public_key": "x3", "z": 1}]}, None),
            ("method 格式非法",
             {"items": [{"method": "M bad", "public_key": "x4"}]}, None),
            ("method 为空",
             {"items": [{"method": "", "public_key": "x5"}]}, None),
            ("method 非字符串",
             {"items": [{"method": 1, "public_key": "x6"}]}, None),
            ("public_key 空白",
             {"items": [{"method": "m", "public_key": "  "}]}, None),
            ("public_key 为 PEM",
             {"items": [{"method": "m",
                         "public_key": "-----BEGIN PUBLIC KEY-----x"}]},
             None),
            ("public_key 非字符串",
             {"items": [{"method": "m", "public_key": 5}]}, None),
            ("key_mode 非法取值",
             {"items": [{"method": "m", "public_key": "x7",
                         "key_mode": "local"}]}, None),
            ("key_mode 为 null",
             {"items": [{"method": "m", "public_key": "x8",
                         "key_mode": None}]}, None),
        ]
        for name, payload, raw in bad_cases:
            st, r = batch(payload, raw=raw)
            check(f"400 {name}",
                  st == 400 and r == {"error": "请求非法"}, (st, r))

        st, r = batch({"items": [{"method": "m", "public_key": "x9"}]},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400 请求非法",
              st == 400 and r == {"error": "请求非法"}, (st, r))

        # ---------- 批内句柄重复：409 ----------
        st, r = batch({"items": [
            {"method": "m", "public_key": "dup-h"},
            {"method": "m", "public_key": " dup-h "},
        ]})
        check("批内句柄重复 409",
              st == 409 and r == {"error": "批内句柄重复"}, (st, r))

        # 校验/冲突失败无副作用：dup-h 未登记
        st, r = batch({"items": [{"method": "m", "public_key": "dup-h"}]})
        check("失败批无副作用（dup-h 可新注册）",
              st == 201 and r["results"][0]["key_handle"] == "dup-h", (st, r))

        # ---------- 成功批：新项 + 幂等命中混合 ----------
        st, pre = _http("POST", f"{BASE}/v1/dids",
                        {"method": "example", "public_key": "pre-h"})
        assert st == 201, (st, pre)
        pre_did = pre["did"]

        st, r = batch({"items": [
            {"method": "example", "public_key": "nb-1"},
            {"method": "example", "public_key": "nb-2",
             "key_mode": "server"},
            {"method": "example", "public_key": "pre-h"},
        ]})
        check("成功批 201 仅含 results",
              st == 201 and set(r) == {"results"} and len(r["results"]) == 3,
              (st, r))
        d1 = d2 = None
        if st == 201:
            for idx, item in enumerate(r["results"]):
                check(f"results[{idx}] 字段集同单项注册",
                      set(item) == RESULT_FIELDS, item)
                check(f"results[{idx}] server/版本一",
                      item["key_mode"] == "server"
                      and item["key_version"] == 1, item)
            d1 = r["results"][0]["did"]
            d2 = r["results"][1]["did"]
            check("新项 DID 互不相同且幂等命中返回原 DID",
                  d1 != d2 and r["results"][2]["did"] == pre_did, r)
            check("幂等命中项沿用原句柄",
                  r["results"][2]["key_handle"] == "pre-h", r)

            # 现有只读接口可直接使用批内注册的 DID
            st, q = _http("GET", f"{BASE}/v1/dids/{d1}")
            check("GET /v1/dids/{did} 可查", st == 200 and q["did"] == d1,
                  (st, q))
            st, q = _http("GET", f"{BASE}/v1/dids/{d1}/document")
            check("DID 文档可查",
                  st == 200 and q.get("current_key_version") == 1, (st, q))
            st, q = _http("GET", f"{BASE}/v1/dids/{d1}/history")
            check("DID 历史含 did.created/active",
                  st == 200 and any(
                      e.get("action") == "did.created"
                      and e.get("status") == "active"
                      for e in q.get("events", [])), (st, q))
            st, q = _http("GET", f"{BASE}/v1/dids/{d1}/keys/history")
            check("密钥生命周期含 v1 active",
                  st == 200 and any(
                      e.get("key_version") == 1 and e.get("status") == "active"
                      for e in q.get("events", [])), (st, q))
            # 幂等命中项不追加 DID 历史/生命周期事件
            st, q = _http("GET", f"{BASE}/v1/dids/{pre_did}/history")
            check("幂等命中不追加 DID 历史",
                  st == 200
                  and len([e for e in q.get("events", [])
                           if e.get("action") == "did.created"]) == 1,
                  (st, q))

            # 批内审计按输入顺序追加（含幂等命中项）
            st, q = _http("GET", f"{BASE}/v1/audit?limit=100")
            created = [e for e in q.get("events", [])
                       if e.get("action") == "did.created"]
            check("批内审计按输入顺序",
                  [e["resource_id"] for e in created[-3:]]
                  == [d1, d2, pre_did], created)

            # 凭证签发与验签流程可用
            st, c = _http("POST", f"{BASE}/v1/credentials",
                          {"issuer_did": d1, "subject_did": d2,
                           "claims": {"name": "n"}})
            check("批内 DID 可签发凭证", st == 201, (st, c))
            if st == 201:
                st, got = _http(
                    "GET", f"{BASE}/v1/credentials/{c['credential_id']}")
                st, v = _http(
                    "POST",
                    f"{BASE}/v1/credentials/{c['credential_id']}/verify",
                    {"body": got["body"], "signature": got["signature"]})
                check("批内 DID 凭证可验签",
                      st == 200 and v.get("valid") is True, (st, v))

        # ---------- 单项入口行为不变：与批量共享幂等空间 ----------
        st, r2 = _http("POST", f"{BASE}/v1/dids",
                       {"method": "example", "public_key": "nb-1"})
        check("单项入口幂等命中批内 DID", st == 201 and r2["did"] == d1,
              (st, r2))

        # ---------- 跨租户隔离 ----------
        st, r3 = batch({"items": [{"method": "example", "public_key": "nb-1"}]},
                       headers={"X-Tenant-ID": "other"})
        check("同句柄跨租户各自独立",
              st == 201 and r3["results"][0]["did"] != d1, (st, r3))
        st, q = _http("GET", f"{BASE}/v1/dids/{d1}",
                      headers={"X-Tenant-ID": "other"})
        check("跨租户访问他租户 DID 404", st == 404, (st, q))
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # ---------- 落盘失败：整批回滚，500 恰含 {"error":"存储失败"} ----------
    path = tempfile.mktemp(suffix=".json")
    store = VCStore(path)
    base_rec = store.create_did("t1", "example", "base-h")
    snapshot = {
        "tenants": copy.deepcopy(store._tenants),  # noqa: SLF001
        "audit": copy.deepcopy(store._audit),  # noqa: SLF001
        "audit_seq": store._audit_seq,  # noqa: SLF001
        "key_lifecycle_cursors": copy.deepcopy(  # noqa: SLF001
            store._key_lifecycle_cursors),
        "did_history_cursors": copy.deepcopy(  # noqa: SLF001
            store._did_history_cursors),
    }

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    try:
        store.create_dids_batch("t1", [
            {"method": "example", "public_key": "rb-1"},
            {"method": "example", "public_key": "base-h"},
        ])
        check("落盘失败抛 StorageError", False)
    except StorageError as exc:
        check("落盘失败抛 StorageError", str(exc) == "存储失败", str(exc))
    check("回滚 tenants", store._tenants == snapshot["tenants"])  # noqa: SLF001
    check("回滚 audit", store._audit == snapshot["audit"])  # noqa: SLF001
    check("回滚 audit_seq",
          store._audit_seq == snapshot["audit_seq"])  # noqa: SLF001
    check("回滚密钥生命周期游标",
          store._key_lifecycle_cursors  # noqa: SLF001
          == snapshot["key_lifecycle_cursors"])
    check("回滚 DID 历史游标",
          store._did_history_cursors  # noqa: SLF001
          == snapshot["did_history_cursors"])
    del store._save_locked  # type: ignore[attr-defined]
    res = store.create_dids_batch("t1", [
        {"method": "example", "public_key": "rb-1"},
        {"method": "example", "public_key": "base-h"},
    ])
    check("失败后可重试且幂等命中原 DID",
          len(res) == 2 and res[1].did == base_rec.did
          and res[0].key_version == 1, res)
    if os.path.exists(path):
        os.unlink(path)

    if os.path.exists(STORE):
        os.unlink(STORE)
    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
