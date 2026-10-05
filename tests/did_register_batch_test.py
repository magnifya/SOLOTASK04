#!/usr/bin/env python3
"""DID 整批注册（POST /v1/dids/register-batch）端到端测试。

覆盖：
- 请求体恰含 items（1..100 个对象）；每项恰含必填 method、public_key
  与可选 key_mode（缺省 server）；外层字段缺失/多余、JSON 非对象、
  items 类型或数量不符、项形状或字段非法一律 400 且恰含
  {"error":"请求非法"}，且在任何写入前按输入顺序完成校验（无副作用）；
- 批内句柄重复 409 且恰含 {"error":"批内句柄重复"}；
- 成功 201 仅返 {"results":[...]}，与输入等长同序，每项字段与
  POST /v1/dids 一致（did、public_key、key_mode、key_handle、
  key_version）；新项生成版本一服务端 P-256 密钥，追加 did.created
  审计、DID 历史与密钥生命周期 active 事件；批内审计按输入顺序追加；
- 已登记句柄幂等命中返回既有 DID 并沿用单项审计行为（仍记
  did.created，不追加 DID 历史）；同句柄跨租户各自独立；
- X-Tenant-ID 缺省 default，显式空值 400 且恰含 {"error":"请求非法"}；
- 结果可经现有 DID 文档、密钥轮换/吊销、停用、凭证签发验签与演示
  接口使用；既有单项入口行为不变；
- 落盘失败 500 且恰含 {"error":"存储失败"}，整批 DID、审计与游标
  完全回滚；重启后结论稳定。

直接运行：python3 tests/did_register_batch_test.py
"""

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

PORT = 8973
PORT_BAD = 8974
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"
BASE_BAD = f"http://127.0.0.1:{PORT_BAD}"

DID_RE = re.compile(r"^did:example:[0-9a-f]{32}$")
RESULT_FIELDS = {"did", "public_key", "key_mode", "key_handle", "key_version"}
ERR_INVALID = {"error": "请求非法"}
ERR_DUP = {"error": "批内句柄重复"}
ERR_STORE = {"error": "存储失败"}


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

    def check(name, cond):
        if cond:
            print("PASS:", name)
        else:
            print("FAIL:", name)
            failures.append(name)

    proc = start_server()
    try:
        T = {}
        OT = {"X-Tenant-ID": "other"}

        def batch(items, headers=T, raw=None, base=BASE):
            return _http(
                "POST", f"{base}/v1/dids/register-batch",
                payload={"items": items} if raw is None else None,
                raw=raw, headers=headers,
            )

        def item(handle, **kw):
            obj = {"method": "example", "public_key": handle}
            obj.update(kw)
            return obj

        def audit(headers=T, after=0):
            st, r = _http(
                "GET", f"{BASE}/v1/audit?limit=200&after={after}",
                headers=headers,
            )
            assert st == 200, (st, r)
            return r["events"]

        def did_created_seq():
            return [
                e["resource_id"] for e in audit()
                if e["action"] == "did.created"
            ]

        # ---------------------------------------------------------- #
        # 1. 全新批量注册：201、严格响应形状、顺序与派生状态
        # ---------------------------------------------------------- #
        st, r = batch([item("b-key-1"), item("b-key-2"),
                       item("b-key-3", key_mode="server")])
        check("全新批量 201 且响应恰含 results",
              st == 201 and set(r) == {"results"})
        results = r.get("results", [])
        check("results 与输入等长",
              len(results) == 3)
        check("每项恰含单项入口五字段",
              all(set(x) == RESULT_FIELDS for x in results))
        check("新项 key_mode=server、key_version=1、句柄原样、DID 格式",
              all(x["key_mode"] == "server" and x["key_version"] == 1
                  and DID_RE.match(x["did"]) for x in results)
              and [x["key_handle"] for x in results]
              == ["b-key-1", "b-key-2", "b-key-3"])
        dids = [x["did"] for x in results]
        check("新项 DID 互不相同", len(set(dids)) == 3)
        check("批内 did.created 审计按输入顺序追加",
              did_created_seq() == dids)

        # 派生状态：DID 查询、文档、密钥状态、DID 历史、密钥生命周期
        for did, handle in zip(dids, ["b-key-1", "b-key-2", "b-key-3"]):
            st, got = _http("GET", f"{BASE}/v1/dids/{did}")
            check(f"GET DID 可读 {handle}",
                  st == 200 and got["did"] == did
                  and got["key_handle"] == handle)
            st, doc = _http("GET", f"{BASE}/v1/dids/{did}/document")
            check(f"DID 文档可读 {handle}",
                  st == 200 and doc["current_key_version"] == 1
                  and len(doc["verification_methods"]) == 1
                  and "document_proof" in doc)
            st, ks = _http("GET", f"{BASE}/v1/dids/{did}/keys/1/status")
            check(f"密钥版本 1 active {handle}",
                  st == 200 and ks["status"] == "active")
            st, hist = _http("GET", f"{BASE}/v1/dids/{did}/history")
            check(f"DID 历史恰一条 did.created {handle}",
                  st == 200 and len(hist["events"]) == 1
                  and hist["events"][0]["action"] == "did.created"
                  and hist["events"][0]["status"] == "active")
            st, kh = _http("GET", f"{BASE}/v1/dids/{did}/keys/history")
            check(f"密钥生命周期恰一条 active {handle}",
                  st == 200 and len(kh["events"]) == 1
                  and kh["events"][0]["action"] == "did.created"
                  and kh["events"][0]["status"] == "active")

        # ---------------------------------------------------------- #
        # 2. 幂等命中：已登记句柄返回既有 DID，审计行为同单项
        # ---------------------------------------------------------- #
        st, single = _http(
            "POST", f"{BASE}/v1/dids",
            {"method": "example", "public_key": "pre-existing"},
        )
        assert st == 201, (st, single)
        existing_did = single["did"]
        seq_before = did_created_seq()

        st, r = batch([item("pre-existing"), item("b-key-4")])
        check("幂等命中混合批 201",
              st == 201 and len(r.get("results", [])) == 2)
        check("幂等命中返回既有 DID（字段与单项一致）",
              r["results"][0]["did"] == existing_did
              and r["results"][0]["key_handle"] == "pre-existing"
              and r["results"][0]["key_version"] == 1)
        new_did = r["results"][1]["did"]
        check("幂等命中批审计按序追加（既有 DID 在前）",
              did_created_seq() == seq_before + [existing_did, new_did])
        st, hist = _http("GET", f"{BASE}/v1/dids/{existing_did}/history")
        check("幂等命中不追加 DID 历史",
              st == 200 and len(hist["events"]) == 1)

        # 单项入口对批注册句柄同样幂等
        st, again = _http(
            "POST", f"{BASE}/v1/dids",
            {"method": "example", "public_key": "b-key-1"},
        )
        check("单项入口对批注册句柄幂等返回原 DID",
              st == 201 and again["did"] == dids[0])

        # ---------------------------------------------------------- #
        # 3. 批内句柄重复 409（恰含固定 error，无副作用）
        # ---------------------------------------------------------- #
        seq_before = did_created_seq()
        st, r = batch([item("dup-a"), item("dup-a")])
        check("批内重复 409 恰含固定 error", st == 409 and r == ERR_DUP)
        st, r = batch([item("dup-b"), item("ok-1"), item(" dup-b ")])
        check("批内重复（含去空白后相同）409", st == 409 and r == ERR_DUP)
        st, r = batch([item("pre-existing"), item("pre-existing")])
        check("已登记句柄批内出现两次仍 409", st == 409 and r == ERR_DUP)
        check("409 后无新审计", did_created_seq() == seq_before)
        st, r = _http(
            "POST", f"{BASE}/v1/dids",
            {"method": "example", "public_key": "ok-1"},
        )
        check("409 批中其他句柄未写入", st == 201)

        # ---------------------------------------------------------- #
        # 4. 请求校验：一律 400 且恰含 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        seq_before = did_created_seq()
        bad_raws = [
            ("空体", b""), ("null", b"null"), ("数组", b"[]"),
            ("非法 JSON", b"{oops"), ("字符串", b'"x"'), ("数字", b"1"),
        ]
        for label, raw in bad_raws:
            st, r = batch(None, raw=raw)
            check(f"400 恰含固定 error: {label}", st == 400 and r == ERR_INVALID)

        bad_payloads = [
            ("缺 items", {}),
            ("多余外层字段", {"items": [item("x1")], "extra": 1}),
            ("items 非数组", {"items": {"a": 1}}),
            ("items 非数组字符串", {"items": "x"}),
            ("items 空数组", {"items": []}),
            ("items 超 100", {"items": [item(f"ov-{i}") for i in range(101)]}),
            ("项非对象", {"items": ["x"]}),
            ("项为 null", {"items": [None]}),
            ("项缺 method", {"items": [{"public_key": "x2"}]}),
            ("项缺 public_key", {"items": [{"method": "example"}]}),
            ("项多余字段", {"items": [item("x3", foo=1)]}),
            ("method 空串", {"items": [item("x4", method="")]}),
            ("method 非字符串", {"items": [item("x5", method=1)]}),
            ("method 大写", {"items": [item("x6", method="Example")]}),
            ("method 数字开头", {"items": [item("x7", method="1abc")]}),
            ("public_key 空串", {"items": [item("")]}),
            ("public_key 空白", {"items": [item("   ")]}),
            ("public_key 非字符串", {"items": [item(123)]}),
            ("public_key 为 PEM",
             {"items": [item("-----BEGIN PUBLIC KEY-----abc")]}),
            ("key_mode 非 server", {"items": [item("x8", key_mode="local")]}),
            ("key_mode 非字符串", {"items": [item("x9", key_mode=1)]}),
            ("key_mode null", {"items": [item("x10", key_mode=None)]}),
        ]
        for label, payload in bad_payloads:
            st, r = _http(
                "POST", f"{BASE}/v1/dids/register-batch", payload,
            )
            check(f"400 恰含固定 error: {label}", st == 400 and r == ERR_INVALID)

        check("全部 400 后无新审计", did_created_seq() == seq_before)
        for handle in ("x1", "x3", "x8"):
            st, _ = _http(
                "POST", f"{BASE}/v1/dids",
                {"method": "example", "public_key": handle},
            )
            check(f"400 批中句柄未写入: {handle}", st == 201)

        # 显式空 X-Tenant-ID → 400 恰含固定 error
        st, r = batch([item("t-empty")], headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400 恰含固定 error",
              st == 400 and r == ERR_INVALID)

        # ---------------------------------------------------------- #
        # 5. 租户隔离与默认租户
        # ---------------------------------------------------------- #
        st, r = batch([item("shared-handle")], headers=OT)
        check("他租户同句柄独立注册 201",
              st == 201 and r["results"][0]["key_handle"] == "shared-handle")
        other_did = r["results"][0]["did"]
        st, r = batch([item("shared-handle")])
        check("默认租户同句柄独立注册 201",
              st == 201 and r["results"][0]["did"] != other_did)
        default_shared = r["results"][0]["did"]
        st, _ = _http("GET", f"{BASE}/v1/dids/{default_shared}", headers=OT)
        check("跨租户查询按不存在 404", st == 404)
        st, r = _http(
            "GET", f"{BASE}/v1/audit?limit=200&after=0", headers=OT)
        check("他租户审计不含默认租户 did.created",
              st == 200 and all(
                  e["resource_id"] != default_shared for e in r["events"]))
        check("默认租户审计 tenant_id=default",
              all(e["tenant_id"] == "default" for e in audit()))

        # ---------------------------------------------------------- #
        # 6. 结果沿用现有流程：轮换、吊销、签发、验签、演示、停用
        # ---------------------------------------------------------- #
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{dids[0]}/keys/rotate",
            {"key_handle": "b-key-1-v2"},
        )
        check("批注册 DID 可轮换密钥", st == 200)
        st, r = _http(
            "POST", f"{BASE}/v1/dids/{dids[0]}/keys/1/revoke", {},
        )
        check("批注册 DID 旧密钥可吊销", st == 200)

        st, issued = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": dids[1], "subject_did": dids[2],
             "claims": {"age": 21}},
        )
        check("批注册 DID 可签发凭证", st == 201)
        cid = issued["credential_id"]
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}")
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": got["body"], "signature": got["signature"]},
        )
        check("批注册 DID 签发凭证可验签",
              st == 200 and r.get("valid") is True)
        st, vp = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"disclose": ["/age"], "challenge": "c1", "expires_in": 300},
        )
        check("批注册 DID 凭证可生成演示", st == 201)
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{vp['presentation_id']}/verify",
            {"presentation": vp, "challenge": "c1"},
        )
        check("演示可验签", st == 200 and r.get("valid") is True)

        st, r = _http("POST", f"{BASE}/v1/dids/{dids[2]}/deactivate", {})
        check("批注册 DID 可停用", st == 200)
        st, r = _http("GET", f"{BASE}/v1/dids/{dids[2]}/status")
        check("停用状态可读", st == 200 and r["status"] == "deactivated")

        # ---------------------------------------------------------- #
        # 7. 重启持久化
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, got = _http("GET", f"{BASE}/v1/dids/{dids[0]}")
        check("重启后批注册 DID 可读", st == 200 and got["did"] == dids[0])
        st, r = batch([item("b-key-4")])
        check("重启后幂等命中返回原 DID",
              st == 201 and r["results"][0]["did"] == new_did)
        st, got = _http("GET", f"{BASE}/v1/credentials/{cid}")
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cid}/verify",
            {"body": got["body"], "signature": got["signature"]},
        )
        check("重启后凭证验签仍有效", st == 200 and r.get("valid") is True)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 8. 落盘失败：HTTP 500 恰含固定 error，整批回滚
    # -------------------------------------------------------------- #
    # 构造“路径父级为普通文件”的存储路径，使 _save_locked 的
    # makedirs 抛 OSError（与权限无关，root 下同样失败）。
    blocker = tempfile.mktemp(suffix=".json")
    with open(blocker, "w", encoding="utf-8") as fh:
        fh.write("{}")
    bad_store = os.path.join(blocker, "nested", "state.json")
    proc_bad = start_server(store=bad_store, port=PORT_BAD)
    try:
        st, r = _http(
            "POST", f"{BASE_BAD}/v1/dids/register-batch",
            {"items": [{"method": "example", "public_key": "fail-1"},
                       {"method": "example", "public_key": "fail-2"}]},
        )
        check("落盘失败 500 恰含固定 error", st == 500 and r == ERR_STORE)
        st, r = _http("GET", f"{BASE_BAD}/v1/audit?limit=200&after=0")
        check("落盘失败不记任何审计",
              st == 200 and r["events"] == [])
        # 整批回滚：同句柄在存储修复前重试仍失败，但内存态无残留
        st, r = _http(
            "GET", f"{BASE_BAD}/v1/dids/did:example:{'0' * 32}",
        )
        check("失败批无可探测残留", st == 404)
    finally:
        proc_bad.terminate()
        proc_bad.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 9. 直接存储层：失败回滚 DID/审计/游标，恢复后可重试
    # -------------------------------------------------------------- #
    from vcbackend.store import StorageError, VCStore  # noqa: E402

    p1 = tempfile.mktemp(suffix=".json")
    s1 = VCStore(p1)
    ok1 = s1.create_did("t", "example", "store-pre")

    def _boom():
        raise OSError("模拟落盘失败")

    s1._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        s1.create_dids_batch(
            "t",
            [{"method": "example", "public_key": "store-pre"},
             {"method": "example", "public_key": "store-new-1"},
             {"method": "example", "public_key": "store-new-2"}],
        )
    except StorageError:
        raised = True
    check("落盘失败 create_dids_batch 抛 StorageError", raised)
    check("回滚后无新 DID",
          s1._find_did_by_handle_locked(  # noqa: SLF001
              s1._bucket_locked("t"), "store-new-1") is None
          and s1._find_did_by_handle_locked(  # noqa: SLF001
              s1._bucket_locked("t"), "store-new-2") is None)
    check("回滚后审计不增长（含幂等命中项）",
          [e.resource_id for e in s1.list_audit("t", 0, 200)[0]
           if e.action == "did.created"] == [ok1.did])
    check("回滚后既有 DID 历史不变",
          len(s1.list_did_history("t", ok1.did, 0, 50)[0]) == 1)

    del s1._save_locked  # type: ignore[attr-defined]
    recs = s1.create_dids_batch(
        "t",
        [{"method": "example", "public_key": "store-pre"},
         {"method": "example", "public_key": "store-new-1"}],
    )
    check("恢复后重试成功且幂等命中返回既有 DID",
          len(recs) == 2 and recs[0].did == ok1.did
          and recs[1].key_handle == "store-new-1")
    s1b = VCStore(p1)
    check("重载后批注册 DID 稳定",
          s1b.get_did("t", recs[1].did).did == recs[1].did)

    # 存储层校验：批内重复抛 ConflictError、非法项抛 ValidationError
    from vcbackend.store import ConflictError, ValidationError  # noqa: E402

    p2 = tempfile.mktemp(suffix=".json")
    s2 = VCStore(p2)
    for fn, exc in (
        (lambda: s2.create_dids_batch(
            "t", [{"method": "example", "public_key": "d"},
                  {"method": "example", "public_key": " d "}]),
         ConflictError),
        (lambda: s2.create_dids_batch("t", [{"method": "Bad"}]), ValidationError),
        (lambda: s2.create_dids_batch("t", ["x"]), ValidationError),
        (lambda: s2.create_dids_batch(
            "t", [{"method": "example", "public_key": "h",
                   "key_mode": "local"}]), ValidationError),
    ):
        try:
            fn()
            check(f"存储层校验抛 {exc.__name__}", False)
        except exc:
            check(f"存储层校验抛 {exc.__name__}", True)
    check("存储层校验失败无副作用",
          s2.list_audit("t", 0, 200)[0] == [])

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
