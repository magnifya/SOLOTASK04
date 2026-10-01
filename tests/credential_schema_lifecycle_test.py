#!/usr/bin/env python3
"""凭证模式版本生命周期（status/history）能力的端到端测试。

覆盖：
- POST /v1/credential-schemas/{schema_id}/{version}/status：请求体校验
  （缺字段/多余字段/status 取值/reason 非空）400；路径非法 400；未知
  版本/未知 issuer/跨租户 404；首次 deprecated/revoked 201（缺省 reason
  固定）；同状态同 reason 幂等 200 且不追加历史/审计；同状态 reason
  变化、逆向恢复、越级转换 409；deprecated 可进 revoked；
- GET .../status：active 返 active/null/null，终态返首次原因与时间；
  参数非法 400，未知/跨租户 404；
- GET .../history：注册事件 reason 为 null，事件七字段与键序，游标租户
  内跨版本共享递增、与 DID 历史游标空间独立，limit/after/next_after
  分页语义，未知参数 400，未知/跨租户 404；幂等与失败不追加；
- POST /v1/credentials：显式引用 deprecated/revoked 版本不签发、不写
  入、不审计，统一 409/{"error":"credential schema unavailable"}（且
  门禁先于 claims 校验）；未引用或引用 active 版本行为不变；历史凭证
  验签结论不受后续弃用/吊销影响；
- 审计动作 credential.schema.deprecated/revoked 仅首次变更记录；
- 跨重启状态与历史持久化；旧状态文件（无历史/游标）加载补录稳定。

直接运行：python3 tests/credential_schema_lifecycle_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

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

# 统一以 --port 0 让内核分配空闲端口，并解析服务自身输出的
# VCBACKEND_READY 行取得实际端口：既不与其他测试/残留进程碰撞，也避免
# 仅凭 /health 误连到占用同端口的旧进程。BASE 由 start_server 回填。
BASE = "http://127.0.0.1:0"
DEFAULT_DEPRECATE = "模式版本已弃用"
DEFAULT_REVOKE = "模式版本已吊销"
UNAVAILABLE = {"error": "credential schema unavailable"}

# 所有已启动服务进程（含异常退出路径），测试结束统一回收。
_PROCS = []


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


def _wait_health(base, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"{base}/health")
            return True
        except OSError:
            time.sleep(0.1)
    return False


def start_server(env):
    """启动服务（端口 0 自动分配），返回 Popen，并回填全局 BASE。

    通过读取服务自身的 VCBACKEND_READY 行确定实际端口，确保后续请求
    一定打到本次启动的进程，而非占用固定端口的残留服务。
    """
    global BASE
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", "0", "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    _PROCS.append(proc)
    base = None
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError("服务进程提前退出")
            time.sleep(0.05)
            continue
        if line.startswith("VCBACKEND_READY"):
            match = re.search(r"port=(\d+)", line)
            if match:
                base = f"http://127.0.0.1:{match.group(1)}"
                break
    if base is None:
        raise RuntimeError("未取得服务实际端口")
    if not _wait_health(base):
        raise RuntimeError("服务启动超时")
    BASE = base
    return proc


def _cleanup_procs():
    for proc in _PROCS:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def main():
    atexit.register(_cleanup_procs)
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    T = {"X-Tenant-ID": "life-a"}
    T2 = {"X-Tenant-ID": "life-b"}

    proc = start_server(env)
    try:
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-life"},
                      headers=T)
        assert st == 201, (st, r)
        issuer = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "subject-life"},
                      headers=T)
        assert st == 201, (st, r)
        subject = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-life-b"},
                      headers=T2)
        assert st == 201, (st, r)
        issuer_b = r["did"]

        claims_types = {"/name": "string", "/age": "integer"}
        required = ["/name", "/age"]
        good_claims = {"name": "Alice", "age": 30}

        def register(version):
            return _http(
                "POST", f"{BASE}/v1/credential-schemas",
                {"schema_id": "life_doc", "version": version,
                 "issuer_did": issuer, "claim_types": claims_types,
                 "required_claims": required},
                headers=T)

        for ver in (1, 2, 3):
            st, r = register(ver)
            assert st == 201, (ver, st, r)

        status_url = (
            f"{BASE}/v1/credential-schemas/life_doc/{{ver}}/status"
        )
        status_get = (
            f"{BASE}/v1/credential-schemas/life_doc/{{ver}}/status"
            f"?issuer_did={issuer}"
        )
        history_url = (
            f"{BASE}/v1/credential-schemas/life_doc/{{ver}}/history"
            f"?issuer_did={issuer}"
        )
        audit_url = f"{BASE}/v1/audit?limit=200"

        def audit_events():
            st, r = _http("GET", audit_url, headers=T)
            assert st == 200, (st, r)
            return r["events"]

        # -------------------------------------------------------------- #
        # 1. POST status：格式错误 -> 400
        # -------------------------------------------------------------- #
        n_before = len(audit_events())
        bad_bodies = [
            ("缺 status", {"issuer_did": issuer}),
            ("缺 issuer_did", {"status": "deprecated"}),
            ("多余字段",
             {"issuer_did": issuer, "status": "deprecated", "x": 1}),
            ("status=active",
             {"issuer_did": issuer, "status": "active"}),
            ("status 非法值",
             {"issuer_did": issuer, "status": "DEPRECATED"}),
            ("status 非字符串",
             {"issuer_did": issuer, "status": 1}),
            ("reason 空串",
             {"issuer_did": issuer, "status": "deprecated", "reason": ""}),
            ("reason 纯空白",
             {"issuer_did": issuer, "status": "deprecated", "reason": "   "}),
            ("reason 为 null",
             {"issuer_did": issuer, "status": "deprecated", "reason": None}),
            ("reason 非字符串",
             {"issuer_did": issuer, "status": "deprecated", "reason": 1}),
            ("issuer_did 为空",
             {"issuer_did": "", "status": "deprecated"}),
            ("issuer_did 非字符串",
             {"issuer_did": 1, "status": "deprecated"}),
        ]
        for label, body in bad_bodies:
            st, r = _http("POST", status_url.format(ver=1), body, headers=T)
            check(f"非法状态请求（{label}）-> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        for path_label, path in [
            ("schema_id 非法",
             "/v1/credential-schemas/BAD/1/status"),
            ("version 为 0",
             "/v1/credential-schemas/life_doc/0/status"),
            ("version 非数字",
             "/v1/credential-schemas/life_doc/x/status"),
            ("段数不足",
             "/v1/credential-schemas/life_doc/status"),
            ("段数过多",
             "/v1/credential-schemas/life_doc/1/2/status"),
        ]:
            st, r = _http(
                "POST", f"{BASE}{path}",
                {"issuer_did": issuer, "status": "deprecated"}, headers=T)
            check(f"非法状态路径（{path_label}）-> 400", st == 400)

        # 非 JSON 对象 / 非法 JSON -> 400
        st, r = _http("POST", status_url.format(ver=1), ["deprecated"],
                      headers=T)
        check("status 请求体非对象 -> 400", st == 400)
        check("400 不写审计", len(audit_events()) == n_before)

        # -------------------------------------------------------------- #
        # 2. POST status：未知/跨租户 -> 404
        # -------------------------------------------------------------- #
        st, r = _http(
            "POST",
            f"{BASE}/v1/credential-schemas/life_doc/9/status",
            {"issuer_did": issuer, "status": "deprecated"}, headers=T)
        check("未知版本 -> 404", st == 404)
        st, r = _http(
            "POST",
            f"{BASE}/v1/credential-schemas/missing/1/status",
            {"issuer_did": issuer, "status": "deprecated"}, headers=T)
        check("未知 schema -> 404", st == 404)
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": "did:x:ghost", "status": "deprecated"}, headers=T)
        check("未知 issuer -> 404", st == 404)
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer_b, "status": "deprecated"}, headers=T2)
        check("跨租户访问 -> 404", st == 404)
        check("404 不写审计", len(audit_events()) == n_before)

        # -------------------------------------------------------------- #
        # 3. 首次弃用 201、幂等 200、reason 冲突 409
        # -------------------------------------------------------------- #
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "deprecated"}, headers=T)
        check("首次弃用 -> 201", st == 201)
        check("弃用响应六字段与键序",
              list(r) == ["schema_id", "version", "issuer_did",
                          "status", "reason", "updated_at"])
        check("弃用缺省 reason 固定", r["reason"] == DEFAULT_DEPRECATE)
        check("回显定位字段",
              r["schema_id"] == "life_doc" and r["version"] == 1
              and r["issuer_did"] == issuer and r["status"] == "deprecated")
        updated_at_dep = r["updated_at"]
        check("updated_at 为 UTC 秒精度 Z",
              isinstance(updated_at_dep, str)
              and updated_at_dep.endswith("Z") and len(updated_at_dep) == 20)

        # 不带 reason 重放（仍解析为缺省值）-> 幂等 200
        st, r2 = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "deprecated"}, headers=T)
        check("同状态缺省 reason 重放 -> 200",
              st == 200 and r2["reason"] == DEFAULT_DEPRECATE
              and r2["updated_at"] == updated_at_dep)
        # 显式相同缺省文本 -> 200
        st, r2 = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "deprecated",
             "reason": DEFAULT_DEPRECATE}, headers=T)
        check("同状态显式同 reason -> 200", st == 200)
        # 裁剪后相等也算相同
        st, r2 = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "deprecated",
             "reason": f"  {DEFAULT_DEPRECATE}  "}, headers=T)
        check("裁剪后相同 reason -> 200", st == 200)
        # 不同 reason -> 409
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "deprecated",
             "reason": "别的原因"}, headers=T)
        check("deprecated 同状态换 reason -> 409", st == 409)
        # 逆向恢复 -> 409
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "active"}, headers=T)
        check("deprecated -> active -> 400（status 不接受 active）",
              st == 400)
        # 幂等不追加历史：弃用后历史恰 2 条（注册 + 弃用）
        st, r = _http("GET", history_url.format(ver=1), headers=T)
        assert st == 200
        check("幂等重放不追加历史", len(r["events"]) == 2)

        dep_events = [
            e for e in audit_events()
            if e["action"] == "credential.schema.deprecated"
            and e["resource_id"] == f"{issuer}:life_doc:1"
        ]
        check("首次弃用记一次审计", len(dep_events) == 1)
        check("弃用审计 resource_type",
              dep_events[0]["resource_type"] == "credential_schema")

        # -------------------------------------------------------------- #
        # 4. revoked：active 直达、幂等、冲突
        # -------------------------------------------------------------- #
        st, r = _http(
            "POST", status_url.format(ver=2),
            {"issuer_did": issuer, "status": "revoked",
             "reason": "  v2 严重问题  "}, headers=T)
        check("active -> revoked（自定义 reason）-> 201",
              st == 201 and r["reason"] == "v2 严重问题")
        rev2_at = r["updated_at"]
        st, r = _http(
            "POST", status_url.format(ver=2),
            {"issuer_did": issuer, "status": "revoked",
             "reason": "v2 严重问题"}, headers=T)
        check("revoked 同 reason 重放 -> 200",
              st == 200 and r["updated_at"] == rev2_at)
        st, r = _http(
            "POST", status_url.format(ver=2),
            {"issuer_did": issuer, "status": "revoked",
             "reason": "另一个原因"}, headers=T)
        check("revoked 换 reason -> 409", st == 409)
        st, r = _http(
            "POST", status_url.format(ver=2),
            {"issuer_did": issuer, "status": "deprecated"}, headers=T)
        check("revoked -> deprecated 越级 -> 409", st == 409)

        # v3 缺省 reason 吊销
        st, r = _http(
            "POST", status_url.format(ver=3),
            {"issuer_did": issuer, "status": "revoked"}, headers=T)
        check("revoked 缺省 reason 固定",
              st == 201 and r["reason"] == DEFAULT_REVOKE)

        # deprecated -> revoked 合法（v1）
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "revoked",
             "reason": "最终吊销"}, headers=T)
        check("deprecated -> revoked -> 201",
              st == 201 and r["status"] == "revoked"
              and r["reason"] == "最终吊销")
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "revoked",
             "reason": "最终吊销"}, headers=T)
        check("终态重放 -> 200", st == 200)
        # 终态再改原因仍 409
        st, r = _http(
            "POST", status_url.format(ver=1),
            {"issuer_did": issuer, "status": "revoked",
             "reason": "x"}, headers=T)
        check("终态改原因 -> 409", st == 409)

        # -------------------------------------------------------------- #
        # 5. GET status
        # -------------------------------------------------------------- #
        st, r = _http("GET", status_get.format(ver=1), headers=T)
        check("GET v1 revoked",
              st == 200 and r["status"] == "revoked"
              and r["reason"] == "最终吊销")
        # 重新注册一个 active 版本用于 active 视图
        st, _ = register(4)
        assert st == 201
        st, r = _http("GET", status_get.format(ver=4), headers=T)
        check("GET active 状态",
              st == 200 and list(r) == ["schema_id", "version",
                                        "issuer_did", "status",
                                        "reason", "updated_at"]
              and r["status"] == "active" and r["reason"] is None
              and r["updated_at"] is None)
        st, r = _http("GET", status_get.format(ver=9), headers=T)
        check("GET status 未知版本 -> 404", st == 404)
        st, r = _http("GET", status_get.format(ver=1), headers=T2)
        check("GET status 跨租户 -> 404", st == 404)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/status",
            headers=T)
        check("GET status 缺 issuer_did -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/status"
            f"?issuer_did={issuer}&issuer_did={issuer}",
            headers=T)
        check("GET status issuer_did 重复 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/status"
            f"?issuer_did={issuer}&limit=1",
            headers=T)
        check("GET status 未知参数 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/BAD/1/status"
            f"?issuer_did={issuer}",
            headers=T)
        check("GET status 路径非法 -> 400", st == 400)

        # -------------------------------------------------------------- #
        # 6. GET history
        # -------------------------------------------------------------- #
        st, r = _http("GET", history_url.format(ver=1), headers=T)
        check("history 200 且 3 条事件",
              st == 200 and len(r["events"]) == 3)
        check("history 顶层键序",
              list(r) == ["schema_id", "version", "issuer_did",
                          "events", "next_after"])
        reg, dep, rev = r["events"]
        check("注册事件字段",
              reg["action"] == "credential.schema.registered"
              and reg["status"] == "active" and reg["reason"] is None
              and isinstance(reg["updated_at"], str)
              and isinstance(reg["audit_seq"], int)
              and isinstance(reg["audit_timestamp"], int))
        check("事件七字段与键序",
              list(reg) == ["action", "status", "reason", "updated_at",
                            "audit_seq", "audit_timestamp", "cursor"])
        check("弃用事件字段",
              dep["action"] == "credential.schema.deprecated"
              and dep["status"] == "deprecated"
              and dep["reason"] == DEFAULT_DEPRECATE)
        check("吊销事件字段",
              rev["action"] == "credential.schema.revoked"
              and rev["status"] == "revoked"
              and rev["reason"] == "最终吊销")
        cursors = [reg["cursor"], dep["cursor"], rev["cursor"]]
        check("cursor 严格递增",
              cursors[0] < cursors[1] < cursors[2])
        check("next_after 为末项 cursor",
              r["next_after"] == cursors[-1])

        # 游标租户内跨版本共享：v2 先于 v1 弃用前注册，其注册事件
        # cursor 恰为 v1 注册 cursor + 1（同一租户无其他模式历史插入）。
        st, r2 = _http("GET", history_url.format(ver=2), headers=T)
        v2_cursors = [e["cursor"] for e in r2["events"]]
        check("跨版本共享游标空间",
              len(v2_cursors) == 2
              and v2_cursors[0] == cursors[0] + 1
              and v2_cursors[1] > v2_cursors[0])
        check("v2 history 2 条（注册+吊销）", len(r2["events"]) == 2)

        # 与 DID 历史游标空间独立：DID 注册事件 cursor 与模式注册事件
        # cursor 可同为小整数（各自从 1 起）。
        st, did_hist = _http(
            "GET", f"{BASE}/v1/dids/{issuer}/history", headers=T)
        check("模式历史与 DID 历史游标空间独立",
              st == 200
              and did_hist["events"][0]["cursor"] == reg["cursor"] == 1)

        # 分页 limit/after
        st, page1 = _http(
            "GET",
            f"{history_url.format(ver=1)}&limit=1", headers=T)
        check("limit=1 仅 1 条",
              st == 200 and len(page1["events"]) == 1
              and page1["events"][0]["cursor"] == cursors[0]
              and page1["next_after"] == cursors[0])
        st, page2 = _http(
            "GET",
            f"{history_url.format(ver=1)}&limit=1&after={cursors[0]}",
            headers=T)
        check("after 翻页到第 2 条",
              len(page2["events"]) == 1
              and page2["events"][0]["cursor"] == cursors[1]
              and page2["next_after"] == cursors[1])
        st, page_empty = _http(
            "GET",
            f"{history_url.format(ver=1)}&after={cursors[2]}",
            headers=T)
        check("空页 next_after 保持 after",
              page_empty["events"] == []
              and page_empty["next_after"] == cursors[2])
        for label, query in [
            ("limit=0", "limit=0"),
            ("limit=201", "limit=201"),
            ("limit 非数字", "limit=x"),
            ("limit 重复", "limit=1&limit=2"),
            ("after 负数", "after=-1"),
            ("after 非数字", "after=x"),
            ("未知参数", "after=0&foo=1"),
        ]:
            st, _ = _http(
                "GET", f"{history_url.format(ver=1)}&{query}", headers=T)
            check(f"history 参数非法（{label}）-> 400", st == 400)
        st, _ = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/9/history"
            f"?issuer_did={issuer}", headers=T)
        check("history 未知版本 -> 404", st == 404)
        st, _ = _http("GET", history_url.format(ver=1), headers=T2)
        check("history 跨租户 -> 404", st == 404)

        # -------------------------------------------------------------- #
        # 7. 签发门禁
        # -------------------------------------------------------------- #
        def issue(ver, claims=good_claims, sid="life_doc"):
            payload = {
                "issuer_did": issuer,
                "subject_did": subject,
                "claims": claims,
            }
            if sid is not None:
                payload["schema_id"] = sid
            if ver is not None:
                payload["schema_version"] = ver
            return _http("POST", f"{BASE}/v1/credentials", payload,
                         headers=T)

        # v4 active：在弃用前签发一张历史凭证
        st, r = issue(4)
        check("active 版本签发 -> 201", st == 201)
        historical_cid = r["credential_id"]
        issued_count_before = len([
            e for e in audit_events()
            if e["action"] == "credential.issued"
        ])

        # v1/v2/v3 已终态 -> 统一 409 固定原因
        for ver in (1, 2, 3):
            st, r = issue(ver)
            check(f"引用 revoked/deprecated v{ver} -> 409 固定原因",
                  st == 409 and r == UNAVAILABLE)
        # 门禁先于 claims 校验：缺必填仍 409 固定原因
        st, r = issue(1, claims={"name": "A"})
        check("终态版本 claims 不符仍 409 固定原因",
              st == 409 and r == UNAVAILABLE)
        # 未引用版本：照常签发
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject,
             "claims": {"anything": 1}}, headers=T)
        check("未引用版本签发不受影响 -> 201", st == 201)
        # 拒绝签发不写审计
        check("拒绝签发不记 credential.issued",
              len([e for e in audit_events()
                   if e["action"] == "credential.issued"])
              == issued_count_before + 1)

        # 历史凭证结论不受后续生命周期影响（v4 此刻仍 active；
        # 把 v4 也弃用后再验）
        st, r = _http(
            "POST", status_url.format(ver=4),
            {"issuer_did": issuer, "status": "deprecated"}, headers=T)
        assert st == 201, (st, r)
        st, got = _http(
            "GET", f"{BASE}/v1/credentials/{historical_cid}", headers=T)
        assert st == 200
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{historical_cid}/verify",
            {"body": got["body"], "signature": got["signature"]}, headers=T)
        check("弃用后历史凭证 verify 仍 valid:true",
              st == 200 and r == {"valid": True})
        st, r = issue(4)
        check("v4 弃用后新签发 -> 409", st == 409 and r == UNAVAILABLE)

        # 审计动作汇总：deprecated v1,v4；revoked v1,v2,v3；幂等不计
        dep_all = [e for e in audit_events()
                   if e["action"] == "credential.schema.deprecated"]
        rev_all = [e for e in audit_events()
                   if e["action"] == "credential.schema.revoked"]
        check("弃用审计恰 2 条", len(dep_all) == 2)
        check("吊销审计恰 3 条", len(rev_all) == 3)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 8. 跨重启：状态/历史持久化（issuer 直接沿用运行期变量；不能用
    # 状态文件 dids 的首键——落盘按 DID 字符串排序，首键可能是 subject）
    # -------------------------------------------------------------- #
    proc = start_server(env)
    try:
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/status"
            f"?issuer_did={issuer}", headers=T)
        check("重启后终态保持",
              st == 200 and r.get("status") == "revoked"
              and r.get("reason") == "最终吊销")
        st, before = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/history"
            f"?issuer_did={issuer}&limit=200", headers=T)
        assert st == 200
        check("重启后历史 3 条", len(before["events"]) == 3)
        cursors_before = [e["cursor"] for e in before["events"]]

        # 幂等重放跨重启仍 200，不追加
        st, r = _http(
            "POST",
            f"{BASE}/v1/credential-schemas/life_doc/1/status",
            {"issuer_did": issuer, "status": "revoked",
             "reason": "最终吊销"}, headers=T)
        check("跨重启终态重放 -> 200", st == 200)
        st, after = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/history"
            f"?issuer_did={issuer}&limit=200", headers=T)
        check("跨重启重放不追加历史",
              [e["cursor"] for e in after["events"]] == cursors_before)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 9. 旧状态文件迁移：手工删除历史与游标后重启，补录且 cursor 稳定
    # -------------------------------------------------------------- #
    raw = json.load(open(store_path, encoding="utf-8"))
    bucket = raw["tenants"]["life-a"]
    # v4 行为 deprecated，v1 为 revoked：删除全部模式历史与游标，
    # 模拟从未写过生命周期历史的旧版本文件。
    bucket["credential_schema_history"] = {}
    raw.pop("credential_schema_history_cursors", None)
    with open(store_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, ensure_ascii=False)

    proc = start_server(env)
    try:
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/4/history"
            f"?issuer_did={issuer}&limit=200", headers=T)
        check("旧文件补录 active 注册事件",
              st == 200 and len(r["events"]) == 2
              and r["events"][0]["action"]
              == "credential.schema.registered"
              and r["events"][0]["status"] == "active"
              and r["events"][0]["reason"] is None
              and r["events"][0]["audit_seq"] is None
              and r["events"][0]["audit_timestamp"] is None
              and r["events"][1]["action"]
              == "credential.schema.deprecated")
        st, r1 = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/history"
            f"?issuer_did={issuer}&limit=200", headers=T)
        assert st == 200
        check("旧文件 v1 补录注册+吊销 2 条",
              len(r1["events"]) == 2
              and [e["action"] for e in r1["events"]]
              == ["credential.schema.registered",
                  "credential.schema.revoked"])
        cursors_m1 = [e["cursor"] for e in r1["events"]]
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 再重启一次：无写操作时补录 cursor 稳定
    proc = start_server(env)
    try:
        st, r2 = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/life_doc/1/history"
            f"?issuer_did={issuer}&limit=200", headers=T)
        check("补录 cursor 跨重启稳定",
              [e["cursor"] for e in r2["events"]] == cursors_m1)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

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
