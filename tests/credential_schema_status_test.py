#!/usr/bin/env python3
"""凭证模式版本生命周期（deprecated/revoked）能力的端到端测试。

覆盖：
- POST /v1/credential-schemas/{schema_id}/{version}/status：
  状态机（deprecated 仅 active 可入，revoked 可自 active/deprecated，
  均不能恢复）；reason 缺省固定值与显式非空校验；首次 201、同状态
  同 reason 幂等 200（不追加历史、不记审计）；reason 变化/逆向/越级
  409；格式错误 400；未知版本与跨租户 404；响应六字段键序；
- GET .../status?issuer_did=...：当前状态（active 注册即更新
  updated_at），参数规则与 404；
- GET .../history?issuer_did=&limit=&after=：注册事件 reason 为
  null，事件七字段，游标分页与 next_after 语义，参数 400；
- POST /v1/credentials：显式引用 deprecated/revoked 版本统一 409
  {"error":"credential schema unavailable"} 且不签发不审计；active
  版本与不引用版本行为不变；历史凭证 verify 结论不受弃用/吊销影响；
- 审计：credential.schema.deprecated / credential.schema.revoked
  仅在首次变更落审计，失败与幂等重试不留审计；
- 租户隔离与跨重启持久化（状态、历史、游标稳定）。

直接运行：python3 tests/credential_schema_status_test.py
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PORT = 8997
BASE = f"http://127.0.0.1:{PORT}"
UNAVAILABLE = "credential schema unavailable"


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


def wait_up(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"{BASE}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


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

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    T = {"X-Tenant-ID": "schema-lc-a"}
    T2 = {"X-Tenant-ID": "schema-lc-b"}
    issuer_did = {"v": None}
    subject_did = {"v": None}

    def serve():
        return subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(PORT), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    try:
        assert wait_up(), "服务启动超时"

        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-lc"},
                      headers=T)
        assert st == 201, (st, r)
        issuer = r["did"]
        issuer_did["v"] = issuer
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "subject-lc"},
                      headers=T)
        assert st == 201, (st, r)
        subject = r["did"]
        subject_did["v"] = subject
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-lc-b"},
                      headers=T2)
        assert st == 201, (st, r)
        issuer_b = r["did"]

        schema = {
            "schema_id": "kyc_lc",
            "version": 1,
            "issuer_did": issuer,
            "claim_types": {"/name": "string", "/age": "integer"},
            "required_claims": ["/name"],
        }
        st, r = _http("POST", f"{BASE}/v1/credential-schemas", schema,
                      headers=T)
        assert st == 201, (st, r)
        st, r = _http("POST", f"{BASE}/v1/credential-schemas",
                      dict(schema, version=2), headers=T)
        assert st == 201, (st, r)

        audit_url = f"{BASE}/v1/audit?limit=200"

        def status_url(sid="kyc_lc", ver=1):
            return f"{BASE}/v1/credential-schemas/{sid}/{ver}/status"

        def get_status(sid="kyc_lc", ver=1, iss=issuer, headers=T,
                       extra=""):
            return _http(
                "GET",
                f"{BASE}/v1/credential-schemas/{sid}/{ver}/status"
                f"?issuer_did={iss}{extra}",
                headers=headers)

        def post_status(payload, sid="kyc_lc", ver=1, headers=T, raw=None):
            return _http("POST", status_url(sid, ver), payload,
                         headers=headers, raw=raw)

        def get_history(sid="kyc_lc", ver=1, iss=issuer, headers=T,
                        extra=""):
            return _http(
                "GET",
                f"{BASE}/v1/credential-schemas/{sid}/{ver}/history"
                f"?issuer_did={iss}{extra}",
                headers=headers)

        def audit_events(action):
            st, ev = _http("GET", audit_url, headers=T)
            assert st == 200
            return [e for e in ev["events"] if e["action"] == action]

        # -------------------------------------------------------------- #
        # 1. 注册即 active：GET status 与注册事件
        # -------------------------------------------------------------- #
        st, r = get_status()
        check("注册后 GET status -> 200 active", st == 200
              and r["status"] == "active")
        check("status 响应六字段键序",
              list(r) == ["schema_id", "version", "issuer_did",
                          "status", "reason", "updated_at"])
        check("active reason 为 null", r["reason"] is None)
        check("active updated_at 为注册时间",
              isinstance(r["updated_at"], str)
              and r["updated_at"].endswith("Z"))
        check("status 响应回显标识",
              r["schema_id"] == "kyc_lc" and r["version"] == 1
              and r["issuer_did"] == issuer)

        st, r = get_history()
        check("注册后历史 -> 200 单事件", st == 200
              and len(r["events"]) == 1)
        check("历史响应键序",
              list(r) == ["schema_id", "version", "issuer_did",
                          "events", "next_after"])
        ev0 = r["events"][0]
        check("注册事件七字段键序",
              list(ev0) == ["action", "status", "reason", "updated_at",
                            "audit_seq", "audit_timestamp", "cursor"])
        check("注册事件内容",
              ev0["action"] == "credential.schema.registered"
              and ev0["status"] == "active"
              and ev0["reason"] is None
              and isinstance(ev0["updated_at"], str)
              and isinstance(ev0["audit_seq"], int)
              and isinstance(ev0["audit_timestamp"], int)
              and ev0["cursor"] == 1)
        check("注册事件审计序号指向注册审计",
              ev0["audit_seq"] == audit_events(
                  "credential.schema.registered")[0]["seq"])
        check("历史 next_after 为末项 cursor", r["next_after"] == 1)

        # -------------------------------------------------------------- #
        # 2. POST status 格式错误 -> 400，不留状态/历史/审计
        # -------------------------------------------------------------- #
        bad_bodies = [
            ("缺 issuer_did", {"status": "deprecated"}),
            ("缺 status", {"issuer_did": issuer}),
            ("多余字段", {"issuer_did": issuer, "status": "deprecated",
                          "extra": 1}),
            ("issuer_did 空", {"issuer_did": "", "status": "deprecated"}),
            ("issuer_did 非字符串",
             {"issuer_did": 1, "status": "deprecated"}),
            ("status 非法值", {"issuer_did": issuer, "status": "active"}),
            ("status 非字符串", {"issuer_did": issuer, "status": 1}),
            ("reason 显式 null",
             {"issuer_did": issuer, "status": "deprecated",
              "reason": None}),
            ("reason 空串",
             {"issuer_did": issuer, "status": "deprecated", "reason": ""}),
            ("reason 全空白",
             {"issuer_did": issuer, "status": "deprecated",
              "reason": "   "}),
            ("reason 非字符串",
             {"issuer_did": issuer, "status": "deprecated", "reason": 1}),
        ]
        for label, payload in bad_bodies:
            st, r = post_status(payload)
            check(f"非法状态变更（{label}）-> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])
        st, r = post_status(None, raw=b"")
        check("空请求体 -> 400", st == 400)
        st, r = post_status(None, raw=b"[1]")
        check("请求体非对象 -> 400", st == 400)
        st, r = post_status(None, raw=b"{")
        check("请求体非法 JSON -> 400", st == 400)
        st, r = _http("POST",
                      f"{BASE}/v1/credential-schemas/BAD/1/status",
                      {"issuer_did": issuer, "status": "deprecated"},
                      headers=T)
        check("路径 schema_id 非法 -> 400", st == 400)
        st, r = _http("POST",
                      f"{BASE}/v1/credential-schemas/kyc_lc/x/status",
                      {"issuer_did": issuer, "status": "deprecated"},
                      headers=T)
        check("路径 version 非数字 -> 400", st == 400)
        st, r = _http("POST",
                      f"{BASE}/v1/credential-schemas/kyc_lc/status",
                      {"issuer_did": issuer, "status": "deprecated"},
                      headers=T)
        check("路径段数不足 -> 400", st == 400)
        check("400 后状态仍 active",
              get_status()[1]["status"] == "active")
        check("400 后历史仍单事件",
              len(get_history()[1]["events"]) == 1)
        check("400 不留弃用审计",
              audit_events("credential.schema.deprecated") == [])

        # -------------------------------------------------------------- #
        # 3. 404：未知版本/模式/issuer 与跨租户
        # -------------------------------------------------------------- #
        dep = {"issuer_did": issuer, "status": "deprecated"}
        st, r = post_status(dep, ver=9)
        check("未知版本 -> 404", st == 404)
        st, r = post_status(dep, sid="nope")
        check("未知 schema_id -> 404", st == 404)
        st, r = post_status({"issuer_did": "did:x:ghost",
                             "status": "deprecated"})
        check("未知 issuer_did -> 404", st == 404)
        st, r = post_status({"issuer_did": issuer_b,
                             "status": "deprecated"})
        check("他租户 issuer_did -> 404", st == 404)
        st, r = post_status(dep, headers=T2)
        check("跨租户变更 -> 404", st == 404)
        st, r = get_status(ver=9)
        check("GET status 未知版本 -> 404", st == 404)
        st, r = get_status(headers=T2)
        check("GET status 跨租户 -> 404", st == 404)
        st, r = get_history(ver=9)
        check("GET history 未知版本 -> 404", st == 404)
        st, r = get_history(headers=T2)
        check("GET history 跨租户 -> 404", st == 404)
        check("404 后状态仍 active",
              get_status()[1]["status"] == "active")

        # GET status / history 参数规则
        st, r = _http("GET", status_url(), headers=T)
        check("GET status 缺 issuer_did -> 400", st == 400)
        st, r = _http("GET", status_url() + "?issuer_did=", headers=T)
        check("GET status issuer_did 空值 -> 400", st == 400)
        st, r = _http("GET",
                      status_url() + f"?issuer_did={issuer}"
                      f"&issuer_did={issuer}", headers=T)
        check("GET status issuer_did 重复 -> 400", st == 400)
        st, r = get_status(extra="&limit=1")
        check("GET status 未知参数 -> 400", st == 400)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/history", headers=T)
        check("GET history 缺 issuer_did -> 400", st == 400)
        st, r = get_history(extra="&limit=0")
        check("history limit 为 0 -> 400", st == 400)
        st, r = get_history(extra="&limit=201")
        check("history limit 超上限 -> 400", st == 400)
        st, r = get_history(extra="&limit=x")
        check("history limit 非数字 -> 400", st == 400)
        st, r = get_history(extra="&limit=1&limit=2")
        check("history limit 重复 -> 400", st == 400)
        st, r = get_history(extra="&after=-1")
        check("history after 负数 -> 400", st == 400)
        st, r = get_history(extra="&after=")
        check("history after 空值 -> 400", st == 400)
        st, r = get_history(extra="&foo=1")
        check("history 未知参数 -> 400", st == 400)

        # -------------------------------------------------------------- #
        # 4. deprecated：首次 201、默认 reason、幂等 200、冲突 409
        # -------------------------------------------------------------- #
        st, r = post_status(dep)
        check("首次 deprecated -> 201", st == 201)
        check("deprecated 响应六字段键序",
              list(r) == ["schema_id", "version", "issuer_did",
                          "status", "reason", "updated_at"])
        check("deprecated 默认 reason",
              r["reason"] == "模式版本已弃用")
        check("deprecated 响应回显",
              r["schema_id"] == "kyc_lc" and r["version"] == 1
              and r["issuer_did"] == issuer and r["status"] == "deprecated")
        dep_updated_at = r["updated_at"]

        st, ev = _http("GET", audit_url, headers=T)
        dep_audits = [e for e in ev["events"]
                      if e["action"] == "credential.schema.deprecated"]
        check("首次弃用记一次审计", len(dep_audits) == 1)
        check("弃用审计 resource",
              dep_audits[0]["resource_type"] == "credential_schema"
              and dep_audits[0]["resource_id"]
              == f"{issuer}:kyc_lc:1")

        st, r = get_history()
        check("弃用后历史两事件", len(r["events"]) == 2)
        ev1 = r["events"][1]
        # 游标为租户内跨模式版本共享：v2 注册事件占 cursor 2
        check("弃用事件内容",
              ev1["action"] == "credential.schema.deprecated"
              and ev1["status"] == "deprecated"
              and ev1["reason"] == "模式版本已弃用"
              and ev1["updated_at"] == dep_updated_at
              and ev1["audit_seq"] == dep_audits[0]["seq"]
              and ev1["audit_timestamp"] == dep_audits[0]["timestamp"]
              and ev1["cursor"] == 3)

        # 幂等：缺省 reason 与显式同值均 200，不追加历史、不记审计
        st, r = post_status(dep)
        check("重复 deprecated（缺省 reason）-> 200", st == 200
              and r["updated_at"] == dep_updated_at)
        st, r = post_status({"issuer_did": issuer, "status": "deprecated",
                             "reason": "模式版本已弃用"})
        check("重复 deprecated（显式同值 reason）-> 200", st == 200)
        st, r = get_history()
        check("幂等重试不追加历史", len(r["events"]) == 2)
        check("幂等重试不记审计",
              len(audit_events("credential.schema.deprecated")) == 1)

        # reason 变化 -> 409
        st, r = post_status({"issuer_did": issuer, "status": "deprecated",
                             "reason": "别的理由"})
        check("deprecated 同状态异 reason -> 409", st == 409)
        check("409 后状态与 reason 不变",
              get_status()[1]["reason"] == "模式版本已弃用")
        check("409 不追加历史", len(get_history()[1]["events"]) == 2)

        # -------------------------------------------------------------- #
        # 5. deprecated 版本不可签发；active 版本与不引用版本不受影响
        # -------------------------------------------------------------- #
        good_claims = {"name": "Alice", "age": 30}

        def issue(ver=1, sid="kyc_lc", headers=T, iss=issuer):
            payload = {
                "issuer_did": iss,
                "subject_did": subject,
                "claims": good_claims,
            }
            if sid is not None:
                payload["schema_id"] = sid
                payload["schema_version"] = ver
            return _http("POST", f"{BASE}/v1/credentials", payload,
                         headers=headers)

        issued_before = len(audit_events("credential.issued"))
        st, r = issue(ver=1)
        check("引用 deprecated 版本签发 -> 409", st == 409)
        check("409 响应恰为统一错误体",
              r == {"error": UNAVAILABLE})
        check("409 签发不落 credential.issued 审计",
              len(audit_events("credential.issued")) == issued_before)
        st, r = issue(ver=2)
        check("引用 active 版本签发 -> 201", st == 201)
        check("签发响应三字段不变",
              set(r) == {"credential_id", "signature",
                         "issuer_key_version"})
        active_cid = r["credential_id"]
        st, r = issue(sid=None)
        check("不引用版本签发 -> 201", st == 201)

        # -------------------------------------------------------------- #
        # 6. deprecated -> revoked：201 与显式 reason
        # -------------------------------------------------------------- #
        st, r = post_status({"issuer_did": issuer, "status": "revoked",
                             "reason": "  安全事件下线  "})
        check("deprecated -> revoked -> 201", st == 201)
        check("revoked 显式 reason 裁剪保存",
              r["reason"] == "安全事件下线")
        st, r = get_history()
        check("吊销后历史三事件", len(r["events"]) == 3)
        ev2 = r["events"][2]
        check("吊销事件内容",
              ev2["action"] == "credential.schema.revoked"
              and ev2["status"] == "revoked"
              and ev2["reason"] == "安全事件下线"
              and ev2["cursor"] == 4)
        check("吊销记审计",
              len(audit_events("credential.schema.revoked")) == 1)

        # revoked 终态：同态同 reason 幂等 200，异 reason/逆向 409
        st, r = post_status({"issuer_did": issuer, "status": "revoked",
                             "reason": "安全事件下线"})
        check("revoked 幂等 -> 200", st == 200)
        st, r = post_status({"issuer_did": issuer, "status": "revoked"})
        check("revoked 缺省 reason 与显式不同 -> 409", st == 409)
        st, r = post_status({"issuer_did": issuer, "status": "revoked",
                             "reason": "其他"})
        check("revoked 异 reason -> 409", st == 409)
        st, r = post_status(dep)
        check("revoked -> deprecated 逆向 -> 409", st == 409)
        check("终态冲突后历史仍三事件",
              len(get_history()[1]["events"]) == 3)
        check("终态冲突不记审计",
              len(audit_events("credential.schema.revoked")) == 1)

        st, r = issue(ver=1)
        check("引用 revoked 版本签发 -> 409 统一错误体",
              st == 409 and r == {"error": UNAVAILABLE})

        # -------------------------------------------------------------- #
        # 7. active -> revoked 直迁（v2），默认 reason
        # -------------------------------------------------------------- #
        st, r = post_status({"issuer_did": issuer, "status": "revoked"},
                            ver=2)
        check("active -> revoked -> 201", st == 201)
        check("revoked 默认 reason", r["reason"] == "模式版本已吊销")
        st, r = get_history(ver=2)
        check("v2 历史两事件（注册+吊销）",
              [e["action"] for e in r["events"]]
              == ["credential.schema.registered",
                  "credential.schema.revoked"])
        st, r = issue(ver=2)
        check("v2 吊销后签发 -> 409", st == 409
              and r == {"error": UNAVAILABLE})

        # -------------------------------------------------------------- #
        # 8. 历史凭证既有结论不受模式弃用/吊销影响
        # -------------------------------------------------------------- #
        st, got = _http("GET", f"{BASE}/v1/credentials/{active_cid}",
                        headers=T)
        assert st == 200
        st, r = _http("POST", f"{BASE}/v1/credentials/{active_cid}/verify",
                      {"body": got["body"], "signature": got["signature"]},
                      headers=T)
        check("模式吊销后历史凭证 verify valid:true",
              st == 200 and r == {"valid": True})

        # -------------------------------------------------------------- #
        # 9. 历史分页：limit/after 与 next_after 语义
        # -------------------------------------------------------------- #
        st, r = get_history(extra="&limit=2")
        check("limit=2 返回两项", len(r["events"]) == 2
              and r["next_after"] == r["events"][-1]["cursor"] == 3)
        st, r2 = get_history(extra=f"&after={r['next_after']}")
        check("after 续页返回剩余事件",
              len(r2["events"]) == 1
              and r2["events"][0]["cursor"] == 4
              and r2["next_after"] == 4)
        st, r3 = get_history(extra="&after=4")
        check("空页 next_after 保持 after",
              r3["events"] == [] and r3["next_after"] == 4)
        st, r4 = get_history(extra="&limit=1&after=1")
        check("limit+after 组合",
              len(r4["events"]) == 1
              and r4["events"][0]["cursor"] == 3
              and r4["next_after"] == 3)

        # -------------------------------------------------------------- #
        # 10. 租户隔离：他租户注册同名模式互不可见
        # -------------------------------------------------------------- #
        schema_b = dict(schema, issuer_did=issuer_b)
        st, r = _http("POST", f"{BASE}/v1/credential-schemas", schema_b,
                      headers=T2)
        assert st == 201, (st, r)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/status"
            f"?issuer_did={issuer_b}", headers=T2)
        check("租户 B 同名版本状态独立 active",
              st == 200 and r["status"] == "active")
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/history"
            f"?issuer_did={issuer_b}", headers=T2)
        check("租户 B 历史独立（仅注册事件）",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["cursor"] == 1)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/status"
            f"?issuer_did={issuer}", headers=T2)
        check("租户 B 读租户 A 版本 -> 404", st == 404)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 11. 跨重启：状态、历史与游标持久化
    # -------------------------------------------------------------- #
    proc = serve()
    try:
        assert wait_up(), "服务重启超时"
        issuer = issuer_did["v"]
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/status"
            f"?issuer_did={issuer}", headers=T)
        check("重启后 revoked 状态保持",
              st == 200 and r["status"] == "revoked"
              and r["reason"] == "安全事件下线")
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/history"
            f"?issuer_did={issuer}", headers=T)
        check("重启后历史三事件且 cursor 稳定",
              st == 200
              and [e["cursor"] for e in r["events"]] == [1, 3, 4]
              and r["next_after"] == 4)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer, "subject_did": subject_did["v"],
             "claims": {"name": "A"},
             "schema_id": "kyc_lc", "schema_version": 1}, headers=T)
        check("重启后 revoked 版本签发仍 409",
              st == 409 and r == {"error": UNAVAILABLE})
        # 重启后幂等重试仍 200 且不追加历史
        st, r = _http(
            "POST", f"{BASE}/v1/credential-schemas/kyc_lc/1/status",
            {"issuer_did": issuer, "status": "revoked",
             "reason": "安全事件下线"}, headers=T)
        check("重启后幂等重试 -> 200", st == 200)
        st, r = _http(
            "GET",
            f"{BASE}/v1/credential-schemas/kyc_lc/1/history"
            f"?issuer_did={issuer}", headers=T)
        check("重启后幂等重试不追加历史", len(r["events"]) == 3)
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
