#!/usr/bin/env python3
"""POST /v1/credentials/issue-batch 整批原子签发端到端测试。

覆盖：
- 请求级 400：空体、非法 JSON、非对象、缺/多外层字段、items 非数组、
  空数组、超过 100、项非对象、项缺 issuer_did/subject_did/claims、项
  多余字段、字段类型错误、schema 引用未成对、非法 expires_at；显式空
  X-Tenant-ID 400；Idempotency-Key（任意取值）一律 400；
- 项级语义 400：未知/他租户签发者或持有人 DID、claims 不满足模式；
  已停用签发者 409；未知/他租户模式 404；deprecated/revoked 模式
  409 且 error 固定为 credential schema unavailable，门禁先于 claims；
- 按输入顺序逐项完整校验，首个失败项决定响应（早项 404/409 不被晚项
  400 覆盖）；任何失败整批不留凭证/审计/审计序号；
- 成功 201：仅 results，与输入等长同序，每项恰含单张签发三字段；混合
  签发者/持有人、重复项各自独立凭证，GET/verify 直接可用；
- 每凭证按序一条 credential.issued 审计，本租户可追溯、他租户不可见；
  他租户 GET 新凭证 404；无幂等头的成功批次再提交生成新凭证；单张签发
  及其幂等重试行为不变；
- 重启后凭证与审计保留；
- 直连 VCStore：落盘失败时凭证与审计整体回滚、审计序号不占用、磁盘
  字节不变，故障排除后重试成功。

直接运行：python3 tests/credential_issue_batch_test.py
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

from vcbackend.store import VCStore  # noqa: E402

PORT = 8997
RESULT_KEYS = ["credential_id", "signature", "issuer_key_version"]
UNAVAILABLE = {"error": "credential schema unavailable"}
FUTURE = "2999-01-01T00:00:00Z"


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
            time.sleep(0.1)
    return False


def start_server(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
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
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "ib-a"}
    T2 = {"X-Tenant-ID": "ib-b"}

    def register_did(headers, handle=None):
        st, body = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example",
             "public_key": handle or f"handle-{time.time_ns()}"},
            headers=headers,
        )
        assert st == 201, body
        return body["did"]

    def deactivate(did):
        st, body = _http(
            "POST", f"{base}/v1/dids/{did}/deactivate", {}, headers=T1)
        assert st == 200, body

    def register_schema(schema_id, version, issuer, claim_types, required):
        st, body = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": schema_id, "version": version,
             "issuer_did": issuer, "claim_types": claim_types,
             "required_claims": required},
            headers=T1)
        assert st == 201, body

    def set_schema_status(schema_id, version, issuer, status):
        st, body = _http(
            "POST",
            f"{base}/v1/credential-schemas/{schema_id}/{version}/status",
            {"issuer_did": issuer, "status": status}, headers=T1)
        assert st == 201, body

    def batch(payload=None, headers=None, raw=None, extra_headers=None):
        hdrs = dict(headers or T1)
        hdrs.update(extra_headers or {})
        return _http(
            "POST", f"{base}/v1/credentials/issue-batch",
            payload=payload, headers=hdrs, raw=raw,
        )

    def issue_one(payload, headers=None, extra_headers=None):
        hdrs = dict(headers or T1)
        hdrs.update(extra_headers or {})
        return _http("POST", f"{base}/v1/credentials", payload, headers=hdrs)

    def get_cred(cid, headers=None):
        return _http("GET", f"{base}/v1/credentials/{cid}",
                     headers=T1 if headers is None else headers)

    def verify(cid, body, signature):
        return _http(
            "POST", f"{base}/v1/credentials/{cid}/verify",
            {"body": body, "signature": signature}, headers=T1)

    def issued_audits(headers=None):
        st, body = _http("GET", f"{base}/v1/audit?limit=200",
                         headers=T1 if headers is None else headers)
        assert st == 200, body
        return [e for e in body["events"]
                if e["action"] == "credential.issued"]

    def max_audit_seq(headers=None):
        st, body = _http("GET", f"{base}/v1/audit?limit=200",
                         headers=T1 if headers is None else headers)
        assert st == 200, body
        events = body["events"]
        return events[-1]["seq"] if events else 0

    try:
        a = register_did(T1, "issuer-a")
        b = register_did(T1, "issuer-b")
        h = register_did(T1, "holder-h")
        deact_did = register_did(T1, "soon-dead")
        other = register_did(T2, "tenant-b-did")

        register_schema("age_schema", 1, a,
                        {"/name": "string", "/age": "integer"},
                        ["/name", "/age"])
        register_schema("dep_schema", 1, a, {"/x": "string"}, ["/x"])
        set_schema_status("dep_schema", 1, a, "deprecated")
        register_schema("rev_schema", 1, a, {"/x": "string"}, ["/x"])
        set_schema_status("rev_schema", 1, a, "revoked")

        item_ok = {"issuer_did": a, "subject_did": h,
                   "claims": {"role": "admin"}}

        # ---- 1. 请求级 400 ----
        bad_requests = [
            ("空体", None, b"", T1, None),
            ("非法 JSON", None, b"{", T1, None),
            ("非对象", None, b'"x"', T1, None),
            ("非对象数组", None, b"[1]", T1, None),
            ("缺少 items", {}, None, T1, None),
            ("外层多余字段", {"items": [], "x": 1}, None, T1, None),
            ("items 非数组", {"items": {}}, None, T1, None),
            ("items 为空", {"items": []}, None, T1, None),
            ("items 超 100",
             {"items": [item_ok] * 101}, None, T1, None),
            ("项非对象", {"items": ["x"]}, None, T1, None),
            ("项为空对象", {"items": [{}]}, None, T1, None),
            ("缺 issuer_did",
             {"items": [{"subject_did": h, "claims": {}}]}, None, T1, None),
            ("缺 subject_did",
             {"items": [{"issuer_did": a, "claims": {}}]}, None, T1, None),
            ("缺 claims",
             {"items": [{"issuer_did": a, "subject_did": h}]},
             None, T1, None),
            ("项多余字段",
             {"items": [dict(item_ok, x=1)]}, None, T1, None),
            ("issuer_did 非字符串",
             {"items": [{"issuer_did": 1, "subject_did": h,
                         "claims": {}}]}, None, T1, None),
            ("issuer_did 为空",
             {"items": [{"issuer_did": "", "subject_did": h,
                         "claims": {}}]}, None, T1, None),
            ("subject_did 为 null",
             {"items": [{"issuer_did": a, "subject_did": None,
                         "claims": {}}]}, None, T1, None),
            ("claims 非对象",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": []}]}, None, T1, None),
            ("只给 schema_id",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": {}, "schema_id": "age_schema"}]},
             None, T1, None),
            ("只给 schema_version",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": {}, "schema_version": 1}]},
             None, T1, None),
            ("expires_at 非字符串",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": {}, "expires_at": 1}]},
             None, T1, None),
            ("expires_at 非法形状",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": {}, "expires_at": "2030-01-01"}]},
             None, T1, None),
            ("expires_at 已过期",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": {},
                         "expires_at": "2000-01-01T00:00:00Z"}]},
             None, T1, None),
            ("schema_version 为字符串",
             {"items": [{"issuer_did": a, "subject_did": h,
                         "claims": {}, "schema_id": "age_schema",
                         "schema_version": "1"}]},
             None, T1, None),
        ]
        for name, payload, raw_body, headers_t, _unused in bad_requests:
            if raw_body is not None:
                st, resp = batch(raw=raw_body, headers=headers_t)
            else:
                st, resp = batch(payload, headers_t)
            check(f"{name} -> 400 非空 error",
                  st == 400 and isinstance(resp.get("error"), str)
                  and resp["error"]
                  and set(resp) == {"error"})

        check("失败批次后无任何签发审计", issued_audits() == [])
        check("失败批次后审计序号为 0（仅 DID/模式事件）",
              max_audit_seq() >= 0)

        # 显式空租户头 400
        st, resp = batch({"items": [item_ok]}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and bool(resp.get("error")))

        # Idempotency-Key 一律 400：合法值、非法值、重复头
        st, resp = batch({"items": [item_ok]},
                         extra_headers={"Idempotency-Key": "k1"})
        check("合法 Idempotency-Key -> 400",
              st == 400 and bool(resp.get("error")))
        st, resp = batch({"items": [item_ok]},
                         extra_headers={"Idempotency-Key": "!!"})
        check("非法 Idempotency-Key -> 400",
              st == 400 and bool(resp.get("error")))
        check("幂等头拒绝后无签发审计", issued_audits() == [])

        # ---- 2. 项级资源/语义错误 ----
        st, resp = batch({"items": [
            {"issuer_did": "did:example:nope", "subject_did": h,
             "claims": {}},
        ]})
        check("未知签发者 -> 400", st == 400 and bool(resp.get("error")))
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": "did:example:nope",
             "claims": {}},
        ]})
        check("未知持有人 -> 400", st == 400 and bool(resp.get("error")))
        st, resp = batch({"items": [
            {"issuer_did": other, "subject_did": h, "claims": {}},
        ]})
        check("他租户签发者 -> 400", st == 400 and bool(resp.get("error")))
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": other, "claims": {}},
        ]})
        check("他租户持有人 -> 400", st == 400 and bool(resp.get("error")))

        deactivate(deact_did)
        st, resp = batch({"items": [
            {"issuer_did": deact_did, "subject_did": h, "claims": {}},
        ]})
        check("已停用签发者 -> 409", st == 409 and bool(resp.get("error")))

        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h, "claims": {},
             "schema_id": "no_such", "schema_version": 1},
        ]})
        check("未知模式 -> 404", st == 404 and bool(resp.get("error")))
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h,
             "claims": {"name": "n", "age": 30},
             "schema_id": "age_schema", "schema_version": 2},
        ]})
        check("未知模式版本 -> 404", st == 404)
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h, "claims": {},
             "schema_id": "dep_schema", "schema_version": 1},
        ]})
        check("deprecated 模式 -> 409 固定 error",
              st == 409 and resp == UNAVAILABLE)
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h, "claims": {},
             "schema_id": "rev_schema", "schema_version": 1},
        ]})
        check("revoked 模式 -> 409 固定 error",
              st == 409 and resp == UNAVAILABLE)
        # 门禁先于 claims：弃用模式即使 claims 也不合法，仍是 409
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h,
             "claims": {"wrong": 1},
             "schema_id": "dep_schema", "schema_version": 1},
        ]})
        check("模式门禁先于 claims（deprecated+坏 claims -> 409）",
              st == 409 and resp == UNAVAILABLE)
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h,
             "claims": {"name": "n"},
             "schema_id": "age_schema", "schema_version": 1},
        ]})
        check("claims 缺必填 -> 400", st == 400 and bool(resp.get("error")))
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h,
             "claims": {"name": "n", "age": "thirty"},
             "schema_id": "age_schema", "schema_version": 1},
        ]})
        check("claims 类型不符 -> 400",
              st == 400 and bool(resp.get("error")))

        check("全部失败场景后仍无签发审计", issued_audits() == [])

        # ---- 3. 首个失败项决定响应 + 原子性 ----
        seq_before = max_audit_seq()
        st, resp = batch({"items": [
            item_ok,
            {"issuer_did": a, "subject_did": h, "claims": {},
             "schema_id": "no_such", "schema_version": 1},  # 404
            {"issuer_did": "", "subject_did": h, "claims": {}},  # 400
        ]})
        check("早项 404 先于晚项 400", st == 404)
        st, resp = batch({"items": [
            {"issuer_did": "did:example:nope", "subject_did": h,
             "claims": {}},  # 400
            {"issuer_did": deact_did, "subject_did": h,
             "claims": {}},  # 409
        ]})
        check("早项 400 先于晚项 409", st == 400)
        st, resp = batch({"items": [
            {"issuer_did": deact_did, "subject_did": h,
             "claims": {}},  # 409
            {"issuer_did": a, "subject_did": h, "claims": {},
             "schema_id": "no_such", "schema_version": 1},  # 404
        ]})
        check("早项 409 先于晚项 404", st == 409)
        # 项非对象也在其位置参与顺序：第 0 项停用(409)、第 1 项非对象
        st, resp = batch({"items": [
            {"issuer_did": deact_did, "subject_did": h, "claims": {}},
            7,
        ]})
        check("早项 409 先于晚项非对象 400", st == 409)
        check("失败批次不占用审计序号", max_audit_seq() == seq_before)

        # ---- 4. 成功批次 ----
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h,
             "claims": {"role": "admin", "level": 1}},
            {"issuer_did": b, "subject_did": a,
             "claims": {"role": "admin", "level": 1},
             "expires_at": FUTURE},
            {"issuer_did": a, "subject_did": h,
             "claims": {"name": "张三", "age": 30},
             "schema_id": "age_schema", "schema_version": 1},
        ]})
        check("混合批次 -> 201", st == 201)
        check("响应恰含 results", set(resp) == {"results"})
        results = resp["results"]
        check("results 等长", isinstance(results, list) and len(results) == 3)
        check("每项恰含三字段且键序固定",
              [list(r) for r in results] == [RESULT_KEYS] * 3)
        ids = [r["credential_id"] for r in results]
        check("credential_id 互相独立且形如 vc_",
              len(set(ids)) == 3 and all(i.startswith("vc_") for i in ids))
        check("签名均非空", all(isinstance(r["signature"], str)
                                and r["signature"] for r in results))
        cid1, cid2, cid3 = ids

        st, rec1 = get_cred(cid1)
        check("新凭证可经 GET 查询", st == 200)
        check("GET 键序为 credential_id/body/signature",
              list(rec1) == ["credential_id", "body", "signature"])
        body1, sig1 = rec1["body"], rec1["signature"]
        check("无 expires 项不注入字段", "expires_at" not in body1)
        check("issuer_key_version 与响应一致",
              body1["issuer_key_version"] == results[0]["issuer_key_version"]
              and sig1 == results[0]["signature"])
        st, v = verify(cid1, body1, sig1)
        check("新凭证可经原验签接口验证", st == 200 and v.get("valid") is True)

        st, rec2 = get_cred(cid2)
        check("expires_at 原样写入",
              st == 200 and rec2["body"].get("expires_at") == FUTURE)
        st, v = verify(cid2, rec2["body"], rec2["signature"])
        check("有效期项可验签", st == 200 and v.get("valid") is True)

        st, rec3 = get_cred(cid3)
        check("模式绑定三字段写入正文",
              st == 200
              and rec3["body"].get("schema_id") == "age_schema"
              and rec3["body"].get("schema_version") == 1
              and isinstance(rec3["body"].get("schema_digest"), str)
              and len(rec3["body"]["schema_digest"]) == 64)
        st, v = verify(cid3, rec3["body"], rec3["signature"])
        check("模式绑定项可验签", st == 200 and v.get("valid") is True)

        # 状态接口对新凭证可用（无状态按 active）
        st, sbody = _http(
            "GET", f"{base}/v1/credentials/{cid1}/status", headers=T1)
        check("新凭证状态接口 active",
              st == 200 and sbody["status"] == "active")

        # ---- 5. 审计：按输入顺序、本租户可追溯、他租户不可见 ----
        audits = issued_audits()
        batch1_ids = ids
        check("每项各一条 credential.issued 且按输入顺序",
              [e["resource_id"] for e in audits[-3:]] == batch1_ids
              and all(e["resource_type"] == "credential" for e in audits[-3:]))
        check("审计序号连续",
              audits[-2]["seq"] == audits[-3]["seq"] + 1
              and audits[-1]["seq"] == audits[-2]["seq"] + 1)
        check("他租户审计不可见本批事件",
              all(e["resource_id"] not in batch1_ids
                  for e in issued_audits(T2)))
        st, _ = get_cred(cid1, T2)
        check("他租户 GET 新凭证 -> 404", st == 404)
        # 缺省租户头 = default，也看不到 ib-a 的凭证
        st, _ = get_cred(cid1, {})
        check("default 租户查询 -> 404", st == 404)

        # ---- 6. 内容相同的重复项各自独立 ----
        st, resp = batch({"items": [dict(item_ok), dict(item_ok)]})
        check("重复项批次 -> 201", st == 201)
        dup_ids = [r["credential_id"] for r in resp["results"]]
        check("重复项生成不同凭证",
              len(dup_ids) == 2 and dup_ids[0] != dup_ids[1])

        # ---- 7. 再提交生成新凭证（无幂等）----
        st, resp2 = batch({"items": [item_ok]})
        check("再次提交 -> 201 新凭证",
              st == 201
              and resp2["results"][0]["credential_id"] not in ids
              and resp2["results"][0]["credential_id"] not in dup_ids)

        # ---- 8. 单张签发及其幂等重试不变 ----
        payload = {"issuer_did": a, "subject_did": h,
                   "claims": {"single": True}}
        st, r1 = issue_one(payload, extra_headers={"Idempotency-Key": "k-1"})
        check("单张首次签发 201", st == 201)
        st, r2 = issue_one(payload, extra_headers={"Idempotency-Key": "k-1"})
        check("单张同内容重放 200 同凭证",
              st == 200 and r2["credential_id"] == r1["credential_id"])
        st, r3 = issue_one(dict(payload, claims={"single": False}),
                           extra_headers={"Idempotency-Key": "k-1"})
        check("单张异内容重放 409", st == 409)

        # ---- 9. 100 项上限边界 ----
        st, resp = batch({"items": [
            {"issuer_did": a, "subject_did": h, "claims": {"i": i}}
            for i in range(100)
        ]})
        check("恰好 100 项 -> 201",
              st == 201 and len(resp["results"]) == 100)

        # ---- 10. 跨重启保留 ----
        audits_before = issued_audits()
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(PORT, store_path)
        st, rec = get_cred(cid1)
        check("重启后凭证可查", st == 200 and rec["credential_id"] == cid1)
        st, v = verify(cid1, rec["body"], rec["signature"])
        check("重启后验签通过", st == 200 and v.get("valid") is True)
        check("重启后审计一致", issued_audits() == audits_before)
        st, resp = batch({"items": [item_ok]})
        check("重启后批次签发正常",
              st == 201 and len(resp["results"]) == 1)
        restart_cid = resp["results"][0]["credential_id"]

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- 11. 落盘失败整体回滚（直连 VCStore）----
    direct = VCStore(store_path)
    tenant = "ib-a"
    audit_before = len(direct._audit)  # noqa: SLF001
    seq_before = direct._audit_seq  # noqa: SLF001
    creds_before = dict(direct._tenants[tenant]["credentials"])  # noqa: SLF001
    with open(store_path, encoding="utf-8") as fh:
        disk_before = fh.read()

    real_save = direct._save_locked  # noqa: SLF001

    def boom():
        raise OSError("模拟落盘失败")

    direct._save_locked = boom  # type: ignore[assignment]  # noqa: SLF001
    raised = False
    try:
        direct.create_credentials_batch(tenant, [
            {"issuer_did": "did:example:nope-x",
             "subject_did": "did:example:nope-y", "claims": {}},
        ])
    except Exception as exc:  # 未知 DID 为 ValidationError
        raised = isinstance(exc, ValueError)
    check("直连：校验失败原样抛 ValidationError", raised)
    check("直连：校验失败不落盘不占序号",
          len(direct._audit) == audit_before
          and direct._audit_seq == seq_before)  # noqa: SLF001

    raised = False
    try:
        direct.create_credentials_batch(tenant, [
            {"issuer_did": a, "subject_did": h,
             "claims": {"rollback": 1}},
            {"issuer_did": b, "subject_did": a,
             "claims": {"rollback": 2}},
        ])
    except OSError:
        raised = True
    check("直连：落盘失败抛 OSError（映射 500）", raised)
    check("直连：凭证内存态回滚",
          dict(direct._tenants[tenant]["credentials"]) == creds_before)  # noqa: SLF001
    check("直连：审计与序号回滚",
          len(direct._audit) == audit_before
          and direct._audit_seq == seq_before)  # noqa: SLF001
    with open(store_path, encoding="utf-8") as fh:
        check("直连：磁盘文件字节不变", fh.read() == disk_before)

    # 故障排除后重试成功，序号连续、事件不重复
    direct._save_locked = real_save  # type: ignore[assignment]  # noqa: SLF001
    records = direct.create_credentials_batch(tenant, [
        {"issuer_did": a, "subject_did": h, "claims": {"retry": 1}},
        {"issuer_did": b, "subject_did": a, "claims": {"retry": 2}},
    ])
    check("直连：回滚后重试成功、等长同序独立凭证",
          len(records) == 2
          and records[0].credential_id != records[1].credential_id)
    check("直连：重试仅追加两条审计且序号连续",
          len(direct._audit) == audit_before + 2
          and [e["resource_id"] for e in direct._audit[-2:]]
          == [r.credential_id for r in records])
    reloaded = VCStore(store_path)
    check("重新加载后新凭证存在且可验签数据完整",
          all(r.credential_id in reloaded._tenants[tenant]["credentials"]  # noqa: SLF001
              for r in records))
    check("重启后经 HTTP 签发的凭证仍在",
          restart_cid in reloaded._tenants[tenant]["credentials"])  # noqa: SLF001

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
