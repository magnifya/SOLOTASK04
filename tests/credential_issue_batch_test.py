#!/usr/bin/env python3
"""POST /v1/credentials/issue-batch 整批原子签发端到端测试。

覆盖：
- 请求级 400：空体、非法 JSON、非对象、外层缺/多 items、items 非数组、
  空数组、超过 100、项非对象、项缺字段/多余字段、claims 非对象、
  issuer_did/subject_did 空、expires_at 非法或过去、schema 引用未成对、
  schema_version 非正整数，响应均为恰含非空 error 的 400；
- 携带 Idempotency-Key 头一律 400；显式空 X-Tenant-ID 400；
- 资源级错误：未知/他租户签发者或持有人 400、已停用签发者 409、
  未知/他租户模式 404、弃用/吊销模式 409 且 error 固定为
  "credential schema unavailable"、claims 不满足模式 400、
  模式门禁先于 claims 约束；
- 校验顺序：先外层后按输入顺序逐项，首个失败项决定响应；
- 原子性：任一项失败整批不留凭证、不记审计、不推进审计序号；
- 成功 201：正文仅含 results，与输入等长同序，每项恰为
  credential_id/signature/issuer_key_version；混合签发者/持有人、
  内容相同的重复项各自独立签发；新凭证可直接查询、验签、查状态；
  每张凭证按输入顺序追加 credential.issued 审计；他租户查询 404；
  未带 Idempotency-Key 的成功批次再次提交生成全新凭证；
- 重启后凭证与审计保留；直连 VCStore 落盘失败整体回滚、磁盘不变、
  故障排除后重试成功。

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

PORT = 8992
RESULT_KEYS = ["credential_id", "signature", "issuer_key_version"]
FUTURE = "2099-01-01T00:00:00Z"


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

    def register_did(headers):
        st, body = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example",
             "public_key": f"handle-{time.time_ns()}"},
            headers=headers,
        )
        assert st == 201, body
        return body["did"]

    def register_schema(headers, issuer_did, schema_id, version=1,
                        claim_types=None, required=None):
        st, body = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": schema_id, "version": version,
             "issuer_did": issuer_did,
             "claim_types": claim_types or {"/name": "string"},
             "required_claims": required if required is not None
             else ["/name"]},
            headers=headers,
        )
        assert st == 201, body
        return body

    def batch(payload=None, headers=None, raw=None):
        return _http(
            "POST", f"{base}/v1/credentials/issue-batch",
            payload=payload, headers=T1 if headers is None else headers,
            raw=raw,
        )

    def audits(headers, action="credential.issued"):
        st, body = _http("GET", f"{base}/v1/audit?limit=200",
                         headers=headers)
        assert st == 200, body
        return [e for e in body["events"] if e["action"] == action]

    try:
        issuer1 = register_did(T1)
        issuer2 = register_did(T1)
        subject1 = register_did(T1)
        did_t2 = register_did(T2)
        register_schema(T1, issuer1, "profile", 1,
                        {"/name": "string", "/age": "integer"}, ["/name"])
        register_schema(T1, issuer1, "oldprofile", 1)
        register_schema(T2, did_t2, "profile", 1)
        register_schema(T2, did_t2, "t2only", 1)
        st, body = _http(
            "POST",
            f"{base}/v1/credential-schemas/oldprofile/1/status",
            {"issuer_did": issuer1, "status": "deprecated"}, headers=T1)
        assert st == 201, body
        register_schema(T1, issuer1, "deadprofile", 1)
        st, body = _http(
            "POST",
            f"{base}/v1/credential-schemas/deadprofile/1/status",
            {"issuer_did": issuer1, "status": "revoked"}, headers=T1)
        assert st == 201, body
        deactivated = register_did(T1)
        st, body = _http(
            "POST", f"{base}/v1/dids/{deactivated}/deactivate",
            {}, headers=T1)
        assert st == 200, body

        def item(**kw):
            base_item = {"issuer_did": issuer1, "subject_did": subject1,
                         "claims": {"name": "alice"}}
            base_item.update(kw)
            return base_item

        # ---- 1. 请求级 400（响应恰含非空 error）----
        bad_requests = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{"),
            ("非对象", None, b"[1,2]"),
            ("缺少 items", {}, None),
            ("外层多余字段", {"items": [item()], "x": 1}, None),
            ("items 非数组", {"items": {}}, None),
            ("items 为空", {"items": []}, None),
            ("items 超 100", {"items": [item()] * 101}, None),
            ("项非对象", {"items": ["x"]}, None),
            ("项缺 issuer_did",
             {"items": [{"subject_did": subject1, "claims": {}}]}, None),
            ("项缺 subject_did",
             {"items": [{"issuer_did": issuer1, "claims": {}}]}, None),
            ("项缺 claims",
             {"items": [{"issuer_did": issuer1,
                         "subject_did": subject1}]}, None),
            ("项多余字段", {"items": [item(extra=1)]}, None),
            ("claims 非对象", {"items": [item(claims=5)]}, None),
            ("issuer_did 为空", {"items": [item(issuer_did="")]}, None),
            ("subject_did 为空", {"items": [item(subject_did="")]}, None),
            ("expires_at 格式非法",
             {"items": [item(expires_at="tomorrow")]}, None),
            ("expires_at 在过去",
             {"items": [item(expires_at="2000-01-01T00:00:00Z")]}, None),
            ("schema 引用未成对（仅 id）",
             {"items": [item(schema_id="profile")]}, None),
            ("schema 引用未成对（仅 version）",
             {"items": [item(schema_version=1)]}, None),
            ("schema_version 非正整数",
             {"items": [item(schema_id="profile", schema_version=0)]},
             None),
            ("schema_id 为空",
             {"items": [item(schema_id="", schema_version=1)]}, None),
        ]
        for name, payload, raw in bad_requests:
            st, body = batch(payload, raw=raw)
            check(f"400: {name}",
                  st == 400 and set(body) == {"error"}
                  and isinstance(body["error"], str) and body["error"])

        st, body = batch({"items": [item()]},
                         headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400", st == 400 and body.get("error"))

        st, body = batch({"items": [item()]},
                         headers={"X-Tenant-ID": "ib-a",
                                  "Idempotency-Key": "abc"})
        check("携带 Idempotency-Key 一律 400",
              st == 400 and set(body) == {"error"} and body["error"])
        st, body = batch({"items": [item()]},
                         headers={"X-Tenant-ID": "ib-a",
                                  "Idempotency-Key": ""})
        check("空 Idempotency-Key 同样 400", st == 400)

        # ---- 2. 资源级错误 ----
        st, body = batch({"items": [item(issuer_did="did:example:none")]})
        check("未知签发者 400", st == 400 and body.get("error"))
        st, body = batch({"items": [item(subject_did="did:example:none")]})
        check("未知持有人 400", st == 400 and body.get("error"))
        st, body = batch({"items": [item(issuer_did=did_t2)]})
        check("他租户签发者 400", st == 400 and body.get("error"))
        st, body = batch({"items": [item(subject_did=did_t2)]})
        check("他租户持有人 400", st == 400 and body.get("error"))
        st, body = batch({"items": [item(issuer_did=deactivated)]})
        check("已停用签发者 409", st == 409 and body.get("error"))
        st, body = batch({"items": [item(schema_id="nosuch",
                                         schema_version=1)]})
        check("未知模式 404", st == 404 and body.get("error"))
        st, body = batch({"items": [item(schema_id="t2only",
                                         schema_version=1)]})
        check("他租户模式 404", st == 404 and body.get("error"))
        st, body = batch({"items": [item(schema_id="oldprofile",
                                         schema_version=1)]})
        check("弃用模式 409 固定 error",
              st == 409
              and body == {"error": "credential schema unavailable"})
        st, body = batch({"items": [item(schema_id="deadprofile",
                                         schema_version=1)]})
        check("吊销模式 409 固定 error",
              st == 409
              and body == {"error": "credential schema unavailable"})
        st, body = batch({"items": [
            {"issuer_did": issuer1, "subject_did": subject1,
             "claims": {"age": 30},
             "schema_id": "profile", "schema_version": 1}]})
        check("claims 缺必填路径 400", st == 400 and body.get("error"))
        st, body = batch({"items": [
            {"issuer_did": issuer1, "subject_did": subject1,
             "claims": {"name": "a", "age": "三十"},
             "schema_id": "profile", "schema_version": 1}]})
        check("claims 类型不符 400", st == 400 and body.get("error"))
        st, body = batch({"items": [
            {"issuer_did": issuer1, "subject_did": subject1,
             "claims": {"age": "bad"},
             "schema_id": "oldprofile", "schema_version": 1}]})
        check("模式门禁先于 claims 约束（409 而非 400）",
              st == 409
              and body == {"error": "credential schema unavailable"})

        # ---- 3. 校验顺序：首个失败项决定响应 ----
        st, body = batch({"items": [
            item(schema_id="nosuch", schema_version=1),
            item(extra=1)]})
        check("首项 404 先于次项形状 400", st == 404)
        st, body = batch({"items": [
            item(extra=1),
            item(schema_id="nosuch", schema_version=1)]})
        check("首项形状 400 先于次项 404", st == 400)
        st, body = batch({"items": [
            item(issuer_did=deactivated),
            item(schema_id="nosuch", schema_version=1)]})
        check("首项 409 先于次项 404", st == 409)

        # ---- 4. 原子性：任一项失败整批不生效 ----
        audits_before = audits(T1)
        st, body = batch({"items": [item(), item(issuer_did="did:x:none")]})
        check("次项失败整批 400", st == 400)
        check("失败批次不记审计", audits(T1) == audits_before)
        st, body = batch({"items": [
            {"issuer_did": issuer1, "subject_did": subject1,
             "claims": {"name": "atomic"}},
            item(issuer_did="did:x:none")]})
        check("含唯一 claims 批次失败 400", st == 400)
        st, body = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("失败批次审计序号未推进", audits(T1) == audits_before)

        # ---- 5. 成功：混合签发者/持有人、重复项、模式与有效期 ----
        dup = {"issuer_did": issuer2, "subject_did": subject1,
               "claims": {"tag": "dup"}}
        ok_items = [
            item(),
            {"issuer_did": issuer2, "subject_did": issuer1,
             "claims": {"name": "bob", "age": 42},
             "expires_at": FUTURE},
            {"issuer_did": issuer1, "subject_did": subject1,
             "claims": {"name": "carol", "age": 7},
             "schema_id": "profile", "schema_version": 1},
            dup,
            dict(dup),
        ]
        st, body = batch({"items": ok_items})
        check("成功 201", st == 201)
        check("成功正文仅含 results", set(body) == {"results"})
        results = body.get("results", [])
        check("results 与输入等长", len(results) == len(ok_items))
        check("每项恰含单张签发三字段",
              all(list(r) == RESULT_KEYS for r in results))
        cids = [r["credential_id"] for r in results]
        check("每项凭证独立（含重复项）", len(set(cids)) == len(cids))
        check("密钥版本沿用签发者当前版本",
              all(isinstance(r["issuer_key_version"], int)
                  for r in results))

        for i, cid in enumerate(cids):
            st, got = _http("GET", f"{base}/v1/credentials/{cid}",
                            headers=T1)
            check(f"第 {i} 张凭证可查询", st == 200)
            if st != 200:
                continue
            check(f"第 {i} 张凭证签发者/持有人正确",
                  got["body"]["issuer_did"] == ok_items[i]["issuer_did"]
                  and got["body"]["subject_did"]
                  == ok_items[i]["subject_did"])
            st, ver = _http(
                "POST", f"{base}/v1/credentials/{cid}/verify",
                {"body": got["body"], "signature": got["signature"]},
                headers=T1)
            check(f"第 {i} 张凭证验签通过",
                  st == 200 and ver.get("valid") is True)
            st, stat = _http(
                "GET", f"{base}/v1/credentials/{cid}/status", headers=T1)
            check(f"第 {i} 张凭证状态 active",
                  st == 200 and stat.get("status") == "active")
        st, got1 = _http("GET", f"{base}/v1/credentials/{cids[1]}",
                         headers=T1)
        check("有效期写入正文", got1["body"].get("expires_at") == FUTURE)
        st, got2 = _http("GET", f"{base}/v1/credentials/{cids[2]}",
                         headers=T1)
        check("模式绑定写入正文",
              got2["body"].get("schema_id") == "profile"
              and got2["body"].get("schema_version") == 1
              and isinstance(got2["body"].get("schema_digest"), str))
        check("无期限项正文不含 expires_at",
              "expires_at" not in got2["body"])

        issued_audits = [a for a in audits(T1)
                         if a["resource_id"] in cids]
        check("每张凭证各一条 credential.issued 审计",
              len(issued_audits) == len(cids))
        check("审计按输入顺序追加",
              [a["resource_id"] for a in issued_audits] == cids
              and [a["seq"] for a in issued_audits]
              == sorted(a["seq"] for a in issued_audits))

        st, body = _http("GET", f"{base}/v1/credentials/{cids[0]}",
                         headers=T2)
        check("他租户查询新凭证 404", st == 404)

        st, body = batch({"items": ok_items})
        new_cids = [r["credential_id"] for r in body.get("results", [])]
        check("无幂等头的成功批次重提生成全新凭证",
              st == 201 and len(set(new_cids) & set(cids)) == 0)

        # 单张签发与幂等重试不受影响
        st, body = _http(
            "POST", f"{base}/v1/credentials",
            item(), headers={**T1, "Idempotency-Key": "single-1"})
        check("单张签发仍支持幂等键（201）", st == 201)
        st, body2 = _http(
            "POST", f"{base}/v1/credentials",
            item(), headers={**T1, "Idempotency-Key": "single-1"})
        check("单张幂等重放 200 同结果",
              st == 200 and body2 == body)

        # ---- 6. 重启后凭证与审计保留 ----
        audits_pre = audits(T1)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(PORT, store_path)
        st, got = _http("GET", f"{base}/v1/credentials/{cids[0]}",
                        headers=T1)
        check("重启后凭证可查", st == 200 and got["body"]["issuer_did"]
              == issuer1)
        st, ver = _http(
            "POST", f"{base}/v1/credentials/{cids[0]}/verify",
            {"body": got["body"], "signature": got["signature"]},
            headers=T1)
        check("重启后验签通过", st == 200 and ver.get("valid") is True)
        check("重启后审计保留", audits(T1) == audits_pre)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- 7. 落盘失败整体回滚（直连 VCStore）----
    direct = VCStore(store_path)
    bucket = direct._tenants["ib-a"]  # noqa: SLF001
    creds_before = set(bucket["credentials"])
    audit_before = len(direct._audit)  # noqa: SLF001
    with open(store_path, encoding="utf-8") as fh:
        disk_before = fh.read()

    real_save = direct._save_locked  # noqa: SLF001

    def boom():
        raise OSError("模拟落盘失败")

    direct._save_locked = boom  # type: ignore[assignment]  # noqa: SLF001
    raised = False
    try:
        direct.create_credentials_batch("ib-a", [item(), dict(dup)])
    except OSError:
        raised = True
    check("落盘失败原样抛 OSError", raised)
    check("内存态凭证回滚",
          set(direct._tenants["ib-a"]["credentials"])  # noqa: SLF001
          == creds_before)
    check("内存态审计回滚",
          len(direct._audit) == audit_before)  # noqa: SLF001
    with open(store_path, encoding="utf-8") as fh:
        check("磁盘文件字节不变", fh.read() == disk_before)
    reloaded = VCStore(store_path)
    check("重新加载无半写凭证",
          set(reloaded._tenants["ib-a"]["credentials"])  # noqa: SLF001
          == creds_before)

    direct._save_locked = real_save  # type: ignore[assignment]  # noqa: SLF001
    records = direct.create_credentials_batch("ib-a", [item(), dict(dup)])
    check("故障排除后重试成功且等长同序",
          len(records) == 2
          and records[0].credential_id != records[1].credential_id
          and records[0].body["issuer_did"] == issuer1
          and records[1].body["issuer_did"] == issuer2)
    check("重试仅追加两条审计",
          len(direct._audit) == audit_before + 2)  # noqa: SLF001

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
