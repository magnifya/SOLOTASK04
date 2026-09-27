#!/usr/bin/env python3
"""外部凭证状态同步 suspended 扩展端到端测试。

POST /v1/trust/credential-status/sync 及 /sync-batch 接受
status:"suspended"（reason 必填、字符串、裁剪后 1–256 码点，否则单项
400 仅返 {"error":"非空中文原因"}、批量项按序 valid:false/400/中文
reason，均不写入）；验签后保存裁剪值；同 updated_at 裁剪后内容相同
为重放 200、不同 409、更晚替换；GET/历史按原结构返回 suspended 与
裁剪 reason；各类 with-status 验真遇 suspended 均 HTTP 200 失败，
reason 恰为“外部凭证已暂停：<reason>”。

直接运行：python3 tests/trust_credential_status_sync_suspended_test.py
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
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/sync"
SYNC_BATCH_PATH = "/v1/trust/credential-status/sync-batch"
ANCHOR_SYNC_PATH = "/v1/trust/anchor-changes/sync"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None)
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


def gen_keypair():
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def make_event(cursor, did, key_version=1, action="registered",
               status="active", uses=None, pub="pem"):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": key_version,
        "public_key": pub,
        "status": status,
        "uses": list(uses if uses is not None else ALL_USES),
    }


def build_changes(events, after, did, signer_priv):
    signed = {
        "events": events,
        "next_after": events[-1]["cursor"] if events else after,
        "signer_did": did,
        "signer_key_version": 1,
    }
    signature = crypto.sign(signed, signer_priv)
    changes = dict(signed)
    changes["signature"] = signature
    return {"changes": changes, "after": after}


def main():
    port = 8979
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"
    T1 = {"X-Tenant-ID": "tsus-a"}
    T2 = {"X-Tenant-ID": "tsus-b"}

    issuer_priv, issuer_pub = gen_keypair()
    signer_priv, signer_pub = gen_keypair()
    did = "did:web:susp-issuer.example"
    signer_did = "did:web:susp-signer.example"

    def sync_status(cred_id, status, updated="2026-09-20T00:00:00Z",
                    reason=None, headers=T1, version=1):
        body = {
            "issuer_did": did,
            "credential_id": cred_id,
            "status": status,
            "updated_at": updated,
            "issuer_key_version": version,
        }
        if reason is not None:
            body["reason"] = reason
        return body, {"body": body, "signature": crypto.sign(body, issuer_priv)}

    def sync(payload, headers=T1):
        return _http("POST", f"{base}{SYNC_PATH}", payload, headers=headers)

    def get_status(cred_id, headers=T1):
        return _http(
            "GET",
            f"{base}/v1/trust/credential-status/{quote(cred_id)}"
            f"?issuer_did={quote(did)}",
            headers=headers,
        )

    def get_history(cred_id, headers=T1):
        return _http(
            "GET",
            f"{base}/v1/trust/credential-status/{quote(cred_id)}/history"
            f"?issuer_did={quote(did)}",
            headers=headers,
        )

    def audit_count(headers=T1):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return len(r["events"])

    try:
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": issuer_pub,
                       "key_version": 1}, headers=T1)
        check("注册签发者锚点 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": 1}, headers=T1)
        check("注册签名方锚点 -> 201", st == 201)

        # -------- 1. suspended 的 reason 校验：400 仅 {"error":"非空中文原因"} -------- #
        n_audit = audit_count()
        for name, reason in (
            ("缺 reason", None),
            ("reason 非字符串", 123),
            ("reason 纯空白", "   "),
            ("reason 空串", ""),
            ("reason 257 码点", "长" * 257),
        ):
            body, payload = sync_status("vc_bad_reason", "suspended",
                                        reason=reason)
            if reason is None:
                body.pop("reason", None)
                payload = {"body": body,
                           "signature": crypto.sign(body, issuer_priv)}
            st, r = sync(payload)
            check(f"suspended {name} -> 400 仅非空中文原因",
                  st == 400 and r == {"error": "非空中文原因"})
        st, _ = get_status("vc_bad_reason")
        check("非法 suspended 不写入（GET 404）", st == 404)
        check("非法 suspended 不记审计", audit_count() == n_audit)

        # 边界：1 码点与 256 码点均可
        _, payload = sync_status("vc_min", "suspended", reason="查")
        st, r = sync(payload)
        check("reason 1 码点 -> 201", st == 201 and r["reason"] == "查")
        _, payload = sync_status("vc_max", "suspended", reason="长" * 256)
        st, r = sync(payload)
        check("reason 256 码点 -> 201", st == 201 and r["reason"] == "长" * 256)

        # -------- 2. 裁剪保存、GET 与历史按原结构返回 -------- #
        _, payload = sync_status("vc_susp", "suspended",
                                 updated="2026-09-21T00:00:00Z",
                                 reason="  违规调查中  ")
        st, r = sync(payload)
        check("suspended 首次同步 -> 201 且 reason 为裁剪值",
              st == 201 and r["status"] == "suspended"
              and r["reason"] == "违规调查中")
        st, r = get_status("vc_susp")
        check("GET 返回 suspended 与裁剪 reason（恰三字段）",
              st == 200 and r == {
                  "status": "suspended",
                  "reason": "违规调查中",
                  "updated_at": "2026-09-21T00:00:00Z",
              })
        st, r = get_history("vc_susp")
        check("历史含 suspended 事件与裁剪 reason",
              st == 200 and len(r["events"]) == 1
              and r["events"][0]["status"] == "suspended"
              and r["events"][0]["reason"] == "违规调查中")

        # -------- 3. 重放 / 冲突 / 严格更新（按裁剪后内容判定） -------- #
        n_audit = audit_count()
        _, payload = sync_status("vc_susp", "suspended",
                                 updated="2026-09-21T00:00:00Z",
                                 reason="违规调查中")  # 无填充，裁剪后相同
        st, r = sync(payload)
        check("同 updated_at 裁剪后内容相同 -> 重放 200",
              st == 200 and r["reason"] == "违规调查中")
        check("重放不重复审计", audit_count() == n_audit)

        _, payload = sync_status("vc_susp", "suspended",
                                 updated="2026-09-21T00:00:00Z",
                                 reason="  另一原因  ")
        st, r = sync(payload)
        check("同 updated_at 裁剪后内容不同 -> 409", st == 409)
        st, r = get_status("vc_susp")
        check("409 不改变已存状态", st == 200 and r["reason"] == "违规调查中")
        check("409 不记审计", audit_count() == n_audit)

        _, payload = sync_status("vc_susp", "suspended",
                                 updated="2026-09-22T00:00:00Z",
                                 reason="  复核维持暂停  ")
        st, r = sync(payload)
        check("更晚 updated_at 替换 -> 200 裁剪保存",
              st == 200 and r["reason"] == "复核维持暂停")
        check("严格更新记审计", audit_count() == n_audit + 1)
        st, r = get_history("vc_susp")
        check("历史追加第二条 suspended 事件",
              st == 200 and len(r["events"]) == 2
              and r["events"][1]["reason"] == "复核维持暂停")

        # -------- 4. 批量：非法项按序 400/中文 reason，不短路、不写入 -------- #
        ok_body, ok_payload = sync_status("vc_batch_ok", "suspended",
                                          reason="  批量暂停  ")
        bad_body, bad_payload = sync_status("vc_batch_bad", "suspended",
                                            reason=None)
        bad_body.pop("reason", None)
        bad_payload = {"body": bad_body,
                       "signature": crypto.sign(bad_body, issuer_priv)}
        long_body, long_payload = sync_status("vc_batch_long", "suspended",
                                              reason="长" * 257)
        act_body, act_payload = sync_status("vc_batch_active", "active")
        st, r = _http("POST", f"{base}{SYNC_BATCH_PATH}",
                      {"items": [ok_payload, bad_payload, long_payload,
                                 act_payload]}, headers=T1)
        check("批量 -> 200 四项等长同序",
              st == 200 and len(r.get("results", [])) == 4)
        res = r["results"]
        check("批量项1 suspended -> 201 裁剪 reason",
              res[0].get("valid") is True and res[0]["http_status"] == 201
              and res[0]["status"] == "suspended"
              and res[0]["reason"] == "批量暂停")
        check("批量项2 缺 reason -> valid:false/400/非空中文原因",
              res[1] == {"valid": False, "http_status": 400,
                         "reason": "非空中文原因"})
        check("批量项3 reason 257 码点 -> valid:false/400/非空中文原因",
              res[2] == {"valid": False, "http_status": 400,
                         "reason": "非空中文原因"})
        check("批量项4 active -> 201（失败不短路）",
              res[3].get("valid") is True
              and res[3]["http_status"] == 201
              and res[3]["status"] == "active")
        st, _ = get_status("vc_batch_bad")
        check("批量非法项不写入", st == 404)
        st, _ = get_status("vc_batch_long")
        check("批量超长 reason 项不写入", st == 404)

        # -------- 5. with-status 验真：suspended -> 外部凭证已暂停：<reason> -------- #
        expected = "外部凭证已暂停：复核维持暂停"

        cred_body = {
            "credential_id": "vc_susp",
            "issuer_did": did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-01T00:00:00Z",
            "issuer_key_version": 1,
        }
        cred_item = {"body": cred_body,
                     "signature": crypto.sign(cred_body, issuer_priv)}

        st, r = _http("POST", f"{base}/v1/trust/credentials/verify-with-status",
                      cred_item, headers=T1)
        check("凭证 verify-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http("POST",
                      f"{base}/v1/trust/credentials/verify-batch-with-status",
                      {"credentials": [cred_item]}, headers=T1)
        check("凭证 verify-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": expected}])

        pres = {
            "presentation_id": "vp_susp",
            "credential_id": "vc_susp",
            "issuer_did": did,
            "issuer_key_version": 1,
            "disclose": ["/role"],
            "claims": {"role": "admin"},
            "challenge": "chal-1",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        pres["proof"] = crypto.sign(pres, issuer_priv)
        st, r = _http("POST",
                      f"{base}/v1/trust/presentations/verify-with-status",
                      {"presentation": pres, "challenge": "chal-1"},
                      headers=T1)
        check("演示 verify-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http(
            "POST", f"{base}/v1/trust/presentations/verify-batch-with-status",
            {"presentations": [{"presentation": pres, "challenge": "chal-1"}]},
            headers=T1)
        check("演示 verify-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": expected}])

        proof = {
            "proof_id": "zp_" + "b" * 32,
            "credential_id": "vc_susp",
            "issuer_did": did,
            "issuer_key_version": 1,
            "predicates": [{"path": "/age", "op": "gte", "value": 18}],
            "results": [True],
            "challenge": "chal-1",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        proof_msg = dict(proof)
        proof_msg["tenant_id"] = "tsus-a"
        proof["proof"] = crypto.sign(proof_msg, issuer_priv)
        proof_req = {"proof": proof, "challenge": "chal-1",
                     "source_tenant_id": "tsus-a"}
        st, r = _http("POST", f"{base}/v1/trust/proofs/verify-with-status",
                      proof_req, headers=T1)
        check("证明 verify-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http("POST",
                      f"{base}/v1/trust/proofs/verify-batch-with-status",
                      {"proofs": [proof_req]}, headers=T1)
        check("证明 verify-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": expected}])

        # imported 单项与批量 with-status 重验
        st, r = _http("POST", f"{base}/v1/trust/credentials/import",
                      cred_item, headers=T1)
        check("导入外部凭证 -> 201", st == 201)
        imp_single = (f"{base}/v1/trust/credentials/imported/vc_susp"
                      f"/verify-with-status?issuer_did={quote(did)}")
        st, r = _http("POST", imp_single, {}, headers=T1)
        check("imported verify-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http(
            "POST",
            f"{base}/v1/trust/credentials/imported/verify-batch-with-status",
            {"items": [{"issuer_did": did, "credential_id": "vc_susp"}]},
            headers=T1)
        check("imported verify-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "http_status": 200, "reason": expected}])

        # -------- 6. synced 单项与批量 with-status：同一结论 -------- #
        page = build_changes(
            [make_event(1, did, 1, pub=issuer_pub)],
            0, signer_did, signer_priv,
        )
        st, _ = _http("POST", f"{base}{ANCHOR_SYNC_PATH}", page, headers=T1)
        check("同步锚点变更页 -> 201", st == 201)

        st, r = _http(
            "POST", f"{base}/v1/trust/credentials/verify-synced-with-status",
            {"signer_did": signer_did, "at": 1, **cred_item}, headers=T1)
        check("凭证 verify-synced-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http(
            "POST",
            f"{base}/v1/trust/credentials/verify-synced-batch-with-status",
            {"signer_did": signer_did, "at": 1, "credentials": [cred_item]},
            headers=T1)
        check("凭证 verify-synced-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": expected}])

        st, r = _http(
            "POST",
            f"{base}/v1/trust/presentations/verify-synced-with-status",
            {"signer_did": signer_did, "at": 1, "presentation": pres,
             "challenge": "chal-1"}, headers=T1)
        check("演示 verify-synced-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http(
            "POST",
            f"{base}/v1/trust/presentations/verify-synced-batch-with-status",
            {"signer_did": signer_did, "at": 1,
             "presentations": [{"presentation": pres,
                                "challenge": "chal-1"}]}, headers=T1)
        check("演示 verify-synced-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": expected}])

        st, r = _http(
            "POST", f"{base}/v1/trust/proofs/verify-synced-with-status",
            {"signer_did": signer_did, "at": 1, **proof_req}, headers=T1)
        check("证明 verify-synced-with-status -> 200 已暂停",
              st == 200 and r == {"valid": False, "reason": expected})
        st, r = _http(
            "POST",
            f"{base}/v1/trust/proofs/verify-synced-batch-with-status",
            {"signer_did": signer_did, "at": 1, "proofs": [proof_req]},
            headers=T1)
        check("证明 verify-synced-batch-with-status -> 已暂停",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": expected}])

        # -------- 7. 租户隔离：他租户无此同步状态 -------- #
        st, r = _http("POST", f"{base}/v1/trust/credentials/verify-with-status",
                      cred_item, headers=T2)
        check("他租户无锚点 -> 验真失败而非已暂停",
              st == 200 and r.get("valid") is False
              and r.get("reason", "") != expected)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------- 8. 重启保持 -------- #
    proc = start()
    try:
        st, r = get_status("vc_susp")
        check("重启后 suspended 与裁剪 reason 保留",
              st == 200 and r == {
                  "status": "suspended",
                  "reason": "复核维持暂停",
                  "updated_at": "2026-09-22T00:00:00Z",
              })
        st, r = get_history("vc_susp")
        check("重启后历史保留", st == 200 and len(r["events"]) == 2)
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("重启后 synced 审计保留",
              st == 200 and any(
                  e["action"] == "trust.credential.status.synced"
                  for e in r["events"]))
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    if os.path.exists(store_path):
        os.remove(store_path)

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
