#!/usr/bin/env python3
"""单条已导入外部凭证重验并合并同步状态的端到端测试。

POST /v1/trust/credentials/imported/{credential_id}/verify-with-status
?issuer_did=...

直接运行：python3 tests/trust_credential_imported_verify_with_status_test.py
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


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
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


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
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


_UNSET = object()


def main():
    port = 8985
    store_path = tempfile.mktemp(suffix=".json")

    def start():
        env = dict(os.environ, VCBACKEND_STORE=store_path)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    def stop(proc):
        proc.terminate()
        proc.wait(timeout=10)

    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def call(method, path, payload=None, raw=None, headers=None):
        st, text = _http(
            method, f"{base}{path}", payload=payload, raw=raw,
            headers=headers,
        )
        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError:
            parsed = None
        return st, parsed, text

    def post_vws(credential_id, issuer_did, payload=None, raw=None,
                 headers=None, query_suffix="", use_query=True):
        path = (
            f"/v1/trust/credentials/imported/{credential_id}"
            f"/verify-with-status"
        )
        if use_query:
            path += f"?issuer_did={quote(issuer_did)}{query_suffix}"
        return call(
            "POST", path, payload=payload, raw=raw, headers=headers
        )

    def expect_400(name, credential_id, issuer_did, payload=None, raw=None,
                   headers=None, query_suffix="", use_query=True):
        st, parsed, _ = post_vws(
            credential_id, issuer_did, payload=payload, raw=raw,
            headers=headers, query_suffix=query_suffix, use_query=use_query,
        )
        check(
            name,
            st == 400
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"error"}
            and isinstance(parsed["error"], str)
            and parsed["error"],
        )

    def expect_result(name, credential_id, issuer_did, expected_reason,
                      headers=None):
        st, parsed, text = post_vws(
            credential_id, issuer_did, payload={}, headers=headers
        )
        if expected_reason is None:
            check(
                name,
                st == 200
                and parsed == {"valid": True}
                and list(json.loads(text).keys()) == ["valid"],
            )
        else:
            check(
                name,
                st == 200
                and parsed == {"valid": False, "reason": expected_reason}
                and list(json.loads(text).keys()) == ["valid", "reason"],
            )

    def audit_seqs(headers=None):
        st, parsed, _ = call(
            "GET", "/v1/audit?limit=200&after=0", headers=headers
        )
        assert st == 200
        return [event["seq"] for event in parsed["events"]]

    def status_views(credential_id, issuer_did, headers=None):
        q = f"issuer_did={quote(issuer_did)}"
        st1, p1, _ = call(
            "GET",
            f"/v1/trust/credential-status/{quote(credential_id)}?{q}",
            headers=headers,
        )
        st2, p2, _ = call(
            "GET",
            f"/v1/trust/credential-status/{quote(credential_id)}"
            f"/history?{q}&limit=200&after=0",
            headers=headers,
        )
        return (st1, p1, st2, p2)

    def sync_status(credential_id, status, updated, priv, version=1,
                    reason=_UNSET, headers=None, issuer=None):
        if issuer is None:
            issuer = did
        body = {
            "issuer_did": issuer,
            "credential_id": credential_id,
            "status": status,
            "updated_at": updated,
            "issuer_key_version": version,
        }
        if reason is not _UNSET:
            body["reason"] = reason
        return call(
            "POST", "/v1/trust/credential-status/sync",
            payload={"body": body, "signature": crypto.sign(body, priv)},
            headers=headers,
        )

    proc = start()
    T1 = {"X-Tenant-ID": "ivws-a"}
    T2 = {"X-Tenant-ID": "ivws-b"}

    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    did = "did:web:verify-imported-ws.example"
    did_other = "did:web:other-anchor-ws.example"
    cred_id = "vc_ivws_0001"
    cred_v2 = "vc_ivws_v2"
    cred_future = "vc_ivws_future"
    cred_rev_reason = "vc_ivws_rev_reason"
    cred_rev_noreason = "vc_ivws_rev_noreason"
    cred_unknown = "vc_ivws_unknown"
    cred_t2 = "vc_ivws_t2_only"

    def make_body(cred=cred_id, issuer=did, version=1, extra=None,
                  issued_at="2026-09-20T00:00:00Z"):
        body = {
            "credential_id": cred,
            "issuer_did": issuer,
            "subject_did": "did:web:holder.example",
            "claims": {"level": 7, "nested": {"z": 1, "a": 2}},
            "issued_at": issued_at,
        }
        if version is not None:
            body["issuer_key_version"] = version
        if extra:
            body.update(extra)
        return body

    def import_cred(body, priv):
        st, parsed, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body, "signature": crypto.sign(body, priv)},
            headers=T1,
        )
        assert st == 201, parsed

    try:
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("T1 注册 v1 active 锚点 -> 201", st == 201)

        import_cred(make_body(version=None), priv1)
        import_cred(
            make_body(
                cred=cred_future,
                extra={"expires_at": "2030-01-01T00:00:00Z"},
            ),
            priv1,
        )

        st, _, _ = call(
            "POST", f"/v1/trust/anchors/{did}/rotate",
            {"from_key_version": 1, "public_key": pub2}, headers=T1,
        )
        check("锚点轮换 v2 -> 201/200", st in (200, 201))
        import_cred(make_body(cred=cred_v2, version=2), priv2)
        import_cred(make_body(cred=cred_rev_reason, version=2), priv2)
        import_cred(make_body(cred=cred_rev_noreason, version=2), priv2)
        import_cred(make_body(cred=cred_unknown, version=2), priv2)

        # T2 注册自己的锚点并导入同双键（跨租户隔离）
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1},
            headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        body_t2 = make_body(cred=cred_t2)
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_t2, "signature": crypto.sign(body_t2, priv2)},
            headers=T2,
        )
        check("T2 导入自有凭证 -> 201", st == 201)

        # ---- 显式空 X-Tenant-ID -> 400 ----
        expect_400(
            "显式空 X-Tenant-ID -> 400 仅 {error}",
            cred_id, did, payload={},
            headers={"X-Tenant-ID": ""},
        )

        # ---- 查询参数 issuer_did：缺失/重复/空值 -> 400 ----
        expect_400(
            "缺 issuer_did -> 400 仅 {error}", cred_id, did, payload={},
            use_query=False,
        )
        expect_400(
            "issuer_did 重复 -> 400 仅 {error}", cred_id, did, payload={},
            query_suffix=f"&issuer_did={quote(did)}",
        )
        expect_400(
            "issuer_did 空值 -> 400 仅 {error}", cred_id, "", payload={},
        )

        # ---- 请求体必须恰为 {}：空体/非法 JSON/非对象/含字段 -> 400 ----
        expect_400("空请求体 -> 400", cred_id, did, raw=b"")
        expect_400("非法 JSON -> 400", cred_id, did, raw=b"{bad")
        expect_400("JSON 数组 -> 400", cred_id, did, raw=b"[1,2]")
        expect_400("JSON 标量 -> 400", cred_id, did, raw=b'"x"')
        expect_400("含字段对象 -> 400", cred_id, did, payload={"x": 1})
        expect_400("含空字段对象 -> 400", cred_id, did, payload={"": ""})

        # ---- 记录查找：不存在 / issuer_did 错配 / 跨租户 -> 404 ----
        st, parsed, _ = post_vws(
            "vc_not_imported", did, payload={}, headers=T1
        )
        check(
            "未导入凭证 -> 404 仅 {error}",
            st == 404 and set(parsed.keys()) == {"error"} and parsed["error"],
        )
        st, parsed, _ = post_vws(
            cred_id, did_other, payload={}, headers=T1
        )
        check(
            "issuer_did 错配 -> 404 仅 {error}",
            st == 404 and set(parsed.keys()) == {"error"} and parsed["error"],
        )
        st, parsed, _ = post_vws(
            cred_id, did, payload={}, headers=T2
        )
        check(
            "跨租户 -> 404 仅 {error}",
            st == 404 and set(parsed.keys()) == {"error"} and parsed["error"],
        )

        # ---- 未同步：重验成功但无同步记录 ----
        expect_result(
            "重验成功但未同步 -> 外部凭证状态未同步",
            cred_id, did, "外部凭证状态未同步", headers=T1,
        )
        expect_result(
            "v2 凭证未同步 -> 外部凭证状态未同步",
            cred_v2, did, "外部凭证状态未同步", headers=T1,
        )

        # ---- active 同步：仅 {"valid": true} ----
        st, _, _ = sync_status(
            cred_id, "active", "2026-09-21T00:00:00Z", priv1, version=1,
            headers=T1,
        )
        check("同步 cred_id active -> 201", st == 201)
        expect_result("active 同步后 -> 仅 {valid:true}", cred_id, did,
                      None, headers=T1)

        # ---- revoked 且带 reason（原样保留，含空白）----
        st, _, _ = sync_status(
            cred_rev_reason, "revoked", "2026-09-21T00:00:00Z",
            priv2, version=2, reason="  持证人违规  ", headers=T1,
        )
        check("同步 cred_rev_reason revoked -> 201", st == 201)
        expect_result(
            "revoked 带 reason -> 外部凭证已吊销：<reason>",
            cred_rev_reason, did,
            "外部凭证已吊销：  持证人违规  ", headers=T1,
        )

        # ---- revoked 但无 reason 字段：固定“未知原因” ----
        st, _, _ = sync_status(
            cred_rev_noreason, "revoked", "2026-09-21T00:00:00Z",
            priv2, version=2, headers=T1,
        )
        check("同步 cred_rev_noreason revoked（无 reason）-> 201",
              st == 201)
        expect_result(
            "revoked 缺 reason -> 外部凭证已吊销：未知原因",
            cred_rev_noreason, did,
            "外部凭证已吊销：未知原因", headers=T1,
        )

        # ---- unknown 同步 ----
        st, _, _ = sync_status(
            cred_unknown, "unknown", "2026-09-21T00:00:00Z",
            priv2, version=2, headers=T1,
        )
        check("同步 cred_unknown unknown -> 201", st == 201)
        expect_result(
            "unknown 同步后 -> 外部凭证状态未知",
            cred_unknown, did, "外部凭证状态未知", headers=T1,
        )

        # ---- 租户隔离：T2 同双键 active 不影响 T1 ----
        st, _, _ = sync_status(
            cred_id, "active", "2026-09-21T00:00:00Z", priv2, version=1,
            headers=T2,
        )
        check("T2 同步同双键 active -> 201", st == 201)
        expect_result("T1 同双键仍为 active", cred_id, did, None,
                      headers=T1)
        # T2 对自己的凭证：未同步 -> 未同步；同步后 active
        expect_result("T2 自有凭证未同步", cred_t2, did,
                      "外部凭证状态未同步", headers=T2)
        st, _, _ = sync_status(
            cred_t2, "active", "2026-09-21T00:00:00Z", priv2, version=1,
            headers=T2,
        )
        check("T2 同步自有凭证 active -> 201", st == 201)
        expect_result("T2 自有凭证 active", cred_t2, did, None,
                      headers=T2)

        # ---- 重验先于状态：吊销 v1 锚点 -> 锚点不可用（无论同步状态）----
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 T1 v1 锚点 -> 200", st == 200)
        expect_result("v1 锚点吊销（同步 active）-> 锚点不可用",
                      cred_id, did, "锚点不可用", headers=T1)
        expect_result("v2 凭证仍可到达状态合并", cred_v2, did,
                      "外部凭证状态未同步", headers=T1)
        expect_result("v2 revoked 结论不受 v1 吊销影响",
                      cred_rev_reason, did,
                      "外部凭证已吊销：  持证人违规  ", headers=T1)

        # ---- 纯只读：审计不增加、同步状态与历史不变、导入原文不变 ----
        seqs_before = audit_seqs(T1)
        views = {
            cid: status_views(cid, did, headers=T1)
            for cid in (cred_id, cred_rev_reason, cred_rev_noreason,
                        cred_unknown)
        }
        for _ in range(3):
            post_vws(cred_id, did, payload={}, headers=T1)
            post_vws(cred_rev_reason, did, payload={}, headers=T1)
            post_vws(cred_unknown, did, raw=b"not-json", headers=T1)
            post_vws("nope", did, payload={}, headers=T1)
        check("各类调用后审计不增加", audit_seqs(T1) == seqs_before)
        for cid in (cred_id, cred_rev_reason, cred_rev_noreason,
                    cred_unknown):
            check(
                f"{cid} 同步状态与历史保持不变",
                status_views(cid, did, headers=T1) == views[cid],
            )

        # ---- 缺省租户 default：无头导入、同步与重验 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        check("default 注册锚点 -> 201", st == 201)
        body_default = make_body(cred="vc_default_ivws")
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_default,
             "signature": crypto.sign(body_default, priv1)},
        )
        check("缺省租户导入 -> 201", st == 201)
        expect_result("缺省租户未同步（无头）", "vc_default_ivws", did,
                      "外部凭证状态未同步")
        st, _, _ = sync_status(
            "vc_default_ivws", "active", "2026-09-21T00:00:00Z",
            priv1, version=1,
        )
        check("default 同步 active -> 201", st == 201)
        expect_result("缺省租户 active（无头）", "vc_default_ivws", did,
                      None)

        # T2 凭证结论不受 T1 锚点吊销影响
        expect_result("T2 凭证不受 T1 吊销影响", cred_t2, did, None,
                      headers=T2)
    finally:
        stop(proc)

    # ---- 重启后：同步状态与重验结论稳定 ----
    proc = start()
    try:
        expect_result("重启后 active 同步仍判锚点不可用（v1 已吊销）",
                      cred_id, did, "锚点不可用", headers=T1)
        expect_result("重启后 revoked reason 稳定", cred_rev_reason, did,
                      "外部凭证已吊销：  持证人违规  ", headers=T1)
        expect_result("重启后 revoked 无 reason 稳定",
                      cred_rev_noreason, did,
                      "外部凭证已吊销：未知原因", headers=T1)
        expect_result("重启后 unknown 稳定", cred_unknown, did,
                      "外部凭证状态未知", headers=T1)
        expect_result("重启后 T2 active 稳定", cred_t2, did, None,
                      headers=T2)
        expect_result("重启后 default active 稳定", "vc_default_ivws",
                      did, None)

        # 恢复 T1 v1 active 并篡改 cred_future 正文（不重签），
        # 该凭证未同步：验签失败优先于状态合并。
        data = json.load(open(store_path, encoding="utf-8"))
        anchor_v1 = data["tenants"]["ivws-a"]["trust_anchors"][did]["1"]
        anchor_v1["status"] = "active"
        anchor_v1.pop("updated_at", None)
        bucket = data["tenants"]["ivws-a"]["imported_credentials"][did]
        bucket[cred_future]["body"]["claims"]["level"] = 999
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后篡改正文 -> 签名校验失败（先于未同步状态）",
            cred_future, did, "签名校验失败", headers=T1,
        )

        # 签名格式错误优先于过期与状态
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivws-a"]["imported_credentials"][did][
            cred_future
        ]
        row["signature"] = "!!!not-base64url!!!"
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后签名格式非法 -> 签名格式错误（优先于过期）",
            cred_future, did, "签名格式错误", headers=T1,
        )

        # 用导入者私钥重签已过期正文，并写入 active 同步：过期仍先返回
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivws-a"]["imported_credentials"][did][
            cred_future
        ]
        row["body"]["claims"]["level"] = 7
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        row["signature"] = crypto.sign(row["body"], priv1)
        data["tenants"]["ivws-a"]["trust_anchors"][did]["1"]["status"] = (
            "active"
        )
        data["tenants"]["ivws-a"]["trust_anchors"][did]["1"].pop(
            "updated_at", None
        )
        sync_bucket = data["tenants"]["ivws-a"].setdefault(
            "credential_status_sync", {}
        ).setdefault(did, {})
        sync_bucket[cred_future] = {
            "status": "active",
            "reason": None,
            "updated_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "已过期且同步 active -> 凭证已过期（验签阶段先返回）",
            cred_future, did, "凭证已过期", headers=T1,
        )

        # 直接写一条空串 reason 的 revoked 同步记录：固定“未知原因”
        data = json.load(open(store_path, encoding="utf-8"))
        data["tenants"]["ivws-a"]["credential_status_sync"][did][
            cred_future
        ] = {
            "status": "revoked",
            "reason": "",
            "updated_at": "2026-09-22T00:00:00Z",
            "issuer_key_version": 1,
        }
        # 恢复为未过期的合法凭证正文，使其到达状态合并阶段
        row = data["tenants"]["ivws-a"]["imported_credentials"][did][
            cred_future
        ]
        row["body"].pop("expires_at", None)
        row["body"]["claims"]["level"] = 7
        row["signature"] = crypto.sign(row["body"], priv1)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "落盘空串 reason 的 revoked -> 外部凭证已吊销：未知原因",
            cred_future, did,
            "外部凭证已吊销：未知原因", headers=T1,
        )

        # 删除锚点 -> 锚点不可用（缺失与吊销同因），不进入状态合并
        data = json.load(open(store_path, encoding="utf-8"))
        data["tenants"]["ivws-a"]["trust_anchors"][did].pop("1", None)
        data["tenants"]["ivws-a"]["trust_anchors"][did].pop("2", None)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后锚点缺失 -> 锚点不可用", cred_future, did,
            "锚点不可用", headers=T1,
        )
        # 既有单项重验行为不变
        st, parsed, text = call(
            "POST",
            f"/v1/trust/credentials/imported/{cred_id}/verify"
            f"?issuer_did={quote(did)}",
            payload={}, headers=T1,
        )
        check(
            "既有 /verify 端点行为不变（锚点不可用、无状态合并）",
            st == 200
            and parsed == {"valid": False, "reason": "锚点不可用"}
            and list(json.loads(text).keys()) == ["valid", "reason"],
        )
        # GET 既有行为不变
        st, _, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{cred_id}"
            f"?issuer_did={quote(did)}",
            headers=T2,
        )
        check("GET 跨租户仍 404（既有行为不变）", st == 404)
    finally:
        stop(proc)

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
