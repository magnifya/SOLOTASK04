#!/usr/bin/env python3
"""已导入外部凭证重验并合并同步状态端到端测试。

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
    port = 8973
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

    def path_for(credential_id, suffix=""):
        return (
            "/v1/trust/credentials/imported/"
            f"{credential_id}/verify-with-status{suffix}"
        )

    def post_vws(credential_id, issuer_did, payload=None, raw=None,
                 headers=None, query_suffix="", use_query=True):
        path = path_for(credential_id)
        if use_query:
            path += f"?issuer_did={issuer_did}{query_suffix}"
        return call(
            "POST", path, payload=payload, raw=raw, headers=headers
        )

    def post_plain_verify(credential_id, issuer_did, headers=None):
        return call(
            "POST",
            f"/v1/trust/credentials/imported/{credential_id}"
            f"/verify?issuer_did={issuer_did}",
            payload={}, headers=headers,
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

    def audit_events(headers=None):
        st, parsed, _ = call(
            "GET", "/v1/audit?limit=200&after=0", headers=headers
        )
        assert st == 200
        return parsed["events"]

    def sync_status(credential_id, status, priv, *, version=1, reason=_UNSET,
                    updated="2026-09-22T00:00:00Z", issuer=None,
                    headers=None):
        body = {
            "issuer_did": issuer if issuer is not None else did,
            "credential_id": credential_id,
            "status": status,
            "updated_at": updated,
            "issuer_key_version": version,
        }
        if reason is not _UNSET:
            body["reason"] = reason
        return call(
            "POST", "/v1/trust/credential-status/sync",
            {"body": body, "signature": crypto.sign(body, priv)},
            headers=headers,
        )

    proc = start()
    T1 = {"X-Tenant-ID": "ivws-a"}
    T2 = {"X-Tenant-ID": "ivws-b"}

    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    did = "did:web:verify-imported-ws.example"
    did_other = "did:web:other-anchor-ws.example"
    c_unsynced = "vc_iws_unsynced"
    c_active = "vc_iws_active"
    c_revoked = "vc_iws_revoked"
    c_revoked_nr = "vc_iws_revoked_nr"
    c_unknown = "vc_iws_unknown"
    c_v2 = "vc_iws_v2"
    c_future = "vc_iws_future"

    def make_body(cred, issuer=did, version=1, extra=None,
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

    def import_credential(body, priv, headers=T1):
        return call(
            "POST", "/v1/trust/credentials/import",
            {"body": body, "signature": crypto.sign(body, priv)},
            headers=headers,
        )

    try:
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("T1 注册 v1 active 锚点 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors/{did}/rotate",
            {"from_key_version": 1, "public_key": pub2}, headers=T1,
        )
        check("锚点轮换 v2 -> 201/200", st in (200, 201))

        # 导入各类凭证
        check("导入未同步凭证 -> 201",
              import_credential(make_body(c_unsynced), priv1)[0] == 201)
        check("导入 active 凭证 -> 201",
              import_credential(make_body(c_active), priv1)[0] == 201)
        check("导入 revoked 凭证 -> 201",
              import_credential(make_body(c_revoked), priv1)[0] == 201)
        check("导入 revoked(无 reason) 凭证 -> 201",
              import_credential(make_body(c_revoked_nr), priv1)[0] == 201)
        check("导入 unknown 凭证 -> 201",
              import_credential(make_body(c_unknown), priv1)[0] == 201)
        check("导入 v2 凭证 -> 201",
              import_credential(make_body(c_v2, version=2), priv2)[0] == 201)
        body_future = make_body(
            c_future, extra={"expires_at": "2030-01-01T00:00:00Z"}
        )
        check("导入未来到期凭证 -> 201",
              import_credential(body_future, priv1)[0] == 201)

        # T2 注册自己的锚点并导入同双键凭证（跨租户隔离）
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1},
            headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        c_t2 = "vc_iws_t2_only"
        check("T2 导入自有凭证 -> 201",
              import_credential(make_body(c_t2), priv2, headers=T2)[0] == 201)
        st, _, _ = sync_status(
            c_t2, "active", priv2, updated="2026-09-22T00:00:00Z",
            headers=T2,
        )
        check("T2 同步自有凭证 active -> 201", st == 201)

        # ---- 显式空 X-Tenant-ID -> 400 ----
        expect_400(
            "显式空 X-Tenant-ID -> 400",
            c_active, did, payload={},
            headers={"X-Tenant-ID": ""},
        )

        # ---- 查询参数 issuer_did：缺失/重复/空值 -> 400 ----
        expect_400(
            "缺 issuer_did -> 400", c_active, did, payload={},
            use_query=False,
        )
        expect_400(
            "issuer_did 重复 -> 400", c_active, did, payload={},
            query_suffix=f"&issuer_did={did}",
        )
        expect_400(
            "issuer_did 空值 -> 400", c_active, "", payload={},
        )

        # ---- 请求体必须恰为 {}：空体/非法 JSON/非对象/含字段 -> 400 ----
        expect_400("空请求体 -> 400", c_active, did, raw=b"")
        expect_400("非法 JSON -> 400", c_active, did, raw=b"{bad")
        expect_400("JSON 数组 -> 400", c_active, did, raw=b"[1,2]")
        expect_400("JSON 标量 -> 400", c_active, did, raw=b'"x"')
        expect_400("含字段对象 -> 400", c_active, did, payload={"x": 1})
        expect_400("含空字段对象 -> 400", c_active, did, payload={"": ""})

        # ---- 记录查找：不存在 / issuer_did 错配 / 跨租户 -> 404 ----
        st, parsed, _ = post_vws(
            "vc_not_imported", did, payload={}, headers=T1
        )
        check(
            "未导入凭证 -> 404 仅 {error}",
            st == 404 and set(parsed.keys()) == {"error"} and parsed["error"],
        )
        st, parsed, _ = post_vws(
            c_active, did_other, payload={}, headers=T1
        )
        check("issuer_did 错配 -> 404 仅 {error}",
              st == 404 and set(parsed.keys()) == {"error"})
        st, parsed, _ = post_vws(
            c_active, did, payload={}, headers=T2
        )
        check("跨租户 -> 404 仅 {error}",
              st == 404 and set(parsed.keys()) == {"error"})

        # ---- 重验成功但未同步 -> 外部凭证状态未同步 ----
        expect_result(
            "重验成功但未同步 -> 外部凭证状态未同步",
            c_unsynced, did, "外部凭证状态未同步", headers=T1,
        )

        # ---- 同步各类状态后合并判定 ----
        st, _, _ = sync_status(c_active, "active", priv1, headers=T1)
        check("同步 active -> 201", st == 201)
        expect_result("active 同步记录 -> 仅 {valid:true}", c_active, did,
                      None, headers=T1)

        rev_reason = "  持证人违规  "
        st, _, _ = sync_status(c_revoked, "revoked", priv1, reason=rev_reason,
                            headers=T1)
        check("同步 revoked(带 reason) -> 201", st == 201)
        expect_result(
            "revoked 同步记录 -> 外部凭证已吊销：<保存 reason>",
            c_revoked, did, f"外部凭证已吊销：{rev_reason}", headers=T1,
        )

        st, _, _ = sync_status(c_revoked_nr, "revoked", priv1, headers=T1)
        check("同步 revoked(无 reason) -> 201", st == 201)
        expect_result(
            "revoked 无 reason -> 外部凭证已吊销：未知原因",
            c_revoked_nr, did, "外部凭证已吊销：未知原因", headers=T1,
        )

        st, _, _ = sync_status(c_unknown, "unknown", priv1, headers=T1)
        check("同步 unknown -> 201", st == 201)
        expect_result(
            "unknown 同步记录 -> 外部凭证状态未知",
            c_unknown, did, "外部凭证状态未知", headers=T1,
        )

        st, _, _ = sync_status(
            c_v2, "active", priv2, version=2,
            updated="2026-09-22T01:00:00Z", headers=T1,
        )
        check("同步 v2 active -> 201", st == 201)
        expect_result("v2 active -> 仅 {valid:true}", c_v2, did,
                      None, headers=T1)

        # T2 自己的结论不受 T1 状态影响
        expect_result("T2 凭证 active -> 仅 {valid:true}", c_t2, did,
                      None, headers=T2)

        # ---- 锚点吊销：重验失败优先于状态合并 ----
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 v1 锚点 -> 200", st == 200)
        expect_result("v1 吊销后 active 记录仍判锚点不可用", c_active, did,
                      "锚点不可用", headers=T1)
        expect_result("v1 吊销后 revoked 记录仍判锚点不可用", c_revoked, did,
                      "锚点不可用", headers=T1)
        expect_result("v1 吊销后未同步记录判锚点不可用", c_unsynced, did,
                      "锚点不可用", headers=T1)
        expect_result("v1 吊销后 v2 仍有效", c_v2, did,
                      None, headers=T1)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did}/2/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 v2 锚点 -> 200", st == 200)
        expect_result("v2 吊销 -> 锚点不可用", c_v2, did,
                      "锚点不可用", headers=T1)

        # ---- 纯只读：审计不增加、同步状态与导入原文不变 ----
        events_before = audit_events(T1)
        for _ in range(3):
            post_vws(c_active, did, payload={}, headers=T1)
            post_vws(c_revoked, did, payload={}, headers=T1)
            post_vws(c_v2, did, raw=b"not-json", headers=T1)
            post_vws("nope", did, payload={}, headers=T1)
        events_after = audit_events(T1)
        check("各类 verify-with-status 调用不记审计",
              events_after == events_before)

        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credential-status/{c_revoked}"
            f"?issuer_did={did}",
            headers=T1,
        )
        check(
            "只读合并后同步状态记录不变",
            st == 200
            and parsed["status"] == "revoked"
            and parsed["reason"] == rev_reason,
        )
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{c_active}"
            f"?issuer_did={did}",
            headers=T1,
        )
        check(
            "只读合并后导入原文保持不变",
            st == 200
            and parsed.get("body") == make_body(c_active)
            and isinstance(parsed.get("signature"), str),
        )

        # ---- 既有单项重验行为不变 ----
        st, parsed, text = post_plain_verify(c_active, did, headers=T1)
        check(
            "单项 /verify 行为不变（v1 吊销 -> 锚点不可用）",
            st == 200
            and parsed == {"valid": False, "reason": "锚点不可用"}
            and list(json.loads(text).keys()) == ["valid", "reason"],
        )

        # ---- 缺省租户 default：无头也能导入、同步与合并判定 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        body_default = make_body(cred="vc_default_iws")
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_default, "signature": crypto.sign(body_default, priv1)},
        )
        check("缺省租户导入 -> 201", st == 201)
        expect_result(
            "缺省租户未同步 -> 外部凭证状态未同步（无头）",
            "vc_default_iws", did, "外部凭证状态未同步",
        )
        st, _, _ = sync_status(
            "vc_default_iws", "active", priv1,
            updated="2026-09-23T00:00:00Z",
        )
        check("缺省租户同步 active -> 201", st == 201)
        expect_result("缺省租户 active -> 仅 {valid:true}",
                      "vc_default_iws", did, None)

        # ---- 他租户结论稳定 ----
        expect_result("T2 凭证不受 T1 吊销影响", c_t2, did,
                      None, headers=T2)
    finally:
        stop(proc)

    # ---- 重启后：同步状态合并结论跨重启稳定 ----
    proc = start()
    try:
        expect_result("重启后 active 记录判锚点不可用", c_active, did,
                      "锚点不可用", headers=T1)
        expect_result("重启后 v2 记录判锚点不可用", c_v2, did,
                      "锚点不可用", headers=T1)
        expect_result("重启后 T2 凭证仍 active", c_t2, did,
                      None, headers=T2)
        expect_result("重启后 default 凭证仍 active", "vc_default_iws", did,
                      None)

        # 恢复 T1 v1 active 以到达签名/状态合并判定
        data = json.load(open(store_path, encoding="utf-8"))
        anchor_v1 = data["tenants"]["ivws-a"]["trust_anchors"][did]["1"]
        anchor_v1["status"] = "active"
        anchor_v1.pop("updated_at", None)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        # 锚点恢复后：同步状态合并结论仍在
        expect_result("重启恢复锚点后 active -> {valid:true}", c_active, did,
                      None, headers=T1)
        expect_result(
            "重启恢复锚点后 revoked 原因保持", c_revoked, did,
            f"外部凭证已吊销：{rev_reason}", headers=T1,
        )
        expect_result(
            "重启恢复锚点后 revoked 无原因 -> 未知原因", c_revoked_nr, did,
            "外部凭证已吊销：未知原因", headers=T1,
        )
        expect_result(
            "重启恢复锚点后 unknown 保持", c_unknown, did,
            "外部凭证状态未知", headers=T1,
        )

        # 篡改正文（不重签）-> 重验失败优先：签名校验失败
        data = json.load(open(store_path, encoding="utf-8"))
        bucket = data["tenants"]["ivws-a"]["imported_credentials"][did]
        bucket[c_future]["body"]["claims"]["level"] = 999
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后篡改正文 -> 签名校验失败（优先于状态合并）",
            c_future, did, "签名校验失败", headers=T1,
        )

        # 签名格式错误 + 过期：签名格式优先于过期
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivws-a"]["imported_credentials"][did][c_future]
        row["signature"] = "!!!not-base64url!!!"
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后签名格式非法 -> 签名格式错误（优先于过期）",
            c_future, did, "签名格式错误", headers=T1,
        )

        # 用导入者私钥重签已过期正文 -> 凭证已过期
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivws-a"]["imported_credentials"][did][c_future]
        row["body"]["claims"]["level"] = 7
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        row["signature"] = crypto.sign(row["body"], priv1)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后当前时间达到 expires_at -> 凭证已过期",
            c_future, did, "凭证已过期", headers=T1,
        )

        # 删除锚点 -> 锚点不可用
        data = json.load(open(store_path, encoding="utf-8"))
        data["tenants"]["ivws-a"]["trust_anchors"][did].pop("1", None)
        data["tenants"]["ivws-a"]["trust_anchors"][did].pop("2", None)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后锚点缺失 -> 锚点不可用", c_future, did,
            "锚点不可用", headers=T1,
        )
        # 即使 T1 锚点全失，T2 与 default 租户结论不变
        expect_result("T2 凭证始终有效", c_t2, did, None, headers=T2)
        expect_result("default 凭证始终有效", "vc_default_iws", did, None)

        # 既有 GET / 单项 verify 行为不变
        st, _, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{c_active}?issuer_did={did}",
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
