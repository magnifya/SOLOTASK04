#!/usr/bin/env python3
"""已导入外部凭证重新验证端到端测试。

POST /v1/trust/credentials/imported/{credential_id}/verify?issuer_did=...

直接运行：python3 tests/trust_credential_imported_verify_test.py
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


def main():
    port = 8968
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

    def post_verify(credential_id, issuer_did, payload=None, raw=None,
                    headers=None, query_suffix="", use_query=True):
        path = (
            f"/v1/trust/credentials/imported/{credential_id}/verify"
        )
        if use_query:
            path += f"?issuer_did={issuer_did}{query_suffix}"
        return call(
            "POST", path, payload=payload, raw=raw, headers=headers
        )

    def expect_400(name, credential_id, issuer_did, payload=None, raw=None,
                   headers=None, query_suffix="", use_query=True):
        st, parsed, _ = post_verify(
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
        st, parsed, text = post_verify(
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
                and parsed == {"valid": False, "reason": expected_reason},
            )

    def audit_seqs(headers=None):
        st, parsed, _ = call(
            "GET", "/v1/audit?limit=200&after=0", headers=headers
        )
        assert st == 200
        return [event["seq"] for event in parsed["events"]]

    proc = start()
    T1 = {"X-Tenant-ID": "iv-a"}
    T2 = {"X-Tenant-ID": "iv-b"}

    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    did = "did:web:verify-imported.example"
    did_other = "did:web:other-anchor.example"
    cred_id = "vc_iv_0001"
    cred_v2 = "vc_iv_v2"
    cred_future = "vc_iv_future"

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

    try:
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("T1 注册 v1 active 锚点 -> 201", st == 201)

        # 无 issuer_key_version 的凭证（缺省按 1）
        body1 = make_body(version=None)
        sig1 = crypto.sign(body1, priv1)
        st, parsed, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body1, "signature": sig1}, headers=T1,
        )
        check("导入无版本号凭证 -> 201", st == 201)

        # 未来到期凭证（验签成功、未到期）
        body_future = make_body(
            cred=cred_future,
            extra={"expires_at": "2030-01-01T00:00:00Z"},
        )
        sig_future = crypto.sign(body_future, priv1)
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_future, "signature": sig_future}, headers=T1,
        )
        check("导入未来到期凭证 -> 201", st == 201)

        # 锚点轮换到 v2，导入一份 v2 凭证
        st, _, _ = call(
            "POST", f"/v1/trust/anchors/{did}/rotate",
            {"from_key_version": 1, "public_key": pub2}, headers=T1,
        )
        check("锚点轮换 v2 -> 201/200", st in (200, 201))
        body_v2 = make_body(cred=cred_v2, version=2)
        sig_v2 = crypto.sign(body_v2, priv2)
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_v2, "signature": sig_v2}, headers=T1,
        )
        check("导入 v2 凭证 -> 201", st == 201)

        # T2 注册自己的锚点并导入同双键（跨租户隔离）
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1},
            headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        cred_t2 = "vc_iv_t2_only"
        body_t2 = make_body(cred=cred_t2)
        sig_t2 = crypto.sign(body_t2, priv2)
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_t2, "signature": sig_t2}, headers=T2,
        )
        check("T2 导入自有凭证 -> 201", st == 201)

        # ---- 显式空 X-Tenant-ID -> 400 ----
        expect_400(
            "显式空 X-Tenant-ID -> 400",
            cred_id, did, payload={},
            headers={"X-Tenant-ID": ""},
        )

        # ---- 查询参数 issuer_did：缺失/重复/空值 -> 400 ----
        expect_400(
            "缺 issuer_did -> 400", cred_id, did, payload={},
            use_query=False,
        )
        expect_400(
            "issuer_did 重复 -> 400", cred_id, did, payload={},
            query_suffix=f"&issuer_did={did}",
        )
        expect_400(
            "issuer_did 空值 -> 400", cred_id, "", payload={},
        )

        # ---- 请求体必须恰为 {}：空体/非法 JSON/非对象/含字段 -> 400 ----
        expect_400("空请求体 -> 400", cred_id, did, raw=b"")
        expect_400("非法 JSON -> 400", cred_id, did, raw=b"{bad")
        expect_400("JSON 数组 -> 400", cred_id, did, raw=b"[1,2]")
        expect_400("JSON 标量 -> 400", cred_id, did, raw=b'"x"')
        expect_400("含字段对象 -> 400", cred_id, did, payload={"x": 1})
        expect_400("含空字段对象 -> 400", cred_id, did, payload={"": ""})

        # ---- 记录查找：不存在 / issuer_did 错配 / 跨租户 -> 404 ----
        st, parsed, _ = post_verify(
            "vc_not_imported", did, payload={}, headers=T1
        )
        check(
            "未导入凭证 -> 404 仅 {error}",
            st == 404 and set(parsed.keys()) == {"error"} and parsed["error"],
        )
        st, parsed, _ = post_verify(
            cred_id, did_other, payload={}, headers=T1
        )
        check("issuer_did 错配 -> 404", st == 404)
        st, parsed, _ = post_verify(
            cred_id, did, payload={}, headers=T2
        )
        check("跨租户 -> 404", st == 404)

        # ---- 成功：仅 {"valid": true} ----
        expect_result("无版本凭证重验成功（缺省 v1）", cred_id, did,
                      None, headers=T1)
        expect_result("v2 凭证用 v2 active 锚点重验成功", cred_v2, did,
                      None, headers=T1)
        expect_result("未来到期凭证重验成功", cred_future, did,
                      None, headers=T1)

        # ---- 吊销 v1：v1 凭证锚点不可用，v2 凭证不受影响 ----
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 v1 锚点 -> 200", st == 200)
        expect_result("v1 锚点吊销 -> 锚点不可用", cred_id, did,
                      "锚点不可用", headers=T1)
        expect_result("v1 吊销后 v2 仍有效", cred_v2, did,
                      None, headers=T1)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did}/2/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 v2 锚点 -> 200", st == 200)
        expect_result("v2 锚点吊销 -> 锚点不可用", cred_v2, did,
                      "锚点不可用", headers=T1)

        # ---- 纯只读：审计不增加、导入原文不变 ----
        seqs_before = audit_seqs(T1)
        for _ in range(3):
            post_verify(cred_id, did, payload={}, headers=T1)
            post_verify(cred_v2, did, raw=b"not-json", headers=T1)
            post_verify("nope", did, payload={}, headers=T1)
        seqs_after = audit_seqs(T1)
        check("各类验证调用不记审计", seqs_after == seqs_before)
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{cred_id}"
            f"?issuer_did={did}",
            headers=T1,
        )
        check(
            "只读验证后导入原文保持不变",
            st == 200
            and parsed.get("body") == body1
            and parsed.get("signature") == sig1,
        )

        # ---- 缺省租户 default：无头也能导入与重验 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        body_default = make_body(cred="vc_default_iv")
        # default 租户 v1 锚点公钥为 pub1（吊销状态仅存在于 T1）
        sig_default = crypto.sign(body_default, priv1)
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_default, "signature": sig_default},
        )
        check("缺省租户导入 -> 201", st == 201)
        expect_result("缺省租户重验成功（无头）", "vc_default_iv", did, None)

        # ---- 他租户结论稳定：T2 自己的凭证仍有效 ----
        expect_result("T2 凭证不受 T1 吊销影响", cred_t2, did,
                      None, headers=T2)
    finally:
        stop(proc)

    # ---- 重启后：落盘凭证重新验证，结论稳定 ----
    proc = start()
    try:
        expect_result("重启后 v1 凭证仍判锚点不可用", cred_id, did,
                      "锚点不可用", headers=T1)
        expect_result("重启后 v2 凭证仍判锚点不可用", cred_v2, did,
                      "锚点不可用", headers=T1)
        expect_result("重启后未来到期凭证随 v1 吊销判锚点不可用",
                      cred_future, did, "锚点不可用", headers=T1)
        expect_result("重启后 T2 凭证仍有效", cred_t2, did,
                      None, headers=T2)
        expect_result("重启后 default 凭证仍有效", "vc_default_iv", did,
                      None)

        # 直接改写落盘记录，模拟重启后对原文的重新验证：
        # 先恢复 T1 v1 为 active（解除吊销，以便到达签名/过期判定），
        # 再篡改 cred_future 正文（不重签）-> 签名校验失败
        data = json.load(open(store_path, encoding="utf-8"))
        anchor_v1 = data["tenants"]["iv-a"]["trust_anchors"][did]["1"]
        anchor_v1["status"] = "active"
        anchor_v1.pop("updated_at", None)
        bucket = data["tenants"]["iv-a"]["imported_credentials"][did]
        bucket[cred_future]["body"]["claims"]["level"] = 999
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后篡改正文 -> 签名校验失败", cred_future, did,
            "签名校验失败", headers=T1,
        )

        # 2) 签名格式错误 + 过期但签名失败优先于过期
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["iv-a"]["imported_credentials"][did][
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

        # 3) 用导入者私钥对“已过期”正文重新签名 -> 凭证已过期
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["iv-a"]["imported_credentials"][did][
            cred_future
        ]
        row["body"]["claims"]["level"] = 7
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        row["signature"] = crypto.sign(row["body"], priv1)
        # T1 v1 已吊销 -> 先恢复一个 active 锚点以到达过期判定
        data["tenants"]["iv-a"]["trust_anchors"][did]["1"]["status"] = (
            "active"
        )
        data["tenants"]["iv-a"]["trust_anchors"][did]["1"].pop(
            "updated_at", None
        )
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后当前时间达到 expires_at -> 凭证已过期",
            cred_future, did, "凭证已过期", headers=T1,
        )

        # 4) 删除锚点 -> 锚点不可用（缺失与吊销同因）
        data = json.load(open(store_path, encoding="utf-8"))
        data["tenants"]["iv-a"]["trust_anchors"][did].pop("1", None)
        data["tenants"]["iv-a"]["trust_anchors"][did].pop("2", None)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        expect_result(
            "重启后锚点缺失 -> 锚点不可用", cred_future, did,
            "锚点不可用", headers=T1,
        )
        # import 与 GET 既有行为不变
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{cred_id}?issuer_did={did}",
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
