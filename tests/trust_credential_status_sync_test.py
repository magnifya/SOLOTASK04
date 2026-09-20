#!/usr/bin/env python3
"""外部凭证状态同步端点的端到端测试。

覆盖：
- POST /v1/trust/credential-status/sync：请求/body 校验 400；锚点、
  签名格式、签名校验三类失败均 200/valid:false（中文前缀）且不写入、
  不记审计；首次 201；相同重放 200 不重复审计；严格时间更新才替换；
  同时间不同内容 409；旧时间忽略；成功记 trust.credential.status.synced
  （resource_id 为 issuer_did#credential_id）；不影响既有凭证状态。
- GET /v1/trust/credential-status/{credential_id}?issuer_did=...：
  参数唯一非空，已同步返回 status/reason/updated_at，未同步 404，
  跨租户不可探测。
- 按租户双键隔离、跨重启保留、落盘失败回滚。

直接运行：python3 tests/trust_credential_status_sync_test.py
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
from vcbackend.store import VCStore  # noqa: E402

_DELETE = object()


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
    port = 8954
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    sync_path = "/v1/trust/credential-status/sync"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def expect_400(name, payload=None, headers=None, raw=None):
        st, r = _http("POST", f"{base}{sync_path}",
                      payload=payload, raw=raw, headers=headers)
        check(name, st == 400
              and isinstance(r.get("error"), str) and r["error"])

    def invalid_with_prefix(name, prefix, payload, headers=None):
        st, r = _http("POST", f"{base}{sync_path}", payload, headers=headers)
        check(
            name,
            st == 200
            and r.get("valid") is False
            and isinstance(r.get("reason"), str)
            and r["reason"]
            and r["reason"].startswith(prefix),
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tcs-a"}
        T2 = {"X-Tenant-ID": "tcs-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:status.example"
        cid = "vc_status_0001"

        # 显式空租户头仍按通用协议 400（在进入流程前判定）
        st, _ = _http("POST", f"{base}{sync_path}",
                      {"body": {}, "signature": "x"},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册状态锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册状态锚点 v2 -> 201", st == 201)

        def make_body(ts="2026-09-20T00:00:00Z", status="active",
                      reason=_DELETE, version=1, credential_id=cid,
                      issuer=did):
            b = {
                "issuer_did": issuer,
                "credential_id": credential_id,
                "status": status,
                "updated_at": ts,
                "issuer_key_version": version,
            }
            if reason is not _DELETE:
                b["reason"] = reason
            return b

        # ------------------------------------------------------------ #
        # 1. 请求层 400
        # ------------------------------------------------------------ #
        body_v2 = make_body(version=2)
        sig_ok = crypto.sign(body_v2, priv2)
        expect_400("空请求体", raw=b"")
        expect_400("非法 JSON", raw=b"not-json")
        expect_400("JSON 数组非对象", raw=b"[1,2]")
        expect_400("缺 body", {"signature": sig_ok}, T1)
        expect_400("缺 signature", {"body": body_v2}, T1)
        expect_400("顶层多余字段",
                   {"body": body_v2, "signature": sig_ok, "extra": 1}, T1)
        expect_400("空对象", {}, T1)
        expect_400("body 为数组", {"body": [], "signature": sig_ok}, T1)
        expect_400("body 为字符串", {"body": "x", "signature": sig_ok}, T1)
        expect_400("body 为 null", {"body": None, "signature": sig_ok}, T1)
        expect_400("signature 为空串",
                   {"body": body_v2, "signature": ""}, T1)
        expect_400("signature 为数字",
                   {"body": body_v2, "signature": 123}, T1)

        # ------------------------------------------------------------ #
        # 2. body 字段 400
        # ------------------------------------------------------------ #
        def body_with(**changes):
            b = json.loads(json.dumps(body_v2))
            for key, value in changes.items():
                if value is _DELETE:
                    b.pop(key, None)
                else:
                    b[key] = value
            return b

        for field in ("issuer_did", "credential_id", "status",
                      "updated_at", "issuer_key_version"):
            expect_400(f"body 缺字段 {field}",
                       {"body": body_with(**{field: _DELETE}),
                        "signature": sig_ok}, T1)
        for field in ("issuer_did", "credential_id"):
            expect_400(f"body {field} 为空串",
                       {"body": body_with(**{field: ""}),
                        "signature": sig_ok}, T1)
            expect_400(f"body {field} 为数字",
                       {"body": body_with(**{field: 1}),
                        "signature": sig_ok}, T1)
        for bad_status in ("", "revoked ", "VALID", "active ", 1, None):
            expect_400(f"body status 非法 {bad_status!r}",
                       {"body": body_with(status=bad_status),
                        "signature": sig_ok}, T1)
        for bad_ts in [
            "2026-09-20T00:00:00",      # 无 Z
            "2026-09-20 00:00:00Z",     # 空格分隔
            "2026-09-20T00:00:00.5Z",   # 小数秒
            "2026-09-20T00:00:00+00:00",  # 偏移
            "2026-9-20T00:00:00Z",      # 非零填充
            "2026-13-20T00:00:00Z",     # 非法月份
            "", 123, None,
        ]:
            expect_400(f"body updated_at 非法 {bad_ts!r}",
                       {"body": body_with(updated_at=bad_ts),
                        "signature": sig_ok}, T1)
        for bad_version, label in [
            (True, "布尔 true"), (False, "布尔 false"), (0, "零"),
            (-1, "负数"), (1.5, "小数"), ("1", "字符串"), (None, "null"),
        ]:
            expect_400(f"body issuer_key_version 非法（{label}）",
                       {"body": body_with(issuer_key_version=bad_version),
                        "signature": sig_ok}, T1)
        expect_400("body reason 为空串",
                   {"body": body_with(reason=""), "signature": sig_ok}, T1)
        expect_400("body reason 为数字",
                   {"body": body_with(reason=1), "signature": sig_ok}, T1)
        expect_400("body 多余字段",
                   {"body": body_with(extra=1), "signature": sig_ok}, T1)

        # ------------------------------------------------------------ #
        # 3. 锚点失败（200/valid:false，前缀“锚点”，不写入）
        # ------------------------------------------------------------ #
        body_unknown = make_body(issuer="did:web:nope.example")
        sig_unknown = crypto.sign(body_unknown, priv1)
        invalid_with_prefix("未知签发者锚点", "锚点",
                            {"body": body_unknown, "signature": sig_unknown},
                            T1)
        body_v9 = make_body(version=9)
        invalid_with_prefix("未知版本锚点（v9）", "锚点",
                            {"body": body_v9,
                             "signature": crypto.sign(body_v9, priv2)}, T1)
        # 锚点查找先于签名校验：坏签名仍返回“锚点”
        invalid_with_prefix("锚点校验优先于签名格式", "锚点",
                            {"body": body_unknown, "signature": "!!!bad!!!"},
                            T1)
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        body_v1 = make_body(version=1)
        invalid_with_prefix("已吊销锚点", "锚点",
                            {"body": body_v1,
                             "signature": crypto.sign(body_v1, priv1)}, T1)

        # ------------------------------------------------------------ #
        # 4. 签名格式 / 校验失败（v2 仍 active）
        # ------------------------------------------------------------ #
        invalid_with_prefix("非 base64url 签名", "签名格式错误",
                            {"body": body_v2, "signature": "!!!not-b64!!!"},
                            T1)
        too_short = sig_ok[:-2]
        invalid_with_prefix("签名长度不足", "签名格式错误",
                            {"body": body_v2, "signature": too_short}, T1)
        invalid_with_prefix("错误私钥签名", "签名校验失败",
                            {"body": body_v2,
                             "signature": crypto.sign(body_v2, priv1)}, T1)
        tampered = json.loads(json.dumps(body_v2))
        tampered["status"] = "revoked"
        invalid_with_prefix("篡改 body 状态", "签名校验失败",
                            {"body": tampered, "signature": sig_ok}, T1)
        # 用另一把未注册公钥对应的私钥
        priv_other = ec.generate_private_key(ec.SECP256R1())
        priv_other_pem = priv_other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        invalid_with_prefix("未注册私钥签名", "签名校验失败",
                            {"body": body_v2,
                             "signature": crypto.sign(body_v2,
                                                      priv_other_pem)}, T1)

        # 失败均不写入：GET 404
        from urllib.parse import quote
        get_url = (f"{base}/v1/trust/credential-status/{cid}"
                   f"?issuer_did={quote(did)}")
        st, _ = _http("GET", get_url, headers=T1)
        check("全部失败后状态未同步（GET 404）", st == 404)

        # ------------------------------------------------------------ #
        # 5. 首次同步 201
        # ------------------------------------------------------------ #
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_v2, "signature": sig_ok}, T1)
        check("首次同步 -> 201 valid:true",
              st == 201 and r.get("valid") is True
              and r.get("status") == "active"
              and r.get("updated_at") == "2026-09-20T00:00:00Z"
              and r.get("issuer_key_version") == 2
              and r.get("issuer_did") == did
              and r.get("credential_id") == cid
              and r.get("reason") is None)

        # GET 返回恰为 status/reason/updated_at
        st, r = _http("GET", get_url, headers=T1)
        check("GET 已同步状态字段恰为 status/reason/updated_at",
              st == 200 and r == {
                  "status": "active",
                  "reason": None,
                  "updated_at": "2026-09-20T00:00:00Z",
              })

        # ------------------------------------------------------------ #
        # 6. 相同重放 200，不重复审计
        # ------------------------------------------------------------ #
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": json.loads(json.dumps(body_v2)),
                       "signature": crypto.sign(body_v2, priv2)}, T1)
        check("相同重放 -> 200",
              st == 200 and r.get("valid") is True
              and r.get("status") == "active")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        synced_events = [
            e for e in audit["events"]
            if e["action"] == "trust.credential.status.synced"
        ]
        check("重放不重复审计", len(synced_events) == 1)
        check("审计 resource_id/type 正确",
              synced_events[0]["resource_id"] == f"{did}#{cid}"
              and synced_events[0]["resource_type"]
              == "trust_credential_status"
              and synced_events[0]["tenant_id"] == "tcs-a")

        # ------------------------------------------------------------ #
        # 7. 同时间不同内容 -> 409；旧时间忽略；新时间替换
        # ------------------------------------------------------------ #
        body_conflict = make_body(status="revoked", version=2)
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_conflict,
                       "signature": crypto.sign(body_conflict, priv2)}, T1)
        check("同 updated_at 不同内容 -> 409", st == 409
              and isinstance(r.get("error"), str) and r["error"])
        st, r = _http("GET", get_url, headers=T1)
        check("409 不改变已存状态", st == 200 and r["status"] == "active")

        body_old = make_body(ts="2026-09-19T00:00:00Z", status="revoked",
                             reason="old", version=2)
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_old,
                       "signature": crypto.sign(body_old, priv2)}, T1)
        check("旧时间消息 -> 200 且返回既有记录",
              st == 200 and r.get("valid") is True
              and r.get("status") == "active"
              and r.get("updated_at") == "2026-09-20T00:00:00Z")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("旧时间不记审计",
              len([e for e in audit["events"]
                   if e["action"] == "trust.credential.status.synced"]) == 1)

        body_new = make_body(ts="2026-09-21T00:00:00Z", status="revoked",
                             reason="持证人资料造假", version=2)
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_new,
                       "signature": crypto.sign(body_new, priv2)}, T1)
        check("新时间替换 -> 200",
              st == 200 and r.get("status") == "revoked"
              and r.get("reason") == "持证人资料造假"
              and r.get("updated_at") == "2026-09-21T00:00:00Z")
        st, r = _http("GET", get_url, headers=T1)
        check("GET 返回替换后状态",
              st == 200 and r["status"] == "revoked"
              and r["reason"] == "持证人资料造假"
              and r["updated_at"] == "2026-09-21T00:00:00Z")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("替换记第二条审计",
              len([e for e in audit["events"]
                   if e["action"] == "trust.credential.status.synced"]) == 2)

        # unknown/active 也合法；reason 可省略
        body_unknown_status = make_body(
            ts="2026-09-22T00:00:00Z", status="unknown", reason=_DELETE,
            version=2)
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_unknown_status,
                       "signature": crypto.sign(body_unknown_status, priv2)},
                      T1)
        check("status=unknown 且无 reason 同步成功",
              st == 200 and r.get("status") == "unknown"
              and r.get("reason") is None)

        # ------------------------------------------------------------ #
        # 8. GET 参数校验与 404/跨租户
        # ------------------------------------------------------------ #
        base_get = f"{base}/v1/trust/credential-status/{cid}"
        st, _ = _http("GET", base_get, headers=T1)
        check("缺 issuer_did -> 400", st == 400)
        st, _ = _http("GET", f"{base_get}?issuer_did=", headers=T1)
        check("空 issuer_did -> 400", st == 400)
        st, _ = _http("GET",
                      f"{base_get}?issuer_did={quote(did)}&issuer_did=x",
                      headers=T1)
        check("重复 issuer_did -> 400", st == 400)
        st, _ = _http("GET",
                      f"{base_get}?issuer_did={quote(did)}&other=1",
                      headers=T1)
        check("多余查询参数 -> 400", st == 400)
        st, _ = _http("GET",
                      f"{base}/v1/trust/credential-status/nope"
                      f"?issuer_did={quote(did)}", headers=T1)
        check("未同步 credential_id -> 404", st == 404)
        st, _ = _http("GET",
                      f"{base_get}?issuer_did={quote('did:web:nope')}",
                      headers=T1)
        check("未同步 issuer_did -> 404", st == 404)
        # 跨租户不可探测
        st, _ = _http("GET", get_url, headers=T2)
        check("跨租户 GET -> 404", st == 404)

        # ------------------------------------------------------------ #
        # 9. 双键租户隔离：同 credential_id 不同 issuer_did 各自独立；
        #    外部同步不影响本租户既有凭证状态、不创建凭证
        # ------------------------------------------------------------ #
        other_priv = ec.generate_private_key(ec.SECP256R1())
        other_priv_pem = other_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        other_pub_pem = other_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        other_issuer = "did:web:other-issuer.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": other_issuer, "public_key": other_pub_pem,
                       "key_version": 1}, headers=T1)
        assert st == 201
        body_other = make_body(ts="2026-09-20T00:00:00Z", status="active",
                               issuer=other_issuer, version=1)
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_other,
                       "signature": crypto.sign(body_other, other_priv_pem)},
                      T1)
        check("同 credential_id 不同 issuer 首次同步 -> 201", st == 201)
        st, r = _http("GET", get_url, headers=T1)
        check("原 issuer 记录不受影响",
              st == 200 and r["status"] == "unknown")

        # 外部同步不创建本租户凭证
        st, _ = _http("GET", f"{base}/v1/credentials/{cid}", headers=T1)
        check("外部状态同步不创建凭证（404）", st == 404)

        # 本租户既有凭证状态不受影响：签发一张凭证并登记 active，
        # 外部状态表的任何变化都不触及它
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "issuer-handle"},
                      T1)
        assert st == 201
        issuer_local = r["did"]
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "subject-handle"},
                      T1)
        assert st == 201
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": issuer_local,
                       "subject_did": r["did"],
                       "claims": {"role": "admin"}}, T1)
        assert st == 201
        local_cid = r["credential_id"]
        st, r = _http("PUT",
                      f"{base}/v1/credentials/{local_cid}/status",
                      {"status": "active"}, T1)
        check("本地凭证登记 active -> 201", st == 201)
        st, r = _http("GET",
                      f"{base}/v1/credentials/{local_cid}/status",
                      headers=T1)
        check("外部同步后本地凭证状态保持 active",
              st == 200 and r["status"] == "active")

        # ------------------------------------------------------------ #
        # 10. 失败路径不记审计（锚点/签名各打若干次）
        # ------------------------------------------------------------ #
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            _http("POST", f"{base}{sync_path}",
                  {"body": body_unknown, "signature": sig_unknown}, T1)
            _http("POST", f"{base}{sync_path}",
                  {"body": body_v2, "signature": "bad"}, T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("锚点/签名失败不记审计", len(after["events"]) == n_before)

        # ------------------------------------------------------------ #
        # 11. 跨租户：T2 同步同双键互不干扰，且需 T2 自己的锚点
        # ------------------------------------------------------------ #
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册自己的同 DID 锚点 -> 201", st == 201)
        body_t2 = make_body(ts="2026-10-01T00:00:00Z", status="revoked",
                            reason="t2 reason", version=2)
        st, r = _http("POST", f"{base}{sync_path}",
                      {"body": body_t2,
                       "signature": crypto.sign(body_t2, priv1)}, T2)
        check("T2 首次同步 -> 201", st == 201)
        st, r = _http("GET", get_url, headers=T1)
        check("T2 同步不影响 T1 记录",
              st == 200 and r["status"] == "unknown"
              and r["updated_at"] == "2026-09-22T00:00:00Z")
        st, r = _http("GET", get_url, headers=T2)
        check("T2 返回自己的记录",
              st == 200 and r["status"] == "revoked"
              and r["reason"] == "t2 reason"
              and r["updated_at"] == "2026-10-01T00:00:00Z")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ------------------------------------------------------------ #
    # 12. 跨重启：外部状态与审计保留
    # ------------------------------------------------------------ #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tcs-a"}
        from urllib.parse import quote
        get_url = (f"{base}/v1/trust/credential-status/{cid}"
                   f"?issuer_did={quote(did)}")
        st, r = _http("GET", get_url, headers=T1)
        check("重启后 T1 外部状态保留",
              st == 200 and r["status"] == "unknown"
              and r["updated_at"] == "2026-09-22T00:00:00Z")
        st, r = _http("GET", get_url, headers={"X-Tenant-ID": "tcs-b"})
        check("重启后 T2 外部状态保留",
              st == 200 and r["status"] == "revoked")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("重启后审计事件保留",
              len([e for e in audit["events"]
                   if e["action"] == "trust.credential.status.synced"]) == 4)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ------------------------------------------------------------ #
    # 13. 落盘失败：内存回滚，状态不生效且审计不记录
    # ------------------------------------------------------------ #
    rollback_path = tempfile.mktemp(suffix=".json")
    try:
        rs = VCStore(rollback_path)
        rpriv, rpub = gen_keypair()
        rs.register_trust_anchor("rollback", did, rpub, 1)
        rbody = make_body(ts="2026-09-20T00:00:00Z", version=1)
        rsig = crypto.sign(rbody, rpriv)

        def _boom():
            raise OSError("模拟落盘失败")

        rs._save_locked = _boom  # type: ignore[assignment]
        try:
            rs.sync_external_credential_status("rollback", rbody, rsig)
            check("落盘失败时同步抛错", False)
        except OSError:
            check("落盘失败时同步抛错", True)
        events, _ = rs.list_audit("rollback", 0, 50)
        # 注册锚点那条审计也因回滚而不存在（register 先成功落过一次盘，
        # 之后被 _boom 替换；此处只关心 synced 未记录）
        check("落盘失败不记 synced 审计",
              all(e.action != "trust.credential.status.synced"
                  for e in events))
        try:
            rs.get_external_credential_status("rollback", did, cid)
            check("落盘失败状态不生效", False)
        except Exception as exc:
            check("落盘失败状态不生效（NotFoundError）",
                  type(exc).__name__ == "NotFoundError")
    finally:
        if os.path.exists(rollback_path):
            os.remove(rollback_path)

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
