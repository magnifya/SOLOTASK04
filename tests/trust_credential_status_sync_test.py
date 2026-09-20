#!/usr/bin/env python3
"""外部凭证状态同步 POST /v1/trust/credential-status/sync 与
GET /v1/trust/credential-status/{credential_id}?issuer_did=... 的端到端测试。

直接运行：python3 tests/trust_credential_status_sync_test.py
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
from vcbackend.store import VCStore  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/sync"


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


def wait_up(proc, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
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
    port = 8957
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def sync(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{SYNC_PATH}", payload,
                     headers=headers, raw=raw)

    def get_status(credential_id, headers=None, query=None):
        url = f"{base}/v1/trust/credential-status/{quote(credential_id)}"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tcs-a"}
        T2 = {"X-Tenant-ID": "tcs-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:issuer.example"
        cred_id = "vc_external_status_1"

        # 显式空租户头在进入同步前判 400
        st, _ = sync({"body": {}, "signature": "x"},
                     headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T1,
        )
        check("注册锚点 v1 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 2}, headers=T1,
        )
        check("注册锚点 v2 -> 201", st == 201)

        def make_body(credential_id=cred_id, status="active",
                      updated="2026-09-21T00:00:00Z", version=1,
                      reason=_UNSET, issuer=did):
            b = {
                "issuer_did": issuer,
                "credential_id": credential_id,
                "status": status,
                "updated_at": updated,
                "issuer_key_version": version,
            }
            if reason is not _UNSET:
                b["reason"] = reason
            return b

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        # ---- 1. 首次同步 201 ----
        body = make_body()
        st, r = sync(signed(body), headers=T1)
        check(
            "首次同步 -> 201 且字段齐全",
            st == 201
            and r == {
                "issuer_did": did,
                "credential_id": cred_id,
                "status": "active",
                "reason": None,
                "updated_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            },
        )

        # ---- 2. 相同重放 200，且不重复审计 ----
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        st, r = sync(signed(make_body()), headers=T1)
        check("相同重放 -> 200 且内容不变",
              st == 200 and r["status"] == "active"
              and r["updated_at"] == "2026-09-21T00:00:00Z")
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("相同重放不重复审计",
              len(audit_after["events"]) == n_before)
        synced_events = [
            e for e in audit_after["events"]
            if e["action"] == "trust.credential.status.synced"
        ]
        check(
            "审计 action/resource_type/resource_id 正确",
            len(synced_events) == 1
            and synced_events[0]["resource_type"]
            == "trust_credential_status"
            and synced_events[0]["resource_id"] == f"{did}#{cred_id}",
        )

        # ---- 3. 同 updated_at 不同内容 -> 409，不写入不审计 ----
        for changed, signer in (
            (make_body(status="revoked"), priv1),
            # version=2 的锚点公钥是 pub2，须用 priv2 签名才能到达 409
            # （否则会先在签名校验阶段返回 200/valid:false）
            (make_body(version=2), priv2),
            (make_body(reason="some reason"), priv1),
        ):
            st, r = sync(signed(changed, signer), headers=T1)
            check("同时间不同内容 -> 409", st == 409 and r.get("error"))
        st, r = get_status(cred_id, headers=T1,
                           query=f"issuer_did={quote(did)}")
        check("409 不改变已存状态",
              st == 200 and r["status"] == "active" and r["reason"] is None)
        st, audit_after2 = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        check("409 不记审计",
              len(audit_after2["events"]) == len(audit_after["events"]))

        # ---- 4. 时间严格更新才替换（200 并记审计）----
        body_rev = make_body(
            status="revoked", updated="2026-09-22T00:00:00Z",
            version=2, reason="  持证人违规  ",
        )
        st, r = sync(signed(body_rev, priv2), headers=T1)
        check(
            "严格更新 -> 200，替换为 revoked（reason 原样保留）",
            st == 200 and r["status"] == "revoked"
            and r["updated_at"] == "2026-09-22T00:00:00Z"
            and r["issuer_key_version"] == 2
            and r["reason"] == "  持证人违规  ",
        )
        st, r = get_status(cred_id, headers=T1,
                           query=f"issuer_did={quote(did)}")
        check(
            "GET 已同步返回 status/reason/updated_at（恰三字段）",
            st == 200 and set(r) == {"status", "reason", "updated_at"}
            and r == {
                "status": "revoked",
                "reason": "  持证人违规  ",
                "updated_at": "2026-09-22T00:00:00Z",
            },
        )

        # ---- 5. 更早的 updated_at 被忽略：保持新值、不记审计 ----
        st, audit_before3 = _http("GET", f"{base}/v1/audit?limit=200",
                                  headers=T1)
        n3 = len(audit_before3["events"])
        body_old = make_body(status="active",
                             updated="2020-01-01T00:00:00Z")
        st, r = sync(signed(body_old, priv1), headers=T1)
        check("更早状态被忽略 -> 200 且保持现有值",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == "2026-09-22T00:00:00Z")
        st, audit_after3 = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        check("更早状态不记审计", len(audit_after3["events"]) == n3)

        # 新值重放（revoked 原样）200 不重复审计
        st, r = sync(signed(body_rev, priv2), headers=T1)
        check("新值相同重放 -> 200",
              st == 200 and r["status"] == "revoked")
        st, audit_after4 = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        check("新值重放不重复审计",
              len(audit_after4["events"]) == len(audit_after3["events"]))

        # ---- 6. status=unknown 合法（另一凭证）----
        body_unk = make_body(credential_id="vc_ext_u", status="unknown",
                             updated="2026-09-23T00:00:00Z")
        st, r = sync(signed(body_unk, priv1), headers=T1)
        check("unknown 首次同步 -> 201",
              st == 201 and r["status"] == "unknown" and r["reason"] is None)

        # ---- 7. GET 参数校验 ----
        st, r = get_status(cred_id, headers=T1)
        check("缺 issuer_did -> 400", st == 400 and r.get("error"))
        st, r = get_status(cred_id, headers=T1,
                           query="issuer_did=a&issuer_did=b")
        check("重复 issuer_did -> 400", st == 400 and r.get("error"))
        st, r = get_status(cred_id, headers=T1, query="issuer_did=")
        check("空 issuer_did -> 400", st == 400 and r.get("error"))

        # ---- 8. 未同步 / 跨租户不可探测 ----
        st, r = get_status("vc_not_synced", headers=T1,
                           query=f"issuer_did={quote(did)}")
        check("未同步凭证 -> 404", st == 404)
        st, r = get_status(cred_id, headers=T1,
                           query="issuer_did=did:web:other.example")
        check("未知 issuer 双键 -> 404", st == 404)
        st, r = get_status(cred_id, headers=T2,
                           query=f"issuer_did={quote(did)}")
        check("跨租户不可探测 -> 404", st == 404)

        # ---- 9. 锚点 / 签名失败：HTTP 200 valid:false，前缀分类，不写入 ----
        st, n_audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_fail_before = len(n_audit["events"])

        body_fresh = make_body(
            credential_id="vc_ext_fail", status="revoked",
            updated="2026-09-24T00:00:00Z",
        )
        # T2 无该锚点 -> 锚点
        st, r = sync(signed(body_fresh, priv1), headers=T2)
        check("无锚点 -> 200 valid:false 前缀锚点",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        # T1 吊销 v1 -> 锚点（吊销）
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        st, r = sync(signed(body_fresh, priv1), headers=T1)
        check("已吊销锚点 -> 200 valid:false 前缀锚点",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))
        # 锚点校验先于签名：坏签名 + 吊销锚点仍前缀锚点
        st, r = sync({"body": body_fresh, "signature": "!!!bad!!!"},
                     headers=T1)
        check("锚点优先于签名格式",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))

        # v2 仍 active：签名格式错误
        body_v2 = make_body(
            credential_id="vc_ext_fail", status="revoked",
            updated="2026-09-24T00:00:00Z", version=2,
        )
        st, r = sync({"body": body_v2, "signature": "!!!bad!!!"},
                     headers=T1)
        check("签名格式错误 -> 前缀签名格式错误",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名格式错误"))
        # 密码学验签失败（v1 私钥签 v2 正文）
        st, r = sync(signed(body_v2, priv1), headers=T1)
        check("签名校验失败 -> 前缀签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 篡改 body
        tampered = json.loads(json.dumps(body_v2))
        tampered["status"] = "unknown"
        st, r = sync({"body": tampered,
                      "signature": crypto.sign(body_v2, priv2)}, headers=T1)
        check("篡改正文 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # 失败均未写入、未记审计
        st, r = get_status("vc_ext_fail", headers=T1,
                           query=f"issuer_did={quote(did)}")
        check("验签失败不写入（GET 404）", st == 404)
        st, n_audit2 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("锚点/签名失败不记审计",
              len(n_audit2["events"]) == n_fail_before + 1)  # 仅多一条吊销审计

        # ---- 10. 请求 / 字段校验 -> 400 ----
        def expect_400(name, payload=None, raw=None):
            st, r = sync(payload=payload, raw=raw, headers=T1)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        expect_400("空请求体", raw=b"")
        expect_400("非法 JSON", raw=b"not-json")
        expect_400("JSON 非对象（数组）", raw=b"[1]")
        expect_400("缺 body", {"signature": "x"})
        expect_400("缺 signature", {"body": make_body(version=2)})
        expect_400("顶层多余字段",
                   {"body": make_body(version=2), "signature": "x", "z": 1})
        expect_400("body 非对象", {"body": [], "signature": "x"})
        expect_400("signature 空串",
                   {"body": make_body(version=2), "signature": ""})
        expect_400("signature 非字符串",
                   {"body": make_body(version=2), "signature": 1})

        def body_400(**changes):
            b = json.loads(json.dumps(make_body(version=2)))
            for key, value in changes.items():
                if value is _DELETE:
                    b.pop(key, None)
                else:
                    b[key] = value
            return {"body": b, "signature": "x"}

        for field in ("issuer_did", "credential_id", "status",
                      "updated_at", "issuer_key_version"):
            expect_400(f"body 缺字段 {field}",
                       body_400(**{field: _DELETE}))
        expect_400("body 多余字段", body_400(extra=1))
        expect_400("issuer_did 空串", body_400(issuer_did=""))
        expect_400("issuer_did 非字符串", body_400(issuer_did=1))
        expect_400("credential_id 空串", body_400(credential_id=""))
        expect_400("status 非法枚举", body_400(status="revoked "))
        expect_400("status 非字符串", body_400(status=1))
        expect_400("updated_at 空串", body_400(updated_at=""))
        for bad_time, label in [
            ("2026-09-21 00:00:00", "空格分隔"),
            ("2026-09-21T00:00:00.5Z", "带毫秒"),
            ("2026-09-21T00:00:00+00:00", "偏移量"),
            ("2026-09-21", "仅日期"),
            ("2026-09-21T24:00:00Z", "非法时刻"),
            (20260921, "非字符串"),
        ]:
            expect_400(f"updated_at 非法（{label}）",
                       body_400(updated_at=bad_time))
        for bad_v, label in [
            (True, "布尔 true"), (False, "布尔 false"),
            (0, "零"), (-1, "负数"), (1.0, "浮点 1.0"),
            ("1", "字符串"),
        ]:
            expect_400(f"issuer_key_version 非法（{label}）",
                       body_400(issuer_key_version=bad_v))
        expect_400("reason 空串", body_400(reason=""))
        expect_400("reason 非字符串", body_400(reason=123))

        # 校验失败不记审计
        st, n_audit3 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("400 校验失败不记审计",
              len(n_audit3["events"]) == len(n_audit2["events"]))

        # ---- 11. 跨租户双键隔离：T2 用自己的锚点独立同步同双键 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T2,
        )
        check("T2 注册自己的同 DID 锚点 -> 201", st == 201)
        body_t2 = make_body(status="revoked",
                            updated="2026-09-25T00:00:00Z")
        st, r = sync(signed(body_t2, priv1), headers=T2)
        check("T2 独立首次同步同双键 -> 201",
              st == 201 and r["status"] == "revoked")
        # T1 视图不受影响（T1 该凭证仍为 2026-09-22 的 revoked）
        st, r = get_status(cred_id, headers=T1,
                           query=f"issuer_did={quote(did)}")
        check("T1 视图不受 T2 同步影响",
              st == 200 and r["updated_at"] == "2026-09-22T00:00:00Z")
        st, r = get_status(cred_id, headers=T2,
                           query=f"issuer_did={quote(did)}")
        check("T2 视图为自身同步值",
              st == 200 and r["updated_at"] == "2026-09-25T00:00:00Z")

        # ---- 12. 同步不改变既有（本租户）凭证状态 ----
        # 签发一张本租户凭证并登记 active；外部同名状态同步是独立命名空间。
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "local-handle"},
                      headers=T1)
        local_did = r["did"]
        st, r = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": local_did, "subject_did": local_did,
             "claims": {"k": "v"}},
            headers=T1,
        )
        local_cred = r["credential_id"]
        local_body = None
        st, vc = _http("GET", f"{base}/v1/credentials/{local_cred}",
                       headers=T1)
        local_body = vc["body"]
        local_sig = vc["signature"]
        st, _ = _http("PUT",
                      f"{base}/v1/credentials/{local_cred}/status",
                      {"status": "active"}, headers=T1)
        check("本租户凭证登记 active -> 201/200", st in (200, 201))
        # 即使外部同名 credential_id 同步为 revoked，也不触碰本租户凭证
        ext_same = make_body(credential_id=local_cred, status="revoked",
                             updated="2026-09-26T00:00:00Z", version=2)
        st, _ = sync(signed(ext_same, priv2), headers=T1)
        check("外部同名状态同步成功", st in (200, 201))
        st, r = _http("GET",
                      f"{base}/v1/credentials/{local_cred}/status",
                      headers=T1)
        check("本租户凭证状态仍为 active（不被外部同步改变）",
              st == 200 and r["status"] == "active")
        st, r = _http(
            "POST", f"{base}/v1/credentials/{local_cred}/verify",
            {"body": local_body, "signature": local_sig}, headers=T1,
        )
        check("本租户凭证验签仍 valid:true",
              st == 200 and r == {"valid": True})

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 13. 跨重启持久化 ----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(proc, port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tcs-a"}
        st, r = get_status(cred_id, headers=T1,
                           query=f"issuer_did={quote(did)}")
        check(
            "重启后已同步状态保留",
            st == 200 and r == {
                "status": "revoked",
                "reason": "  持证人违规  ",
                "updated_at": "2026-09-22T00:00:00Z",
            },
        )
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("重启后审计保留",
              any(e["action"] == "trust.credential.status.synced"
                  for e in r["events"]))
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 14. 落盘失败回滚：内存不写入、审计不记录 ----
    rollback_path = tempfile.mktemp(suffix=".json")
    try:
        rs = VCStore(rollback_path)
        rs.register_trust_anchor("rb", did, pub1, 1)

        def _boom():
            raise OSError("模拟落盘失败")

        rs._save_locked = _boom  # type: ignore[assignment]
        rb_body = make_body(credential_id="vc_rollback")
        rb_payload = {"body": rb_body,
                      "signature": crypto.sign(rb_body, priv1)}
        try:
            rs.sync_credential_status("rb", rb_payload)
            check("落盘失败时 sync 抛错", False)
        except OSError:
            check("落盘失败时 sync 抛错", True)
        try:
            rs.get_synced_credential_status("rb", did, "vc_rollback")
            check("落盘失败回滚（状态不写入）", False)
        except Exception:
            check("落盘失败回滚（状态不写入）", True)
        events, _ = rs.list_audit("rb", 0, 200)
        check("落盘失败不记同步审计",
              all(e.action != "trust.credential.status.synced"
                  for e in events))
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


_UNSET = object()
_DELETE = object()

if __name__ == "__main__":
    raise SystemExit(main())
