#!/usr/bin/env python3
"""已导入外部凭证重新验证端到端测试。

POST /v1/trust/credentials/imported/{credential_id}/verify?issuer_did=...

直接运行：python3 tests/trust_imported_credential_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
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


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main():
    port = 8973
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
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

    def verify(credential_id, query, payload=None, raw=None, headers=None):
        suffix = f"?{query}" if query else ""
        return call(
            "POST",
            f"/v1/trust/credentials/imported/"
            f"{credential_id}/verify{suffix}",
            payload=payload, raw=raw, headers=headers,
        )

    def get_imported(credential_id, query, headers=None):
        return call(
            "GET",
            f"/v1/trust/credentials/imported/"
            f"{credential_id}?{query}",
            headers=headers,
        )

    def import_cred(body, signature, headers=None):
        return call(
            "POST", "/v1/trust/credentials/import",
            payload={"body": body, "signature": signature},
            headers=headers,
        )

    def expect_400(name, credential_id, query, payload=None, raw=None,
                   headers=None):
        st, parsed, _ = verify(
            credential_id, query, payload=payload, raw=raw, headers=headers
        )
        check(
            name,
            st == 400
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"error"}
            and isinstance(parsed["error"], str)
            and bool(parsed["error"].strip()),
        )

    def expect_invalid_exact(name, credential_id, query, reason, headers=None):
        st, parsed, text = verify(
            credential_id, query, payload={}, headers=headers
        )
        check(
            name,
            st == 200
            and isinstance(parsed, dict)
            and list(parsed.keys()) == ["valid", "reason"]
            and parsed == {"valid": False, "reason": reason}
            and json.loads(text) == {"valid": False, "reason": reason},
        )

    T1 = {"X-Tenant-ID": "ivr-a"}
    T2 = {"X-Tenant-ID": "ivr-b"}

    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    priv3, pub3 = gen_keypair()
    did = "did:web:issuer.example"
    did_rev = "did:web:revoked-issuer.example"
    did_ver = "did:web:rotated.example"
    cred = "vc_verify_0001"

    def make_body(cred_id=cred, issuer=did, version=None, extra=None,
                  issued_at="2026-09-20T00:00:00Z"):
        body = {
            "credential_id": cred_id,
            "issuer_did": issuer,
            "subject_did": "did:web:holder.example",
            "claims": {"level": 7, "note": "外部凭证"},
            "issued_at": issued_at,
        }
        if version is not None:
            body["issuer_key_version"] = version
        if extra:
            body.update(extra)
        return body

    try:
        assert wait_up(port), "服务启动超时"

        # ---- 注册锚点：did/did_rev v1；did_ver v1(pub1) 轮换 v2(pub3) ----
        st, _, _ = call(
            "POST", "/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("注册 did v1 锚点 -> 201", st == 201)
        st, _, _ = call(
            "POST", "/v1/trust/anchors",
            {"did": did_rev, "public_key": pub2, "key_version": 1},
            headers=T1,
        )
        check("注册 did_rev v1 锚点 -> 201", st == 201)
        st, _, _ = call(
            "POST", "/v1/trust/anchors",
            {"did": did_ver, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("注册 did_ver v1 锚点 -> 201", st == 201)
        st, _, _ = call(
            "POST", f"/v1/trust/anchors/{did_ver}/rotate",
            {"from_key_version": 1, "public_key": pub3}, headers=T1,
        )
        check("轮换 did_ver v2 锚点 -> 201", st == 201)

        # ---- 导入三条凭证 ----
        body_ok = make_body()                       # 省略版本 -> 1
        sig_ok = crypto.sign(body_ok, priv1)
        st, parsed, _ = import_cred(body_ok, sig_ok, headers=T1)
        check("导入 cred（无 issuer_key_version）-> 201",
              st == 201 and parsed.get("imported") is True)

        body_v2 = make_body("vc_verify_v2", issuer=did_ver, version=2)
        sig_v2 = crypto.sign(body_v2, priv3)
        st, _, _ = import_cred(body_v2, sig_v2, headers=T1)
        check("导入 v2 凭证 -> 201", st == 201)

        body_rev = make_body("vc_verify_rev", issuer=did_rev)
        sig_rev = crypto.sign(body_rev, priv2)
        st, _, _ = import_cred(body_rev, sig_rev, headers=T1)
        check("导入 将吊销锚点凭证 -> 201", st == 201)

        future = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        body_future = make_body(
            "vc_verify_future", extra={"expires_at": future}
        )
        sig_future = crypto.sign(body_future, priv1)
        st, _, _ = import_cred(body_future, sig_future, headers=T1)
        check("导入 未到期凭证 -> 201", st == 201)

        # default 租户独立锚点+导入（验证缺省租户头）
        st, _, _ = call(
            "POST", "/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        check("default 租户注册锚点 -> 201", st == 201)
        body_def = make_body("vc_verify_default")
        sig_def = crypto.sign(body_def, priv1)
        st, _, _ = import_cred(body_def, sig_def)
        check("default 租户导入 -> 201", st == 201)

        # ---- 查询参数 issuer_did：缺失/重复/空值 -> 400 ----
        expect_400("缺 issuer_did -> 400", cred, "", payload={})
        expect_400(
            "issuer_did 重复 -> 400", cred,
            f"issuer_did={did}&issuer_did={did}", payload={},
        )
        expect_400("issuer_did 空值 -> 400", cred, "issuer_did=", payload={})

        # ---- 请求体必须恰为 {} ----
        expect_400("空请求体 -> 400", cred, f"issuer_did={did}", raw=b"",
                   headers=T1)
        expect_400("非法 JSON -> 400", cred, f"issuer_did={did}",
                   raw=b"not-json", headers=T1)
        expect_400("JSON null -> 400", cred, f"issuer_did={did}",
                   raw=b"null", headers=T1)
        expect_400("JSON 数组 -> 400", cred, f"issuer_did={did}",
                   raw=b"[1]", headers=T1)
        expect_400("非空对象 -> 400", cred, f"issuer_did={did}",
                   raw=b'{"x":1}', headers=T1)
        expect_400("含 null 值字段 -> 400", cred, f"issuer_did={did}",
                   raw=b'{"x":null}', headers=T1)

        # ---- 显式空 X-Tenant-ID -> 400（先于其他判定）----
        expect_400(
            "显式空 X-Tenant-ID -> 400", cred, f"issuer_did={did}",
            payload={}, headers={"X-Tenant-ID": ""},
        )

        # ---- 404：不存在 / 错配 / 跨租户 ----
        st, parsed, _ = verify(
            "vc_never_imported", f"issuer_did={did}", payload={},
            headers=T1,
        )
        check("未导入凭证 -> 404 仅 {error}",
              st == 404 and set(parsed.keys()) == {"error"}
              and bool(parsed["error"].strip()))
        st, _, _ = verify(
            cred, "issuer_did=did:web:other.example", payload={},
            headers=T1,
        )
        check("issuer_did 错配 -> 404", st == 404)
        st, _, _ = verify(cred, f"issuer_did={did}", payload={}, headers=T2)
        check("跨租户 -> 404", st == 404)

        # ---- 成功：恰为 {"valid": true}（含版本省略/版本2/未到期/default）----
        st, parsed, text = verify(
            cred, f"issuer_did={did}", payload={}, headers=T1
        )
        check(
            "v1 凭证验签成功 -> 200 恰 {valid:true}",
            st == 200 and json.loads(text) == {"valid": True}
            and list(parsed.keys()) == ["valid"] and parsed["valid"] is True,
        )
        st, parsed, _ = verify(
            "vc_verify_v2", f"issuer_did={did_ver}", payload={}, headers=T1
        )
        check("v2 凭证验签成功 -> {valid:true}",
              st == 200 and parsed == {"valid": True})
        st, parsed, _ = verify(
            "vc_verify_future", f"issuer_did={did}", payload={},
            headers=T1,
        )
        check("未到期凭证 -> {valid:true}",
              st == 200 and parsed == {"valid": True})
        st, parsed, _ = verify(
            "vc_verify_default", f"issuer_did={did}", payload={}
        )
        check("缺省租户验签成功 -> {valid:true}",
              st == 200 and parsed == {"valid": True})

        # ---- 锚点吊销：结论恰为“锚点不可用” ----
        st, _, _ = call(
            "PUT", f"/v1/trust/anchors/{did_rev}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 did_rev 锚点 -> 200", st == 200)
        expect_invalid_exact(
            "吊销后验签 -> 锚点不可用",
            "vc_verify_rev", f"issuer_did={did_rev}", "锚点不可用",
            headers=T1,
        )
        # 反复查询结论稳定
        expect_invalid_exact(
            "吊销结论重复查询稳定",
            "vc_verify_rev", f"issuer_did={did_rev}", "锚点不可用",
            headers=T1,
        )
        # 吊销 v1 不影响 did_ver v2 与 did v1
        st, parsed, _ = verify(
            "vc_verify_v2", f"issuer_did={did_ver}", payload={}, headers=T1
        )
        check("他 DID 凭证不受吊销影响", st == 200 and parsed["valid"] is True)

        # ---- 只读：不改记录、不记审计 ----
        st, before_audit, _ = call(
            "GET", "/v1/audit?limit=200", headers=T1
        )
        before_max = max(
            (e["seq"] for e in before_audit.get("events", [])), default=0
        )
        st, got, _ = get_imported(cred, f"issuer_did={did}", headers=T1)
        check("只读前 GET 原记录",
              st == 200 and got.get("body") == body_ok
              and got.get("signature") == sig_ok)
        for _ in range(3):
            verify(cred, f"issuer_did={did}", payload={}, headers=T1)
        verify(
            "vc_verify_rev", f"issuer_did={did_rev}", payload={},
            headers=T1,
        )
        st, after_audit, _ = call("GET", "/v1/audit?limit=200", headers=T1)
        after_max = max(
            (e["seq"] for e in after_audit.get("events", [])), default=0
        )
        check("verify 不新增审计事件", before_max == after_max)
        st, got, _ = get_imported(cred, f"issuer_did={did}", headers=T1)
        check(
            "verify 后记录原文不变",
            st == 200 and got.get("body") == body_ok
            and got.get("signature") == sig_ok,
        )

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 停机改写存储：锚点缺失/签名格式错/验签错/过期 + 重启稳定性 ----
    with open(store, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    t1 = data["tenants"]["ivr-a"]
    imported = t1["imported_credentials"]

    def seed(issuer, cred_id, body, signature):
        imported.setdefault(issuer, {})[cred_id] = {
            "body": body, "signature": signature,
        }

    # 从未注册锚点的 DID -> 锚点不可用
    body_no_anchor = make_body(
        "vc_verify_noanchor", issuer="did:web:never-registered.example"
    )
    seed(
        "did:web:never-registered.example", "vc_verify_noanchor",
        body_no_anchor, crypto.sign(body_no_anchor, priv1),
    )
    # did_ver v1 公钥为 pub1：签名原文被换成非法编码 -> 签名格式错误
    body_mal = make_body("vc_verify_malformed", issuer=did_ver, version=1)
    seed(did_ver, "vc_verify_malformed", body_mal, "!!!bad!!!")
    # 格式合法（64 字节裸 R||S 的 base64url）但内容错误 -> 签名校验失败
    body_badsig = make_body("vc_verify_badsig", issuer=did_ver, version=1)
    seed(
        did_ver, "vc_verify_badsig", body_badsig,
        b64url_nopad(b"\x00" * 31 + b"\x01" + b"\x00" * 31 + b"\x01"),
    )
    # 已到期（签名本身有效）-> 凭证已过期
    body_exp = make_body(
        "vc_verify_expired", issuer=did_ver, version=1,
        extra={"expires_at": "2000-01-01T00:00:00Z"},
    )
    seed(
        did_ver, "vc_verify_expired", body_exp,
        crypto.sign(body_exp, priv1),
    )
    # 对照：同锚点同密钥的正常凭证 -> valid:true
    body_ctrl = make_body("vc_verify_ctrl", issuer=did_ver, version=1)
    seed(
        did_ver, "vc_verify_ctrl", body_ctrl,
        crypto.sign(body_ctrl, priv1),
    )
    with open(store, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)

    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "ivr-a"}
        T2 = {"X-Tenant-ID": "ivr-b"}

        expect_invalid_exact(
            "重启后 锚点缺失 -> 锚点不可用",
            "vc_verify_noanchor",
            "issuer_did=did:web:never-registered.example",
            "锚点不可用", headers=T1,
        )
        expect_invalid_exact(
            "重启后 签名格式错 -> 签名格式错误",
            "vc_verify_malformed", f"issuer_did={did_ver}",
            "签名格式错误", headers=T1,
        )
        expect_invalid_exact(
            "重启后 验签失败 -> 签名校验失败",
            "vc_verify_badsig", f"issuer_did={did_ver}",
            "签名校验失败", headers=T1,
        )
        expect_invalid_exact(
            "重启后 已过期 -> 凭证已过期",
            "vc_verify_expired", f"issuer_did={did_ver}",
            "凭证已过期", headers=T1,
        )
        st, parsed, text = verify(
            "vc_verify_ctrl", f"issuer_did={did_ver}", payload={},
            headers=T1,
        )
        check(
            "重启后 正常凭证 -> 恰 {valid:true}",
            st == 200 and json.loads(text) == {"valid": True},
        )

        # 重启后结论稳定：成功仍成功、吊销仍不可用、跨租户仍 404
        st, parsed, _ = verify(
            cred, f"issuer_did={did}", payload={}, headers=T1
        )
        check("重启后 原成功凭证仍 {valid:true}",
              st == 200 and parsed == {"valid": True})
        expect_invalid_exact(
            "重启后 吊销结论稳定",
            "vc_verify_rev", f"issuer_did={did_rev}", "锚点不可用",
            headers=T1,
        )
        st, _, _ = verify(cred, f"issuer_did={did}", payload={}, headers=T2)
        check("重启后 跨租户仍 404", st == 404)
        expect_400(
            "重启后 缺 issuer_did 仍 400", cred, "", payload={},
            headers=T1,
        )
        expect_400(
            "重启后 非空对象仍 400", cred, f"issuer_did={did}",
            raw=b'{"a":1}', headers=T1,
        )

        # 响应不泄露私钥：任何响应体中都不出现 PEM 私钥标记
        leak = False
        for cid, q in (
            (cred, f"issuer_did={did}"),
            ("vc_verify_expired", f"issuer_did={did_ver}"),
            ("vc_verify_noanchor",
             "issuer_did=did:web:never-registered.example"),
        ):
            _, _, text = verify(cid, q, payload={}, headers=T1)
            if "PRIVATE KEY" in text:
                leak = True
        check("响应不包含私钥材料", not leak)

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
