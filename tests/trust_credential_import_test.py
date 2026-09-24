#!/usr/bin/env python3
"""外部凭证导入/读取的端到端测试。

POST /v1/trust/credentials/import
GET  /v1/trust/credentials/imported/{credential_id}?issuer_did=...

直接运行：python3 tests/trust_credential_import_test.py
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

IMPORT_PATH = "/v1/trust/credentials/import"


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
            text = resp.read().decode()
            parsed = json.loads(text) if text else {}
            return resp.status, parsed, text
    except urllib.error.HTTPError as exc:
        text = exc.read().decode()
        parsed = json.loads(text) if text else {}
        return exc.code, parsed, text


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
    port = 8964
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

    def import_req(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{IMPORT_PATH}", payload,
                     headers=headers, raw=raw)

    def imported_get(cred_id, issuer_did=None, headers=None,
                     extra_query=""):
        url = f"{base}/v1/trust/credentials/imported/{cred_id}"
        if issuer_did is not None:
            url += f"?issuer_did={urllib.request.quote(issuer_did)}"
        url += extra_query
        return _http("GET", url, headers=headers)

    def top_key_order(text):
        pairs = json.loads(text, object_pairs_hook=lambda p: p)
        return [k for k, _ in pairs]

    def count_import_audit(headers):
        st, r, _ = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return sum(
            1 for e in r.get("events", [])
            if e.get("action") == "trust.credential.imported"
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "timp-a"}
        T2 = {"X-Tenant-ID": "timp-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        priv_other, _ = gen_keypair()
        did = "did:web:importer.example"
        did_revoked = "did:web:revoked.example"

        st, _, _ = _http("POST", f"{base}/v1/trust/anchors",
                         {"did": did, "public_key": pub1, "key_version": 1},
                         headers=T1)
        check("注册锚点 v1 -> 201", st == 201)
        st, _, _ = _http("POST", f"{base}/v1/trust/anchors",
                         {"did": did, "public_key": pub2, "key_version": 2},
                         headers=T1)
        check("注册锚点 v2 -> 201", st == 201)
        st, _, _ = _http("POST", f"{base}/v1/trust/anchors",
                         {"did": did_revoked, "public_key": pub1,
                          "key_version": 1},
                         headers=T1)
        assert st == 201
        st, _, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did_revoked}/1/status",
            {"status": "revoked"}, headers=T1)
        assert st == 200

        def make_body(cred_id, version=None, claims=None, issued=None):
            b = {
                "credential_id": cred_id,
                "issuer_did": did,
                "subject_did": "did:web:holder.example",
                "claims": claims if claims is not None else {"level": 3},
                "issued_at": issued or "2026-09-24T00:00:00Z",
            }
            if version is not None:
                b["issuer_key_version"] = version
            return b

        cred_id = "vc_import_0001"
        body1 = make_body(cred_id)
        sig1 = crypto.sign(body1, priv1)

        # ---- 显式空租户头 -> 400（进入流程前判定）----
        st, r, _ = import_req({"body": body1, "signature": sig1},
                              headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # ---- 请求/字段错 -> 400 且仅 {"error":...} ----
        def expect_400(name, payload=None, raw=None):
            st, r, _ = import_req(payload=payload, raw=raw, headers=T1)
            check(name, st == 400 and set(r.keys()) == {"error"}
                  and isinstance(r["error"], str) and r["error"])

        expect_400("非法 JSON -> 400", raw=b"{not json")
        expect_400("顶层非对象 -> 400", payload=[1, 2])
        expect_400("缺 signature -> 400", payload={"body": body1})
        expect_400("多余字段 -> 400",
                   payload={"body": body1, "signature": sig1, "x": 1})
        expect_400("body 非对象 -> 400",
                   payload={"body": [], "signature": sig1})
        expect_400("signature 空串 -> 400",
                   payload={"body": body1, "signature": ""})
        expect_400("body 缺 credential_id -> 400",
                   payload={"body": {k: v for k, v in body1.items()
                                     if k != "credential_id"},
                            "signature": sig1})
        expect_400("body 缺 issuer_did -> 400",
                   payload={"body": {k: v for k, v in body1.items()
                                     if k != "issuer_did"},
                            "signature": sig1})
        expect_400("body 缺 subject_did -> 400",
                   payload={"body": {k: v for k, v in body1.items()
                                     if k != "subject_did"},
                            "signature": sig1})
        expect_400("body 缺 claims -> 400",
                   payload={"body": {k: v for k, v in body1.items()
                                     if k != "claims"},
                            "signature": sig1})
        expect_400("body 缺 issued_at -> 400",
                   payload={"body": {k: v for k, v in body1.items()
                                     if k != "issued_at"},
                            "signature": sig1})
        bad_claims = dict(body1)
        bad_claims["claims"] = "not-an-object"
        expect_400("claims 非对象 -> 400",
                   payload={"body": bad_claims, "signature": sig1})
        bad_subject = dict(body1)
        bad_subject["subject_did"] = ""
        expect_400("subject_did 空串 -> 400",
                   payload={"body": bad_subject,
                            "signature": crypto.sign(bad_subject, priv1)})
        bad_version = dict(body1)
        bad_version["issuer_key_version"] = 0
        expect_400("issuer_key_version 非正整数 -> 400",
                   payload={"body": bad_version,
                            "signature": crypto.sign(bad_version, priv1)})

        # ---- 验签类失败 -> 200 valid:false + 非空中文 reason，且不写入 ----
        def expect_invalid(name, prefix, payload=None, raw=None,
                           headers=None):
            st, r, _ = import_req(payload=payload, raw=raw,
                                  headers=headers or T1)
            ok = (st == 200 and r.get("valid") is False
                  and isinstance(r.get("reason"), str) and r["reason"]
                  and r["reason"].startswith(prefix))
            check(name, ok)

        body_missing = make_body("vc_fail_no_anchor")
        # 在 T2 无该锚点
        expect_invalid("锚点缺失 -> 200 valid:false", "锚点",
                       payload={"body": body_missing,
                                "signature": crypto.sign(body_missing, priv1)},
                       headers=T2)
        body_rev = make_body("vc_fail_revoked")
        body_rev["issuer_did"] = did_revoked
        expect_invalid("锚点已吊销 -> 200 valid:false", "锚点",
                       payload={"body": body_rev,
                                "signature": crypto.sign(body_rev, priv1)})
        expect_invalid("签名格式错 -> 200 valid:false", "签名格式错误",
                       payload={"body": make_body("vc_fail_malformed"),
                                "signature": "aaa"})
        expect_invalid("验签失败 -> 200 valid:false", "签名校验失败",
                       payload={"body": make_body("vc_fail_badsig"),
                                "signature": crypto.sign(
                                    make_body("vc_fail_badsig"), priv_other)})

        for cid in ("vc_fail_no_anchor", "vc_fail_revoked",
                    "vc_fail_malformed", "vc_fail_badsig"):
            owner = did if cid != "vc_fail_revoked" else did_revoked
            hdr = T2 if cid == "vc_fail_no_anchor" else T1
            st, _, _ = imported_get(cid, owner, headers=hdr)
            check(f"失败不写入 {cid}", st == 404)

        # ---- 首次导入 -> 201，键序严格 ----
        st, r, text = import_req({"body": body1, "signature": sig1},
                                 headers=T1)
        check("首次导入 -> 201", st == 201)
        check("首次导入 imported=true", r.get("imported") is True)
        check("首次导入回显 issuer/credential",
              r.get("issuer_did") == did and r.get("credential_id") == cred_id)
        check("首次导入回显 body/signature",
              r.get("body") == body1 and r.get("signature") == sig1)
        check("首次导入键序",
              top_key_order(text) == [
                  "imported", "issuer_did", "credential_id",
                  "body", "signature"])
        check("首次导入记一条审计", count_import_audit(T1) == 1)

        # ---- 同内容重放 -> 200 回原响应，不重复审计 ----
        st2, r2, text2 = import_req({"body": body1, "signature": sig1},
                                    headers=T1)
        check("同内容重放 -> 200", st2 == 200)
        check("重放响应一致",
              r2.get("imported") is True and r2.get("body") == body1
              and r2.get("signature") == sig1
              and r2.get("issuer_did") == did
              and r2.get("credential_id") == cred_id)
        check("重放键序",
              top_key_order(text2) == [
                  "imported", "issuer_did", "credential_id",
                  "body", "signature"])
        check("重放不重复审计", count_import_audit(T1) == 1)

        # ---- 不同内容 -> 409 仅 {"error":...}，原记录不变 ----
        sig_alt = crypto.sign(body1, priv1)
        while sig_alt == sig1:  # ECDSA 签名随机化，极小概率相同则重签
            sig_alt = crypto.sign(body1, priv1)
        st, r, _ = import_req({"body": body1, "signature": sig_alt},
                              headers=T1)
        check("同 body 不同签名 -> 409",
              st == 409 and set(r.keys()) == {"error"} and r["error"])
        body_changed = make_body(cred_id, claims={"level": 99})
        st, r, _ = import_req(
            {"body": body_changed,
             "signature": crypto.sign(body_changed, priv1)}, headers=T1)
        check("不同 body -> 409",
              st == 409 and set(r.keys()) == {"error"})
        st, r, _ = imported_get(cred_id, did, headers=T1)
        check("冲突后原记录不变",
              st == 200 and r.get("body") == body1
              and r.get("signature") == sig1)
        check("冲突不记审计", count_import_audit(T1) == 1)

        # ---- issuer_key_version=2 凭证导入 -> 201 ----
        cred_id2 = "vc_import_0002"
        body_v2 = make_body(cred_id2, version=2)
        sig_v2 = crypto.sign(body_v2, priv2)
        st, r, _ = import_req({"body": body_v2, "signature": sig_v2},
                              headers=T1)
        check("v2 凭证首次导入 -> 201", st == 201 and r.get("imported") is True)
        check("v2 审计计数", count_import_audit(T1) == 2)

        # ---- GET 读取：参数错误 400 ----
        def expect_get_400(name, cred_id_arg=cred_id, **kwargs):
            st, r, _ = imported_get(cred_id_arg, headers=T1, **kwargs)
            check(name, st == 400 and set(r.keys()) == {"error"}
                  and r["error"])

        expect_get_400("缺 issuer_did -> 400", issuer_did=None)
        expect_get_400("空 issuer_did -> 400", issuer_did="")
        expect_get_400("重复 issuer_did -> 400",
                       issuer_did=did,
                       extra_query=f"&issuer_did={urllib.request.quote(did)}")

        # ---- GET 404：未导入 / 不匹配 / 跨租户 ----
        st, _, _ = imported_get("vc_never_imported", did, headers=T1)
        check("未导入 -> 404", st == 404)
        st, _, _ = imported_get(cred_id, "did:web:other.example", headers=T1)
        check("issuer_did 不匹配 -> 404", st == 404)
        st, _, _ = imported_get(cred_id, did, headers=T2)
        check("跨租户 -> 404", st == 404)

        # ---- GET 成功：200，键序严格 ----
        st, r, text = imported_get(cred_id, did, headers=T1)
        check("读取已导入 -> 200", st == 200)
        check("读取内容一致",
              r.get("issuer_did") == did
              and r.get("credential_id") == cred_id
              and r.get("body") == body1 and r.get("signature") == sig1)
        check("读取键序",
              top_key_order(text) == [
                  "issuer_did", "credential_id", "body", "signature"])
        st, r, _ = imported_get(cred_id2, did, headers=T1)
        check("读取 v2 凭证 -> 200",
              st == 200 and r.get("body") == body_v2
              and r.get("signature") == sig_v2)

        # ---- 缺省租户 default ----
        body_def = make_body("vc_default_tenant")
        body_def["issuer_did"] = "did:web:default-anchor.example"
        # default 租户注册自己的锚点
        priv_def, pub_def = gen_keypair()
        st, _, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": body_def["issuer_did"], "public_key": pub_def,
             "key_version": 1},
            headers={})  # 无 X-Tenant-ID -> default
        assert st == 201
        sig_def = crypto.sign(body_def, priv_def)
        st, _, _ = import_req({"body": body_def, "signature": sig_def})
        check("缺省租户导入 -> 201", st == 201)
        st, r, _ = imported_get("vc_default_tenant", body_def["issuer_did"])
        check("缺省租户读取 -> 200",
              st == 200 and r.get("signature") == sig_def)
        # default 与 T1 相互隔离
        st, _, _ = imported_get("vc_default_tenant",
                                body_def["issuer_did"], headers=T1)
        check("default 记录对 T1 不可见 -> 404", st == 404)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 重启持久化：同状态文件重新启动后仍可读、可幂等重放 ----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "重启后服务启动超时"
        T1 = {"X-Tenant-ID": "timp-a"}
        did = "did:web:importer.example"
        cred_id = "vc_import_0001"
        body1 = {
            "credential_id": cred_id,
            "issuer_did": did,
            "subject_did": "did:web:holder.example",
            "claims": {"level": 3},
            "issued_at": "2026-09-24T00:00:00Z",
        }
        st, r, text = imported_get(cred_id, did, headers=T1)
        check("重启后读取 -> 200", st == 200 and r.get("body") == body1)
        check("重启后读取键序",
              top_key_order(text) == [
                  "issuer_did", "credential_id", "body", "signature"])
        # 重放仍 200（原内容不被替换），审计不新增
        sig1 = r["signature"]
        st, r2, _ = import_req({"body": body1, "signature": sig1},
                               headers=T1)
        check("重启后同内容重放 -> 200", st == 200 and r2.get("imported") is True)
        check("重启后审计不重复", count_import_audit(T1) == 2)
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
