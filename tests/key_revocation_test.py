#!/usr/bin/env python3
"""POST /v1/dids/{did}/keys/{key_version}/revoke 密钥版本吊销的端到端测试。

直接运行：python3 tests/key_revocation_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 吊销端点：空体/{} 省略 reason（响应 reason 为 null）、恰含 reason 且
  裁剪、非法 reason/多余字段 400、路径 key_version 各类非法 400、
  DID/版本（含他租户）404、当前版本 409、首次 200 字段精确、重复吊销
  忽略任意 reason 返回首次结果；
- 审计：首次与重复均记 key.revoked（resource_type=did、
  resource_id=<did>#<version>），失败路径不记；
- DID 文档：被吊销版本保留在 verification_methods，document_proof 仍
  由当前版本私钥签发；
- 凭证 verify：验签后按 签发密钥 -> 有效期 -> 凭证吊销 顺序检查，
  命中返回 200 valid:false “签发密钥已吊销：<reason>”；
- 演示 verify：issuer proof -> 签发密钥 -> holder proof -> 持有者密钥
  顺序，已消费/已过期优先，失败不消费；
- 谓词证明 verify：验签后查签发密钥；
- present/prove 遇吊销签发版本 400 且不留记录；
- 轮换新版本照常签发验真；状态跨重启保留；租户隔离。
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402


def _http(method, url, payload=None, headers=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None
    )
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


def _start(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    return subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def main():
    port = 8961
    store = tempfile.mktemp(suffix=".json")
    proc = _start(port, store)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"

        # ---- 准备：issuer 三个版本，holder 一个版本 ------------------ #
        st, issuer = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "iss-key"})
        assert st == 201
        issuer_did = issuer["did"]
        st, _ = _http("POST", f"{base}/v1/dids/{issuer_did}/keys/rotate",
                      {"key_handle": "iss-key-v2"})
        assert st == 200
        st, _ = _http("POST", f"{base}/v1/dids/{issuer_did}/keys/rotate",
                      {"key_handle": "iss-key-v3"})
        assert st == 200
        st, holder = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "hold-key"})
        holder_did = holder["did"]

        revoke_url = lambda did, v: (  # noqa: E731
            f"{base}/v1/dids/{did}/keys/"
            f"{urllib.parse.quote(str(v), safe='')}/revoke"
        )

        # ---- 路径 key_version 非法 -> 400 ---------------------------- #
        for bad in ("0", "-1", "+1", "1.5", "abc", " 1", "1 ", "",
                    "true", "१"):
            st, body = _http("POST", revoke_url(issuer_did, bad))
            check(f"key_version={bad!r} -> 400",
                  st == 400 and body.get("error"))

        # ---- DID/版本不存在 -> 404 ---------------------------------- #
        st, body = _http("POST", revoke_url("did:example:none", "1"))
        check("未知 DID -> 404", st == 404 and body.get("error"))
        st, body = _http("POST", revoke_url(issuer_did, "9"))
        check("未知版本 -> 404", st == 404 and body.get("error"))
        st, body = _http("POST", revoke_url(issuer_did, "1"),
                         headers={"X-Tenant-ID": "other"})
        check("他租户 DID -> 404", st == 404 and body.get("error"))

        # ---- 当前版本 -> 409 ---------------------------------------- #
        st, body = _http("POST", revoke_url(issuer_did, "3"))
        check("当前版本 -> 409", st == 409 and body.get("error"))

        # ---- 请求体非法 -> 400 -------------------------------------- #
        st, body = _http("POST", revoke_url(issuer_did, "1"),
                         {"reason": "x", "extra": 1})
        check("多余字段 -> 400", st == 400 and body.get("error"))
        for bad_reason in (None, 123, True, "   ", ""):
            st, body = _http("POST", revoke_url(issuer_did, "1"),
                             {"reason": bad_reason})
            check(f"reason={bad_reason!r} -> 400",
                  st == 400 and body.get("error"))
        st, body = _http("POST", revoke_url(issuer_did, "1"), raw=b"[1]")
        check("非对象请求体 -> 400", st == 400 and body.get("error"))

        # 失败路径不记审计
        st, aud = _http("GET", f"{base}/v1/audit?limit=200")
        n_audit_before = len(aud["events"])
        check("失败路径未记 key.revoked",
              not any(e["action"] == "key.revoked"
                      for e in aud["events"]))

        # ---- 首次吊销：空体省略 reason ------------------------------- #
        st, body = _http("POST", revoke_url(issuer_did, "1"))
        check("空体首次吊销 200",
              st == 200
              and set(body) == {"did", "key_version", "status",
                                "reason", "updated_at"}
              and body["did"] == issuer_did
              and body["key_version"] == 1
              and body["status"] == "revoked"
              and body["reason"] is None
              and UTC_Z_RE.match(body["updated_at"] or ""))
        first_updated = body["updated_at"]

        # ---- 重复吊销：忽略任意 reason（含非法值） ------------------- #
        st, body = _http("POST", revoke_url(issuer_did, "1"),
                         {"reason": "  换个原因  "})
        check("重复吊销忽略 reason",
              st == 200 and body["reason"] is None
              and body["updated_at"] == first_updated)
        st, body = _http("POST", revoke_url(issuer_did, "1"),
                         {"reason": 123})
        check("重复吊销忽略非法 reason",
              st == 200 and body["updated_at"] == first_updated)

        # ---- {} 与带 reason 吊销版本 2 ------------------------------- #
        st, body = _http("POST", revoke_url(issuer_did, "2"), {})
        check("{} 省略 reason", st == 200 and body["reason"] is None)
        st, body = _http("POST", revoke_url(holder_did, "1"),
                         {"reason": "  持有者密钥泄露  "})
        # holder 只有版本 1（当前版本）-> 409；先轮换再吊销
        check("holder 当前版本 -> 409", st == 409)
        st, _ = _http("POST", f"{base}/v1/dids/{holder_did}/keys/rotate",
                      {"key_handle": "hold-key-v2"})
        assert st == 200
        st, body = _http("POST", revoke_url(holder_did, "1"),
                         {"reason": "  持有者密钥泄露  "})
        check("reason 裁剪保存",
              st == 200 and body["reason"] == "持有者密钥泄露")

        # ---- 审计：首次与重复均记 key.revoked ------------------------ #
        st, aud = _http("GET", f"{base}/v1/audit?limit=200")
        revoked_events = [e for e in aud["events"]
                          if e["action"] == "key.revoked"]
        check("key.revoked 审计字段",
              len(revoked_events) == 5  # v1首次+v1重复x2+v2首次+holder首次
              and all(e["resource_type"] == "did" for e in revoked_events)
              and {e["resource_id"] for e in revoked_events}
              == {f"{issuer_did}#1", f"{issuer_did}#2", f"{holder_did}#1"})

        # ---- DID 文档：吊销版本保留，证明仍由当前版本签发 ------------- #
        st, doc = _http("GET", f"{base}/v1/dids/{issuer_did}/document")
        versions = [m["key_version"] for m in doc["verification_methods"]]
        check("吊销版本保留在文档历史",
              st == 200 and versions == [1, 2, 3]
              and doc["current_key_version"] == 3)
        current_pub = [m["public_key"] for m in doc["verification_methods"]
                       if m["key_version"] == 3][0]
        unsigned = {k: v for k, v in doc.items() if k != "document_proof"}
        try:
            crypto.verify(unsigned, doc["document_proof"], current_pub)
            proof_ok = True
        except Exception:  # noqa: BLE001
            proof_ok = False
        check("document_proof 由当前版本签发", proof_ok)

        # ---- 凭证 verify：签发密钥吊销 ------------------------------- #
        # 新凭证用当前版本 v3 签发，先吊销 v3 不可（当前版本），故另起
        # 一个 DID：v1 签发凭证 -> 轮换到 v2 -> 吊销 v1。
        st, iss2 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss2-key"})
        iss2_did = iss2["did"]
        st, cred = _http("POST", f"{base}/v1/credentials",
                         {"issuer_did": iss2_did, "subject_did": holder_did,
                          "claims": {"role": "admin", "age": 30}})
        assert st == 201
        cred_id = cred["credential_id"]
        st, full = _http("GET", f"{base}/v1/credentials/{cred_id}")
        body_v1, sig_v1 = full["body"], full["signature"]
        assert full["body"]["issuer_key_version"] == 1
        st, _ = _http("POST", f"{base}/v1/dids/{iss2_did}/keys/rotate",
                      {"key_handle": "iss2-key-v2"})
        assert st == 200

        # 轮换后旧凭证（v1 签发）验真通过
        st, res = _http("POST", f"{base}/v1/credentials/{cred_id}/verify",
                        {"body": body_v1, "signature": sig_v1})
        check("轮换后旧凭证验真通过", st == 200 and res.get("valid") is True)

        # 吊销 v1（带 reason）
        st, body = _http("POST", revoke_url(iss2_did, "1"),
                         {"reason": "  密钥泄漏  "})
        assert st == 200 and body["reason"] == "密钥泄漏"

        st, res = _http("POST", f"{base}/v1/credentials/{cred_id}/verify",
                        {"body": body_v1, "signature": sig_v1})
        check("verify 命中签发密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason") == "签发密钥已吊销：密钥泄漏")

        # 签名失败仍优先于密钥吊销
        tampered = dict(body_v1, claims={"role": "admin", "age": 31})
        st, res = _http("POST", f"{base}/v1/credentials/{cred_id}/verify",
                        {"body": tampered, "signature": sig_v1})
        check("签名失败优先于密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason", "").startswith("签名校验失败"))

        # 密钥吊销优先于凭证吊销
        _http("POST", f"{base}/v1/credentials/{cred_id}/revoke",
              {"reason": "凭证作废"})
        st, res = _http("POST", f"{base}/v1/credentials/{cred_id}/verify",
                        {"body": body_v1, "signature": sig_v1})
        check("密钥吊销优先于凭证吊销",
              st == 200 and res.get("reason") == "签发密钥已吊销：密钥泄漏")

        # 轮换后的新版本照常签发验真
        st, cred2 = _http("POST", f"{base}/v1/credentials",
                          {"issuer_did": iss2_did, "subject_did": holder_did,
                           "claims": {"role": "user"}})
        assert st == 201 and cred2["issuer_key_version"] == 2
        st, full2 = _http("GET", f"{base}/v1/credentials/{cred2['credential_id']}")
        st, res = _http("POST",
                        f"{base}/v1/credentials/{cred2['credential_id']}/verify",
                        {"body": full2["body"],
                         "signature": full2["signature"]})
        check("轮换新版本照常签发验真",
              st == 200 and res.get("valid") is True)

        # ---- present/prove 遇吊销签发版本 -> 400 且不留记录 ---------- #
        st, aud = _http("GET", f"{base}/v1/audit?limit=200")
        n_events = len(aud["events"])
        st, body = _http("POST",
                         f"{base}/v1/credentials/{cred_id}/present",
                         {"disclose": ["/role"]})
        check("present 遇吊销签发版本 -> 400",
              st == 400 and body.get("error"))
        st, body = _http("POST",
                         f"{base}/v1/credentials/{cred_id}/prove",
                         {"predicates": [{"path": "/age", "op": "gte",
                                          "value": 18}]})
        check("prove 遇吊销签发版本 -> 400",
              st == 400 and body.get("error"))
        st, aud = _http("GET", f"{base}/v1/audit?limit=200")
        check("present/prove 400 不留记录",
              len(aud["events"]) == n_events)

        # ---- 演示 verify：签发密钥/持有者密钥 ------------------------ #
        # 新 issuer（iss3）：v1 签发凭证并生成演示，再轮换吊销 v1
        st, iss3 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss3-key"})
        iss3_did = iss3["did"]
        st, cred3 = _http("POST", f"{base}/v1/credentials",
                          {"issuer_did": iss3_did, "subject_did": holder_did,
                           "claims": {"role": "admin"}})
        cred3_id = cred3["credential_id"]
        st, pres = _http("POST",
                         f"{base}/v1/credentials/{cred3_id}/present",
                         {"disclose": ["/role"], "challenge": "chal-1"})
        assert st == 201
        pres_id = pres["presentation_id"]
        # 轮换并吊销 iss3 v1
        _http("POST", f"{base}/v1/dids/{iss3_did}/keys/rotate",
              {"key_handle": "iss3-key-v2"})
        _http("POST", revoke_url(iss3_did, "1"), {"reason": "轮换下线"})
        st, res = _http("POST",
                        f"{base}/v1/presentations/{pres_id}/verify",
                        {"presentation": pres, "challenge": "chal-1"})
        check("演示 verify 命中签发密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason") == "签发密钥已吊销：轮换下线")
        # 失败不消费：恢复不可能（吊销不可逆），改验“未消费”——用新演示
        # 验证已消费优先：先消费一次，再吊销，再验证返回“演示已消费”
        st, iss4 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss4-key"})
        iss4_did = iss4["did"]
        st, cred4 = _http("POST", f"{base}/v1/credentials",
                          {"issuer_did": iss4_did, "subject_did": holder_did,
                           "claims": {"role": "admin"}})
        cred4_id = cred4["credential_id"]
        st, pres4 = _http("POST",
                          f"{base}/v1/credentials/{cred4_id}/present",
                          {"disclose": ["/role"], "challenge": "chal-4"})
        pres4_id = pres4["presentation_id"]
        st, res = _http("POST",
                        f"{base}/v1/presentations/{pres4_id}/verify",
                        {"presentation": pres4, "challenge": "chal-4"})
        check("演示首次验证成功", st == 200 and res.get("valid") is True)
        _http("POST", f"{base}/v1/dids/{iss4_did}/keys/rotate",
              {"key_handle": "iss4-key-v2"})
        _http("POST", revoke_url(iss4_did, "1"))
        st, res = _http("POST",
                        f"{base}/v1/presentations/{pres4_id}/verify",
                        {"presentation": pres4, "challenge": "chal-4"})
        check("已消费优先于密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason") == "演示已消费")

        # 持有者密钥吊销：holder v1 已吊销，iss5 正常，绑定演示
        st, iss5 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss5-key"})
        iss5_did = iss5["did"]
        # holder 当前为 v2；用 holder v2 绑定后吊销 v2 不可（当前版本），
        # 故再轮换 holder 到 v3 并吊销 v2
        st, cred5 = _http("POST", f"{base}/v1/credentials",
                          {"issuer_did": iss5_did, "subject_did": holder_did,
                           "claims": {"role": "admin"}})
        cred5_id = cred5["credential_id"]
        st, pres5 = _http("POST",
                          f"{base}/v1/credentials/{cred5_id}/present",
                          {"disclose": ["/role"], "challenge": "chal-5",
                           "holder_binding": True})
        assert st == 201 and pres5.get("holder_key_version") == 2
        pres5_id = pres5["presentation_id"]
        _http("POST", f"{base}/v1/dids/{holder_did}/keys/rotate",
              {"key_handle": "hold-key-v3"})
        _http("POST", revoke_url(holder_did, "2"),
              {"reason": "持有者设备丢失"})
        st, res = _http("POST",
                        f"{base}/v1/presentations/{pres5_id}/verify",
                        {"presentation": pres5, "challenge": "chal-5"})
        check("演示 verify 命中持有者密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason") == "持有者密钥已吊销：持有者设备丢失")

        # ---- 谓词证明 verify：签发密钥吊销 --------------------------- #
        st, iss6 = _http("POST", f"{base}/v1/dids",
                         {"method": "example", "public_key": "iss6-key"})
        iss6_did = iss6["did"]
        st, cred6 = _http("POST", f"{base}/v1/credentials",
                          {"issuer_did": iss6_did, "subject_did": holder_did,
                           "claims": {"age": 30}})
        cred6_id = cred6["credential_id"]
        st, proof = _http("POST",
                          f"{base}/v1/credentials/{cred6_id}/prove",
                          {"predicates": [{"path": "/age", "op": "gte",
                                           "value": 18}],
                           "challenge": "chal-6"})
        assert st == 201
        proof_id = proof["proof_id"]
        _http("POST", f"{base}/v1/dids/{iss6_did}/keys/rotate",
              {"key_handle": "iss6-key-v2"})
        _http("POST", revoke_url(iss6_did, "1"), {"reason": "密钥归档"})
        st, res = _http("POST", f"{base}/v1/proofs/{proof_id}/verify",
                        {"proof": proof, "challenge": "chal-6"})
        check("谓词证明 verify 命中签发密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason") == "签发密钥已吊销：密钥归档")

        # ---- 重启保留 ------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = _start(port, store)
        assert wait_up(port), "服务重启超时"
        st, body = _http("POST", revoke_url(iss2_did, "1"))
        check("重启后重复吊销保持首次结果",
              st == 200 and body["reason"] == "密钥泄漏")
        st, res = _http("POST", f"{base}/v1/credentials/{cred_id}/verify",
                        {"body": body_v1, "signature": sig_v1})
        check("重启后 verify 仍命中密钥吊销",
              st == 200 and res.get("valid") is False
              and res.get("reason") == "签发密钥已吊销：密钥泄漏")
        st, doc = _http("GET", f"{base}/v1/dids/{issuer_did}/document")
        check("重启后文档仍含吊销版本",
              st == 200 and [m["key_version"]
                             for m in doc["verification_methods"]] == [1, 2, 3])

        # ---- 租户隔离：他租户吊销不影响本租户 ------------------------- #
        st, body = _http("POST", revoke_url(iss2_did, "2"),
                         headers={"X-Tenant-ID": "other"})
        check("他租户吊销 -> 404", st == 404 and body.get("error"))
        st, res = _http("POST",
                        f"{base}/v1/credentials/{cred2['credential_id']}/verify",
                        {"body": full2["body"],
                         "signature": full2["signature"]})
        check("本租户验证不受他租户影响",
              st == 200 and res.get("valid") is True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
