#!/usr/bin/env python3
"""批量外部凭证状态同步 POST /v1/trust/credential-status/sync-batch
的端到端测试。

直接运行：python3 tests/trust_credential_status_sync_batch_test.py
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

BATCH_PATH = "/v1/trust/credential-status/sync-batch"
SUCCESS_KEYS = [
    "valid", "http_status", "issuer_did", "credential_id", "status",
    "reason", "updated_at", "issuer_key_version",
]
FAILURE_KEYS = ["valid", "http_status", "reason"]


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
    port = 8963
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

    def batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{BATCH_PATH}", payload,
                     headers=headers, raw=raw)

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tcsb-a"}
        T2 = {"X-Tenant-ID": "tcsb-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:issuer.batch"
        cred_id = "vc_batch_status_1"

        # 显式空租户头在进入同步前判 400
        st, _ = batch({"items": []}, headers={"X-Tenant-ID": ""})
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
                      reason=None, issuer=did):
            b = {
                "issuer_did": issuer,
                "credential_id": credential_id,
                "status": status,
                "updated_at": updated,
                "issuer_key_version": version,
            }
            if reason is not None:
                b["reason"] = reason
            return b

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        # ---- 1. 请求级非法：一律 200 + {"results": [], "reason": "请求..."} ----
        def expect_request_invalid(name, payload=None, raw=None):
            st, r = batch(payload, headers=T1, raw=raw)
            check(f"请求非法[{name}] -> 200 results 空且 reason 请求开头",
                  st == 200 and r.get("results") == []
                  and isinstance(r.get("reason"), str)
                  and r["reason"].startswith("请求"))

        expect_request_invalid("缺请求体", raw=None)
        expect_request_invalid("非法 JSON", raw=b"{not json")
        expect_request_invalid("非对象", payload=[1, 2])
        expect_request_invalid("缺 items", payload={})
        expect_request_invalid("多余字段",
                               payload={"items": [signed(make_body())],
                                        "z": 1})
        expect_request_invalid("items 非数组", payload={"items": {}})
        expect_request_invalid("items 空数组", payload={"items": []})
        expect_request_invalid(
            "items 超上限",
            payload={"items": [signed(make_body())] * 101})

        # ---- 2. 混合批次：逐项不短路、等长同序、键序正确 ----
        items = [
            signed(make_body()),                                  # 0 首次 201
            {"body": {}, "signature": "x"},                       # 1 字段 400
            signed(make_body(credential_id="no_anchor",
                             issuer="did:web:nobody")),           # 2 锚点 200
            {"body": make_body(credential_id="bad_sig"),
             "signature": "!!!bad!!!"},                           # 3 签名 200
            signed(make_body(status="revoked")),                  # 4 同秒 409
            signed(make_body()),                                  # 5 重放 200
            signed(make_body(                                     # 6 更晚 200
                status="revoked", updated="2026-09-22T00:00:00Z",
                version=2, reason="持证人违规"), priv2),
            signed(make_body(                                     # 7 更早 200
                updated="2026-09-20T00:00:00Z")),
        ]
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        st, r = batch({"items": items}, headers=T1)
        results = r.get("results", [])
        check("混合批次 -> 200 且 results 等长",
              st == 200 and len(results) == len(items))

        check("首次同步 201 且键序正确",
              results[0].get("valid") is True
              and results[0].get("http_status") == 201
              and list(results[0]) == SUCCESS_KEYS
              and results[0].get("issuer_did") == did
              and results[0].get("credential_id") == cred_id
              and results[0].get("status") == "active"
              and results[0].get("reason") is None
              and results[0].get("updated_at") == "2026-09-21T00:00:00Z"
              and results[0].get("issuer_key_version") == 1)
        check("字段错误 400 且键序正确、reason 非空中文",
              results[1].get("valid") is False
              and results[1].get("http_status") == 400
              and list(results[1]) == FAILURE_KEYS
              and bool(results[1].get("reason")))
        check("锚点缺失 200 valid:false 且 reason 以锚点开头",
              results[2].get("valid") is False
              and results[2].get("http_status") == 200
              and list(results[2]) == FAILURE_KEYS
              and str(results[2].get("reason", "")).startswith("锚点"))
        check("签名格式错误 200 valid:false 且 reason 以签名开头",
              results[3].get("valid") is False
              and results[3].get("http_status") == 200
              and list(results[3]) == FAILURE_KEYS
              and str(results[3].get("reason", "")).startswith("签名"))
        check("同秒冲突 409 且 reason 非空",
              results[4].get("valid") is False
              and results[4].get("http_status") == 409
              and list(results[4]) == FAILURE_KEYS
              and bool(results[4].get("reason")))
        check("重放 200 且内容不变",
              results[5].get("valid") is True
              and results[5].get("http_status") == 200
              and list(results[5]) == SUCCESS_KEYS
              and results[5].get("status") == "active")
        check("更晚更新 200 且替换内容",
              results[6].get("valid") is True
              and results[6].get("http_status") == 200
              and list(results[6]) == SUCCESS_KEYS
              and results[6].get("status") == "revoked"
              and results[6].get("reason") == "持证人违规"
              and results[6].get("updated_at") == "2026-09-22T00:00:00Z"
              and results[6].get("issuer_key_version") == 2)
        check("更早状态 200 且保持既有值",
              results[7].get("valid") is True
              and results[7].get("http_status") == 200
              and list(results[7]) == SUCCESS_KEYS
              and results[7].get("status") == "revoked"
              and results[7].get("updated_at") == "2026-09-22T00:00:00Z")

        # 审计：首次 + 严格更新各一条，重放/更早/失败均不记
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        synced_events = [
            e for e in audit_after["events"]
            if e["action"] == "trust.credential.status.synced"
        ]
        check("批次恰好记两条 synced 审计且字段正确",
              len(audit_after["events"]) == n_before + 2
              and len(synced_events) == 2
              and all(e["resource_type"] == "trust_credential_status"
                      for e in synced_events)
              and all(e["resource_id"] == f"{did}#{cred_id}"
                      for e in synced_events))

        # 失败项不写入：锚点缺失/签名错误/冲突均未落库
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/no_anchor"
            f"?issuer_did={quote('did:web:nobody')}", headers=T1)
        check("锚点缺失项未写入", st == 404)
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/bad_sig"
            f"?issuer_did={quote(did)}", headers=T1)
        check("签名错误项未写入", st == 404)
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/{quote(cred_id)}"
            f"?issuer_did={quote(did)}", headers=T1)
        check("冲突/更早项未覆盖最终状态",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == "2026-09-22T00:00:00Z")

        # ---- 3. 租户隔离与缺省租户 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T2,
        )
        check("T2 注册锚点 v1 -> 201", st == 201)
        st, r = batch({"items": [signed(make_body())]}, headers=T2)
        check("他租户同步同一内容 -> 201（租户隔离）",
              st == 200 and r["results"][0]["http_status"] == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1})
        check("default 租户注册锚点 v1 -> 201", st == 201)
        st, r = batch({"items": [signed(make_body(
            credential_id="default_tenant_cred"))]})
        check("缺省 X-Tenant-ID 走 default 租户 -> 201",
              st == 200 and r["results"][0]["http_status"] == 201)

        # ---- 4. 本地凭证状态不受同步影响 ----
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "batch-issuer"},
                      headers=T1)
        local_issuer = r["did"]
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "batch-holder"},
                      headers=T1)
        local_holder = r["did"]
        st, vc = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": local_issuer,
            "subject_did": local_holder,
            "claims": {"k": 1},
        }, headers=T1)
        check("本地签发凭证 -> 201", st == 201)
        local_cred_id = vc["credential_id"]
        st, r = batch({"items": [signed(make_body(
            credential_id=local_cred_id))]}, headers=T1)
        check("同名外部状态同步 -> 201",
              st == 200 and r["results"][0]["http_status"] == 201)
        st, r = _http(
            "GET", f"{base}/v1/credentials/{local_cred_id}/status",
            headers=T1)
        check("本地凭证状态不变",
              st == 200 and r.get("status") == "active")

        # ---- 5. 重启后状态保持 ----
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(proc, port), "重启后服务启动超时"
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/{quote(cred_id)}"
            f"?issuer_did={quote(did)}", headers=T1)
        check("重启后同步状态保持",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == "2026-09-22T00:00:00Z")
        st, r = batch({"items": [signed(make_body(
            status="revoked", updated="2026-09-22T00:00:00Z",
            version=2, reason="持证人违规"), priv2)]}, headers=T1)
        check("重启后重放严格更新内容 -> 200 幂等",
              st == 200 and r["results"][0]["valid"] is True
              and r["results"][0]["http_status"] == 200)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)

    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部批量同步测试通过 ✔")


if __name__ == "__main__":
    main()
