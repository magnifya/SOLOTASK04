#!/usr/bin/env python3
"""端到端测试：临时启动 HTTP 服务，覆盖 DID/凭证接口与签名验真。

直接运行：python3 tests/e2e_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402


def _http(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
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


def main():
    port = 8941
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

    try:
        assert wait_up(port), "服务启动超时"

        # 1. 注册 DID
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "alice-key"})
        check("POST /v1/dids -> 201", st == 201 and r["did"].startswith("did:example:"))
        alice = r["did"]
        check("返回含 public_key", bool(r.get("public_key")))

        # 2. 同一 public_key 去重
        st, r2 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "alice-key"})
        check("同一 public_key 返回既有 DID", r2["did"] == alice)

        # 3. 缺字段 400
        st, r = _http("POST", f"{base}/v1/dids", {"method": "example"})
        check("缺 public_key -> 400 且说明原因",
              st == 400 and "public_key" in r.get("error", ""))

        # 4. GET DID
        st, r = _http("GET", f"{base}/v1/dids/{alice}")
        check("GET DID -> 200 含 public_key/created_at",
              st == 200 and r["public_key"] and r["created_at"])

        # 5. GET 不存在 404
        st, _ = _http("GET", f"{base}/v1/dids/did:example:nope")
        check("GET 不存在 DID -> 404", st == 404)

        # 第二个 DID 作为签发者
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "issuer-key"})
        issuer = r["did"]

        # 6. 签发凭证
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"role": "admin", "level": 3}})
        check("POST /v1/credentials -> 201",
              st == 201 and r["credential_id"].startswith("vc_")
              and bool(r["signature"]))
        cid, sig = r["credential_id"], r["signature"]

        # 7. 不存在 DID 签发 -> 400 指明哪一个
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": "did:example:nope", "subject_did": alice,
            "claims": {}})
        check("issuer 不存在 -> 400 指明 issuer_did",
              st == 400 and "issuer_did" in r.get("error", ""))
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": "did:example:nope",
            "claims": {}})
        check("subject 不存在 -> 400 指明 subject_did",
              st == 400 and "subject_did" in r.get("error", ""))

        # 8. GET 凭证
        st, r = _http("GET", f"{base}/v1/credentials/{cid}")
        check("GET 凭证 -> 200 含 body/signature",
              st == 200 and r["body"] and r["signature"] == sig)
        body = r["body"]

        # 9. GET 不存在凭证 -> 404
        st, _ = _http("GET", f"{base}/v1/credentials/vc_nope")
        check("GET 不存在凭证 -> 404", st == 404)

        # 10. 现取签发者公钥验签 -> 成功
        _, did_doc = _http("GET", f"{base}/v1/dids/{issuer}")
        try:
            crypto.verify(body, sig, did_doc["public_key"])
            check("现取签发者公钥验签通过", True)
        except Exception:
            check("现取签发者公钥验签通过", False)

        # 11. 篡改 claims -> 验签失败
        tampered = json.loads(json.dumps(body))
        tampered["claims"]["role"] = "superadmin"
        try:
            crypto.verify(tampered, sig, did_doc["public_key"])
            check("篡改 claims 后验签失败", False)
        except crypto.InvalidSignature:
            check("篡改 claims 后验签失败", True)

        # 12. 篡改顶层字段 -> 验签失败
        tampered2 = json.loads(json.dumps(body))
        tampered2["subject_did"] = alice + "x"
        try:
            crypto.verify(tampered2, sig, did_doc["public_key"])
            check("篡改 subject_did 后验签失败", False)
        except crypto.InvalidSignature:
            check("篡改 subject_did 后验签失败", True)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("全部端到端测试通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
