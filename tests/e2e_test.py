#!/usr/bin/env python3
"""端到端测试：临时启动 HTTP 服务，覆盖 DID/凭证/密钥轮换/验签接口。

直接运行：python3 tests/e2e_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import shutil
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


def _http(method, url, payload=None, raw=None):
    if raw is not None:
        data = raw
    else:
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


def start_server(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def cli_verify(port, credential_id):
    env = dict(os.environ, VCBACKEND_URL=f"http://127.0.0.1:{port}")
    proc = subprocess.run(
        [sys.executable, "-m", "vcbackend.cli", "verify", credential_id],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def main():
    port = 8941
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        # 1. 注册 DID（缺省 key_mode=server）
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "alice-key"})
        check("POST /v1/dids -> 201", st == 201 and r["did"].startswith("did:example:"))
        alice = r["did"]
        check("返回真实 PEM 公钥",
              "BEGIN PUBLIC KEY" in r.get("public_key", ""))
        check("返回 key_mode=server / key_handle / key_version=1",
              r.get("key_mode") == "server"
              and r.get("key_handle") == "alice-key"
              and r.get("key_version") == 1)

        # 2. 同一 public_key 句柄去重
        st, r2 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "alice-key"})
        check("同一 public_key 返回既有 DID", r2["did"] == alice)

        # 3. 缺字段 / PEM 句柄 / 非法 key_mode -> 400
        st, r = _http("POST", f"{base}/v1/dids", {"method": "example"})
        check("缺 public_key -> 400 且说明原因",
              st == 400 and "public_key" in r.get("error", ""))
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "   "})
        check("空白 public_key -> 400", st == 400)
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example",
                       "public_key": "-----BEGIN PUBLIC KEY-----\nAAAA"})
        check("PEM 作为句柄 -> 400", st == 400)
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "k",
                       "key_mode": "client"})
        check("非法 key_mode -> 400", st == 400 and "key_mode" in r["error"])
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "k2",
                       "key_mode": "server"})
        check("显式 key_mode=server -> 201", st == 201)

        # 4. GET DID 含密钥元数据
        st, r = _http("GET", f"{base}/v1/dids/{alice}")
        check("GET DID -> 200 含 public_key/created_at",
              st == 200 and r["public_key"] and r["created_at"])
        check("GET DID 含 key_mode/key_handle/key_version",
              r.get("key_mode") == "server"
              and r.get("key_handle") == "alice-key"
              and r.get("key_version") == 1)

        # 5. GET 不存在 404
        st, _ = _http("GET", f"{base}/v1/dids/did:example:nope")
        check("GET 不存在 DID -> 404", st == 404)

        # 签发者 DID
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "issuer-key"})
        issuer = r["did"]

        # 6. v1 签发凭证（轮换前）
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"role": "admin", "level": 3}})
        check("POST /v1/credentials -> 201",
              st == 201 and r["credential_id"].startswith("vc_")
              and bool(r["signature"]))
        check("签发响应含整数 issuer_key_version=1",
              r.get("issuer_key_version") == 1
              and isinstance(r["issuer_key_version"], int))
        cid, sig_v1 = r["credential_id"], r["signature"]

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

        # 8. GET 凭证：正文含 issuer_key_version
        st, r = _http("GET", f"{base}/v1/credentials/{cid}")
        check("GET 凭证 -> 200 含 body/signature",
              st == 200 and r["body"] and r["signature"] == sig_v1)
        body = r["body"]
        check("凭证正文含整数 issuer_key_version=1",
              body.get("issuer_key_version") == 1
              and isinstance(body["issuer_key_version"], int))

        # 9. GET 不存在凭证 -> 404
        st, _ = _http("GET", f"{base}/v1/credentials/vc_nope")
        check("GET 不存在凭证 -> 404", st == 404)

        # 10. 现取签发者公钥验签 -> 成功
        _, did_doc = _http("GET", f"{base}/v1/dids/{issuer}")
        try:
            crypto.verify(body, sig_v1, did_doc["public_key"])
            check("现取签发者公钥验签通过", True)
        except Exception:
            check("现取签发者公钥验签通过", False)

        # 11. 篡改 claims -> 验签失败
        tampered = json.loads(json.dumps(body))
        tampered["claims"]["role"] = "superadmin"
        try:
            crypto.verify(tampered, sig_v1, did_doc["public_key"])
            check("篡改 claims 后验签失败", False)
        except crypto.InvalidSignature:
            check("篡改 claims 后验签失败", True)

        # 12. 篡改顶层字段 -> 验签失败
        tampered2 = json.loads(json.dumps(body))
        tampered2["subject_did"] = alice + "x"
        try:
            crypto.verify(tampered2, sig_v1, did_doc["public_key"])
            check("篡改 subject_did 后验签失败", False)
        except crypto.InvalidSignature:
            check("篡改 subject_did 后验签失败", True)

        # 13. 密钥轮换
        st, r = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "issuer-key-2"})
        check("轮换 -> 200 且版本递增到 2",
              st == 200 and r.get("did") == issuer
              and r.get("key_handle") == "issuer-key-2"
              and r.get("key_version") == 2
              and "BEGIN PUBLIC KEY" in r.get("public_key", ""))
        new_pub = r["public_key"]
        check("轮换后 GET 当前公钥为新公钥、版本 2",
              _http("GET", f"{base}/v1/dids/{issuer}")[1]["public_key"] == new_pub)

        st, r = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "issuer-key-2"})
        check("重复句柄轮换 -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "issuer-key"})
        check("与历史句柄重复 -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": ""})
        check("空句柄轮换 -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "-----BEGIN PRIVATE KEY-----\nx"})
        check("PEM 句柄轮换 -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/dids/did:example:nope/keys/rotate",
                      {"key_handle": "x"})
        check("未知 DID 轮换 -> 404", st == 404)

        # 14. v1 凭证经历史公钥仍可验签，当前公钥验不过
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/verify",
                      {"signature": sig_v1})
        check("轮换后 v1 凭证经历史公钥验签 valid=true",
              st == 200 and r == {"valid": True})
        try:
            crypto.verify(body, sig_v1, new_pub)
            check("v1 签名不能用新公钥验过", False)
        except crypto.InvalidSignature:
            check("v1 签名不能用新公钥验过", True)

        # 15. 轮换后新签发凭证锚定版本 2
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"role": "user"}})
        check("v2 凭证响应 issuer_key_version=2",
              st == 201 and r["issuer_key_version"] == 2)
        cid2, sig_v2 = r["credential_id"], r["signature"]
        _, r = _http("GET", f"{base}/v1/credentials/{cid2}")
        check("v2 凭证正文 issuer_key_version=2",
              r["body"]["issuer_key_version"] == 2)
        st, r = _http("POST", f"{base}/v1/credentials/{cid2}/verify",
                      {"signature": sig_v2})
        check("v2 凭证用当前公钥验签 valid=true",
              st == 200 and r == {"valid": True})

        # 16. 验签接口失败场景：全部 200 + valid=false + 中文非空 reason
        def check_invalid(name, payload=None, raw=None, cred=cid):
            st, rr = _http("POST", f"{base}/v1/credentials/{cred}/verify",
                           payload=payload, raw=raw)
            ok = (
                st == 200
                and rr.get("valid") is False
                and isinstance(rr.get("reason"), str)
                and bool(rr["reason"].strip())
                and "PRIVATE KEY" not in json.dumps(rr)
            )
            check(name, ok)

        check_invalid("错误签名 -> 200 valid=false/中文原因",
                      {"signature": sig_v1[:-3] + "AAA"})
        check_invalid("未知凭证验签 -> 200 valid=false",
                      {"signature": sig_v1}, cred="vc_nope")
        check_invalid("缺 signature -> 200 valid=false", {})
        check_invalid("signature 非字符串 -> 200 valid=false",
                      {"signature": 123})
        check_invalid("请求体非对象 -> 200 valid=false", raw=b"[1, 2]")
        check_invalid("非法 JSON -> 200 valid=false", raw=b"{bad json")
        check_invalid("乱码签名不泄露内部信息 -> 200 valid=false",
                      {"signature": "@@@not-base64@@@"})

        # 17. CLI verify：有效凭证 true/0
        code, out, err = cli_verify(port, cid)
        check("CLI verify 有效凭证 -> true / 退出码 0",
              code == 0 and out == "true", )

        # 18. CLI verify：无效凭证 false / stderr 原因 / 退出码 1
        #    复制状态文件并破坏其中一条凭证签名，再起一个服务实例。
        proc.terminate()
        proc.wait(timeout=5)
        bad_store = tempfile.mktemp(suffix=".json")
        shutil.copy(store, bad_store)
        with open(bad_store, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        state["credentials"][cid]["signature"] = sig_v1[:-3] + "AAA"
        with open(bad_store, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        port2 = 8942
        proc2 = start_server(port2, bad_store)
        try:
            code, out, err = cli_verify(port2, cid)
            check("CLI verify 失效凭证 -> false / stderr 原因 / 退出码 1",
                  code == 1 and out == "false" and bool(err.strip()))
        finally:
            proc2.terminate()
            try:
                proc2.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc2.kill()
            if os.path.exists(bad_store):
                os.remove(bad_store)
        proc = None

    finally:
        if proc is not None:
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
