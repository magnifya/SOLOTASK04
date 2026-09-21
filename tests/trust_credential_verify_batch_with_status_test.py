#!/usr/bin/env python3
"""批量外部凭证验真并合并状态 POST /v1/trust/credentials/verify-batch-with-status。

直接运行：python3 tests/trust_credential_verify_batch_with_status_test.py
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


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    port = 8955
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/verify-batch-with-status"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"
        T1 = {"X-Tenant-ID": "tvbws-a"}
        T2 = {"X-Tenant-ID": "tvbws-b"}

        priv1, pub1 = gen_keypair()
        did = "did:web:ext-bws.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册锚点 -> 201", st == 201)

        def make_body(cred_id="vc_bws", **extra):
            body = {
                "credential_id": cred_id,
                "issuer_did": did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin"},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
            body.update(extra)
            return body

        def item(body, priv=priv1, bad_sig=False):
            sig = crypto.sign(body, priv)
            if bad_sig:
                sig = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
            return {"body": body, "signature": sig}

        def batch(items, headers=T1, **kw):
            return _http("POST", f"{base}{path}",
                         {"credentials": items}, headers=headers, **kw)

        def sync(cred_id, status, reason=_DELETE, updated_at=None):
            sb = {
                "issuer_did": did,
                "credential_id": cred_id,
                "status": status,
                "updated_at": updated_at or utc_z(timedelta(days=-1)),
                "issuer_key_version": 1,
            }
            if reason is not _DELETE:
                sb["reason"] = reason
            return _http("POST",
                         f"{base}/v1/trust/credential-status/sync",
                         {"body": sb, "signature": crypto.sign(sb, priv1)},
                         headers=T1)

        # 预置同步状态：active / revoked(带原因) / unknown
        check("同步 active -> 201", sync("vc_active", "active")[0] == 201)
        check("同步 revoked -> 201",
              sync("vc_rev", "revoked", reason="持证人违规")[0] == 201)
        check("同步 unknown -> 201", sync("vc_unk", "unknown")[0] == 201)

        # ---- 请求级错误：统一 200 + {"results": [], "reason": "请求..."} ----
        def check_request_error(name, st, r):
            check(name, st == 200 and r.get("results") == []
                  and isinstance(r.get("reason"), str)
                  and r["reason"].startswith("请求"))

        st, r = _http("POST", f"{base}{path}", headers=T1)  # 无请求体
        check_request_error("缺请求体 -> 200/请求原因", st, r)
        st, r = _http("POST", f"{base}{path}", raw=b"{not json",
                      headers=T1)
        check_request_error("非法 JSON -> 200/请求原因", st, r)
        st, r = _http("POST", f"{base}{path}", raw=b"[1,2]", headers=T1)
        check_request_error("非对象 -> 200/请求原因", st, r)
        st, r = _http("POST", f"{base}{path}", {}, headers=T1)
        check_request_error("缺少 credentials -> 200/请求原因", st, r)
        st, r = _http("POST", f"{base}{path}",
                      {"credentials": [item(make_body("vc_active"))],
                       "extra": 1}, headers=T1)
        check_request_error("多余字段 -> 200/请求原因", st, r)
        st, r = _http("POST", f"{base}{path}",
                      {"credentials": "not-a-list"}, headers=T1)
        check_request_error("credentials 非数组 -> 200/请求原因", st, r)
        st, r = batch([])
        check_request_error("空数组 -> 200/请求原因", st, r)
        st, r = batch([item(make_body("vc_active"))] * 101)
        check_request_error("超过 100 项 -> 200/请求原因", st, r)

        # 边界：1 项与 100 项均合法
        st, r = batch([item(make_body("vc_active"))])
        check("1 项合法", st == 200 and r.get("results") == [{"valid": True}])
        st, r = batch([item(make_body("vc_active"))] * 100)
        check("100 项合法",
              st == 200 and len(r.get("results", [])) == 100
              and all(x == {"valid": True} for x in r["results"]))

        # ---- 混合批次：逐项处理、不短路、等长同序 ----
        items = [
            item(make_body("vc_active")),                       # 0 成功
            item(make_body("vc_rev")),                          # 1 revoked
            item(make_body("vc_unk")),                          # 2 unknown
            item(make_body("vc_nosync")),                       # 3 未同步
            "not-an-object",                                    # 4 项级类型错误
            {"body": make_body("vc_active")},                   # 5 缺 signature
            {"body": make_body("vc_active"), "signature": "x",
             "extra": 1},                                       # 6 项级多余字段
            {"body": {"credential_id": "x"}, "signature": "x"},  # 7 凭证字段缺失
            item(make_body("vc_active"), bad_sig=True),         # 8 签名失败
            item(make_body("vc_active",
                           expires_at=utc_z(timedelta(hours=-1)))),  # 9 已过期
            item(make_body("vc_active", ext_a="x")),            # 10 扩展字段成功
        ]
        st, r = batch(items)
        res = r.get("results", [])
        check("混合批次 200 且等长", st == 200 and len(res) == len(items))
        check("0 active 成功且无 reason", res[0] == {"valid": True})
        check("1 revoked 带保存原因",
              res[1] == {"valid": False,
                         "reason": "外部凭证已吊销：持证人违规"})
        check("2 unknown", res[2] == {"valid": False,
                                      "reason": "外部凭证状态未知"})
        check("3 未同步", res[3] == {"valid": False,
                                     "reason": "外部凭证状态未同步"})
        check("4 项级类型错误 -> 请求前缀",
              res[4].get("valid") is False
              and res[4].get("reason", "").startswith("请求"))
        check("5 缺 signature -> 请求前缀",
              res[5].get("valid") is False
              and res[5].get("reason", "").startswith("请求"))
        check("6 项级多余字段 -> 请求前缀",
              res[6].get("valid") is False
              and res[6].get("reason", "").startswith("请求"))
        check("7 凭证字段缺失 -> 凭证前缀",
              res[7].get("valid") is False
              and res[7].get("reason", "").startswith("凭证"))
        check("8 签名失败 -> 签名校验失败前缀",
              res[8].get("valid") is False
              and res[8].get("reason", "").startswith("签名校验失败"))
        check("9 已过期", res[9] == {"valid": False, "reason": "凭证已过期"})
        check("10 扩展字段成功", res[10] == {"valid": True})
        check("失败项 reason 均非空",
              all(x.get("reason") for x in res if x.get("valid") is False))
        check("成功项均不含 reason",
              all("reason" not in x for x in res if x.get("valid") is True))

        # 省略 issuer_key_version：按版本 1 验签且不注入正文
        body_no_ver = {k: v for k, v in make_body("vc_active").items()
                       if k != "issuer_key_version"}
        st, r = batch([{"body": body_no_ver,
                        "signature": crypto.sign(body_no_ver, priv1)}])
        check("省略版本按 1 验签 + active",
              st == 200 and r.get("results") == [{"valid": True}])

        # ---- 租户协议 ----
        st, r = _http("POST", f"{base}{path}",
                      {"credentials": [item(make_body("vc_active"))]},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)
        # 缺省 default 租户：无锚点，逐项失败而非请求级错误
        st, r = _http("POST", f"{base}{path}",
                      {"credentials": [item(make_body("vc_active"))]})
        check("缺省 default 租户逐项锚点不存在",
              st == 200 and len(r.get("results", [])) == 1
              and r["results"][0].get("valid") is False
              and r["results"][0].get("reason", "").startswith("锚点不存在"))
        # 跨租户隔离：他租户看不到锚点与同步状态
        st, r = batch([item(make_body("vc_active"))], headers=T2)
        check("他租户逐项锚点不存在",
              st == 200 and r["results"][0].get("valid") is False
              and r["results"][0].get("reason", "").startswith("锚点不存在"))

        # ---- 只读：不新增审计、不改变同步记录 ----
        _, before = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                          headers=T1)
        batch(items)
        _, after_pages = _http("GET", f"{base}/v1/audit?limit=200&after=0",
                               headers=T1)
        check("只读：不新增审计",
              len(before.get("events", []))
              == len(after_pages.get("events", [])))
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/vc_rev?issuer_did={did}",
            headers=T1)
        check("同步记录保持不变",
              st == 200 and r.get("status") == "revoked"
              and r.get("reason") == "持证人违规")

        # 既有接口不受影响：单项与批量纯验真仍可用
        st, r = _http("POST", f"{base}/v1/trust/credentials/verify-batch",
                      {"credentials": [item(make_body("vc_active"))]},
                      headers=T1)
        check("既有批量纯验真不受影响",
              st == 200 and r.get("results") == [{"valid": True}])
        st, r = _http("POST",
                      f"{base}/v1/trust/credentials/verify-with-status",
                      item(make_body("vc_active")), headers=T1)
        check("既有单项 with-status 不受影响",
              st == 200 and r == {"valid": True})

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 重启持久化：同一状态文件新起服务，状态合并结论保持一致。
    port2 = port + 100
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port2), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base2 = f"http://127.0.0.1:{port2}"
    try:
        assert wait_up(port2), "重启服务启动超时"
        items = [item(make_body("vc_active")), item(make_body("vc_rev"))]
        st, r = _http(
            "POST", f"{base2}{path}", {"credentials": items},
            headers={"X-Tenant-ID": "tvbws-a"})
        check("重启后状态合并结论持久化",
              st == 200 and r.get("results") == [
                  {"valid": True},
                  {"valid": False, "reason": "外部凭证已吊销：持证人违规"}])
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


_DELETE = object()


if __name__ == "__main__":
    main()
