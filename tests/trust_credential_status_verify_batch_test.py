#!/usr/bin/env python3
"""外部凭证状态签名声明批量验真
POST /v1/trust/credential-status/verify-batch 的端到端测试。

直接运行：python3 tests/trust_credential_status_verify_batch_test.py
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

PATH = "/v1/trust/credential-status/verify-batch"
_UNSET = object()


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


def start(store_path, port):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(proc, port), "服务启动超时"
    return proc


def main():
    port = 8977
    store_path = tempfile.mktemp(suffix=".json")
    proc = start(store_path, port)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify_batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{PATH}", payload,
                     headers=headers, raw=raw)

    def get_status(credential_id, headers, issuer):
        url = (f"{base}/v1/trust/credential-status/"
               f"{quote(credential_id)}?issuer_did={quote(issuer)}")
        return _http("GET", url, headers=headers)

    def audit_actions(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e["action"] for e in r["events"]]

    T1 = {"X-Tenant-ID": "tv-a"}
    T2 = {"X-Tenant-ID": "tv-b"}

    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    did = "did:web:issuer-verify-batch.example"
    no_anchor_did = "did:web:missing-anchor-verify-batch.example"
    no_status_did = "did:web:no-status-use-verify-batch.example"

    try:
        st, r = verify_batch({"items": []}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and r.get("error"))

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1)
        check("注册锚点 v1 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 2},
            headers=T1)
        check("注册锚点 v2 -> 201", st == 201)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{quote(did)}/2/status",
            {"status": "revoked"}, headers=T1)
        check("吊销锚点 v2 -> 200", st == 200)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": no_status_did, "public_key": pub1,
             "key_version": 1, "uses": ["vc"]},
            headers=T1)
        check("注册仅 vc 用途锚点 -> 201", st == 201)

        def make_body(credential_id, status="active",
                      updated="2026-09-21T00:00:00Z", version=1,
                      reason=_UNSET, issuer=did):
            body = {
                "issuer_did": issuer,
                "credential_id": credential_id,
                "status": status,
                "updated_at": updated,
                "issuer_key_version": version,
            }
            if reason is not _UNSET:
                body["reason"] = reason
            return body

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        def expect_bad_request(name, payload=None, raw=None):
            st, r = verify_batch(payload=payload, raw=raw, headers=T1)
            check(
                name,
                st == 200 and r == {"results": [], "reason": "请求非法"},
            )

        expect_bad_request("空请求体", raw=b"")
        expect_bad_request("非法 JSON", raw=b"not-json")
        expect_bad_request("JSON 非对象（数组）", raw=b"[1]")
        expect_bad_request("JSON 非对象（字符串）", raw=b'"x"')
        expect_bad_request("缺 items", {})
        expect_bad_request("顶层多余字段", {"items": [], "x": 1})
        expect_bad_request("items 非数组（对象）", {"items": {}})
        expect_bad_request("items 非数组（字符串）", {"items": "x"})
        expect_bad_request("items 空数组", {"items": []})
        expect_bad_request("items 101 项超上限",
                           {"items": [signed(make_body(f"vc_over_{i}"))
                                      for i in range(101)]})

        st, _ = get_status("vc_over_0", T1, did)
        check("超上限不写入（GET 404）", st == 404)

        body_ok = make_body("vc_ok")
        body_missing = dict(make_body("vc_missing"))
        del body_missing["updated_at"]
        body_bad_status = dict(make_body("vc_bad_status"), status="bogus")
        body_bad_version = dict(make_body("vc_bad_version"),
                                issuer_key_version=0)
        body_bool_version = dict(make_body("vc_bool_version"),
                                 issuer_key_version=True)
        body_bad_time = dict(make_body("vc_bad_time"),
                             updated_at="2026-09-21 00:00:00")
        body_suspend_no_reason = make_body("vc_s1", status="suspended")
        body_suspend_blank = make_body("vc_s2", status="suspended",
                                       reason="   ")
        body_suspend_long = make_body(
            "vc_s3", status="suspended", reason="好" * 257)
        body_suspend_reason_num = make_body(
            "vc_s4", status="suspended", reason=123)
        body_active_empty_reason = make_body("vc_a1", reason="")
        body_extra = dict(make_body("vc_extra_field"), nope=1)
        body_no_anchor = make_body("vc_no_anchor", issuer=no_anchor_did)
        body_revoked_anchor = make_body("vc_revoked_anchor", version=2)
        body_no_status_use = make_body(
            "vc_no_status_use", issuer=no_status_did)
        body_bad_sig_fmt = make_body("vc_bad_sig")
        body_wrong_sig = make_body("vc_wrong_sig")
        body_revoked_ok = make_body(
            "vc_revoked_ok", status="revoked", reason="持证人违规")
        body_unknown_ok = make_body("vc_unknown_ok", status="unknown")
        body_suspended_ok = make_body(
            "vc_suspended_ok", status="suspended", reason=" 暂停原因 ")
        body_suspended_unicode = make_body(
            "vc_suspended_u", status="suspended", reason="好" * 256)
        body_active_reason_ok = make_body(
            "vc_active_reason", status="active", reason="x")
        wrong_sig = crypto.sign(make_body("vc_other_body"), priv1)

        items = [
            signed(body_ok),                                   # 0 valid
            [1, 2, 3],                                         # 1 项非法
            {"body": body_ok, "signature": ""},                # 2 项非法
            {"body": "x", "signature": "y"},                   # 3 项非法
            {"body": body_ok, "signature": "z", "x": 1},       # 4 项非法
            {"body": body_missing, "signature": "x"},          # 5 声明非法
            {"body": body_bad_status, "signature": "x"},       # 6
            {"body": body_bad_version, "signature": "x"},      # 7
            {"body": body_bool_version, "signature": "x"},     # 8
            {"body": body_bad_time, "signature": "x"},         # 9
            {"body": body_suspend_no_reason, "signature": "x"},  # 10
            {"body": body_suspend_blank, "signature": "x"},    # 11
            {"body": body_suspend_long, "signature": "x"},     # 12
            {"body": body_suspend_reason_num, "signature": "x"},  # 13
            {"body": body_active_empty_reason, "signature": "x"},  # 14
            {"body": body_extra, "signature": "x"},            # 15
            {"body": 1, "signature": "x"},                     # 16 项非法
            signed(body_no_anchor),                            # 17 锚点
            signed(body_revoked_anchor, priv2),                # 18 锚点
            signed(body_no_status_use),                        # 19 锚点
            {"body": body_bad_sig_fmt, "signature": "!!!bad!!!"},  # 20 格式
            {"body": body_wrong_sig, "signature": wrong_sig},  # 21 验签失败
            signed(body_revoked_ok),                           # 22 valid
            signed(body_unknown_ok),                           # 23 valid
            signed(body_suspended_ok),                         # 24 valid
            signed(body_suspended_unicode),                    # 25 valid
            signed(body_active_reason_ok),                     # 26 valid
        ]
        st, r = verify_batch({"items": items}, headers=T1)
        check("混合批 HTTP 200 且仅含 results",
              st == 200 and list(r.keys()) == ["results"])
        results = r.get("results")
        check("results 等长同序",
              isinstance(results, list) and len(results) == len(items))

        def valid_row(row):
            return row == {"valid": True}

        def fail_row(row, reason):
            return row == {"valid": False, "reason": reason}

        if isinstance(results, list) and len(results) == len(items):
            for idx in (0, 22, 23, 24, 25, 26):
                check(f"results[{idx}] 成功仅 valid:true",
                      valid_row(results[idx]))
            for idx in (1, 2, 3, 4, 16):
                check(f"results[{idx}] 请求项非法",
                      fail_row(results[idx], "请求项非法"))
            for idx in range(5, 16):
                check(f"results[{idx}] 状态声明非法",
                      fail_row(results[idx], "状态声明非法"))
            for idx in (17, 18, 19):
                check(f"results[{idx}] 锚点不可用",
                      fail_row(results[idx], "锚点不可用"))
            check("results[20] 签名格式错误",
                  fail_row(results[20], "签名格式错误"))
            check("results[21] 签名校验失败",
                  fail_row(results[21], "签名校验失败"))

        for cid in ("vc_ok", "vc_revoked_ok", "vc_unknown_ok",
                    "vc_suspended_ok"):
            st, _ = get_status(cid, T1, did)
            check(f"{cid} 未写入同步状态（404）", st == 404)
        check("不记 trust.credential.status.synced 审计",
              "trust.credential.status.synced" not in audit_actions(T1))

        # 租户隔离：T2 无锚点，全部锚点不可用
        st, r = verify_batch(
            {"items": [signed(body_ok), signed(body_revoked_ok)]},
            headers=T2)
        check("跨租户锚点不可用",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"},
              ])

        # 恰 100 项边界
        st, r = verify_batch(
            {"items": [signed(make_body(f"vc_bound_{i}"))
                       for i in range(100)]},
            headers=T1)
        check("100 项边界全部成功",
              st == 200 and len(r["results"]) == 100
              and all(row == {"valid": True} for row in r["results"]))

        # 重启后同一批结论一致（只读、由持久化状态决定）
        mixed_request = {"items": items}
        proc.terminate()
        proc.wait(timeout=10)
        proc = start(store_path, port)
        st, r2 = verify_batch(mixed_request, headers=T1)
        check("重启后同一批结论一致",
              st == 200 and r2.get("results") == results)
        check("重启后仍无落盘",
              all(
                  get_status(cid, T1, did)[0] == 404
                  for cid in ("vc_ok", "vc_revoked_ok")
              ))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
