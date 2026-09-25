#!/usr/bin/env python3
"""POST /v1/trust/dids/deactivations/manifest/verify-batch 批量清单验真测试。

直接运行：python3 tests/trust_did_deactivations_manifest_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级非法（空体、非法 JSON、非对象、缺/多字段、items 非数组/空/
  超过 100 项）均 HTTP 200 且按键序返回 {"results":[],"reason":"请求…"}；
- 合法批次逐项不短路：成功项仅 {"valid":true}，失败项键序
  valid,reason，reason 恰为“清单非法”“锚点不可用”“签名格式错误”
  “签名校验失败”“导出内容不匹配”之一；项非对象、字段或类型非法按
  “清单非法”处理；结果与输入等长同序；
- 租户隔离（跨租户锚点不可用）、显式空租户头 400、纯只读不记审计、
  重启后结论稳定。
"""

import hashlib
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

BATCH_PATH = "/v1/trust/dids/deactivations/manifest/verify-batch"
MANIFEST_PATH = "/v1/trust/dids/deactivations/manifest"
EXPORT_PATH = "/v1/trust/dids/deactivations/export"


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def _keypair():
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
    port = 9027
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def batch(payload=None, raw_body=None, headers=None):
        return _http("POST", f"{base}{BATCH_PATH}", payload=payload,
                     raw_body=raw_body, headers=headers or TA)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # 签名本地 DID 与本租户锚点
        _http("POST", f"{base}/v1/dids",
              {"method": "web", "public_key": "batch-signer"}, TA)
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "batch-signer"}, TA)
        assert st == 201, raw
        signer = json.loads(raw)
        signer_did, signer_pub = signer["did"], signer["public_key"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": 1}, TA)
        assert st in (200, 201)

        # 一条停用通告，生成非空清单与对应 NDJSON
        ext_priv, ext_pub = _keypair()
        ext_did = "did:web:ext-batch.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ext_did, "public_key": ext_pub,
                       "key_version": 1}, TA)
        assert st == 201
        notice = {"did": ext_did, "key_version": 1, "reason": "机构业务终止",
                  "deactivated_at": "2026-01-01T00:00:00Z"}
        st, raw = _http(
            "POST", f"{base}/v1/trust/dids/deactivate-sync",
            {"body": notice, "signature": crypto.sign(notice, ext_priv)}, TA)
        assert st == 201, raw

        st, raw = _http(
            "GET", f"{base}{MANIFEST_PATH}?snapshot=1&signer_did={signer_did}",
            headers=TA)
        assert st == 200
        m1 = json.loads(raw)
        st, export_raw = _http(
            "GET", f"{base}{EXPORT_PATH}?snapshot=1", headers=TA)
        assert st == 200
        ndjson_text = export_raw.decode("utf-8")
        st, raw = _http(
            "GET", f"{base}{MANIFEST_PATH}?snapshot=0&signer_did={signer_did}",
            headers=TA)
        m0 = json.loads(raw)

        # ---------------------------------------------------------- #
        # 1. 请求级非法：均 200 + {"results":[],"reason":"请求…"}
        # ---------------------------------------------------------- #
        def expect_request_error(name, **kwargs):
            st, raw = batch(**kwargs)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"请求级 200/空结果/请求原因: {name}",
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r["results"] == []
                  and isinstance(r["reason"], str)
                  and r["reason"].startswith("请求"))

        expect_request_error("空体", raw_body=b"")
        expect_request_error("非法 JSON", raw_body=b"not json")
        expect_request_error("非对象(数组)", raw_body=b"[1,2]")
        expect_request_error("非对象(字符串)", payload="x")
        expect_request_error("缺 items", payload={})
        expect_request_error("多余字段",
                             payload={"items": [{"manifest": m0, "ndjson": ""}],
                                      "x": 1})
        expect_request_error("items 非数组", payload={"items": {}})
        expect_request_error("items 空数组", payload={"items": []})
        expect_request_error(
            "items 超限(101)",
            payload={"items": [{"manifest": m0, "ndjson": ""}] * 101})

        # 显式空租户头 400
        st, _ = _http("POST", f"{base}{BATCH_PATH}",
                      payload={"items": [{"manifest": m0, "ndjson": ""}]},
                      headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 合法批次：成功项与各类失败项混合，等长同序不短路
        # ---------------------------------------------------------- #
        bad_manifest = json.loads(json.dumps(m1))
        bad_manifest["alg"] = "SHA-512"
        unknown_anchor = json.loads(json.dumps(m1))
        unknown_anchor["signer_did"] = "did:web:unknown"
        bad_sig_fmt = json.loads(json.dumps(m1))
        bad_sig_fmt["signature"] = "abc"
        bad_sig = json.loads(json.dumps(m1))
        bad_sig["signature"] = "A" * 86

        items = [
            {"manifest": m1, "ndjson": ndjson_text},          # 0 成功
            {"manifest": m0, "ndjson": ""},                   # 1 成功(空页)
            "not-an-object",                                  # 2 清单非法
            {"manifest": m1},                                 # 3 清单非法(缺字段)
            {"manifest": m1, "ndjson": "", "x": 1},           # 4 清单非法(多字段)
            {"manifest": "x", "ndjson": ""},                  # 5 清单非法(类型)
            {"manifest": m1, "ndjson": 5},                    # 6 清单非法(类型)
            {"manifest": bad_manifest, "ndjson": ndjson_text},  # 7 清单非法
            {"manifest": unknown_anchor, "ndjson": ndjson_text},  # 8 锚点不可用
            {"manifest": bad_sig_fmt, "ndjson": ndjson_text},  # 9 签名格式错误
            {"manifest": bad_sig, "ndjson": ndjson_text},      # 10 签名校验失败
            {"manifest": m1, "ndjson": ndjson_text + "{}\n"},  # 11 导出内容不匹配
        ]
        st, raw = batch({"items": items})
        r = json.loads(raw.decode())
        check("批量 200 且仅含 results", st == 200 and list(r.keys()) == ["results"])
        res = r["results"]
        check("结果等长", len(res) == len(items))
        expected = [
            {"valid": True},
            {"valid": True},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "锚点不可用"},
            {"valid": False, "reason": "签名格式错误"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": False, "reason": "导出内容不匹配"},
        ]
        check("逐项结果与顺序正确（不短路）", res == expected)
        check("失败项键序 valid,reason",
              all(list(x.keys()) == ["valid", "reason"]
                  for x in res if not x["valid"]))
        check("成功项仅 valid 键",
              all(list(x.keys()) == ["valid"] for x in res if x["valid"]))

        # 上限边界：恰 100 项合法
        st, raw = batch({"items": [{"manifest": m0, "ndjson": ""}] * 100})
        r = json.loads(raw.decode())
        check("恰 100 项合法",
              st == 200 and len(r["results"]) == 100
              and all(x == {"valid": True} for x in r["results"]))

        # ---------------------------------------------------------- #
        # 3. 租户隔离：tenant-b 无签名 DID 锚点
        # ---------------------------------------------------------- #
        st, raw = batch({"items": [{"manifest": m1, "ndjson": ndjson_text}]},
                        headers=TB)
        r = json.loads(raw.decode())
        check("跨租户锚点不可用",
              st == 200
              and r["results"] == [{"valid": False, "reason": "锚点不可用"}])

        # ---------------------------------------------------------- #
        # 4. 纯只读：审计不变
        # ---------------------------------------------------------- #
        _, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        batch({"items": items})
        _, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("批量验真不记审计", audit_before == audit_after)

        # ---------------------------------------------------------- #
        # 5. 跨重启结论稳定
        # ---------------------------------------------------------- #
        proc.terminate(); proc.wait(timeout=10)
        proc = start()
        st, raw = batch({"items": [
            {"manifest": m1, "ndjson": ndjson_text},
            {"manifest": m1, "ndjson": ""},
        ]})
        r = json.loads(raw.decode())
        check("重启后结论稳定",
              st == 200 and r["results"] == [
                  {"valid": True},
                  {"valid": False, "reason": "导出内容不匹配"},
              ])

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store):
            os.remove(store)

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
