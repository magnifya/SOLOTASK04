#!/usr/bin/env python3
"""POST /v1/trust/dids/deactivations/manifest/verify-batch 批量清单验真测试。

直接运行：python3 tests/trust_did_deactivations_manifest_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级非法（空体、非法 JSON、非对象、字段缺失/多余、items 非数组、
  空数组、超过 100 项）均 200 且按键序 {"results":[],"reason":"请求..."}；
- 合法批次 200 仅含等长同序 results，逐项不短路；项非对象、字段或类型
  非法按“清单非法”；逐项沿用单项验真顺序（清单结构 -> 锚点 -> 签名
  格式 -> 签名 -> 摘要/行数），失败原因恰为五种之一，成功仅
  {"valid":true}，失败键序 valid、reason；
- 100 项边界、租户隔离（缺省 default、显式空 400、跨租户锚点不可用）、
  纯只读不记审计、结论跨重启稳定。
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
    port = 9041
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
                     raw_body=raw_body, headers=headers)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # 签名本地 DID + 本租户 active 锚点
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

        # 一条外部停用通告，使导出非空
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
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot=1&signer_did={signer_did}",
            headers=TA)
        assert st == 200
        m1 = json.loads(raw)
        st, export_raw = _http(
            "GET", f"{base}{EXPORT_PATH}?snapshot=1", headers=TA)
        assert st == 200
        ndjson_text = export_raw.decode("utf-8")
        assert hashlib.sha256(export_raw).hexdigest() == m1["digest"]

        # ---------------------------------------------------------- #
        # 1. 请求级非法：200 + {"results":[],"reason":"请求..."}
        # ---------------------------------------------------------- #
        def expect_request_invalid(name, **kwargs):
            st, raw = batch(**kwargs)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"请求级非法 200: {name}",
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r["results"] == []
                  and isinstance(r["reason"], str)
                  and r["reason"].startswith("请求"))

        expect_request_invalid("空体", raw_body=b"")
        expect_request_invalid("非法 JSON", raw_body=b"not json")
        expect_request_invalid("非对象(数组)", raw_body=b"[1,2]")
        expect_request_invalid("非对象(字符串)", raw_body=b'"x"')
        expect_request_invalid("缺 items", payload={"manifest": m1})
        expect_request_invalid("多余字段",
                               payload={"items": [], "x": 1})
        expect_request_invalid("items 非数组", payload={"items": "x"})
        expect_request_invalid("items 空数组", payload={"items": []})
        expect_request_invalid(
            "items 超限(101)",
            payload={"items": [{"manifest": m1,
                                "ndjson": ndjson_text}] * 101})

        # 显式空租户头仍 400（仅 error）
        st, raw = batch(payload={"items": []}, headers={"X-Tenant-ID": ""})
        r = json.loads(raw.decode() or "{}")
        check("显式空租户头 400 仅 error",
              st == 400 and list(r.keys()) == ["error"])

        # ---------------------------------------------------------- #
        # 2. 合法批次：等长同序、逐项不短路、五种失败原因
        # ---------------------------------------------------------- #
        bad_struct = json.loads(json.dumps(m1)); bad_struct.pop("alg")
        bad_anchor = json.loads(json.dumps(m1))
        bad_anchor["signer_did"] = "did:web:no-such-anchor"
        bad_sigfmt = json.loads(json.dumps(m1)); bad_sigfmt["signature"] = "abc"
        bad_sig = json.loads(json.dumps(m1))
        bad_sig["signature"] = "A" * 86

        items = [
            {"manifest": m1, "ndjson": ndjson_text},          # valid
            "not-an-object",                                  # 清单非法
            {"manifest": m1},                                 # 清单非法(缺键)
            {"manifest": m1, "ndjson": ndjson_text, "x": 1},  # 清单非法(多键)
            {"manifest": "x", "ndjson": ndjson_text},         # 清单非法(类型)
            {"manifest": m1, "ndjson": 5},                    # 清单非法(类型)
            {"manifest": bad_struct, "ndjson": ndjson_text},  # 清单非法(结构)
            {"manifest": bad_anchor, "ndjson": ndjson_text},  # 锚点不可用
            {"manifest": bad_sigfmt, "ndjson": ndjson_text},  # 签名格式错误
            {"manifest": bad_sig, "ndjson": ndjson_text},     # 签名校验失败
            {"manifest": m1, "ndjson": ndjson_text + "{}\n"},  # 内容不匹配
            {"manifest": m1, "ndjson": ndjson_text},          # valid(不短路)
        ]
        st, raw = batch(payload={"items": items}, headers=TA)
        r = json.loads(raw.decode())
        expected = [
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
            {"valid": True},
        ]
        check("混合批次 200 且等长同序不短路",
              st == 200 and list(r.keys()) == ["results"]
              and r["results"] == expected)
        check("失败项键序 valid,reason",
              all(list(item.keys()) == ["valid", "reason"]
                  for item in r["results"] if item.get("valid") is False))
        check("成功项仅 valid 键",
              all(list(item.keys()) == ["valid"]
                  for item in r["results"] if item.get("valid") is True))

        # 100 项边界合法
        st, raw = batch(
            payload={"items": [{"manifest": m1,
                                "ndjson": ndjson_text}] * 100},
            headers=TA)
        r = json.loads(raw.decode())
        check("100 项边界全部 valid",
              st == 200 and len(r["results"]) == 100
              and all(item == {"valid": True} for item in r["results"]))

        # 单项与批量结论一致（空页清单 + 空串）
        st, raw = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot=0&signer_did={signer_did}",
            headers=TA)
        m0 = json.loads(raw)
        st, raw = batch(payload={"items": [{"manifest": m0, "ndjson": ""}]},
                        headers=TA)
        check("空页清单批量 valid",
              st == 200 and json.loads(raw.decode())["results"]
              == [{"valid": True}])

        # ---------------------------------------------------------- #
        # 3. 租户隔离：缺省 default 无锚点；跨租户锚点不可用
        # ---------------------------------------------------------- #
        st, raw = batch(payload={"items": [{"manifest": m1,
                                            "ndjson": ndjson_text}]})
        check("缺省 default 租户 -> 锚点不可用",
              st == 200 and json.loads(raw.decode())["results"]
              == [{"valid": False, "reason": "锚点不可用"}])
        st, raw = batch(payload={"items": [{"manifest": m1,
                                            "ndjson": ndjson_text}]},
                        headers=TB)
        check("跨租户 -> 锚点不可用",
              st == 200 and json.loads(raw.decode())["results"]
              == [{"valid": False, "reason": "锚点不可用"}])

        # ---------------------------------------------------------- #
        # 4. 纯只读：审计不变；跨重启结论稳定
        # ---------------------------------------------------------- #
        _, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        batch(payload={"items": items}, headers=TA)
        _, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("批量验真不记审计", audit_before == audit_after)

        proc.terminate(); proc.wait(timeout=10)
        proc = start()
        st, raw = batch(payload={"items": items}, headers=TA)
        r = json.loads(raw.decode())
        check("重启后同批次结论一致",
              st == 200 and r["results"] == expected)

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
