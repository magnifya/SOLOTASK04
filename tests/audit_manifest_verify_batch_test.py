#!/usr/bin/env python3
"""POST /v1/audit/manifest/verify-batch 批量审计签名清单验真测试。

直接运行：python3 tests/audit_manifest_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BATCH_PATH = "/v1/audit/manifest/verify-batch"
MANIFEST_PATH = "/v1/audit/manifest"


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


def main():
    port = 9037
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

        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "batch-auditor"}, TA)
        assert st == 201, raw
        signer = json.loads(raw)
        signer_did = signer["did"]
        signer_pub = signer["public_key"]

        st, _ = _http("POST", f"{base}/v1/dids",
                      {"method": "web", "public_key": "batch-subject"}, TA)
        assert st == 201
        st, audit_raw = _http("GET", f"{base}/v1/audit?limit=200",
                              headers=TA)
        assert st == 200
        max_seq = json.loads(audit_raw)["events"][-1]["seq"]

        st, raw = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot={max_seq}"
            f"&signer_did={signer_did}",
            headers=TA)
        assert st == 200, raw
        m1 = json.loads(raw)

        def expect_request_invalid(name, **kwargs):
            st, raw = batch(**kwargs)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"请求级非法 200: {name}",
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r == {"results": [], "reason": "请求非法"})

        expect_request_invalid("空体", raw_body=b"")
        expect_request_invalid("非法 JSON", raw_body=b"{")
        expect_request_invalid("非对象(数组)", raw_body=b"[1]")
        expect_request_invalid("非对象(字符串)", raw_body=b'"x"')
        expect_request_invalid("非对象(数字)", raw_body=b"1")
        expect_request_invalid("缺 items", payload={"manifest": m1})
        expect_request_invalid("多余字段", payload={"items": [], "x": 1})
        expect_request_invalid("items 非数组", payload={"items": "x"})
        expect_request_invalid("items 空数组", payload={"items": []})
        expect_request_invalid(
            "items 超限 101",
            payload={"items": [{"manifest": m1}] * 101})

        st, raw = batch(payload={"items": []},
                        headers={"X-Tenant-ID": ""})
        r = json.loads(raw.decode() or "{}")
        check("显式空租户头 400 error=请求非法",
              st == 400 and list(r.keys()) == ["error"]
              and r["error"] == "请求非法")

        st, raw = batch(payload={"items": [{"manifest": m1}]}, headers=TA)
        check("无锚点 -> 锚点不可用",
              st == 200 and json.loads(raw)["results"]
              == [{"valid": False, "reason": "锚点不可用"}])

        st, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": signer_did, "public_key": signer_pub,
            "key_version": 1, "uses": ["generic", "vc"]}, TA)
        assert st in (200, 201)

        bad_struct = copy.deepcopy(m1)
        del bad_struct["count"]
        bad_anchor = copy.deepcopy(m1)
        bad_anchor["signer_did"] = "did:web:no-such-audit-anchor"
        bad_sigfmt = copy.deepcopy(m1)
        bad_sigfmt["signature"] = "@@@"
        bad_sig = copy.deepcopy(m1)
        bad_sig["signature"] = "A" * 86
        bad_body = copy.deepcopy(m1)
        bad_body["events"][0]["action"] = "tampered.event"

        items = [
            {"manifest": m1},
            "not-an-object",
            42,
            None,
            {},
            {"manifest": m1, "x": 1},
            {"manifest": "x"},
            {"manifest": None},
            {"manifest": []},
            {"manifest": bad_struct},
            {"manifest": bad_anchor},
            {"manifest": bad_sigfmt},
            {"manifest": bad_sig},
            {"manifest": bad_body},
            {"manifest": m1},
        ]
        expected = [
            {"valid": True},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "清单非法"},
            {"valid": False, "reason": "锚点不可用"},
            {"valid": False, "reason": "签名格式错误"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": True},
        ]
        st, raw = batch(payload={"items": items}, headers=TA)
        r = json.loads(raw)
        check("混合批次 200 等长同序不短路",
              st == 200 and list(r.keys()) == ["results"]
              and r["results"] == expected)
        check("失败项键序 valid,reason",
              all(list(x.keys()) == ["valid", "reason"]
                  for x in r["results"] if x.get("valid") is False))
        check("成功项仅 valid",
              all(list(x.keys()) == ["valid"]
                  for x in r["results"] if x.get("valid") is True))

        st, raw = batch(payload={"items": [{"manifest": m1}] * 100},
                        headers=TA)
        r = json.loads(raw)
        check("100 项边界全部 valid",
              st == 200 and r["results"] == [{"valid": True}] * 100)

        st, raw = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot=0&signer_did={signer_did}",
            headers=TA)
        assert st == 200
        m0 = json.loads(raw)
        st, raw = batch(payload={"items": [{"manifest": m0}]}, headers=TA)
        check("空页清单批量 valid",
              st == 200 and json.loads(raw)["results"]
              == [{"valid": True}])

        st, raw = batch(payload={"items": [{"manifest": m1}]})
        check("缺省 default -> 锚点不可用",
              st == 200 and json.loads(raw)["results"]
              == [{"valid": False, "reason": "锚点不可用"}])
        st, raw = batch(payload={"items": [{"manifest": m1}]}, headers=TB)
        check("跨租户 -> 锚点不可用",
              st == 200 and json.loads(raw)["results"]
              == [{"valid": False, "reason": "锚点不可用"}])

        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web",
                         "public_key": "vc-only-auditor"}, TA)
        assert st == 201
        vc = json.loads(raw)
        st, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": vc["did"], "public_key": vc["public_key"],
            "key_version": 1, "uses": ["vc"]}, TA)
        assert st in (200, 201)
        st, raw = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot={max_seq}"
            f"&signer_did={vc['did']}",
            headers=TA)
        assert st == 200
        mvc = json.loads(raw)
        st, raw = batch(payload={"items": [{"manifest": mvc}]}, headers=TA)
        check("锚点无 generic 用途 -> 锚点不可用",
              st == 200 and json.loads(raw)["results"]
              == [{"valid": False, "reason": "锚点不可用"}])

        _, before = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        batch(payload={"items": items}, headers=TA)
        _, after = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("批量验真不记审计", before == after)

        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = batch(payload={"items": items}, headers=TA)
        check("重启后同批次结论一致",
              st == 200 and json.loads(raw)["results"] == expected)

        st, raw = _http("POST", f"{base}/v1/audit/manifest/verify",
                        {"manifest": m1}, TA)
        check("单条验真仍 valid",
              st == 200 and json.loads(raw) == {"valid": True})
        st, _ = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot={max_seq}"
            f"&signer_did={signer_did}",
            headers=TA)
        check("GET 清单仍 200", st == 200)
        st, _ = _http("GET", f"{base}/v1/audit?limit=1", headers=TA)
        check("GET 审计仍 200", st == 200)

        valid_item = {"manifest": m1}

        def run_round(mutation):
            barrier = threading.Barrier(2)
            outcomes = {}

            def verify_all():
                barrier.wait()
                st, raw = batch(
                    payload={"items": [valid_item] * 100}, headers=TA)
                outcomes["verify"] = (st, json.loads(raw.decode()))

            worker = threading.Thread(target=verify_all)
            worker.start()
            barrier.wait()
            outcomes["mutation"] = mutation()
            worker.join()
            return outcomes

        def assert_uniform(name, outcomes):
            st, r = outcomes["verify"]
            results = r.get("results", [])
            distinct = {json.dumps(x, sort_keys=True) for x in results}
            check(f"{name}: 100 项结论不混合",
                  st == 200 and len(results) == 100 and len(distinct) == 1)
            check(f"{name}: 全 valid 或全锚点不可用",
                  distinct
                  <= {json.dumps({"valid": True}, sort_keys=True),
                      json.dumps({"valid": False,
                                  "reason": "锚点不可用"},
                                 sort_keys=True)})

        for round_no in range(3):
            outcomes = run_round(lambda: _http(
                "PUT",
                f"{base}/v1/trust/anchors/{signer_did}/1/status",
                {"status": "revoked"}, TA))
            assert outcomes["mutation"][0] == 200, outcomes["mutation"]
            assert_uniform(f"并发吊销第 {round_no + 1} 轮", outcomes)

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
    print("审计清单批量验真测试全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
