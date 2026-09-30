#!/usr/bin/env python3
"""POST /v1/audit/manifest/verify-batch 批量审计清单验真端到端测试。

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

MANIFEST_PATH = "/v1/audit/manifest"
BATCH_PATH = "/v1/audit/manifest/verify-batch"
VERIFY_PATH = "/v1/audit/manifest/verify"


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
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
            time.sleep(0.1)
    return False


def main():
    port = 9032
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
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web",
                         "public_key": "batch-auditor"}, TA)
        assert st == 201, raw
        signer_did = json.loads(raw)["did"]
        signer_pub = json.loads(raw)["public_key"]

        st, raws = _http("POST", f"{base}/v1/dids",
                         {"method": "web",
                          "public_key": "batch-subject"}, TA)
        assert st == 201
        sub_did = json.loads(raws)["did"]
        st, _ = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": signer_did, "subject_did": sub_did,
            "claims": {"role": "admin"}}, TA)
        assert st == 201
        st, audit_raw = _http("GET", f"{base}/v1/audit?limit=200",
                              headers=TA)
        max_seq = json.loads(audit_raw)["events"][-1]["seq"]
        st, raw = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot={max_seq}"
            f"&signer_did={signer_did}",
            headers=TA)
        assert st == 200
        manifest = json.loads(raw)

        st, raws = _http("POST", f"{base}/v1/trust/anchors", {
            "did": signer_did, "public_key": signer_pub,
            "key_version": 1, "uses": ["generic"]}, TA)
        assert st == 201, raws

        st, raws = _http("POST", f"{base}/v1/dids",
                         {"method": "web", "public_key": "vc-only"}, TA)
        assert st == 201
        vc_did = json.loads(raws)["did"]
        vc_pub = json.loads(raws)["public_key"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": vc_did, "public_key": vc_pub,
            "key_version": 1, "uses": ["vc"]}, TA)
        assert st == 201
        st, raw = _http(
            "GET",
            f"{base}{MANIFEST_PATH}?snapshot={max_seq}"
            f"&signer_did={vc_did}",
            headers=TA)
        assert st == 200
        vc_manifest = json.loads(raw)

        def batch(items, headers=None):
            return _http("POST", base + BATCH_PATH,
                         {"items": items}, headers=headers)

        invalid_expectation = {"results": [], "reason": "请求非法"}

        stx, rawx = _http("POST", base + BATCH_PATH, raw=b"", headers=TA)
        check("空体 -> 200 请求非法",
              stx == 200 and json.loads(rawx) == invalid_expectation)
        stx, rawx = _http("POST", base + BATCH_PATH, raw=b"{", headers=TA)
        check("非法 JSON -> 200 请求非法",
              stx == 200 and json.loads(rawx) == invalid_expectation)
        stx, rawx = _http("POST", base + BATCH_PATH, raw=b"[]", headers=TA)
        check("非对象 -> 200 请求非法",
              stx == 200 and json.loads(rawx) == invalid_expectation)
        for name, payload in (
            ("缺 items", {}),
            ("多余外层字段", {"items": [], "x": 1}),
            ("items 为对象", {"items": {}}),
            ("items 为空数组", {"items": []}),
            ("items 为字符串", {"items": "x"}),
        ):
            stx, rawx = _http("POST", base + BATCH_PATH, payload, TA)
            rr = json.loads(rawx)
            check(f"{name} -> 200 请求非法",
                  stx == 200 and rr == invalid_expectation
                  and list(rr.keys()) == ["results", "reason"])
        stx, rawx = _http(
            "POST", base + BATCH_PATH,
            {"items": [{"manifest": manifest}] * 101}, TA)
        check("101 项 -> 200 请求非法",
              stx == 200 and json.loads(rawx) == invalid_expectation)

        stx, rawx = _http("POST", base + BATCH_PATH,
                          {"items": [{"manifest": manifest}]},
                          {"X-Tenant-ID": ""})
        check("显式空租户头(合法体) -> 400",
              stx == 400 and json.loads(rawx) == {"error": "请求非法"})
        stx, rawx = _http("POST", base + BATCH_PATH, raw=b"",
                          headers={"X-Tenant-ID": ""})
        check("显式空租户头(空体) -> 400",
              stx == 400 and json.loads(rawx) == {"error": "请求非法"})

        bad_structure = copy.deepcopy(manifest)
        del bad_structure["count"]
        bad_sig = copy.deepcopy(manifest)
        bad_sig["signature"] = "@@@"
        bad_crypto = copy.deepcopy(manifest)
        flipped = "A" if manifest["signature"][10] != "A" else "B"
        bad_crypto["signature"] = (
            manifest["signature"][:10] + flipped
            + manifest["signature"][11:]
        )
        items = [
            {"manifest": manifest},          # 0 valid
            {"manifest": bad_structure},     # 1 清单非法
            "not-an-object",                 # 2 清单非法
            {"manifest": []},                # 3 清单非法
            {"manifest": manifest, "x": 1},  # 4 项多余字段
            {},                              # 5 缺 manifest
            {"manifest": vc_manifest},       # 6 锚点不可用
            {"manifest": bad_sig},           # 7 签名格式错误
            {"manifest": bad_crypto},        # 8 签名校验失败
            {"manifest": manifest},          # 9 valid
        ]
        stx, rawx = batch(items, TA)
        rr = json.loads(rawx)
        check("混合批次 200 且顶层仅 results",
              stx == 200 and list(rr.keys()) == ["results"])
        results = rr["results"]
        check("结果与输入等长同序", len(results) == len(items))

        def invalid_at(index, reason):
            entry = results[index]
            return (list(entry.keys()) == ["valid", "reason"]
                    and entry == {"valid": False, "reason": reason})

        check("成功项仅 valid:true",
              results[0] == {"valid": True}
              and list(results[0].keys()) == ["valid"]
              and results[9] == {"valid": True})
        check("结构非法项 -> 清单非法",
              all(invalid_at(i, "清单非法") for i in (1, 2, 3, 4, 5)))
        check("无 generic 用途 -> 锚点不可用",
              invalid_at(6, "锚点不可用"))
        check("签名乱码 -> 签名格式错误", invalid_at(7, "签名格式错误"))
        check("签名被替换 -> 签名校验失败",
              invalid_at(8, "签名校验失败"))
        expected = copy.deepcopy(results)

        tampered = copy.deepcopy(manifest)
        tampered["events"][0]["action"] = "tampered.event"
        stx, rawx = batch([{"manifest": tampered}], TA)
        check("正文篡改 -> 签名校验失败",
              json.loads(rawx) == {
                  "results": [
                      {"valid": False, "reason": "签名校验失败"}]})

        bad_count = copy.deepcopy(manifest)
        bad_count["count"] += 1
        stx, rawx = batch([{"manifest": bad_count}], TA)
        check("count 不一致 -> 清单非法",
              json.loads(rawx)["results"][0]["reason"] == "清单非法")

        bad_range = copy.deepcopy(manifest)
        bad_range["after"] = bad_range["snapshot"] + 1
        stx, rawx = batch([{"manifest": bad_range}], TA)
        check("after>snapshot -> 清单非法",
              json.loads(rawx)["results"][0]["reason"] == "清单非法")
        bad_seq = copy.deepcopy(manifest)
        bad_seq["events"][0]["seq"] = bad_seq["after"]
        stx, rawx = batch([{"manifest": bad_seq}], TA)
        check("事件 seq 越界 -> 清单非法",
              json.loads(rawx)["results"][0]["reason"] == "清单非法")

        stx, rawx = batch([{"manifest": manifest}], TB)
        check("跨租户批次 -> 锚点不可用",
              json.loads(rawx) == {
                  "results": [
                      {"valid": False, "reason": "锚点不可用"}]})

        mixed = [{"manifest": manifest}, {"manifest": bad_sig}] * 50
        stx, rawx = batch(mixed, TA)
        results = json.loads(rawx)["results"]
        check("100 项不短路且交替正确",
              len(results) == 100
              and results[0] == {"valid": True}
              and results[-1]["reason"] == "签名格式错误"
              and all(results[i] == {"valid": True}
                      for i in range(0, 100, 2))
              and all(results[i]["reason"] == "签名格式错误"
                      for i in range(1, 100, 2)))

        n_before = len(
            _http("GET", f"{base}/v1/audit?limit=200", headers=TA)[1])
        batch(items, TA)
        _http("POST", base + BATCH_PATH,
              {"items": [{"manifest": bad_structure}]}, TA)
        n_after = len(
            _http("GET", f"{base}/v1/audit?limit=200", headers=TA)[1])
        check("批量验真不记审计", n_before == n_after)

        stx, rawx = _http("POST", base + VERIFY_PATH,
                          {"manifest": manifest}, TA)
        check("单条验真仍成功",
              stx == 200 and json.loads(rawx) == {"valid": True})
        stx, _ = _http("POST", base + VERIFY_PATH, {}, TA)
        check("单条验真空对象仍 400", stx == 400)

        # 批初锚点快照：批内并发吊销不得产生批内混合结论
        def race_round(round_idx):
            stx, raws = _http("POST", f"{base}/v1/dids", {
                "method": "web",
                "public_key": f"race-signer-{round_idx}"}, TA)
            assert stx == 201, raws
            race_did = json.loads(raws)["did"]
            race_pub = json.loads(raws)["public_key"]
            stx, _ = _http("POST", f"{base}/v1/trust/anchors", {
                "did": race_did, "public_key": race_pub,
                "key_version": 1, "uses": ["generic"]}, TA)
            assert stx == 201
            stx, raws = _http(
                "GET",
                f"{base}{MANIFEST_PATH}?snapshot={max_seq}"
                f"&signer_did={race_did}",
                headers=TA)
            assert stx == 200
            race_manifest = json.loads(raws)
            race_items = [{"manifest": race_manifest}] * 100

            def revoke_soon():
                time.sleep(0.002 * round_idx)
                _http("PUT",
                      f"{base}/v1/trust/anchors/{race_did}/1/status",
                      {"status": "revoked"}, TA)

            worker = threading.Thread(target=revoke_soon)
            worker.start()
            stx, raws = batch(race_items, TA)
            worker.join()
            assert stx == 200
            out = json.loads(raws)["results"]
            valids = {json.dumps(r, sort_keys=True) for r in out}
            check(f"批内并发吊销结论一致(轮 {round_idx})",
                  len(valids) == 1 and len(out) == 100)

        for round_idx in range(4):
            race_round(round_idx)

        # 重启后同一批结论、顺序与原因保持一致
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port), "服务重启超时"
        stx, rawx = batch(items, TA)
        check("重启后同批结论/顺序/原因不变",
              stx == 200 and json.loads(rawx) == {"results": expected})

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
    print("审计签名清单批量验真测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
