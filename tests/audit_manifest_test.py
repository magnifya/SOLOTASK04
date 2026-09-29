#!/usr/bin/env python3
"""GET/POST /v1/audit/manifest 审计签名清单端到端测试。

直接运行：python3 tests/audit_manifest_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import copy
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

MANIFEST_PATH = "/v1/audit/manifest"
VERIFY_PATH = "/v1/audit/manifest/verify"
MANIFEST_KEYS = [
    "snapshot", "after", "limit", "count", "events",
    "signer_did", "key_version", "signature",
]
EVENT_KEYS = [
    "seq", "timestamp", "tenant_id",
    "action", "resource_type", "resource_id",
]


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
            time.sleep(0.15)
    return False

def main():
    port = 9031
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
                        {"method": "web", "public_key": "audit-signer"}, TA)
        assert st == 201, raw
        signer_info = json.loads(raw)
        signer_did = signer_info["did"]
        signer_pub = signer_info["public_key"]

        def get_manifest(query="", headers=None):
            url = (f"{base}{MANIFEST_PATH}?{query}" if query
                   else base + MANIFEST_PATH)
            return _http("GET", url, headers=headers)

        def verify(manifest, headers=None):
            return _http("POST", base + VERIFY_PATH,
                         {"manifest": manifest}, headers=headers)

        # 1. 400 族
        def expect_400(name, query, headers=None):
            stx, rawx = get_manifest(query, headers=headers)
            try:
                rr = json.loads(rawx.decode() or "{}")
            except ValueError:
                rr = {}
            check(f"400: {name}",
                  stx == 400 and list(rr.keys()) == ["error"]
                  and isinstance(rr["error"], str) and rr["error"])

        expect_400("缺 snapshot", f"signer_did={signer_did}")
        expect_400("snapshot 空值", f"snapshot=&signer_did={signer_did}")
        expect_400("缺 signer_did", "snapshot=0")
        expect_400("signer_did 空值", "snapshot=0&signer_did=")
        expect_400("未知参数", f"snapshot=0&signer_did={signer_did}&x=1")
        expect_400("snapshot 重复",
                   f"snapshot=0&snapshot=1&signer_did={signer_did}")
        expect_400("signer_did 重复",
                   "snapshot=0&signer_did=a&signer_did=b")
        expect_400("after 重复",
                   f"snapshot=0&signer_did={signer_did}&after=1&after=2")
        expect_400("limit 重复",
                   f"snapshot=0&signer_did={signer_did}&limit=1&limit=2")
        expect_400("snapshot 非 ASCII 数字",
                   "snapshot=%C2%B2&signer_did=x")
        expect_400("limit Unicode 数字",
                   f"snapshot=0&signer_did={signer_did}&limit=%D9%A0")
        expect_400("snapshot 负数", f"snapshot=-1&signer_did={signer_did}")
        expect_400("snapshot 小数", f"snapshot=1.0&signer_did={signer_did}")
        expect_400("snapshot 符号", f"snapshot=%2B1&signer_did={signer_did}")
        expect_400("snapshot 布尔", f"snapshot=true&signer_did={signer_did}")
        expect_400("limit=0", f"snapshot=0&signer_did={signer_did}&limit=0")
        expect_400("limit=201", f"snapshot=0&signer_did={signer_did}&limit=201")
        expect_400("limit 空值",
                   f"snapshot=0&signer_did={signer_did}&limit=")
        expect_400("limit 小数",
                   f"snapshot=0&signer_did={signer_did}&limit=1.5")
        expect_400("after 大于 snapshot",
                   f"snapshot=1&signer_did={signer_did}&after=2")
        expect_400("snapshot 越界(超过最大序号)",
                   f"snapshot=999999999&signer_did={signer_did}")
        stx, _ = get_manifest("snapshot=0", headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", stx == 400)

        # 2. 404 / 409
        stx, _ = get_manifest("snapshot=0&signer_did=did:web:unknown", TA)
        check("未知签名 DID 404", stx == 404)
        stx, _ = get_manifest(f"snapshot=0&signer_did={signer_did}", TB)
        check("他租户签名 DID 404（与未知不可区分）", stx == 404)
        _http("POST", f"{base}/v1/dids",
              {"method": "web", "public_key": "dead-auditor"}, TA)
        stx, rawx = _http("POST", f"{base}/v1/dids",
                          {"method": "web", "public_key": "dead-auditor"}, TA)
        dead_did = json.loads(rawx)["did"]
        stx, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                       {"reason": "停用"}, TA)
        assert stx == 200
        stx, _ = get_manifest(f"snapshot=0&signer_did={dead_did}", TA)
        check("已停用签名 DID 409", stx == 409)

        # 3. 制造审计事件后取清单
        stx, raws = _http("POST", f"{base}/v1/dids",
                          {"method": "web", "public_key": "subject-1"}, TA)
        assert stx == 201
        sub_did = json.loads(raws)["did"]
        stx, raws = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": signer_did, "subject_did": sub_did,
            "claims": {"role": "admin"}}, TA)
        assert stx == 201
        stx, audit_raw = _http("GET", f"{base}/v1/audit?limit=200",
                                  headers=TA)
        audit_events = json.loads(audit_raw)["events"]
        max_seq = audit_events[-1]["seq"]

        stx, rawx = get_manifest(
            f"snapshot={max_seq}&signer_did={signer_did}", TA)
        check("清单 200", stx == 200)
        manifest = json.loads(rawx)
        check("清单键序固定", list(manifest.keys()) == MANIFEST_KEYS)
        check("snapshot/after/limit 缺省值",
              manifest["snapshot"] == max_seq
              and manifest["after"] == 0
              and manifest["limit"] == 50)
        check("count 与 events 一致",
              manifest["count"] == len(manifest["events"])
              and manifest["count"] == len(audit_events))
        check("事件内容与 /v1/audit 完全一致",
              manifest["events"] == audit_events)
        for ev in manifest["events"]:
            check("事件保留完整六字段且键序固定",
                  list(ev.keys()) == EVENT_KEYS)
        seqs = [ev["seq"] for ev in manifest["events"]]
        check("事件按 seq 升序且不超过 snapshot",
              seqs == sorted(seqs) and all(s <= max_seq for s in seqs))
        check("签名 DID/版本/签名长度",
              manifest["signer_did"] == signer_did
              and manifest["key_version"] == 1
              and isinstance(manifest["signature"], str)
              and len(manifest["signature"]) == 86)

        # 4. after/limit/snapshot 窗口语义 + 空页
        stx, rawx = get_manifest(
            f"snapshot={max_seq}&signer_did={signer_did}"
            f"&after={seqs[1]}&limit=1", TA)
        page = json.loads(rawx)
        check("after 严格下界且 limit 生效",
              page["count"] == 1
              and page["events"][0]["seq"] == seqs[2])
        stx, rawx = get_manifest(
            f"snapshot={seqs[1]}&signer_did={signer_did}", TA)
        page = json.loads(rawx)
        check("snapshot 为上界",
              page["count"] == 2
              and [e["seq"] for e in page["events"]] == seqs[:2])
        stx, rawx = get_manifest(
            f"snapshot={max_seq}&signer_did={signer_did}"
            f"&after={max_seq}", TA)
        page = json.loads(rawx)
        check("空页 count=0 events=[]",
              page["events"] == [] and page["count"] == 0)

        # 5. 注册含 generic 用途的信任锚点后验真成功
        stx, raws = _http("POST", f"{base}/v1/trust/anchors", {
            "did": signer_did, "public_key": signer_pub,
            "key_version": 1, "uses": ["generic"]}, TA)
        assert stx == 201, raws
        stx, rawx = verify(manifest, TA)
        check("锚点可用时验真成功",
              stx == 200 and json.loads(rawx) == {"valid": True})

        # 6. 验真外层 400
        stx, rawx = _http("POST", base + VERIFY_PATH, payload={},
                          headers=TA)
        rr = json.loads(rawx.decode() or "{}")
        check("验真空对象 -> 400", stx == 400 and bool(rr.get("error")))
        stx, rawx = _http("POST", base + VERIFY_PATH, payload=None,
                          raw=b"{", headers=TA)
        rr = json.loads(rawx.decode() or "{}")
        check("验真非法 JSON -> 400", stx == 400 and bool(rr.get("error")))
        for name, payload in (
            ("多余字段", {"manifest": manifest, "x": 1}),
            ("manifest 非对象(数组)", {"manifest": []}),
            ("manifest 为字符串", {"manifest": "x"}),
        ):
            stx, rawx = _http("POST", base + VERIFY_PATH, payload, TA)
            rr = json.loads(rawx.decode() or "{}")
            check(f"验真外层 400: {name}", stx == 400 and bool(rr.get("error")))
        stx, _ = _http("POST", base + VERIFY_PATH, {"manifest": manifest},
                       headers={"X-Tenant-ID": ""})
        check("验真显式空租户头 400", stx == 400)

        # 7. valid:false 原因顺序
        def expect_invalid(name, bad_manifest, reason):
            stx, rawx = verify(bad_manifest, TA)
            rr = json.loads(rawx)
            check(name,
                  stx == 200 and rr.get("valid") is False
                  and rr.get("reason") == reason
                  and set(rr) == {"valid", "reason"})

        bad = copy.deepcopy(manifest)
        del bad["count"]
        expect_invalid("缺字段 -> 清单非法", bad, "清单非法")
        bad = copy.deepcopy(manifest)
        bad["extra"] = 1
        expect_invalid("多字段 -> 清单非法", bad, "清单非法")
        bad = copy.deepcopy(manifest)
        bad["limit"] = 0
        expect_invalid("limit 越界 -> 清单非法", bad, "清单非法")
        bad = copy.deepcopy(manifest)
        bad["after"] = bad["snapshot"] + 1
        expect_invalid("after>snapshot -> 清单非法", bad, "清单非法")
        bad = copy.deepcopy(manifest)
        bad["events"][0]["seq"] = bad["after"]
        expect_invalid("事件 seq 越界 -> 清单非法", bad, "清单非法")
        bad = copy.deepcopy(manifest)
        bad["events"][0]["nope"] = 1
        expect_invalid("事件多余字段 -> 清单非法", bad, "清单非法")
        bad = copy.deepcopy(manifest)
        bad["count"] = bad["count"] + 1
        expect_invalid("count 不一致 -> 清单非法", bad, "清单非法")

        # 锚点不可用：他租户无锚点
        stx, rawx = verify(manifest, TB)
        rr = json.loads(rawx)
        check("跨租户验真 -> 锚点不可用",
              stx == 200 and rr == {"valid": False, "reason": "锚点不可用"})

        # 锚点用途不含 generic
        stx, raws = _http("POST", f"{base}/v1/dids",
                          {"method": "web", "public_key": "vc-only"}, TA)
        vc_did = json.loads(raws)["did"]
        vc_pub = json.loads(raws)["public_key"]
        stx, raws = _http("POST", f"{base}/v1/trust/anchors", {
            "did": vc_did, "public_key": vc_pub,
            "key_version": 1, "uses": ["vc"]}, TA)
        assert stx == 201, raws
        stx, rawx = get_manifest(
            f"snapshot={max_seq}&signer_did={vc_did}", TA)
        assert stx == 200
        vc_manifest = json.loads(rawx)
        expect_invalid("锚点无 generic 用途 -> 锚点不可用",
                       vc_manifest, "锚点不可用")

        # 签名格式错误（结构合法但签名不是 86 字符 base64url）
        bad = copy.deepcopy(manifest)
        bad["signature"] = "@@@"
        expect_invalid("签名乱码 -> 签名格式错误", bad, "签名格式错误")
        bad = copy.deepcopy(manifest)
        flipped = "A" if manifest["signature"][10] != "A" else "B"
        bad["signature"] = (
            manifest["signature"][:10] + flipped
            + manifest["signature"][11:]
        )
        # 86 字符规范编码但内容被篡改 -> 密码学验签失败
        expect_invalid("签名被替换 -> 签名校验失败", bad, "签名校验失败")
        bad = copy.deepcopy(manifest)
        bad["events"][0]["action"] = "tampered.event"
        expect_invalid("正文被篡改 -> 签名校验失败", bad, "签名校验失败")

        # 8. 验真只读：不写审计
        n_before = len(
            _http("GET", f"{base}/v1/audit?limit=200", headers=TA)[1])
        verify(manifest, TA)
        verify({"snapshot": 0}, TA)
        n_after = len(
            _http("GET", f"{base}/v1/audit?limit=200", headers=TA)[1])
        check("验真不记审计", n_before == n_after)

        # 9. 重启后结论不变
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
        stx, rawx = verify(manifest, TA)
        check("重启后验真结论不变",
              stx == 200 and json.loads(rawx) == {"valid": True})
        # 旧 snapshot 仍可生成（snapshot 不超过当前最大序号）
        stx, rawx = get_manifest(
            f"snapshot={max_seq}&signer_did={signer_did}", TA)
        check("重启后旧 snapshot 清单仍可生成且验真通过",
              stx == 200
              and verify(json.loads(rawx), TA)[0] == 200)

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
    print("审计签名清单测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
