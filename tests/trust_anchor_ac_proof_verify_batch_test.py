#!/usr/bin/env python3
"""POST /v1/trust/ac-proof/verify-batch 批量校验锚点变更证明端到端测试。

直接运行：python3 tests/trust_anchor_ac_proof_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求体须恰为 {"items":[证明...]}（1–100 项）；空体、非法 JSON、非对象、
  键集错误、items 非数组/空/超限均 HTTP 200 且按键序恰返
  {"results":[],"reason":"请求非法"}；
- 显式空 X-Tenant-ID 400，缺省 default；
- 合法批次顶层 HTTP 200 且仅含 results，等长同序、逐项不短路；成功项仅
  {"valid":true}，失败项键序 valid、reason，reason 限五类；
- 每项为 POST /v1/trust/ac-proof 的 proof 对象，逐项校验顺序与单项一致；
- 批初原子快照：同批不观察到混合状态（并发吊销/用途收紧）；
- 纯只读：不写状态、游标或审计；单项 ac-proof 行为不变。
"""

import copy
import hashlib
import json
import os
import re
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

from vcbackend import crypto  # noqa: E402

BATCH_PATH = "/v1/trust/ac-proof/verify-batch"
PROOF_PATH = "/v1/trust/ac-proof"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REASONS = {
    "证明非法", "锚点不可用", "签名格式错误", "签名校验失败", "包含证明校验失败",
}


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


def gen_keypair():
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def leaf_hash(event_obj):
    body = json.dumps(
        event_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(b"\x00" + body).hexdigest()


def parent_hash(left_hex, right_hex):
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def main():
    port = 9067
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

    def batch_post(payload=None, headers=None, raw_body=None):
        return _http("POST", base + BATCH_PATH, payload,
                     headers=headers, raw_body=raw_body)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def add_anchor(did, pub, version, headers, uses=None):
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors",
                            payload, headers)
            assert st in (200, 201), raw
            return json.loads(raw)

        # 签名锚点（含 generic 全用途）与自造事件证明。
        signer_did = "did:web:acb-signer"
        signer_priv, signer_pub = gen_keypair()
        add_anchor(signer_did, signer_pub, 1, TA)

        def make_event(did=signer_did, pub=signer_pub, cursor=10):
            return {
                "cursor": cursor,
                "action": "registered",
                "did": did,
                "key_version": 1,
                "public_key": pub,
                "status": "active",
                "uses": list(ALL_USES),
            }

        def sign_proof(event_obj, snapshot, root, path,
                       did=signer_did, version=1, priv=signer_priv):
            signed = {
                "event": event_obj,
                "snapshot": snapshot,
                "root": root,
                "path": path,
                "signer_did": did,
                "signer_key_version": version,
            }
            proof_obj = dict(signed)
            proof_obj["signature"] = crypto.sign(signed, priv)
            return proof_obj

        ev = make_event()
        good = sign_proof(ev, 10, leaf_hash(ev), [])

        # ---------------------------------------------------------- #
        # 1. 请求级非法：HTTP 200 + {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_bad_request(name, payload=None, raw_body=None,
                               headers=TA):
            st, raw = batch_post(payload, headers=headers, raw_body=raw_body)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            check(f"请求非法 200 同形: {name}",
                  st == 200 and isinstance(body, dict)
                  and list(body.keys()) == ["results", "reason"]
                  and body == {"results": [], "reason": "请求非法"})

        expect_bad_request("空体", raw_body=b"")
        expect_bad_request("无 Content-Length 体", raw_body=None)
        expect_bad_request("非法 JSON", raw_body=b"{")
        expect_bad_request("非 UTF-8", raw_body=b"\xff\xfe")
        expect_bad_request("非对象(数组)", raw_body=b"[1]")
        expect_bad_request("非对象(字符串)", raw_body=b'"x"')
        expect_bad_request("非对象(null)", raw_body=b"null")
        expect_bad_request("缺 items", payload={})
        expect_bad_request("多余键", payload={"items": [good], "x": 1})
        expect_bad_request("items 非数组(对象)", payload={"items": {}})
        expect_bad_request("items 非数组(字符串)", payload={"items": "x"})
        expect_bad_request("items 空数组", payload={"items": []})
        expect_bad_request("items 超限(101)",
                           payload={"items": [good] * 101})

        # 显式空租户头 400；缺省 default 正常
        st, _ = batch_post({"items": [good]}, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)
        st, raw = batch_post({"items": [good]})  # default 租户无此锚点
        body = json.loads(raw)
        check("缺省租户头按 default 隔离",
              st == 200 and list(body.keys()) == ["results"]
              and body["results"] == [
                  {"valid": False, "reason": "锚点不可用"}])

        # ---------------------------------------------------------- #
        # 2. 合法批次：等长同序、逐项不短路、五类原因各一
        # ---------------------------------------------------------- #
        malformed_item = {"not": "a proof"}
        no_anchor = sign_proof(ev, 10, leaf_hash(ev), [],
                               did="did:web:no-anchor")
        fmt_bad = sign_proof(ev, 10, leaf_hash(ev), [])
        fmt_bad["signature"] = "not-a-signature"
        other_priv, _ = gen_keypair()
        sig_bad = sign_proof(ev, 10, leaf_hash(ev), [], priv=other_priv)
        incl_bad = sign_proof(ev, 10, leaf_hash(ev),
                              [{"side": "right", "hash": "0" * 64}])

        items = [good, malformed_item, no_anchor, fmt_bad, sig_bad,
                 incl_bad, good]
        st, raw = batch_post({"items": items}, headers=TA)
        body = json.loads(raw)
        check("顶层 200 且仅含 results",
              st == 200 and list(body.keys()) == ["results"])
        expected = [
            {"valid": True},
            {"valid": False, "reason": "证明非法"},
            {"valid": False, "reason": "锚点不可用"},
            {"valid": False, "reason": "签名格式错误"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": False, "reason": "包含证明校验失败"},
            {"valid": True},
        ]
        check("results 等长同序逐项不短路", body["results"] == expected)
        check("失败项键序 valid,reason",
              all(list(r.keys()) == ["valid", "reason"]
                  for r in body["results"] if not r["valid"]))
        check("成功项恰为 {valid:true}",
              all(r == {"valid": True}
                  for r in body["results"] if r["valid"]))
        check("reason 限五类",
              all(r["reason"] in REASONS
                  for r in body["results"] if not r["valid"]))

        # 非对象项按“证明非法”处理且不短路
        st, raw = batch_post({"items": [good, 1, "x", None, [], good]},
                             headers=TA)
        body = json.loads(raw)
        check("非对象项 证明非法 且不短路",
              body["results"] == [
                  {"valid": True},
                  {"valid": False, "reason": "证明非法"},
                  {"valid": False, "reason": "证明非法"},
                  {"valid": False, "reason": "证明非法"},
                  {"valid": False, "reason": "证明非法"},
                  {"valid": True},
              ])

        # 边界：1 项与 100 项均合法
        st, raw = batch_post({"items": [good]}, headers=TA)
        check("单项批次合法", json.loads(raw)["results"] == [{"valid": True}])
        st, raw = batch_post({"items": [good] * 100}, headers=TA)
        body = json.loads(raw)
        check("100 项批次合法",
              st == 200 and body["results"] == [{"valid": True}] * 100)

        # 跨租户：A 的锚点在 B 不可用
        st, raw = batch_post({"items": [good]}, headers=TB)
        check("跨租户锚点不可用",
              json.loads(raw)["results"] == [
                  {"valid": False, "reason": "锚点不可用"}])

        # ---------------------------------------------------------- #
        # 3. 批初原子快照：吊销/用途收紧前后结论一致，同批不混合
        # ---------------------------------------------------------- #
        snap_did = "did:web:acb-snap"
        snap_priv, snap_pub = gen_keypair()
        add_anchor(snap_did, snap_pub, 1, TA)
        snap_proof = sign_proof(make_event(did=snap_did, pub=snap_pub),
                                10, leaf_hash(make_event(did=snap_did,
                                                         pub=snap_pub)), [],
                                did=snap_did, priv=snap_priv)
        st, raw = batch_post({"items": [snap_proof, snap_proof]}, headers=TA)
        check("吊销前同批一致 valid",
              json.loads(raw)["results"] == [{"valid": True}] * 2)

        # 并发吊销 + 100 项大批次：结果必须全 valid 或全 锚点不可用，
        # 不得混合（批初快照原子读取）。
        mixed_seen = []
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                st, raw = batch_post({"items": [snap_proof] * 100},
                                     headers=TA)
                rs = json.loads(raw)["results"]
                kinds = {tuple(sorted(r.items())) for r in rs}
                if len(kinds) != 1:
                    mixed_seen.append(rs)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.3)
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{snap_did}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        time.sleep(0.5)
        stop.set()
        for t in threads:
            t.join()
        check("并发吊销下同批不观察混合状态", not mixed_seen)

        st, raw = batch_post({"items": [snap_proof, snap_proof]}, headers=TA)
        check("吊销后同批一致 锚点不可用",
              json.loads(raw)["results"] == [
                  {"valid": False, "reason": "锚点不可用"}] * 2)

        # 用途收紧（去掉 generic）后同样一致不可用
        use_did = "did:web:acb-uses"
        use_priv, use_pub = gen_keypair()
        add_anchor(use_did, use_pub, 1, TA)
        use_ev = make_event(did=use_did, pub=use_pub)
        use_proof = sign_proof(use_ev, 10, leaf_hash(use_ev), [],
                               did=use_did, priv=use_priv)
        st, raw = batch_post({"items": [use_proof]}, headers=TA)
        check("收紧前 valid", json.loads(raw)["results"] == [{"valid": True}])
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{use_did}/1/uses",
                      {"from_uses": ALL_USES,
                       "uses": ["vc", "vp", "proof", "did",
                                "status", "deactivation"]}, TA)
        assert st == 200
        st, raw = batch_post({"items": [use_proof, use_proof]}, headers=TA)
        check("用途收紧后同批一致 锚点不可用",
              json.loads(raw)["results"] == [
                  {"valid": False, "reason": "锚点不可用"}] * 2)

        # ---------------------------------------------------------- #
        # 4. 纯只读：不记审计；单项 ac-proof 行为不变
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        n_before = len(json.loads(raw)["events"])
        batch_post({"items": [good, malformed_item, sig_bad]}, headers=TA)
        batch_post({"items": [good] * 100}, headers=TA)
        batch_post(raw_body=b"{")
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("批量验真不记审计",
              len(json.loads(raw)["events"]) == n_before)

        st, raw = _http("POST", base + PROOF_PATH, {"proof": good},
                        headers=TA)
        check("单项 ac-proof 行为不变",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 5. 重启稳定：结论不依赖变更事件/游标
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = batch_post({"items": [good, snap_proof]}, headers=TA)
        check("重启后结论稳定",
              json.loads(raw)["results"] == [
                  {"valid": True},
                  {"valid": False, "reason": "锚点不可用"}])

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
