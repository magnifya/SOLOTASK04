#!/usr/bin/env python3
"""POST /v1/trust/ac-proof/verify-batch 批量锚点变更证明验真端到端测试。

直接运行：python3 tests/trust_anchor_ac_proof_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求体须恰为 {"items":[证明...]}，数组限 1–100 项；空体、非法 JSON、
  非对象、键集错误、items 非数组/空/超限均 HTTP 200 且按键序恰返
  {"results":[],"reason":"请求非法"}；
- 显式空 X-Tenant-ID 仍 400，缺省 default；
- 合法批次顶层仅含 results，等长同序、逐项不短路；成功项仅
  {"valid":true}，失败项键序恰为 valid、reason，reason 恰为
  证明非法/锚点不可用/签名格式错误/签名校验失败/包含证明校验失败 之一；
- 批初快照语义：同批重复项结果一致，吊销/用途收紧前注册的锚点在批内
  表现一致；跨租户锚点不可用；
- 纯只读（不记审计），单项 POST /v1/trust/ac-proof 行为不变。
"""

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

BATCH_PATH = "/v1/trust/ac-proof/verify-batch"
SINGLE_PATH = "/v1/trust/ac-proof"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REASONS = {"证明非法", "锚点不可用", "签名格式错误", "签名校验失败",
           "包含证明校验失败"}


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


def gen_pub_pem():
    return gen_keypair()[1]


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
    port = 9103
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
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

        def make_did(label, headers=None):
            st, raw = _http("POST", f"{base}/v1/dids",
                            {"method": "web", "public_key": label}, headers)
            assert st in (200, 201), raw
            body = json.loads(raw)
            return body["did"], body["public_key"]

        def add_anchor(did, pub, version, headers=None, uses=None):
            payload = {"did": did, "public_key": pub, "key_version": version}
            if uses is not None:
                payload["uses"] = uses
            st, raw = _http("POST", f"{base}/v1/trust/anchors",
                            payload, headers)
            assert st in (200, 201), raw
            return json.loads(raw)

        # 租户 A：本地签名 DID + 含 generic 的活动锚点（事件 1、2）
        signer_did, signer_pub = make_did("batch-signer", TA)
        add_anchor(signer_did, signer_pub, 1, TA)
        add_anchor("did:web:batch-other", gen_pub_pem(), 1, TA)

        # 取服务自签的合法证明（cursor=1, snapshot=2）
        st, raw = _http(
            "GET",
            f"{base}{SINGLE_PATH}?cursor=1&snapshot=2"
            f"&signer_did={signer_did}",
            headers=TA,
        )
        assert st == 200, raw
        valid_proof = json.loads(raw)

        # 远端锚点（自造事件、自签证明），用于构造各类失败项
        remote_did = "did:web:batch-remote"
        r_priv, r_pub = gen_keypair()
        add_anchor(remote_did, r_pub, 1, TA)

        def remote_event(cursor=10, uses=None):
            return {
                "cursor": cursor,
                "action": "registered",
                "did": remote_did,
                "key_version": 1,
                "public_key": r_pub,
                "status": "active",
                "uses": list(ALL_USES if uses is None else uses),
            }

        def sign_proof(event_obj, snapshot, root, path, did=remote_did,
                       version=1, priv=r_priv):
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

        ev1 = remote_event()
        lh1 = leaf_hash(ev1)
        good_remote = sign_proof(ev1, 10, lh1, [])

        # ---------------------------------------------------------- #
        # 1. 请求级非法：200 且按键序恰返
        #    {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_request_invalid(name, payload=None, raw_body=None,
                                   headers=TA):
            st, raw = batch_post(payload, headers=headers, raw_body=raw_body)
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
            check(f"请求非法 200 恰返: {name}",
                  st == 200 and body is not None
                  and list(body.keys()) == ["results", "reason"]
                  and body == {"results": [], "reason": "请求非法"})

        expect_request_invalid("空体", raw_body=b"")
        expect_request_invalid("非法 JSON", raw_body=b"{")
        expect_request_invalid("非对象（数组）", raw_body=b"[1]")
        expect_request_invalid("非对象（字符串）", raw_body=b'"x"')
        expect_request_invalid("缺 items", payload={})
        expect_request_invalid("多余键",
                               payload={"items": [good_remote], "x": 1})
        expect_request_invalid("items 非数组（对象）",
                               payload={"items": {}})
        expect_request_invalid("items 非数组（字符串）",
                               payload={"items": "x"})
        expect_request_invalid("items 为 null", payload={"items": None})
        expect_request_invalid("items 空数组", payload={"items": []})
        expect_request_invalid("items 101 项",
                               payload={"items": [good_remote] * 101})

        # 显式空租户头仍 400
        st, _ = batch_post({"items": [good_remote]},
                           headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)
        st, _ = batch_post({"items": []}, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400（非法批次亦先判租户）", st == 400)

        # ---------------------------------------------------------- #
        # 2. 缺省 default 租户：不带头解析到 default
        # ---------------------------------------------------------- #
        d_signer, d_pub = make_did("batch-default-signer")
        add_anchor(d_signer, d_pub, 1)
        st, raw = _http(
            "GET",
            f"{base}{SINGLE_PATH}?cursor=1&snapshot=1"
            f"&signer_did={d_signer}",
        )
        assert st == 200, raw
        default_proof = json.loads(raw)
        st, raw = batch_post({"items": [default_proof]})
        body = json.loads(raw)
        check("缺省 default 租户合法批次 valid",
              st == 200 and body == {"results": [{"valid": True}]})

        # ---------------------------------------------------------- #
        # 3. 合法批次：顶层仅 results、等长同序、逐项不短路、键序
        # ---------------------------------------------------------- #
        malformed_item = copy.deepcopy(good_remote)
        malformed_item.pop("root")  # 缺键 -> 证明非法
        non_object_item = ["not", "a", "proof"]
        unknown_anchor = sign_proof(ev1, 10, lh1, [],
                                    did="did:web:no-such-anchor")
        fmt_bad = sign_proof(ev1, 10, lh1, [])
        fmt_bad["signature"] = "not-a-signature"
        other_priv, _ = gen_keypair()
        sig_bad = sign_proof(ev1, 10, lh1, [], priv=other_priv)
        incl_bad = sign_proof(ev1, 10, lh1,
                              [{"side": "right", "hash": "0" * 64}])

        items = [
            valid_proof,        # valid
            malformed_item,     # 证明非法
            non_object_item,    # 证明非法
            unknown_anchor,     # 锚点不可用
            fmt_bad,            # 签名格式错误
            sig_bad,            # 签名校验失败
            incl_bad,           # 包含证明校验失败
            good_remote,        # valid（不短路，末项仍处理）
        ]
        st, raw = batch_post({"items": items}, headers=TA)
        body = json.loads(raw)
        check("合法批次顶层仅含 results",
              st == 200 and list(body.keys()) == ["results"])
        results = body["results"]
        check("results 等长同序", len(results) == len(items))
        check("成功项恰为 {valid:true}",
              results[0] == {"valid": True}
              and list(results[0].keys()) == ["valid"]
              and results[7] == {"valid": True})
        expected_reasons = [
            None, "证明非法", "证明非法", "锚点不可用",
            "签名格式错误", "签名校验失败", "包含证明校验失败", None,
        ]
        ok = True
        for idx, (result, expect) in enumerate(zip(results,
                                                   expected_reasons)):
            if expect is None:
                if result != {"valid": True}:
                    ok = False
            else:
                if (list(result.keys()) != ["valid", "reason"]
                        or result["valid"] is not False
                        or result["reason"] != expect):
                    ok = False
        check("失败项键序 valid,reason 且原因逐项符合", ok)
        check("失败原因均在五种枚举内",
              all(r.get("reason") in REASONS
                  for r in results if r != {"valid": True}))

        # 服务自签证明（valid_proof）与远端自造证明（good_remote）同批可验：
        # 不依赖本地事件
        check("远端自造事件证明在批中 valid", results[7] == {"valid": True})

        # ---------------------------------------------------------- #
        # 4. 批初快照语义：同批重复项一致；吊销/收紧后整批一致
        # ---------------------------------------------------------- #
        st, raw = batch_post({"items": [good_remote] * 5}, headers=TA)
        results = json.loads(raw)["results"]
        check("同批重复项结果一致（valid）",
              results == [{"valid": True}] * 5)

        # 用途收紧：去掉 generic 后整批均为锚点不可用
        tight_did = "did:web:batch-tightened"
        t_priv, t_pub = gen_keypair()
        add_anchor(tight_did, t_pub, 1, TA)
        tight_proof = sign_proof(remote_event(), 10, lh1, [],
                                 did=tight_did, priv=t_priv)
        st, raw = batch_post({"items": [tight_proof]}, headers=TA)
        check("收紧前证明 valid",
              json.loads(raw)["results"] == [{"valid": True}])
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{tight_did}/1/uses",
                      {"from_uses": ALL_USES, "uses": ["vc"]}, TA)
        assert st == 200
        st, raw = batch_post({"items": [tight_proof, tight_proof]},
                             headers=TA)
        results = json.loads(raw)["results"]
        check("用途收紧后整批一致锚点不可用",
              results == [{"valid": False, "reason": "锚点不可用"}] * 2)

        # 吊销后整批一致锚点不可用
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{remote_did}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        st, raw = batch_post({"items": [good_remote, good_remote]},
                             headers=TA)
        results = json.loads(raw)["results"]
        check("吊销后整批一致锚点不可用",
              results == [{"valid": False, "reason": "锚点不可用"}] * 2)

        # 跨租户：锚点在 A，租户 B 验 -> 锚点不可用
        st, raw = batch_post({"items": [valid_proof]}, headers=TB)
        check("跨租户锚点不可用",
              json.loads(raw)["results"]
              == [{"valid": False, "reason": "锚点不可用"}])

        # ---------------------------------------------------------- #
        # 5. 上限 100 项可验
        # ---------------------------------------------------------- #
        st, raw = batch_post({"items": [valid_proof] * 100}, headers=TA)
        body = json.loads(raw)
        check("100 项批次全部 valid",
              st == 200 and list(body.keys()) == ["results"]
              and body["results"] == [{"valid": True}] * 100)

        # ---------------------------------------------------------- #
        # 6. 只读：不记审计；单项 POST 行为不变
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        n_before = len(json.loads(raw)["events"])
        batch_post({"items": [valid_proof, malformed_item]}, headers=TA)
        batch_post({"items": []}, headers=TA)
        batch_post(raw_body=b"{", headers=TA)
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("批量验真不记审计",
              len(json.loads(raw)["events"]) == n_before)

        # 单项行为不变：合法证明仍 valid:true，非法请求体仍 400
        st, raw = _http("POST", base + SINGLE_PATH,
                        {"proof": valid_proof}, headers=TA)
        check("单项 POST 仍 valid:true",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = _http("POST", base + SINGLE_PATH, {"proof": {}},
                        headers=TA)
        body = json.loads(raw)
        check("单项 POST 失败原因协议不变",
              st == 200 and body == {"valid": False, "reason": "证明非法"})
        st, raw = _http("POST", base + SINGLE_PATH, {}, headers=TA)
        check("单项 POST 缺 proof 仍 400", st == 400)

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
