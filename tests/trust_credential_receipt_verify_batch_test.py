#!/usr/bin/env python3
"""批量只读校验 POST /v1/trust/credentials/receipt/verify-batch 端到端测试。

直接运行：python3 tests/trust_credential_receipt_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

BATCH_PATH = "/v1/trust/credentials/receipt/verify-batch"
VERIFY_PATH = "/v1/trust/credentials/receipt/verify"
CONSUME_PATH = "/v1/trust/credentials/receipt/consume"
RECEIPT_PATH = "/v1/trust/credentials/verify-receipt"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw_body=None):
    data = raw_body
    if data is None and payload is not None:
        data = json.dumps(payload).encode("utf-8")
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
    port = 9237
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

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

    def post(path, payload=None, headers=None, raw_body=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw_body=raw_body)

    def put(path, payload=None, headers=None):
        return _http("PUT", base + path, payload=payload, headers=headers)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        T1 = {"X-Tenant-ID": "crvb-a"}
        T2 = {"X-Tenant-ID": "crvb-b"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:crvb-issuer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": issuer_did, "public_key": issuer_pub,
                      "key_version": 1}, T1)
        assert st in (200, 201), st

        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-receipt-verify-batch"},
                       T1)
        assert st == 201, (st, raw)
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": 1,
                      "uses": ["generic", "vc"]}, T1)
        assert st in (200, 201), st

        body = {
            "credential_id": "vc_crvb_0001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)

        def make_item(nonce, b=body, s=sig, vdid=verifier_did):
            st_, raw_ = post(RECEIPT_PATH,
                             {"body": b, "signature": s,
                              "verifier_did": vdid, "nonce": nonce}, T1)
            assert st_ == 200, raw_
            r_ = json.loads(raw_)
            assert r_.get("valid"), r_
            return {
                "receipt": r_["receipt"],
                "receipt_signature": r_["receipt_signature"],
                "body": b,
                "signature": s,
                "nonce": nonce,
            }

        def batch(payload=None, headers=T1, raw_body=None):
            st, raw = post(BATCH_PATH, payload=payload, headers=headers,
                           raw_body=raw_body)
            return st, json.loads(raw.decode() or "null")

        good = make_item("nonce-批-001")

        # 1. 成功：单项批次仅 {"results":[{"valid":true}]}
        st, r = batch({"items": [good]})
        check("单项成功 200 且仅 valid:true",
              st == 200 and list(r.keys()) == ["results"]
              and r == {"results": [{"valid": True}]})

        # 2. 请求级非法：200 按键序恰返 {"results":[],"reason":"请求非法"}
        def expect_bad_request(name, payload=None, raw_body=None,
                               headers=T1):
            st, r = batch(payload, headers=headers, raw_body=raw_body)
            check(name, st == 200
                  and list(r.keys()) == ["results", "reason"]
                  and r == {"results": [], "reason": "请求非法"})

        expect_bad_request("空体", raw_body=b"")
        expect_bad_request("非法 JSON", raw_body=b"{not json")
        expect_bad_request("非 UTF-8", raw_body=b"\xff\xfe")
        expect_bad_request("非对象（数组）", raw_body=b"[1,2]")
        expect_bad_request("非对象（字符串）", raw_body=b'"x"')
        expect_bad_request("缺 items", {})
        expect_bad_request("多余字段", {"items": [good], "x": 1})
        expect_bad_request("items 非数组", {"items": "x"})
        expect_bad_request("items 空数组", {"items": []})
        expect_bad_request("items 超限 101",
                           {"items": [make_item(f"n-{i:03d}")
                                      for i in range(101)]})
        st, r = batch({"items": [good] * 100})
        check("items 100 项合法",
              st == 200 and len(r.get("results", [])) == 100)
        st, _ = batch({"items": [good]}, headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400", st == 400)

        # 3. 项级非法：请求项非法，不短路
        bad_items = [
            "not-object",
            [1, 2],
            {k: v for k, v in good.items() if k != "nonce"},
            dict(good, x=1),
            dict(good, receipt="x"),
            dict(good, body=[]),
            dict(good, receipt_signature=""),
            dict(good, signature=1),
            dict(good, nonce=""),
            dict(good, nonce="中" * 257),
        ]
        st, r = batch({"items": bad_items + [good]})
        check("混合非法项不短路且末项成功",
              st == 200 and len(r["results"]) == 11
              and all(item == {"valid": False, "reason": "请求项非法"}
                      for item in r["results"][:10])
              and r["results"][10] == {"valid": True})

        # 4. 逐项验真失败原因与优先级（批量 reason 集合不含“绑定错误”）
        other_priv, _ = _keypair()
        fail_items = [
            dict(good, receipt={k: v for k, v in good["receipt"].items()
                                if k != "nonce"}),                # 回执非法
            dict(good, nonce="其他nonce"),                        # nonce错误
            dict(good, body=dict(body, credential_id="vc_x")),    # 绑定不通过
            dict(good, body=dict(body, claims={"role": "user"})),  # 摘要错误
            dict(good, receipt_signature="!!!bad!!!"),            # 签名格式错误
            dict(good, receipt_signature=crypto.sign(
                good["receipt"], other_priv)),                    # 签名校验失败
        ]
        st, r = batch({"items": fail_items})
        want = ["回执非法", "nonce错误", "回执非法", "摘要错误",
                "签名格式错误", "签名校验失败"]
        check("六类失败 reason 等长同序（绑定不通过归回执非法）",
              st == 200 and [i.get("reason") for i in r["results"]] == want
              and all(list(i.keys()) == ["valid", "reason"]
                      for i in r["results"])
              and all(i["valid"] is False for i in r["results"]))

        # 锚点不可用：未知验证者 / 他租户 / 缺省租户
        unknown = dict(good)
        unknown["receipt"] = dict(good["receipt"],
                                  verifier_did="did:web:no-such.example")
        st, r = batch({"items": [unknown]})
        check("未知验证者 -> 锚点不可用",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "锚点不可用"})
        st, r = batch({"items": [good]}, headers=T2)
        check("他租户 -> 锚点不可用",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "锚点不可用"})
        st, r = batch({"items": [good]}, headers=None)
        check("缺省租户隔离 -> 锚点不可用",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "锚点不可用"})

        # 单条 receipt/verify 行为不变：绑定不通过仍为“绑定错误”
        st, raw = post(VERIFY_PATH,
                       dict(good, body=dict(body, credential_id="vc_x")),
                       T1)
        check("单条 verify 绑定不通过仍为 绑定错误",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "绑定错误"})

        # 5. 同 (验证者, nonce) 重复只验真不判重；不影响后续消费防重放
        st, r = batch({"items": [good, good, good]})
        check("批内同键重复三项均 valid:true",
              st == 200 and r["results"] == [{"valid": True}] * 3)
        st, raw = post(CONSUME_PATH, good, T1)
        first_consume = json.loads(raw)
        check("批量验真后单条消费仍首次成功",
              st == 200 and first_consume.get("valid") is True
              and list(first_consume.keys())
              == ["valid", "receipt_id", "consumed_at"])
        st, r = batch({"items": [good]})
        check("消费后批量验真仍只读 valid:true（不判重）",
              st == 200 and r == {"results": [{"valid": True}]})
        st, raw = post(CONSUME_PATH, good, T1)
        check("单条消费重放仍判重 回执已消费",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "回执已消费"})

        # 6. 只读：不写消费审计、不推进消费历史
        st, raw = get("/v1/audit?limit=200", headers=T1)
        consumed_audits = [
            e for e in json.loads(raw)["events"]
            if e["action"] == "trust.credential.receipt.consumed"
        ]
        check("消费审计恰为单条消费的一条（批量验真零审计）",
              len(consumed_audits) == 1)
        st, raw = get(
            "/v1/trust/credentials/receipt/consumptions?limit=200", T1)
        history = json.loads(raw)["events"]
        check("消费历史仅一条", st == 200 and len(history) == 1)
        fresh = make_item("nonce-批-002")
        for _ in range(3):
            st, r = batch({"items": [fresh, unknown, good]})
            assert st == 200 and len(r["results"]) == 3
        st, raw = get(
            "/v1/trust/credentials/receipt/consumptions?limit=200", T1)
        check("多次批量验真后消费历史不变",
              len(json.loads(raw)["events"]) == 1)

        # 7. 批初锚点快照：吊销后同批各项一致判定
        vkey = good["receipt"]["verifier_key_version"]
        st, _ = put(
            f"{ANCHORS_PATH}/{urllib.parse.quote(verifier_did)}"
            f"/{vkey}/status",
            {"status": "revoked"}, T1)
        assert st == 200, st
        st, r = batch({"items": [good, fresh, good]})
        check("吊销后同批一致锚点不可用",
              st == 200 and r == {"results": [
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"}]})

        # 用途收紧：新锚点登记含 vc，再收紧为不含 vc。
        tighten_did = "did:web:crvb-tighten.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": tighten_did, "public_key": verifier_pub,
                      "key_version": 1, "uses": ["generic", "vc"]}, T1)
        assert st in (200, 201), st
        st, _ = put(f"{ANCHORS_PATH}/{tighten_did}/1/uses",
                    {"from_uses": ["generic", "vc"],
                     "uses": ["generic"]}, T1)
        assert st == 200, st
        # tighten_did 非托管 DID：复用同公钥的合法回执并改验证者字段，
        # 用途检查先于验签，故结论为锚点不可用。
        tighten_item = dict(
            fresh,
            receipt=dict(fresh["receipt"], verifier_did=tighten_did,
                         verifier_key_version=1))
        st, r = batch({"items": [tighten_item]})
        check("用途收紧（不含 vc）-> 锚点不可用",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "锚点不可用"}])

        # 8. 重启后结论一致（纯只读，锚点仍吊销）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, r = batch({"items": [good, fresh]})
        check("重启后结果一致",
              st == 200 and r == {"results": [
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"}]})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.remove(store_path)

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
