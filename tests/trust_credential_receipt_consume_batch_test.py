#!/usr/bin/env python3
"""批量防重放消费 POST /v1/trust/credentials/receipt/consume-batch 的端到端测试。

直接运行：python3 tests/trust_credential_receipt_consume_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
import shutil
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


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


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def main():
    port = 8984
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/receipt/consume-batch"
    single_path = "/v1/trust/credentials/receipt/consume"
    receipt_path = "/v1/trust/credentials/verify-receipt"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume_batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def consume_single(payload, headers=None):
        return _http("POST", f"{base}{single_path}", payload,
                     headers=headers)

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    def consumed_audits(headers):
        return [e for e in audit_events(headers)
                if e["action"] == "trust.credential.receipt.consumed"]

    try:
        T1 = {"X-Tenant-ID": "rcb-a"}
        T2 = {"X-Tenant-ID": "rcb-b"}

        # ---- 准备：外部签发者锚点 + 本地验证者 DID + 验证者锚点 ----
        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:issuer.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": issuer_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册外部签发者锚点 -> 201", st == 201)

        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-handle-b"},
            headers=T1,
        )
        check("注册本地验证者 DID -> 201", st == 201)
        verifier_did = r["did"]
        verifier_pub = r["public_key"]

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": verifier_did, "public_key": verifier_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册验证者锚点 -> 201", st == 201)

        body = {
            "credential_id": "vc_rcb_0001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)

        def make_item(nonce, b=body, s=sig, vdid=verifier_did):
            st_, r_ = _http(
                "POST", f"{base}{receipt_path}",
                {"body": b, "signature": s,
                 "verifier_did": vdid, "nonce": nonce},
                headers=T1,
            )
            assert st_ == 200 and r_.get("valid"), r_
            return {
                "receipt": r_["receipt"],
                "receipt_signature": r_["receipt_signature"],
                "body": b,
                "signature": s,
                "nonce": nonce,
            }

        good1 = make_item("nonce-批-001")
        want_receipt_id1 = hashlib.sha256(
            crypto.canonicalize(good1["receipt"])
        ).hexdigest()

        # 1. 请求级非法 -> 200 按键序恰返 {"results":[],"reason":"请求..."}
        def expect_request_invalid(name, payload=None, raw=None, headers=T1):
            st, r = consume_batch(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r["results"] == []
                  and isinstance(r["reason"], str)
                  and r["reason"].startswith("请求"))

        expect_request_invalid("空请求体 -> 200 请求...", raw=b"")
        expect_request_invalid("非法 JSON -> 200 请求...", raw=b"not-json")
        expect_request_invalid("非 UTF-8 -> 200 请求...", raw=b"\xff\xfe")
        expect_request_invalid("非对象（数组） -> 200 请求...", raw=b"[1,2]")
        expect_request_invalid("缺 items -> 200 请求...", payload={})
        expect_request_invalid("多余字段 -> 200 请求...",
                               payload={"items": [good1], "x": 1})
        expect_request_invalid("items 非数组 -> 200 请求...",
                               payload={"items": "x"})
        expect_request_invalid("items 空数组 -> 200 请求...",
                               payload={"items": []})
        expect_request_invalid(
            "items 超限（101）-> 200 请求...",
            payload={"items": [make_item(f"nonce-超-{i:03d}")
                               for i in range(101)]},
        )
        st, r = consume_batch({"items": [good1]},
                              headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"})

        # 2. 项结构非法 -> {"valid":false,"reason":"请求项非法"}，不短路
        st, r = consume_batch({"items": [
            "not-object",
            [1, 2],
            {k: v for k, v in good1.items() if k != "nonce"},
            dict(good1, x=1),
            dict(good1, receipt="x"),
            dict(good1, body=[]),
            dict(good1, receipt_signature=""),
            dict(good1, signature=1),
            dict(good1, nonce=""),
            dict(good1, nonce="中" * 257),
            good1,
        ]}, headers=T1)
        check("混合批次 -> 200 且 results 等长同序",
              st == 200 and len(r.get("results", [])) == 11)
        results = r["results"]
        check("十种非法项均为 请求项非法",
              all(item == {"valid": False, "reason": "请求项非法"}
                  for item in results[:10]))
        check("末项合法首次消费成功",
              results[10].get("valid") is True
              and list(results[10].keys())
              == ["valid", "receipt_id", "consumed_at"])
        check("成功项 receipt_id 为 receipt 规范化 JSON 的 SHA-256",
              results[10].get("receipt_id") == want_receipt_id1)
        check("成功项 consumed_at 为 UTC 秒精度 Z",
              isinstance(results[10].get("consumed_at"), str)
              and UTC_Z_RE.fullmatch(results[10]["consumed_at"]) is not None)

        # 3. 七阶段验真失败沿用单条 reason，逐项不短路
        other_priv, _ = gen_keypair()
        seven_items = [
            dict(good1, receipt={k: v for k, v in good1["receipt"].items()
                                 if k != "nonce"}),          # 回执非法
            dict(good1, nonce="其他nonce"),                  # nonce错误
            dict(good1, body=dict(body, credential_id="vc_other")),  # 绑定
            dict(good1, body=dict(body, claims={"role": "user"})),  # 摘要
            dict(good1, receipt_signature="!!!bad!!!"),      # 签名格式错误
            dict(good1, receipt_signature=crypto.sign(
                good1["receipt"], other_priv)),              # 签名校验失败
            good1,                                           # 历史重放
        ]
        st, r = consume_batch({"items": seven_items}, headers=T1)
        check("七阶段批次 -> 200 等长", st == 200 and len(r["results"]) == 7)
        want_reasons = ["回执非法", "nonce错误", "绑定错误", "摘要错误",
                        "签名格式错误", "签名校验失败", "回执已消费"]
        check("七阶段 reason 与优先级沿用单条",
              [item.get("reason") for item in r["results"]] == want_reasons
              and all(item.get("valid") is False for item in r["results"]))
        check("验真失败与重放不记消费审计",
              len(consumed_audits(T1)) == 1)

        # 4. 批内同键判重：首项成功、后项已消费；不同 nonce 各自成功
        dup = make_item("nonce-批-002")
        dup_other_receipt = make_item("nonce-批-002",
                                      b=dict(body,
                                             credential_id="vc_rcb_0002"),
                                      s=crypto.sign(
                                          dict(body,
                                               credential_id="vc_rcb_0002"),
                                          issuer_priv))
        fresh = make_item("nonce-批-003")
        st, r = consume_batch({"items": [dup, dup_other_receipt, fresh]},
                              headers=T1)
        check("批内同键首项成功、后项已消费、异键成功",
              st == 200
              and r["results"][0].get("valid") is True
              and r["results"][1] == {"valid": False, "reason": "回执已消费"}
              and r["results"][2].get("valid") is True)
        check("批内两项新消费记两条审计",
              len(consumed_audits(T1)) == 3)

        # 5. 与单条 consume 互判重
        st, r = consume_batch({"items": [dup]}, headers=T1)
        check("历史重放（批内消费后整批重放）-> 回执已消费",
              st == 200
              and r["results"] == [{"valid": False, "reason": "回执已消费"}])
        single_item = make_item("nonce-批-004")
        st, r = consume_single(single_item, headers=T1)
        check("单条先消费 -> 200 valid:true", st == 200 and r.get("valid"))
        st, r = consume_batch({"items": [single_item]}, headers=T1)
        check("单条消费后批量同键 -> 回执已消费",
              st == 200
              and r["results"] == [{"valid": False, "reason": "回执已消费"}])
        batch_first = make_item("nonce-批-005")
        st, r = consume_batch({"items": [batch_first]}, headers=T1)
        check("批量先消费 -> 成功", st == 200 and r["results"][0].get("valid"))
        st, r = consume_single(batch_first, headers=T1)
        check("批量消费后单条同键 -> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})

        # 6. 租户隔离：自备验证者密钥，同键在两租户各自首次成功
        my_priv, my_pub = gen_keypair()
        my_verifier = "did:web:verifier-batch.example"
        for headers in (T1, T2):
            st, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": my_verifier, "public_key": my_pub,
                 "key_version": 1},
                headers=headers,
            )
            check(f"注册自备验证者锚点（{headers['X-Tenant-ID']}）-> 201",
                  st == 201)

        def make_self_receipt(n):
            rcpt = {
                "credential_id": body["credential_id"],
                "issuer_did": body["issuer_did"],
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": body, "signature": sig})
                ).hexdigest(),
                "verifier_did": my_verifier,
                "verifier_key_version": 1,
                "nonce": n,
            }
            return {"receipt": rcpt,
                    "receipt_signature": crypto.sign(rcpt, my_priv),
                    "body": body, "signature": sig, "nonce": n}

        iso_item = make_self_receipt("nonce-批隔离-001")
        st, r = consume_batch({"items": [iso_item]}, headers=T1)
        check("租户 A 同键首次消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = consume_batch({"items": [iso_item]}, headers=T2)
        check("租户 B 同键互不影响首次消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = consume_batch({"items": [iso_item]}, headers=T2)
        check("租户 B 重放 -> 回执已消费",
              st == 200
              and r["results"] == [{"valid": False, "reason": "回执已消费"}])
        check("缺省租户头按 default 隔离 -> 锚点不可用",
              consume_batch({"items": [iso_item]})[1]["results"][0]
              == {"valid": False, "reason": "锚点不可用"})

        # 7. 并发：批量与单条同键仅一次成功
        conc_item = make_self_receipt("nonce-批并发-001")
        outcomes = []

        def worker_batch():
            outcomes.append(consume_batch({"items": [conc_item]},
                                          headers=T1))

        def worker_single():
            outcomes.append(consume_single(conc_item, headers=T1))

        threads = [threading.Thread(target=worker_batch) for _ in range(4)]
        threads += [threading.Thread(target=worker_single)
                    for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = 0
        n_replay = 0
        for st, r in outcomes:
            if "results" in r:
                item = r["results"][0]
            else:
                item = r
            if st == 200 and item.get("valid") is True:
                n_ok += 1
            elif item == {"valid": False, "reason": "回执已消费"}:
                n_replay += 1
        check("并发同键（批量+单条）仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)

        # 8. 落盘失败：500 仅 {"error":"存储失败"}，全回滚可重试
        fail_item = make_self_receipt("nonce-批落盘-001")
        fail_item2 = make_self_receipt("nonce-批落盘-002")
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume_batch({"items": [fail_item, fail_item2]},
                                  headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume_batch({"items": [fail_item, fail_item2]},
                              headers=T1)
        check("落盘失败回滚后同批两键均可重试成功",
              st == 200
              and all(item.get("valid") is True for item in r["results"]))
        check("重试成功后补记两条审计",
              len(consumed_audits(T1)) == audits_before + 2)

        # 9. 重启仍判重
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume_batch({"items": [good1, dup, iso_item, fail_item]},
                              headers=T1)
        check("重启后历史键整批判重 -> 全部回执已消费",
              st == 200
              and r["results"]
              == [{"valid": False, "reason": "回执已消费"}] * 4)
        st, r = consume_batch({"items": [iso_item]}, headers=T2)
        check("重启后他租户同键重放 -> 回执已消费",
              st == 200
              and r["results"] == [{"valid": False, "reason": "回执已消费"}])

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        for p in (store,):
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.unlink(p)

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
