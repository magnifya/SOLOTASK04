#!/usr/bin/env python3
"""防重放消费 POST /v1/trust/credentials/receipt/consume 的端到端测试。

直接运行：python3 tests/trust_credential_receipt_consume_test.py
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
    port = 8983
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/receipt/consume"
    receipt_path = "/v1/trust/credentials/verify-receipt"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def audit_events(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    def consumed_audits(headers):
        return [e for e in audit_events(headers)
                if e["action"] == "trust.credential.receipt.consumed"]

    try:
        T1 = {"X-Tenant-ID": "rc-a"}
        T2 = {"X-Tenant-ID": "rc-b"}

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
            {"method": "example", "public_key": "verifier-handle-a"},
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
            "credential_id": "vc_rc_0001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)
        nonce = "nonce-消费-001"

        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": nonce},
            headers=T1,
        )
        check("verify-receipt 出回执 -> 200", st == 200 and r.get("valid"))
        receipt = r["receipt"]
        receipt_signature = r["receipt_signature"]
        want_receipt_id = hashlib.sha256(
            crypto.canonicalize(receipt)
        ).hexdigest()

        good_payload = {
            "receipt": receipt,
            "receipt_signature": receipt_signature,
            "body": body,
            "signature": sig,
            "nonce": nonce,
        }

        # 1. 外层非法 -> 400 仅 {error: 非空中文}
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r = consume(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 400 and set(r.keys()) == {"error"}
                  and isinstance(r["error"], str) and r["error"])

        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("非对象（数组） -> 400", raw=b"[1,2]")
        for field in ("receipt", "receipt_signature", "body",
                      "signature", "nonce"):
            expect_400(f"缺 {field} -> 400",
                       {k: v for k, v in good_payload.items() if k != field})
        expect_400("多余字段 -> 400", dict(good_payload, x=1))
        expect_400("receipt 非对象 -> 400",
                   dict(good_payload, receipt="x"))
        expect_400("body 非对象 -> 400", dict(good_payload, body=[]))
        expect_400("receipt_signature 空串 -> 400",
                   dict(good_payload, receipt_signature=""))
        expect_400("signature 非字符串 -> 400",
                   dict(good_payload, signature=1))
        expect_400("nonce 空串 -> 400", dict(good_payload, nonce=""))
        expect_400("nonce 257 码点 -> 400",
                   dict(good_payload, nonce="中" * 257))
        expect_400("显式空租户头 -> 400", good_payload,
                   headers={"X-Tenant-ID": ""})

        # 2. 七阶段验真失败沿用原 200/reason，且不写状态（不消费）
        def expect_invalid(name, payload, reason, headers=T1):
            st, r = consume(payload, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        expect_invalid("回执缺字段 -> 回执非法",
                       dict(good_payload,
                            receipt={k: v for k, v in receipt.items()
                                     if k != "nonce"}),
                       "回执非法")
        expect_invalid("两处 nonce 不等 -> nonce错误",
                       dict(good_payload, nonce="其他nonce"),
                       "nonce错误")
        expect_invalid("body credential_id 不符 -> 绑定错误",
                       dict(good_payload,
                            body=dict(body, credential_id="vc_other")),
                       "绑定错误")
        expect_invalid("claims 改动 -> 摘要错误",
                       dict(good_payload,
                            body=dict(body, claims={"role": "user"})),
                       "摘要错误")
        expect_invalid("他租户无验证者锚点 -> 锚点不可用",
                       good_payload, "锚点不可用", headers=T2)
        expect_invalid("receipt_signature 格式非法 -> 签名格式错误",
                       dict(good_payload, receipt_signature="!!!bad!!!"),
                       "签名格式错误")
        other_priv, _ = gen_keypair()
        expect_invalid("他钥签回执 -> 签名校验失败",
                       dict(good_payload,
                            receipt_signature=crypto.sign(receipt,
                                                          other_priv)),
                       "签名校验失败")
        check("验真失败不记消费审计", consumed_audits(T1) == [])

        # 缺省租户头（default 租户无锚点）-> 锚点不可用而非 400
        st, r = consume(good_payload)
        check("缺省租户头按 default 隔离 -> 200 锚点不可用",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "锚点不可用")

        # 3. 首次消费：200 按序恰返 valid、receipt_id、consumed_at
        st, r = consume(good_payload, headers=T1)
        check("首次消费 -> 200 恰返 valid,receipt_id,consumed_at",
              st == 200 and list(r.keys())
              == ["valid", "receipt_id", "consumed_at"]
              and r["valid"] is True)
        check("receipt_id 为 receipt 规范化 JSON 的 SHA-256 小写 hex",
              r.get("receipt_id") == want_receipt_id)
        check("consumed_at 为 UTC 秒精度 Z 字符串",
              isinstance(r.get("consumed_at"), str)
              and UTC_Z_RE.fullmatch(r["consumed_at"]) is not None)

        # 4. 审计：首次消费恰记一条，字段正确
        audits = consumed_audits(T1)
        check("首次消费记一条 trust.credential.receipt.consumed 审计",
              len(audits) == 1
              and audits[0]["resource_type"] == "credential_receipt"
              and audits[0]["resource_id"] == want_receipt_id)

        # 5. 同键重放（同 receipt）-> 200 恰返 回执已消费，不再记审计
        st, r = consume(good_payload, headers=T1)
        check("同键重放 -> 200 恰返 回执已消费",
              st == 200 and list(r.keys()) == ["valid", "reason"]
              and r["valid"] is False and r["reason"] == "回执已消费")
        check("重放不记审计", len(consumed_audits(T1)) == 1)

        # 6. 同键重放（receipt 不同）：同 nonce 的另一张合法回执
        body2 = dict(body, credential_id="vc_rc_0002")
        sig2 = crypto.sign(body2, issuer_priv)
        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"body": body2, "signature": sig2,
             "verifier_did": verifier_did, "nonce": nonce},
            headers=T1,
        )
        check("同 nonce 出第二张回执 -> 200", st == 200 and r.get("valid"))
        st, r = consume(
            {"receipt": r["receipt"],
             "receipt_signature": r["receipt_signature"],
             "body": body2, "signature": sig2, "nonce": nonce},
            headers=T1,
        )
        check("同键重放（receipt 不同）-> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        check("不同 receipt 重放不记审计", len(consumed_audits(T1)) == 1)

        # 7. 不同 nonce -> 新键，可成功消费
        nonce2 = "nonce-消费-002"
        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": nonce2},
            headers=T1,
        )
        receipt2, receipt2_sig = r["receipt"], r["receipt_signature"]
        st, r = consume(
            {"receipt": receipt2, "receipt_signature": receipt2_sig,
             "body": body, "signature": sig, "nonce": nonce2},
            headers=T1,
        )
        check("不同 nonce -> 首次消费成功",
              st == 200 and r.get("valid") is True)
        check("第二次首次消费再记一条审计", len(consumed_audits(T1)) == 2)

        # 8. 租户隔离：自备验证者密钥，同键在两租户各自首次成功
        my_priv, my_pub = gen_keypair()
        my_verifier = "did:web:verifier.example"
        for headers in (T1, T2):
            st, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": my_verifier, "public_key": my_pub,
                 "key_version": 1},
                headers=headers,
            )
            check(f"注册自备验证者锚点（{headers['X-Tenant-ID']}）-> 201",
                  st == 201)

        def make_receipt(b, s, n):
            rcpt = {
                "credential_id": b["credential_id"],
                "issuer_did": b["issuer_did"],
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": b, "signature": s})
                ).hexdigest(),
                "verifier_did": my_verifier,
                "verifier_key_version": 1,
                "nonce": n,
            }
            return rcpt, crypto.sign(rcpt, my_priv)

        iso_nonce = "nonce-隔离-001"
        rcpt, rcpt_sig = make_receipt(body, sig, iso_nonce)
        iso_payload = {"receipt": rcpt, "receipt_signature": rcpt_sig,
                       "body": body, "signature": sig, "nonce": iso_nonce}
        st, r = consume(iso_payload, headers=T1)
        check("租户 A 同键首次消费成功", st == 200 and r.get("valid") is True)
        st, r = consume(iso_payload, headers=T2)
        check("租户 B 同键互不影响首次消费成功",
              st == 200 and r.get("valid") is True)
        st, r = consume(iso_payload, headers=T2)
        check("租户 B 重放 -> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        check("消费审计按租户隔离",
              len(consumed_audits(T1)) == 3
              and len(consumed_audits(T2)) == 1)

        # 9. 并发：同键仅一次成功
        conc_nonce = "nonce-并发-001"
        rcpt, rcpt_sig = make_receipt(body, sig, conc_nonce)
        conc_payload = {"receipt": rcpt, "receipt_signature": rcpt_sig,
                        "body": body, "signature": sig, "nonce": conc_nonce}
        results = []

        def worker():
            results.append(consume(conc_payload, headers=T1))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = sum(1 for st, r in results
                   if st == 200 and r.get("valid") is True)
        n_replay = sum(1 for st, r in results
                       if st == 200
                       and r == {"valid": False, "reason": "回执已消费"})
        check("并发同键仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)

        # 10. 落盘失败：500 仅 {"error":"存储失败"}，回滚可重试
        fail_nonce = "nonce-落盘-001"
        rcpt, rcpt_sig = make_receipt(body, sig, fail_nonce)
        fail_payload = {"receipt": rcpt, "receipt_signature": rcpt_sig,
                        "body": body, "signature": sig, "nonce": fail_nonce}
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume(fail_payload, headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = consume(fail_payload, headers=T1)
        check("落盘失败回滚后同键可重试成功",
              st == 200 and r.get("valid") is True)

        # 11. 重启仍判重
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume(good_payload, headers=T1)
        check("重启后同键重放 -> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        st, r = consume(iso_payload, headers=T2)
        check("重启后他租户同键重放 -> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        st, r = consume(fail_payload, headers=T1)
        check("重启后落盘失败重试键仍判重",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})

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
