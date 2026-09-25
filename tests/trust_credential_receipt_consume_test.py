#!/usr/bin/env python3
"""验真回执防重放消费 POST /v1/trust/credentials/receipt/consume 的端到端测试。

直接运行：python3 tests/trust_credential_receipt_consume_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

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


def main():
    port = 8985
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
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

    def restart():
        proc.terminate()
        proc.wait(timeout=10)
        return subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "rc-a"}
        T2 = {"X-Tenant-ID": "rc-b"}

        # ---- 准备：外部签发者锚点 + 本地验证者 DID + 验证者锚点 ----
        issuer_priv, issuer_pub = gen_keypair()
        issuer_did = "did:web:issuer-rc.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": issuer_did, "public_key": issuer_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册外部签发者锚点 -> 201", st == 201)

        st, r = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "verifier-handle-rc"},
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
            "credential_id": "vc_rc_1001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)
        nonce = "nonce-回执消费-001"

        st, r = _http(
            "POST", f"{base}{receipt_path}",
            {"body": body, "signature": sig,
             "verifier_did": verifier_did, "nonce": nonce},
            headers=T1,
        )
        check("verify-receipt 出回执 -> 200", st == 200 and r.get("valid"))
        receipt = r["receipt"]
        good_payload = {
            "receipt": receipt,
            "receipt_signature": r["receipt_signature"],
            "body": body,
            "signature": sig,
            "nonce": nonce,
        }
        want_receipt_id = hashlib.sha256(
            crypto.canonicalize(receipt)
        ).hexdigest()

        # 1. 400 系列与 receipt/verify 完全一致，仅 {error}
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
        expect_400("signature 空串 -> 400", dict(good_payload, signature=""))
        expect_400("nonce 空串 -> 400", dict(good_payload, nonce=""))
        expect_400("nonce 非字符串 -> 400", dict(good_payload, nonce=1))
        expect_400("nonce 257 码点 -> 400",
                   dict(good_payload, nonce="中" * 257))
        expect_400("显式空租户头 -> 400", good_payload,
                   headers={"X-Tenant-ID": ""})

        # 2. 验真失败沿用 200/固定 reason，且不消费（之后首次仍成功）
        def expect_invalid(name, payload, reason, headers=T1):
            st, r = consume(payload, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        expect_invalid("nonce 不符 -> nonce错误（不消费）",
                       dict(good_payload, nonce="其他nonce"),
                       "nonce错误")
        expect_invalid("签名格式非法 -> 签名格式错误（不消费）",
                       dict(good_payload, receipt_signature="!!!bad!!!"),
                       "签名格式错误")
        expect_invalid("他租户无锚点 -> 锚点不可用（不消费）",
                       good_payload, "锚点不可用", headers=T2)
        st, r = consume(good_payload)
        check("缺省租户头按 default 隔离 -> 200 锚点不可用",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "锚点不可用")

        # 3. 首次消费：200 恰返 valid、receipt_id、consumed_at
        st, r = consume(good_payload, headers=T1)
        check(
            "首次消费 -> 200 键序 valid,receipt_id,consumed_at",
            st == 200 and list(r.keys())
            == ["valid", "receipt_id", "consumed_at"]
            and r["valid"] is True,
        )
        check("receipt_id 为 receipt 规范化 JSON 的 SHA-256 小写 hex",
              r.get("receipt_id") == want_receipt_id
              and re.fullmatch(r"[0-9a-f]{64}", r["receipt_id"]))
        check("consumed_at 为 UTC 秒精度 Z 字符串",
              isinstance(r.get("consumed_at"), str)
              and UTC_Z_RE.fullmatch(r["consumed_at"]) is not None)
        first_consumed_at = r["consumed_at"]

        # 4. 同键重放（receipt 相同）：200 恰返 {"valid":false,...}
        st, r = consume(good_payload, headers=T1)
        check("同载荷重放 -> 200 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})

        # 5. 首次消费记且仅记一条审计，重放不记
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        events = [e for e in audit["events"]
                  if e["action"] == "trust.credential.receipt.consumed"
                  and e["resource_id"] == want_receipt_id]
        check("首次消费记一条 consumed 审计", len(events) == 1)
        if events:
            ev = events[0]
            check("审计 resource_type=credential_receipt",
                  ev["resource_type"] == "credential_receipt")
            check("审计 resource_id=receipt_id",
                  ev["resource_id"] == want_receipt_id)
        st, r = consume(good_payload, headers=T1)
        st, audit2 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("重放不追加审计",
              audit2["events"].count(events[0]) == 1 if events else False)
        # 验真失败同样不记审计
        n_audit = len(audit2["events"])
        consume(dict(good_payload, nonce="x"), headers=T1)
        consume(dict(good_payload, receipt_signature="!!!"), headers=T1)
        st, audit3 = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("验真失败不记审计", len(audit3["events"]) == n_audit)

        # 6. 同键重放且 receipt 内容不同：自备验证者密钥构造两份均能
        #    通过七阶段验真、但 (verifier_did,nonce) 相同的不同回执
        own_priv, own_pub = gen_keypair()
        own_verifier = "did:web:own-verifier.example"
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": own_verifier, "public_key": own_pub,
             "key_version": 1},
            headers=T1,
        )
        check("注册自备验证者锚点 -> 201", st == 201)

        def make_item(credential_id, n, verifier=own_verifier):
            b = {
                "credential_id": credential_id,
                "issuer_did": "did:web:any-issuer.example",
                "subject_did": "did:web:subject.example",
                "claims": {"k": credential_id},
                "issued_at": "2026-09-22T00:00:00Z",
                "issuer_key_version": 1,
            }
            s = "sig-" + credential_id  # 回执验真不重验凭证签名
            rcpt = {
                "credential_id": b["credential_id"],
                "issuer_did": b["issuer_did"],
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": b, "signature": s})
                ).hexdigest(),
                "verifier_did": verifier,
                "verifier_key_version": 1,
                "nonce": n,
            }
            return {
                "receipt": rcpt,
                "receipt_signature": crypto.sign(rcpt, own_priv),
                "body": b,
                "signature": s,
                "nonce": n,
            }

        item_a = make_item("vc_diff_A", "shared-nonce")
        item_b = make_item("vc_diff_B", "shared-nonce")
        check("两份同键回执各自 receipt_id 不同",
              hashlib.sha256(crypto.canonicalize(item_a["receipt"]))
              .hexdigest()
              != hashlib.sha256(crypto.canonicalize(item_b["receipt"]))
              .hexdigest())
        st, ra = consume(item_a, headers=T1)
        check("同键首份回执 -> 200 首次消费",
              st == 200 and ra["valid"] is True
              and list(ra.keys()) == ["valid", "receipt_id",
                                      "consumed_at"])
        st, rb = consume(item_b, headers=T1)
        check("同键不同回执重放 -> 200 回执已消费",
              st == 200 and rb == {"valid": False, "reason": "回执已消费"})

        # 7. 租户隔离：同 verifier_did+nonce 在 T2 注册同公钥锚点后仍首次
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": own_verifier, "public_key": own_pub,
             "key_version": 1},
            headers=T2,
        )
        check("他租户注册同验证者锚点 -> 201", st == 201)
        st, rt = consume(item_a, headers=T2)
        check("跨租户同键不判重 -> 200 首次消费",
              st == 200 and rt["valid"] is True
              and rt["receipt_id"] == ra["receipt_id"])
        st, rt2 = consume(item_a, headers=T2)
        check("他租户内重放 -> 200 回执已消费",
              st == 200 and rt2["reason"] == "回执已消费")

        # 8. 并发仅一次成功
        item_c = make_item("vc_concurrent", "concurrent-nonce")
        results = []
        results_lock = threading.Lock()

        def fire():
            st_i, r_i = consume(item_c, headers=T1)
            with results_lock:
                results.append((st_i, r_i))

        threads = [threading.Thread(target=fire) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        firsts = [r for st_i, r in results
                  if st_i == 200 and r.get("valid") is True]
        replays = [r for st_i, r in results
                   if st_i == 200 and r ==
                   {"valid": False, "reason": "回执已消费"}]
        check("并发 12 次仅一次首次成功",
              len(results) == 12 and len(firsts) == 1
              and len(replays) == 11)

        # 9. 重启后仍判重
        proc = restart()
        assert wait_up(port), "重启超时"
        st, r = consume(good_payload, headers=T1)
        check("重启后同键重放 -> 200 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        st, r = consume(item_c, headers=T1)
        check("重启后并发键仍判重",
              st == 200 and r["reason"] == "回执已消费")
        # 重启后首次消费的新键仍成功，consumed_at 正常生成
        item_d = make_item("vc_after_restart", "after-restart-nonce")
        st, r = consume(item_d, headers=T1)
        check("重启后新键首次消费 -> 200",
              st == 200 and r["valid"] is True
              and UTC_Z_RE.fullmatch(r["consumed_at"]) is not None)

        # 10. 落盘失败：500 仅 {error:存储失败}，回滚后可重试成功
        item_e = make_item("vc_persist", "persist-fail-nonce")
        assert os.path.isfile(store)
        os.remove(store)
        os.mkdir(store)
        try:
            st, r = consume(item_e, headers=T1)
            check("落盘失败 -> 500 恰返 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        st, r = consume(item_e, headers=T1)
        check("回滚后重试 -> 200 首次消费（可重试）",
              st == 200 and r["valid"] is True
              and list(r.keys()) == ["valid", "receipt_id",
                                     "consumed_at"])
        st, r = consume(item_e, headers=T1)
        check("重试成功后重放 -> 200 回执已消费",
              st == 200 and r["reason"] == "回执已消费")

        # 11. 真实回执首次 consumed_at 与审计记录一致
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        real_events = [e for e in audit["events"]
                       if e["resource_id"] == want_receipt_id]
        check("真实回执审计仍恰一条", len(real_events) == 1
              and real_events[0]["action"]
              == "trust.credential.receipt.consumed")

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store) and os.path.isfile(store):
            os.unlink(store)
        elif os.path.isdir(store):
            os.rmdir(store)

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
