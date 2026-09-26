#!/usr/bin/env python3
"""receipt-sync 冒烟测试（临时）。"""
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

SYNC_PATH = "/v1/trust/receipt-sync"
RECEIPT_PATH = "/v1/trust/credentials/verify-receipt"
CONSUME_PATH = "/v1/trust/credentials/receipt/consume"
BATCH_PATH = "/v1/trust/credentials/receipt/consume-batch"


def _http(method, url, payload=None, headers=None, raw_body=None):
    data = raw_body if raw_body is not None else (
        json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
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
        encryption_algorithm=serialization.NoEncryption()).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem


def ndjson_of(events):
    return "".join(
        json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n"
        for e in events)


def manifest_for(signer_did, priv, snapshot, after, ndjson, limit=1000,
                 key_version=1):
    raw = ndjson.encode("utf-8")
    m = {
        "snapshot": snapshot,
        "filters": {"after": after, "limit": limit},
        "count": raw.count(b"\n"),
        "alg": "SHA-256",
        "digest": hashlib.sha256(raw).hexdigest(),
        "signer_did": signer_did,
        "key_version": key_version,
    }
    m["signature"] = crypto.sign(m, priv)
    return m


def ev(cursor, receipt_id, verifier_did, nonce, consumed_at):
    return {"cursor": cursor, "receipt_id": receipt_id,
            "verifier_did": verifier_did, "nonce": nonce,
            "consumed_at": consumed_at}


def main():
    port = 9137
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port)
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    TA = {"X-Tenant-ID": "tenant-a"}
    TB = {"X-Tenant-ID": "tenant-b"}

    def sync(payload=None, raw_body=None, headers=TA):
        return _http("POST", f"{base}{SYNC_PATH}", payload=payload,
                     raw_body=raw_body, headers=headers)

    try:
        # 外部签名者（自持私钥）+ vc 锚点
        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:sync-source.example"
        st, raw = _http("POST", f"{base}/v1/trust/anchors",
                        {"did": signer_did, "public_key": signer_pub,
                         "key_version": 1, "uses": ["vc"]}, TA)
        assert st == 201, raw

        # 本地验证者 DID + vc 锚点（供 consume 交叉验证）
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "verifier"}, TA)
        verifier = json.loads(raw)
        verifier_did, verifier_pub = verifier["did"], verifier["public_key"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": verifier_did, "public_key": verifier_pub,
                       "key_version": 1}, TA)
        assert st in (200, 201)

        # 外部签发者（供构造真实回执）
        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:sync-issuer.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": issuer_did, "public_key": issuer_pub,
                       "key_version": 1}, TA)
        assert st == 201

        # ---- 400 族 ----
        def expect_400(name, **kw):
            st, raw = sync(**kw)
            r = json.loads(raw.decode() or "{}")
            check(f"400: {name}", st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and r["error"])

        expect_400("非法 JSON", raw_body=b"nope")
        expect_400("非对象", raw_body=b"[1]")
        expect_400("空体", raw_body=b"")
        expect_400("缺 ndjson", payload={"manifest": {}})
        expect_400("缺 manifest", payload={"ndjson": ""})
        expect_400("多余字段", payload={"manifest": {}, "ndjson": "", "x": 1})
        expect_400("manifest 非对象", payload={"manifest": 1, "ndjson": ""})
        expect_400("ndjson 非字符串", payload={"manifest": {}, "ndjson": 1})

        # ---- 清单验真失败 ----
        e1 = ev(1, "r" * 64, verifier_did, "n-1", "2026-09-26T00:00:01Z")
        e2 = ev(2, "s" * 64, verifier_did, "n-2", "2026-09-26T00:00:02Z")
        page1 = ndjson_of([e1, e2])
        m1 = manifest_for(signer_did, signer_priv, 4, 0, page1)
        bad = dict(m1); bad["signature"] = "A" * 86
        st, raw = sync({"manifest": bad, "ndjson": page1})
        check("清单验真失败沿用原因", st == 200 and json.loads(raw) == {
            "valid": False, "reason": "签名校验失败"})

        # ---- 首次同步 201 ----
        st, raw = sync({"manifest": m1, "ndjson": page1})
        r = json.loads(raw)
        check("首次 201", st == 201)
        check("首次响应键序与取值",
              list(r.keys()) == ["valid", "signer_did", "snapshot",
                                 "next_after", "count"]
              and r == {"valid": True, "signer_did": signer_did,
                        "snapshot": 4, "next_after": 2, "count": 2})

        # ---- 重放 200 ----
        st, raw = sync({"manifest": m1, "ndjson": page1})
        check("重放 200 同响应", st == 200 and json.loads(raw) == r)

        # ---- 同位异内容 409 ----
        e2x = ev(2, "t" * 64, verifier_did, "n-2x", "2026-09-26T00:00:03Z")
        page1x = ndjson_of([e1, e2x])
        m1x = manifest_for(signer_did, signer_priv, 4, 0, page1x)
        st, raw = sync({"manifest": m1x, "ndjson": page1x})
        check("同位异内容 409", st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # ---- 跳页 409 ----
        e3 = ev(3, "u" * 64, verifier_did, "n-3", "2026-09-26T00:00:04Z")
        page_skip = ndjson_of([e3])
        m_skip = manifest_for(signer_did, signer_priv, 4, 0 + 3 - 3 + 0, page_skip)
        # after=0 但 cursor 从 3 开始（与检查点 after=2 不符）-> 409
        st, raw = sync({"manifest": m_skip, "ndjson": page_skip})
        check("跳页/位置不符 409", st == 409
              and json.loads(raw) == {"error": "同步游标冲突"})

        # ---- 续页 201 ----
        page2 = ndjson_of([e3, ev(4, "v" * 64, verifier_did, "n-4",
                                  "2026-09-26T00:00:05Z")])
        m2 = manifest_for(signer_did, signer_priv, 4, 2, page2)
        st, raw = sync({"manifest": m2, "ndjson": page2})
        r2 = json.loads(raw)
        check("续页 201", st == 201 and r2 == {
            "valid": True, "signer_did": signer_did, "snapshot": 4,
            "next_after": 4, "count": 2})

        # ---- 新 snapshot（末 cursor=旧 snapshot）----
        page3 = ndjson_of([ev(5, "w" * 64, verifier_did, "n-5",
                              "2026-09-26T00:00:06Z")])
        m3 = manifest_for(signer_did, signer_priv, 5, 4, page3)
        st, raw = sync({"manifest": m3, "ndjson": page3})
        check("新 snapshot 201", st == 201 and json.loads(raw)[
            "snapshot"] == 5 and json.loads(raw)["next_after"] == 5)

        # ---- 旧页 409 ----
        st, raw = sync({"manifest": m2, "ndjson": page2})
        check("旧页 409", st == 409)

        # ---- 重复 (verifier_did, nonce) ----
        ed = ev(6, "x" * 64, verifier_did, "n-5", "2026-09-26T00:00:07Z")
        paged = ndjson_of([ed])
        md = manifest_for(signer_did, signer_priv, 6, 5, paged)
        st, raw = sync({"manifest": md, "ndjson": paged})
        check("与已同步重复 -> 导出内容非法", st == 200 and json.loads(raw)
              == {"valid": False, "reason": "导出内容非法"})
        # 页内重复
        edup1 = ev(6, "y" * 64, verifier_did, "n-6", "2026-09-26T00:00:07Z")
        edup2 = ev(7, "z" * 64, verifier_did, "n-6", "2026-09-26T00:00:08Z")
        pagedup = ndjson_of([edup1, edup2])
        mdup = manifest_for(signer_did, signer_priv, 7, 5, pagedup)
        st, raw = sync({"manifest": mdup, "ndjson": pagedup})
        check("页内重复 -> 导出内容非法", st == 200 and json.loads(raw)
              == {"valid": False, "reason": "导出内容非法"})

        # ---- 结构非法 ----
        def expect_illegal(name, events=None, raw_ndjson=None, snapshot=6,
                           after=5):
            text = raw_ndjson if raw_ndjson is not None else ndjson_of(events)
            m = manifest_for(signer_did, signer_priv, snapshot, after, text)
            st, raw = sync({"manifest": m, "ndjson": text})
            check(name, st == 200 and json.loads(raw) == {
                "valid": False, "reason": "导出内容非法"})

        bad_key_order = ('{"receipt_id":"%s","cursor":6,"verifier_did":"v",'
                         '"nonce":"n","consumed_at":"t"}\n' % ("a" * 64))
        expect_illegal("键序不符", raw_ndjson=bad_key_order)
        bad_type = ('{"cursor":"6","receipt_id":"%s","verifier_did":"v",'
                    '"nonce":"n","consumed_at":"t"}\n' % ("a" * 64))
        expect_illegal("cursor 类型非法", raw_ndjson=bad_type)
        expect_illegal("cursor 越界(>snapshot)",
                       events=[ev(7, "a" * 64, verifier_did, "n-7",
                                  "2026-09-26T00:00:09Z")], snapshot=6)
        expect_illegal("cursor 不递增(<=after)",
                       events=[ev(5, "a" * 64, verifier_did, "n-7",
                                  "2026-09-26T00:00:09Z")], snapshot=6)
        expect_illegal("非 JSON 行", raw_ndjson="hello\n")
        expect_illegal("缺 LF 结行",
                       raw_ndjson=ndjson_of([ev(6, "a" * 64, verifier_did,
                                                "n-7", "t")])[:-1])

        # ---- 同步不记审计 ----
        _, a1 = _http("GET", f"{base}/v1/audit", headers=TA)
        page4 = ndjson_of([ev(6, "b" * 64, verifier_did, "n-6",
                              "2026-09-26T00:00:10Z")])
        m4 = manifest_for(signer_did, signer_priv, 6, 5, page4)
        st, raw = sync({"manifest": m4, "ndjson": page4})
        check("续新页 201", st == 201)
        _, a2 = _http("GET", f"{base}/v1/audit", headers=TA)
        check("同步无审计", a1 == a2)

        # ---- consume 命中同步键 ----
        body = {"credential_id": "vc_sync_0001", "issuer_did": issuer_did,
                "subject_did": "did:web:sub", "claims": {"r": "x"},
                "issued_at": "2026-09-20T00:00:00Z", "issuer_key_version": 1}
        sig = crypto.sign(body, issuer_priv)
        st, raw = _http("POST", f"{base}{RECEIPT_PATH}",
                        {"body": body, "signature": sig,
                         "verifier_did": verifier_did, "nonce": "n-1"}, TA)
        pack = json.loads(raw)
        assert pack["valid"] is True, pack
        st, raw = _http("POST", f"{base}{CONSUME_PATH}",
                        {"receipt": pack["receipt"],
                         "receipt_signature": pack["receipt_signature"],
                         "body": body, "signature": sig, "nonce": "n-1"}, TA)
        check("consume 命中同步键 -> 回执已消费", st == 200
              and json.loads(raw) == {"valid": False, "reason": "回执已消费"})
        # 未同步键正常消费
        st, raw = _http("POST", f"{base}{RECEIPT_PATH}",
                        {"body": body, "signature": sig,
                         "verifier_did": verifier_did, "nonce": "n-new"}, TA)
        pack2 = json.loads(raw)
        st, raw = _http("POST", f"{base}{CONSUME_PATH}",
                        {"receipt": pack2["receipt"],
                         "receipt_signature": pack2["receipt_signature"],
                         "body": body, "signature": sig, "nonce": "n-new"}, TA)
        check("未同步键正常消费", st == 200
              and json.loads(raw)["valid"] is True)
        # 批量 consume 命中同步键
        st, raw = _http("POST", f"{base}{RECEIPT_PATH}",
                        {"body": body, "signature": sig,
                         "verifier_did": verifier_did, "nonce": "n-2"}, TA)
        pack3 = json.loads(raw)
        st, raw = _http("POST", f"{base}{BATCH_PATH}",
                        {"items": [
                            {"receipt": pack3["receipt"],
                             "receipt_signature": pack3["receipt_signature"],
                             "body": body, "signature": sig, "nonce": "n-2"}]},
                        TA)
        check("批量 consume 命中同步键", st == 200 and json.loads(raw)[
            "results"] == [{"valid": False, "reason": "回执已消费"}])

        # ---- 租户隔离：tenant-b 无该锚点 -> 锚点不可用；且无检查点 ----
        st, raw = sync({"manifest": m1, "ndjson": page1}, headers=TB)
        check("租户隔离", st == 200 and json.loads(raw) == {
            "valid": False, "reason": "锚点不可用"})

        # ---- 重启后检查点与同步键保留 ----
        proc.terminate(); proc.wait(timeout=10)
        proc = start()
        st, raw = sync({"manifest": m4, "ndjson": page4})
        check("重启后重放 200", st == 200 and json.loads(raw)[
            "next_after"] == 6)
        st, raw = _http("POST", f"{base}{CONSUME_PATH}",
                        {"receipt": pack["receipt"],
                         "receipt_signature": pack["receipt_signature"],
                         "body": body, "signature": sig, "nonce": "n-1"}, TA)
        check("重启后 consume 仍判重", st == 200 and json.loads(raw) == {
            "valid": False, "reason": "回执已消费"})
        # 重启后续页
        page5 = ndjson_of([ev(7, "c" * 64, verifier_did, "n-7",
                              "2026-09-26T00:00:11Z")])
        m5 = manifest_for(signer_did, signer_priv, 7, 6, page5)
        st, raw = sync({"manifest": m5, "ndjson": page5})
        check("重启后续页 201", st == 201 and json.loads(raw)[
            "next_after"] == 7)

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
