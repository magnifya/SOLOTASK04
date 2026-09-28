#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt-sync/receipt/consume 一次性
消费凭证状态回执消费同步进度签名回执端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consume_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖（完整对齐
POST /v1/trust/presentation-sync/receipt/consume，差异为锚点用途 status、
判重索引独立、重放文案“状态同步回执已消费”及审计动作
trust.credential.status.sync.receipt.consumed /
credential_status_sync_receipt）：
- 400：空体、非法 JSON、非对象、键集错（缺/多键）、类型错，均仅
  {"error":"请求非法"}；显式空租户头 400；
- 200 验真失败原因沿用同目录 verify 六阶段优先级，失败不写消费、
  不记审计；
- 首次 200 恰返 valid、receipt_id、consumed_at；receipt_id 为完整
  receipt 规范化 JSON UTF-8 字节 SHA-256 小写 64 位 hex；
  consumed_at 为 UTC 秒精度 Z；
- 同键重放（内容不同）及并发后到者均 200，仅
  {"valid":false,"reason":"状态同步回执已消费"}，不记审计；
- 首次记 trust.credential.status.sync.receipt.consumed 审计
  （resource_type=credential_status_sync_receipt、
  resource_id=receipt_id），失败与重放不记；
- 判重索引与 credential-status/receipt/consume 相互独立；
  租户隔离；重启判重。
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
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt-sync/receipt"
CONSUME_PATH = "/v1/trust/credential-status/receipt-sync/receipt/consume"
STATUS_CONSUME_PATH = "/v1/trust/credential-status/receipt/consume"
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


VERIFIER_DID = "did:web:cs-rs-consume-verifier.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-演-{index:055d}",
        "verifier_did": VERIFIER_DID,
        "nonce": f"cs-rs-consume-nonce-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9067
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

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        TENANT = {"X-Tenant-ID": "cs-rs-consume-tenant"}
        OTHER = {"X-Tenant-ID": "cs-rs-consume-other-tenant"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:cs-rs-consume-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, TENANT)
        assert st in (200, 201), st

        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-status-receipt-sync-consume"},
                       TENANT)
        assert st == 201, (st, raw)
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]

        def signed_manifest(snapshot, after, ndjson):
            manifest = {
                "snapshot": snapshot,
                "filters": {"after": after, "limit": 1000},
                "count": ndjson.count("\n"),
                "alg": "SHA-256",
                "digest": hashlib.sha256(
                    ndjson.encode("utf-8")).hexdigest(),
                "signer_did": signer_did,
                "key_version": 1,
            }
            manifest["signature"] = crypto.sign(
                {k: manifest[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return manifest

        def sync_page(cursors, after, snapshot):
            rows = [make_row(c, c) for c in cursors]
            ndjson = to_ndjson(rows)
            st, r = post(SYNC_PATH,
                         {"manifest": signed_manifest(snapshot, after,
                                                      ndjson),
                          "ndjson": ndjson}, TENANT)
            assert st in (200, 201), (st, r)
            return ndjson

        def get_receipt(nonce):
            qs = urllib.parse.urlencode(
                {"signer_did": signer_did, "verifier_did": verifier_did,
                 "nonce": nonce})
            st, raw = get(f"{RECEIPT_PATH}?{qs}", headers=TENANT)
            assert st == 200, (st, raw)
            issued = json.loads(raw)
            return issued["receipt"], issued["signature"]

        ndjson1 = sync_page([1, 2, 3], 0, 3)
        nonce = "nonce-consume-一"
        receipt, signature = get_receipt(nonce)
        key_version = receipt["verifier_key_version"]

        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": key_version,
                      "uses": ["generic", "status"]}, TENANT)
        assert st in (200, 201), st

        good = {"receipt": receipt, "signature": signature,
                "ndjson": ndjson1, "nonce": nonce}

        def consume(payload=None, headers=TENANT, raw_body=None,
                    path=CONSUME_PATH):
            st, raw = post(path, payload=payload, headers=headers,
                           raw_body=raw_body)
            return st, json.loads(raw.decode() or "null")

        # ---------------------------------------------------------- #
        # 1. 400：仅 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, payload=None, raw_body=None, headers=TENANT):
            st, body = consume(payload, headers=headers, raw_body=raw_body)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("空体 400", raw_body=b"")
        expect_400("非法 JSON 400", raw_body=b"{not json")
        expect_400("非对象（数组）400", raw_body=b"[1,2]")
        expect_400("非对象（字符串）400", raw_body=b'"x"')
        for field in ("receipt", "signature", "ndjson", "nonce"):
            expect_400(f"缺 {field} 400",
                       {k: v for k, v in good.items() if k != field})
        extra = dict(good)
        extra["x"] = 1
        expect_400("多键 400", extra)
        bad = dict(good)
        bad["receipt"] = "not-object"
        expect_400("receipt 非对象", bad)
        bad = dict(good)
        bad["signature"] = ""
        expect_400("signature 空串", bad)
        bad = dict(good)
        bad["signature"] = 123
        expect_400("signature 非串", bad)
        bad = dict(good)
        bad["ndjson"] = 1
        expect_400("ndjson 非串", bad)
        bad = dict(good)
        bad["nonce"] = ""
        expect_400("nonce 空串", bad)
        bad = dict(good)
        bad["nonce"] = "a" * 257
        expect_400("nonce 257 码点", bad)
        st, body = consume(good, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400
              and body == {"error": "请求非法"})

        # ---------------------------------------------------------- #
        # 2. 验真失败 200：沿用 verify 的 reason，不写消费不记审计
        # ---------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=TENANT)
        assert st == 200
        audit_before = json.loads(audit_before)

        def expect_reason(name, payload, reason, headers=TENANT):
            st, body = consume(payload, headers=headers)
            check(name, st == 200
                  and list(body.keys()) == ["valid", "reason"]
                  and body == {"valid": False, "reason": reason})

        bad_receipt = dict(receipt)
        bad_receipt["digest"] = "0" * 64
        expect_reason("摘要错误不消费",
                      {"receipt": bad_receipt, "signature": signature,
                       "ndjson": ndjson1, "nonce": nonce}, "摘要错误")
        expect_reason("nonce 错误不消费",
                      {"receipt": receipt, "signature": signature,
                       "ndjson": ndjson1, "nonce": "other"}, "nonce错误")
        # 回执非法
        disordered = {
            "nonce": receipt["nonce"],
            "signer_did": receipt["signer_did"],
            "next_after": receipt["next_after"],
            "digest": receipt["digest"],
            "verifier_did": receipt["verifier_did"],
            "verifier_key_version": receipt["verifier_key_version"],
        }
        expect_reason("回执非法不消费",
                      {"receipt": disordered, "signature": signature,
                       "ndjson": ndjson1, "nonce": nonce}, "回执非法")
        expect_reason("跨租户锚点不可用不消费", good, "锚点不可用",
                      headers=OTHER)
        expect_reason("签名格式错误不消费",
                      {"receipt": receipt, "signature": "!!!",
                       "ndjson": ndjson1, "nonce": nonce}, "签名格式错误")
        other_priv, _ = _keypair()
        expect_reason("签名校验失败不消费",
                      {"receipt": receipt,
                       "signature": crypto.sign(receipt, other_priv),
                       "ndjson": ndjson1, "nonce": nonce}, "签名校验失败")

        st, audit_after = get("/v1/audit?limit=200", headers=TENANT)
        check("验真失败不记审计",
              audit_before == json.loads(audit_after))

        # ---------------------------------------------------------- #
        # 3. 首次消费：valid、receipt_id、consumed_at
        # ---------------------------------------------------------- #
        st, body = consume(good)
        expected_id = hashlib.sha256(
            crypto.canonicalize(receipt)).hexdigest()
        check(
            "首次消费 200 键序 valid/receipt_id/consumed_at",
            st == 200
            and list(body.keys()) == ["valid", "receipt_id", "consumed_at"]
            and body["valid"] is True
            and body["receipt_id"] == expected_id
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                             body["consumed_at"]) is not None,
        )
        receipt_id = body["receipt_id"]
        consumed_at = body["consumed_at"]

        # ---------------------------------------------------------- #
        # 4. 审计：恰好一条，字段正确
        # ---------------------------------------------------------- #
        st, raw = get("/v1/audit?limit=200", headers=TENANT)
        events = [e for e in json.loads(raw)["events"]
                  if e["action"]
                  == "trust.credential.status.sync.receipt.consumed"]
        check(
            "首次记一条消费审计且字段正确",
            len(events) == 1
            and events[0]["resource_type"]
            == "credential_status_sync_receipt"
            and events[0]["resource_id"] == receipt_id
            and events[0]["tenant_id"] == "cs-rs-consume-tenant",
        )

        # ---------------------------------------------------------- #
        # 5. 同键重放（内容不同）：状态同步回执已消费，不重复记审计
        # ---------------------------------------------------------- #
        st, body = consume(good)
        check("同请求重放 -> 状态同步回执已消费",
              st == 200
              and list(body.keys()) == ["valid", "reason"]
              and body == {"valid": False,
                           "reason": "状态同步回执已消费"})

        ndjson2 = sync_page([4], 3, 4)
        ndjson_all = ndjson1 + ndjson2
        receipt2, signature2 = get_receipt(nonce)
        assert receipt2 != receipt
        st, body = consume({"receipt": receipt2, "signature": signature2,
                            "ndjson": ndjson_all, "nonce": nonce})
        check("同键不同内容重放 -> 状态同步回执已消费",
              st == 200 and body == {
                  "valid": False, "reason": "状态同步回执已消费"})

        st, raw = get("/v1/audit?limit=200", headers=TENANT)
        events = [e for e in json.loads(raw)["events"]
                  if e["action"]
                  == "trust.credential.status.sync.receipt.consumed"]
        check("重放不追加审计", len(events) == 1)

        # 同租户不同 nonce 可独立消费。
        nonce_b = "nonce-consume-b"
        receipt_b, signature_b = get_receipt(nonce_b)
        st, body = consume({"receipt": receipt_b, "signature": signature_b,
                            "ndjson": ndjson_all, "nonce": nonce_b})
        check("不同 nonce 独立消费",
              st == 200 and body.get("valid") is True
              and body.get("receipt_id") == hashlib.sha256(
                  crypto.canonicalize(receipt_b)).hexdigest()
              and body.get("consumed_at") >= consumed_at)

        # ---------------------------------------------------------- #
        # 6. 判重索引与 credential-status/receipt/consume 相互独立：
        #    本接口已消费不影响普通状态回执消费（该回执 receipt 协议
        #    不同，验真阶段即失败；直连存储验证两个索引互不命中）。
        # ---------------------------------------------------------- #
        from vcbackend.store import VCStore  # noqa: E402
        direct = VCStore(store_path)
        direct_ok, direct_at = direct.consume_credential_status_sync_receipt(
            "cs-rs-consume-tenant", verifier_did, "direct-nonce", "r" * 64
        )
        check("直连存储首次消费成功", direct_ok and bool(direct_at))
        direct_again, _ = direct.consume_credential_status_sync_receipt(
            "cs-rs-consume-tenant", verifier_did, "direct-nonce", "s" * 64
        )
        check("直连存储同键重放", direct_again is False)
        # 本接口键不污染普通状态回执消费索引：以普通状态回执消费协议
        # （恰含 receipt/signature/nonce）提交同一 (verifier_did,nonce)，
        # 回执结构不符先于判重失败为“回执非法”，而非“状态回执已消费”，
        # 证明两个判重索引互不串扰。
        st, body = consume(
            {"receipt": receipt, "signature": signature, "nonce": nonce},
            path=STATUS_CONSUME_PATH)
        check("普通状态回执消费索引不串扰（回执非法而非已消费）",
              st == 200 and body == {"valid": False, "reason": "回执非法"})

        # ---------------------------------------------------------- #
        # 7. 租户隔离
        # ---------------------------------------------------------- #
        st, body = consume(good, headers=OTHER)
        check("他租户隔离（锚点不可用）",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        st, body = consume(good, headers={})
        check("缺省租户头 default 隔离",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 8. 并发：同键仅一次成功
        # ---------------------------------------------------------- #
        nonce_c = "nonce-consume-c"
        receipt_c, signature_c = get_receipt(nonce_c)
        payload_c = json.dumps(
            {"receipt": receipt_c, "signature": signature_c,
             "ndjson": ndjson_all, "nonce": nonce_c}).encode("utf-8")
        barrier = threading.Barrier(8)

        def fire():
            barrier.wait()
            req = urllib.request.Request(base + CONSUME_PATH, data=payload_c,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Tenant-ID", "cs-rs-consume-tenant")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: fire(), range(8)))
        oks = [b for s, b in responses if s == 200 and b.get("valid") is True]
        replays = [b for s, b in responses
                   if s == 200 and b == {
                       "valid": False, "reason": "状态同步回执已消费"}]
        check("并发同键恰一次成功、其余重放",
              len(oks) == 1 and len(replays) == 7
              and oks[0]["receipt_id"] == hashlib.sha256(
                  crypto.canonicalize(receipt_c)).hexdigest())

        # ---------------------------------------------------------- #
        # 9. 重启判重
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = consume(good)
        check("重启后同键仍判重",
              st == 200 and body == {
                  "valid": False, "reason": "状态同步回执已消费"})
        st, body = consume(good, headers=OTHER)
        check("重启后他租户未被污染",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

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
