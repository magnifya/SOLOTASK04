#!/usr/bin/env python3
"""POST /v1/trust/presentation-sync/receipt/consume-batch 批量一次性消费
演示同步回执端到端测试。

直接运行：python3 tests/trust_presentation_sync_receipt_consume_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级非法（空体、非法 JSON、非 UTF-8、非对象、键集错、items 非
  数组/空/超 100）均 200 且按键序恰返 {"results":[],"reason":"请求非法"}；
  显式空租户头 400 仅 {"error"}；
- 项结构非法（非对象、键集错、receipt 非对象、signature 空/非串、
  ndjson 非串、nonce 空/超 256 码点）逐项
  {"valid":false,"reason":"请求项非法"}，不短路；
- 六阶段验真失败沿用单条 reason 与优先级，失败不写消费、不记审计；
- 成功项键序 valid、receipt_id、consumed_at，取值同单条；
- 批内同键前项对后项可见、历史与并发重放均
  {"valid":false,"reason":"同步回执已消费"}；与单条 consume 互判重；
- 首消审计与单条同规格、整批原子落盘；落盘失败 500 仅
  {"error":"存储失败"} 且全回滚可重试；租户隔离；重启判重。
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
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/presentation-sync"
RECEIPT_PATH = "/v1/trust/presentation-sync/receipt"
CONSUME_PATH = "/v1/trust/presentation-sync/receipt/consume"
BATCH_PATH = "/v1/trust/presentation-sync/receipt/consume-batch"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

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


ISSUER_DID = "did:web:pres-sync-receipt-consume-batch-issuer.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "consumption_id": f"cons-{index:060d}",
        "issuer_did": ISSUER_DID,
        "presentation_id": f"vp_{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9093
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
        TENANT = {"X-Tenant-ID": "consume-batch-tenant"}
        OTHER = {"X-Tenant-ID": "other-consume-batch-tenant"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:pres-sync-receipt-consume-batch-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1}, TENANT)
        assert st in (200, 201), st

        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "presentation-sync-receipt-consume-batch"},
                       TENANT)
        assert st == 201, (st, raw)
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": 1,
                      "uses": ["generic", "vp"]}, TENANT)
        assert st in (200, 201), st

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

        ndjson1 = sync_page([3, 7, 11], 0, 11)

        def make_item(nonce, ndjson=ndjson1):
            receipt, signature = get_receipt(nonce)
            return {"receipt": receipt, "signature": signature,
                    "ndjson": ndjson, "nonce": nonce}

        good1 = make_item("nonce-批-001")
        want_receipt_id1 = hashlib.sha256(
            crypto.canonicalize(good1["receipt"])).hexdigest()

        def consume_batch(payload=None, headers=TENANT, raw_body=None):
            return post(BATCH_PATH, payload=payload, headers=headers,
                        raw_body=raw_body)

        def consume_single(payload, headers=TENANT):
            return post(CONSUME_PATH, payload=payload, headers=headers)

        def consumed_audits(headers):
            st, raw = get("/v1/audit?limit=200", headers=headers)
            assert st == 200
            return [e for e in json.loads(raw)["events"]
                    if e["action"]
                    == "trust.presentation.sync.receipt.consumed"]

        # ---------------------------------------------------------- #
        # 1. 请求级非法 -> 200 按键序恰返 {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_request_invalid(name, payload=None, raw_body=None,
                                   headers=TENANT):
            st, raw = consume_batch(payload=payload, raw_body=raw_body,
                                    headers=headers)
            body = json.loads(raw.decode() or "null")
            check(name, st == 200
                  and list(body.keys()) == ["results", "reason"]
                  and body == {"results": [], "reason": "请求非法"})

        expect_request_invalid("空请求体", raw_body=b"")
        expect_request_invalid("非法 JSON", raw_body=b"{not json")
        expect_request_invalid("非 UTF-8", raw_body=b"\xff\xfe")
        expect_request_invalid("非对象（数组）", raw_body=b"[1,2]")
        expect_request_invalid("非对象（字符串）", raw_body=b'"x"')
        expect_request_invalid("缺 items", payload={})
        expect_request_invalid("多余字段", payload={"items": [good1], "x": 1})
        expect_request_invalid("items 非数组", payload={"items": "x"})
        expect_request_invalid("items 空数组", payload={"items": []})
        expect_request_invalid("items 超限（101）",
                               payload={"items": [good1] * 101})
        st, raw = consume_batch({"items": [good1]},
                                headers={"X-Tenant-ID": ""})
        body = json.loads(raw.decode() or "null")
        check("显式空租户头 400 仅 {error}",
              st == 400 and list(body.keys()) == ["error"])

        # ---------------------------------------------------------- #
        # 2. 项结构非法 -> 请求项非法，逐项不短路
        # ---------------------------------------------------------- #
        st, raw = consume_batch({"items": [
            "not-object",
            [1, 2],
            {k: v for k, v in good1.items() if k != "nonce"},
            dict(good1, x=1),
            dict(good1, receipt="x"),
            dict(good1, signature=""),
            dict(good1, signature=1),
            dict(good1, ndjson=1),
            dict(good1, nonce=""),
            dict(good1, nonce="中" * 257),
            good1,
        ]})
        body = json.loads(raw.decode())
        check("混合批次 -> 200 且 results 等长同序",
              st == 200 and list(body.keys()) == ["results"]
              and len(body["results"]) == 11)
        results = body["results"]
        check("十种非法项均为 请求项非法",
              all(item == {"valid": False, "reason": "请求项非法"}
                  for item in results[:10]))
        check("末项合法首次消费成功且键序 valid/receipt_id/consumed_at",
              list(results[10].keys()) == ["valid", "receipt_id", "consumed_at"]
              and results[10]["valid"] is True
              and results[10]["receipt_id"] == want_receipt_id1
              and UTC_Z_RE.fullmatch(results[10]["consumed_at"]) is not None)

        events = consumed_audits(TENANT)
        check("首次消费记一条审计且字段正确",
              len(events) == 1
              and events[0]["resource_type"] == "presentation_sync_receipt"
              and events[0]["resource_id"] == want_receipt_id1
              and events[0]["tenant_id"] == "consume-batch-tenant")

        # ---------------------------------------------------------- #
        # 3. 六阶段验真失败沿用单条 reason，失败不消费不记审计
        # ---------------------------------------------------------- #
        other_priv, _ = _keypair()
        bad_structure = dict(good1["receipt"])
        del bad_structure["nonce"]
        bad_digest = dict(good1["receipt"])
        bad_digest["digest"] = "0" * 64
        no_anchor_receipt = {
            "signer_did": signer_did,
            "next_after": 11,
            "digest": hashlib.sha256(ndjson1.encode("utf-8")).hexdigest(),
            "verifier_did": "did:web:no-such-anchor.example",
            "verifier_key_version": 1,
            "nonce": "nonce-无锚点",
        }
        seven_items = [
            dict(good1, receipt=bad_structure),                 # 回执非法
            dict(good1, nonce="其他nonce"),                     # nonce错误
            dict(good1, receipt=bad_digest),                    # 摘要错误
            {"receipt": no_anchor_receipt,
             "signature": crypto.sign(no_anchor_receipt, other_priv),
             "ndjson": ndjson1,
             "nonce": "nonce-无锚点"},                          # 锚点不可用
            dict(good1, signature="!!!"),                       # 签名格式错误
            dict(good1, signature=crypto.sign(good1["receipt"],
                                              other_priv)),     # 签名校验失败
            good1,                                              # 历史重放
        ]
        st, raw = consume_batch({"items": seven_items})
        body = json.loads(raw.decode())
        want_reasons = ["回执非法", "nonce错误", "摘要错误", "锚点不可用",
                        "签名格式错误", "签名校验失败", "同步回执已消费"]
        check("六阶段+重放 reason 与优先级沿用单条",
              st == 200
              and [item.get("reason") for item in body["results"]]
              == want_reasons
              and all(item.get("valid") is False
                      for item in body["results"])
              and all(list(item.keys()) == ["valid", "reason"]
                      for item in body["results"]))
        check("验真失败与重放不记审计",
              len(consumed_audits(TENANT)) == 1)

        # ---------------------------------------------------------- #
        # 4. 批内同键判重：首项成功、后项已消费；不同 nonce 各自成功
        # ---------------------------------------------------------- #
        item_b = make_item("nonce-批-002")
        item_c = make_item("nonce-批-003")
        st, raw = consume_batch({"items": [item_b, item_b, item_c]})
        body = json.loads(raw.decode())
        check("批内同键首项成功、后项已消费、异键成功",
              st == 200
              and body["results"][0].get("valid") is True
              and body["results"][1] == {"valid": False,
                                         "reason": "同步回执已消费"}
              and body["results"][2].get("valid") is True)
        check("批内两项新消费记两条审计",
              len(consumed_audits(TENANT)) == 3)

        # 推进检查点后同键（verifier_did, nonce）不同内容仍为重放。
        ndjson2 = sync_page([15], 11, 15)
        ndjson_all = ndjson1 + ndjson2
        item_b2 = make_item("nonce-批-002", ndjson=ndjson_all)
        assert item_b2["receipt"] != item_b["receipt"]
        st, raw = consume_batch({"items": [item_b2]})
        body = json.loads(raw.decode())
        check("同键不同内容重放 -> 同步回执已消费",
              st == 200 and body["results"] == [
                  {"valid": False, "reason": "同步回执已消费"}])
        check("重放不追加审计", len(consumed_audits(TENANT)) == 3)

        # ---------------------------------------------------------- #
        # 5. 与单条 consume 互判重
        # ---------------------------------------------------------- #
        item_d = make_item("nonce-批-004", ndjson=ndjson_all)
        st, raw = consume_single(item_d)
        check("单条先消费 -> 200 valid:true",
              st == 200 and json.loads(raw.decode()).get("valid") is True)
        st, raw = consume_batch({"items": [item_d]})
        check("单条消费后批量同键 -> 同步回执已消费",
              st == 200 and json.loads(raw.decode())["results"] == [
                  {"valid": False, "reason": "同步回执已消费"}])
        item_e = make_item("nonce-批-005", ndjson=ndjson_all)
        st, raw = consume_batch({"items": [item_e]})
        check("批量先消费 -> 成功",
              st == 200
              and json.loads(raw.decode())["results"][0].get("valid") is True)
        st, raw = consume_single(item_e)
        check("批量消费后单条同键 -> 同步回执已消费",
              st == 200 and json.loads(raw.decode()) == {
                  "valid": False, "reason": "同步回执已消费"})

        # ---------------------------------------------------------- #
        # 6. 租户隔离：自备验证者密钥，同键在两租户各自首次成功
        # ---------------------------------------------------------- #
        my_priv, my_pub = _keypair()
        my_verifier = "did:web:pres-sync-consume-batch-self.example"
        for headers in (TENANT, OTHER):
            st, _ = post(ANCHORS_PATH,
                         {"did": my_verifier, "public_key": my_pub,
                          "key_version": 1, "uses": ["vp"]}, headers)
            assert st in (200, 201), st

        def make_self_item(nonce):
            rcpt = {
                "signer_did": signer_did,
                "next_after": 11,
                "digest": hashlib.sha256(
                    ndjson1.encode("utf-8")).hexdigest(),
                "verifier_did": my_verifier,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return {"receipt": rcpt,
                    "signature": crypto.sign(rcpt, my_priv),
                    "ndjson": ndjson1, "nonce": nonce}

        iso_item = make_self_item("nonce-批隔离-001")
        st, raw = consume_batch({"items": [iso_item]}, headers=TENANT)
        check("租户 A 同键首次消费成功",
              st == 200
              and json.loads(raw.decode())["results"][0].get("valid") is True)
        st, raw = consume_batch({"items": [iso_item]}, headers=OTHER)
        check("租户 B 同键互不影响首次消费成功",
              st == 200
              and json.loads(raw.decode())["results"][0].get("valid") is True)
        st, raw = consume_batch({"items": [iso_item]}, headers=OTHER)
        check("租户 B 重放 -> 同步回执已消费",
              st == 200 and json.loads(raw.decode())["results"] == [
                  {"valid": False, "reason": "同步回执已消费"}])
        st, raw = consume_batch({"items": [iso_item]}, headers={})
        check("缺省租户头按 default 隔离 -> 锚点不可用",
              st == 200 and json.loads(raw.decode())["results"][0] == {
                  "valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 7. 并发：批量与单条同键仅一次成功
        # ---------------------------------------------------------- #
        conc_item = make_self_item("nonce-批并发-001")
        outcomes = []

        def worker_batch():
            outcomes.append(consume_batch({"items": [conc_item]},
                                          headers=TENANT))

        def worker_single():
            outcomes.append(consume_single(conc_item, headers=TENANT))

        threads = [threading.Thread(target=worker_batch) for _ in range(4)]
        threads += [threading.Thread(target=worker_single)
                    for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        n_ok = 0
        n_replay = 0
        for st, raw in outcomes:
            body = json.loads(raw.decode())
            item = body["results"][0] if "results" in body else body
            if st == 200 and item.get("valid") is True:
                n_ok += 1
            elif item == {"valid": False, "reason": "同步回执已消费"}:
                n_replay += 1
        check("并发同键（批量+单条）仅一次成功，其余均为已消费",
              n_ok == 1 and n_replay == 7)

        # ---------------------------------------------------------- #
        # 8. 落盘失败：500 仅 {"error":"存储失败"}，全回滚可重试
        # ---------------------------------------------------------- #
        fail_item1 = make_self_item("nonce-批落盘-001")
        fail_item2 = make_self_item("nonce-批落盘-002")
        audits_before = len(consumed_audits(TENANT))
        os.unlink(store_path)
        os.mkdir(store_path)
        try:
            st, raw = consume_batch({"items": [fail_item1, fail_item2]},
                                    headers=TENANT)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and json.loads(raw.decode()) == {
                      "error": "存储失败"})
        finally:
            os.rmdir(store_path)
        check("落盘失败不记审计",
              len(consumed_audits(TENANT)) == audits_before)
        st, raw = consume_batch({"items": [fail_item1, fail_item2]},
                                headers=TENANT)
        body = json.loads(raw.decode())
        check("落盘失败回滚后同批两键均可重试成功",
              st == 200
              and all(item.get("valid") is True
                      for item in body["results"]))
        check("重试成功后补记两条审计",
              len(consumed_audits(TENANT)) == audits_before + 2)

        # ---------------------------------------------------------- #
        # 9. 重启仍判重
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = consume_batch(
            {"items": [good1, item_b, iso_item, fail_item1]},
            headers=TENANT)
        check("重启后历史键整批判重 -> 全部同步回执已消费",
              st == 200 and json.loads(raw.decode())["results"]
              == [{"valid": False, "reason": "同步回执已消费"}] * 4)
        st, raw = consume_batch({"items": [iso_item]}, headers=OTHER)
        check("重启后他租户同键重放 -> 同步回执已消费",
              st == 200 and json.loads(raw.decode())["results"] == [
                  {"valid": False, "reason": "同步回执已消费"}])

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.isdir(store_path):
            shutil.rmtree(store_path)
        elif os.path.exists(store_path):
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
