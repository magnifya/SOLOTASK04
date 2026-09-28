#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt-sync/receipt/consume-batch
批量一次性消费凭证状态回执消费同步进度签名回执端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consume_batch_test.py
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
BATCH_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume-batch"
)
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


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
            return resp.status, json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "null")


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            return True
        except (OSError, urllib.error.HTTPError):
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


ROW_VERIFIER_DID = "did:web:cs-sync-rcb-verifier.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-sync-rcb-{index:055d}",
        "verifier_did": ROW_VERIFIER_DID,
        "nonce": f"cs-sync-rcb-nonce-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9074
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

    def post(path, payload=None, headers=None, raw=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw=raw)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        T1 = {"X-Tenant-ID": "cs-sync-rcb-a"}
        T2 = {"X-Tenant-ID": "cs-sync-rcb-b"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:cs-sync-rcb-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        # 本地验证者 DID（托管私钥，GET receipt 的签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-status-sync-receipt-rcb"},
                       T1)
        assert st == 201, (st, raw)
        verifier_did = raw["did"]
        verifier_pub = raw["public_key"]

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
                          "ndjson": ndjson}, T1)
            assert st in (200, 201), (st, r)
            return ndjson

        ndjson1 = sync_page([1, 2, 3], 0, 3)

        def get_receipt(nonce):
            qs = urllib.parse.urlencode(
                {"signer_did": signer_did, "verifier_did": verifier_did,
                 "nonce": nonce})
            st, raw = get(f"{RECEIPT_PATH}?{qs}", headers=T1)
            assert st == 200, (st, raw)
            return raw["receipt"], raw["signature"]

        receipt0, _ = get_receipt("nonce-rcb-init")
        key_version = receipt0["verifier_key_version"]
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": key_version,
                      "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        def make_item(nonce):
            receipt, signature = get_receipt(nonce)
            return {"receipt": receipt, "signature": signature,
                    "ndjson": ndjson1, "nonce": nonce}

        good1 = make_item("nonce-rcb-001")
        want_id1 = hashlib.sha256(
            crypto.canonicalize(good1["receipt"])).hexdigest()

        def consumed_audits(headers):
            st, r = get("/v1/audit?limit=200", headers=headers)
            assert st == 200
            return [e for e in r["events"]
                    if e["action"]
                    == "trust.credential.status.sync.receipt.consumed"]

        def batch(payload=None, headers=T1, raw=None):
            return post(BATCH_PATH, payload=payload, headers=headers,
                        raw=raw)

        def single(payload, headers=T1):
            return post(CONSUME_PATH, payload=payload, headers=headers)

        # ---------------------------------------------------------- #
        # 1. 请求级非法 -> 200 恰返 {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_request_invalid(name, payload=None, raw=None,
                                   headers=T1):
            st, r = batch(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 200
                  and list(r.keys()) == ["results", "reason"]
                  and r == {"results": [], "reason": "请求非法"})

        expect_request_invalid("空体 -> 请求非法", raw=b"")
        expect_request_invalid("非法 JSON -> 请求非法", raw=b"{not json")
        expect_request_invalid("非 UTF-8 -> 请求非法", raw=b"\xff\xfe")
        expect_request_invalid("非对象（数组） -> 请求非法", raw=b"[1,2]")
        expect_request_invalid("非对象（null） -> 请求非法", raw=b"null")
        expect_request_invalid("非对象（字符串） -> 请求非法", raw=b'"x"')
        expect_request_invalid("缺 items -> 请求非法", payload={})
        expect_request_invalid("多余字段 -> 请求非法",
                               payload={"items": [good1], "x": 1})
        expect_request_invalid("items 非数组 -> 请求非法",
                               payload={"items": "x"})
        expect_request_invalid("items 空数组 -> 请求非法",
                               payload={"items": []})
        expect_request_invalid(
            "items 101 项超限 -> 请求非法",
            payload={"items": [make_item(f"nonce-rcb-over-{i:03d}")
                               # 这些 receipt 均未消费也无妨：请求级非法
                               # 在逐项处理之前返回。
                               for i in range(101)]},
        )
        st, r = batch({"items": [good1]}, headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅 {error}",
              st == 400 and r == {"error": "请求非法"})

        # ---------------------------------------------------------- #
        # 2. 项结构非法 -> 请求项非法，不短路；末项合法首消成功
        # ---------------------------------------------------------- #
        st, r = batch({"items": [
            "not-object",
            [1, 2],
            {k: v for k, v in good1.items() if k != "nonce"},
            dict(good1, x=1),
            dict(good1, receipt="x"),
            dict(good1, signature=""),
            dict(good1, signature=123),
            dict(good1, ndjson=1),
            dict(good1, nonce=""),
            dict(good1, nonce="中" * 257),
            good1,
        ]})
        check("混合批次 200 且 results 等长(11)同序",
              st == 200 and len(r["results"]) == 11
              and list(r.keys()) == ["results"])
        results = r["results"]
        check("前十种非法项均为 请求项非法",
              all(it == {"valid": False, "reason": "请求项非法"}
                  for it in results[:10]))
        check("末项合法首次消费成功",
              results[10] == {
                  "valid": True, "receipt_id": want_id1,
                  "consumed_at": results[10]["consumed_at"]}
              and list(results[10].keys())
              == ["valid", "receipt_id", "consumed_at"]
              and UTC_Z_RE.fullmatch(results[10]["consumed_at"])
              is not None)

        # ---------------------------------------------------------- #
        # 3. 六阶段验真失败 + 历史重放，逐项不短路
        # ---------------------------------------------------------- #
        other_priv, _ = _keypair()
        rcpt = good1["receipt"]
        seven = [
            dict(good1, receipt={k: v for k, v in rcpt.items()
                                 if k != "nonce"}),      # 回执非法
            dict(good1, nonce="其他nonce"),              # nonce错误
            dict(good1, receipt=dict(
                rcpt, digest="0" * 64)),                 # 摘要错误
            dict(good1, receipt=dict(
                rcpt, verifier_did="did:web:no-anchor.example")),  # 锚点
            dict(good1, signature="!!!"),               # 签名格式错误
            dict(good1, signature=crypto.sign(
                rcpt, other_priv)),                     # 签名校验失败
            good1,                                      # 历史重放
        ]
        st, r = batch({"items": seven})
        want_reasons = ["回执非法", "nonce错误", "摘要错误", "锚点不可用",
                        "签名格式错误", "签名校验失败", "状态同步回执已消费"]
        check("七项批次 200 等长，reason 与优先级沿用单条",
              st == 200 and len(r["results"]) == 7
              and [it.get("reason") for it in r["results"]] == want_reasons
              and all(list(it.keys()) == ["valid", "reason"]
                      for it in r["results"]))
        check("验真失败与重放不记审计（仅 good1 一条）",
              len(consumed_audits(T1)) == 1
              and consumed_audits(T1)[0]["resource_type"]
              == "credential_status_sync_receipt"
              and consumed_audits(T1)[0]["resource_id"] == want_id1)

        # ---------------------------------------------------------- #
        # 4. 批内判重：前项对后项可见；异键各自成功
        # ---------------------------------------------------------- #
        dup = make_item("nonce-rcb-002")
        fresh = make_item("nonce-rcb-003")
        st, r = batch({"items": [dup, dup, fresh]})
        check("批内同键首项成功、次项已消费、异键成功",
              st == 200
              and r["results"][0].get("valid") is True
              and list(r["results"][0].keys())
              == ["valid", "receipt_id", "consumed_at"]
              and r["results"][1] == {
                  "valid": False, "reason": "状态同步回执已消费"}
              and r["results"][2].get("valid") is True)
        check("批内两项新消费补记两条审计（共 3 条）",
              len(consumed_audits(T1)) == 3)

        # ---------------------------------------------------------- #
        # 5. 与单条 consume 互判重
        # ---------------------------------------------------------- #
        st, r = batch({"items": [dup]})
        check("历史重放 -> 状态同步回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态同步回执已消费"}])
        s_item = make_item("nonce-rcb-004")
        st, r = single(s_item)
        check("单条先消费成功", st == 200 and r.get("valid") is True)
        st, r = batch({"items": [s_item]})
        check("单条消费后批量同键 -> 状态同步回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态同步回执已消费"}])
        b_item = make_item("nonce-rcb-005")
        st, r = batch({"items": [b_item]})
        check("批量先消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = single(b_item)
        check("批量消费后单条同键 -> 状态同步回执已消费",
              st == 200 and r == {
                  "valid": False, "reason": "状态同步回执已消费"})

        # ---------------------------------------------------------- #
        # 6. 租户隔离：自备验证者密钥，同键两租户各自首次成功
        # ---------------------------------------------------------- #
        my_priv, my_pub = _keypair()
        my_verifier = "did:web:cs-sync-rcb-self.example"
        for headers in (T1, T2):
            st, _ = post(ANCHORS_PATH,
                         {"did": my_verifier, "public_key": my_pub,
                          "key_version": 1,
                          "uses": ["generic", "status"]},
                         headers)
            assert st in (200, 201), st

        def self_item(nonce, ndjson_text=""):
            rcpt2 = {
                "signer_did": "did:web:any-signer.example",
                "next_after": 0,
                "digest": hashlib.sha256(
                    ndjson_text.encode("utf-8")).hexdigest(),
                "verifier_did": my_verifier,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return {"receipt": rcpt2,
                    "signature": crypto.sign(rcpt2, my_priv),
                    "ndjson": ndjson_text, "nonce": nonce}

        iso = self_item("nonce-rcb-iso-001")
        st, r = batch({"items": [iso]}, headers=T1)
        check("租户 A 同键首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = batch({"items": [iso]}, headers=T2)
        check("租户 B 同键互不影响首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = batch({"items": [iso]}, headers=T2)
        check("租户 B 重放 -> 状态同步回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态同步回执已消费"}])
        st, r = batch({"items": [iso]}, headers={})  # 缺省租户头 -> default
        check("缺省租户头按 default 隔离 -> 锚点不可用",
              st == 200 and r["results"][0] == {
                  "valid": False, "reason": "锚点不可用"})
        check("他租户审计互不污染",
              len([e for e in consumed_audits(T2)]) == 1)

        # ---------------------------------------------------------- #
        # 7. 并发：批量与单条同键仅一次成功
        # ---------------------------------------------------------- #
        conc = self_item("nonce-rcb-conc-001")
        payload_conc = json.dumps({"items": [conc]}).encode("utf-8")
        single_conc = json.dumps(conc).encode("utf-8")
        barrier = threading.Barrier(8)

        def fire_batch():
            barrier.wait()
            req = urllib.request.Request(base + BATCH_PATH, data=payload_conc,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Tenant-ID", "cs-sync-rcb-a")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        def fire_single():
            barrier.wait()
            req = urllib.request.Request(base + CONSUME_PATH,
                                         data=single_conc, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Tenant-ID", "cs-sync-rcb-a")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(
                lambda i: fire_batch() if i < 4 else fire_single(),
                range(8)))
        n_ok = n_replay = 0
        for st, r in responses:
            it = r["results"][0] if "results" in r else r
            if st == 200 and it.get("valid") is True:
                n_ok += 1
            elif it == {"valid": False, "reason": "状态同步回执已消费"}:
                n_replay += 1
        check("并发同键（批量+单条）仅一次成功，其余已消费",
              n_ok == 1 and n_replay == 7)

        # ---------------------------------------------------------- #
        # 8. 落盘失败：500 仅 {error:存储失败}，全回滚可重试
        # ---------------------------------------------------------- #
        f1 = self_item("nonce-rcb-disk-001")
        f2 = self_item("nonce-rcb-disk-002")
        audits_before = len(consumed_audits(T1))
        os.unlink(store_path)
        os.mkdir(store_path)
        try:
            st, r = batch({"items": [f1, f2]})
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store_path)
        check("落盘失败不记审计", len(consumed_audits(T1)) == audits_before)
        st, r = batch({"items": [f1, f2]})
        check("回滚后同批两键均可重试成功",
              st == 200
              and all(it.get("valid") is True for it in r["results"]))
        check("重试成功补记两条审计",
              len(consumed_audits(T1)) == audits_before + 2)

        # ---------------------------------------------------------- #
        # 9. 重启判重 + 租户隔离保持
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, r = batch({"items": [good1, dup, iso, f1]}, headers=T1)
        check("重启后历史键整批判重 -> 全部状态同步回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态同步回执已消费"}] * 4)
        st, r = batch({"items": [iso]}, headers=T2)
        check("重启后他租户同键仍判重",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态同步回执已消费"}])
        st, r = batch({"items": [iso]}, headers={})
        check("重启后 default 租户未被污染 -> 锚点不可用",
              st == 200 and r["results"][0] == {
                  "valid": False, "reason": "锚点不可用"})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.isdir(store_path):
            shutil.rmtree(store_path)
        elif os.path.exists(store_path):
            os.unlink(store_path)

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
