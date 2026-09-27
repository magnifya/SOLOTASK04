#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt/consume-batch 批量一次性
消费凭证状态同步回执端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_consume_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级非法（空体、非法 JSON、非对象、键集错、items 非数组/空/超限）
  均 HTTP 200 恰返 {"results":[],"reason":"请求非法"}；显式空租户头
  400 且仅 {"error":"请求非法"}；
- 合法批次逐项不短路：项结构非法 -> 请求项非法；五阶段验真失败沿用
  单条 reason 与优先级；失败项无副作用、不记审计；
- 验真通过后按租户 (verifier_did, nonce) 判重：批内前项可见；历史、
  批内或与单条并发的后到者均“状态回执已消费”；
- 成功项键序 valid、receipt_id、consumed_at；顶层仅含等长同序
  results；本批新消费每项同规格审计一次，整批原子落盘；
- 存储失败全回滚，500 仅 {"error":"存储失败"}；重启判重；租户隔离。
"""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt"
CONSUME_PATH = "/v1/trust/credential-status/receipt/consume"
BATCH_PATH = "/v1/trust/credential-status/receipt/consume-batch"
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


def _raw_post(port, path, body, extra_headers=b""):
    """用原始 socket 发请求（urllib 会丢弃空值头）。"""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(
        b"POST " + path.encode() + b" HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\nContent-Type: application/json\r\n"
        + extra_headers
        + b"Content-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n" + body
    )
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()
    status_line, rest = data.split(b"\r\n", 1)
    payload = json.loads(rest.split(b"\r\n\r\n", 1)[1].decode())
    return int(status_line.split()[1]), payload


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


def main():
    port = 9124
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
        T1 = {"X-Tenant-ID": "csrcb-a"}
        T2 = {"X-Tenant-ID": "csrcb-b"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:csrcb-issuer.example"
        cred_id = "vc_csrcb_0001"
        st, _ = post(ANCHORS_PATH,
                     {"did": issuer_did, "public_key": issuer_pub,
                      "key_version": 1, "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        def sync_status(status, updated_at, reason=None):
            body = {
                "issuer_did": issuer_did,
                "credential_id": cred_id,
                "status": status,
                "updated_at": updated_at,
                "issuer_key_version": 1,
            }
            if reason is not None:
                body["reason"] = reason
            return post(SYNC_PATH,
                        {"body": body,
                         "signature": crypto.sign(body, issuer_priv)}, T1)

        st, _ = sync_status("active", "2026-09-20T00:00:00Z")
        assert st == 201, st

        st, raw = post(DIDS_PATH,
                       {"method": "example",
                        "public_key": "credential-status-receipt-consume-batch"},
                       T1)
        assert st == 201, st
        verifier_did = raw["did"]
        verifier_pub = raw["public_key"]
        verifier_version = raw["key_version"]

        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": verifier_version,
                      "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        def get_receipt(nonce):
            st, raw = post(RECEIPT_PATH,
                           {"issuer_did": issuer_did,
                            "credential_id": cred_id,
                            "verifier_did": verifier_did,
                            "nonce": nonce}, T1)
            assert st == 200, (st, raw)
            return raw["receipt"], raw["signature"]

        def make_item(nonce):
            receipt, signature = get_receipt(nonce)
            return {"receipt": receipt, "signature": signature,
                    "nonce": nonce}

        good1 = make_item("nonce-csrcb-001")
        want_id1 = hashlib.sha256(
            crypto.canonicalize(good1["receipt"])).hexdigest()

        def consumed_audits(headers):
            st, r = get("/v1/audit?limit=200", headers=headers)
            assert st == 200
            return [e for e in r["events"]
                    if e["action"]
                    == "trust.credential.status.receipt.consumed"]

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
            payload={"items": [make_item(f"nonce-csrcb-over-{i:03d}")
                               for i in range(101)]},
        )

        # 显式空租户头：新端点 400 且仅 {"error":"请求非法"}。
        st, r = batch({"items": [good1]}, headers={"X-Tenant-ID": ""})
        check("批量端点显式空租户头 -> 400 仅 {error:请求非法}",
              st == 400 and r == {"error": "请求非法"})
        st, r = _raw_post(port, BATCH_PATH,
                          json.dumps({"items": [good1]}).encode("utf-8"),
                          b"X-Tenant-ID: \r\n")
        check("批量端点原始空租户头 -> 400 仅 {error:请求非法}",
              st == 400 and r == {"error": "请求非法"})
        # 单条 consume 同等待遇。
        st, r = _raw_post(port, CONSUME_PATH,
                          json.dumps(good1).encode("utf-8"),
                          b"X-Tenant-ID: \r\n")
        check("单条端点原始空租户头 -> 400 仅 {error:请求非法}",
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
            dict(good1, receipt=[]),
            dict(good1, signature=""),
            dict(good1, signature=123),
            dict(good1, nonce=""),
            dict(good1, nonce=1),
            dict(good1, nonce=True),
            dict(good1, nonce="中" * 257),
            good1,
        ]})
        check("混合批次 200 且 results 等长(13)同序，顶层仅 results",
              st == 200 and len(r["results"]) == 13
              and list(r.keys()) == ["results"])
        results = r["results"]
        check("前十二种非法项均为 请求项非法",
              all(it == {"valid": False, "reason": "请求项非法"}
                  for it in results[:12]))
        check("末项合法首次消费成功",
              results[12] == {
                  "valid": True, "receipt_id": want_id1,
                  "consumed_at": results[12]["consumed_at"]}
              and list(results[12].keys())
              == ["valid", "receipt_id", "consumed_at"]
              and UTC_Z_RE.fullmatch(results[12]["consumed_at"])
              is not None)

        # ---------------------------------------------------------- #
        # 3. 五阶段验真失败 + 历史重放，逐项不短路
        # ---------------------------------------------------------- #
        other_priv, _ = _keypair()
        rcpt = good1["receipt"]
        six = [
            {k: v for k, v in rcpt.items() if k != "status"},  # 回执非法
            dict(good1, nonce="其他nonce"),                     # nonce错误
            dict(good1, receipt=dict(
                rcpt, verifier_did="did:web:no-anchor.example")),  # 锚点
            dict(good1, signature="!!!"),                      # 签名格式错误
            dict(good1, signature=crypto.sign(rcpt, other_priv)),  # 签名失败
            good1,                                             # 历史重放
        ]
        st, r = batch({"items": [
            {"receipt": six[0], "signature": good1["signature"],
             "nonce": good1["nonce"]},
            six[1], six[2], six[3], six[4], six[5],
        ]})
        want_reasons = ["回执非法", "nonce错误", "锚点不可用",
                        "签名格式错误", "签名校验失败", "状态回执已消费"]
        check("六项批次 200 等长，reason 与优先级沿用单条",
              st == 200 and len(r["results"]) == 6
              and [it.get("reason") for it in r["results"]] == want_reasons
              and all(list(it.keys()) == ["valid", "reason"]
                      for it in r["results"]))
        check("验真失败与重放不记审计（仅 good1 一条）",
              len(consumed_audits(T1)) == 1)

        # ---------------------------------------------------------- #
        # 4. 批内判重：前项对后项可见；异键各自成功
        # ---------------------------------------------------------- #
        dup = make_item("nonce-csrcb-002")
        fresh = make_item("nonce-csrcb-003")
        st, r = batch({"items": [dup, dup, fresh]})
        check("批内同键首项成功、次项已消费、异键成功",
              st == 200
              and r["results"][0].get("valid") is True
              and r["results"][1] == {
                  "valid": False, "reason": "状态回执已消费"}
              and r["results"][2].get("valid") is True)
        check("批内两项新消费补记两条审计（共 3 条）",
              len(consumed_audits(T1)) == 3)
        check("审计字段与单条同规格",
              all(e["resource_type"] == "credential_status_receipt"
                  and re.fullmatch(r"[0-9a-f]{64}", e["resource_id"])
                  and e["tenant_id"] == "csrcb-a"
                  for e in consumed_audits(T1)))

        # ---------------------------------------------------------- #
        # 5. 与单条 consume 互判重
        # ---------------------------------------------------------- #
        st, r = batch({"items": [dup]})
        check("历史重放 -> 状态回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态回执已消费"}])
        s_item = make_item("nonce-csrcb-004")
        st, r = single(s_item)
        check("单条先消费成功", st == 200 and r.get("valid") is True)
        st, r = batch({"items": [s_item]})
        check("单条消费后批量同键 -> 状态回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态回执已消费"}])
        b_item = make_item("nonce-csrcb-005")
        st, r = batch({"items": [b_item]})
        check("批量先消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = single(b_item)
        check("批量消费后单条同键 -> 状态回执已消费",
              st == 200 and r == {
                  "valid": False, "reason": "状态回执已消费"})

        # ---------------------------------------------------------- #
        # 6. 租户隔离：自备验证者密钥，同键两租户各自首次成功
        # ---------------------------------------------------------- #
        my_priv, my_pub = _keypair()
        my_verifier = "did:web:csrcb-self.example"
        for headers in (T1, T2):
            st, _ = post(ANCHORS_PATH,
                         {"did": my_verifier, "public_key": my_pub,
                          "key_version": 1, "uses": ["generic", "status"]},
                         headers)
            assert st in (200, 201), st

        def self_item(nonce):
            rcpt2 = {
                "issuer_did": "did:web:any-issuer.example",
                "credential_id": "vc-any",
                "status": "active",
                "reason": None,
                "updated_at": "2026-09-20T00:00:00Z",
                "issuer_key_version": 1,
                "verifier_did": my_verifier,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return {"receipt": rcpt2,
                    "signature": crypto.sign(rcpt2, my_priv),
                    "nonce": nonce}

        iso = self_item("nonce-csrcb-iso-001")
        st, r = batch({"items": [iso]}, headers=T1)
        check("租户 A 同键首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = batch({"items": [iso]}, headers=T2)
        check("租户 B 同键互不影响首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = batch({"items": [iso]}, headers=T2)
        check("租户 B 重放 -> 状态回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态回执已消费"}])
        st, r = batch({"items": [iso]}, headers={})  # 缺省 -> default
        check("缺省租户头按 default 隔离 -> 锚点不可用",
              st == 200 and r["results"][0] == {
                  "valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 7. 并发：批量与单条同键仅一次成功
        # ---------------------------------------------------------- #
        conc = self_item("nonce-csrcb-conc-001")
        payload_conc = json.dumps({"items": [conc]}).encode("utf-8")
        single_conc = json.dumps(conc).encode("utf-8")
        barrier = threading.Barrier(8)

        def fire_batch():
            barrier.wait()
            req = urllib.request.Request(base + BATCH_PATH, data=payload_conc,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Tenant-ID", "csrcb-a")
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
            req.add_header("X-Tenant-ID", "csrcb-a")
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
            elif it == {"valid": False, "reason": "状态回执已消费"}:
                n_replay += 1
        check("并发同键（批量+单条）仅一次成功，其余已消费",
              n_ok == 1 and n_replay == 7)

        # ---------------------------------------------------------- #
        # 8. 落盘失败：500 仅 {error:存储失败}，全回滚可重试
        # ---------------------------------------------------------- #
        f1 = self_item("nonce-csrcb-disk-001")
        f2 = self_item("nonce-csrcb-disk-002")
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
        check("重启后历史键整批判重 -> 全部状态回执已消费",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态回执已消费"}] * 4)
        st, r = batch({"items": [iso]}, headers=T2)
        check("重启后他租户同键仍判重",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "状态回执已消费"}])
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
