#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt-sync/receipt/consume-batch
批量一次性消费凭证状态回执消费同步进度签名回执端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consume_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级非法（空体、非法 JSON、非 UTF-8、非对象、键集错、items
  非数组/空/101 项超限）均 HTTP 200，按键序恰返
  {"results":[],"reason":"请求非法"}，且无副作用；显式空租户头 400；
- 项结构非法逐项不短路返 {"valid":false,"reason":"请求项非法"}，
  同批合法项仍首消成功；
- 六阶段验真失败（回执非法 -> nonce错误 -> 摘要错误 -> 锚点不可用
  -> 签名格式错误 -> 签名校验失败，锚点用途 status）与历史重放逐项
  返固定 reason，失败与重放不记审计；
- 批内 (verifier_did,nonce) 判重前项可见（含同键内容不同），异键
  各自成功，成功项键序 valid、receipt_id、consumed_at；
- 与单条 consume 互判重；租户隔离；缺省租户头 default；
- 并发（批量+单条同键）仅一次成功；
- 落盘失败 500 仅 {"error":"存储失败"}、全批回滚可重试、不记审计；
- 重启判重、租户隔离保持；不污染普通凭证状态回执消费审计空间。
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

CONSUME_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume"
)
BATCH_PATH = (
    "/v1/trust/credential-status/receipt-sync/receipt/consume-batch"
)
ANCHORS_PATH = "/v1/trust/anchors"

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REPLAY = {"valid": False, "reason": "状态同步回执已消费"}
ITEM_INVALID = {"valid": False, "reason": "请求项非法"}
REQUEST_INVALID = {"results": [], "reason": "请求非法"}

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
    port = 9122
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
        T1 = {"X-Tenant-ID": "cssrccb-a"}
        T2 = {"X-Tenant-ID": "cssrccb-b"}

        # 自备验证者密钥：直接构造同步进度回执（验真只查验证者锚点）。
        my_priv, my_pub = _keypair()
        my_verifier = "did:web:cssrccb-self.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": my_verifier, "public_key": my_pub,
                      "key_version": 1, "uses": ["generic", "status"]},
                     T1)
        assert st in (200, 201), st

        def self_item(nonce, ndjson=None, verifier=my_verifier,
                      priv=my_priv, version=1):
            if ndjson is None:
                ndjson = f'{{"n":"{nonce}"}}\n'
            receipt = {
                "signer_did": "did:web:cssrccb-signer.example",
                "next_after": 1,
                "digest": hashlib.sha256(
                    ndjson.encode("utf-8")).hexdigest(),
                "verifier_did": verifier,
                "verifier_key_version": version,
                "nonce": nonce,
            }
            return {
                "receipt": receipt,
                "signature": crypto.sign(receipt, priv),
                "ndjson": ndjson,
                "nonce": nonce,
            }

        def want_id(item):
            return hashlib.sha256(
                crypto.canonicalize(item["receipt"])).hexdigest()

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

        good1 = self_item("nonce-cssrccb-001")
        want_id1 = want_id(good1)

        # ---------------------------------------------------------- #
        # 1. 请求级非法 -> 200 恰返 {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_request_invalid(name, payload=None, raw=None,
                                   headers=T1):
            st, r = batch(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 200
                  and list(r.keys()) == ["results", "reason"]
                  and r == REQUEST_INVALID)

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
            payload={"items": [self_item(f"nonce-cssrccb-over-{i:03d}")
                               for i in range(101)]},
        )
        # 请求级非法无任何副作用（无消费、无审计）。
        check("请求级非法不记审计", consumed_audits(T1) == [])

        # 显式空租户头 -> 400 且仅固定文案（原始 socket）。
        st, r = _raw_post(port, BATCH_PATH,
                          json.dumps({"items": [good1]}).encode("utf-8"),
                          b"X-Tenant-ID: \r\n")
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and r == {"error": "请求非法"})

        # ---------------------------------------------------------- #
        # 2. 项结构非法 -> 请求项非法，不短路；末项合法首消成功
        # ---------------------------------------------------------- #
        st, r = batch({"items": [
            "not-object",
            [1, 2],
            {k: v for k, v in good1.items() if k != "nonce"},
            {k: v for k, v in good1.items() if k != "ndjson"},
            dict(good1, x=1),
            dict(good1, receipt="x"),
            dict(good1, signature=""),
            dict(good1, signature=123),
            dict(good1, ndjson=1),
            dict(good1, nonce=""),
            dict(good1, nonce="中" * 257),
            good1,
        ]})
        check("混合批次 200 且 results 等长(12)同序、顶层仅 results",
              st == 200 and len(r["results"]) == 12
              and list(r.keys()) == ["results"])
        results = r["results"]
        check("前十一种非法项均为 请求项非法",
              all(it == ITEM_INVALID for it in results[:11]))
        check("末项合法首次消费成功",
              results[11] == {
                  "valid": True, "receipt_id": want_id1,
                  "consumed_at": results[11]["consumed_at"]}
              and list(results[11].keys())
              == ["valid", "receipt_id", "consumed_at"]
              and UTC_Z_RE.fullmatch(results[11]["consumed_at"])
              is not None)

        # ---------------------------------------------------------- #
        # 3. 六阶段验真失败 + 历史重放，逐项不短路
        # ---------------------------------------------------------- #
        other_priv, _ = _keypair()
        rcpt = good1["receipt"]
        disordered = {
            "nonce": rcpt["nonce"],
            "signer_did": rcpt["signer_did"],
            "next_after": rcpt["next_after"],
            "digest": rcpt["digest"],
            "verifier_did": rcpt["verifier_did"],
            "verifier_key_version": rcpt["verifier_key_version"],
        }
        seven = [
            dict(good1, receipt=disordered),                    # 回执非法
            dict(good1, nonce="其他nonce"),                    # nonce错误
            dict(good1, receipt=dict(rcpt, digest="0" * 64)),  # 摘要错误
            dict(good1, receipt=dict(
                rcpt, verifier_did="did:web:no-anchor.example")),  # 锚点
            dict(good1, signature="!!!"),                      # 签名格式错误
            dict(good1, signature=crypto.sign(rcpt, other_priv)),  # 签名失败
            good1,                                             # 历史重放
        ]
        st, r = batch({"items": seven})
        want_reasons = ["回执非法", "nonce错误", "摘要错误", "锚点不可用",
                        "签名格式错误", "签名校验失败", "状态同步回执已消费"]
        check("七项批次 200 等长，reason 与六阶段优先级沿用单条",
              st == 200 and len(r["results"]) == 7
              and [it.get("reason") for it in r["results"]] == want_reasons
              and all(list(it.keys()) == ["valid", "reason"]
                      for it in r["results"]))
        audits = consumed_audits(T1)
        check("验真失败与重放不记审计（仅 good1 一条）",
              len(audits) == 1
              and audits[0]["resource_type"]
              == "credential_status_sync_receipt"
              and audits[0]["resource_id"] == want_id1
              and audits[0]["tenant_id"] == "cssrccb-a")

        # ---------------------------------------------------------- #
        # 4. 批内判重：前项对后项可见（含同键内容不同）；异键成功
        # ---------------------------------------------------------- #
        dup = self_item("nonce-cssrccb-002")
        dup_other_content = self_item(
            "nonce-cssrccb-002", ndjson='{"different":true}\n')
        fresh = self_item("nonce-cssrccb-003")
        st, r = batch({"items": [dup, dup_other_content, fresh]})
        check("批内同键首项成功、次项（内容不同）已消费、异键成功",
              st == 200
              and list(r["results"][0].keys())
              == ["valid", "receipt_id", "consumed_at"]
              and r["results"][0].get("valid") is True
              and r["results"][0]["receipt_id"] == want_id(dup)
              and r["results"][1] == REPLAY
              and r["results"][2].get("valid") is True)
        check("批内两项新消费补记两条审计（共 3 条）",
              len(consumed_audits(T1)) == 3)

        # ---------------------------------------------------------- #
        # 5. 与单条 consume 互判重
        # ---------------------------------------------------------- #
        st, r = batch({"items": [dup]})
        check("批量历史重放 -> 状态同步回执已消费",
              st == 200 and r["results"] == [REPLAY])
        s_item = self_item("nonce-cssrccb-004")
        st, r = single(s_item)
        check("单条先消费成功",
              st == 200 and r.get("valid") is True
              and r.get("receipt_id") == want_id(s_item))
        st, r = batch({"items": [s_item]})
        check("单条消费后批量同键 -> 状态同步回执已消费",
              st == 200 and r["results"] == [REPLAY])
        b_item = self_item("nonce-cssrccb-005")
        st, r = batch({"items": [b_item]})
        check("批量先消费成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = single(b_item)
        check("批量消费后单条同键 -> 状态同步回执已消费",
              st == 200 and r == REPLAY)

        # 不向普通凭证状态回执消费审计空间写事件。
        st, r = get("/v1/audit?limit=200", headers=T1)
        check("不写普通凭证状态回执消费审计",
              [e for e in r["events"]
               if e["action"]
               == "trust.credential.status.receipt.consumed"] == [])

        # ---------------------------------------------------------- #
        # 6. 租户隔离：同键两租户各自首次成功；default 隔离
        # ---------------------------------------------------------- #
        st, _ = post(ANCHORS_PATH,
                     {"did": my_verifier, "public_key": my_pub,
                      "key_version": 1, "uses": ["generic", "status"]},
                     T2)
        assert st in (200, 201), st

        iso = self_item("nonce-cssrccb-iso-001")
        st, r = batch({"items": [iso]}, headers=T1)
        check("租户 A 同键首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = batch({"items": [iso]}, headers=T2)
        check("租户 B 同键互不影响首次成功",
              st == 200 and r["results"][0].get("valid") is True)
        st, r = batch({"items": [iso]}, headers=T2)
        check("租户 B 重放 -> 状态同步回执已消费",
              st == 200 and r["results"] == [REPLAY])
        st, r = batch({"items": [iso]}, headers={})
        check("缺省租户头按 default 隔离 -> 锚点不可用",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "锚点不可用"}])
        check("他租户审计互不污染（T2 仅 1 条）",
              len(consumed_audits(T2)) == 1)

        # ---------------------------------------------------------- #
        # 7. 并发：批量与单条同键仅一次成功
        # ---------------------------------------------------------- #
        conc = self_item("nonce-cssrccb-conc-001")
        payload_conc = json.dumps({"items": [conc]}).encode("utf-8")
        single_conc = json.dumps(conc).encode("utf-8")
        barrier = threading.Barrier(8)

        def fire_batch():
            barrier.wait()
            req = urllib.request.Request(base + BATCH_PATH, data=payload_conc,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Tenant-ID", "cssrccb-a")
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
            req.add_header("X-Tenant-ID", "cssrccb-a")
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
            elif it == REPLAY:
                n_replay += 1
        check("并发同键（批量+单条）仅一次成功，其余已消费",
              n_ok == 1 and n_replay == 7)

        # ---------------------------------------------------------- #
        # 8. 落盘失败：500 仅 {error:存储失败}，全回滚可重试
        # ---------------------------------------------------------- #
        f1 = self_item("nonce-cssrccb-disk-001")
        f2 = self_item("nonce-cssrccb-disk-002")
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
              and [it.get("receipt_id") for it in r["results"]]
              == [want_id(f1), want_id(f2)]
              and all(it.get("valid") is True for it in r["results"]))
        check("重试成功补记两条审计",
              len(consumed_audits(T1)) == audits_before + 2)
        st, r = single(f1)
        check("回滚重试后单条同键判重", st == 200 and r == REPLAY)

        # ---------------------------------------------------------- #
        # 9. 重启判重 + 租户隔离保持
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, r = batch({"items": [good1, dup, fresh, f1, iso]}, headers=T1)
        check("重启后历史键整批判重 -> 全部状态同步回执已消费",
              st == 200 and r["results"] == [REPLAY] * 5)
        st, r = batch({"items": [iso]}, headers=T2)
        check("重启后他租户同键仍判重",
              st == 200 and r["results"] == [REPLAY])
        st, r = batch({"items": [iso]}, headers={})
        check("重启后 default 租户未被污染 -> 锚点不可用",
              st == 200 and r["results"] == [
                  {"valid": False, "reason": "锚点不可用"}])
        # 重启后未消费 nonce 仍可首消，键序与取值沿用单条。
        g = self_item("nonce-cssrccb-after-restart")
        st, r = batch({"items": [g]})
        check("重启后新 nonce 可首次消费",
              st == 200 and r["results"][0] == {
                  "valid": True, "receipt_id": want_id(g),
                  "consumed_at": r["results"][0]["consumed_at"]}
              and list(r["results"][0].keys())
              == ["valid", "receipt_id", "consumed_at"])

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
