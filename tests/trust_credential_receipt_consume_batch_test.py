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
BATCH_PATH = "/v1/trust/credentials/receipt/consume-batch"
SINGLE_PATH = "/v1/trust/credentials/receipt/consume"


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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{BATCH_PATH}", payload,
                     headers=headers, raw=raw)

    def single(payload, headers=None):
        return _http("POST", f"{base}{SINGLE_PATH}", payload, headers=headers)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.credential.receipt.consumed"]

    try:
        T1 = {"X-Tenant-ID": "rb-a"}
        T2 = {"X-Tenant-ID": "rb-b"}

        # ---- 准备：验证者锚点（回执验真只查验证者锚点，不重验凭证签名）----
        verifier_priv, verifier_pub = gen_keypair()
        verifier_did = "did:web:verifier-batch.example"
        issuer_priv, _ = gen_keypair()
        issuer_did = "did:web:issuer-batch.example"
        for headers in (T1, T2):
            st, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": verifier_did, "public_key": verifier_pub,
                 "key_version": 1},
                headers=headers,
            )
            check(f"注册验证者锚点（{headers['X-Tenant-ID']}）-> 201",
                  st == 201)
        other_priv, _ = gen_keypair()

        def make_item(nonce, credential_id="vc_b_0001", sign_priv=None):
            """构造一项合法消费请求；sign_priv 非空时用他钥签回执。"""
            body = {
                "credential_id": credential_id,
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin"},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
            sig = crypto.sign(body, issuer_priv)
            receipt = {
                "credential_id": credential_id,
                "issuer_did": issuer_did,
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": body, "signature": sig})
                ).hexdigest(),
                "verifier_did": verifier_did,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            receipt_signature = crypto.sign(
                receipt, sign_priv or verifier_priv
            )
            return {
                "receipt": receipt,
                "receipt_signature": receipt_signature,
                "body": body,
                "signature": sig,
                "nonce": nonce,
            }

        def request_invalid(name, payload=None, raw=None, headers=T1):
            st, r = batch(payload=payload, raw=raw, headers=headers)
            check(name,
                  st == 200 and list(r.keys()) == ["results", "reason"]
                  and r["results"] == []
                  and isinstance(r["reason"], str)
                  and r["reason"].startswith("请求") and r["reason"])

        # 1. 请求级非法 -> HTTP 200 恰返 {"results":[],"reason":"请求..."}
        request_invalid("空请求体", raw=b"")
        request_invalid("非法 JSON", raw=b"not-json")
        request_invalid("非对象（数组）", raw=b"[1,2]")
        request_invalid("缺 items", {})
        request_invalid("多余字段", {"items": [], "x": 1})
        request_invalid("items 非数组", {"items": {}})
        request_invalid("items 空数组", {"items": []})
        request_invalid("items 101 项",
                        {"items": [make_item(f"n-{i}") for i in range(101)]})
        # 请求级非法不消费、不审计
        check("请求级非法不记审计", consumed_audits(T1) == [])

        # 显式空租户头在解析请求体前即 400
        st, r = batch({"items": [make_item("n-empty-header")]},
                      headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400 仅 {error}",
              st == 400 and set(r.keys()) == {"error"} and r["error"])

        # 2. 项结构非法 -> {"valid":false,"reason":"请求项非法"}
        good = make_item("n-good-template")

        def item_invalid(name, bad_item):
            st, r = batch({"items": [bad_item]}, headers=T1)
            check(name,
                  st == 200 and list(r.keys()) == ["results"]
                  and len(r["results"]) == 1
                  and r["results"][0]
                  == {"valid": False, "reason": "请求项非法"})

        item_invalid("项非对象", ["not-object"])
        for field in ("receipt", "receipt_signature", "body",
                      "signature", "nonce"):
            item_invalid(f"项缺 {field}",
                         {k: v for k, v in good.items() if k != field})
        item_invalid("项多余字段", dict(good, x=1))
        item_invalid("receipt 非对象", dict(good, receipt="x"))
        item_invalid("body 非对象", dict(good, body=[]))
        item_invalid("receipt_signature 空串",
                     dict(good, receipt_signature=""))
        item_invalid("signature 非字符串", dict(good, signature=1))
        item_invalid("nonce 空串", dict(good, nonce=""))
        item_invalid("nonce 257 码点", dict(good, nonce="中" * 257))
        check("项非法不记审计", consumed_audits(T1) == [])

        # 3. 七阶段验真失败逐项返固定原因，失败不短路、不消费
        def stage_item(nonce, kind):
            item = make_item(nonce)
            if kind == "回执非法":
                item["receipt"] = {
                    k: v for k, v in item["receipt"].items()
                    if k != "nonce"
                }
            elif kind == "nonce错误":
                item["nonce"] = nonce + "-别的"
            elif kind == "绑定错误":
                item["body"] = dict(item["body"], credential_id="vc_other")
            elif kind == "摘要错误":
                item["body"] = dict(
                    item["body"], claims={"role": "user"}
                )
            elif kind == "签名格式错误":
                item["receipt_signature"] = "!!!bad!!!"
            elif kind == "签名校验失败":
                item["receipt_signature"] = crypto.sign(
                    item["receipt"], other_priv
                )
            return item

        stages = ["回执非法", "nonce错误", "绑定错误", "摘要错误",
                  "签名格式错误", "签名校验失败"]
        mixed_items = [stage_item(f"n-stage-{i}", kind)
                       for i, kind in enumerate(stages)]
        st, r = batch({"items": mixed_items}, headers=T1)
        check("七阶段失败批 -> 200 等长同序",
              st == 200 and len(r["results"]) == 6)
        for got, want in zip(r["results"], stages):
            check(f"  原因: {want}",
                  got == {"valid": False, "reason": want})
        check("验真失败项不记审计", consumed_audits(T1) == [])

        # 缺省租户头按 default 隔离（default 无锚点）-> 逐项锚点不可用
        st, r = batch({"items": [make_item("n-default-tenant")]})
        check("缺省租户头 -> 200 逐项锚点不可用",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "锚点不可用"})

        # 4. 混合批：项非法 + 验真失败 + 两个新键 + 批内重放，顺序保持
        n1, n2, n3 = "n-mix-1", "n-mix-2", "n-mix-3"
        items = [
            ["not-object"],                              # 0 请求项非法
            stage_item("unused", "nonce错误"),           # 1 nonce错误
            make_item(n1, "vc_mix_1"),                   # 2 首次成功
            make_item(n2, "vc_mix_2"),                   # 3 首次成功
            make_item(n1, "vc_mix_other"),               # 4 批内同键重放
            make_item(n3),                               # 5 首次成功
        ]
        audits_before = len(consumed_audits(T1))
        st, r = batch({"items": items}, headers=T1)
        check("混合批 -> 200 results 等长",
              st == 200 and len(r["results"]) == 6)
        res = r["results"]
        check("  0 请求项非法",
              res[0] == {"valid": False, "reason": "请求项非法"})
        check("  1 nonce错误",
              res[1] == {"valid": False, "reason": "nonce错误"})
        check("  2/3/5 首次成功键序 valid,receipt_id,consumed_at",
              all(list(res[i].keys())
                  == ["valid", "receipt_id", "consumed_at"]
                  and res[i]["valid"] is True for i in (2, 3, 5)))
        check("  成功项 receipt_id 为 receipt 规范化 SHA-256 hex",
              all(res[i]["receipt_id"] == hashlib.sha256(
                  crypto.canonicalize(items[i]["receipt"])).hexdigest()
                  for i in (2, 3, 5)))
        check("  成功项 consumed_at 为 UTC 秒精度 Z",
              all(isinstance(res[i]["consumed_at"], str)
                  and UTC_Z_RE.fullmatch(res[i]["consumed_at"])
                  for i in (2, 3, 5)))
        check("  4 批内同键重放 -> 回执已消费",
              res[4] == {"valid": False, "reason": "回执已消费"})
        check("三个新消费记三条审计",
              len(consumed_audits(T1)) == audits_before + 3)
        check("审计 resource_type/id 正确",
              all(e["resource_type"] == "credential_receipt"
                  for e in consumed_audits(T1)[-3:])
              and {e["resource_id"] for e in consumed_audits(T1)[-3:]}
              == {res[i]["receipt_id"] for i in (2, 3, 5)})

        # 5. 历史重放：批内项对上一批已消费键 -> 回执已消费，不记审计
        audits_before = len(consumed_audits(T1))
        st, r = batch(
            {"items": [make_item(n1), make_item(n2),
                       make_item("n-mix-fresh", "vc_mix_fresh")]},
            headers=T1,
        )
        check("历史重放批 -> 200",
              st == 200 and len(r["results"]) == 3)
        check("  历史键两项均已消费",
              r["results"][0] == {"valid": False, "reason": "回执已消费"}
              and r["results"][1]
              == {"valid": False, "reason": "回执已消费"})
        check("  新键首次成功", r["results"][2]["valid"] is True)
        check("重放不记审计、新键记一条",
              len(consumed_audits(T1)) == audits_before + 1)

        # 6. 与单项 consume 互通：单项先消费，批量只见重放；反之亦然
        cross_nonce_a = "n-cross-a"
        cross_nonce_b = "n-cross-b"
        st, r = single(make_item(cross_nonce_a), headers=T1)
        check("单项先消费 -> 成功",
              st == 200 and r.get("valid") is True)
        st, r = batch({"items": [make_item(cross_nonce_a)]}, headers=T1)
        check("批量见单项历史 -> 回执已消费",
              st == 200 and r["results"][0]
              == {"valid": False, "reason": "回执已消费"})
        st, r = batch({"items": [make_item(cross_nonce_b)]}, headers=T1)
        check("批量先消费 -> 成功",
              st == 200 and r["results"][0]["valid"] is True)
        st, r = single(make_item(cross_nonce_b), headers=T1)
        check("单项见批量历史 -> 回执已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})

        # 7. 租户隔离：同键在 T1/T2 各自首次成功
        iso_nonce = "n-iso-1"
        st, r1 = batch({"items": [make_item(iso_nonce)]}, headers=T1)
        st, r2 = batch({"items": [make_item(iso_nonce)]}, headers=T2)
        check("租户隔离：两租户同键各自首次成功",
              r1["results"][0]["valid"] is True
              and r2["results"][0]["valid"] is True)
        st, r2 = batch({"items": [make_item(iso_nonce)]}, headers=T2)
        check("租户隔离：T2 重放不受 T1 影响",
              r2["results"][0]
              == {"valid": False, "reason": "回执已消费"})

        # 8. 并发：单项与批量混合打同一键，仅一次成功
        conc_nonce = "n-conc-1"
        conc_item = make_item(conc_nonce)
        outcomes = []
        lock = threading.Lock()

        def run_single():
            st, r = single(conc_item, headers=T1)
            with lock:
                outcomes.append(("single", st, r))

        def run_batch():
            st, r = batch({"items": [conc_item]}, headers=T1)
            with lock:
                outcomes.append(("batch", st, r))

        threads = (
            [threading.Thread(target=run_single) for _ in range(4)]
            + [threading.Thread(target=run_batch) for _ in range(4)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        def is_success(kind, st, r):
            if kind == "single":
                return st == 200 and r.get("valid") is True
            return (st == 200 and len(r.get("results", [])) == 1
                    and r["results"][0].get("valid") is True)

        def is_replay(kind, st, r):
            want = {"valid": False, "reason": "回执已消费"}
            if kind == "single":
                return st == 200 and r == want
            return st == 200 and r.get("results") == [want]

        n_ok = sum(1 for k, st, r in outcomes if is_success(k, st, r))
        n_replay = sum(1 for k, st, r in outcomes if is_replay(k, st, r))
        check("并发单项+批量同键仅一次成功，其余均已消费",
              n_ok == 1 and n_replay == 7 and len(outcomes) == 8)
        check("并发同键仅一条审计",
              len([e for e in consumed_audits(T1)
                   if e["resource_id"]
                   == hashlib.sha256(
                       crypto.canonicalize(conc_item["receipt"])
                   ).hexdigest()]) == 1)

        # 9. 落盘失败：500 仅 {"error":"存储失败"}，整批回滚可重试
        fail_nonces = ["n-fail-1", "n-fail-2"]
        fail_items = [make_item(n, f"vc_fail_{i}")
                      for i, n in enumerate(fail_nonces)]
        audits_before = len(consumed_audits(T1))
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = batch({"items": fail_items}, headers=T1)
            check("落盘失败 -> 500 仅 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败整批不记审计",
              len(consumed_audits(T1)) == audits_before)
        st, r = batch({"items": fail_items}, headers=T1)
        check("回滚后整批重试均成功",
              st == 200
              and all(x.get("valid") is True for x in r["results"]))
        check("重试成功记两条审计",
              len(consumed_audits(T1)) == audits_before + 2)

        # 10. 重启后判重保持（批量/单项双向）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = batch({"items": [make_item(n1), make_item(iso_nonce)]
                       + fail_items}, headers=T1)
        check("重启后批量历史键全部已消费",
              st == 200 and len(r["results"]) == 4
              and all(x == {"valid": False, "reason": "回执已消费"}
                      for x in r["results"]))
        st, r = single(make_item(n2), headers=T1)
        check("重启后单项对批量历史键已消费",
              st == 200 and r == {"valid": False, "reason": "回执已消费"})
        st, r = batch({"items": [make_item(iso_nonce)]}, headers=T2)
        check("重启后租户隔离判重保持",
              r["results"][0]
              == {"valid": False, "reason": "回执已消费"})
        st, r = batch({"items": [make_item("n-after-restart")]},
                      headers=T1)
        check("重启后新键仍可消费",
              st == 200 and r["results"][0]["valid"] is True)

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.isdir(store):
            shutil.rmtree(store)
        elif os.path.exists(store):
            os.unlink(store)

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
