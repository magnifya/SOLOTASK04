#!/usr/bin/env python3
"""POST /v1/trust/presentation-sync/receipt/verify-batch 批量验真演示消费
同步进度签名回执端到端测试。

直接运行：python3 tests/trust_presentation_sync_receipt_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求体须恰为 {"items":[项...]}（1–100 项）；空体、非法 JSON、非对象、
  键集错误、items 非数组/空/超限均 HTTP 200 且按键序恰返
  {"results":[],"reason":"请求非法"}；
- 显式空 X-Tenant-ID 400，缺省 default、按租户隔离；
- 合法批次顶层 HTTP 200 且仅含 results，等长同序、逐项不短路；成功项仅
  {"valid":true}，失败项键序 valid、reason；
- 项须恰含 receipt（对象）、signature（非空串）、ndjson（串）、nonce
  （1–256 码点非空串），否则 {"valid":false,"reason":"请求项非法"}；
- 合法项复用单条验真顺序：回执非法（含 receipt 内 nonce 非法）->
  nonce错误 -> 摘要错误 -> 锚点不可用 -> 签名格式错误 -> 签名校验失败；
- 批初原子快照：并发吊销/用途收紧下同批不观察混合状态；
- 纯只读：不写状态、游标或审计；重启稳定；单条入口行为一致。
"""

import hashlib
import json
import os
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

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/presentation-sync"
RECEIPT_PATH = "/v1/trust/presentation-sync/receipt"
VERIFY_PATH = "/v1/trust/presentation-sync/receipt/verify"
BATCH_PATH = "/v1/trust/presentation-sync/receipt/verify-batch"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

REASONS = {
    "回执非法", "nonce错误", "摘要错误", "锚点不可用", "签名格式错误",
    "签名校验失败", "请求项非法",
}

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


ISSUER_DID = "did:web:pres-sync-receipt-vfy-batch-issuer.example"


def make_row(cursor, index):
    return {
        "cursor": cursor,
        "consumption_id": f"cons-{index:060d}",
        "issuer_did": ISSUER_DID,
        "presentation_id": f"vp_演示_{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9097
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
        DST = {"X-Tenant-ID": "batch-verify-tenant"}
        OTHER = {"X-Tenant-ID": "batch-verify-other-tenant"}

        signer_priv, signer_pub = crypto.generate_private_key_pem(), None
        signer_pub = crypto.public_key_pem_from_private(signer_priv)
        signer_did = "did:web:pres-sync-receipt-vfy-batch-signer.example"
        st, raw = post(ANCHORS_PATH,
                       {"did": signer_did, "public_key": signer_pub,
                        "key_version": 1}, DST)
        assert st in (200, 201), (st, raw)

        # 本地验证者 DID（托管私钥，GET receipt 的签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "presentation-sync-receipt-vfy-batch"},
                       DST)
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

        rows = [make_row(c, i + 1) for i, c in enumerate([3, 7, 11])]
        ndjson = to_ndjson(rows)
        st, r = post(SYNC_PATH,
                     {"manifest": signed_manifest(11, 0, ndjson),
                      "ndjson": ndjson}, DST)
        assert st == 201, (st, r)

        # 取回执。
        nonce = "nonce-批一"
        qs = urllib.parse.urlencode(
            {"signer_did": signer_did, "verifier_did": verifier_did,
             "nonce": nonce})
        st, raw = get(f"{RECEIPT_PATH}?{qs}", headers=DST)
        assert st == 200, raw
        issued = json.loads(raw)
        receipt = issued["receipt"]
        signature = issued["signature"]
        key_version = receipt["verifier_key_version"]

        # 为验证者 DID 登记含 vp 用途的 active 信任锚点。
        st, raw = post(ANCHORS_PATH,
                       {"did": verifier_did, "public_key": verifier_pub,
                        "key_version": key_version,
                        "uses": ["generic", "vp"]}, DST)
        assert st in (200, 201), (st, raw)

        def batch(payload=None, headers=DST, raw_body=None):
            st, raw = post(BATCH_PATH, payload=payload, headers=headers,
                           raw_body=raw_body)
            try:
                return st, json.loads(raw.decode() or "null")
            except ValueError:
                return st, None

        good = {"receipt": receipt, "signature": signature,
                "ndjson": ndjson, "nonce": nonce}

        # ---------------------------------------------------------- #
        # 1. 请求级非法：HTTP 200 + {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_bad_request(name, payload=None, raw_body=None,
                               headers=DST):
            st, body = batch(payload, headers=headers, raw_body=raw_body)
            check(f"请求非法 200 同形: {name}",
                  st == 200 and isinstance(body, dict)
                  and list(body.keys()) == ["results", "reason"]
                  and body == {"results": [], "reason": "请求非法"})

        expect_bad_request("空体", raw_body=b"")
        expect_bad_request("非法 JSON", raw_body=b"{not json")
        expect_bad_request("非 UTF-8", raw_body=b"\xff\xfe")
        expect_bad_request("非对象(数组)", raw_body=b"[1]")
        expect_bad_request("非对象(字符串)", raw_body=b'"x"')
        expect_bad_request("非对象(null)", raw_body=b"null")
        expect_bad_request("缺 items", payload={})
        expect_bad_request("多余键", payload={"items": [good], "x": 1})
        expect_bad_request("items 非数组(对象)", payload={"items": {}})
        expect_bad_request("items 非数组(字符串)", payload={"items": "x"})
        expect_bad_request("items 空数组", payload={"items": []})
        expect_bad_request("items 超限(101)",
                           payload={"items": [good] * 101})

        # 显式空租户头 400；缺省 default 隔离（default 无此锚点）。
        st, _ = post(BATCH_PATH, {"items": [good]},
                     headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)
        st, body = batch({"items": [good]}, headers=None)
        check("缺省租户头按 default 隔离",
              st == 200 and list(body.keys()) == ["results"]
              and body["results"] == [
                  {"valid": False, "reason": "锚点不可用"}])
        st, body = batch({"items": [good]}, headers=OTHER)
        check("跨租户锚点不可用",
              body["results"] == [{"valid": False, "reason": "锚点不可用"}])

        # ---------------------------------------------------------- #
        # 2. 项级非法：{"valid":false,"reason":"请求项非法"} 不短路
        # ---------------------------------------------------------- #
        bad_items = [
            1, "x", None, [],  # 非对象
            {},  # 键集错
            {k: v for k, v in good.items() if k != "ndjson"},  # 缺键
            dict(good, extra=1),  # 多键
            dict(good, receipt="x"),  # receipt 非对象
            dict(good, signature=""),  # signature 空串
            dict(good, signature=1),  # signature 非串
            dict(good, ndjson=1),  # ndjson 非串
            dict(good, nonce=""),  # nonce 空
            dict(good, nonce=1),  # nonce 非串
            dict(good, nonce="n" * 257),  # nonce 超 256 码点
        ]
        st, body = batch({"items": [good] + bad_items + [good]})
        check("项级非法 200 且仅含 results",
              st == 200 and list(body.keys()) == ["results"])
        expected = ([{"valid": True}]
                    + [{"valid": False, "reason": "请求项非法"}]
                    * len(bad_items)
                    + [{"valid": True}])
        check("项级非法等长同序不短路", body["results"] == expected)
        check("项级失败键序 valid,reason",
              all(list(r.keys()) == ["valid", "reason"]
                  for r in body["results"] if not r["valid"]))

        # nonce 边界：1 与 256 码点合法（nonce 须与 receipt 内一致，
        # 故此处进入 nonce错误 而非 请求项非法）。
        st, body = batch({"items": [dict(good, nonce="n" * 256)]})
        check("nonce 256 码点合法进入比对",
              body["results"] == [{"valid": False, "reason": "nonce错误"}])

        # ---------------------------------------------------------- #
        # 3. 合法项：复用单条顺序的六类原因
        # ---------------------------------------------------------- #
        # 回执非法：键序错。
        bad_order = dict(good)
        bad_order["receipt"] = {
            "next_after": receipt["next_after"],
            "signer_did": receipt["signer_did"],
            "digest": receipt["digest"],
            "verifier_did": receipt["verifier_did"],
            "verifier_key_version": receipt["verifier_key_version"],
            "nonce": receipt["nonce"],
        }
        # 回执非法：receipt 内 nonce 非串/空/超长。
        bad_nonce_num = dict(good, receipt=dict(receipt, nonce=123))
        bad_nonce_empty = dict(good, receipt=dict(receipt, nonce=""))
        bad_nonce_long = dict(good, receipt=dict(receipt, nonce="n" * 257))
        # nonce错误：外层 nonce 与回执不一致。
        nonce_mismatch = dict(good, nonce="别的nonce")
        # 摘要错误：ndjson 改动。
        digest_bad = dict(good, ndjson=ndjson + "\n")
        # 锚点不可用：receipt 的 verifier_did 未知（摘要/nonce 先过）。
        unknown_receipt = dict(receipt)
        unknown_receipt["verifier_did"] = "did:web:unknown-verifier.example"
        no_anchor = dict(good, receipt=unknown_receipt)
        # 签名格式错误。
        fmt_bad = dict(good, signature="not-a-signature!!!")
        # 签名校验失败：他人私钥签名。
        other_priv = crypto.generate_private_key_pem()
        sig_bad = dict(good, signature=crypto.sign(receipt, other_priv))

        items = [good, bad_order, bad_nonce_num, bad_nonce_empty,
                 bad_nonce_long, nonce_mismatch, digest_bad, no_anchor,
                 fmt_bad, sig_bad, good]
        st, body = batch({"items": items})
        expected = [
            {"valid": True},
            {"valid": False, "reason": "回执非法"},
            {"valid": False, "reason": "回执非法"},
            {"valid": False, "reason": "回执非法"},
            {"valid": False, "reason": "回执非法"},
            {"valid": False, "reason": "nonce错误"},
            {"valid": False, "reason": "摘要错误"},
            {"valid": False, "reason": "锚点不可用"},
            {"valid": False, "reason": "签名格式错误"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": True},
        ]
        check("六类原因等长同序逐项不短路", body["results"] == expected)
        check("reason 限允许集合",
              all(r["reason"] in REASONS
                  for r in body["results"] if not r["valid"]))
        check("成功项恰为 {valid:true}",
              all(r == {"valid": True}
                  for r in body["results"] if r["valid"]))

        # 单条入口：receipt 内 nonce 非法亦 200 返“回执非法”。
        for name, bad_receipt in (
            ("非串", dict(receipt, nonce=123)),
            ("空串", dict(receipt, nonce="")),
            ("超长", dict(receipt, nonce="n" * 257)),
        ):
            st, raw = post(VERIFY_PATH,
                           {"receipt": bad_receipt, "signature": signature,
                            "ndjson": ndjson, "nonce": nonce}, DST)
            check(f"单条 receipt 内 nonce {name} -> 回执非法",
                  st == 200 and json.loads(raw) == {
                      "valid": False, "reason": "回执非法"})

        # 边界：1 项与 100 项均合法。
        st, body = batch({"items": [good]})
        check("单项批次合法", body["results"] == [{"valid": True}])
        st, body = batch({"items": [good] * 100})
        check("100 项批次合法",
              st == 200 and body["results"] == [{"valid": True}] * 100)

        # ---------------------------------------------------------- #
        # 4. 批初原子快照：并发吊销下同批不观察混合状态
        # ---------------------------------------------------------- #
        st, body = batch({"items": [good, good]})
        check("吊销前同批一致 valid",
              body["results"] == [{"valid": True}] * 2)

        mixed_seen = []
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                st, raw = post(BATCH_PATH, {"items": [good] * 100}, DST)
                rs = json.loads(raw)["results"]
                kinds = {tuple(sorted(r.items())) for r in rs}
                if len(kinds) != 1:
                    mixed_seen.append(rs)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.3)
        st, raw = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/{verifier_did}/{key_version}/status",
            {"status": "revoked"}, DST)
        assert st == 200, (st, raw)
        time.sleep(0.5)
        stop.set()
        for t in threads:
            t.join()
        check("并发吊销下同批不观察混合状态", not mixed_seen)

        st, body = batch({"items": [good, good]})
        check("吊销后同批一致 锚点不可用",
              body["results"] == [
                  {"valid": False, "reason": "锚点不可用"}] * 2)

        # 用途收紧（去掉 vp）后同样一致不可用。
        st, raw = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/{verifier_did}/{key_version}/uses",
            {"from_uses": ["generic", "vp"], "uses": ["generic"]}, DST)
        check("用途收紧前提（吊销状态更新用途或忽略）", st in (200, 404, 409))

        # 另起验证者验证用途收紧。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "presentation-sync-receipt-vfy-b2"},
                       DST)
        assert st == 201, (st, raw)
        verifier2 = json.loads(raw)
        qs2 = urllib.parse.urlencode(
            {"signer_did": signer_did, "verifier_did": verifier2["did"],
             "nonce": nonce})
        st, raw = get(f"{RECEIPT_PATH}?{qs2}", headers=DST)
        assert st == 200, raw
        issued2 = json.loads(raw)
        st, raw = post(ANCHORS_PATH,
                       {"did": verifier2["did"],
                        "public_key": verifier2["public_key"],
                        "key_version": issued2["receipt"]
                        ["verifier_key_version"],
                        "uses": ["generic", "vp"]}, DST)
        assert st in (200, 201), (st, raw)
        good2 = {"receipt": issued2["receipt"],
                 "signature": issued2["signature"],
                 "ndjson": ndjson, "nonce": nonce}
        st, body = batch({"items": [good2]})
        check("收紧前 valid", body["results"] == [{"valid": True}])
        st, raw = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/{verifier2['did']}/"
            f"{issued2['receipt']['verifier_key_version']}/uses",
            {"from_uses": ["generic", "vp"], "uses": ["generic"]}, DST)
        assert st == 200, (st, raw)
        st, body = batch({"items": [good2, good2]})
        check("用途收紧后同批一致 锚点不可用",
              body["results"] == [
                  {"valid": False, "reason": "锚点不可用"}] * 2)

        # ---------------------------------------------------------- #
        # 5. 纯只读：不记审计、不推进检查点；重启稳定
        # ---------------------------------------------------------- #
        st, raw = get("/v1/audit?limit=200", headers=DST)
        n_before = len(json.loads(raw)["events"])
        batch({"items": [good, bad_order, sig_bad]})
        batch({"items": [good] * 100})
        batch(raw_body=b"{")
        st, raw = get("/v1/audit?limit=200", headers=DST)
        check("批量验真不记审计",
              len(json.loads(raw)["events"]) == n_before)

        # 检查点未受影响：receipt 的 next_after 不变。
        st, raw = get(f"{RECEIPT_PATH}?{qs2}", headers=DST)
        check("检查点未受影响",
              json.loads(raw)["receipt"]["next_after"]
              == issued2["receipt"]["next_after"])

        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = batch({"items": [good2, good]})
        check("重启后结论稳定",
              body["results"] == [
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"}])

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    main()
