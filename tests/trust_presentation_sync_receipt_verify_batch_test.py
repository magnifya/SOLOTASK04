#!/usr/bin/env python3
"""POST /v1/trust/presentation-sync/receipt/verify-batch 批量验真演示消费
同步回执端到端测试。

直接运行：python3 tests/trust_presentation_sync_receipt_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级非法一律 200 且按键序恰返 {"results":[],"reason":"请求非法"}：
  空体、非法 JSON、非对象、键集错（缺/多键）、items 非数组、空数组、
  超过 100 项；显式空租户头 400；
- 项级非法 {"valid":false,"reason":"请求项非法"}：项非对象、键集错、
  receipt 非对象、signature 非串/空串、ndjson 非串、nonce 非串/空/
  257 码点；
- 合法批次逐项不短路、等长同序：成功仅 {"valid":true}，失败键序恰为
  valid、reason，reason 依次覆盖 回执非法（含 receipt.nonce 非法）、
  nonce错误、摘要错误、锚点不可用、签名格式错误、签名校验失败；
- 批初锚点快照：批后吊销/用途收紧不影响已取快照语义（重启前后一致
  地按批初状态判定）；单条 verify 的 receipt.nonce 非法同样 200 返
  “回执非法”；
- 只读：不写审计、不推进检查点；租户隔离；重启后结果一致。
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
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
HISTORY_PATH = "/v1/trust/presentation-sync/history"
RECEIPT_PATH = "/v1/trust/presentation-sync/receipt"
VERIFY_PATH = "/v1/trust/presentation-sync/receipt/verify"
BATCH_PATH = "/v1/trust/presentation-sync/receipt/verify-batch"
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


ISSUER_DID = "did:web:pres-sync-receipt-vfybatch-issuer.example"


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
    port = 9218
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
        DST = {"X-Tenant-ID": "dst-vfybatch-tenant"}
        OTHER = {"X-Tenant-ID": "other-vfybatch-tenant"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:pres-sync-receipt-vfybatch-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1}, DST)
        assert st in (200, 201), st

        # 本地验证者 DID（托管私钥，GET receipt 的签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "presentation-sync-receipt-vfybatch"},
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
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": key_version,
                      "uses": ["generic", "vp"]}, DST)
        assert st in (200, 201), st

        def batch(payload=None, headers=DST, raw_body=None):
            st, raw = post(BATCH_PATH, payload=payload, headers=headers,
                           raw_body=raw_body)
            return st, json.loads(raw.decode() or "null")

        good_item = {"receipt": receipt, "signature": signature,
                     "ndjson": ndjson, "nonce": nonce}

        # ---------------------------------------------------------- #
        # 1. 成功：单项批次仅 {"results":[{"valid":true}]}
        # ---------------------------------------------------------- #
        st, body = batch({"items": [good_item]})
        check("单项成功 200 且 results 仅 valid:true",
              st == 200 and list(body.keys()) == ["results"]
              and body == {"results": [{"valid": True}]})

        # ---------------------------------------------------------- #
        # 2. 请求级非法：200 {"results":[],"reason":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_bad_request(name, payload=None, raw_body=None,
                               headers=DST):
            st, body = batch(payload, headers=headers, raw_body=raw_body)
            check(name, st == 200
                  and list(body.keys()) == ["results", "reason"]
                  and body == {"results": [], "reason": "请求非法"})

        expect_bad_request("空体 200 请求非法", raw_body=b"")
        expect_bad_request("非法 JSON 200 请求非法", raw_body=b"{not json")
        expect_bad_request("非对象（数组）200 请求非法", raw_body=b"[1,2]")
        expect_bad_request("非对象（字符串）200 请求非法", raw_body=b'"x"')
        expect_bad_request("缺 items 键", {})
        expect_bad_request("多键", {"items": [good_item], "x": 1})
        expect_bad_request("items 非数组", {"items": "x"})
        expect_bad_request("items 非数组（对象）", {"items": {}})
        expect_bad_request("items 空数组", {"items": []})
        expect_bad_request("items 超限（101 项）",
                           {"items": [good_item] * 101})
        st, body = batch({"items": [good_item] * 100})
        check("items 100 项合法",
              st == 200 and len(body.get("results", [])) == 100)
        st, body = batch({"items": [good_item]},
                         headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 3. 项级非法：{"valid":false,"reason":"请求项非法"}
        # ---------------------------------------------------------- #
        def expect_item_invalid(name, item):
            st, body = batch({"items": [item]})
            check(name, st == 200
                  and body == {"results": [
                      {"valid": False, "reason": "请求项非法"}]})

        expect_item_invalid("项非对象", "not-object")
        expect_item_invalid("项缺 receipt",
                            {k: v for k, v in good_item.items()
                             if k != "receipt"})
        expect_item_invalid("项缺 signature",
                            {k: v for k, v in good_item.items()
                             if k != "signature"})
        expect_item_invalid("项缺 ndjson",
                            {k: v for k, v in good_item.items()
                             if k != "ndjson"})
        expect_item_invalid("项缺 nonce",
                            {k: v for k, v in good_item.items()
                             if k != "nonce"})
        extra = dict(good_item)
        extra["x"] = 1
        expect_item_invalid("项多键", extra)
        bad = dict(good_item)
        bad["receipt"] = "not-object"
        expect_item_invalid("项 receipt 非对象", bad)
        bad = dict(good_item)
        bad["signature"] = ""
        expect_item_invalid("项 signature 空串", bad)
        bad = dict(good_item)
        bad["signature"] = 7
        expect_item_invalid("项 signature 非串", bad)
        bad = dict(good_item)
        bad["ndjson"] = 1
        expect_item_invalid("项 ndjson 非串", bad)
        bad = dict(good_item)
        bad["nonce"] = ""
        expect_item_invalid("项 nonce 空串", bad)
        bad = dict(good_item)
        bad["nonce"] = "a" * 257
        expect_item_invalid("项 nonce 257 码点", bad)
        bad = dict(good_item)
        bad["nonce"] = "a" * 200 + "中" * 57
        expect_item_invalid("项 nonce 257 Unicode 码点", bad)
        bad = dict(good_item)
        bad["nonce"] = 1
        expect_item_invalid("项 nonce 非串", bad)
        bad = dict(good_item)
        bad["nonce"] = "a" * 200 + "中" * 56
        st, body = batch({"items": [bad]})
        check("项 nonce 256 码点合法（进入验真）",
              st == 200 and body["results"][0]["reason"] == "nonce错误")

        # ---------------------------------------------------------- #
        # 4. 逐项失败原因与优先级（不短路、等长同序）
        # ---------------------------------------------------------- #
        # 回执非法：键序错
        disordered = {
            "nonce": receipt["nonce"],
            "signer_did": receipt["signer_did"],
            "next_after": receipt["next_after"],
            "digest": receipt["digest"],
            "verifier_did": receipt["verifier_did"],
            "verifier_key_version": receipt["verifier_key_version"],
        }
        item_receipt_bad_order = {"receipt": disordered,
                                  "signature": signature,
                                  "ndjson": ndjson, "nonce": nonce}
        # 回执非法：receipt.nonce 非法（空串/超长/非串）
        bad_nonce_receipts = []
        for value in ("", "a" * 257, 7, None):
            bad_receipt = dict(receipt)
            bad_receipt["nonce"] = value
            bad_nonce_receipts.append(
                {"receipt": bad_receipt, "signature": signature,
                 "ndjson": ndjson, "nonce": nonce})
        # nonce 错误
        item_nonce_mismatch = {"receipt": receipt, "signature": signature,
                               "ndjson": ndjson, "nonce": "other"}
        # 摘要错误
        item_digest = {"receipt": receipt, "signature": signature,
                       "ndjson": ndjson + "\n", "nonce": nonce}
        # 锚点不可用：未知验证者 DID
        unknown_receipt = dict(receipt)
        unknown_receipt["verifier_did"] = "did:web:no-such-vfybatch.example"
        item_anchor = {"receipt": unknown_receipt, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}
        # 签名格式错误
        item_sig_fmt = {"receipt": receipt, "signature": "!!!",
                        "ndjson": ndjson, "nonce": nonce}
        # 签名校验失败：他人私钥签名
        other_priv, other_pub = _keypair()
        wrong_sig = crypto.sign(receipt, other_priv)
        item_sig_bad = {"receipt": receipt, "signature": wrong_sig,
                        "ndjson": ndjson, "nonce": nonce}

        items = [
            good_item,                # valid
            item_receipt_bad_order,   # 回执非法
            *bad_nonce_receipts,      # 回执非法 x4
            item_nonce_mismatch,      # nonce错误
            item_digest,              # 摘要错误
            item_anchor,              # 锚点不可用
            item_sig_fmt,             # 签名格式错误
            item_sig_bad,             # 签名校验失败
            {"broken": True},         # 请求项非法
            good_item,                # valid（不短路）
        ]
        st, body = batch({"items": items})
        expected = (
            [{"valid": True}]
            + [{"valid": False, "reason": "回执非法"}] * 5
            + [{"valid": False, "reason": "nonce错误"},
               {"valid": False, "reason": "摘要错误"},
               {"valid": False, "reason": "锚点不可用"},
               {"valid": False, "reason": "签名格式错误"},
               {"valid": False, "reason": "签名校验失败"},
               {"valid": False, "reason": "请求项非法"},
               {"valid": True}]
        )
        check("混合批次等长同序不短路",
              st == 200 and list(body.keys()) == ["results"]
              and body == {"results": expected})
        if st == 200 and body.get("results") != expected:
            print("  实际结果:", json.dumps(body, ensure_ascii=False))

        # 失败项键序恰为 valid、reason。
        st, body = batch({"items": [item_nonce_mismatch]})
        check("失败项键序恰为 valid、reason",
              st == 200
              and list(body["results"][0].keys()) == ["valid", "reason"])

        # receipt 各字段类型/取值非法 -> 回执非法。
        for field, value in [
            ("signer_did", ""), ("next_after", -1),
            ("next_after", True), ("digest", "0" * 63),
            ("digest", "A" * 64), ("verifier_did", ""),
            ("verifier_key_version", 0),
        ]:
            bad_receipt = dict(receipt)
            bad_receipt[field] = value
            st, body = batch({"items": [
                {"receipt": bad_receipt, "signature": signature,
                 "ndjson": ndjson, "nonce": nonce}]})
            check(f"项 receipt.{field}={value!r} -> 回执非法",
                  st == 200 and body["results"][0]
                  == {"valid": False, "reason": "回执非法"})

        # ---------------------------------------------------------- #
        # 5. 单条 verify：receipt.nonce 非法同样 200 返“回执非法”
        # ---------------------------------------------------------- #
        for value in ("", "a" * 257, 7):
            bad_receipt = dict(receipt)
            bad_receipt["nonce"] = value
            st, raw = post(VERIFY_PATH,
                           {"receipt": bad_receipt, "signature": signature,
                            "ndjson": ndjson, "nonce": nonce}, DST)
            body = json.loads(raw)
            check(f"单条 receipt.nonce={value!r} -> 回执非法",
                  st == 200
                  and body == {"valid": False, "reason": "回执非法"})

        # ---------------------------------------------------------- #
        # 6. 跨租户与缺省租户头隔离
        # ---------------------------------------------------------- #
        st, body = batch({"items": [good_item]}, headers=OTHER)
        check("跨租户锚点不可用",
              st == 200 and body == {"results": [
                  {"valid": False, "reason": "锚点不可用"}]})
        st, body = batch({"items": [good_item]}, headers=None)
        check("缺省租户头 default 隔离",
              st == 200 and body == {"results": [
                  {"valid": False, "reason": "锚点不可用"}]})

        # ---------------------------------------------------------- #
        # 7. 只读：不写审计、不推进检查点
        # ---------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=DST)
        assert st == 200
        for _ in range(3):
            st, body = batch({"items": [good_item, item_sig_bad]})
            assert st == 200, body
        st, audit_after = get("/v1/audit?limit=200", headers=DST)
        check("批量验真不写审计", audit_before == audit_after)
        st, raw = get(f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        check("检查点未受影响",
              st == 200 and json.loads(raw)["next_after"] == 11)

        # ---------------------------------------------------------- #
        # 8. 锚点吊销/用途收紧后同批一致判定（快照语义）
        # ---------------------------------------------------------- #
        st, _ = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/{urllib.parse.quote(verifier_did)}"
            f"/{key_version}/status",
            payload={"status": "revoked"}, headers=DST)
        assert st == 200, st
        st, body = batch({"items": [good_item, good_item]})
        check("吊销后同批一致锚点不可用",
              st == 200 and body == {"results": [
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"}]})

        # 用途收紧：登记新锚点再收紧到不含 vp。
        st, _ = post(ANCHORS_PATH,
                     {"did": "did:web:tighten-vfybatch.example",
                      "public_key": verifier_pub, "key_version": 1,
                      "uses": ["generic", "vp"]}, DST)
        assert st in (200, 201), st
        st, _ = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/did:web:tighten-vfybatch.example"
            "/1/uses",
            payload={"from_uses": ["generic", "vp"],
                     "uses": ["generic"]}, headers=DST)
        assert st == 200, st
        tighten_receipt = dict(receipt)
        tighten_receipt["verifier_did"] = "did:web:tighten-vfybatch.example"
        tighten_receipt["verifier_key_version"] = 1
        st, body = batch({"items": [
            {"receipt": tighten_receipt, "signature": signature,
             "ndjson": ndjson, "nonce": nonce}]})
        check("用途收紧后锚点不可用",
              st == 200 and body == {"results": [
                  {"valid": False, "reason": "锚点不可用"}]})

        # ---------------------------------------------------------- #
        # 9. 重启稳定：结果一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = batch({"items": [good_item, item_sig_fmt]})
        check("重启后结果一致（锚点仍吊销，先于签名格式）",
              st == 200 and body == {"results": [
                  {"valid": False, "reason": "锚点不可用"},
                  {"valid": False, "reason": "锚点不可用"}]})
        st, body = batch({"items": [good_item]}, headers=None)
        check("重启后缺省租户仍隔离",
              st == 200 and body == {"results": [
                  {"valid": False, "reason": "锚点不可用"}]})

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
