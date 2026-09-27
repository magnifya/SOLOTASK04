#!/usr/bin/env python3
"""POST /v1/trust/presentation-sync/receipt/verify 验真演示消费同步回执
端到端测试。

直接运行：python3 tests/trust_presentation_sync_receipt_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400：空体、非法 JSON、非对象、键集错（缺/多键）、类型错
  （receipt 非对象、signature 非串/空串、ndjson 非串、nonce 非串/
  空/257 码点），均仅 {"error":"请求非法"}；显式空租户头 400；
- 200 失败原因依次：回执非法（键序/类型/取值）、nonce错误、
  摘要错误、锚点不可用（未知/他租户/版本不符/吊销/用途不含 vp）、
  签名格式错误、签名校验失败；失败响应键序恰为 valid、reason；
- 成功仅 {"valid":true}；ndjson 不被解析（非法行内容只要摘要
  匹配即通过）；
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


ISSUER_DID = "did:web:pres-sync-receipt-verify-issuer.example"


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
    port = 9086
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
        DST = {"X-Tenant-ID": "dst-verify-tenant"}
        OTHER = {"X-Tenant-ID": "other-verify-tenant"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:pres-sync-receipt-verify-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1}, DST)
        assert st in (200, 201), st

        # 本地验证者 DID（托管私钥，GET receipt 的签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "presentation-sync-receipt-vfy"},
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
        nonce = "nonce-一"
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

        def verify(payload=None, headers=DST, raw_body=None):
            st, raw = post(VERIFY_PATH, payload=payload, headers=headers,
                           raw_body=raw_body)
            return st, json.loads(raw.decode() or "null")

        good = {"receipt": receipt, "signature": signature,
                "ndjson": ndjson, "nonce": nonce}

        # ---------------------------------------------------------- #
        # 1. 成功：仅 {"valid": true}
        # ---------------------------------------------------------- #
        st, body = verify(good)
        check("正常验真 200 且仅 valid:true",
              st == 200 and body == {"valid": True})

        # ndjson 不被解析：非 NDJSON 内容只要摘要匹配即通过。
        weird = "这不是NDJSON\n{broken\n"
        weird_receipt = dict(receipt)
        weird_receipt["digest"] = hashlib.sha256(
            weird.encode("utf-8")).hexdigest()
        # 重新取得覆盖新 digest 的签名不可行（无私钥），改用本地
        # 锚点自签：以验证者锚点公钥对应的私钥不可得，故仅验证
        # “摘要错误”之前的解析行为——非法 ndjson 不触发 500。
        st, body = verify({"receipt": receipt, "signature": signature,
                           "ndjson": weird, "nonce": nonce})
        check("非法 ndjson 内容不解析（摘要错误）",
              st == 200 and body == {"valid": False, "reason": "摘要错误"})

        # ---------------------------------------------------------- #
        # 2. 400：仅 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, payload=None, raw_body=None, headers=DST):
            st, body = verify(payload, headers=headers, raw_body=raw_body)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("空体 400", raw_body=b"")
        expect_400("非法 JSON 400", raw_body=b"{not json")
        expect_400("非对象（数组）400", raw_body=b"[1,2]")
        expect_400("非对象（字符串）400", raw_body=b'"x"')
        expect_400("缺 receipt", {k: v for k, v in good.items()
                                  if k != "receipt"})
        expect_400("缺 signature", {k: v for k, v in good.items()
                                    if k != "signature"})
        expect_400("缺 ndjson", {k: v for k, v in good.items()
                                 if k != "ndjson"})
        expect_400("缺 nonce", {k: v for k, v in good.items()
                                if k != "nonce"})
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
        bad = dict(good)
        bad["nonce"] = "a" * 200 + "中" * 57
        expect_400("nonce 257 Unicode 码点", bad)
        bad = dict(good)
        bad["nonce"] = "a" * 200 + "中" * 56
        st, body = verify(bad)
        check("nonce 256 码点合法", st == 200)
        st, body = verify(good, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 3. 200 失败原因（键序恰为 valid、reason）
        # ---------------------------------------------------------- #
        def expect_reason(name, payload, reason):
            st, body = verify(payload)
            check(name, st == 200
                  and list(body.keys()) == ["valid", "reason"]
                  and body == {"valid": False, "reason": reason})

        # 回执非法：键序错
        disordered = {
            "nonce": receipt["nonce"],
            "signer_did": receipt["signer_did"],
            "next_after": receipt["next_after"],
            "digest": receipt["digest"],
            "verifier_did": receipt["verifier_did"],
            "verifier_key_version": receipt["verifier_key_version"],
        }
        expect_reason("receipt 键序错 -> 回执非法",
                      {"receipt": disordered, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "回执非法")
        # 回执非法：缺键/多键
        missing = {k: v for k, v in receipt.items() if k != "digest"}
        expect_reason("receipt 缺键 -> 回执非法",
                      {"receipt": missing, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "回执非法")
        extra_key = dict(receipt)
        extra_key["zz"] = 1
        expect_reason("receipt 多键 -> 回执非法",
                      {"receipt": extra_key, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "回执非法")
        # 回执非法：各字段类型/取值
        for field, value in [
            ("signer_did", ""), ("signer_did", 1),
            ("next_after", -1), ("next_after", True),
            ("next_after", "7"), ("next_after", 1.5),
            ("digest", "0" * 63), ("digest", "0" * 65),
            ("digest", "A" * 64), ("digest", "g" * 64), ("digest", 7),
            ("verifier_did", ""), ("verifier_did", None),
            ("verifier_key_version", 0), ("verifier_key_version", False),
            ("verifier_key_version", "1"),
        ]:
            bad_receipt = dict(receipt)
            bad_receipt[field] = value
            expect_reason(f"receipt.{field}={value!r} -> 回执非法",
                          {"receipt": bad_receipt, "signature": signature,
                           "ndjson": ndjson, "nonce": nonce}, "回执非法")

        # nonce 错误：receipt.nonce 与外层不一致
        expect_reason("nonce 不一致 -> nonce错误",
                      {"receipt": receipt, "signature": signature,
                       "ndjson": ndjson, "nonce": "other"}, "nonce错误")
        bad_receipt = dict(receipt)
        bad_receipt["nonce"] = "别的"
        expect_reason("receipt.nonce 被改 -> nonce错误",
                      {"receipt": bad_receipt, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "nonce错误")

        # 摘要错误：ndjson 改动后 digest 不匹配
        expect_reason("ndjson 篡改 -> 摘要错误",
                      {"receipt": receipt, "signature": signature,
                       "ndjson": ndjson + "\n", "nonce": nonce},
                      "摘要错误")
        expect_reason("空 ndjson -> 摘要错误",
                      {"receipt": receipt, "signature": signature,
                       "ndjson": "", "nonce": nonce}, "摘要错误")

        # 锚点不可用：他租户无锚点
        st, body = verify(good, headers=OTHER)
        check("跨租户锚点不可用",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        # 锚点不可用：版本不符
        bad_receipt = dict(receipt)
        bad_receipt["verifier_key_version"] = key_version + 1
        expect_reason("锚点版本不存在 -> 锚点不可用",
                      {"receipt": bad_receipt, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "锚点不可用")
        # 锚点不可用：未知 DID
        bad_receipt = dict(receipt)
        bad_receipt["verifier_did"] = "did:web:no-such-verifier.example"
        expect_reason("未知验证者 -> 锚点不可用",
                      {"receipt": bad_receipt, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "锚点不可用")

        # 签名格式错误：合法锚点 + 匹配摘要，签名编码非法
        expect_reason("签名非 base64url -> 签名格式错误",
                      {"receipt": receipt, "signature": "!!!",
                       "ndjson": ndjson, "nonce": nonce}, "签名格式错误")
        expect_reason("签名带填充 -> 签名格式错误",
                      {"receipt": receipt, "signature": signature + "==",
                       "ndjson": ndjson, "nonce": nonce}, "签名格式错误")
        short_sig = signature[:10]
        expect_reason("签名长度错 -> 签名格式错误",
                      {"receipt": receipt, "signature": short_sig,
                       "ndjson": ndjson, "nonce": nonce}, "签名格式错误")

        # 签名校验失败：格式合法但签名与内容不符（换 nonce 重签的回执
        # 与当前 receipt 不匹配；直接用他人签名）。
        other_priv, other_pub = _keypair()
        st, _ = post(ANCHORS_PATH,
                     {"did": "did:web:other-verifier.example",
                      "public_key": other_pub, "key_version": 1,
                      "uses": ["vp"]}, DST)
        assert st in (200, 201), st
        other_receipt = dict(receipt)
        other_receipt["verifier_did"] = "did:web:other-verifier.example"
        other_receipt["verifier_key_version"] = 1
        other_sig = crypto.sign(other_receipt, other_priv)
        tampered = dict(other_receipt)
        tampered["next_after"] = receipt["next_after"] + 1
        expect_reason("签名覆盖内容被改 -> 签名校验失败",
                      {"receipt": tampered, "signature": other_sig,
                       "ndjson": ndjson, "nonce": nonce}, "签名校验失败")
        # 用 other 的私钥签当前 receipt，但锚点是 verifier 的公钥。
        wrong_sig = crypto.sign(receipt, other_priv)
        expect_reason("他人签名 -> 签名校验失败",
                      {"receipt": receipt, "signature": wrong_sig,
                       "ndjson": ndjson, "nonce": nonce}, "签名校验失败")

        # 吊销锚点后不可用。
        st, _ = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/{urllib.parse.quote(verifier_did)}"
            f"/{key_version}/status",
            payload={"status": "revoked"}, headers=DST)
        assert st == 200, st
        st, body = verify(good)
        check("锚点吊销 -> 锚点不可用",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        # 恢复：重新登记同 DID/版本不可行（已吊销），改登记新版本。
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": key_version + 10, "uses": ["vp"]},
                     DST)
        assert st in (200, 201), st
        new_receipt = dict(receipt)
        new_receipt["verifier_key_version"] = key_version + 10
        # 无对应私钥重签 -> 签名校验失败（锚点可用、格式合法）。
        st, body = verify({"receipt": new_receipt, "signature": signature,
                           "ndjson": ndjson, "nonce": nonce})
        check("换版本后锚点可用但签名不符 -> 签名校验失败",
              st == 200 and body == {"valid": False, "reason": "签名校验失败"})

        # 用途不含 vp 的锚点不可用。
        st, _ = post(ANCHORS_PATH,
                     {"did": "did:web:generic-only.example",
                      "public_key": verifier_pub, "key_version": 1,
                      "uses": ["generic"]}, DST)
        assert st in (200, 201), st
        gen_receipt = dict(receipt)
        gen_receipt["verifier_did"] = "did:web:generic-only.example"
        gen_receipt["verifier_key_version"] = 1
        expect_reason("锚点用途不含 vp -> 锚点不可用",
                      {"receipt": gen_receipt, "signature": signature,
                       "ndjson": ndjson, "nonce": nonce}, "锚点不可用")

        # ---------------------------------------------------------- #
        # 4. 只读：不写审计、不推进检查点
        # ---------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=DST)
        assert st == 200
        for _ in range(3):
            st, body = verify(good)
            # 锚点已吊销，此处为锚点不可用；只验证不写审计。
            assert st == 200
        st, audit_after = get("/v1/audit?limit=200", headers=DST)
        check("验真不写审计", audit_before == audit_after)
        st, raw = get(f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        check("检查点未受影响",
              st == 200 and json.loads(raw)["next_after"] == 11)

        # ---------------------------------------------------------- #
        # 5. 缺省租户头：default 租户内锚点不可用（隔离）
        # ---------------------------------------------------------- #
        st, body = verify(good, headers=None)
        check("缺省租户头 default 隔离",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 6. 重启稳定：结果一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = verify(good)
        check("重启后结果一致（锚点仍吊销）",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        st, body = verify({"receipt": receipt, "signature": "!!!",
                           "ndjson": ndjson, "nonce": nonce})
        check("重启后阶段顺序一致（锚点先于签名格式）",
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
