#!/usr/bin/env python3
"""只读 POST /v1/trust/presentation-sync/receipt/verify
验真演示消费同步回执的端到端测试。

直接运行：python3 tests/trust_presentation_sync_receipt_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

回执与 ndjson 由 GET /v1/trust/presentation-sync/receipt 与已同步数据
实际生成，不硬编码摘要。

覆盖：
- 外层协议：恰含 receipt 对象、非空串 signature、字符串 ndjson、
  1..256 码点非空串 nonce；空体、非法 JSON、非对象、键集或类型错均
  400 且仅 {"error":"请求非法"}；显式空租户头 400；
- 六阶段失败均 HTTP 200，键序 valid、reason，原因依次为
  “回执非法”“nonce错误”“摘要错误”“锚点不可用”
  “签名格式错误”“签名校验失败”；成功仅 {"valid":true}；
- 锚点须本租户同 verifier_did/版本、active 且含 vp 用途；
- 不解析 ndjson、不写状态、游标或审计；缺省租户头按 default 隔离；
- 重启稳定。
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
RECEIPT_PATH = "/v1/trust/presentation-sync/receipt"
VERIFY_PATH = "/v1/trust/presentation-sync/receipt/verify"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
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


def main():
    port = 9087
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

    def put(path, payload=None, headers=None):
        return _http("PUT", base + path, payload=payload, headers=headers)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        T = {"X-Tenant-ID": "prv-tenant"}
        OTHER = {"X-Tenant-ID": "prv-other"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:prv-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1}, T)
        assert st in (200, 201), st

        st, raw = post(DIDS_PATH,
                       {"method": "web", "public_key": "prv-verifier"}, T)
        assert st == 201, (st, raw)
        vrec = json.loads(raw)
        verifier_did, verifier_pub = vrec["did"], vrec["public_key"]

        # 验证者 vp 用途 active 锚点（receipt 验签所需）。
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": 1, "uses": ["vp"]}, T)
        assert st in (200, 201), st

        issuer = "did:web:prv-issuer.example"
        rows = [
            {"cursor": 3, "consumption_id": "cons-1",
             "issuer_did": issuer, "presentation_id": "vp_演示_001",
             "consumed_at": "2099-01-01T00:00:00Z"},
            {"cursor": 7, "consumption_id": "cons-2",
             "issuer_did": issuer, "presentation_id": "vp_002",
             "consumed_at": "2099-01-01T00:00:00Z"},
        ]
        ndjson = "".join(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
            for r in rows
        )

        def signed_manifest(snapshot, after, text):
            manifest = {
                "snapshot": snapshot,
                "filters": {"after": after, "limit": 1000},
                "count": text.count("\n"),
                "alg": "SHA-256",
                "digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "signer_did": signer_did,
                "key_version": 1,
            }
            manifest["signature"] = crypto.sign(
                {k: manifest[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return manifest

        st, r = post(SYNC_PATH,
                     {"manifest": signed_manifest(11, 0, ndjson),
                      "ndjson": ndjson}, headers=T)
        assert st == 201, (st, r)

        qs = urllib.parse.urlencode(
            {"signer_did": signer_did,
             "verifier_did": verifier_did, "nonce": "nonce-一"})
        st, raw = get(f"{RECEIPT_PATH}?{qs}", headers=T)
        assert st == 200, raw
        issued = json.loads(raw)
        receipt = issued["receipt"]
        signature = issued["signature"]
        nonce = "nonce-一"
        good = {"receipt": receipt, "signature": signature,
                "ndjson": ndjson, "nonce": nonce}

        def verify(payload=None, headers=T, raw=None):
            st, body = post(VERIFY_PATH, payload=payload,
                            headers=headers, raw=raw)
            return st, json.loads(body.decode() or "null")

        # -------------------------------------------------------------- #
        # 1. 成功
        # -------------------------------------------------------------- #
        st, body = verify(good)
        check("成功仅 {valid:true}",
              st == 200 and body == {"valid": True})

        # -------------------------------------------------------------- #
        # 2. 400：外层协议，仅 {"error":"请求非法"}
        # -------------------------------------------------------------- #
        def expect_400(name, payload=None, raw=None, headers=T):
            st, body = verify(payload=payload, raw=raw, headers=headers)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("空体", raw=b"")
        expect_400("非法 JSON", raw=b"{bad")
        expect_400("非对象（数组）", raw=b"[1]")
        expect_400("JSON null", raw=b"null")
        for field in ("receipt", "signature", "ndjson", "nonce"):
            expect_400(
                f"缺 {field}",
                {k: v for k, v in good.items() if k != field})
        expect_400("多余字段", dict(good, x=1))
        expect_400("receipt 非对象", dict(good, receipt=[]))
        expect_400("receipt null", dict(good, receipt=None))
        expect_400("signature 空串", dict(good, signature=""))
        expect_400("signature 非字符串", dict(good, signature=1))
        expect_400("ndjson 非字符串", dict(good, ndjson=1))
        expect_400("ndjson null", dict(good, ndjson=None))
        expect_400("nonce 空串", dict(good, nonce=""))
        expect_400("nonce 非字符串", dict(good, nonce=1))
        expect_400("nonce 257 码点", dict(good, nonce="a" * 257))
        expect_400("nonce 257 Unicode 码点",
                   dict(good, nonce="a" * 200 + "中" * 57))
        st, _ = verify(good, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # 空串 ndjson 外层合法：进入 200 验真，摘要不匹配。
        st, body = verify(dict(good, ndjson=""))
        check("空串 ndjson -> 200 摘要错误",
              st == 200 and body == {"valid": False, "reason": "摘要错误"})
        # nonce 边界 1/256 码点外层合法（回执 nonce 不同 -> nonce错误）。
        st, body = verify(dict(good, nonce="中"))
        check("nonce 1 码点 -> 200 nonce错误",
              st == 200 and body["reason"] == "nonce错误")
        st, body = verify(dict(good, nonce="a" * 200 + "中" * 56))
        check("nonce 256 码点 -> 200 nonce错误",
              st == 200 and body["reason"] == "nonce错误")

        # -------------------------------------------------------------- #
        # 3. 200 六阶段失败，键序 valid、reason
        # -------------------------------------------------------------- #
        def expect_invalid(name, payload, reason):
            st, body = verify(payload)
            check(name,
                  st == 200 and list(body.keys()) == ["valid", "reason"]
                  and body["valid"] is False
                  and body["reason"] == reason)

        # 回执非法
        expect_invalid(
            "回执缺字段 -> 回执非法",
            dict(good, receipt={k: v for k, v in receipt.items()
                                if k != "nonce"}),
            "回执非法")
        expect_invalid(
            "回执多字段 -> 回执非法",
            dict(good, receipt=dict(receipt, x=1)), "回执非法")
        expect_invalid(
            "signer_did 空串 -> 回执非法",
            dict(good, receipt=dict(receipt, signer_did="")), "回执非法")
        expect_invalid(
            "verifier_did 空串 -> 回执非法",
            dict(good, receipt=dict(receipt, verifier_did="")), "回执非法")
        expect_invalid(
            "next_after 负数 -> 回执非法",
            dict(good, receipt=dict(receipt, next_after=-1)), "回执非法")
        expect_invalid(
            "next_after 布尔 -> 回执非法",
            dict(good, receipt=dict(receipt, next_after=True)), "回执非法")
        expect_invalid(
            "next_after 字符串 -> 回执非法",
            dict(good, receipt=dict(receipt, next_after="7")), "回执非法")
        expect_invalid(
            "digest 大写 -> 回执非法",
            dict(good, receipt=dict(receipt, digest="A" * 64)), "回执非法")
        expect_invalid(
            "digest 非 hex -> 回执非法",
            dict(good, receipt=dict(receipt, digest="z" * 64)), "回执非法")
        expect_invalid(
            "版本 0 -> 回执非法",
            dict(good, receipt=dict(receipt, verifier_key_version=0)),
            "回执非法")
        expect_invalid(
            "版本布尔 -> 回执非法",
            dict(good, receipt=dict(receipt, verifier_key_version=True)),
            "回执非法")
        expect_invalid(
            "回执 nonce 空串 -> 回执非法",
            dict(good, receipt=dict(receipt, nonce="")), "回执非法")
        expect_invalid(
            "回执 nonce 257 码点 -> 回执非法",
            dict(good, receipt=dict(receipt, nonce="中" * 257)),
            "回执非法")
        # 回执键序不影响：签名覆盖的是规范化 JSON。
        reversed_receipt = dict(list(receipt.items())[::-1])
        st, body = verify(dict(good, receipt=reversed_receipt))
        check("回执乱键序仍验真成功",
              st == 200 and body == {"valid": True})

        # nonce错误
        expect_invalid("两处 nonce 不等 -> nonce错误",
                       dict(good, nonce="其他nonce"), "nonce错误")

        # 摘要错误
        expect_invalid("ndjson 追加换行 -> 摘要错误",
                       dict(good, ndjson=ndjson + "\n"), "摘要错误")
        expect_invalid("digest 改为 0 -> 摘要错误",
                       dict(good, receipt=dict(receipt, digest="0" * 64)),
                       "摘要错误")

        # 锚点不可用
        st, body = verify(good, headers=OTHER)
        check("跨租户 -> 锚点不可用",
              st == 200 and body["reason"] == "锚点不可用")
        expect_invalid("版本不存在 -> 锚点不可用",
                       dict(good, receipt=dict(
                           receipt, verifier_key_version=99)),
                       "锚点不可用")
        # 缺省租户头按 default 隔离：无锚点。
        st, body = verify(good, headers=None)
        check("缺省租户头 -> default 隔离 锚点不可用",
              st == 200 and body["reason"] == "锚点不可用")

        # 仅 vc 用途锚点不含 vp -> 锚点不可用
        vc_priv, vc_pub = _keypair()
        vc_did = "did:web:prv-vc-only.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": vc_did, "public_key": vc_pub,
                      "key_version": 1, "uses": ["vc"]}, T)
        assert st in (200, 201), st
        rcpt_vc = dict(receipt, verifier_did=vc_did)
        expect_invalid(
            "vc-only 锚点 -> 锚点不可用",
            {"receipt": rcpt_vc, "signature": crypto.sign(rcpt_vc, vc_priv),
             "ndjson": ndjson, "nonce": nonce},
            "锚点不可用")

        # 吊销验证者锚点 -> 锚点不可用
        st, _ = put(f"{ANCHORS_PATH}/{verifier_did}/1/status",
                    {"status": "revoked"}, T)
        assert st == 200, st
        expect_invalid("锚点吊销 -> 锚点不可用", good, "锚点不可用")

        # 自备 vp 签名者锚点供签名类与成功路径
        vp_priv, vp_pub = _keypair()
        vp_did = "did:web:prv-vp-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": vp_did, "public_key": vp_pub, "key_version": 3,
                      "uses": ["vp"]}, T)
        assert st in (200, 201), st
        vp_receipt = dict(receipt, verifier_did=vp_did,
                          verifier_key_version=3)
        vp_good = {"receipt": vp_receipt,
                   "signature": crypto.sign(vp_receipt, vp_priv),
                   "ndjson": ndjson, "nonce": nonce}
        st, body = verify(vp_good)
        check("自备 vp 锚点验真成功", st == 200 and body == {"valid": True})

        # 签名格式错误
        expect_invalid("signature 非 base64url -> 签名格式错误",
                       dict(vp_good, signature="!!!bad!!!"), "签名格式错误")

        # 签名校验失败
        other_priv, _ = _keypair()
        expect_invalid("他钥签回执 -> 签名校验失败",
                       dict(vp_good,
                            signature=crypto.sign(vp_receipt, other_priv)),
                       "签名校验失败")
        tampered = dict(vp_receipt, next_after=99)
        bad_request = {"receipt": tampered,
                       "signature": crypto.sign(vp_receipt, vp_priv),
                       "ndjson": ndjson, "nonce": nonce}
        # 改 next_after 不影响 digest（digest 本就与实际 ndjson 相符），
        # 锚点仍在，故落在签名校验失败。
        st, body = verify(bad_request)
        check("回执被篡改 -> 签名校验失败",
              st == 200 and body["reason"] == "签名校验失败")

        # -------------------------------------------------------------- #
        # 4. 只读：不写状态、游标、审计
        # -------------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=T)
        assert st == 200
        verify(vp_good)
        verify(dict(vp_good, nonce="x"))
        verify(dict(vp_good, signature="!!!"))
        st, audit_after = get("/v1/audit?limit=200", headers=T)
        assert st == 200
        check("成功与失败均不写审计", audit_before == audit_after)

        # 游标未被推进：history 的 next_after 仍为 7。
        st, hist = get(
            f"/v1/trust/presentation-sync/history?signer_did={signer_did}",
            headers=T)
        check("游标仍为 7（未写游标）",
              st == 200 and json.loads(hist)["next_after"] == 7)

        # ndjson 不解析：内容不是合规 NDJSON 也不影响摘要验真。
        st, body = verify(dict(vp_good, ndjson="随便一段文本@@@"))
        check("ndjson 不解析，仅按字节验摘要",
              st == 200 and body["reason"] == "摘要错误")

        # -------------------------------------------------------------- #
        # 5. 重启稳定
        # -------------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = verify(vp_good)
        check("重启后仍验真成功", st == 200 and body == {"valid": True})
        st, body = verify(good)
        check("重启后吊销状态保持 -> 锚点不可用",
              st == 200 and body["reason"] == "锚点不可用")

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
