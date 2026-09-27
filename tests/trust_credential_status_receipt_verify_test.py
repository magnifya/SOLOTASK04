#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt/verify 验真凭证状态同步
签名回执端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 400：空体、非法 JSON、非对象、键集错（缺/多键）、类型错
  （receipt 非对象、signature 非串/空串、nonce 非串/空/257 码点），
  均仅 {"error":"请求非法"}；显式空租户头 400；
- 200 失败原因依次：回执非法（键/类型/取值/日期/reason 规则）、
  nonce错误、锚点不可用（未知/他租户/版本不符/吊销/用途不含
  status）、签名格式错误、签名校验失败；失败响应键序恰为
  valid、reason；
- receipt 键出现顺序不影响验真；
- 成功仅 {"valid":true}；不查询当前同步状态（自签未同步凭证的
  回执亦可验真）；
- 只读：不写审计；租户隔离；重启后结论一致。
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt"
VERIFY_PATH = "/v1/trust/credential-status/receipt/verify"
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


def _raw_post(port, path, body: bytes, extra_headers: bytes = b""):
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
    port = 9099
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
        T1 = {"X-Tenant-ID": "csrv-a"}
        OTHER = {"X-Tenant-ID": "csrv-other"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:csrv-issuer.example"
        cred_id = "vc_csrv_0001"
        st, _ = post(ANCHORS_PATH,
                     {"did": issuer_did, "public_key": issuer_pub,
                      "key_version": 1, "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        # 同步一条 active 状态。
        sync_body = {
            "issuer_did": issuer_did,
            "credential_id": cred_id,
            "status": "active",
            "updated_at": "2026-09-20T00:00:00Z",
            "issuer_key_version": 1,
        }
        st, _ = post(SYNC_PATH,
                     {"body": sync_body,
                      "signature": crypto.sign(sync_body, issuer_priv)}, T1)
        assert st == 201, st

        # 本地托管验证者 DID（GET receipt 的签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "example",
                        "public_key": "credential-status-receipt-vfy"}, T1)
        assert st == 201, st
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]
        verifier_version = verifier_rec["key_version"]

        # 为验证者登记含 status 用途的 active 锚点。
        st, _ = post(ANCHORS_PATH,
                     {"did": verifier_did, "public_key": verifier_pub,
                      "key_version": verifier_version,
                      "uses": ["generic", "status"]}, T1)
        assert st in (200, 201), st

        # 取回执。
        nonce = "nonce-挑战"
        st, raw = post(RECEIPT_PATH,
                       {"issuer_did": issuer_did, "credential_id": cred_id,
                        "verifier_did": verifier_did, "nonce": nonce}, T1)
        assert st == 200, st
        issued = json.loads(raw)
        receipt = issued["receipt"]
        signature = issued["signature"]

        def verify(payload=None, headers=T1, raw_body=None):
            st, raw = post(VERIFY_PATH, payload=payload, headers=headers,
                           raw_body=raw_body)
            return st, json.loads(raw.decode() or "null")

        good = {"receipt": receipt, "signature": signature, "nonce": nonce}

        # ---------------------------------------------------------- #
        # 1. 成功：仅 {"valid": true}
        # ---------------------------------------------------------- #
        st, body = verify(good)
        check("正常验真 200 且仅 valid:true",
              st == 200 and body == {"valid": True}
              and list(body.keys()) == ["valid"])

        # 键出现顺序不影响验真：反向键序的原始 JSON + 同一签名。
        reversed_obj = {
            "nonce": nonce,
            "signature": signature,
            "receipt": dict(reversed(list(receipt.items()))),
        }
        st, body = verify(raw_body=json.dumps(reversed_obj).encode("utf-8"))
        check("receipt/外层键序打乱仍验真成功",
              st == 200 and body == {"valid": True})

        # 不查询当前同步状态：自签锚点 + 从未同步的凭证回执亦可验真。
        solo_priv, solo_pub = _keypair()
        solo_did = "did:web:csrv-solo.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": solo_did, "public_key": solo_pub,
                      "key_version": 3, "uses": ["status"]}, T1)
        assert st in (200, 201), st
        solo_receipt = {
            "issuer_did": "did:web:never-synced.example",
            "credential_id": "vc_never_synced",
            "status": "unknown",
            "reason": None,
            "updated_at": "2030-01-02T03:04:05Z",
            "issuer_key_version": 9,
            "verifier_did": solo_did,
            "verifier_key_version": 3,
            "nonce": "only-here",
        }
        solo_sig = crypto.sign(solo_receipt, solo_priv)
        st, body = verify({"receipt": solo_receipt, "signature": solo_sig,
                           "nonce": "only-here"})
        check("未同步凭证的自签回执亦可验真（不查同步状态）",
              st == 200 and body == {"valid": True})

        # ---------------------------------------------------------- #
        # 2. 400：仅 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        def expect_400(name, payload=None, raw_body=None, headers=T1):
            st, body = verify(payload, headers=headers, raw_body=raw_body)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("空体 400", raw_body=b"")
        expect_400("非法 JSON 400", raw_body=b"{not json")
        expect_400("非对象（数组）400", raw_body=b"[1,2]")
        expect_400("非对象（null）400", raw_body=b"null")
        expect_400("非对象（字符串）400", raw_body=b'"x"')
        expect_400("缺 receipt", {k: v for k, v in good.items()
                                  if k != "receipt"})
        expect_400("缺 signature", {k: v for k, v in good.items()
                                    if k != "signature"})
        expect_400("缺 nonce", {k: v for k, v in good.items()
                                if k != "nonce"})
        extra = dict(good)
        extra["x"] = 1
        expect_400("多键 400", extra)
        bad = dict(good)
        bad["receipt"] = "not-object"
        expect_400("receipt 非对象", bad)
        bad = dict(good)
        bad["receipt"] = []
        expect_400("receipt 为数组", bad)
        bad = dict(good)
        bad["signature"] = ""
        expect_400("signature 空串", bad)
        bad = dict(good)
        bad["signature"] = 123
        expect_400("signature 非串", bad)
        bad = dict(good)
        bad["nonce"] = ""
        expect_400("nonce 空串", bad)
        bad = dict(good)
        bad["nonce"] = 1
        expect_400("nonce 数字", bad)
        bad = dict(good)
        bad["nonce"] = True
        expect_400("nonce 布尔", bad)
        bad = dict(good)
        bad["nonce"] = "a" * 257
        expect_400("nonce 257 码点", bad)
        bad = dict(good)
        bad["nonce"] = "中" * 257
        expect_400("nonce 257 Unicode 码点", bad)
        bad = dict(good)
        bad["nonce"] = "中" * 256
        st, body = verify(bad)
        check("nonce 256 码点合法", st == 200)

        # 显式空租户头 400（原始 socket），统一租户头错误，不进验真。
        st, body = _raw_post(port, VERIFY_PATH,
                             json.dumps(good).encode("utf-8"),
                             b"X-Tenant-ID: \r\n")
        check("显式空 X-Tenant-ID -> 400 仅 {error}",
              st == 400 and set(body.keys()) == {"error"} and body["error"])

        # ---------------------------------------------------------- #
        # 3. 200 失败原因（键序恰为 valid、reason）
        # ---------------------------------------------------------- #
        def expect_reason(name, payload, reason):
            st, body = verify(payload)
            check(name, st == 200
                  and list(body.keys()) == ["valid", "reason"]
                  and body == {"valid": False, "reason": reason})

        def with_receipt(**changes):
            bad_receipt = dict(receipt)
            bad_receipt.update(changes)
            return {"receipt": bad_receipt, "signature": signature,
                    "nonce": nonce}

        # 回执非法：缺键/多键
        missing = {k: v for k, v in receipt.items() if k != "status"}
        expect_reason("receipt 缺键 -> 回执非法",
                      {"receipt": missing, "signature": signature,
                       "nonce": nonce}, "回执非法")
        extra_key = dict(receipt)
        extra_key["zz"] = 1
        expect_reason("receipt 多键 -> 回执非法",
                      {"receipt": extra_key, "signature": signature,
                       "nonce": nonce}, "回执非法")
        # 回执非法：字段类型/取值
        for field, value in [
            ("issuer_did", ""), ("issuer_did", 1),
            ("credential_id", ""), ("credential_id", True),
            ("verifier_did", ""), ("verifier_did", []),
            ("status", "revoke"), ("status", ""), ("status", 7),
            ("updated_at", "2026-09-20 00:00:00"),
            ("updated_at", "2026-09-20T00:00:00.123Z"),
            ("updated_at", "2026-13-40T99:99:99Z"),
            ("issuer_key_version", 0), ("issuer_key_version", False),
            ("issuer_key_version", "1"), ("issuer_key_version", 1.5),
            ("verifier_key_version", 0), ("verifier_key_version", True),
            ("verifier_key_version", "1"),
            ("nonce", ""), ("nonce", 1), ("nonce", "a" * 257),
            ("reason", ""), ("reason", 7),
        ]:
            expect_reason(f"receipt.{field}={value!r} -> 回执非法",
                          with_receipt(**{field: value}), "回执非法")
        # suspended 的 reason 规则：null、空白、超长均非法
        expect_reason("suspended 缺 reason -> 回执非法",
                      with_receipt(status="suspended", reason=None),
                      "回执非法")
        expect_reason("suspended reason 带首尾空白 -> 回执非法",
                      with_receipt(status="suspended", reason=" 调查中 "),
                      "回执非法")
        expect_reason("suspended reason 257 码点 -> 回执非法",
                      with_receipt(status="suspended", reason="中" * 257),
                      "回执非法")
        # active/unknown/revoked 的 reason 允许 null 或非空字符串
        st, body = verify(with_receipt(status="revoked", reason=None))
        check("revoked + reason:null 结构合法（走到后续阶段）",
              st == 200 and body.get("reason") != "回执非法")
        st, body = verify(with_receipt(status="suspended", reason="调查中"))
        check("suspended + 裁剪后 reason 结构合法",
              st == 200 and body.get("reason") != "回执非法")

        # 回执结构与签名格式同时非法：回执非法优先（键缺属回执非法；
        # receipt 整体为数组在外层 400 拦截，不在此列）。
        bad_struct = {k: v for k, v in receipt.items() if k != "status"}
        expect_reason("回执缺键且签名乱码 -> 回执非法",
                      {"receipt": bad_struct, "signature": "!!!",
                       "nonce": nonce}, "回执非法")

        # nonce 错误：外层与回执内层不一致
        expect_reason("外层 nonce 不一致 -> nonce错误",
                      {"receipt": receipt, "signature": signature,
                       "nonce": "别的"}, "nonce错误")
        expect_reason("回执 nonce 被改 -> nonce错误",
                      with_receipt(nonce="别的"), "nonce错误")
        # nonce 错误优先于锚点/签名问题
        expect_reason("nonce 错误优先于锚点不可用",
                      {"receipt": dict(receipt, verifier_did="did:x"),
                       "signature": signature, "nonce": "别的"},
                      "nonce错误")

        # 锚点不可用：他租户无锚点
        st, body = verify(good, headers=OTHER)
        check("跨租户锚点不可用",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        # 锚点不可用：未知 DID / 版本不符
        expect_reason("未知验证者 -> 锚点不可用",
                      with_receipt(verifier_did="did:web:no-such.example"),
                      "锚点不可用")
        expect_reason("锚点版本不存在 -> 锚点不可用",
                      with_receipt(verifier_key_version=verifier_version + 1),
                      "锚点不可用")
        # 锚点不可用优先于签名格式
        expect_reason("锚点不可用优先于签名格式错误",
                      {"receipt": dict(receipt, verifier_did="did:web:no-such.example"),
                       "signature": "!!!", "nonce": nonce},
                      "锚点不可用")

        # 用途不含 status 的锚点不可用（用自有私钥构造格式合法的回执）。
        gen_priv, gen_pub = _keypair()
        gen_did = "did:web:generic-only.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": gen_did, "public_key": gen_pub,
                      "key_version": 1, "uses": ["generic"]}, T1)
        assert st in (200, 201), st
        gen_receipt = dict(receipt)
        gen_receipt["verifier_did"] = gen_did
        gen_receipt["verifier_key_version"] = 1
        gen_sig = crypto.sign(gen_receipt, gen_priv)
        expect_reason("锚点用途不含 status -> 锚点不可用",
                      {"receipt": gen_receipt, "signature": gen_sig,
                       "nonce": nonce}, "锚点不可用")

        # 签名格式错误：合法锚点 + 匹配 nonce
        expect_reason("签名非 base64url -> 签名格式错误",
                      {"receipt": receipt, "signature": "!!!",
                       "nonce": nonce}, "签名格式错误")
        expect_reason("签名带填充 -> 签名格式错误",
                      {"receipt": receipt, "signature": signature + "==",
                       "nonce": nonce}, "签名格式错误")
        expect_reason("签名长度错 -> 签名格式错误",
                      {"receipt": receipt, "signature": signature[:10],
                       "nonce": nonce}, "签名格式错误")

        # 签名校验失败：他人密钥签当前 receipt
        wrong_sig = crypto.sign(receipt, issuer_priv)
        expect_reason("他人签名 -> 签名校验失败",
                      {"receipt": receipt, "signature": wrong_sig,
                       "nonce": nonce}, "签名校验失败")
        # 签名校验失败：合法锚点回执被篡改（solo 锚点）
        tampered = dict(solo_receipt)
        tampered["updated_at"] = "2030-01-02T03:04:06Z"
        expect_reason("签名覆盖内容被改 -> 签名校验失败",
                      {"receipt": tampered, "signature": solo_sig,
                       "nonce": "only-here"}, "签名校验失败")

        # 托管验证者 DID 停用不影响验真（验真只看信任锚点）。
        st, _ = post(f"/v1/dids/{verifier_did}/deactivate",
                     {"reason": "验证者业务终止"}, T1)
        assert st == 200, st
        st, body = verify(good)
        check("验证者 DID 停用但锚点 active：仍验真成功",
              st == 200 and body == {"valid": True})

        # 吊销锚点后不可用。
        st, _ = _http(
            "PUT",
            f"{base}{ANCHORS_PATH}/{verifier_did}/{verifier_version}/status",
            payload={"status": "revoked"}, headers=T1)
        assert st == 200, st
        st, body = verify(good)
        check("锚点吊销 -> 锚点不可用",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 4. 只读：不写审计
        # ---------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=T1)
        assert st == 200
        for _ in range(3):
            verify(good)  # 锚点不可用
            verify({"receipt": receipt, "signature": "!!!",
                    "nonce": nonce})  # 锚点不可用（顺序）
            verify({"receipt": bad_struct, "signature": signature,
                    "nonce": nonce})  # 回执非法
            verify({"receipt": solo_receipt, "signature": solo_sig,
                    "nonce": "only-here"})  # 成功
        st, audit_after = get("/v1/audit?limit=200", headers=T1)
        check("任何验真结果均不写审计", audit_before == audit_after)

        # ---------------------------------------------------------- #
        # 5. 缺省租户头：default 租户内锚点不可用（隔离）
        # ---------------------------------------------------------- #
        st, body = verify(good, headers=None)
        check("缺省租户头 default 隔离",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 6. 重启稳定：结论一致
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, body = verify(good)
        check("重启后吊销锚点仍不可用",
              st == 200 and body == {"valid": False, "reason": "锚点不可用"})
        st, body = verify({"receipt": solo_receipt, "signature": solo_sig,
                           "nonce": "only-here"})
        check("重启后有效回执结论稳定",
              st == 200 and body == {"valid": True})
        st, body = verify({"receipt": receipt, "signature": "!!!",
                           "nonce": nonce})
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
