#!/usr/bin/env python3
"""GET manifest / POST manifest/verify 停用通告清单端到端测试。

直接运行：python3 tests/trust_did_deactivations_manifest_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
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

MANIFEST_PATH = "/v1/trust/dids/deactivations/manifest"
VERIFY_PATH = MANIFEST_PATH + "/verify"
EXPORT_PATH = "/v1/trust/dids/deactivations/export"
SYNC_PATH = "/v1/trust/dids/deactivate-sync"

MANIFEST_KEYS = [
    "snapshot",
    "filters",
    "count",
    "alg",
    "digest",
    "signer_did",
    "key_version",
    "signature",
]
FILTER_KEYS = ["after", "limit", "did", "key_version", "from", "to"]


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _http_raw(url, headers=None):
    req = urllib.request.Request(url, method="GET")
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
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
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
    port = 9017
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def manifest_get(query="", headers=None):
        url = f"{base}{MANIFEST_PATH}?{query}" if query else base + MANIFEST_PATH
        return _http_raw(url, headers=headers)

    def manifest_json(query="", headers=None):
        st, raw = manifest_get(query, headers=headers)
        try:
            return st, json.loads(raw.decode() or "{}")
        except ValueError:
            return st, {}

    def verify(payload, headers=None):
        return _http("POST", base + VERIFY_PATH, payload, headers=headers)

    def verify_raw(raw_body, headers=None):
        return _http(
            "POST", base + VERIFY_PATH, raw_body=raw_body, headers=headers
        )

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # ---------------------------------------------------------- #
        # 0. 无事件：参数非法先判（snapshot 必填）
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, r = manifest_json(query, headers=headers)
            check(f"400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("缺 snapshot 与 signer_did", "")
        expect_400("仅 snapshot 缺 signer_did", "snapshot=0")
        expect_400("仅 signer_did 缺 snapshot",
                   "signer_did=did:example:x")
        expect_400("snapshot 空值", "snapshot=&signer_did=did:example:x")
        expect_400("snapshot 非数字", "snapshot=abc&signer_did=did:example:x")
        expect_400("snapshot 负数", "snapshot=-1&signer_did=did:example:x")
        expect_400("snapshot 越界(无事件)",
                   "snapshot=1&signer_did=did:example:x")
        expect_400("snapshot 重复",
                   "snapshot=0&snapshot=1&signer_did=did:example:x")
        expect_400("signer_did 空值", "snapshot=0&signer_did=")
        expect_400("signer_did 重复",
                   "snapshot=0&signer_did=a&signer_did=b")
        expect_400("未知参数", "snapshot=0&signer_did=a&unknown=1")
        expect_400("limit=0", "snapshot=0&signer_did=a&limit=0")
        expect_400("limit 越界", "snapshot=0&signer_did=a&limit=10001")
        expect_400("after 负数", "snapshot=0&signer_did=a&after=-1")
        expect_400("key_version=0",
                   "snapshot=0&signer_did=a&key_version=0")
        expect_400("from 非 ASCII 数字",
                   "snapshot=0&signer_did=a&from=%E0%A9%91")
        expect_400("to 非 ASCII 数字",
                   "snapshot=0&signer_did=a&to=%E0%A9%91")
        expect_400("from 晚于 to",
                   "snapshot=0&signer_did=a"
                   "&from=2026-03-01T00:00:00Z&to=2026-02-01T00:00:00Z")
        expect_400("显式空 X-Tenant-ID", "snapshot=0&signer_did=a",
                   headers={"X-Tenant-ID": ""})

        # 签名 DID 未知（snapshot=0 合法）-> 404
        st, r = manifest_json("snapshot=0&signer_did=did:example:unknown",
                              headers=TA)
        check("未知签名 DID 404", st == 404 and "error" in r)

        # ---------------------------------------------------------- #
        # 1. 准备：本地签名 DID + 同 DID/版本信任锚点 + 外部通告
        # ---------------------------------------------------------- #
        st, signer = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "signer-handle"},
                           headers=TA)
        assert st == 201, signer
        signer_did = signer["did"]
        signer_pub = signer["public_key"]
        signer_ver = signer["key_version"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": signer_ver}, headers=TA)
        assert st == 201

        did_a = "did:web:man-a.example"
        did_b = "did:web:man-b.example"
        priv_a, pub_a = _keypair()
        priv_b, pub_b = _keypair()
        for did, pub, ver in ((did_a, pub_a, 1), (did_b, pub_b, 2)):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub, "key_version": ver},
                          headers=TA)
            assert st == 201

        def make_body(did, key_version=1, reason="机构业务终止",
                      deactivated_at="2026-09-20T10:00:00Z"):
            return {"did": did, "key_version": key_version,
                    "reason": reason, "deactivated_at": deactivated_at}

        body_b = make_body(did_b, key_version=2,
                           deactivated_at="2026-02-01T00:00:00Z")
        body_a = make_body(did_a, deactivated_at="2026-01-01T00:00:00Z")
        for body, priv in ((body_b, priv_b), (body_a, priv_a)):
            st, r = _http("POST", f"{base}{SYNC_PATH}",
                          {"body": body, "signature": crypto.sign(body, priv)},
                          headers=TA)
            assert st == 201, r

        # ---------------------------------------------------------- #
        # 2. 200 清单形状与摘要/计数
        # ---------------------------------------------------------- #
        st, export_raw = _http_raw(
            f"{base}{EXPORT_PATH}?snapshot=2", headers=TA)
        assert st == 200
        ndjson_text = export_raw.decode("utf-8")

        st, m = manifest_json(f"snapshot=2&signer_did={signer_did}", TA)
        check("清单 200", st == 200)
        check("清单八键固定顺序", list(m.keys()) == MANIFEST_KEYS)
        check("filters 六键固定顺序", list(m["filters"].keys()) == FILTER_KEYS)
        check("缺省过滤项为 null",
              m["filters"] == {"after": None, "limit": None, "did": None,
                               "key_version": None, "from": None, "to": None})
        check("snapshot/count/alg/签名 DID 字段",
              m["snapshot"] == 2 and m["count"] == 2 and m["alg"] == "SHA-256"
              and m["signer_did"] == signer_did
              and m["key_version"] == signer_ver)
        check("digest 为 64 位小写 hex",
              isinstance(m["digest"], str)
              and len(m["digest"]) == 64
              and all(c in "0123456789abcdef" for c in m["digest"]))
        check("digest 等于 NDJSON 字节 SHA-256",
              m["digest"] == hashlib.sha256(export_raw).hexdigest())
        check("signature 非空字符串", isinstance(m["signature"], str)
              and bool(m["signature"]))

        # 签名字节可变（同参数两次签名不同）
        _, m2 = manifest_json(f"snapshot=2&signer_did={signer_did}", TA)
        check("签名字节可变", m["signature"] != m2["signature"])

        # 显式过滤项写回 filters
        q = (f"snapshot=2&signer_did={signer_did}&after=0&limit=1000"
             f"&did={did_b}&key_version=2"
             "&from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z")
        st, mf = manifest_json(q, TA)
        check("显式 filters 生效值",
              st == 200 and mf["filters"] == {
                  "after": 0, "limit": 1000, "did": did_b,
                  "key_version": 2, "from": "2026-01-01T00:00:00Z",
                  "to": "2026-12-31T00:00:00Z"}
              and mf["count"] == 1)

        # ---------------------------------------------------------- #
        # 3. verify 成功（含跨重启稳定）
        # ---------------------------------------------------------- #
        st, r = verify({"manifest": m, "ndjson": ndjson_text}, headers=TA)
        check("验真成功 200 仅 valid:true",
              st == 200 and r == {"valid": True})

        # 第二份（不同签名）同样可验
        st, r = verify({"manifest": m2, "ndjson": ndjson_text}, headers=TA)
        check("不同签名字节均验真成功", st == 200 and r == {"valid": True})

        # 只读：清单与验真不记审计
        st, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        manifest_json(f"snapshot=2&signer_did={signer_did}", TA)
        verify({"manifest": m, "ndjson": ndjson_text}, headers=TA)
        st, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("清单/验真不记审计", audit_before == audit_after)

        # 跨重启验真稳定
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, r = verify({"manifest": m, "ndjson": ndjson_text}, headers=TA)
        check("跨重启验真稳定", st == 200 and r == {"valid": True})

        # 租户隔离：B 无该锚点 -> 锚点不可用
        st, r = verify({"manifest": m, "ndjson": ndjson_text}, headers=TB)
        check("他租户锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 4. verify 外层错误 -> 400 仅 {error}
        # ---------------------------------------------------------- #
        def expect_verify_400(name, payload=None, raw_body=None):
            if raw_body is not None:
                st, r = verify_raw(raw_body, headers=TA)
            else:
                st, r = verify(payload, headers=TA)
            check(f"verify 外层 400: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_verify_400("空体", raw_body=b"")
        expect_verify_400("非法 JSON", raw_body=b"{not json")
        expect_verify_400("非对象", raw_body=b"[1,2]")
        expect_verify_400("缺 manifest", {"ndjson": "x\n"})
        expect_verify_400("缺 ndjson", {"manifest": m})
        expect_verify_400("多余字段",
                          {"manifest": m, "ndjson": ndjson_text, "x": 1})
        expect_verify_400("manifest 非对象",
                          {"manifest": "x", "ndjson": "y\n"})
        expect_verify_400("ndjson 非字符串",
                          {"manifest": m, "ndjson": 123})

        # ---------------------------------------------------------- #
        # 5. verify 各类 200 失败原因（顺序固定）
        # ---------------------------------------------------------- #
        def expect_invalid(name, manifest_obj, text=ndjson_text,
                           reason=None):
            st, r = verify({"manifest": manifest_obj, "ndjson": text},
                           headers=TA)
            cond = st == 200 and r.get("valid") is False and isinstance(
                r.get("reason"), str) and bool(r.get("reason"))
            if reason is not None:
                cond = cond and r.get("reason") == reason
            check(name, cond)

        # 清单非法：结构/取值问题（先于锚点判定）
        bad = json.loads(json.dumps(m))
        del bad["alg"]
        expect_invalid("缺键 -> 清单非法", bad, reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["extra"] = 1
        expect_invalid("多键 -> 清单非法", bad, reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["count"] = -1
        expect_invalid("count 负数 -> 清单非法", bad, reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["alg"] = "SHA-512"
        expect_invalid("alg 非 SHA-256 -> 清单非法", bad,
                       reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["digest"] = "z" * 64
        expect_invalid("digest 非小写 hex -> 清单非法", bad,
                       reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["snapshot"] = -1
        expect_invalid("snapshot 负数 -> 清单非法", bad,
                       reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["filters"]["from"] = "not-a-time"
        expect_invalid("filters.from 非法 -> 清单非法", bad,
                       reason="清单非法")
        bad = json.loads(json.dumps(m))
        bad["filters"] = {"after": 0}
        expect_invalid("filters 缺键 -> 清单非法", bad,
                       reason="清单非法")

        # 锚点不可用：结构合法且签名本可验，但吊销锚点
        st, _ = _http(
            "PUT",
            f"{base}/v1/trust/anchors/{signer_did}/{signer_ver}/status",
            {"status": "revoked"}, headers=TA)
        assert st == 200
        expect_invalid("锚点吊销 -> 锚点不可用", m,
                       reason="锚点不可用")
        # 恢复一个新锚点版本不影响：重新注册同版本（PEM 相同）为幂等重试，
        # 仍为 revoked；改用租户 B 已覆盖缺失情形。这里直接验证顺序：
        # 签名格式错误在锚点可用时才出现，故先重建 active 锚点（新 DID）。
        st, signer2 = _http("POST", f"{base}/v1/dids",
                            {"method": "example",
                             "public_key": "signer-handle-2"}, headers=TA)
        assert st == 201
        signer2_did = signer2["did"]
        signer2_pub = signer2["public_key"]
        signer2_ver = signer2["key_version"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer2_did, "public_key": signer2_pub,
                       "key_version": signer2_ver}, headers=TA)
        assert st == 201
        _, m3 = manifest_json(f"snapshot=2&signer_did={signer2_did}", TA)

        # 签名格式错误
        bad = json.loads(json.dumps(m3))
        bad["signature"] = "abc"
        expect_invalid("签名编码非法 -> 签名格式错误", bad,
                       reason="签名格式错误")

        # 签名校验失败：保持 86 字符 base64url 但改动签名
        bad = json.loads(json.dumps(m3))
        sig = bad["signature"]
        flipped = ("A" if sig[-1] != "A" else "B")
        bad["signature"] = sig[:-1] + flipped
        expect_invalid("签名被改 -> 签名校验失败", bad,
                       reason="签名校验失败")

        # 导出内容不匹配：清单签名有效但提交 ndjson 被改（count/digest
        # 由服务端与签名绑定，篡改文本即与摘要不符）
        expect_invalid("ndjson 与摘要不符 -> 导出内容不匹配",
                       m3, text=ndjson_text + " ",
                       reason="导出内容不匹配")
        expect_invalid("改 ndjson 末字节 -> 导出内容不匹配",
                       m3, text=ndjson_text.rstrip("\n") + " \n",
                       reason="导出内容不匹配")

        # 用合法清单+正确签名但错误文本，确认走到内容比对（非签名失败）
        st, r = verify({"manifest": m3,
                        "ndjson": ndjson_text.replace("\n", "\r\n")},
                       headers=TA)
        check("CRLF 文本 -> 导出内容不匹配（签名仍有效）",
              st == 200 and r == {"valid": False,
                                  "reason": "导出内容不匹配"})

        # ---------------------------------------------------------- #
        # 6. 签名 DID 停用 -> 409（最后做，终态）
        # ---------------------------------------------------------- #
        st, _ = _http("POST",
                      f"{base}/v1/dids/{signer2_did}/deactivate",
                      {"reason": "签名方业务终止"}, headers=TA)
        assert st == 200
        st, r = manifest_json(f"snapshot=2&signer_did={signer2_did}", TA)
        check("已停用签名 DID 409", st == 409 and "error" in r)

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store):
            os.remove(store)

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
