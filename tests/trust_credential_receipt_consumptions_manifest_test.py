#!/usr/bin/env python3
"""GET/POST /v1/trust/credentials/receipt/consumptions/manifest(/verify) 测试。

直接运行：python3 tests/trust_credential_receipt_consumptions_manifest_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- GET manifest：参数非法（未知/重复/空值/格式/范围、snapshot 缺失或越界、
  after 大于生效 snapshot、signer_did 缺失或为空）均 400 且仅
  {error: 非空中文}；签名 DID 未知/跨租户 404、已停用 409；200 键序恰为
  snapshot、filters、count、alg、digest、signer_did、key_version、
  signature，filters 键序 after、limit 且值为生效整数；count/digest 与
  同参数 export NDJSON 页一致；签名可用签名 DID 公钥验真；
- POST verify：外层非法（空体、非法 JSON、非对象、缺漏/多余字段、
  manifest 非对象、ndjson 非字符串）均 400 且仅 {error}；外层合法后按
  清单结构 -> 锚点（本租户同 did/版本且含 vc 用途的 active 锚点）->
  签名格式 -> 签名 -> 摘要/行数顺序，失败 200 恰返
  {valid:false,reason}（五种中文原因之一），成功仅 {"valid":true}；
- 租户隔离、纯只读不记审计、结论跨重启稳定。
"""

import hashlib
import json
import os
import re
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

MANIFEST_PATH = "/v1/trust/credentials/receipt/consumptions/manifest"
VERIFY_PATH = "/v1/trust/credentials/receipt/consumptions/manifest/verify"
EXPORT_PATH = "/v1/trust/credentials/receipt/consumptions/export"

SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
SIG_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{86}")


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = json.dumps(payload).encode() if payload is not None else None
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
    port = 9042
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

    def manifest_get(qs="", headers=None):
        return _http("GET", f"{base}{MANIFEST_PATH}{qs}", headers=headers)

    def verify_post(payload=None, headers=None, raw_body=None):
        return _http("POST", f"{base}{VERIFY_PATH}", payload=payload,
                     raw_body=raw_body, headers=headers)

    def expect_get_400(name, qs="", headers=None):
        st, raw = manifest_get(qs, headers=headers)
        try:
            r = json.loads(raw.decode() or "{}")
        except ValueError:
            r = {}
        check(f"GET 400 仅 error: {name}",
              st == 400 and list(r.keys()) == ["error"]
              and isinstance(r["error"], str) and r["error"])

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # ---- 准备：签名本地 DID + 本租户含 vc 用途的 active 锚点 ----
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "rcpt-signer"}, TA)
        assert st == 201, raw
        signer = json.loads(raw)
        signer_did, signer_pub = signer["did"], signer["public_key"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": 1}, TA)
        assert st == 201

        # 第二签名 DID：锚点 uses 不含 vc（验真时应判锚点不可用）
        st, raw = _http("POST", f"{base}/v1/dids",
                         {"method": "web", "public_key": "rcpt-signer2"}, TA)
        assert st == 201, raw
        signer2 = json.loads(raw)
        signer2_did, signer2_pub = signer2["did"], signer2["public_key"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer2_did, "public_key": signer2_pub,
                       "key_version": 1, "uses": ["generic"]}, TA)
        assert st == 201

        # 第三 DID：注册后停用（GET 应 409）
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "rcpt-signer3"}, TA)
        assert st == 201, raw
        signer3_did = json.loads(raw)["did"]
        st, _ = _http("POST", f"{base}/v1/dids/{signer3_did}/deactivate",
                      {}, TA)
        assert st == 200

        # 他租户 DID（跨租户签名应 404）
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "rcpt-other"}, TB)
        assert st == 201, raw
        other_did = json.loads(raw)["did"]

        # ---- 准备：两条回执消费历史事件 ----
        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:issuer-mf.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": issuer_did, "public_key": issuer_pub,
                       "key_version": 1}, TA)
        assert st == 201
        verifier = "did:web:verifier-mf.example"
        v_priv, v_pub = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": verifier, "public_key": v_pub,
                       "key_version": 1}, TA)
        assert st == 201

        def make_item(cid, nonce):
            body = {
                "credential_id": cid,
                "issuer_did": issuer_did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin"},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
            sig = crypto.sign(body, issuer_priv)
            receipt = {
                "credential_id": cid,
                "issuer_did": issuer_did,
                "issuer_key_version": 1,
                "credential_digest": hashlib.sha256(
                    crypto.canonicalize({"body": body, "signature": sig})
                ).hexdigest(),
                "verifier_did": verifier,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return {"receipt": receipt,
                    "receipt_signature": crypto.sign(receipt, v_priv),
                    "body": body, "signature": sig, "nonce": nonce}

        for i in (1, 2):
            st, raw = _http(
                "POST", f"{base}/v1/trust/credentials/receipt/consume",
                make_item(f"vc_mf_{i:04d}", f"mf-n-{i}"), TA)
            assert st == 200 and json.loads(raw).get("valid") is True, raw

        # ========================================================== #
        # 1. GET manifest：参数非法 -> 400 仅 {error: 非空中文}
        # ========================================================== #
        expect_get_400("未知参数", "?snapshot=1&signer_did=x&foo=1")
        expect_get_400("重复 limit", "?snapshot=1&limit=1&limit=2")
        expect_get_400("重复 after", "?snapshot=1&after=0&after=1")
        expect_get_400("重复 snapshot", "?snapshot=1&snapshot=1")
        expect_get_400("重复 signer_did",
                       f"?snapshot=1&signer_did={signer_did}"
                       f"&signer_did={signer_did}")
        expect_get_400("空 limit", "?snapshot=1&limit=")
        expect_get_400("空 after", "?snapshot=1&after=")
        expect_get_400("空 snapshot", "?snapshot=")
        expect_get_400("空 signer_did", "?snapshot=1&signer_did=")
        expect_get_400("缺 snapshot", f"?signer_did={signer_did}")
        expect_get_400("缺 signer_did", "?snapshot=1")
        expect_get_400("limit=0", "?snapshot=1&limit=0")
        expect_get_400("limit=10001", "?snapshot=1&limit=10001")
        expect_get_400("limit=-1", "?snapshot=1&limit=-1")
        expect_get_400("limit 小数", "?snapshot=1&limit=1.0")
        expect_get_400("limit 布尔词", "?snapshot=1&limit=true")
        expect_get_400("limit 含空白", "?snapshot=1&limit=%201")
        expect_get_400("limit Unicode 数字",
                       "?snapshot=1&limit=%E0%A5%91")
        expect_get_400("after=-1", "?snapshot=1&after=-1")
        expect_get_400("after=+1", "?snapshot=1&after=%2B1")
        expect_get_400("snapshot=-1", "?snapshot=-1")
        expect_get_400("snapshot 越界(3>2)",
                       f"?snapshot=3&signer_did={signer_did}")
        expect_get_400("after 大于生效 snapshot",
                       f"?snapshot=1&after=2&signer_did={signer_did}")
        expect_get_400("显式空租户头", "?snapshot=1&signer_did=x",
                       headers={"X-Tenant-ID": ""})

        # 400 优先于签名 DID 的 404/409
        st, raw = manifest_get("?snapshot=3&signer_did=did:web:no-such",
                               headers=TA)
        check("snapshot 越界优先于 404",
              st == 400 and list(json.loads(raw).keys()) == ["error"])

        # ========================================================== #
        # 2. GET manifest：签名 DID 未知/跨租户 404、停用 409
        # ========================================================== #
        st, raw = manifest_get("?snapshot=1&signer_did=did:web:no-such",
                               headers=TA)
        r = json.loads(raw)
        check("签名 DID 未知 -> 404 仅 error",
              st == 404 and list(r.keys()) == ["error"] and r["error"])
        st, raw = manifest_get(f"?snapshot=1&signer_did={other_did}",
                               headers=TA)
        check("跨租户签名 DID -> 404", st == 404)
        st, raw = manifest_get(f"?snapshot=1&signer_did={signer3_did}",
                               headers=TA)
        check("签名 DID 已停用 -> 409", st == 409)

        # ========================================================== #
        # 3. GET manifest：200 键序、filters、count/digest、签名
        # ========================================================== #
        st, raw = manifest_get(f"?snapshot=2&signer_did={signer_did}",
                               headers=TA)
        m_full = json.loads(raw)
        check("GET 200", st == 200)
        check("200 键序恰为 snapshot,filters,count,alg,digest,"
              "signer_did,key_version,signature",
              list(m_full.keys()) == ["snapshot", "filters", "count",
                                      "alg", "digest", "signer_did",
                                      "key_version", "signature"])
        check("filters 键序 after,limit 且为生效整数缺省值",
              list(m_full["filters"].keys()) == ["after", "limit"]
              and m_full["filters"] == {"after": 0, "limit": 1000})
        check("类型与取值合法",
              m_full["snapshot"] == 2
              and isinstance(m_full["count"], int)
              and not isinstance(m_full["count"], bool)
              and m_full["count"] == 2
              and m_full["alg"] == "SHA-256"
              and SHA256_HEX_RE.fullmatch(m_full["digest"])
              and m_full["signer_did"] == signer_did
              and m_full["key_version"] == 1
              and SIG_B64URL_RE.fullmatch(m_full["signature"]))

        # digest/count 与同参数 export NDJSON 页一致
        st, export_raw = _http("GET", f"{base}{EXPORT_PATH}?snapshot=2",
                               headers=TA)
        assert st == 200
        ndjson_text = export_raw.decode("utf-8")
        check("digest 等于同参数 export NDJSON 字节 SHA-256",
              m_full["digest"] == hashlib.sha256(export_raw).hexdigest())
        check("count 等于 NDJSON 行数",
              m_full["count"] == ndjson_text.count("\n") == 2)

        # 签名可用签名 DID 公钥验真（前七键规范化 JSON）
        signed = {k: m_full[k] for k in (
            "snapshot", "filters", "count", "alg", "digest",
            "signer_did", "key_version")}
        try:
            crypto.verify(signed, m_full["signature"], signer_pub)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("签名可被签名 DID 公钥验真", sig_ok)

        # 显式 limit/after：filters 记录生效值，分页与 export 一致
        st, raw = manifest_get(
            f"?snapshot=2&after=1&limit=1&signer_did={signer_did}", TA)
        m_page = json.loads(raw)
        st, export_raw2 = _http(
            "GET", f"{base}{EXPORT_PATH}?snapshot=2&after=1&limit=1",
            headers=TA)
        check("显式分页 filters 为生效整数",
              st == 200
              and m_page["filters"] == {"after": 1, "limit": 1}
              and m_page["count"] == 1
              and m_page["digest"]
              == hashlib.sha256(export_raw2).hexdigest())
        ndjson_page = export_raw2.decode("utf-8")

        # 空页清单（snapshot=0）
        st, raw = manifest_get(f"?snapshot=0&signer_did={signer_did}", TA)
        m_empty = json.loads(raw)
        check("空页清单 count=0 且 digest 为空字节 SHA-256",
              st == 200 and m_empty["count"] == 0
              and m_empty["digest"]
              == hashlib.sha256(b"").hexdigest())

        # ========================================================== #
        # 4. POST verify：外层非法 -> 400 仅 {error: 非空中文}
        # ========================================================== #
        def expect_verify_400(name, **kwargs):
            st, raw = verify_post(**kwargs)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"POST 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and r["error"])

        expect_verify_400("空体", raw_body=b"")
        expect_verify_400("非法 JSON", raw_body=b"not json")
        expect_verify_400("非对象(数组)", raw_body=b"[1,2]")
        expect_verify_400("缺 manifest", payload={"ndjson": ndjson_text})
        expect_verify_400("缺 ndjson", payload={"manifest": m_full})
        expect_verify_400("多余字段",
                          payload={"manifest": m_full,
                                   "ndjson": ndjson_text, "x": 1})
        expect_verify_400("manifest 非对象",
                          payload={"manifest": "x", "ndjson": ndjson_text})
        expect_verify_400("ndjson 非字符串",
                          payload={"manifest": m_full, "ndjson": 5})

        # ========================================================== #
        # 5. POST verify：成功与五种失败原因（按序）
        # ========================================================== #
        st, raw = verify_post(payload={"manifest": m_full,
                                       "ndjson": ndjson_text}, headers=TA)
        check("合法清单验真成功仅 {valid:true}",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = verify_post(payload={"manifest": m_page,
                                       "ndjson": ndjson_page}, headers=TA)
        check("分页清单验真成功", st == 200
              and json.loads(raw) == {"valid": True})
        st, raw = verify_post(payload={"manifest": m_empty, "ndjson": ""},
                              headers=TA)
        check("空页清单验真成功", st == 200
              and json.loads(raw) == {"valid": True})

        def expect_invalid(name, manifest, ndjson, reason):
            st, raw = verify_post(
                payload={"manifest": manifest, "ndjson": ndjson},
                headers=TA)
            r = json.loads(raw)
            check(f"200 失败原因[{reason}]: {name}",
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == reason)

        bad_struct = dict(m_full); bad_struct.pop("alg")
        expect_invalid("清单缺键", bad_struct, ndjson_text, "清单非法")
        bad_struct2 = json.loads(json.dumps(m_full))
        bad_struct2["filters"]["did"] = None
        expect_invalid("filters 多键", bad_struct2, ndjson_text, "清单非法")
        bad_struct3 = json.loads(json.dumps(m_full))
        bad_struct3["filters"]["after"] = None
        expect_invalid("filters after 非生效整数", bad_struct3,
                       ndjson_text, "清单非法")
        bad_struct4 = json.loads(json.dumps(m_full))
        bad_struct4["filters"]["limit"] = 0
        expect_invalid("filters limit 越界", bad_struct4,
                       ndjson_text, "清单非法")
        bad_struct5 = json.loads(json.dumps(m_full))
        bad_struct5["digest"] = "0" * 64
        # digest 被改后签名不再匹配 -> 签名校验失败（结构仍合法）
        expect_invalid("digest 合法形状但被改", bad_struct5,
                       ndjson_text, "签名校验失败")

        bad_anchor = json.loads(json.dumps(m_full))
        bad_anchor["signer_did"] = "did:web:no-such-anchor"
        expect_invalid("锚点不存在", bad_anchor, ndjson_text, "锚点不可用")

        # 锚点 uses 不含 vc -> 锚点不可用（用 signer2 现签一份清单）
        st, raw = manifest_get(f"?snapshot=2&signer_did={signer2_did}", TA)
        assert st == 200, raw
        m_no_vc = json.loads(raw)
        expect_invalid("锚点 uses 不含 vc", m_no_vc, ndjson_text,
                       "锚点不可用")

        bad_sigfmt = json.loads(json.dumps(m_full))
        bad_sigfmt["signature"] = "abc"
        expect_invalid("签名格式非法", bad_sigfmt, ndjson_text,
                       "签名格式错误")
        bad_sig = json.loads(json.dumps(m_full))
        bad_sig["signature"] = "A" * 86
        expect_invalid("签名形状合法但验签失败", bad_sig, ndjson_text,
                       "签名校验失败")
        expect_invalid("NDJSON 被篡改", m_full, ndjson_text + "{}\n",
                       "导出内容不匹配")
        expect_invalid("NDJSON 行数不符", m_full, "",
                       "导出内容不匹配")

        # ========================================================== #
        # 6. 租户隔离：缺省 default/跨租户 -> 锚点不可用；GET 404
        # ========================================================== #
        st, raw = verify_post(payload={"manifest": m_full,
                                       "ndjson": ndjson_text})
        check("缺省 default 租户验真 -> 锚点不可用",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "锚点不可用"})
        st, raw = verify_post(payload={"manifest": m_full,
                                       "ndjson": ndjson_text}, headers=TB)
        check("跨租户验真 -> 锚点不可用",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "锚点不可用"})
        st, raw = manifest_get(f"?snapshot=0&signer_did={signer_did}",
                               headers=TB)
        check("跨租户 GET 签名 DID -> 404", st == 404)

        # ========================================================== #
        # 7. 纯只读：审计不变；结论跨重启稳定
        # ========================================================== #
        _, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        manifest_get(f"?snapshot=2&signer_did={signer_did}", TA)
        verify_post(payload={"manifest": m_full, "ndjson": ndjson_text},
                    headers=TA)
        verify_post(payload={"manifest": bad_sig, "ndjson": ndjson_text},
                    headers=TA)
        _, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("GET/verify 均不记审计", audit_before == audit_after)

        proc.terminate(); proc.wait(timeout=10)
        proc = start()
        st, raw = verify_post(payload={"manifest": m_full,
                                       "ndjson": ndjson_text}, headers=TA)
        check("重启后同一清单仍验真成功",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = verify_post(payload={"manifest": bad_sig,
                                       "ndjson": ndjson_text}, headers=TA)
        check("重启后失败结论一致",
              st == 200 and json.loads(raw)
              == {"valid": False, "reason": "签名校验失败"})
        st, raw = manifest_get(f"?snapshot=2&signer_did={signer_did}", TA)
        m2 = json.loads(raw)
        check("重启后重签清单内容一致且可验真",
              st == 200
              and {k: m2[k] for k in (
                  "snapshot", "filters", "count", "alg", "digest",
                  "signer_did", "key_version")}
              == {k: m_full[k] for k in (
                  "snapshot", "filters", "count", "alg", "digest",
                  "signer_did", "key_version")})
        st, raw = verify_post(payload={"manifest": m2,
                                       "ndjson": ndjson_text}, headers=TA)
        check("重启后新签清单验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

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
