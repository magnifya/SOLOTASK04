#!/usr/bin/env python3
"""GET/POST /v1/trust/credentials/receipt/consumptions/manifest 回执消费
历史签名清单端到端测试。

直接运行：python3 tests/trust_credential_receipt_consumptions_manifest_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- GET：取既有 export 的 limit、after、snapshot（snapshot 必填且不得越界）
  与唯一非空 signer_did；越界等 400 优先，未知/他租户签名 DID 404，已停用
  409，错误仅 {"error"}；不接受 verifier_did 等 export 之外的参数；
- 200 键序 snapshot,filters,count,alg,digest,signer_did,key_version,
  signature；filters 键序恰为 after,limit 且值为生效整数（含缺省 0/1000）；
  count 非负整数；alg=SHA-256；digest 为同参数回执 NDJSON 页字节的 64 位
  小写 hex；签名由签名 DID 当前私钥对前七键 ES256 裸签名；纯只读；
- POST /verify：外层错误 400 仅 {error}；外层合法后按序返回
  “清单非法”“锚点不可用”（须本租户同 did/版本且含 vc 用途的 active
  锚点）“签名格式错误”“签名校验失败”“导出内容不匹配”，成功仅
  {"valid":true}；租户隔离、跨重启稳定。
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

MANIFEST_PATH = "/v1/trust/credentials/receipt/consumptions/manifest"
VERIFY_PATH = MANIFEST_PATH + "/verify"
EXPORT_PATH = "/v1/trust/credentials/receipt/consumptions/export"
RECEIPT_PATH = "/v1/trust/credentials/verify-receipt"
CONSUME_PATH = "/v1/trust/credentials/receipt/consume"
MANIFEST_KEYS = [
    "snapshot", "filters", "count", "alg",
    "digest", "signer_did", "key_version", "signature",
]
FILTER_KEYS = ["after", "limit"]


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
    port = 9027
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
        return _http("GET", url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # ---- 准备：外部签发者锚点 + 本地签名/验证者 DID（含 vc 锚点）----
        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:rcm-issuer.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": issuer_did, "public_key": issuer_pub,
                       "key_version": 1}, TA)
        assert st == 201, st

        _http("POST", f"{base}/v1/dids",
              {"method": "web", "public_key": "rcm-signer"}, TA)
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "rcm-signer"}, TA)
        assert st == 201, raw
        signer = json.loads(raw)
        signer_did, signer_pub = signer["did"], signer["public_key"]

        # ---------------------------------------------------------- #
        # 1. 400 族：仅 {error} 非空中文
        # ---------------------------------------------------------- #
        def expect_400(name, query, headers=None):
            st, raw = manifest_get(query, headers=headers)
            try:
                r = json.loads(raw.decode() or "{}")
            except ValueError:
                r = {}
            check(f"400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_400("缺 snapshot", f"signer_did={signer_did}")
        expect_400("snapshot 空值", f"snapshot=&signer_did={signer_did}")
        expect_400("snapshot 负数", f"snapshot=-1&signer_did={signer_did}")
        expect_400("snapshot 小数", f"snapshot=1.0&signer_did={signer_did}")
        expect_400("snapshot 越界(无事件)", f"snapshot=1&signer_did={signer_did}")
        expect_400("snapshot Unicode 数字",
                   "snapshot=%E0%A9%91&signer_did=x")
        expect_400("snapshot 重复",
                   f"snapshot=0&snapshot=1&signer_did={signer_did}")
        expect_400("缺 signer_did", "snapshot=0")
        expect_400("signer_did 空值", "snapshot=0&signer_did=")
        expect_400("signer_did 重复", "snapshot=0&signer_did=a&signer_did=b")
        expect_400("未知参数 verifier_did",
                   f"snapshot=0&signer_did={signer_did}&verifier_did=x")
        expect_400("未知参数 x", f"snapshot=0&signer_did={signer_did}&x=1")
        expect_400("limit=0", f"snapshot=0&signer_did={signer_did}&limit=0")
        expect_400("limit=10001",
                   f"snapshot=0&signer_did={signer_did}&limit=10001")
        expect_400("after 负数", f"snapshot=0&signer_did={signer_did}&after=-1")
        expect_400("after 越界大于 snapshot",
                   f"snapshot=0&signer_did={signer_did}&after=1")
        st, _ = manifest_get("snapshot=0&signer_did=x",
                             headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---------------------------------------------------------- #
        # 2. 404 / 409（400 越界优先）
        # ---------------------------------------------------------- #
        st, _ = manifest_get("snapshot=0&signer_did=did:web:unknown", TA)
        check("未知签名 DID 404", st == 404)
        st, _ = manifest_get(f"snapshot=0&signer_did={signer_did}", TB)
        check("他租户签名 DID 404", st == 404)

        _http("POST", f"{base}/v1/dids",
              {"method": "web", "public_key": "rcm-dead-signer"}, TA)
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "rcm-dead-signer"}, TA)
        dead_did = json.loads(raw)["did"]
        st, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                      {"reason": "机构终止"}, TA)
        assert st == 200
        st, _ = manifest_get(f"snapshot=0&signer_did={dead_did}", TA)
        check("已停用签名 DID 409", st == 409)
        st, _ = manifest_get(f"snapshot=99&signer_did={dead_did}", TA)
        check("越界 snapshot 优先于 409", st == 400)

        # ---------------------------------------------------------- #
        # 3. 空页清单 200：键序、filters 生效整数、digest(空)、签名
        # ---------------------------------------------------------- #
        st, raw = manifest_get(f"snapshot=0&signer_did={signer_did}", TA)
        check("空清单 200", st == 200)
        m = json.loads(raw)
        check("响应键序固定", list(m.keys()) == MANIFEST_KEYS)
        check("filters 恰两键且键序/缺省生效值",
              list(m["filters"].keys()) == FILTER_KEYS
              and m["filters"] == {"after": 0, "limit": 1000})
        check("空页 count=0", m["count"] == 0)
        check("alg=SHA-256", m["alg"] == "SHA-256")
        check("空字节 digest",
              m["digest"] == hashlib.sha256(b"").hexdigest()
              and len(m["digest"]) == 64
              and m["digest"] == m["digest"].lower())
        check("签名 DID/版本",
              m["signer_did"] == signer_did and m["key_version"] == 1
              and isinstance(m["signature"], str) and m["signature"])
        signed = {k: m[k] for k in MANIFEST_KEYS[:7]}
        try:
            crypto.verify(signed, m["signature"], signer_pub)
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("签名可由签名 DID 公钥验证（前七键）", sig_ok)

        # ---------------------------------------------------------- #
        # 4. 制造一条回执消费记录，非空清单 digest 与 export 字节一致
        # ---------------------------------------------------------- #
        # 以签名 DID 作为验证者登记含 vc 用途的本租户 active 锚点
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": 1}, TA)
        assert st in (200, 201)

        body = {
            "credential_id": "vc_rcm_0001",
            "issuer_did": issuer_did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, issuer_priv)
        nonce = "nonce-清单-001"
        st, raw = _http("POST", f"{base}{RECEIPT_PATH}",
                        {"body": body, "signature": sig,
                         "verifier_did": signer_did, "nonce": nonce}, TA)
        assert st == 200 and json.loads(raw)["valid"] is True, raw
        receipt_pack = json.loads(raw)
        st, raw = _http("POST", f"{base}{CONSUME_PATH}",
                        {"receipt": receipt_pack["receipt"],
                         "receipt_signature": receipt_pack["receipt_signature"],
                         "body": body, "signature": sig, "nonce": nonce}, TA)
        assert st == 200 and json.loads(raw)["valid"] is True, raw

        st, raw = manifest_get(f"snapshot=1&signer_did={signer_did}", TA)
        m1 = json.loads(raw)
        check("非空清单 200/快照/count",
              st == 200 and m1["snapshot"] == 1 and m1["count"] == 1)
        st, export_raw = _http(
            "GET", f"{base}{EXPORT_PATH}?snapshot=1", headers=TA)
        assert st == 200
        check("digest = 同参数 export NDJSON 字节 SHA-256",
              m1["digest"] == hashlib.sha256(export_raw).hexdigest())
        ndjson_text = export_raw.decode("utf-8")
        check("导出行数为 1", ndjson_text.count("\n") == 1)

        # filters 显式生效值回显（仍恰 after、limit 两键）
        st, raw = manifest_get(
            f"snapshot=1&signer_did={signer_did}&after=0&limit=10", TA)
        mf = json.loads(raw)
        check("filters 显式值按序回显",
              list(mf["filters"].keys()) == FILTER_KEYS
              and mf["filters"] == {"after": 0, "limit": 10}
              and mf["count"] == 1 and mf["digest"] == m1["digest"])

        # 纯只读：审计不变
        _, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        manifest_get(f"snapshot=1&signer_did={signer_did}", TA)
        _, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("清单生成不记审计", audit_before == audit_after)

        # ---------------------------------------------------------- #
        # 5. verify：外层 400 仅 {error}
        # ---------------------------------------------------------- #
        def verify(payload=None, raw_body=None, headers=TA):
            return _http("POST", f"{base}{VERIFY_PATH}", payload=payload,
                         raw_body=raw_body, headers=headers)

        def expect_outer_400(name, **kwargs):
            st, raw = verify(**kwargs)
            r = json.loads(raw.decode() or "{}")
            check(f"verify 外层 400: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and bool(r["error"]))

        expect_outer_400("非法 JSON", raw_body=b"not json")
        expect_outer_400("非对象", raw_body=b"[1,2]")
        expect_outer_400("空体", raw_body=b"")
        expect_outer_400("缺 manifest", payload={"ndjson": ndjson_text})
        expect_outer_400("缺 ndjson", payload={"manifest": m1})
        expect_outer_400("多余字段",
                         payload={"manifest": m1, "ndjson": "", "x": 1})
        expect_outer_400("manifest 非对象",
                         payload={"manifest": "x", "ndjson": ""})
        expect_outer_400("ndjson 非字符串",
                         payload={"manifest": m1, "ndjson": 5})

        def verify_result(manifest_obj, ndjson_str):
            st, raw = verify({"manifest": manifest_obj,
                              "ndjson": ndjson_str})
            return st, json.loads(raw.decode())

        def invalid(name, manifest_obj, reason):
            st, r = verify_result(manifest_obj, ndjson_text)
            check(name, st == 200 and r == {"valid": False, "reason": reason})

        # 成功
        st, r = verify_result(m1, ndjson_text)
        check("正确清单+导出 valid:true", st == 200 and r == {"valid": True})
        st, raw = manifest_get(f"snapshot=0&signer_did={signer_did}", TA)
        m0 = json.loads(raw)
        check("空页清单+空串 valid:true",
              verify_result(m0, "") == (200, {"valid": True}))

        # ---------------------------------------------------------- #
        # 6. verify：五段失败原因（按序短路）
        # ---------------------------------------------------------- #
        bad = json.loads(json.dumps(m1)); bad.pop("alg")
        invalid("缺键 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["alg"] = "SHA-512"
        invalid("alg 非 SHA-256 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["digest"] = "g" * 64
        invalid("digest 非小写 hex -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["count"] = -1
        invalid("count 负数 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["snapshot"] = True
        invalid("snapshot 布尔 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["key_version"] = 0
        invalid("key_version 非正整数 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["filters"] = {"after": 0}
        invalid("filters 缺 limit -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1))
        bad["filters"] = {"after": 0, "limit": 1000, "did": None}
        invalid("filters 多键 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["filters"]["limit"] = 0
        invalid("filters.limit=0 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["filters"]["after"] = -1
        invalid("filters.after 负数 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["filters"]["limit"] = 10001
        invalid("filters.limit 越界 -> 清单非法", bad, "清单非法")

        bad = json.loads(json.dumps(m1)); bad["signer_did"] = "did:web:other"
        invalid("未知锚点 -> 锚点不可用", bad, "锚点不可用")
        bad = json.loads(json.dumps(m1)); bad["key_version"] = 9
        invalid("版本无锚点 -> 锚点不可用", bad, "锚点不可用")

        # active 锚点但不含 vc 用途 -> 锚点不可用
        no_vc_priv, no_vc_pub = _keypair()
        no_vc_did = "did:web:no-vc.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": no_vc_did, "public_key": no_vc_pub,
                       "key_version": 1, "uses": ["vp"]}, TA)
        assert st == 201
        bad = json.loads(json.dumps(m1)); bad["signer_did"] = no_vc_did
        invalid("锚点缺 vc 用途 -> 锚点不可用", bad, "锚点不可用")

        # 吊销锚点 -> 不可用
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{signer_did}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        invalid("已吊销锚点 -> 锚点不可用", m1, "锚点不可用")

        # 轮换签名 DID 到 v2 并登记 v2 锚点（全用途，含 vc）
        st, _ = _http("POST", f"{base}/v1/dids/{signer_did}/keys/rotate",
                      {"key_handle": "rcm-signer-v2"}, TA)
        assert st == 200
        _, raw = _http("GET", f"{base}/v1/dids/{signer_did}", headers=TA)
        srec = json.loads(raw)
        assert srec["key_version"] == 2
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": srec["public_key"],
                       "key_version": 2}, TA)
        assert st in (200, 201)
        _, raw = manifest_get(f"snapshot=1&signer_did={signer_did}", TA)
        m2 = json.loads(raw)
        check("GET 用当前 v2 私钥签署", m2["key_version"] == 2)

        bad = json.loads(json.dumps(m2)); bad["signature"] = "abc"
        invalid("签名过短 -> 签名格式错误", bad, "签名格式错误")
        bad = json.loads(json.dumps(m2)); bad["signature"] = "A" * 86
        invalid("规范长度但值错误 -> 签名校验失败", bad, "签名校验失败")

        st, r = verify_result(m2, ndjson_text)
        check("v2 正确清单 valid:true", st == 200 and r == {"valid": True})

        st, r = verify_result(m2, ndjson_text + '{"cursor":2}\n')
        check("NDJSON 字节改动 -> 导出内容不匹配",
              st == 200 and r == {"valid": False, "reason": "导出内容不匹配"})
        st, r = verify_result(m2, "")
        check("空 NDJSON 对 count=1 -> 导出内容不匹配",
              st == 200 and r == {"valid": False, "reason": "导出内容不匹配"})
        # 行数与 count 不符但签名合法（恶意签名者自签清单）-> 导出内容不匹配
        evil_priv, evil_pub = _keypair()
        evil_did = "did:web:evil-manifest.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": evil_did, "public_key": evil_pub,
                       "key_version": 1, "uses": ["vc"]}, TA)
        assert st == 201
        evil_manifest = {
            "snapshot": m2["snapshot"],
            "filters": m2["filters"],
            "count": 2,
            "alg": "SHA-256",
            "digest": hashlib.sha256(ndjson_text.encode("utf-8")).hexdigest(),
            "signer_did": evil_did,
            "key_version": 1,
        }
        evil_manifest["signature"] = crypto.sign(evil_manifest, evil_priv)
        st, r = verify_result(evil_manifest, ndjson_text)
        check("合法签名但行数不符 -> 导出内容不匹配",
              st == 200 and r == {"valid": False, "reason": "导出内容不匹配"})

        # 租户隔离：tenant-b 无签名 DID 锚点
        req = urllib.request.Request(
            f"{base}{VERIFY_PATH}",
            data=json.dumps({"manifest": m2, "ndjson": ndjson_text}).encode(),
            method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Tenant-ID", "tenant-b")
        try:
            with urllib.request.urlopen(req) as resp:
                rb = json.loads(resp.read()); rcode = resp.status
        except urllib.error.HTTPError as exc:
            rcode, rb = exc.code, json.loads(exc.read())
        check("verify 租户隔离 -> 锚点不可用",
              rcode == 200 and rb == {"valid": False,
                                      "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 7. 跨重启：已签发清单仍可验真，重新生成的清单也通过
        # ---------------------------------------------------------- #
        captured = (m2, ndjson_text)
        proc.terminate(); proc.wait(timeout=10)
        proc = start()
        check("重启后捕获清单仍 valid",
              verify_result(captured[0], captured[1])
              == (200, {"valid": True}))
        _, raw = manifest_get(f"snapshot=1&signer_did={signer_did}", TA)
        m3 = json.loads(raw)
        check("重启后重新生成清单可验真（签名字节可变）",
              verify_result(m3, ndjson_text) == (200, {"valid": True}))

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
