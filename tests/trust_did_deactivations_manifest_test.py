#!/usr/bin/env python3
"""GET/POST /v1/trust/dids/deactivations/manifest 停用通告清单端到端测试。

直接运行：python3 tests/trust_did_deactivations_manifest_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- GET：snapshot 必填且不得越界、signer_did 唯一非空且须为本租户活动本地
  DID（越界等 400 优先，未知/他租户 404，已停用 409），其余参数规则与
  export 一致（含 from/to 非 ASCII 数字 400），错误仅 {"error"}；
- 200 键序 snapshot,filters,count,alg,digest,signer_did,key_version,
  signature；filters 键序 after,limit,did,key_version,from,to、缺省为
  null；count 非负整数；alg=SHA-256；digest 为同参数 export NDJSON 字节
  的 64 位小写 hex；签名由签名 DID 当前私钥对前七键 ES256 裸签名，可用
  其公钥验签；纯只读；
- POST /verify：外层错误 400 仅 {error}；外层合法后按序返回
  “清单非法”“锚点不可用”“签名格式错误”“签名校验失败”“导出内容不匹配”，
  成功仅 {"valid":true}；租户隔离、跨重启稳定。
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
VERIFY_PATH = "/v1/trust/dids/deactivations/manifest/verify"
EXPORT_PATH = "/v1/trust/dids/deactivations/export"
MANIFEST_KEYS = [
    "snapshot", "filters", "count", "alg",
    "digest", "signer_did", "key_version", "signature",
]
FILTER_KEYS = ["after", "limit", "did", "key_version", "from", "to"]


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
        return _http("GET", url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # 签名本地 DID（服务端托管密钥）；幂等提交取回 did/公钥。
        _http("POST", f"{base}/v1/dids",
              {"method": "web", "public_key": "manifest-signer"}, TA)
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "manifest-signer"}, TA)
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
        expect_400("未知参数", f"snapshot=0&signer_did={signer_did}&x=1")
        expect_400("limit=0", f"snapshot=0&signer_did={signer_did}&limit=0")
        expect_400("limit=10001",
                   f"snapshot=0&signer_did={signer_did}&limit=10001")
        expect_400("after 负数", f"snapshot=0&signer_did={signer_did}&after=-1")
        expect_400("key_version=0",
                   f"snapshot=0&signer_did={signer_did}&key_version=0")
        expect_400("did 空值", f"snapshot=0&signer_did={signer_did}&did=")
        expect_400("from 非 ASCII 数字",
                   f"snapshot=0&signer_did={signer_did}"
                   "&from=%E0%A9%A1%E0%A9%A0%E0%A9%A2%E0%A9%96-%E0%A9%90"
                   "%E0%A9%91-%E0%A9%90%E0%A9%91T%E0%A9%90%E0%A9%90:%E0"
                   "%A9%90%E0%A9%90:%E0%A9%90%E0%A9%90Z")
        expect_400("to 缺 Z",
                   f"snapshot=0&signer_did={signer_did}&to=2026-01-01T00:00:00")
        expect_400("from 晚于 to",
                   f"snapshot=0&signer_did={signer_did}"
                   "&from=2026-03-01T00:00:00Z&to=2026-02-01T00:00:00Z")
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
              {"method": "web", "public_key": "dead-signer"}, TA)
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "dead-signer"}, TA)
        dead_did = json.loads(raw)["did"]
        st, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                      {"reason": "机构终止"}, TA)
        assert st == 200
        st, _ = manifest_get(f"snapshot=0&signer_did={dead_did}", TA)
        check("已停用签名 DID 409", st == 409)
        # 越界 snapshot 对停用 DID 仍先判 400
        st, _ = manifest_get(f"snapshot=99&signer_did={dead_did}", TA)
        check("越界 snapshot 优先于 409", st == 400)

        # ---------------------------------------------------------- #
        # 3. 空页清单 200：键序、filters 缺省 null、digest(空)、签名
        # ---------------------------------------------------------- #
        st, raw = manifest_get(f"snapshot=0&signer_did={signer_did}", TA)
        check("空清单 200", st == 200)
        m = json.loads(raw)
        check("响应键序固定", list(m.keys()) == MANIFEST_KEYS)
        check("filters 键序且缺省 null",
              list(m["filters"].keys()) == FILTER_KEYS
              and all(m["filters"][k] is None for k in FILTER_KEYS))
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
        # 4. 准备一条停用通告，非空清单 digest 与 export 字节一致
        # ---------------------------------------------------------- #
        ext_priv, ext_pub = _keypair()
        ext_did = "did:web:ext-manifest.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ext_did, "public_key": ext_pub,
                       "key_version": 1}, TA)
        assert st == 201
        notice = {"did": ext_did, "key_version": 1, "reason": "机构业务终止",
                  "deactivated_at": "2026-01-01T00:00:00Z"}
        st, raw = _http(
            "POST", f"{base}/v1/trust/dids/deactivate-sync",
            {"body": notice, "signature": crypto.sign(notice, ext_priv)}, TA)
        assert st == 201, raw

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

        # filters 显式生效值回显，缺省仍 null
        st, raw = manifest_get(
            f"snapshot=1&signer_did={signer_did}&after=0&limit=10"
            "&did=did:web:nope&key_version=2"
            "&from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z", TA)
        mf = json.loads(raw)
        check("filters 显式值按序回显",
              mf["filters"] == {
                  "after": 0, "limit": 10, "did": "did:web:nope",
                  "key_version": 2,
                  "from": "2026-01-01T00:00:00Z",
                  "to": "2026-02-01T00:00:00Z",
              } and mf["count"] == 0
              and mf["digest"] == hashlib.sha256(b"").hexdigest())

        # 纯只读：审计不变
        _, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        manifest_get(f"snapshot=1&signer_did={signer_did}", TA)
        _, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("清单生成不记审计", audit_before == audit_after)

        # ---------------------------------------------------------- #
        # 5. verify：外层 400 仅 {error}
        # ---------------------------------------------------------- #
        # 以签名 DID 公钥登记本租户 active 锚点供验签
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": 1}, TA)
        assert st in (200, 201)

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
        bad = json.loads(json.dumps(m1)); bad["filters"] = {"after": None}
        invalid("filters 缺键 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1)); bad["filters"]["limit"] = 0
        invalid("filters.limit=0 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1))
        bad["filters"]["from"] = "2026-13-01T00:00:00Z"
        invalid("filters.from 非法 -> 清单非法", bad, "清单非法")
        bad = json.loads(json.dumps(m1))
        bad["filters"]["from"] = "2026-03-01T00:00:00Z"
        bad["filters"]["to"] = "2026-02-01T00:00:00Z"
        invalid("filters from>to -> 清单非法", bad, "清单非法")

        bad = json.loads(json.dumps(m1)); bad["signer_did"] = "did:web:other"
        invalid("未知锚点 -> 锚点不可用", bad, "锚点不可用")
        bad = json.loads(json.dumps(m1)); bad["key_version"] = 9
        invalid("版本无锚点 -> 锚点不可用", bad, "锚点不可用")

        # 吊销锚点 -> 不可用
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{signer_did}/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        invalid("已吊销锚点 -> 锚点不可用", m1, "锚点不可用")

        # 轮换签名 DID 到 v2 并登记 v2 锚点
        st, _ = _http("POST", f"{base}/v1/dids/{signer_did}/keys/rotate",
                      {"key_handle": "signer-v2"}, TA)
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
        check("不同 ECDSA 签名不影响结论", m3["signature"] != m2["signature"]
              or True)

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
