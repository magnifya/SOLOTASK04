#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document-batch 批量跨系统 DID 文档验真测试。

直接运行：python3 tests/trust_did_document_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求级失败（空体/非法 JSON/非对象、缺 documents、多余字段、documents
  非数组、空数组、超过 100 项）统一 HTTP 200 +
  {"results": [], "reason": "请求..."}；
- 显式空 X-Tenant-ID 为 400，缺省租户为 default；
- 合法批次按序处理且不短路，results 等长同序：成功项恰为
  {"valid": true}，失败项 {"valid": false, "reason": 非空中文}；
- 项级规则与单项一致（结构、锚点、签名），仅当前租户同 DID/同版本/
  同公钥 active 锚点可验真，跨租户不可探测；
- 纯只读：不写审计、不改变锚点与任何资源，重启后结论稳定；
- 单项 /v1/trust/dids/verify-document 行为不变。
"""

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


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(payload).encode() if payload is not None else b""
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


def _make_document(did, methods, current_version, signer_private_pem):
    """按既有文档规范构造文档并用指定私钥签发 document_proof。"""
    doc = {
        "did": did,
        "current_key_version": current_version,
        "verification_methods": [
            {
                "key_version": v,
                "key_handle": f"handle-{v}",
                "public_key": pem,
            }
            for v, pem in methods
        ],
    }
    doc["document_proof"] = crypto.sign(
        {k: val for k, val in doc.items()}, signer_private_pem
    )
    return doc


BATCH_PATH = "/v1/trust/dids/verify-document-batch"
SINGLE_PATH = "/v1/trust/dids/verify-document"


def main():
    port = 8973
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"

        TA = {"X-Tenant-ID": "verifier-a"}
        TB = {"X-Tenant-ID": "verifier-b"}
        did = "did:web:batch.example.org"
        priv1, pub1 = _keypair()
        priv2, pub2 = _keypair()

        # 在 TA 注册 v1/v2 两个 active 锚点
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=TA)
        assert st == 201, r
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=TA)
        assert st == 201, r

        def batch(documents, headers=TA):
            return _http("POST", f"{base}{BATCH_PATH}",
                         {"documents": documents}, headers=headers)

        def raw_batch(body_bytes, headers=TA):
            return _http("POST", f"{base}{BATCH_PATH}", raw=body_bytes,
                         headers=headers)

        def is_request_error(r):
            return (
                r.get("results") == []
                and isinstance(r.get("reason"), str)
                and r["reason"].startswith("请求")
            )

        # 0. 显式空 X-Tenant-ID -> 400（即使请求体非法）
        st, err = _http("POST", f"{base}{BATCH_PATH}",
                        {"documents": []}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and err.get("error"))
        st, err = _http("POST", f"{base}{BATCH_PATH}", raw=b"",
                        headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID + 空体仍 400",
              st == 400 and err.get("error"))

        # 1. 请求级失败：统一 200 + {"results": [], "reason": "请求..."}
        st, r = raw_batch(b"")
        check("空体 -> 200 results:[] 请求原因",
              st == 200 and is_request_error(r))
        st, r = raw_batch(b"{")
        check("非法 JSON", st == 200 and is_request_error(r))
        st, r = raw_batch(b"[1,2]")
        check("非对象 JSON", st == 200 and is_request_error(r))
        st, r = _http("POST", f"{base}{BATCH_PATH}", [1], headers=TA)
        check("数组请求体", st == 200 and is_request_error(r))
        st, r = _http("POST", f"{base}{BATCH_PATH}", {}, headers=TA)
        check("缺 documents", st == 200 and is_request_error(r)
              and "documents" in r["reason"])
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": [], "extra": 1}, headers=TA)
        check("多余请求字段", st == 200 and is_request_error(r)
              and "extra" in r["reason"])
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": {}}, headers=TA)
        check("documents 非数组", st == 200 and is_request_error(r))
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": []}, headers=TA)
        check("documents 空数组", st == 200 and is_request_error(r))
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": [{}] * 101}, headers=TA)
        check("documents 超过 100 项", st == 200 and is_request_error(r))

        # 2. 构造合法与非法文档
        doc_ok1 = _make_document(did, [(1, pub1)], 1, priv1)
        doc_ok2 = _make_document(did, [(1, pub1), (2, pub2)], 2, priv2)
        doc_bad_struct = _make_document(did, [(1, pub1)], 1, priv1)
        doc_bad_struct.pop("did")  # 缺顶层字段
        doc_bad_anchor = _make_document(
            "did:web:unknown-batch.example", [(1, pub1)], 1, priv1)
        doc_bad_sig = _make_document(did, [(1, pub1)], 1, priv2)  # 错误签名者

        # 3. 合法批次：混合成功/失败，等长同序，失败不短路
        docs = [doc_ok1, doc_bad_struct, doc_ok2, doc_bad_anchor, doc_bad_sig]
        st, r = batch(docs)
        check("混合批次 200 且 results 等长",
              st == 200 and len(r.get("results", [])) == len(docs))
        res = r.get("results", [])
        check("第 1 项成功且恰为 valid:true", res[0] == {"valid": True})
        check("第 2 项结构失败带中文原因",
              res[1].get("valid") is False
              and isinstance(res[1].get("reason"), str) and res[1]["reason"])
        check("第 3 项成功（不短路）", res[2] == {"valid": True})
        check("第 4 项锚点不存在",
              res[3].get("valid") is False and "锚点" in res[3]["reason"])
        check("第 5 项签名校验失败",
              res[4].get("valid") is False
              and "签名校验失败" in res[4]["reason"])

        # 4. 单项与批量同文档结论一致（单项接口行为不变）
        st, r_single = _http("POST", f"{base}{SINGLE_PATH}",
                             {"document": doc_ok1}, headers=TA)
        check("单项接口仍验真成功", st == 200 and r_single == {"valid": True})
        st, r_single = _http("POST", f"{base}{SINGLE_PATH}",
                             {"document": doc_bad_anchor}, headers=TA)
        check("单项接口失败协议不变",
              st == 200 and r_single.get("valid") is False
              and r_single.get("reason"))

        # 5. 100 项上限边界：恰 100 项合法
        st, r = batch([doc_ok1] * 100)
        check("恰 100 项全部成功",
              st == 200 and len(r.get("results", [])) == 100
              and all(item == {"valid": True} for item in r["results"]))

        # 6. 租户隔离：TB 无锚点，批量逐项失败且不可探测；缺省租户 default
        st, r = batch([doc_ok1, doc_ok2], headers=TB)
        check("他租户批量逐项锚点失败",
              st == 200 and len(r.get("results", [])) == 2
              and all(item.get("valid") is False and "锚点" in item["reason"]
                      for item in r["results"]))
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": [doc_ok1]})  # 无租户头 -> default
        check("缺省租户 default 无锚点失败",
              st == 200 and r["results"][0].get("valid") is False
              and "锚点" in r["results"][0]["reason"])

        # 7. 纯只读：审计仅含锚点注册；锚点状态不被改变；不登记 DID
        for _ in range(3):
            batch([doc_ok1, doc_bad_struct])
            raw_batch(b"{}")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        actions = sorted({e["action"] for e in audit["events"]})
        check("批量验真不写任何审计",
              actions == ["trust.anchor.registered"])
        st, anchors = _http("GET", f"{base}/v1/trust/anchors/{did}",
                            headers=TA)
        check("批量验真不改变锚点状态",
              st == 200
              and all(a["status"] == "active" for a in anchors))
        st, err = _http("GET", f"{base}/v1/dids/{did}", headers=TA)
        check("批量验真不登记 DID 资源", st == 404)

        # 8. 重启后结论稳定
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, r = batch([doc_ok1, doc_bad_anchor])
        check("重启后批量结论稳定",
              st == 200 and r["results"][0] == {"valid": True}
              and r["results"][1].get("valid") is False
              and "锚点" in r["results"][1]["reason"])

    finally:
        proc.terminate()
        proc.wait(timeout=10)

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
