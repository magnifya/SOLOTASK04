#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document-batch 批量 DID 文档验真的端到端测试。

直接运行：python3 tests/trust_did_document_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 成功路径：批量合法文档 200 且 results 等长同序、每项恰为 {"valid": true}；
- 混合批次：失败不短路，项级失败 valid:false + 非空中文 reason，顺序保持；
- 请求类失败（空体/非法 JSON/非对象、缺 documents、多余字段、documents
  非数组/空数组/超过 100 项）统一 HTTP 200 + {"results": [], "reason": "请求..."}；
- 项级失败：非对象项、结构非法项、锚点缺失/吊销/公钥不匹配、签名错误；
- 显式空 X-Tenant-ID 为 400，缺省租户为 default；
- 租户隔离：他租户锚点不可探测；
- 纯只读：不写审计、不改变锚点与任何资源；
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
    port = 8972
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

        doc1 = _make_document(did, [(1, pub1)], 1, priv1)
        doc2 = _make_document(did, [(1, pub1), (2, pub2)], 2, priv2)

        # 0. 显式空 X-Tenant-ID -> 400（即使请求体非法）
        st, err = _http("POST", f"{base}{BATCH_PATH}",
                        {"documents": []}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and err.get("error"))
        st, err = _http("POST", f"{base}{BATCH_PATH}", raw=b"",
                        headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID + 空体仍 400",
              st == 400 and err.get("error"))

        # 1. 成功：全部合法文档，results 等长同序
        st, r = batch([doc1, doc2, doc1])
        check("批量验真成功，results 等长同序",
              st == 200 and r == {"results": [{"valid": True}] * 3})

        # 2. 缺省租户为 default：default 租户无锚点 -> 项级失败
        st, r = _http("POST", f"{base}{BATCH_PATH}", {"documents": [doc1]})
        check("缺省租户 default 隔离",
              st == 200 and r["results"][0]["valid"] is False
              and "锚点" in r["results"][0]["reason"])

        # 3. 请求类失败 -> {"results": [], "reason": "请求..."}
        def raw_batch(body_bytes, headers=TA):
            return _http("POST", f"{base}{BATCH_PATH}", raw=body_bytes,
                         headers=headers)

        def check_request_fail(name, st, r):
            check(name, st == 200 and r.get("results") == []
                  and isinstance(r.get("reason"), str)
                  and r["reason"].startswith("请求"))

        st, r = raw_batch(b"")
        check_request_fail("空体", st, r)
        st, r = raw_batch(b"{")
        check_request_fail("非法 JSON", st, r)
        st, r = raw_batch(b"[1,2]")
        check_request_fail("非对象 JSON", st, r)
        st, r = _http("POST", f"{base}{BATCH_PATH}", {}, headers=TA)
        check_request_fail("缺 documents", st, r)
        check("缺 documents 原因含字段名", "documents" in r["reason"])
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": [doc1], "extra": 1}, headers=TA)
        check_request_fail("多余请求字段", st, r)
        check("多余字段原因含字段名", "extra" in r["reason"])
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": {"a": 1}}, headers=TA)
        check_request_fail("documents 非数组", st, r)
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": []}, headers=TA)
        check_request_fail("documents 空数组", st, r)
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": [doc1] * 101}, headers=TA)
        check_request_fail("documents 超过 100 项", st, r)
        st, r = _http("POST", f"{base}{BATCH_PATH}",
                      {"documents": [doc1] * 100}, headers=TA)
        check("documents 恰 100 项合法",
              st == 200 and len(r.get("results", [])) == 100
              and all(item == {"valid": True} for item in r["results"]))

        # 4. 混合批次：失败不短路，顺序保持
        unknown = "did:web:unknown-batch.example"
        doc_unknown = _make_document(unknown, [(1, pub1)], 1, priv1)
        bad_struct = json.loads(json.dumps(doc1))
        bad_struct.pop("did")
        tampered = json.loads(json.dumps(doc1))
        tampered["verification_methods"][0]["key_handle"] = "changed"
        st, r = batch([doc1, "not-an-object", doc_unknown, bad_struct,
                       tampered, doc2])
        check("混合批次 200 且等长", st == 200 and len(r.get("results", [])) == 6)
        results = r["results"]
        check("混合批次第 1 项成功", results[0] == {"valid": True})
        check("混合批次非对象项失败",
              results[1]["valid"] is False and results[1]["reason"])
        check("混合批次锚点缺失项失败",
              results[2]["valid"] is False and "锚点" in results[2]["reason"])
        check("混合批次结构非法项失败",
              results[3]["valid"] is False and "did" in results[3]["reason"])
        check("混合批次签名篡改项失败",
              results[4]["valid"] is False
              and "签名校验失败" in results[4]["reason"])
        check("混合批次末项成功（不短路）", results[5] == {"valid": True})

        # 5. 项级失败原因均为非空中文
        st, r = batch([doc_unknown, bad_struct, tampered, 42, None])
        check("项级失败均含非空原因",
              st == 200 and all(
                  item["valid"] is False
                  and isinstance(item.get("reason"), str) and item["reason"]
                  for item in r["results"]))

        # 6. 租户隔离：TB 无锚点 -> 全部项级失败
        st, r = batch([doc1, doc2], headers=TB)
        check("跨租户锚点不可探测",
              st == 200 and all(
                  item["valid"] is False and "锚点" in item["reason"]
                  for item in r["results"]))

        # 7. 锚点吊销后批量结论随之变化
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did}/2/status",
                      {"status": "revoked"}, headers=TA)
        assert st == 200
        st, r = batch([doc1, doc2])
        check("吊销后批量结果分化",
              st == 200 and r["results"][0] == {"valid": True}
              and r["results"][1]["valid"] is False
              and "吊销" in r["results"][1]["reason"])

        # 8. 纯只读：审计仅含锚点注册/吊销
        for _ in range(5):
            batch([doc1, doc_unknown])
            raw_batch(b"{}")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        actions = sorted({e["action"] for e in audit["events"]})
        check("批量验真不写任何审计",
              actions == ["trust.anchor.registered", "trust.anchor.revoked"])
        st, anchors = _http("GET", f"{base}/v1/trust/anchors/{did}",
                            headers=TA)
        by_ver = {a["key_version"]: a["status"] for a in anchors}
        check("批量验真不改变锚点状态",
              by_ver[1] == "active" and by_ver[2] == "revoked")
        st, err = _http("GET", f"{base}/v1/dids/{did}", headers=TA)
        check("批量验真不登记 DID 资源", st == 404)

        # 9. 单项接口行为不变
        st, r = _http("POST", f"{base}{SINGLE_PATH}",
                      {"document": doc1}, headers=TA)
        check("单项接口仍成功", st == 200 and r == {"valid": True})
        st, r = _http("POST", f"{base}{SINGLE_PATH}",
                      {"document": doc2}, headers=TA)
        check("单项接口吊销结论不变",
              st == 200 and r["valid"] is False and "吊销" in r["reason"])
        st, r = _http("POST", f"{base}{SINGLE_PATH}", {}, headers=TA)
        check("单项接口请求失败协议不变",
              st == 200 and r["valid"] is False and r["reason"])

        # 10. 重启后批量结论稳定
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, r = batch([doc1, doc2])
        check("重启后批量结论稳定",
              st == 200 and r["results"][0] == {"valid": True}
              and r["results"][1]["valid"] is False
              and "吊销" in r["results"][1]["reason"])

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
