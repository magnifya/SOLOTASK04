#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document 跨系统 DID 文档验真的端到端测试。

直接运行：python3 tests/trust_did_document_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 未在本租户注册的 DID 可仅凭提交文档验真（锚点按本租户同 DID/同版本/
  公钥完全匹配的 active 记录）；
- 成功仅返回 {"valid": true}；请求、字段、锚点、签名各类失败均 200
  返回 {"valid": false, "reason": 非空中文}；
- 显式空 X-Tenant-ID 仍为 400；跨租户不可探测；
- 文档可直接取自其他租户 GET /v1/dids/{did}/document 的响应；
- 纯只读：不登记资源、不写审计；重启后结论稳定。
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
        data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
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


def _sign_document(document, priv_pem):
    unsigned = {k: v for k, v in document.items() if k != "document_proof"}
    return crypto.sign(unsigned, priv_pem)


def main():
    port = 8991
    store_file = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_file)
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

    VERIFY = f"{base}/v1/trust/dids/verify-document"
    TA = {"X-Tenant-ID": "trust-a"}
    TB = {"X-Tenant-ID": "trust-b"}
    did = "did:web:example.org"

    try:
        assert wait_up(port), "服务启动超时"

        priv1, pub1 = _keypair()
        priv2, pub2 = _keypair()

        def make_document(current=2, methods=None, proof_priv=None):
            if methods is None:
                methods = [
                    {"key_version": 1, "key_handle": "h1",
                     "public_key": pub1},
                    {"key_version": 2, "key_handle": "h2",
                     "public_key": pub2},
                ]
            doc = {
                "did": did,
                "current_key_version": current,
                "verification_methods": methods,
            }
            doc["document_proof"] = _sign_document(
                doc, proof_priv if proof_priv is not None else priv2
            )
            return doc

        # 0. 显式空 X-Tenant-ID -> 400（即使请求体非法也先判租户头）
        st, err = _http("POST", VERIFY, {"document": {}},
                        headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and err.get("error"))

        # 1. 未注册任何锚点：锚点不存在（不 404，200 valid:false）
        st, r = _http("POST", VERIFY, {"document": make_document()},
                      headers=TA)
        check("无锚点 200", st == 200)
        check("无锚点 valid:false + 中文锚点原因",
              r.get("valid") is False
              and isinstance(r.get("reason"), str) and r["reason"]
              and "锚点" in r["reason"] and "不存在" in r["reason"])

        # 2. 注册 v1/v2 active 锚点后验真成功，响应恰为 {"valid": true}
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=TA)
        assert st == 201, r
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=TA)
        assert st == 201, r

        doc = make_document()
        st, r = _http("POST", VERIFY, {"document": doc}, headers=TA)
        check("合法文档验真成功 200", st == 200 and r == {"valid": True})

        # 3. 跨租户不可探测：trust-b 无该锚点
        st, r = _http("POST", VERIFY, {"document": doc}, headers=TB)
        check("他租户无锚点 -> valid:false",
              st == 200 and r.get("valid") is False
              and "锚点" in r["reason"])
        # 在 trust-b 注册同 DID 但不同公钥 -> 公钥不匹配（不能探测 TA）
        _, other_pub = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": other_pub,
                       "key_version": 2},
                      headers=TB)
        assert st == 201
        st, r = _http("POST", VERIFY, {"document": doc}, headers=TB)
        check("他租户锚点公钥不匹配",
              st == 200 and r.get("valid") is False and "不匹配" in r["reason"])

        # 4. 请求级错误：均为 200 + 请求中文原因
        request_cases = [
            ({}, "空请求体"),
            ({"document": doc, "extra": 1}, "多余字段"),
            ({"document": "not-object"}, "document 非对象"),
            ({"foo": doc}, "缺 document"),
        ]
        for payload, label in request_cases:
            st, r = _http("POST", VERIFY, payload, headers=TA)
            check(f"请求错误[{label}]",
                  st == 200 and r.get("valid") is False
                  and isinstance(r.get("reason"), str)
                  and bool(r["reason"]))
        # 非法 JSON / 空体
        st, r = _http("POST", VERIFY, raw=b"{not json", headers=TA)
        check("非法 JSON -> 200 valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", VERIFY, raw=b"", headers=TA)
        check("空体 -> 200 valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 5. 文档字段级错误
        def expect_doc_invalid(mutator, label):
            bad = json.loads(json.dumps(doc))
            mutator(bad)
            st, r = _http("POST", VERIFY, {"document": bad}, headers=TA)
            check(f"文档非法[{label}]",
                  st == 200 and r.get("valid") is False
                  and isinstance(r.get("reason"), str)
                  and bool(r["reason"]))

        expect_doc_invalid(lambda d: d.pop("did"), "缺 did")
        expect_doc_invalid(lambda d: d.update(extra=1), "多余顶层字段")
        expect_doc_invalid(lambda d: d.update(did=""), "did 空串")
        expect_doc_invalid(lambda d: d.update(did=123), "did 非字符串")
        expect_doc_invalid(
            lambda d: d.update(current_key_version=True), "版本为布尔")
        expect_doc_invalid(
            lambda d: d.update(current_key_version=0), "版本为 0")
        expect_doc_invalid(
            lambda d: d.update(current_key_version="2"), "版本为字符串")
        expect_doc_invalid(
            lambda d: d.update(document_proof=""), "证明空串")
        expect_doc_invalid(
            lambda d: d.update(document_proof=123), "证明非字符串")
        expect_doc_invalid(
            lambda d: d.update(verification_methods=[]), "方法为空数组")
        expect_doc_invalid(
            lambda d: d.update(verification_methods="x"), "方法非数组")
        # 版本乱序/重复
        expect_doc_invalid(
            lambda d: d.update(verification_methods=list(reversed(
                d["verification_methods"]))),
            "版本降序")
        expect_doc_invalid(
            lambda d: d.update(verification_methods=[
                d["verification_methods"][0],
                d["verification_methods"][0]]),
            "版本重复")
        # current_key_version 非最高
        expect_doc_invalid(
            lambda d: d.update(current_key_version=1), "current 非最高")
        # 方法元素字段
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].update(extra=1),
            "方法多余字段")
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].pop("key_handle"),
            "方法缺 key_handle")
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].update(key_version="1"),
            "方法版本为字符串")
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].update(key_version=True),
            "方法版本为布尔")
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].update(key_handle=""),
            "key_handle 空串")
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].update(
                public_key="not a pem"),
            "public_key 非 PEM")
        expect_doc_invalid(
            lambda d: d["verification_methods"][1].update(
                public_key=pub1),
            "最高版本公钥与锚点不匹配")

        # 私钥泄露：文档中任何位置出现私钥 PEM 即失败
        expect_doc_invalid(
            lambda d: d["verification_methods"][0].update(
                public_key=pub1.replace("BEGIN PUBLIC KEY",
                                        "BEGIN PRIVATE KEY")),
            "私钥 PEM")

        # 6. 签名类错误
        bad_proof = json.loads(json.dumps(doc))
        bad_proof["document_proof"] = "not-base64url!!"
        st, r = _http("POST", VERIFY, {"document": bad_proof}, headers=TA)
        check("签名格式错误",
              st == 200 and r.get("valid") is False
              and "签名格式错误" in r["reason"])
        bad_sig = json.loads(json.dumps(doc))
        bad_sig["document_proof"] = crypto.sign(
            {k: v for k, v in bad_sig.items() if k != "document_proof"},
            priv1)  # 用 v1 私钥签当前版本文档
        st, r = _http("POST", VERIFY, {"document": bad_sig}, headers=TA)
        check("签名校验失败（错误签名者）",
              st == 200 and r.get("valid") is False
              and "签名校验失败" in r["reason"])
        tampered = json.loads(json.dumps(doc))
        # 保持与锚点匹配以越过锚点检查，篡改被签名内容（key_handle）
        tampered["verification_methods"][0]["key_handle"] = "changed"
        st, r = _http("POST", VERIFY, {"document": tampered}, headers=TA)
        check("文档被篡改 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and "签名校验失败" in r["reason"])

        # 7. 吊销锚点后失败
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/2/status",
                      {"status": "revoked"}, headers=TA)
        assert st == 200
        st, r = _http("POST", VERIFY, {"document": doc}, headers=TA)
        check("锚点吊销后失败",
              st == 200 and r.get("valid") is False
              and "吊销" in r["reason"])
        # 恢复一个新租户便于只读/重启检查
        TC = {"X-Tenant-ID": "trust-c"}
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=TC)
        assert st == 201
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=TC)
        assert st == 201

        # 8. 文档可直接取自其他系统的 GET DID 文档响应
        st, reg = _http("POST", f"{base}/v1/dids",
                        {"method": "example", "public_key": "ext-source"},
                        headers={"X-Tenant-ID": "source"})
        assert st == 201, reg
        src_did = reg["did"]
        st, src_doc = _http(
            "GET", f"{base}/v1/dids/{src_did}/document",
            headers={"X-Tenant-ID": "source"})
        assert st == 200
        st, _ = _http("POST", f"{base}/v1/dids/{src_did}/keys/rotate",
                      {"key_handle": "ext-source-v2"},
                      headers={"X-Tenant-ID": "source"})
        assert st == 200
        st, src_doc = _http(
            "GET", f"{base}/v1/dids/{src_did}/document",
            headers={"X-Tenant-ID": "source"})
        assert st == 200
        TD = {"X-Tenant-ID": "relying"}
        for vm in src_doc["verification_methods"]:
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": src_did, "public_key": vm["public_key"],
                           "key_version": vm["key_version"]},
                          headers=TD)
            assert st == 201
        st, r = _http("POST", VERIFY, {"document": src_doc}, headers=TD)
        check("他系统文档原文验真成功", st == 200 and r == {"valid": True})

        # 9. 纯只读：trust-c 仅有两次锚点注册审计，无验真审计；
        #    多次验真不改变审计与锚点
        for _ in range(3):
            st, r = _http("POST", VERIFY, {"document": doc}, headers=TC)
            assert r == {"valid": True}, r
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=TC)
        actions = [e["action"] for e in audit["events"]]
        check("验真不记审计",
              actions == ["trust.anchor.registered",
                          "trust.anchor.registered"])
        st, anchors = _http(
            "GET", f"{base}/v1/trust/anchors/{did}", headers=TC)
        check("验真不改变锚点",
              st == 200 and len(anchors) == 2
              and all(a["status"] == "active" for a in anchors))

        # 10. 重启后结论稳定
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, r = _http("POST", VERIFY, {"document": doc}, headers=TC)
        check("重启后验真结论稳定", st == 200 and r == {"valid": True})
        st, r = _http("POST", VERIFY, {"document": doc}, headers=TA)
        check("重启后吊销结论稳定",
              st == 200 and r.get("valid") is False and "吊销" in r["reason"])
        st, r = _http("POST", VERIFY, {"document": src_doc}, headers=TD)
        check("重启后他系统文档仍可验真",
              st == 200 and r == {"valid": True})

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
