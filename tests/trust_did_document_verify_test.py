#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document 跨系统 DID 文档验真的端到端测试。

直接运行：python3 tests/trust_did_document_verify_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 成功路径（外部系统本地生成文档）与“他租户 GET 文档原文 + 本租户锚点”
  跨系统形态：200 且响应恰为 {"valid": true}；
- 多版本文档（轮换后）仅需当前版本 active 锚点即可验真；
- 请求类失败（空体/非法 JSON/非对象、缺 document、多余字段、document
  非对象）统一 HTTP 200 + valid:false + 非空中文原因；
- 文档结构：缺/多顶层字段、did/current_key_version/document_proof 类型、
  布尔版本、方法非对象/缺字段/多字段、版本非正整数、句柄非法、公钥非
  P-256 PEM、方法乱序/重复、current_key_version 非最高、文档携带私钥；
- 锚点：未注册、跨租户不可探测、已吊销、公钥原文不匹配；
- 证明：签名覆盖除 document_proof 外整个文档、错误签名者、签名被篡改、
  base64url 非法、长度非法；
- 显式空 X-Tenant-ID 仍为 400；
- 纯只读：不写审计、不改变锚点与任何资源；
- 结论随状态文件重启稳定；
- 既有 GET /v1/dids/{did}/document 与锚点接口行为不变。
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


def _p384_public_pem():
    priv = ec.generate_private_key(ec.SECP384R1())
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


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


VERIFY_PATH = "/v1/trust/dids/verify-document"


def main():
    port = 8971
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
        did = "did:web:example.org"
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

        def verify(document, headers=TA):
            return _http("POST", f"{base}{VERIFY_PATH}",
                         {"document": document}, headers=headers)

        # 0. 显式空 X-Tenant-ID -> 400（即使请求体非法）
        st, err = _http("POST", f"{base}{VERIFY_PATH}",
                        {"document": {}}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and err.get("error"))
        st, err = _http("POST", f"{base}{VERIFY_PATH}", raw=b"",
                        headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID + 空体仍 400",
              st == 400 and err.get("error"))

        # 1. 成功：单版本文档
        doc1 = _make_document(did, [(1, pub1)], 1, priv1)
        st, r = verify(doc1)
        check("单版本文档验真成功", st == 200 and r == {"valid": True})

        # 2. 成功：多版本文档（证明由当前 v2 私钥签发，仅 v2 需锚点）
        doc2 = _make_document(did, [(1, pub1), (2, pub2)], 2, priv2)
        st, r = verify(doc2)
        check("多版本文档验真成功，响应恰为 valid:true",
              st == 200 and r == {"valid": True})

        # 3. 跨系统形态：他租户注册 DID 并 GET 文档原文，本租户仅凭
        #    锚点 + 提交文档验真（DID 未在 TA 本地注册）。
        st, reg = _http("POST", f"{base}/v1/dids",
                        {"method": "example", "public_key": "ext-issuer"},
                        headers=TB)
        assert st == 201, reg
        local_did = reg["did"]
        st, served = _http("GET",
                           f"{base}/v1/dids/{local_did}/document",
                           headers=TB)
        assert st == 200, served
        # TA 中并无该本地 DID；登记同 DID/版本/公钥的信任锚点
        st, r = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": local_did,
             "public_key": served["verification_methods"][-1]["public_key"],
             "key_version": served["current_key_version"]},
            headers=TA,
        )
        check("跨系统锚点注册 201", st == 201)
        st, r = verify(served, headers=TA)
        check("GET 文档原文跨租户提交验真成功",
              st == 200 and r == {"valid": True})

        # 4. 请求类失败
        def raw_verify(body_bytes, headers=TA):
            return _http("POST", f"{base}{VERIFY_PATH}", raw=body_bytes,
                         headers=headers)

        st, r = raw_verify(b"")
        check("空体 -> 200 valid:false 中文原因",
              st == 200 and r.get("valid") is False
              and isinstance(r.get("reason"), str) and r["reason"])
        st, r = raw_verify(b"{")
        check("非法 JSON", st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = raw_verify(b"[1,2]")
        check("非对象 JSON", st == 200 and r.get("valid") is False)
        st, r = _http("POST", f"{base}{VERIFY_PATH}", [1], headers=TA)
        check("数组请求体", st == 200 and r.get("valid") is False)
        st, r = _http("POST", f"{base}{VERIFY_PATH}", {}, headers=TA)
        check("缺 document", st == 200 and r.get("valid") is False
              and "document" in r["reason"])
        st, r = _http("POST", f"{base}{VERIFY_PATH}",
                      {"document": doc2, "extra": 1}, headers=TA)
        check("多余请求字段", st == 200 and r.get("valid") is False
              and "extra" in r["reason"])
        st, r = _http("POST", f"{base}{VERIFY_PATH}",
                      {"document": []}, headers=TA)
        check("document 非对象", st == 200 and r.get("valid") is False)
        st, r = _http("POST", f"{base}{VERIFY_PATH}",
                      {"document": "x"}, headers=TA)
        check("document 为字符串", st == 200 and r.get("valid") is False)

        # 5. 文档结构类失败
        def tamper(mut):
            d = json.loads(json.dumps(doc2))
            mut(d)
            st, r = verify(d)
            ok = st == 200 and r.get("valid") is False and bool(r.get("reason"))
            return ok, r.get("reason", "")

        cases = [
            ("缺顶层字段 did", lambda d: d.pop("did")),
            ("缺 current_key_version",
             lambda d: d.pop("current_key_version")),
            ("缺 verification_methods",
             lambda d: d.pop("verification_methods")),
            ("缺 document_proof", lambda d: d.pop("document_proof")),
            ("多余顶层字段", lambda d: d.update(extra=1)),
            ("did 为空串", lambda d: d.update(did="")),
            ("did 非字符串", lambda d: d.update(did=123)),
            ("current_key_version 为 0",
             lambda d: d.update(current_key_version=0)),
            ("current_key_version 为负数",
             lambda d: d.update(current_key_version=-1)),
            ("current_key_version 为布尔",
             lambda d: d.update(current_key_version=True)),
            ("current_key_version 为字符串",
             lambda d: d.update(current_key_version="2")),
            ("document_proof 为空",
             lambda d: d.update(document_proof="")),
            ("document_proof 非字符串",
             lambda d: d.update(document_proof=123)),
            ("verification_methods 非数组",
             lambda d: d.update(verification_methods={})),
            ("verification_methods 空数组",
             lambda d: d.update(verification_methods=[])),
            ("方法项非对象",
             lambda d: d.update(verification_methods=[1])),
            ("方法缺 key_version",
             lambda d: d["verification_methods"][0].pop("key_version")),
            ("方法缺 key_handle",
             lambda d: d["verification_methods"][0].pop("key_handle")),
            ("方法缺 public_key",
             lambda d: d["verification_methods"][0].pop("public_key")),
            ("方法含多余字段",
             lambda d: d["verification_methods"][0].update(extra=1)),
            ("方法 key_version 布尔",
             lambda d: d["verification_methods"][0].update(key_version=True)),
            ("方法 key_version 为 0",
             lambda d: d["verification_methods"][0].update(key_version=0)),
            ("方法 key_handle 为空",
             lambda d: d["verification_methods"][0].update(key_handle="")),
            ("方法 public_key 为空",
             lambda d: d["verification_methods"][0].update(public_key="")),
            ("方法 public_key 非 PEM",
             lambda d: d["verification_methods"][0].update(
                 public_key="not-a-pem")),
            ("方法 public_key 为 P-384",
             lambda d: d["verification_methods"][0].update(
                 public_key=_p384_public_pem())),
            ("方法乱序",
             lambda d: d.update(
                 verification_methods=list(reversed(d["verification_methods"])))),
            ("版本重复",
             lambda d: d.update(verification_methods=[
                 d["verification_methods"][0],
                 dict(d["verification_methods"][0], key_handle="dup")])),
            ("current_key_version 非最高(=1)",
             lambda d: d.update(current_key_version=1)),
            ("current_key_version 超出最高",
             lambda d: d.update(current_key_version=3)),
            ("私钥藏在 key_handle",
             lambda d: d["verification_methods"][0].update(
                 key_handle=priv1)),
        ]
        for name, mut in cases:
            ok, reason = tamper(mut)
            check(f"结构失败: {name}", ok)

        # 私钥作为额外字段（两种检测路径任一失败即可）
        d = json.loads(json.dumps(doc2))
        d["verification_methods"][0]["private"] = priv1
        st, r = verify(d)
        check("文档携带私钥 -> 失败",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 6. 锚点类失败
        # 6a. 未注册 DID
        unknown = "did:web:unknown.example"
        d = _make_document(unknown, [(1, pub1)], 1, priv1)
        st, r = verify(d)
        check("未注册 DID 锚点不存在",
              st == 200 and r.get("valid") is False
              and "锚点" in r["reason"] and unknown in r["reason"])
        # 6b. 跨租户：TB 无该锚点，不可探测
        st, r = verify(doc2, headers=TB)
        check("跨租户锚点不可探测",
              st == 200 and r.get("valid") is False
              and "锚点" in r["reason"])
        # 6c. 锚点已吊销
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/2/status",
                      {"status": "revoked"}, headers=TA)
        assert st == 200
        st, r = verify(doc2)
        check("当前版本锚点已吊销 -> 失败",
              st == 200 and r.get("valid") is False
              and "吊销" in r["reason"])
        # 恢复：换一个 DID 做公钥不匹配测试，避免影响重启稳定性用例
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/2/status",
                      {"status": "revoked"}, headers=TA)
        assert st == 200
        # 6d. 公钥原文不匹配：锚点公钥与文档当前版本公钥不同
        d_mismatch_did = "did:web:mismatch.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": d_mismatch_did, "public_key": pub1,
                       "key_version": 1},
                      headers=TA)
        assert st == 201
        d = _make_document(d_mismatch_did, [(1, pub2)], 1, priv2)
        st, r = verify(d)
        check("锚点公钥与文档公钥不匹配 -> 失败",
              st == 200 and r.get("valid") is False
              and "公钥" in r["reason"])

        # 7. 证明类失败（重新使用 doc1，其 v1 锚点仍 active）
        st, r = verify(doc1)
        assert r == {"valid": True}, r

        d = json.loads(json.dumps(doc1))
        d["did"] = did[:-1] + "x"  # 改 did：锚点缺失（不泄露可验签性）
        st, r = verify(d)
        check("篡改 did -> 失败",
              st == 200 and r.get("valid") is False and r.get("reason"))

        d = json.loads(json.dumps(doc1))
        d["verification_methods"][0]["key_handle"] = "changed"
        st, r = verify(d)
        check("篡改方法内容 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and "签名校验失败" in r["reason"])

        # 错误签名者：用另一把私钥签发结构合法的文档
        d = _make_document(did, [(1, pub1)], 1, priv2)
        st, r = verify(d)
        check("错误签名者 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and "签名校验失败" in r["reason"])

        d = json.loads(json.dumps(doc1))
        d["document_proof"] = "%%%not-base64url%%%"
        st, r = verify(d)
        check("签名 base64url 非法 -> 签名格式错误",
              st == 200 and r.get("valid") is False
              and "签名格式错误" in r["reason"])

        d = json.loads(json.dumps(doc1))
        d["document_proof"] = "AAAA"  # 可解码但不足 64 字节
        st, r = verify(d)
        check("签名长度非法 -> 签名格式错误",
              st == 200 and r.get("valid") is False
              and "签名格式错误" in r["reason"])

        # 证明只签部分字段（缺 verification_methods）-> 验签失败
        d = json.loads(json.dumps(doc1))
        d["document_proof"] = crypto.sign(
            {"did": d["did"], "current_key_version": d["current_key_version"]},
            priv1,
        )
        st, r = verify(d)
        check("证明未覆盖完整文档 -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and "签名校验失败" in r["reason"])

        # 8. 纯只读：大量成功/失败调用后审计仅含锚点注册/吊销
        for _ in range(5):
            verify(doc1)
            raw_verify(b"{}")
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        actions = sorted({e["action"] for e in audit["events"]})
        check("验真不写任何审计",
              actions == ["trust.anchor.registered",
                          "trust.anchor.revoked"])
        # 锚点状态不被验真改变
        st, anchors = _http("GET",
                            f"{base}/v1/trust/anchors/{did}", headers=TA)
        by_ver = {a["key_version"]: a["status"] for a in anchors}
        check("验真不改变锚点状态",
              by_ver[1] == "active" and by_ver[2] == "revoked")
        # 本地 DID（TB）不被验真登记
        st, err = _http("GET",
                        f"{base}/v1/dids/{d_mismatch_did}", headers=TA)
        check("验真不登记 DID 资源", st == 404)

        # 9. 重启后结论稳定（吊销状态持久化：doc2 仍失败，doc1 仍成功）
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, r = verify(doc1)
        check("重启后 active 文档结论稳定", r == {"valid": True})
        st, r = verify(doc2)
        check("重启后吊销锚点结论稳定",
              r.get("valid") is False and "吊销" in r["reason"])

        # 10. 既有接口不受影响：文档与锚点 GET 仍正常
        st, served = _http("GET",
                           f"{base}/v1/dids/{local_did}/document",
                           headers=TB)
        check("既有 DID 文档接口不变",
              st == 200 and set(served) == {
                  "did", "current_key_version",
                  "verification_methods", "document_proof"})
        st, anchors = _http("GET",
                            f"{base}/v1/trust/anchors/{did}", headers=TA)
        check("既有锚点列表接口不变",
              st == 200 and len(anchors) == 2
              and [a["key_version"] for a in anchors] == [1, 2])

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
