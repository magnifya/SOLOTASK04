#!/usr/bin/env python3
"""GET /v1/dids/{did}/document 只读 DID 文档接口的端到端测试。

直接运行：python3 tests/did_document_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 200 返回体字段精确、verification_methods 升序与元素字段、不暴露私钥；
- document_proof 为 ES256 裸 R||S 无填充 base64url，覆盖除 document_proof
  外的整个响应对象；恒用当前版本私钥（轮换后历史版本查询仍由新版本签）；
- current_key_version 与注册/轮换/GET DID 一致；
- version 查询参数：缺省全量、正整数单项、前导零兼容；空值/0/符号/小数/
  布尔词/字母/空白/Unicode 数字/重复一律 400 且 error 非空；版本不存在 404；
- 租户：缺省 default、显式空值 400、未知 DID 与他租户 404；
- 只读：不记审计、不改变 DID 状态；
- 文档与证明随状态文件持久化，重启后验签结论稳定；
- 旧状态缺密钥元数据时按既有迁移规则公开版本 1，既有接口仍兼容。
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


def _http(method, url, payload=None, headers=None):
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


def _unsigned(document):
    return {k: v for k, v in document.items() if k != "document_proof"}


def _verify(document, public_pem):
    """用给定公钥验文档证明，返回是否通过。"""
    try:
        crypto.verify(
            _unsigned(document), document["document_proof"], public_pem
        )
        return True
    except Exception:  # noqa: BLE001 格式/验签任一失败即不通过
        return False


def _legacy_keypair_pem():
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
    port = 8955
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

        T1 = {"X-Tenant-ID": "doc-a"}
        T2 = {"X-Tenant-ID": "doc-b"}

        # 0. 租户头：显式空串 400
        st, err = _http("GET", f"{base}/v1/dids/did:example:x/document",
                        headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and err.get("error"))

        # 1. 注册后文档：200 与精确字段
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "doc-alice"},
                      headers=T1)
        assert st == 201, r
        did = r["did"]
        st, doc = _http("GET", f"{base}/v1/dids/{did}/document", headers=T1)
        check("文档 200", st == 200)
        check("顶层字段恰为四项",
              set(doc) == {"did", "current_key_version",
                           "verification_methods", "document_proof"})
        check("did/current_key_version",
              doc["did"] == did and doc["current_key_version"] == 1)
        vms = doc["verification_methods"]
        check("单个版本方法", len(vms) == 1)
        check("方法元素字段精确",
              set(vms[0]) == {"key_version", "key_handle", "public_key"})
        check("版本 1 元数据",
              vms[0]["key_version"] == 1
              and vms[0]["key_handle"] == "doc-alice")
        check("public_key 为 P-256 PEM",
              vms[0]["public_key"].startswith("-----BEGIN PUBLIC KEY-----"))
        crypto.validate_public_key_pem(vms[0]["public_key"])
        check("PEM 可解析为 P-256 公钥", True)
        check("禁止暴露 private_key",
              "PRIVATE" not in json.dumps(doc)
              and all("private" not in k for k in vms[0]))
        check("证明为非空字符串",
              isinstance(doc["document_proof"], str)
              and doc["document_proof"])
        check("证明可用版本 1 公钥验签", _verify(doc, vms[0]["public_key"]))

        # current_key_version 与 GET DID / 注册结果一致
        st, got = _http("GET", f"{base}/v1/dids/{did}", headers=T1)
        check("current_key_version 与 GET DID 一致",
              got["key_version"] == doc["current_key_version"] == 1)

        # 2. 轮换后：历史升序、当前版本私钥签名
        st, rot = _http("POST", f"{base}/v1/dids/{did}/keys/rotate",
                        {"key_handle": "doc-alice-v2"}, headers=T1)
        assert st == 200, rot
        check("轮换返回版本 2", rot["key_version"] == 2)
        st, doc2 = _http("GET", f"{base}/v1/dids/{did}/document", headers=T1)
        check("全量方法按版本升序",
              [v["key_version"] for v in doc2["verification_methods"]]
              == [1, 2])
        check("current_key_version 与轮换一致",
              doc2["current_key_version"] == 2
              and doc2["current_key_version"] == rot["key_version"])
        pub1 = doc2["verification_methods"][0]["public_key"]
        pub2 = doc2["verification_methods"][1]["public_key"]
        check("公钥随版本不同", pub1 != pub2)
        check("全量证明由当前版本(v2)私钥签发", _verify(doc2, pub2))
        check("旧版本(v1)公钥验当前证明失败", not _verify(doc2, pub1))

        # 3. version 查询：仅返回该版本、证明重新生成且仍由当前版本签发
        st, d1 = _http("GET",
                       f"{base}/v1/dids/{did}/document?version=1",
                       headers=T1)
        check("version=1 返回 200 单项",
              st == 200
              and [v["key_version"] for v in d1["verification_methods"]]
              == [1])
        check("version=1 current_key_version 仍为当前 2",
              d1["current_key_version"] == 2)
        check("version=1 证明重新生成且由当前(v2)私钥签发",
              _verify(d1, pub2))
        check("version=1 证明不能用 v1 公钥验（证明由当前版本签）",
              not _verify(d1, pub1))
        st, d2 = _http("GET",
                       f"{base}/v1/dids/{did}/document?version=2",
                       headers=T1)
        check("version=2 单项与句柄",
              st == 200
              and d2["verification_methods"][0]["key_handle"]
              == "doc-alice-v2"
              and _verify(d2, pub2))
        # 前导零：全 ASCII 数字的正整数写法，按既有整数查询参数习惯接受
        st, d01 = _http("GET",
                        f"{base}/v1/dids/{did}/document?version=01",
                        headers=T1)
        check("version=01 视为 1（200）",
              st == 200
              and d01["verification_methods"][0]["key_version"] == 1)

        # 4. version 非法形态：400 且 error 非空
        bad_queries = [
            "version=",          # 空值
            "version=0",         # 非正
            "version=-1",        # 负号
            "version=%2B1",      # 正号
            "version=1.5",       # 小数
            "version=true",      # 布尔词
            "version=abc",       # 字母
            "version=%201",      # 前导空白（编码）
            "version=1%20",      # 尾随空白
            "version=%091",      # TAB（编码）
            "version=%E0%A5%A7", # Unicode 数字 DEVANAGARI DIGIT ONE
            "version=1&version=2",  # 重复
        ]
        for query in bad_queries:
            st, err = _http(
                "GET",
                f"{base}/v1/dids/{did}/document?{query}",
                headers=T1,
            )
            check(f"非法参数 400: ?{query}",
                  st == 400
                  and isinstance(err.get("error"), str)
                  and bool(err["error"]))

        # 5. 404：版本不存在、未知 DID、他租户
        st, err = _http("GET",
                        f"{base}/v1/dids/{did}/document?version=99",
                        headers=T1)
        check("版本不存在 404 且 error 非空", st == 404 and err.get("error"))
        unknown = "did:example:00000000000000000000000000000000"
        st, err = _http("GET",
                        f"{base}/v1/dids/{unknown}/document",
                        headers=T1)
        check("未知 DID 404", st == 404 and err.get("error"))
        st, err = _http("GET",
                        f"{base}/v1/dids/{unknown}/document?version=1",
                        headers=T1)
        check("未知 DID + version 仍 404", st == 404 and err.get("error"))
        st, err = _http("GET", f"{base}/v1/dids/{did}/document", headers=T2)
        check("他租户资源 404", st == 404 and err.get("error"))
        # 同句柄在 T2 独立注册，互不可见
        st, r_other = _http("POST", f"{base}/v1/dids",
                            {"method": "example", "public_key": "doc-alice"},
                            headers=T2)
        check("同句柄跨租户可注册", st == 201 and r_other["did"] != did)
        st, doc_other = _http(
            "GET",
            f"{base}/v1/dids/{r_other['did']}/document",
            headers=T2,
        )
        check("他租户内文档独立可见", st == 200 and doc_other["did"]
              == r_other["did"])

        # 6. 只读：文档查询不记审计；DID 状态不被改变
        for _ in range(3):
            _http("GET", f"{base}/v1/dids/{did}/document", headers=T1)
            _http("GET", f"{base}/v1/dids/{did}/document?version=1",
                  headers=T1)
        st, audit = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        actions = [e["action"] for e in audit["events"]]
        check("文档查询不记任何审计",
              all("document" not in a for a in actions)
              and actions == ["did.created", "key.rotated"])
        st, got_after = _http("GET", f"{base}/v1/dids/{did}", headers=T1)
        check("只读不改变 DID 当前版本/公钥",
              got_after["key_version"] == 2
              and got_after["public_key"] == pub2)

        # 7. 重启持久化：文档与证明重新签名后结论稳定
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, doc_r = _http("GET",
                          f"{base}/v1/dids/{did}/document", headers=T1)
        check("重启后文档完整",
              st == 200
              and doc_r["current_key_version"] == 2
              and [v["key_version"] for v in doc_r["verification_methods"]]
              == [1, 2])
        check("重启后证明验签结论稳定（当前 v2）",
              _verify(doc_r, doc_r["verification_methods"][1]["public_key"]))
        st, d1r = _http("GET",
                        f"{base}/v1/dids/{did}/document?version=1",
                        headers=T1)
        check("重启后历史版本证明仍由当前版本验签",
              _verify(d1r, doc_r["verification_methods"][1]["public_key"]))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 8. 旧状态迁移：缺密钥元数据的 DID 公开版本 1，既有接口兼容
    legacy_priv, legacy_pub = _legacy_keypair_pem()
    legacy_store = tempfile.mktemp(suffix=".json")
    legacy_did = "did:example:ff000000000000000000000000000001"
    with open(legacy_store, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "tenants": {
                    "default": {
                        "dids": {
                            legacy_did: {
                                "method": "example",
                                "public_key": legacy_pub,
                                "submitted_public_key": "legacy-handle",
                                "created_at": "2025-01-01T00:00:00Z",
                                "private_key_pem": legacy_priv,
                            }
                        },
                        "credentials": {},
                        "presentations": {},
                    }
                },
                "audit": [],
                "audit_seq": 0,
            },
            fh,
        )
    legacy_port = 8956
    legacy_env = dict(os.environ, VCBACKEND_STORE=legacy_store)
    legacy_proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(legacy_port), "--host", "127.0.0.1"],
        cwd=ROOT, env=legacy_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(legacy_port), "旧状态服务启动超时"
        st, doc = _http(
            "GET", f"http://127.0.0.1:{legacy_port}/v1/dids/{legacy_did}/document"
        )
        check("旧状态迁移后文档 200", st == 200)
        check("迁移公开版本 1",
              doc["current_key_version"] == 1
              and [v["key_version"] for v in doc["verification_methods"]]
              == [1])
        vm = doc["verification_methods"][0]
        check("迁移版本 1 句柄与公钥",
              vm["key_handle"] == "legacy-handle"
              and vm["public_key"] == legacy_pub)
        check("迁移后证明可验签", _verify(doc, legacy_pub))
        st, got = _http(
            "GET", f"http://127.0.0.1:{legacy_port}/v1/dids/{legacy_did}"
        )
        check("既有 GET DID 接口兼容",
              st == 200 and got["key_version"] == 1
              and got["key_mode"] == "server")
    finally:
        legacy_proc.terminate()
        legacy_proc.wait(timeout=10)

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
