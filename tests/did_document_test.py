#!/usr/bin/env python3
"""只读 DID 文档接口 GET /v1/dids/{did}/document 的端到端测试。

直接运行：python3 tests/did_document_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
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

from cryptography.exceptions import InvalidSignature  # noqa: E402

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


def start(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def verify_doc(doc, public_pem):
    """用给定公钥验 document_proof，覆盖除 document_proof 外的对象。"""
    unsigned = {k: v for k, v in doc.items() if k != "document_proof"}
    crypto.verify(unsigned, doc["document_proof"], public_pem)


def main():
    port = 8961
    store = tempfile.mktemp(suffix=".json")
    proc = start(port, store)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        # 1. 注册 DID（默认租户）
        st, reg = _http("POST", f"{base}/v1/dids",
                        {"method": "example", "public_key": "alice-key"})
        check("注册 DID 201", st == 201)
        did = reg["did"]

        st, doc = _http("GET", f"{base}/v1/dids/{did}/document")
        check("文档 200", st == 200)
        check("文档字段恰为四项",
              set(doc.keys()) == {
                  "did", "current_key_version",
                  "verification_methods", "document_proof"})
        check("did 一致", doc.get("did") == did)
        check("current_key_version=1", doc.get("current_key_version") == 1)
        methods = doc.get("verification_methods")
        check("verification_methods 为单项列表", isinstance(methods, list)
              and len(methods) == 1)
        if methods:
            m = methods[0]
            check("方法字段恰为三项",
                  set(m.keys()) == {"key_version", "key_handle", "public_key"})
            check("方法版本/句柄", m.get("key_version") == 1
                  and m.get("key_handle") == "alice-key")
            pub1 = m.get("public_key", "")
            check("public_key 为 P-256 PEM",
                  pub1.startswith("-----BEGIN PUBLIC KEY-----"))
            try:
                crypto.validate_public_key_pem(pub1)
                pem_ok = True
            except ValueError:
                pem_ok = False
            check("public_key 可解析为 ES256 P-256 公钥", pem_ok)
            check("public_key 与注册返回一致", pub1 == reg["public_key"])
        check("响应不含任何私钥字段",
              "private_key" not in json.dumps(doc)
              and "private_key_pem" not in json.dumps(doc))
        check("document_proof 非空字符串",
              isinstance(doc.get("document_proof"), str)
              and bool(doc["document_proof"]))
        try:
            verify_doc(doc, pub1)
            proof_ok = True
        except Exception:  # noqa: BLE001
            proof_ok = False
        check("document_proof 可用当前公钥验签", proof_ok)

        # 篡改任一字段验签必须失败
        tampered = dict(doc)
        tampered["current_key_version"] = 2
        try:
            verify_doc(tampered, pub1)
            tamper_ok = False
        except InvalidSignature:
            tamper_ok = True
        check("篡改 current_key_version 后验签失败", tamper_ok)

        # 2. 轮换后文档含升序历史，current 与注册/轮换一致
        st, rot = _http("POST", f"{base}/v1/dids/{did}/keys/rotate",
                        {"key_handle": "alice-key-v2"})
        check("轮换 200 且版本 2", st == 200 and rot.get("key_version") == 2)
        st, got = _http("GET", f"{base}/v1/dids/{did}")
        st, doc2 = _http("GET", f"{base}/v1/dids/{did}/document")
        check("文档 200（轮换后）", st == 200)
        check("current_key_version 与轮换/GET 一致",
              doc2.get("current_key_version") == 2
              == rot["key_version"] == got["key_version"])
        ms = doc2.get("verification_methods", [])
        check("历史含两个版本", len(ms) == 2)
        check("按 key_version 升序",
              [m.get("key_version") for m in ms] == [1, 2])
        check("句柄依次正确",
              [m.get("key_handle") for m in ms]
              == ["alice-key", "alice-key-v2"])
        check("仍无私钥泄露",
              "private_key" not in json.dumps(doc2))
        for m in ms:
            check(f"方法 {m.get('key_version')} 字段仅三项",
                  set(m.keys()) == {"key_version", "key_handle",
                                    "public_key"})
        pub2 = ms[1]["public_key"]
        check("公钥随版本不同", pub1 != pub2)
        try:
            verify_doc(doc2, pub2)
            cur_proof_ok = True
        except Exception:  # noqa: BLE001
            cur_proof_ok = False
        check("证明由当前版本(v2)私钥签名", cur_proof_ok)
        try:
            verify_doc(doc2, pub1)
            old_proof_ok = True
        except InvalidSignature:
            old_proof_ok = False
        check("证明不能被旧版本(v1)公钥验过", not old_proof_ok)

        # 3. ?version= 过滤：仅该版本，current 不变，证明仍用当前私钥重签
        st, d1 = _http("GET", f"{base}/v1/dids/{did}/document?version=1")
        check("version=1 200", st == 200)
        check("仅返回版本1",
              [m["key_version"] for m in d1.get("verification_methods", [])]
              == [1])
        check("过滤后 current_key_version 仍为 2",
              d1.get("current_key_version") == 2)
        try:
            verify_doc(d1, pub2)
            v1_proof_ok = True
        except Exception:  # noqa: BLE001
            v1_proof_ok = False
        check("version=1 的证明仍由当前(v2)私钥重新生成", v1_proof_ok)

        st, d2 = _http("GET", f"{base}/v1/dids/{did}/document?version=2")
        check("version=2 200 且仅版本2", st == 200
              and [m["key_version"] for m in d2["verification_methods"]]
              == [2])
        check("版本2 公钥为当前公钥",
              d2["verification_methods"][0]["public_key"] == pub2)

        st, missing = _http("GET", f"{base}/v1/dids/{did}/document?version=9")
        check("版本不存在 404", st == 404)
        check("404 返回非空 error",
              isinstance(missing.get("error"), str)
              and bool(missing.get("error")))

        # 4. version 参数各类非法值 -> 400 非空 error
        bad_versions = [
            ("空值", "version="),
            ("零", "version=0"),
            ("负号", "version=-1"),
            ("正号", "version=%2B1"),
            ("小数", "version=1.5"),
            ("字母", "version=abc"),
            ("布尔词", "version=true"),
            ("空白", "version=%20"),
            ("Unicode 数字(٣)", "version=%D9%A3"),
        ]
        for label, qs in bad_versions:
            st, r = _http("GET", f"{base}/v1/dids/{did}/document?{qs}")
            check(f"非法 version（{label}）400", st == 400
                  and isinstance(r.get("error"), str)
                  and bool(r.get("error")))
        st, r = _http(
            "GET",
            f"{base}/v1/dids/{did}/document?version=1&version=2",
        )
        check("重复 version 400 且非空 error",
              st == 400 and isinstance(r.get("error"), str)
              and bool(r.get("error")))
        # 无关参数应被忽略，行为同缺省
        st, d_extra = _http(
            "GET", f"{base}/v1/dids/{did}/document?foo=bar"
        )
        check("无关查询参数不影响", st == 200
              and d_extra.get("current_key_version") == 2)

        # 5. 未知 DID 与租户规则
        st, r = _http("GET", f"{base}/v1/dids/did:example:nope/document")
        check("未知 DID 404 非空 error", st == 404
              and isinstance(r.get("error"), str) and bool(r.get("error")))

        st, r = _http("GET", f"{base}/v1/dids/{did}/document",
                      headers={"X-Tenant-ID": "other-tenant"})
        check("他租户 DID 404", st == 404)

        st, r = _http("GET", f"{base}/v1/dids/{did}/document",
                      headers={"X-Tenant-ID": ""})
        check("显式空租户头 400 非空 error", st == 400
              and isinstance(r.get("error"), str) and bool(r.get("error")))

        st, r = _http("GET", f"{base}/v1/dids/{did}/document")
        check("缺省租户头仍为 default 可访问", st == 200)

        # 6. 只读：调用前后审计事件不变（含 400/404 路径）
        def audit():
            st, r = _http("GET", f"{base}/v1/audit?limit=200&after=0")
            assert st == 200
            return r.get("events", [])

        before = audit()
        _http("GET", f"{base}/v1/dids/{did}/document")
        _http("GET", f"{base}/v1/dids/{did}/document?version=1")
        _http("GET", f"{base}/v1/dids/{did}/document?version=99")
        _http("GET", f"{base}/v1/dids/{did}/document?version=bad")
        after = audit()
        check("文档查询只读、不记审计", before == after)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 7. 重启持久化：文档与证明结论稳定
    proc = start(port + 1, store)
    base2 = f"http://127.0.0.1:{port + 1}"
    try:
        st, doc = _http("GET", f"{base2}/v1/dids/{did}/document")
        check("重启后文档 200", st == 200)
        ms = doc.get("verification_methods", [])
        check("重启后历史两版本升序",
              [m["key_version"] for m in ms] == [1, 2])
        pub2 = ms[1]["public_key"]
        try:
            verify_doc(doc, pub2)
            restart_ok = True
        except Exception:  # noqa: BLE001
            restart_ok = False
        check("重启后证明仍可验签", restart_ok)
        st, d1 = _http("GET", f"{base2}/v1/dids/{did}/document?version=1")
        try:
            verify_doc(d1, pub2)
            restart_v1_ok = True
        except Exception:  # noqa: BLE001
            restart_v1_ok = False
        check("重启后 version=1 证明可验签", st == 200 and restart_v1_ok)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 8. 旧状态迁移：缺密钥元数据的 DID 公开版本 1 且证明可用
    old_priv = crypto.generate_private_key_pem()
    old_pub = crypto.public_key_pem_from_private(old_priv).strip()
    old_did = "did:example:olddid00000000000000000000aa"
    old_store = tempfile.mktemp(suffix=".json")
    with open(old_store, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "dids": {
                    old_did: {
                        "method": "example",
                        "public_key": old_pub,
                        "submitted_public_key": "legacy-handle",
                        "created_at": "2025-01-01T00:00:00Z",
                        "private_key_pem": old_priv,
                    }
                },
                "credentials": {},
                "presentations": {},
            },
            fh,
        )
    proc = start(port + 2, old_store)
    base3 = f"http://127.0.0.1:{port + 2}"
    try:
        st, doc = _http("GET", f"{base3}/v1/dids/{old_did}/document")
        check("旧状态文档 200", st == 200)
        check("旧状态 current_key_version=1",
              doc.get("current_key_version") == 1)
        ms = doc.get("verification_methods", [])
        check("旧状态仅公开版本1 且句柄取提交原文",
              len(ms) == 1 and ms[0].get("key_version") == 1
              and ms[0].get("key_handle") == "legacy-handle"
              and ms[0].get("public_key") == old_pub)
        try:
            verify_doc(doc, old_pub)
            legacy_ok = True
        except Exception:  # noqa: BLE001
            legacy_ok = False
        check("旧状态迁移后证明可用迁移公钥验签", legacy_ok)
        st, got = _http("GET", f"{base3}/v1/dids/{old_did}")
        check("旧 DID 既有 GET 接口仍兼容",
              st == 200 and got.get("key_version") == 1
              and got.get("key_mode") == "server")
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
