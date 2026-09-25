#!/usr/bin/env python3
"""POST /v1/trust/dids/deactivate-sync 外部 DID 停用通告与
POST /v1/trust/dids/verify-document 通告拦截的端到端测试。

直接运行：python3 tests/trust_did_deactivation_sync_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求结构：恰含 body/signature，body 恰含 did/key_version/reason/
  deactivated_at；结构或值非法一律 400 且响应仅含非空中文 error；
- 字段规则：did 非空串、key_version 非布尔正整数、reason 1–256 码点
  且首尾无空白、deactivated_at 为 UTC 秒精度 Z；
- 锚点缺失/吊销/跨租户 -> 200 {"valid":false,"reason":"锚点不可用"}；
  签名编码非法 -> “签名格式错误”；验签失败 -> “签名校验失败”；
  三类失败均不写入；
- 首次接受 201，响应键序 valid,did,key_version,reason,deactivated_at
  且 valid:true；完全重放 200 返回首次记录；同 did 不同通告 409 仅
  含 error；
- verify-document 原验真成功后命中同 did 通告 -> 200 键序 valid,reason，
  值 false、“外部DID已停用：<reason>”；未命中维持原结果；
- 显式空 X-Tenant-ID 400、缺省 default、跨租户隔离；
- 记录跨重启稳定；失败路径不产生任何写入。
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


SYNC_PATH = "/v1/trust/dids/deactivate-sync"
VERIFY_DOC_PATH = "/v1/trust/dids/verify-document"
SUCCESS_KEYS = ["valid", "did", "key_version", "reason", "deactivated_at"]


def main():
    port = 8997
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

    def make_body(did, key_version=1, reason="机构业务终止",
                  deactivated_at="2026-09-20T10:00:00Z"):
        return {
            "did": did,
            "key_version": key_version,
            "reason": reason,
            "deactivated_at": deactivated_at,
        }

    try:
        assert wait_up(port), "服务启动超时"

        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}
        did = "did:web:deact.example"
        priv1, pub1 = _keypair()
        priv2, pub2 = _keypair()

        # 在 TA 注册 did#1 active 锚点
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=TA)
        assert st == 201, r

        def sync(payload=None, raw=None, headers=TA):
            return _http("POST", f"{base}{SYNC_PATH}", payload=payload,
                         raw=raw, headers=headers)

        def signed_sync(body, priv=priv1, headers=TA):
            return sync({"body": body, "signature": crypto.sign(body, priv)},
                        headers=headers)

        # ---------------------------------------------------------- #
        # 0. 显式空 X-Tenant-ID -> 400
        # ---------------------------------------------------------- #
        st, r = sync({"body": make_body(did), "signature": "x"},
                     headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 仅 error",
              st == 400 and set(r) == {"error"} and r["error"])

        # ---------------------------------------------------------- #
        # 1. 请求结构非法 -> 400 仅含非空中文 error
        # ---------------------------------------------------------- #
        bad_requests = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{oops"),
            ("非对象（数组）", None, b"[1]"),
            ("非对象（null）", None, b"null"),
            ("缺 body", {"signature": "x"}, None),
            ("缺 signature", {"body": make_body(did)}, None),
            ("多余字段", {"body": make_body(did), "signature": "x",
                          "extra": 1}, None),
            ("body 非对象", {"body": "x", "signature": "x"}, None),
            ("signature 空串", {"body": make_body(did), "signature": ""},
             None),
            ("signature 非字符串", {"body": make_body(did), "signature": 1},
             None),
        ]
        for name, payload, raw in bad_requests:
            st, r = sync(payload, raw=raw)
            check(f"请求结构 400: {name}",
                  st == 400 and set(r) == {"error"}
                  and isinstance(r["error"], str) and r["error"])

        # ---------------------------------------------------------- #
        # 2. body 字段非法 -> 400
        # ---------------------------------------------------------- #
        good = make_body(did)

        def bad_body(name, mut):
            body = json.loads(json.dumps(good))
            mut(body)
            st, r = sync({"body": body, "signature": "x"})
            check(f"body 字段 400: {name}",
                  st == 400 and set(r) == {"error"} and r["error"])

        bad_body("缺 did", lambda b: b.pop("did"))
        bad_body("缺 key_version", lambda b: b.pop("key_version"))
        bad_body("缺 reason", lambda b: b.pop("reason"))
        bad_body("缺 deactivated_at", lambda b: b.pop("deactivated_at"))
        bad_body("多余字段", lambda b: b.update(extra=1))
        bad_body("did 空串", lambda b: b.update(did=""))
        bad_body("did 非字符串", lambda b: b.update(did=1))
        bad_body("key_version 布尔", lambda b: b.update(key_version=True))
        bad_body("key_version 0", lambda b: b.update(key_version=0))
        bad_body("key_version 负数", lambda b: b.update(key_version=-1))
        bad_body("key_version 字符串", lambda b: b.update(key_version="1"))
        bad_body("key_version 小数", lambda b: b.update(key_version=1.5))
        bad_body("reason 空串", lambda b: b.update(reason=""))
        bad_body("reason 纯空白", lambda b: b.update(reason="   "))
        bad_body("reason 首尾空白", lambda b: b.update(reason=" 停用 "))
        bad_body("reason 尾部换行", lambda b: b.update(reason="停用\n"))
        bad_body("reason 超长", lambda b: b.update(reason="长" * 257))
        bad_body("reason 非字符串", lambda b: b.update(reason=1))
        bad_body("deactivated_at 毫秒",
                 lambda b: b.update(deactivated_at="2026-09-20T10:00:00.000Z"))
        bad_body("deactivated_at 缺 Z",
                 lambda b: b.update(deactivated_at="2026-09-20T10:00:00"))
        bad_body("deactivated_at 偏移",
                 lambda b: b.update(
                     deactivated_at="2026-09-20T10:00:00+08:00"))
        bad_body("deactivated_at 非法时刻",
                 lambda b: b.update(deactivated_at="2026-13-40T99:99:99Z"))
        bad_body("deactivated_at 非字符串",
                 lambda b: b.update(deactivated_at=123))

        # reason 边界：恰 256 码点合法（但锚点版本 2 未注册 -> 200 锚点不可用）
        body_256 = make_body(did, key_version=2, reason="界" * 256)
        st, r = signed_sync(body_256)
        check("reason 恰 256 码点通过字段校验",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 3. 锚点/签名失败 -> 200 固定原因，且不写入
        # ---------------------------------------------------------- #
        # 3a. 锚点不存在（未知 DID）
        ghost = make_body("did:web:ghost.example")
        st, r = signed_sync(ghost)
        check("锚点不存在 -> 200 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        # 3b. 锚点版本不存在
        body_v9 = make_body(did, key_version=9)
        st, r = signed_sync(body_v9)
        check("锚点版本不存在 -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        # 3c. 跨租户：TB 无锚点
        st, r = signed_sync(make_body(did), headers=TB)
        check("跨租户锚点不可探测 -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        # 3d. 锚点已吊销
        did_rev = "did:web:revoked.example"
        priv_r, pub_r = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_rev, "public_key": pub_r, "key_version": 1},
                      headers=TA)
        assert st == 201
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_rev}/1/status",
                      {"status": "revoked"}, headers=TA)
        assert st == 200
        st, r = signed_sync(make_body(did_rev), priv=priv_r)
        check("锚点已吊销 -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        # 3e. 签名格式错误
        st, r = sync({"body": make_body(did), "signature": "%%%bad%%%"})
        check("签名 base64url 非法 -> 签名格式错误",
              st == 200 and r == {"valid": False, "reason": "签名格式错误"})
        st, r = sync({"body": make_body(did), "signature": "AAAA"})
        check("签名长度非法 -> 签名格式错误",
              st == 200 and r == {"valid": False, "reason": "签名格式错误"})
        # 3f. 验签失败：错误私钥
        st, r = signed_sync(make_body(did), priv=priv2)
        check("错误私钥 -> 签名校验失败",
              st == 200 and r == {"valid": False, "reason": "签名校验失败"})
        # 3g. 验签失败：正文被篡改（签名对应原文）
        tampered = make_body(did, reason="被改过的原因")
        sig_orig = crypto.sign(make_body(did), priv1)
        st, r = sync({"body": tampered, "signature": sig_orig})
        check("正文篡改 -> 签名校验失败",
              st == 200 and r == {"valid": False, "reason": "签名校验失败"})

        # 失败路径不写入：此后同 did 首次合法通告仍应为 201 而非 409
        # （在下方首次成功用例中间接验证）

        # ---------------------------------------------------------- #
        # 4. 首次接受 201、键序与字段
        # ---------------------------------------------------------- #
        body1 = make_body(did)
        st, r = signed_sync(body1)
        check("首次接受 201 键序 valid,did,key_version,reason,deactivated_at",
              st == 201 and list(r.keys()) == SUCCESS_KEYS
              and r["valid"] is True and r["did"] == did
              and r["key_version"] == 1 and r["reason"] == "机构业务终止"
              and r["deactivated_at"] == "2026-09-20T10:00:00Z")

        # ---------------------------------------------------------- #
        # 5. 完全重放 200 返回首次记录
        # ---------------------------------------------------------- #
        st, r = signed_sync(body1)
        check("完全重放 200 返回首次记录",
              st == 200 and list(r.keys()) == SUCCESS_KEYS
              and r["valid"] is True and r["reason"] == "机构业务终止"
              and r["deactivated_at"] == "2026-09-20T10:00:00Z")

        # ---------------------------------------------------------- #
        # 6. 同 did 不同通告 -> 409 仅含 error
        # ---------------------------------------------------------- #
        for name, mut in (
            ("不同 reason", lambda b: b.update(reason="另一条原因")),
            ("不同 deactivated_at",
             lambda b: b.update(deactivated_at="2026-09-21T00:00:00Z")),
            ("不同 key_version", lambda b: b.update(key_version=2)),
        ):
            conflict_body = make_body(did)
            mut(conflict_body)
            # key_version=2 无锚点时会先命中锚点不可用；为走到冲突分支，
            # 对 key_version 情形注册 v2 锚点
            if conflict_body["key_version"] == 2:
                _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=TA)
                st, r = signed_sync(conflict_body, priv=priv2)
            else:
                st, r = signed_sync(conflict_body)
            check(f"同 did {name} -> 409 仅 error",
                  st == 409 and set(r) == {"error"} and r["error"])

        # 409 不写入：通告仍为首次内容
        st, r = signed_sync(body1)
        check("409 后重放仍返回首次记录",
              st == 200 and r["reason"] == "机构业务终止")

        # ---------------------------------------------------------- #
        # 7. verify-document 命中通告 -> 外部DID已停用
        # ---------------------------------------------------------- #
        def make_document(doc_did, pem, priv, version=1):
            doc = {
                "did": doc_did,
                "current_key_version": version,
                "verification_methods": [{
                    "key_version": version,
                    "key_handle": f"handle-{version}",
                    "public_key": pem,
                }],
            }
            doc["document_proof"] = crypto.sign(doc, priv)
            return doc

        # 未停用 DID：锚点 + 文档验真成功
        did_ok = "did:web:still-active.example"
        priv_ok, pub_ok = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_ok, "public_key": pub_ok, "key_version": 1},
                      headers=TA)
        assert st == 201
        doc_ok = make_document(did_ok, pub_ok, priv_ok)
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": doc_ok}, headers=TA)
        check("未通告 DID 文档验真维持 valid:true",
              st == 200 and r == {"valid": True})

        # 已停用 DID（did 的当前锚点为 v1=pub1；文档用 v1）
        doc_deact = make_document(did, pub1, priv1)
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": doc_deact}, headers=TA)
        check("命中停用通告 -> 200 键序 valid,reason 外部DID已停用",
              st == 200 and list(r.keys()) == ["valid", "reason"]
              and r["valid"] is False
              and r["reason"] == "外部DID已停用：机构业务终止")

        # 跨租户：TB 未登记通告，同 did 文档在 TB 验真（需 TB 锚点）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=TB)
        assert st == 201
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": doc_deact}, headers=TB)
        check("跨租户通告不可见：TB 验真仍 valid:true",
              st == 200 and r == {"valid": True})

        # 原验真失败优先：篡改文档仍返回签名校验失败而非停用原因
        tampered_doc = json.loads(json.dumps(doc_deact))
        tampered_doc["verification_methods"][0]["key_handle"] = "changed"
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": tampered_doc}, headers=TA)
        check("原验真失败优先于停用通告",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # ---------------------------------------------------------- #
        # 8. 缺省 default 租户隔离
        # ---------------------------------------------------------- #
        did_def = "did:web:default-tenant.example"
        priv_d, pub_d = _keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_def, "public_key": pub_d, "key_version": 1})
        assert st == 201
        body_def = make_body(did_def, reason="默认租户停用")
        st, r = signed_sync(body_def, priv=priv_d, headers={})
        check("缺省 default 租户首次接受 201",
              st == 201 and r["valid"] is True)
        st, r = signed_sync(body_def, priv=priv_d, headers=TA)
        check("TA 看不到 default 锚点 -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        doc_def = make_document(did_def, pub_d, priv_d)
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": doc_def})
        check("default 租户命中停用通告",
              st == 200 and r == {"valid": False,
                                  "reason": "外部DID已停用：默认租户停用"})

        # ---------------------------------------------------------- #
        # 9. 重启后通告与拦截结论稳定
        # ---------------------------------------------------------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"

        st, r = signed_sync(body1)
        check("重启后完全重放仍 200 首次记录",
              st == 200 and list(r.keys()) == SUCCESS_KEYS
              and r["valid"] is True and r["reason"] == "机构业务终止")
        conflict_body = make_body(did, reason="重启后不同原因")
        st, r = signed_sync(conflict_body)
        check("重启后异通告仍 409",
              st == 409 and set(r) == {"error"} and r["error"])
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": doc_deact}, headers=TA)
        check("重启后 verify-document 拦截结论稳定",
              st == 200 and r == {"valid": False,
                                  "reason": "外部DID已停用：机构业务终止"})
        st, r = _http("POST", f"{base}{VERIFY_DOC_PATH}",
                      {"document": doc_ok}, headers=TA)
        check("重启后未通告 DID 仍 valid:true",
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
