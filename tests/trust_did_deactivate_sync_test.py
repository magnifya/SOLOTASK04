#!/usr/bin/env python3
"""外部 DID 停用通告 POST /v1/trust/dids/deactivate-sync 与
POST /v1/trust/dids/verify-document 停用联动的端到端测试。

覆盖：
- 请求恰含 body/signature，body 恰含 did/key_version/reason/deactivated_at；
  结构或值非法一律 400 且响应仅含非空中文 error；
- 锚点不可用 / 签名格式错误 / 签名校验失败均 200 + valid:false +
  恰为“锚点不可用”/“签名格式错误”/“签名校验失败”，且不写入；
- 首次接受 201、完全重放 200、同 did 不同通告 409（仅含 error）；
  成功响应键序 valid,did,key_version,reason,deactivated_at；
- DID 文档验真原成功后命中同 did 通告 -> 200 valid:false
  “外部DID已停用：<reason>”，否则维持原结果；
- X-Tenant-ID 缺省 default、显式空 400、跨租户隔离；
- 落盘失败回滚、重启后结论稳定。

直接运行：python3 tests/trust_did_deactivate_sync_test.py
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

SYNC_PATH = "/v1/trust/dids/deactivate-sync"
DOC_PATH = "/v1/trust/dids/verify-document"

PORT = 8971
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

SUCCESS_KEYS = ["valid", "did", "key_version", "reason", "deactivated_at"]


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


def start_server(store=STORE, port=PORT):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def gen_keypair():
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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    proc = start_server()
    try:
        T = {}
        OT = {"X-Tenant-ID": "other"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:issuer.example"
        did2 = "did:web:other.example"

        def sync(payload=None, headers=T, raw=None):
            return _http("POST", f"{BASE}{SYNC_PATH}", payload,
                         headers=headers, raw=raw)

        def register_anchor(a_did, pub, version=1, headers=T):
            st, r = _http(
                "POST", f"{BASE}/v1/trust/anchors",
                {"did": a_did, "public_key": pub, "key_version": version},
                headers=headers,
            )
            assert st in (200, 201), (st, r)

        def make_body(a_did=did, version=1, reason="密钥泄露",
                      ts="2026-01-02T03:04:05Z"):
            return {
                "did": a_did,
                "key_version": version,
                "reason": reason,
                "deactivated_at": ts,
            }

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        # ---------------------------------------------------------- #
        # 1. 结构/值非法 -> 400 且仅含非空中文 error
        # ---------------------------------------------------------- #
        st, r = sync({"body": {}, "signature": "x"},
                     headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400 and set(r) == {"error"})

        bad_requests = [
            ("空体", None, b""),
            ("非法 JSON", None, b"{oops"),
            ("非对象", None, b"[]"),
            ("缺 signature", {"body": make_body()}, None),
            ("缺 body", {"signature": "x"}, None),
            ("多余顶层字段", {**signed(make_body()), "x": 1}, None),
            ("body 非对象", {"body": [], "signature": "x"}, None),
            ("signature 空串", {"body": make_body(), "signature": ""}, None),
            ("signature 非字符串", {"body": make_body(), "signature": 1}, None),
        ]
        for label, payload, raw in bad_requests:
            st2, r2 = sync(payload, raw=raw)
            check(f"非法请求 400 仅含 error: {label}",
                  st2 == 400 and set(r2) == {"error"}
                  and isinstance(r2["error"], str) and r2["error"].strip())

        good = make_body()
        bad_bodies = [
            ("body 缺 did", {k: v for k, v in good.items() if k != "did"}),
            ("body 缺 key_version",
             {k: v for k, v in good.items() if k != "key_version"}),
            ("body 缺 reason",
             {k: v for k, v in good.items() if k != "reason"}),
            ("body 缺 deactivated_at",
             {k: v for k, v in good.items() if k != "deactivated_at"}),
            ("body 多余字段", {**good, "extra": 1}),
            ("did 空串", make_body(a_did="")),
            ("did 非字符串", make_body(a_did=1)),
            ("key_version 布尔", make_body(version=True)),
            ("key_version 零", make_body(version=0)),
            ("key_version 负", make_body(version=-1)),
            ("key_version 字符串", make_body(version="1")),
            ("reason 空串", make_body(reason="")),
            ("reason 非字符串", make_body(reason=1)),
            ("reason 257 码点", make_body(reason="x" * 257)),
            ("reason 前空白", make_body(reason=" 停用")),
            ("reason 后空白", make_body(reason="停用 ")),
            ("deactivated_at 非 Z", make_body(ts="2026-01-02 03:04:05")),
            ("deactivated_at 带偏移",
             make_body(ts="2026-01-02T03:04:05+00:00")),
            ("deactivated_at 毫秒",
             make_body(ts="2026-01-02T03:04:05.000Z")),
            ("deactivated_at 非法时刻",
             make_body(ts="2026-13-02T03:04:05Z")),
        ]
        for label, body in bad_bodies:
            st2, r2 = sync({"body": body, "signature": "x"})
            check(f"非法 body 400 仅含 error: {label}",
                  st2 == 400 and set(r2) == {"error"}
                  and isinstance(r2["error"], str) and r2["error"].strip())

        # reason 边界：1 与 256 码点均合法（锚点未注册 -> 锚点不可用）
        for n in (1, 256):
            st2, r2 = sync(signed(make_body(reason="理" * n)))
            check(f"reason {n} 码点通过结构校验",
                  st2 == 200 and r2 == {
                      "valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 2. 锚点/签名失败 -> 200 valid:false，且不写入
        # ---------------------------------------------------------- #
        st, r = sync(signed(make_body()))
        check("锚点未注册 -> 200 锚点不可用",
              st == 200 and list(r) == ["valid", "reason"]
              and r == {"valid": False, "reason": "锚点不可用"})

        register_anchor(did, pub1)
        register_anchor(did2, pub2)

        # 吊销锚点后不可用
        register_anchor(did2, pub2)  # 幂等
        st, r = _http("PUT", f"{BASE}/v1/trust/anchors/{did2}/1/status",
                      {"status": "revoked"}, headers=T)
        assert st == 200, (st, r)
        st, r = sync(signed(make_body(a_did=did2), priv=priv2))
        check("锚点已吊销 -> 200 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})

        st, r = sync({"body": make_body(), "signature": "!!!"})
        check("签名格式错误 -> 200",
              st == 200 and r == {"valid": False, "reason": "签名格式错误"})

        st, r = sync(signed(make_body(), priv=priv2))  # 私钥不匹配
        check("签名校验失败 -> 200",
              st == 200 and r == {"valid": False, "reason": "签名校验失败"})

        # 失败不写入：随后合法请求仍属首次（201）
        # ---------------------------------------------------------- #
        # 3. 首次 201 / 完全重放 200 / 不同通告 409
        # ---------------------------------------------------------- #
        body1 = make_body()
        st, r = sync(signed(body1))
        check("首次接受 201 键序与值",
              st == 201 and list(r) == SUCCESS_KEYS
              and r == {"valid": True, "did": did, "key_version": 1,
                        "reason": "密钥泄露",
                        "deactivated_at": "2026-01-02T03:04:05Z"})

        st, r = sync(signed(body1))
        check("完全重放 200 同值",
              st == 200 and list(r) == SUCCESS_KEYS
              and r["valid"] is True and r["reason"] == "密钥泄露")

        # 重放但签名不同（同一 body 重新签名）仍属完全重放
        st, r = sync(signed(body1))
        check("重放幂等不改写", st == 200 and r["valid"] is True)

        # key_version 不同的通告：需先注册 v2 锚点才能通过验签
        priv1b, pub1b = gen_keypair()
        register_anchor(did, pub1b, version=2)
        for label, body2 in [
            ("不同 reason", make_body(reason="另一原因")),
            ("不同 deactivated_at", make_body(ts="2026-01-03T00:00:00Z")),
        ]:
            st2, r2 = sync(signed(body2))
            check(f"同 did 不同通告 409 仅含 error: {label}",
                  st2 == 409 and set(r2) == {"error"}
                  and isinstance(r2["error"], str) and r2["error"].strip())
        st2, r2 = sync({
            "body": make_body(version=2),
            "signature": crypto.sign(make_body(version=2), priv1b),
        })
        check("同 did 不同通告 409 仅含 error: 不同 key_version",
              st2 == 409 and set(r2) == {"error"}
              and isinstance(r2["error"], str) and r2["error"].strip())

        # 409 不写入：重放原通告仍 200
        st, r = sync(signed(body1))
        check("409 后原通告重放仍 200",
              st == 200 and r["valid"] is True
              and r["reason"] == "密钥泄露")

        # ---------------------------------------------------------- #
        # 4. DID 文档验真联动
        # ---------------------------------------------------------- #
        def make_document(a_did, pub, version=1):
            doc = {
                "did": a_did,
                "current_key_version": version,
                "verification_methods": [
                    {"key_version": version,
                     "key_handle": f"{a_did}#key-{version}",
                     "public_key": pub},
                ],
            }
            proof = crypto.sign(doc, priv1 if a_did == did else priv2)
            return {**doc, "document_proof": proof}

        def verify_doc(doc, headers=T):
            return _http("POST", f"{BASE}{DOC_PATH}",
                         {"document": doc}, headers=headers)

        # did 已有通告：验真原成功 -> 停用原因
        st, r = verify_doc(make_document(did, pub1))
        check("验真命中停用通告",
              st == 200 and list(r) == ["valid", "reason"]
              and r == {"valid": False, "reason": "外部DID已停用：密钥泄露"})

        # did2 无通告（其通告因锚点吊销未写入）：维持原结果
        st, r = verify_doc(make_document(did2, pub2))
        check("无通告 did 文档验真维持原结果（锚点吊销原因）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))

        # 未停用且锚点可用的 did3：valid:true 不受影响
        priv3, pub3 = gen_keypair()
        did3 = "did:web:third.example"
        register_anchor(did3, pub3)
        doc3 = {
            "did": did3,
            "current_key_version": 1,
            "verification_methods": [
                {"key_version": 1, "key_handle": "k1",
                 "public_key": pub3},
            ],
        }
        doc3 = {**doc3, "document_proof": crypto.sign(doc3, priv3)}
        st, r = verify_doc(doc3)
        check("未停用 did 文档验真仍 valid:true",
              st == 200 and r == {"valid": True})

        # ---------------------------------------------------------- #
        # 5. 多租户：缺省 default、跨租户隔离
        # ---------------------------------------------------------- #
        # 他租户无 did 锚点 -> 锚点不可用；也看不到 default 的通告
        st, r = sync(signed(body1), headers=OT)
        check("他租户无锚点 -> 锚点不可用",
              st == 200 and r == {"valid": False, "reason": "锚点不可用"})
        st, r = verify_doc(make_document(did, pub1), headers=OT)
        check("他租户验真不受 default 通告影响（锚点缺失）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("锚点"))

        # 他租户独立注册锚点并同步自己的通告
        register_anchor(did, pub1, headers=OT)
        body_ot = make_body(reason="他租户停用", ts="2026-02-01T00:00:00Z")
        st, r = sync(signed(body_ot), headers=OT)
        check("他租户首次接受 201",
              st == 201 and r["valid"] is True
              and r["reason"] == "他租户停用")
        st, r = verify_doc(make_document(did, pub1), headers=OT)
        check("他租户验真命中自己的通告",
              st == 200 and r == {
                  "valid": False, "reason": "外部DID已停用：他租户停用"})
        st, r = verify_doc(make_document(did, pub1))
        check("default 通告不受他租户影响",
              st == 200 and r == {
                  "valid": False, "reason": "外部DID已停用：密钥泄露"})

        # 缺省头即 default：通告仍命中
        st, r = sync(signed(body1))
        check("缺省租户头重放 200", st == 200 and r["valid"] is True)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 6. 直接存储层：落盘失败回滚
    # -------------------------------------------------------------- #
    from vcbackend.store import VCStore  # noqa: E402

    p2 = tempfile.mktemp(suffix=".json")
    s2 = VCStore(p2)
    priv4, pub4 = gen_keypair()
    s2.register_trust_anchor("t", "did:web:rb.example", pub4, 1)
    rb_body = {
        "did": "did:web:rb.example",
        "key_version": 1,
        "reason": "回滚测试",
        "deactivated_at": "2026-03-01T00:00:00Z",
    }
    rb_payload = {"body": rb_body, "signature": crypto.sign(rb_body, priv4)}

    def _boom():
        raise OSError("模拟落盘失败")

    s2._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        s2.sync_did_deactivation("t", rb_payload)
    except OSError:
        raised = True
    check("落盘失败时 sync_did_deactivation 抛错", raised)
    check("落盘失败状态回滚（无通告记录）",
          s2.get_did_deactivation("t", "did:web:rb.example") is None)

    # -------------------------------------------------------------- #
    # 7. 重启持久化：通告与验真结论稳定
    # -------------------------------------------------------------- #
    proc2 = start_server()
    try:
        st, r = sync(signed(body1))
        check("重启后重放仍 200 同值",
              st == 200 and list(r) == SUCCESS_KEYS
              and r["valid"] is True and r["reason"] == "密钥泄露")
        st, r = _http("POST", f"{BASE}{DOC_PATH}",
                      {"document": make_document(did, pub1)})
        check("重启后验真仍命中停用通告",
              st == 200 and r == {
                  "valid": False, "reason": "外部DID已停用：密钥泄露"})
        st, r = sync(signed(make_body(reason="重启后不同")))
        check("重启后不同通告仍 409",
              st == 409 and set(r) == {"error"})
    finally:
        proc2.terminate()
        proc2.wait(timeout=10)

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
