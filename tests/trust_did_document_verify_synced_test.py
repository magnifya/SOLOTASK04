#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document-synced 以同步锚点快照验真外部
DID 文档的端到端测试。

直接运行：python3 tests/trust_did_document_verify_synced_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/document（非空字符串、非布尔非负整数、
  对象）；空体、非法 JSON、非对象、键集或类型错误均 400 且仅
  {"error":"请求非法"}；显式空租户头 400；
- 404/409：signer_did 未同步或跨租户 404 同形；at 超过检查点 409
  同形且优先于文档字段校验；
- 200 失败：文档四字段/验证方法升序无重/P-256 PEM/禁私钥/当前版本
  最高规则沿用现有 DID 文档验真协议，失败原因统一“DID文档非法”；
  取该来源 cursor<=at 事件中 (did,current_key_version) 末项，缺失、
  非 active、uses 无 did 或公钥与文档当前版本不逐字相同均为
  “同步锚点不可用”；签名格式错误/签名校验失败依次同形；验签成功后
  命中外部 DID 停用通告返“外部DID已停用：<reason>”；失败响应键序恰
  为 valid、reason；
- 成功仅 {"valid":true}；
- 纯只读：不推进检查点、不改同步页/锚点/状态、不记审计；重启一致；
  租户隔离。
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

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
DEACTIVATE_PATH = "/v1/trust/dids/deactivate-sync"
VERIFY_PATH = "/v1/trust/dids/verify-document-synced"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
NO_DID_USES = ["generic", "vc", "vp", "proof", "status", "deactivation"]
SIGNER_DID = "did:web:remote-signer"
DOC_DID = "did:web:remote-org"
NODID_DID = "did:web:no-did-use"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


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


def gen_keypair():
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def _p384_public_pem():
    priv = ec.generate_private_key(ec.SECP384R1())
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def make_event(cursor, did, key_version=1, action="registered",
               status="active", uses=None, pub="pem"):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": key_version,
        "public_key": pub,
        "status": status,
        "uses": list(uses if uses is not None else ALL_USES),
    }


def build_changes(events, after, signer_priv):
    signed = {
        "events": events,
        "next_after": events[-1]["cursor"] if events else after,
        "signer_did": SIGNER_DID,
        "signer_key_version": 1,
    }
    changes = dict(signed)
    changes["signature"] = crypto.sign(signed, signer_priv)
    return {"changes": changes, "after": after}


def make_document(did, methods, current_version, signer_private_pem):
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


def test_http():
    port = 9183
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

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
    TA = {"X-Tenant-ID": "tenant-a"}
    TB = {"X-Tenant-ID": "tenant-b"}
    TC = {"X-Tenant-ID": "tenant-c"}

    signer_priv, signer_pub = gen_keypair()
    a1_priv, a1_pub = gen_keypair()
    a2_priv, a2_pub = gen_keypair()
    nodid_priv, nodid_pub = gen_keypair()
    other_priv, other_pub = gen_keypair()

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers if headers is not None else TA,
                     raw=raw)

    def expect_status_error(name, st, raw, status, message):
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(
            name,
            st == status
            and body == {"error": message},
        )

    def expect_400(name, payload=None, headers=None, raw=None):
        st, resp = verify(payload=payload, headers=headers or TA, raw=raw)
        expect_status_error(name, st, resp, 400, "请求非法")

    def expect_invalid(name, payload, reason, headers=None):
        st, raw = verify(payload=payload, headers=headers or TA)
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(
            name,
            st == 200
            and isinstance(body, dict)
            and list(body.keys()) == ["valid", "reason"]
            and body["valid"] is False
            and body["reason"] == reason,
        )

    def synced_payload(document, at, signer=SIGNER_DID):
        return {"signer_did": signer, "at": at, "document": document}

    try:
        # 登记变更流签名方锚点（两租户；默认全用途，含 generic）
        for headers in (TA, TB):
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": SIGNER_DID, "public_key": signer_pub,
                 "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # 同步两页（tenant-a 检查点=4；tenant-b 仅首页，检查点=2）
        # c1: DOC_DID#1 注册(active 全用途)；c2: NODID_DID#1 无 did 用途
        # c3: DOC_DID#1 吊销；c4: DOC_DID#2 轮换(active)
        page1 = build_changes(
            [
                make_event(1, DOC_DID, 1, pub=a1_pub),
                make_event(2, NODID_DID, 1, uses=NO_DID_USES, pub=nodid_pub),
            ],
            0, signer_priv,
        )
        page2 = build_changes(
            [
                make_event(3, DOC_DID, 1, action="revoked",
                           status="revoked", pub=a1_pub),
                make_event(4, DOC_DID, 2, action="rotated", pub=a2_pub),
            ],
            2, signer_priv,
        )
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TA)
        assert st == 201
        st, _ = _http("POST", base + SYNC_PATH, page2, headers=TA)
        assert st == 200
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TB)
        assert st == 201

        doc_v1 = make_document(DOC_DID, [(1, a1_pub)], 1, a1_priv)
        doc_v2 = make_document(DOC_DID, [(1, a1_pub), (2, a2_pub)], 2,
                               a2_priv)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议（错误体恰为 {"error":"请求非法"}）
        # ---------------------------------------------------------- #
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("空体 400", raw=b"")
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "document": doc_v1})
        expect_400("缺 at 400",
                   payload={"signer_did": SIGNER_DID, "document": doc_v1})
        expect_400("缺 document 400",
                   payload={"signer_did": SIGNER_DID, "at": 1})
        expect_400("多余字段 400",
                   payload={"signer_did": SIGNER_DID, "at": 1,
                            "document": doc_v1, "extra": 1})
        expect_400("signer_did 空串 400",
                   payload={"signer_did": "", "at": 1, "document": doc_v1})
        expect_400("signer_did 非字符串 400",
                   payload={"signer_did": 1, "at": 1, "document": doc_v1})
        expect_400("at 布尔 400",
                   payload={"signer_did": SIGNER_DID, "at": True,
                            "document": doc_v1})
        expect_400("at 负数 400",
                   payload={"signer_did": SIGNER_DID, "at": -1,
                            "document": doc_v1})
        expect_400("at 字符串 400",
                   payload={"signer_did": SIGNER_DID, "at": "1",
                            "document": doc_v1})
        expect_400("at 小数 400",
                   payload={"signer_did": SIGNER_DID, "at": 1.5,
                            "document": doc_v1})
        expect_400("document 非对象 400",
                   payload={"signer_did": SIGNER_DID, "at": 1,
                            "document": []})
        expect_400("document 为字符串 400",
                   payload={"signer_did": SIGNER_DID, "at": 1,
                            "document": "x"})
        # 显式空租户头由路由统一判 400（error 为非空中文，不要求同形）
        st, raw = verify(payload=synced_payload(doc_v1, 1),
                         headers={"X-Tenant-ID": ""})
        expect_status_error_any = (
            st == 400 and json.loads(raw.decode()).get("error")
        )
        check("显式空租户头 400", expect_status_error_any)
        st, raw = verify(raw=b"", headers={"X-Tenant-ID": ""})
        check("显式空租户头 + 空体仍 400",
              st == 400 and bool(json.loads(raw.decode()).get("error")))

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户（错误体恰为 {"error":"同步来源不存在"}）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload(doc_v1, 1,
                                                signer="did:web:nobody"))
        expect_status_error("未知签名方 404", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TC)
        expect_status_error("跨租户未同步 404", st, raw, 404,
                            "同步来源不存在")

        # ---------------------------------------------------------- #
        # 3. 409：at 超过检查点（优先于文档字段错误）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload(doc_v1, 5))
        expect_status_error("at 超过检查点 409", st, raw, 409,
                            "同步游标冲突")
        st, raw = verify(payload=synced_payload(doc_v1, 3), headers=TB)
        expect_status_error("tenant-b at 超过其检查点 409", st, raw, 409,
                            "同步游标冲突")
        st, raw = verify(
            payload={"signer_did": SIGNER_DID, "at": 5, "document": {}})
        expect_status_error("at 超检查点优先于文档字段错误 409", st, raw,
                            409, "同步游标冲突")

        # ---------------------------------------------------------- #
        # 4. 200：文档结构类失败统一“DID文档非法”
        # ---------------------------------------------------------- #
        def tamper(mut):
            d = json.loads(json.dumps(doc_v2))
            mut(d)
            st, raw = verify(payload=synced_payload(d, 4))
            try:
                body = json.loads(raw.decode() or "{}")
            except ValueError:
                body = None
            return (
                st == 200
                and isinstance(body, dict)
                and list(body.keys()) == ["valid", "reason"]
                and body["valid"] is False
                and body["reason"] == "DID文档非法"
            )

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
            ("current_key_version 为布尔",
             lambda d: d.update(current_key_version=True)),
            ("document_proof 为空",
             lambda d: d.update(document_proof="")),
            ("verification_methods 非数组",
             lambda d: d.update(verification_methods={})),
            ("verification_methods 空数组",
             lambda d: d.update(verification_methods=[])),
            ("方法项非对象",
             lambda d: d.update(verification_methods=[1])),
            ("方法缺 key_version",
             lambda d: d["verification_methods"][0].pop("key_version")),
            ("方法含多余字段",
             lambda d: d["verification_methods"][0].update(extra=1)),
            ("方法 key_version 布尔",
             lambda d: d["verification_methods"][0].update(key_version=True)),
            ("方法 key_handle 为空",
             lambda d: d["verification_methods"][0].update(key_handle="")),
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
                 key_handle=a1_priv)),
        ]
        for name, mut in cases:
            check(f"结构失败: {name}", tamper(mut))

        # ---------------------------------------------------------- #
        # 5. 200：同步锚点不可用
        # ---------------------------------------------------------- #
        expect_invalid(
            "文档 DID 不在同步事件",
            synced_payload(
                make_document("did:web:unknown", [(1, a1_pub)], 1, a1_priv),
                1),
            "同步锚点不可用",
        )
        expect_invalid(
            "at 之前锚点尚未注册",
            synced_payload(doc_v2, 2),
            "同步锚点不可用",
        )
        expect_invalid(
            "末事件为吊销",
            synced_payload(doc_v1, 3),
            "同步锚点不可用",
        )
        expect_invalid(
            "uses 无 did",
            synced_payload(
                make_document(NODID_DID, [(1, nodid_pub)], 1, nodid_priv),
                2),
            "同步锚点不可用",
        )
        expect_invalid(
            "公钥与文档当前版本不逐字相同",
            synced_payload(
                make_document(DOC_DID, [(1, a2_pub)], 1, a2_priv), 1),
            "同步锚点不可用",
        )
        # 视图差异：tenant-b 检查点=2，v2 在其视图中不存在
        expect_invalid(
            "他租户视图无该版本",
            synced_payload(doc_v2, 2),
            "同步锚点不可用",
            headers=TB,
        )
        # 即使文档结构非法也先判结构（锚点不影响该结论）
        expect_invalid(
            "文档非法优先于锚点不可用",
            synced_payload(
                make_document("did:web:unknown", [(1, a1_pub)], 2, a1_priv),
                1),
            "DID文档非法",
        )

        # ---------------------------------------------------------- #
        # 6. 200：签名格式错误 / 签名校验失败
        # ---------------------------------------------------------- #
        d = json.loads(json.dumps(doc_v1))
        d["document_proof"] = "%%%not-base64url%%%"
        expect_invalid("签名 base64url 非法 -> 签名格式错误",
                       synced_payload(d, 1), "签名格式错误")
        d = json.loads(json.dumps(doc_v1))
        d["document_proof"] = "AAAA"  # 可解码但不足 64 字节
        expect_invalid("签名长度非法 -> 签名格式错误",
                       synced_payload(d, 1), "签名格式错误")
        d = json.loads(json.dumps(doc_v1))
        d["verification_methods"][0]["key_handle"] = "changed"
        expect_invalid("篡改方法内容 -> 签名校验失败",
                       synced_payload(d, 1), "签名校验失败")
        expect_invalid(
            "错误签名者 -> 签名校验失败",
            synced_payload(
                make_document(DOC_DID, [(1, a1_pub)], 1, a2_priv), 1),
            "签名校验失败",
        )
        # 较早错误优先：锚点不可用优先于签名格式错误
        d = json.loads(json.dumps(doc_v2))
        d["document_proof"] = "not-a-signature"
        expect_invalid("锚点不可用优先于签名格式错误",
                       synced_payload(d, 2), "同步锚点不可用")

        # ---------------------------------------------------------- #
        # 7. 成功：仅 {"valid":true}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload(doc_v1, 1))
        body = json.loads(raw)
        check("v1 在 c1 后成功仅 valid:true",
              st == 200 and list(body.keys()) == ["valid"]
              and body["valid"] is True)
        st, raw = verify(payload=synced_payload(doc_v1, 2))
        check("v1 在 c2 时点仍成功",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = verify(payload=synced_payload(doc_v2, 4))
        check("v2 轮换后成功，响应恰为 valid:true",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TB)
        check("tenant-b 视图内 v1 验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 8. 停用通告：验签成功后命中 -> “外部DID已停用：<reason>”
        #    （deactivate-sync 验的是本租户本地锚点，与同步页无关）
        # ---------------------------------------------------------- #
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": DOC_DID, "public_key": a2_pub, "key_version": 2},
            headers=TA,
        )
        assert st in (200, 201)
        notice_body = {
            "did": DOC_DID,
            "key_version": 2,
            "reason": "机构业务终止",
            "deactivated_at": "2026-09-20T10:00:00Z",
        }
        notice = {
            "body": notice_body,
            "signature": crypto.sign(notice_body, a2_priv),
        }
        st, raw = _http("POST", base + DEACTIVATE_PATH, notice, headers=TA)
        assert st in (200, 201), raw
        expect_invalid(
            "命中外部 DID 停用通告",
            synced_payload(doc_v2, 4),
            "外部DID已停用：机构业务终止",
        )
        # 跨租户通告互不可见：tenant-b 视图内 v1 仍成功
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TB)
        check("跨租户停用通告不可见",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 9. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={SIGNER_DID}",
            headers=TA)
        assert st == 200

        verify(payload=synced_payload(doc_v2, 4))
        verify(payload=synced_payload(doc_v2, 2))
        verify(payload=synced_payload(doc_v1, 5))
        verify(raw=b"{}")

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={SIGNER_DID}",
            headers=TA)
        check("验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        st, raw = _http("POST", base + SYNC_PATH, page2, headers=TA)
        check("验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # 缺省租户头：default 租户无该来源 -> 404
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers={})
        expect_status_error("缺省租户头与 TA 隔离（default 无来源）",
                            st, raw, 404, "同步来源不存在")

        # ---------------------------------------------------------- #
        # 10. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(payload=synced_payload(doc_v1, 1),
                               headers=TB)
        st, na_before = verify(payload=synced_payload(doc_v1, 3))
        st, deact_before = verify(payload=synced_payload(doc_v2, 4))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TB)
        check("重启后成功响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=synced_payload(doc_v1, 3))
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == na_before)
        st, raw = verify(payload=synced_payload(doc_v2, 4))
        check("重启后停用通告结论逐字节一致",
              st == 200 and raw == deact_before)
        st, raw = verify(payload=synced_payload(doc_v1, 5))
        expect_status_error("重启后 at 超检查点仍 409", st, raw, 409,
                            "同步游标冲突")
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TC)
        expect_status_error("重启后跨租户仍 404", st, raw, 404,
                            "同步来源不存在")

        # 既有 verify-document 不受影响：TA 本地存在 DOC_DID#2 锚点，
        # 停用通告在原验真成功后拦截。
        st, raw = _http("POST", base + "/v1/trust/dids/verify-document",
                        {"document": doc_v2}, headers=TA)
        body = json.loads(raw)
        check("既有 verify-document 协议不变（本地存在 v2 锚点且停用拦截）",
              st == 200 and body.get("valid") is False
              and body.get("reason", "").startswith("外部DID已停用："))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def main():
    test_http()
    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
