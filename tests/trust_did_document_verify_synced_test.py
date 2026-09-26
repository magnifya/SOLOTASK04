#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document-synced 以同步锚点快照验真外部 DID 文档测试。

直接运行：python3 tests/trust_did_document_verify_synced_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/document（非空字符串、非布尔非负整数、
  对象）；空体、非法 JSON、非对象、键集或类型错误均 400 且仅
  {"error":"请求非法"}；显式空租户头 400；
- 404/409：signer_did 未同步或跨租户 404 仅 {"error":"同步来源不存在"}；
  at 超过检查点 409 仅 {"error":"同步游标冲突"}，且先于文档校验；
- 200 失败：文档结构（四字段、升序无重、P-256 PEM、禁私钥、当前版本
  最高）为“DID文档非法”；同步锚点缺失/非 active/uses 无 did/公钥不
  逐字相同为“同步锚点不可用”；格式、验签依次为“签名格式错误”
  “签名校验失败”；失败响应键序恰为 valid、reason；
- 验签成功后命中外部 DID 停用通告为“外部DID已停用：<reason>”；
- 成功仅 {"valid":true}；
- 纯只读：不推进检查点、不改同步页/锚点/状态、不记审计；重启一致。
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

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
VERIFY_PATH = "/v1/trust/dids/verify-document-synced"
DEACTIVATE_PATH = "/v1/trust/dids/deactivate-sync"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is None:
        data = json.dumps(payload).encode() if payload is not None else None
    else:
        data = raw
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


def build_changes(events, after, did, signer_priv):
    signed = {
        "events": events,
        "next_after": events[-1]["cursor"] if events else after,
        "signer_did": did,
        "signer_key_version": 1,
    }
    signature = crypto.sign(signed, signer_priv)
    changes = dict(signed)
    changes["signature"] = signature
    return {"changes": changes, "after": after}


def make_document(did, methods, current_version, signer_priv):
    """按既有 DID 文档协议构造文档并用当前版本私钥签发 document_proof。"""
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
    doc["document_proof"] = crypto.sign(doc, signer_priv)
    return doc


def test_http():
    port = 9088
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

    signer_did = "did:web:remote-signer"
    signer_priv, signer_pub = gen_keypair()
    doc_did = "did:web:external-subject"
    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    deactivated_did = "did:web:deactivated-subject"
    deact_priv, deact_pub = gen_keypair()

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", base + VERIFY_PATH, payload,
                     headers=headers if headers is not None else TA,
                     raw=raw)

    def expect_error(name, st, raw, status, message=None):
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        ok = (
            st == status
            and isinstance(body, dict)
            and set(body) == {"error"}
            and isinstance(body["error"], str)
            and body["error"].strip() != ""
        )
        if message is not None:
            ok = ok and body["error"] == message
        check(name, ok)

    def expect_400(name, payload=None, headers=None, raw=None):
        st, resp = verify(payload=payload, headers=headers or TA, raw=raw)
        expect_error(name, st, resp, 400, "请求非法")

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

    def synced_payload(document, at, signer=signer_did):
        return {"signer_did": signer, "at": at, "document": document}

    try:
        # 登记签名方锚点（两个租户），供 sync 验真通过
        for headers in (TA, TB):
            st, raw = _http(
                "POST",
                f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": signer_pub,
                 "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # 同步两页（tenant-a 检查点=4；tenant-b 仅首页，检查点=2）
        # c1: doc_did#1 注册(active, 全用途, pub1)
        # c2: nodid#1 注册(uses 无 did)
        # c3: doc_did#1 吊销；c4: doc_did#2 轮换(active, pub2)
        # c2 同时注册 deactivated_did#1（active, 全用途, deact_pub）
        page1 = build_changes(
            [
                make_event(1, doc_did, 1, pub=pub1),
                make_event(2, "did:web:nodid", 1,
                           uses=["generic", "vc"], pub=pub1),
            ],
            0, signer_did, signer_priv,
        )
        page2 = build_changes(
            [
                make_event(3, doc_did, 1, action="revoked",
                           status="revoked", pub=pub1),
                make_event(4, doc_did, 2, action="rotated", pub=pub2),
            ],
            2, signer_did, signer_priv,
        )
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TA)
        assert st == 201
        st, _ = _http("POST", base + SYNC_PATH, page2, headers=TA)
        assert st == 200
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TB)
        assert st == 201

        # deactivated_did：同步事件（cursor 5）+ 本地锚点 + 停用通告
        page3 = build_changes(
            [make_event(5, deactivated_did, 1, pub=deact_pub)],
            4, signer_did, signer_priv,
        )
        st, _ = _http("POST", base + SYNC_PATH, page3, headers=TA)
        assert st == 200
        st, raw = _http(
            "POST",
            f"{base}/v1/trust/anchors",
            {"did": deactivated_did, "public_key": deact_pub,
             "key_version": 1},
            TA,
        )
        assert st in (200, 201), raw
        notice_body = {
            "did": deactivated_did,
            "key_version": 1,
            "reason": "外部主体已注销",
            "deactivated_at": "2026-01-01T00:00:00Z",
        }
        st, raw = _http(
            "POST",
            base + DEACTIVATE_PATH,
            {"body": notice_body,
             "signature": crypto.sign(notice_body, deact_priv)},
            TA,
        )
        assert st == 201, raw

        doc_v1 = make_document(doc_did, [(1, pub1)], 1, priv1)
        doc_v2 = make_document(doc_did, [(1, pub1), (2, pub2)], 2, priv2)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议（仅 {"error":"请求非法"}）
        # ---------------------------------------------------------- #
        expect_400("空体 400", raw=b"")
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "document": {}})
        expect_400("缺 at 400",
                   payload={"signer_did": signer_did, "document": {}})
        expect_400("缺 document 400",
                   payload={"signer_did": signer_did, "at": 1})
        expect_400("多余字段 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "document": {}, "extra": 1})
        expect_400("signer_did 空串 400",
                   payload={"signer_did": "", "at": 1, "document": {}})
        expect_400("signer_did 非字符串 400",
                   payload={"signer_did": 1, "at": 1, "document": {}})
        expect_400("at 布尔 400",
                   payload={"signer_did": signer_did, "at": True,
                            "document": {}})
        expect_400("at 负数 400",
                   payload={"signer_did": signer_did, "at": -1,
                            "document": {}})
        expect_400("at 字符串 400",
                   payload={"signer_did": signer_did, "at": "1",
                            "document": {}})
        expect_400("at 小数 400",
                   payload={"signer_did": signer_did, "at": 1.5,
                            "document": {}})
        expect_400("document 非对象 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "document": []})
        expect_400("document 为字符串 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "document": "x"})
        st, raw = verify(payload=synced_payload(doc_v1, 1),
                         headers={"X-Tenant-ID": ""})
        expect_error("显式空租户头 400", st, raw, 400)

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户（仅 {"error":"同步来源不存在"}）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload(doc_v1, 1,
                                                signer="did:web:nobody"))
        expect_error("未知签名方 404", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TC)
        expect_error("跨租户未同步 404", st, raw, 404, "同步来源不存在")

        # ---------------------------------------------------------- #
        # 3. 409：at 超过检查点（仅 {"error":"同步游标冲突"}，先于文档校验）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload(doc_v1, 6))
        expect_error("at 超过检查点 409", st, raw, 409, "同步游标冲突")
        st, raw = verify(payload=synced_payload(doc_v1, 3), headers=TB)
        expect_error("tenant-b at 超过其检查点 409", st, raw, 409,
                     "同步游标冲突")
        st, raw = verify(payload=synced_payload({"bad": True}, 6))
        expect_error("at 超检查点优先于文档校验 409", st, raw, 409,
                     "同步游标冲突")

        # ---------------------------------------------------------- #
        # 4. 200：文档结构非法 -> “DID文档非法”
        # ---------------------------------------------------------- #
        def tampered_doc(mut):
            d = json.loads(json.dumps(doc_v2))
            mut(d)
            return d

        doc_cases = [
            ("缺 did", lambda d: d.pop("did")),
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
            ("verification_methods 空数组",
             lambda d: d.update(verification_methods=[])),
            ("方法项非对象",
             lambda d: d.update(verification_methods=[1])),
            ("方法缺 public_key",
             lambda d: d["verification_methods"][0].pop("public_key")),
            ("方法含多余字段",
             lambda d: d["verification_methods"][0].update(extra=1)),
            ("方法 key_version 布尔",
             lambda d: d["verification_methods"][0].update(
                 key_version=True)),
            ("方法 key_handle 为空",
             lambda d: d["verification_methods"][0].update(key_handle="")),
            ("方法 public_key 非 PEM",
             lambda d: d["verification_methods"][0].update(
                 public_key="not-a-pem")),
            ("方法乱序",
             lambda d: d.update(verification_methods=list(
                 reversed(d["verification_methods"])))),
            ("版本重复",
             lambda d: d.update(verification_methods=[
                 d["verification_methods"][0],
                 dict(d["verification_methods"][0], key_handle="dup")])),
            ("current_key_version 非最高",
             lambda d: d.update(current_key_version=1)),
            ("文档携带私钥",
             lambda d: d["verification_methods"][0].update(
                 key_handle=priv1)),
        ]
        for name, mut in doc_cases:
            expect_invalid(f"文档非法: {name}",
                           synced_payload(tampered_doc(mut), 4),
                           "DID文档非法")

        # ---------------------------------------------------------- #
        # 5. 200：同步锚点不可用
        # ---------------------------------------------------------- #
        unknown_doc = make_document("did:web:unknown", [(1, pub1)], 1, priv1)
        expect_invalid("did 不在同步事件",
                       synced_payload(unknown_doc, 4), "同步锚点不可用")
        expect_invalid("at 之前锚点尚未注册（v2 视图取 at=2）",
                       synced_payload(doc_v2, 2), "同步锚点不可用")
        expect_invalid("末事件为吊销（v1 视图取 at=3）",
                       synced_payload(doc_v1, 3), "同步锚点不可用")
        nodid_doc = make_document("did:web:nodid", [(1, pub1)], 1, priv1)
        expect_invalid("uses 无 did",
                       synced_payload(nodid_doc, 2), "同步锚点不可用")
        # 公钥不逐字相同：同步事件为 pub1，文档当前版本公钥为 pub2
        mismatch_doc = make_document(doc_did, [(1, pub2)], 1, priv2)
        expect_invalid("公钥与文档当前版本不逐字相同",
                       synced_payload(mismatch_doc, 1), "同步锚点不可用")
        # tenant-b 仅同步首页：doc_did#2 在其视图中不存在
        expect_invalid("他租户视图无该版本",
                       synced_payload(doc_v2, 2), "同步锚点不可用",
                       headers=TB)

        # ---------------------------------------------------------- #
        # 6. 200：签名格式错误 / 签名校验失败
        # ---------------------------------------------------------- #
        bad_fmt = tampered_doc(lambda d: d.update(
            document_proof="not-a-signature"))
        expect_invalid("签名格式错误",
                       synced_payload(bad_fmt, 4), "签名格式错误")
        bad_len = tampered_doc(lambda d: d.update(document_proof="AAAA"))
        expect_invalid("签名长度非法",
                       synced_payload(bad_len, 4), "签名格式错误")
        tampered = tampered_doc(
            lambda d: d["verification_methods"][0].update(
                key_handle="changed"))
        expect_invalid("文档被篡改签名校验失败",
                       synced_payload(tampered, 4), "签名校验失败")
        wrong_signer = make_document(doc_did, [(1, pub1), (2, pub2)], 2,
                                     priv1)
        expect_invalid("错误签名者签名校验失败",
                       synced_payload(wrong_signer, 4), "签名校验失败")

        # ---------------------------------------------------------- #
        # 7. 200：停用通告
        # ---------------------------------------------------------- #
        deact_doc = make_document(deactivated_did, [(1, deact_pub)], 1,
                                  deact_priv)
        expect_invalid("外部 DID 已停用",
                       synced_payload(deact_doc, 5),
                       "外部DID已停用：外部主体已注销")
        # 未停用前（at=4 尚无该 did 的同步事件）-> 锚点不可用
        expect_invalid("停用通告不先于锚点判定",
                       synced_payload(deact_doc, 4), "同步锚点不可用")

        # ---------------------------------------------------------- #
        # 8. 成功：仅 {"valid":true}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload(doc_v1, 1))
        body = json.loads(raw)
        check("v1 文档验真成功仅 valid:true",
              st == 200 and list(body.keys()) == ["valid"]
              and body["valid"] is True)
        st, raw = verify(payload=synced_payload(doc_v2, 4))
        check("v2 文档验真成功",
              st == 200 and json.loads(raw) == {"valid": True})
        st, raw = verify(payload=synced_payload(doc_v1, 2), headers=TB)
        check("tenant-b 视图内验真成功",
              st == 200 and json.loads(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 9. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=synced_payload(doc_v1, 1))
        verify(payload=synced_payload(doc_v1, 3))
        verify(payload=synced_payload(doc_v1, 6))
        verify(payload=synced_payload(deact_doc, 5))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        st, raw = _http("POST", base + SYNC_PATH, page3, headers=TA)
        check("验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 10. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(payload=synced_payload(doc_v2, 4))
        st, na_before = verify(payload=synced_payload(doc_v1, 3))
        st, deact_before = verify(payload=synced_payload(deact_doc, 5))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=synced_payload(doc_v2, 4))
        check("重启后成功响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=synced_payload(doc_v1, 3))
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == na_before)
        st, raw = verify(payload=synced_payload(deact_doc, 5))
        check("重启后停用通告响应逐字节一致",
              st == 200 and raw == deact_before)
        st, raw = verify(payload=synced_payload(doc_v1, 6))
        expect_error("重启后 at 超检查点仍 409", st, raw, 409,
                     "同步游标冲突")
        st, raw = verify(payload=synced_payload(doc_v1, 1), headers=TC)
        expect_error("重启后跨租户仍 404", st, raw, 404, "同步来源不存在")
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
