#!/usr/bin/env python3
"""POST /v1/trust/dids/verify-document-synced-batch 批量同步锚点验真 DID 文档测试。

直接运行：python3 tests/trust_did_document_verify_synced_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/documents（非空字符串、非布尔非负整数、
  1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或
  超限均 400 且仅 {"error":"请求非法"}；显式空租户头 400；
- 404/409：signer_did 未同步或跨租户 404 仅 {"error":"同步来源不存在"}；
  at 超过检查点 409 仅 {"error":"同步游标冲突"}，均先于项校验；
- 200 批次：仅返 {"results":[...]}，等长同序、不短路；非对象项为
  “DID文档非法”，其余逐项沿用 verify-document-synced 的文档结构、
  cursor<=at 末锚点、ES256 proof 覆盖、校验顺序与停用判定；失败
  reason 恰为“DID文档非法”“同步锚点不可用”“签名格式错误”
  “签名校验失败”或“外部DID已停用：<reason>”；成功项仅
  {"valid":true}，失败项键序 valid、reason；
- 纯只读：不推进检查点、不改同步视图、不记审计；重启一致。
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
VERIFY_PATH = "/v1/trust/dids/verify-document-synced-batch"
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
    port = 9221
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

    def expect_results(name, payload, expected, headers=None):
        """expected 为逐项期望：True 或失败原因字符串。"""
        st, raw = verify(payload=payload, headers=headers or TA)
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        if not (
            st == 200
            and isinstance(body, dict)
            and list(body.keys()) == ["results"]
            and isinstance(body["results"], list)
            and len(body["results"]) == len(expected)
        ):
            check(name, False)
            return
        ok = True
        for item, want in zip(body["results"], expected):
            if want is True:
                ok = ok and item == {"valid": True}
            else:
                ok = ok and (
                    list(item.keys()) == ["valid", "reason"]
                    and item["valid"] is False
                    and item["reason"] == want
                )
        check(name, ok)

    def synced_payload(documents, at, signer=signer_did):
        return {"signer_did": signer, "at": at, "documents": documents}

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
        # c2: nodid#1 注册(uses 无 did) 且 deactivated_did#1 注册
        # c3: doc_did#1 吊销；c4: doc_did#2 轮换(active, pub2)
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
        deact_doc = make_document(deactivated_did, [(1, deact_pub)], 1,
                                  deact_priv)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议（仅 {"error":"请求非法"}）
        # ---------------------------------------------------------- #
        expect_400("空体 400", raw=b"")
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "documents": [{}]})
        expect_400("缺 at 400",
                   payload={"signer_did": signer_did, "documents": [{}]})
        expect_400("缺 documents 400",
                   payload={"signer_did": signer_did, "at": 1})
        expect_400("多余字段 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "documents": [{}], "extra": 1})
        expect_400("signer_did 空串 400",
                   payload={"signer_did": "", "at": 1, "documents": [{}]})
        expect_400("signer_did 非字符串 400",
                   payload={"signer_did": 1, "at": 1, "documents": [{}]})
        expect_400("at 布尔 400",
                   payload={"signer_did": signer_did, "at": True,
                            "documents": [{}]})
        expect_400("at 负数 400",
                   payload={"signer_did": signer_did, "at": -1,
                            "documents": [{}]})
        expect_400("at 字符串 400",
                   payload={"signer_did": signer_did, "at": "1",
                            "documents": [{}]})
        expect_400("at 小数 400",
                   payload={"signer_did": signer_did, "at": 1.5,
                            "documents": [{}]})
        expect_400("documents 非数组 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "documents": {}})
        expect_400("documents 空数组 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "documents": []})
        expect_400("documents 超限 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "documents": [{}] * 101})
        st, raw = verify(payload=synced_payload([doc_v1], 1),
                         headers={"X-Tenant-ID": ""})
        expect_error("显式空租户头 400", st, raw, 400)

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户（仅 {"error":"同步来源不存在"}）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload([doc_v1], 1,
                                                signer="did:web:nobody"))
        expect_error("未知签名方 404", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=synced_payload([doc_v1], 1), headers=TC)
        expect_error("跨租户未同步 404", st, raw, 404, "同步来源不存在")

        # ---------------------------------------------------------- #
        # 3. 409：at 超过检查点（仅 {"error":"同步游标冲突"}，先于项校验）
        # ---------------------------------------------------------- #
        st, raw = verify(payload=synced_payload([doc_v1], 6))
        expect_error("at 超过检查点 409", st, raw, 409, "同步游标冲突")
        st, raw = verify(payload=synced_payload([doc_v1], 3), headers=TB)
        expect_error("tenant-b at 超过其检查点 409", st, raw, 409,
                     "同步游标冲突")
        st, raw = verify(payload=synced_payload([{"bad": True}, "x"], 6))
        expect_error("at 超检查点优先于项校验 409", st, raw, 409,
                     "同步游标冲突")

        # ---------------------------------------------------------- #
        # 4. 200：非对象项与文档结构非法 -> “DID文档非法”
        # ---------------------------------------------------------- #
        expect_results(
            "非对象项均为 DID文档非法",
            synced_payload([1, "x", [], None, True], 4),
            ["DID文档非法"] * 5,
        )

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
            ("current_key_version 为 0",
             lambda d: d.update(current_key_version=0)),
            ("document_proof 为空",
             lambda d: d.update(document_proof="")),
            ("verification_methods 空数组",
             lambda d: d.update(verification_methods=[])),
            ("方法项非对象",
             lambda d: d.update(verification_methods=[1])),
            ("方法缺 public_key",
             lambda d: d["verification_methods"][0].pop("public_key")),
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
        expect_results(
            "文档结构非法逐项 DID文档非法（不短路、等长同序）",
            synced_payload([tampered_doc(mut) for _, mut in doc_cases], 4),
            ["DID文档非法"] * len(doc_cases),
        )

        # ---------------------------------------------------------- #
        # 5. 200：混合批次（锚点不可用 / 签名 / 停用 / 成功，不短路）
        # ---------------------------------------------------------- #
        unknown_doc = make_document("did:web:unknown", [(1, pub1)], 1,
                                    priv1)
        nodid_doc = make_document("did:web:nodid", [(1, pub1)], 1, priv1)
        mismatch_doc = make_document(doc_did, [(1, pub2)], 1, priv2)
        bad_fmt = tampered_doc(lambda d: d.update(
            document_proof="not-a-signature"))
        bad_len = tampered_doc(lambda d: d.update(document_proof="AAAA"))
        tampered = tampered_doc(
            lambda d: d["verification_methods"][0].update(
                key_handle="changed"))
        wrong_signer = make_document(doc_did, [(1, pub1), (2, pub2)], 2,
                                     priv1)
        expect_results(
            "混合批次逐项判定（等长同序不短路）",
            synced_payload(
                [
                    doc_v2,                # 成功
                    "not-an-object",       # DID文档非法
                    tampered_doc(lambda d: d.pop("did")),  # DID文档非法
                    unknown_doc,           # did 不在同步事件
                    doc_v2,                # at=5 视图内仍成功
                    nodid_doc,             # uses 无 did
                    mismatch_doc,          # 公钥不逐字相同
                    bad_fmt,               # 签名格式错误
                    bad_len,               # 签名格式错误
                    tampered,              # 签名校验失败
                    wrong_signer,          # 签名校验失败
                    deact_doc,             # 外部DID已停用
                    doc_v1,                # at=5 视图：v1 末事件为吊销
                ],
                5,
            ),
            [
                True,
                "DID文档非法",
                "DID文档非法",
                "同步锚点不可用",
                True,
                "同步锚点不可用",
                "同步锚点不可用",
                "签名格式错误",
                "签名格式错误",
                "签名校验失败",
                "签名校验失败",
                "外部DID已停用：外部主体已注销",
                "同步锚点不可用",
            ],
        )
        # at 视图差异：at=1 时 v1 锚点 active，at=3 时末事件为吊销
        expect_results(
            "同一文档按 at 视图分别判定",
            synced_payload([doc_v1, doc_v2], 1),
            [True, "同步锚点不可用"],
        )
        expect_results(
            "v1 末事件吊销视图",
            synced_payload([doc_v1], 3),
            ["同步锚点不可用"],
        )
        # 停用通告不先于锚点判定（at=4 尚无该 did 的同步事件）
        expect_results(
            "停用通告不先于锚点判定",
            synced_payload([deact_doc], 4),
            ["同步锚点不可用"],
        )
        # tenant-b 仅同步首页：doc_did#2 在其视图中不存在
        expect_results(
            "他租户视图独立判定",
            synced_payload([doc_v1, doc_v2], 2),
            [True, "同步锚点不可用"],
            headers=TB,
        )

        # ---------------------------------------------------------- #
        # 6. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=synced_payload([doc_v1, doc_v2, deact_doc], 5))
        verify(payload=synced_payload([doc_v1], 6))
        verify(payload=synced_payload(["x"], 1))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("批量验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("批量验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        st, raw = _http("POST", base + SYNC_PATH, page3, headers=TA)
        check("批量验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 7. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(
            payload=synced_payload([doc_v2, deact_doc, "x"], 5))
        st, na_before = verify(payload=synced_payload([doc_v1], 3))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=synced_payload([doc_v2, deact_doc, "x"], 5))
        check("重启后混合批次响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=synced_payload([doc_v1], 3))
        check("重启后锚点不可用响应逐字节一致",
              st == 200 and raw == na_before)
        st, raw = verify(payload=synced_payload([doc_v1], 6))
        expect_error("重启后 at 超检查点仍 409", st, raw, 409,
                     "同步游标冲突")
        st, raw = verify(payload=synced_payload([doc_v1], 1), headers=TC)
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
