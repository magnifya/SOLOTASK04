#!/usr/bin/env python3
"""GET /v1/trust/anchors/snapshot 与 POST .../snapshot/verify 端到端测试。

直接运行：python3 tests/trust_anchor_snapshot_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- GET：signer_did 缺失/空/重复/多余参数 400 仅 {error}；签名 DID 未知
  （含他租户）404、停用 409；200 顶层键序 anchors,signer_did,
  signer_key_version,signature，项键序 did,key_version,public_key,
  status,updated_at,uses；anchors 按 did 码点、key_version 升序；
  signature 对前三键递归键升序紧凑 UTF-8 JSON 成立（ES256 裸 R||S
  base64url）；
- verify：请求体恰为 {"snapshot": 对象} 否则 400 仅 {error}；失败 200
  键序 valid,reason，原因依次恰为“快照非法”“锚点不可用”“签名格式错误”
  “签名校验失败”；成功 {"valid":true}；
- generic 用途：锚点无 generic 用途时“锚点不可用”；
- 租户隔离（缺省 default、显式空 400、跨租户锚点不可用）；
- 纯只读（GET 与 verify 均不记审计），结论跨重启稳定。
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

SNAP_PATH = "/v1/trust/anchors/snapshot"
VERIFY_PATH = "/v1/trust/anchors/snapshot/verify"


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = (
            json.dumps(payload).encode()
            if payload is not None
            else None
        )
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


def main():
    port = 9051
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)

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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def get_snap(query, headers=None):
        return _http("GET", f"{base}{SNAP_PATH}{query}", headers=headers)

    def verify(payload=None, raw_body=None, headers=None):
        return _http("POST", f"{base}{VERIFY_PATH}", payload=payload,
                     raw_body=raw_body, headers=headers)

    def jbody(raw):
        return json.loads(raw.decode() or "{}")

    try:
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # 签名本地 DID（server 托管密钥），并注册其 v1 全用途 active 锚点
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "snap-signer"}, TA)
        assert st == 201, raw
        signer = jbody(raw)
        signer_did, signer_pub = signer["did"], signer["public_key"]
        assert signer["key_version"] == 1
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": signer_did, "public_key": signer_pub,
                       "key_version": 1}, TA)
        assert st in (200, 201)

        # 另两个 DID 的锚点，制造跨 DID/多版本排序场景
        _, pub_b = _keypair()
        _, pub_c = _keypair()
        for _ in range(2):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": "did:web:zzz", "public_key": pub_b,
                           "key_version": 1}, TA)
            assert st in (200, 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "did:web:aaa", "public_key": pub_c,
                       "key_version": 2}, TA)
        assert st == 201
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "did:web:aaa", "public_key": pub_c,
                       "key_version": 1}, TA)
        assert st == 201

        # ---------------------------------------------------------- #
        # 1. GET 参数与错误协议
        # ---------------------------------------------------------- #
        for name, query in (
            ("缺 signer_did", ""),
            ("空 signer_did", "?signer_did="),
            ("重复 signer_did", f"?signer_did=x&signer_did={signer_did}"),
            ("多余参数", f"?signer_did={signer_did}&extra=1"),
        ):
            st, raw = get_snap(query, headers=TA)
            r = jbody(raw)
            check(f"GET 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and r["error"])

        # 显式空租户头 400
        st, raw = get_snap(f"?signer_did={signer_did}",
                           headers={"X-Tenant-ID": ""})
        check("GET 显式空租户头 400",
              st == 400 and list(jbody(raw).keys()) == ["error"])

        # 未知签名 DID 404（本租户）
        st, raw = get_snap("?signer_did=did:web:no-such", headers=TA)
        check("GET 未知 DID 404 仅 error",
              st == 404 and list(jbody(raw).keys()) == ["error"])

        # 他租户签名 DID 404
        st, raw = get_snap(f"?signer_did={signer_did}", headers=TB)
        check("GET 他租户 DID 404", st == 404)

        # 停用签名 DID 409
        st, _ = _http("POST", f"{base}/v1/dids/{signer_did}/deactivate",
                      headers=TA)
        assert st == 200
        st, raw = get_snap(f"?signer_did={signer_did}", headers=TA)
        check("GET 停用 DID 409 仅 error",
              st == 409 and list(jbody(raw).keys()) == ["error"])
        # 恢复一个新的活动签名 DID 供后续签名使用
        st, raw = _http("POST", f"{base}/v1/dids",
                        {"method": "web", "public_key": "snap-signer-2"}, TA)
        assert st == 201
        signer2 = jbody(raw)
        s2_did, s2_pub = signer2["did"], signer2["public_key"]
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": s2_did, "public_key": s2_pub,
                       "key_version": 1}, TA)
        assert st in (200, 201)

        # ---------------------------------------------------------- #
        # 2. GET 成功：键序、排序、签名
        # ---------------------------------------------------------- #
        st, raw = get_snap(f"?signer_did={s2_did}", headers=TA)
        assert st == 200, raw
        snap = jbody(raw)
        check("GET 200 顶层键序",
              list(snap.keys()) == [
                  "anchors", "signer_did",
                  "signer_key_version", "signature"])
        check("GET signer 字段",
              snap["signer_did"] == s2_did
              and snap["signer_key_version"] == 1
              and isinstance(snap["signature"], str)
              and len(snap["signature"]) == 86)
        anchors = snap["anchors"]
        check("GET anchors 非空", isinstance(anchors, list) and anchors)
        check("GET 项键序",
              all(list(a.keys()) == [
                  "did", "key_version", "public_key",
                  "status", "updated_at", "uses"]
                  for a in anchors))
        order = [(a["did"], a["key_version"]) for a in anchors]
        check("GET anchors 按 did 码点/版本升序",
              order == sorted(order))
        check("GET 排序内容正确",
              ("did:web:aaa", 1) in order
              and ("did:web:aaa", 2) in order
              and ("did:web:zzz", 1) in order
              and (s2_did, 1) in order
              and (signer_did, 1) in order
              and len(order) == 5)
        # 类型沿用既有锚点与用途响应
        sample = next(a for a in anchors if a["did"] == "did:web:zzz")
        check("GET 项类型",
              isinstance(sample["public_key"], str)
              and sample["status"] == "active"
              and sample["updated_at"] is None
              and sample["uses"] == [
                  "generic", "vc", "vp", "proof",
                  "did", "status", "deactivation"])

        # 用 GET 之外的公钥独立验证签名覆盖前三键规范化 JSON
        signed = {
            "anchors": snap["anchors"],
            "signer_did": snap["signer_did"],
            "signer_key_version": snap["signer_key_version"],
        }
        crypto.validate_signature_format_strict(snap["signature"])
        crypto.verify(signed, snap["signature"], s2_pub)
        check("GET 签名对前三键规范化 JSON 成立", True)

        # 签名不覆盖 signature 自身：改 signature 不影响验签输入（自洽）
        # 改任一前三键内容必使验签失败（在 verify 端点用例中覆盖）。

        # ---------------------------------------------------------- #
        # 3. verify 请求级 400
        # ---------------------------------------------------------- #
        def expect_400(name, **kwargs):
            st, raw = verify(**kwargs)
            r = jbody(raw)
            check(f"verify 400 仅 error: {name}",
                  st == 400 and list(r.keys()) == ["error"]
                  and isinstance(r["error"], str) and r["error"])

        expect_400("空体", raw_body=b"")
        expect_400("非法 JSON", raw_body=b"not json")
        expect_400("非对象(数组)", raw_body=b"[1,2]")
        expect_400("非对象(字符串)", raw_body=b'"x"')
        expect_400("缺 snapshot", payload={})
        expect_400("多余字段", payload={"snapshot": snap, "x": 1})
        expect_400("snapshot 非对象", payload={"snapshot": "x"})
        expect_400("snapshot 为数组", payload={"snapshot": []})

        st, raw = verify(payload={"snapshot": snap},
                         headers={"X-Tenant-ID": ""})
        check("verify 显式空租户头 400",
              st == 400 and list(jbody(raw).keys()) == ["error"])

        # ---------------------------------------------------------- #
        # 4. verify 成功与四类失败原因（顺序）
        # ---------------------------------------------------------- #
        st, raw = verify(payload={"snapshot": snap}, headers=TA)
        check("verify 成功仅 valid",
              st == 200 and jbody(raw) == {"valid": True})

        def fail_case(name, mutate):
            bad = json.loads(json.dumps(snap))
            mutate(bad)
            st, raw = verify(payload={"snapshot": bad}, headers=TA)
            r = jbody(raw)
            ok = (st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False and r["reason"] == name)
            check(f"verify 失败: {name}", ok)

        # 快照非法：键集/类型、anchors 顺序/重复
        fail_case("快照非法", lambda b: b.pop("signature"))
        fail_case("快照非法", lambda b: b.update(extra=1))
        fail_case("快照非法", lambda b: b.update(signer_did=""))
        fail_case("快照非法", lambda b: b.update(signer_key_version=0))
        fail_case("快照非法", lambda b: b.update(signer_key_version=True))
        fail_case("快照非法", lambda b: b.update(signature=""))
        fail_case("快照非法", lambda b: b.update(signature=123))
        fail_case("快照非法", lambda b: b.update(anchors="x"))

        def _bad_anchor(mut):
            def m(b):
                mut(b["anchors"][0])
            return m

        fail_case("快照非法", _bad_anchor(lambda a: a.pop("uses")))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(extra=1)))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(did="")))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(key_version=0)))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(key_version="1")))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(public_key="")))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(status="bogus")))
        fail_case("快照非法",
                  _bad_anchor(lambda a: a.update(updated_at=123)))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(uses=[])))
        fail_case("快照非法", _bad_anchor(lambda a: a.update(uses="generic")))
        fail_case("快照非法",
                  _bad_anchor(lambda a: a.update(uses=[1, 2])))

        # 顺序/重复（其余结构合法、签名先不关心，因结构阶段即失败）
        def m_dup(b):
            b["anchors"].append(dict(b["anchors"][0]))
        fail_case("快照非法", m_dup)

        def m_reorder(b):
            b["anchors"].reverse()
        fail_case("快照非法", m_reorder)

        # 空 anchors 数组：结构合法（顺序/重复为空真），签名 DID 锚点仍
        # 存在（阶段二只查 signer），合规但错误的签名直达阶段四 ->
        # “签名校验失败”（据此证明它已越过结构与锚点阶段）。
        empty_snap = {
            "anchors": [],
            "signer_did": s2_did,
            "signer_key_version": 1,
            "signature": "A" * 86,
        }
        st, raw = verify(payload={"snapshot": empty_snap}, headers=TA)
        check("空 anchors 越过结构/锚点阶段 -> 签名校验失败",
              st == 200 and jbody(raw) ==
              {"valid": False, "reason": "签名校验失败"})

        # 锚点不可用：未知/他租户 DID、版本不符
        fail_case("锚点不可用", lambda b: b.update(signer_did="did:web:nope"))
        fail_case("锚点不可用",
                  lambda b: b.update(signer_key_version=999))

        def m_revoked(b):
            b["signer_did"] = "did:web:zzz"
            b["signer_key_version"] = 1

        # 注册一个仅 vc 用途（无 generic）的锚点
        _, nog_pub = _keypair()
        nog_did = "did:web:nogeneric"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": nog_did, "public_key": nog_pub,
                       "key_version": 1, "uses": ["vc"]}, TA)
        assert st == 201, raw

        def m_nogeneric(b):
            b["signer_did"] = nog_did
            b["signer_key_version"] = 1
        fail_case("锚点不可用", m_nogeneric)

        # 吊销 zzz v1 后验“已吊销 -> 锚点不可用”
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/did:web:zzz/1/status",
                      {"status": "revoked"}, TA)
        assert st == 200
        fail_case("锚点不可用", m_revoked)

        # 签名格式错误：结构与锚点均合法，签名编码不合规
        fail_case("签名格式错误", lambda b: b.update(signature="abc"))
        fail_case("签名格式错误", lambda b: b.update(signature="A" * 85))
        fail_case("签名格式错误",
                  lambda b: b.update(signature="=" + "A" * 85))

        # 签名校验失败：格式合规但内容错误/被篡改
        fail_case("签名校验失败", lambda b: b.update(signature="A" * 86))

        def m_tamper_status(b):
            for a in b["anchors"]:
                if a["did"] == "did:web:aaa" and a["key_version"] == 1:
                    a["status"] = "revoked"
        fail_case("签名校验失败", m_tamper_status)

        def m_tamper_uses(b):
            for a in b["anchors"]:
                if a["did"] == s2_did:
                    a["uses"] = ["generic"]
        fail_case("签名校验失败", m_tamper_uses)

        # 改 anchors 中 signer 项的 updated_at（null -> 字符串）即改变
        # 签名输入而结构仍合法。
        def m_tamper_time(b):
            for a in b["anchors"]:
                if a["did"] == s2_did:
                    a["updated_at"] = "2026-01-01T00:00:00Z"
        fail_case("签名校验失败", m_tamper_time)

        # 失败原因优先级：结构正确、锚点不可用时即使签名格式非法也报
        # “锚点不可用”
        priority = json.loads(json.dumps(snap))
        priority["signer_did"] = "did:web:nope"
        priority["signature"] = "abc"
        st, raw = verify(payload={"snapshot": priority}, headers=TA)
        check("失败原因优先级 锚点>签名格式",
              jbody(raw) == {"valid": False, "reason": "锚点不可用"})
        priority2 = json.loads(json.dumps(snap))
        priority2["signature"] = "abc"
        # 锚点合法但签名格式非法 -> 签名格式错误（而非校验失败）
        st, raw = verify(payload={"snapshot": priority2}, headers=TA)
        check("失败原因优先级 签名格式>签名校验",
              jbody(raw) == {"valid": False, "reason": "签名格式错误"})

        # 用真实私钥为“锚点合法但签名者不同”的快照签名 -> 签名校验失败
        foreign_priv, foreign_pub = _keypair()
        foreign_did = "did:web:foreign-signer"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": foreign_did, "public_key": foreign_pub,
                       "key_version": 1}, TA)
        assert st == 201
        forged = {
            "anchors": snap["anchors"],
            "signer_did": foreign_did,
            "signer_key_version": 1,
        }
        forged["signature"] = crypto.sign(
            {"anchors": forged["anchors"],
             "signer_did": forged["signer_did"],
             "signer_key_version": forged["signer_key_version"]},
            foreign_priv)
        # foreign 锚点公钥与 foreign_priv 对应，本应 valid——这验证外部
        # 签名者只要在本租户有 active generic 锚点即可让快照验真通过。
        st, raw = verify(payload={"snapshot": forged}, headers=TA)
        check("外部签名者(本租户有锚点)可使验真通过",
              st == 200 and jbody(raw) == {"valid": True})

        # ---------------------------------------------------------- #
        # 5. 租户隔离
        # ---------------------------------------------------------- #
        st, raw = verify(payload={"snapshot": snap})  # 缺省 default
        check("default 租户无锚点 -> 锚点不可用",
              st == 200 and jbody(raw) ==
              {"valid": False, "reason": "锚点不可用"})
        st, raw = verify(payload={"snapshot": snap}, headers=TB)
        check("跨租户验真 -> 锚点不可用",
              st == 200 and jbody(raw) ==
              {"valid": False, "reason": "锚点不可用"})

        # ---------------------------------------------------------- #
        # 6. 纯只读：GET 与 verify 均不记审计；跨重启稳定
        # ---------------------------------------------------------- #
        _, audit_before = _http("GET", f"{base}/v1/audit", headers=TA)
        get_snap(f"?signer_did={s2_did}", headers=TA)
        verify(payload={"snapshot": snap}, headers=TA)
        verify(payload={"snapshot": priority}, headers=TA)
        _, audit_after = _http("GET", f"{base}/v1/audit", headers=TA)
        check("GET/verify 不记审计", audit_before == audit_after)

        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = get_snap(f"?signer_did={s2_did}", headers=TA)
        snap2 = jbody(raw)
        st, raw = verify(payload={"snapshot": snap2}, headers=TA)
        check("重启后快照仍可验真",
              st == 200 and jbody(raw) == {"valid": True})
        # 重启后旧快照内容（含此前吊销的 zzz）可能变化；至少结构与签名
        # 自洽，且对篡改仍判失败
        tampered = json.loads(json.dumps(snap2))
        tampered["anchors"][0]["status"] = (
            "revoked" if tampered["anchors"][0]["status"] == "active"
            else "active")
        st, raw = verify(payload={"snapshot": tampered}, headers=TA)
        check("重启后篡改判签名校验失败",
              jbody(raw) == {"valid": False, "reason": "签名校验失败"})

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.exists(store):
            os.remove(store)

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
