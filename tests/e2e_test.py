#!/usr/bin/env python3
"""端到端测试：临时启动 HTTP 服务，覆盖 DID/凭证接口与签名验真。

直接运行：python3 tests/e2e_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import concurrent.futures
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402


def _http(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
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


def main():
    port = 8941
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

        # 1. 注册 DID
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "alice-key"})
        check("POST /v1/dids -> 201", st == 201 and r["did"].startswith("did:example:"))
        alice = r["did"]
        check("返回含 public_key", bool(r.get("public_key")))
        check("注册返回 key_mode/key_handle/key_version=1",
              r.get("key_mode") == "server"
              and r.get("key_handle") == "alice-key"
              and r.get("key_version") == 1)
        alice_pem = r["public_key"]

        # 2. 同一 public_key 去重
        st, r2 = _http("POST", f"{base}/v1/dids",
                       {"method": "example", "public_key": "alice-key"})
        check("同一 public_key 返回既有 DID", r2["did"] == alice)

        # 3. 缺字段 400
        st, r = _http("POST", f"{base}/v1/dids", {"method": "example"})
        check("缺 public_key -> 400 且说明原因",
              st == 400 and "public_key" in r.get("error", ""))

        # 3b. PEM 句柄 / 非法 key_mode -> 400；显式 server -> 201
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": alice_pem})
        check("PEM 作 public_key -> 400",
              st == 400 and "public_key" in r.get("error", ""))
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bob-key",
                       "key_mode": "local"})
        check("非法 key_mode -> 400",
              st == 400 and "key_mode" in r.get("error", ""))
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "bob-key",
                       "key_mode": "server"})
        check("显式 key_mode=server -> 201",
              st == 201 and r.get("key_handle") == "bob-key")

        # 4. GET DID
        st, r = _http("GET", f"{base}/v1/dids/{alice}")
        check("GET DID -> 200 含 public_key/created_at",
              st == 200 and r["public_key"] and r["created_at"])
        check("GET DID 含 key_mode/key_handle/key_version",
              r.get("key_mode") == "server"
              and r.get("key_handle") == "alice-key"
              and r.get("key_version") == 1)

        # 5. GET 不存在 404
        st, _ = _http("GET", f"{base}/v1/dids/did:example:nope")
        check("GET 不存在 DID -> 404", st == 404)

        # 第二个 DID 作为签发者
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "issuer-key"})
        issuer = r["did"]

        # 6. 签发凭证
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"role": "admin", "level": 3}})
        check("POST /v1/credentials -> 201",
              st == 201 and r["credential_id"].startswith("vc_")
              and bool(r["signature"]))
        check("签发响应含整数 issuer_key_version=1",
              isinstance(r.get("issuer_key_version"), int)
              and r["issuer_key_version"] == 1)
        cid, sig = r["credential_id"], r["signature"]

        # 7. 不存在 DID 签发 -> 400 指明哪一个
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": "did:example:nope", "subject_did": alice,
            "claims": {}})
        check("issuer 不存在 -> 400 指明 issuer_did",
              st == 400 and "issuer_did" in r.get("error", ""))
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": "did:example:nope",
            "claims": {}})
        check("subject 不存在 -> 400 指明 subject_did",
              st == 400 and "subject_did" in r.get("error", ""))

        # 8. GET 凭证
        st, r = _http("GET", f"{base}/v1/credentials/{cid}")
        check("GET 凭证 -> 200 含 body/signature",
              st == 200 and r["body"] and r["signature"] == sig)
        body = r["body"]

        # 9. GET 不存在凭证 -> 404
        st, _ = _http("GET", f"{base}/v1/credentials/vc_nope")
        check("GET 不存在凭证 -> 404", st == 404)

        # 10. 现取签发者公钥验签 -> 成功
        _, did_doc = _http("GET", f"{base}/v1/dids/{issuer}")
        try:
            crypto.verify(body, sig, did_doc["public_key"])
            check("现取签发者公钥验签通过", True)
        except Exception:
            check("现取签发者公钥验签通过", False)

        # 11. 篡改 claims -> 验签失败
        tampered = json.loads(json.dumps(body))
        tampered["claims"]["role"] = "superadmin"
        try:
            crypto.verify(tampered, sig, did_doc["public_key"])
            check("篡改 claims 后验签失败", False)
        except crypto.InvalidSignature:
            check("篡改 claims 后验签失败", True)

        # 12. 篡改顶层字段 -> 验签失败
        tampered2 = json.loads(json.dumps(body))
        tampered2["subject_did"] = alice + "x"
        try:
            crypto.verify(tampered2, sig, did_doc["public_key"])
            check("篡改 subject_did 后验签失败", False)
        except crypto.InvalidSignature:
            check("篡改 subject_did 后验签失败", True)

        # 13. 密钥轮换
        st, r = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "issuer-key-v2"})
        check("轮换 -> 200 且 key_version=2/key_handle/新公钥",
              st == 200 and r["did"] == issuer
              and r.get("key_version") == 2
              and r.get("key_handle") == "issuer-key-v2"
              and r.get("public_key")
              and r["public_key"] != did_doc["public_key"])

        # 14. 轮换错误路径
        st, _ = _http("POST", f"{base}/v1/dids/did:example:nope/keys/rotate",
                      {"key_handle": "h"})
        check("轮换未知 DID -> 404", st == 404)
        st, r = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": ""})
        check("轮换空句柄 -> 400", st == 400)
        st, r = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": alice_pem})
        check("轮换 PEM 句柄 -> 400", st == 400)
        st, r = _http("POST", f"{base}/v1/dids/{issuer}/keys/rotate",
                      {"key_handle": "alice-key"})
        check("轮换重复句柄 -> 400",
              st == 400 and "key_handle" in r.get("error", ""))

        # 15. verify 端点：历史版本凭证（v1）轮换后仍验真
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/verify",
                      {"body": body, "signature": sig})
        check("verify 端点: 历史版本凭证 valid=true",
              st == 200 and r.get("valid") is True)

        # 16. 轮换后新签发用当前版本（v2）
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"role": "user"}})
        check("轮换后签发 issuer_key_version=2",
              st == 201 and r.get("issuer_key_version") == 2)
        cid2 = r["credential_id"]
        _, vc2 = _http("GET", f"{base}/v1/credentials/{cid2}")
        check("凭证正文含 issuer_key_version=2",
              vc2["body"].get("issuer_key_version") == 2)
        st, r = _http("POST", f"{base}/v1/credentials/{cid2}/verify",
                      {"body": vc2["body"], "signature": vc2["signature"]})
        check("verify 端点: 当前版本凭证 valid=true",
              st == 200 and r.get("valid") is True)

        # 17. verify 端点：篡改 -> 200 valid=false 且中文 reason 非空
        tampered3 = json.loads(json.dumps(vc2["body"]))
        tampered3["claims"]["role"] = "hacked"
        st, r = _http("POST", f"{base}/v1/credentials/{cid2}/verify",
                      {"body": tampered3, "signature": vc2["signature"]})
        check("verify 端点: 篡改 valid=false 且 reason 非空",
              st == 200 and r.get("valid") is False
              and isinstance(r.get("reason"), str) and r["reason"])

        # 18. verify 端点：锚定字段被改 -> valid=false
        anchor_bad = json.loads(json.dumps(vc2["body"]))
        anchor_bad["issuer_key_version"] = 1
        st, r = _http("POST", f"{base}/v1/credentials/{cid2}/verify",
                      {"body": anchor_bad, "signature": vc2["signature"]})
        check("verify 端点: 锚定版本不一致 valid=false",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 19. verify 端点公开错误协议：任何失败都 200 + valid:false + 非空中文 reason
        def verify_raw(cid, raw_bytes, ctype="application/json"):
            req = urllib.request.Request(
                f"{base}/v1/credentials/{cid}/verify",
                data=raw_bytes, method="POST")
            req.add_header("Content-Type", ctype)
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read().decode() or "{}")
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode() or "{}")

        def check_invalid(name, cid, payload=None, raw=None):
            if raw is None:
                raw = json.dumps(payload).encode("utf-8")
            st, rr = verify_raw(cid, raw)
            ok = (
                st == 200
                and rr.get("valid") is False
                and isinstance(rr.get("reason"), str)
                and rr["reason"].strip()
            )
            check(name, ok)
            return rr

        # 请求类：缺失请求体 / 非法 JSON / 非对象
        check_invalid("verify 缺失请求体 -> 200 valid:false", cid2, raw=b"")
        check_invalid("verify 非法 JSON -> 200 valid:false", cid2,
                      raw=b"{not json")
        check_invalid("verify 请求体非对象(JSON 数组) -> 200 valid:false",
                      cid2, raw=b"[1,2]")
        # 请求类：缺 body / 缺 signature / body 非对象 / signature 空串与非字符串
        check_invalid("verify 缺 body -> 200 valid:false", cid2,
                      {"signature": vc2["signature"]})
        check_invalid("verify 缺 signature -> 200 valid:false", cid2,
                      {"body": vc2["body"]})
        check_invalid("verify body 非对象 -> 200 valid:false", cid2,
                      {"body": "x", "signature": vc2["signature"]})
        check_invalid("verify 空 signature -> 200 valid:false", cid2,
                      {"body": vc2["body"], "signature": ""})
        check_invalid("verify signature 非字符串 -> 200 valid:false", cid2,
                      {"body": vc2["body"], "signature": 123})
        # 资源类：未知 credential_id
        rr = check_invalid("verify 未知凭证 -> 200 valid:false", "vc_nope",
                           {"body": {}, "signature": "x"})
        check("verify 未知凭证 reason 指向资源类别",
              "凭证不存在" in rr.get("reason", ""))
        # 锚定类：credential_id / issuer_did / issuer_key_version 不一致
        anchor_bad2 = json.loads(json.dumps(vc2["body"]))
        anchor_bad2["credential_id"] = "vc_other"
        rr = check_invalid("verify 正文 credential_id 不一致", cid2,
                           {"body": anchor_bad2, "signature": vc2["signature"]})
        check("verify credential_id 不一致 reason 指向锚定",
              "锚定" in rr["reason"])
        anchor_bad3 = json.loads(json.dumps(vc2["body"]))
        anchor_bad3["issuer_did"] = alice
        rr = check_invalid("verify 正文 issuer_did 不一致", cid2,
                           {"body": anchor_bad3, "signature": vc2["signature"]})
        check("verify issuer_did 不一致 reason 指向锚定",
              "锚定" in rr["reason"])
        rr = check_invalid("verify 锚定版本不一致 valid=false", cid2,
                           {"body": anchor_bad, "signature": vc2["signature"]})
        check("verify issuer_key_version 不一致 reason 指向锚定",
              "锚定" in rr["reason"])
        # 签名格式类：合法 body 但签名编码/长度非法（先通过锚定再判格式）
        rr = check_invalid("verify 签名非 base64url -> 200 valid:false", cid2,
                           {"body": vc2["body"], "signature": "@@@"})
        check("verify 非法编码 reason 指向签名格式",
              "签名格式" in rr["reason"])
        rr = check_invalid("verify 签名长度错误 -> 200 valid:false", cid2,
                           {"body": vc2["body"], "signature": "AAAA"})
        check("verify 错误长度 reason 指向签名格式",
              "签名格式" in rr["reason"])
        # 签名校验类：合法格式、错误签名
        wrong_sig = crypto.sign(vc2["body"], crypto.generate_private_key_pem())
        rr = check_invalid("verify 他人密钥签名 -> 200 valid:false", cid2,
                           {"body": vc2["body"], "signature": wrong_sig})
        check("verify 错误签名 reason 指向签名校验",
              "签名校验" in rr["reason"])
        # 成功路径不受影响
        st, r = _http("POST", f"{base}/v1/credentials/{cid2}/verify",
                      {"body": vc2["body"], "signature": vc2["signature"]})
        check("verify 合法凭证仍 valid=true/200",
              st == 200 and r.get("valid") is True and "reason" not in r)

        # 20. 凭证状态登记与吊销
        # 新签发两张专用凭证，避免吊销影响后续 cid2 的 CLI verify 用例
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"kind": "status"}})
        cid3 = r["credential_id"]
        sig3 = r["signature"]
        body3 = _http("GET", f"{base}/v1/credentials/{cid3}")[1]["body"]
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice,
            "claims": {"kind": "revoke"}})
        cid4 = r["credential_id"]
        sig4 = r["signature"]
        body4 = _http("GET", f"{base}/v1/credentials/{cid4}")[1]["body"]

        # 20.1 历史无状态：GET status -> active / updated_at=null
        st, r = _http("GET", f"{base}/v1/credentials/{cid3}/status")
        check("GET status 无状态按 active 返回且 updated_at=null",
              st == 200 and r == {
                  "credential_id": cid3, "status": "active",
                  "updated_at": None})

        # 20.2 首次 PUT status -> 201，三字段齐全
        st, r = _http("PUT", f"{base}/v1/credentials/{cid3}/status",
                      {"status": "active"})
        check("PUT status 首次 -> 201 含三字段",
              st == 201 and r.get("credential_id") == cid3
              and r.get("status") == "active"
              and isinstance(r.get("updated_at"), str)
              and r["updated_at"])
        first_updated = r["updated_at"]

        # 20.3 重复 PUT -> 200，updated_at 与首次一致
        st, r = _http("PUT", f"{base}/v1/credentials/{cid3}/status",
                      {"status": "active"})
        check("PUT status 重复 -> 200 且 updated_at 不变",
              st == 200 and r.get("status") == "active"
              and r.get("updated_at") == first_updated
              and set(r) == {"credential_id", "status", "updated_at"})

        # 20.4 缺失/非法/多余字段/非法 JSON/空体/非对象 -> 400 非空 error
        def put_status_raw(cid, raw_bytes):
            req = urllib.request.Request(
                f"{base}/v1/credentials/{cid}/status",
                data=raw_bytes, method="PUT")
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read().decode() or "{}")
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode() or "{}")

        for bad in ({}, {"status": "revoked"}, {"status": 1},
                    {"status": "active", "extra": 1}):
            stx, rr = _http("PUT", f"{base}/v1/credentials/{cid3}/status", bad)
            check(f"PUT status 非法请求体 {bad} -> 400",
                  stx == 400 and isinstance(rr.get("error"), str)
                  and rr["error"])
        stx, rr = put_status_raw(cid3, b"{not json")
        check("PUT status 非法 JSON -> 400", stx == 400 and rr.get("error"))
        stx, rr = put_status_raw(cid3, b"")
        check("PUT status 空请求体 -> 400", stx == 400 and rr.get("error"))
        stx, rr = put_status_raw(cid3, b"[1]")
        check("PUT status 非对象 -> 400", stx == 400 and rr.get("error"))

        # 20.5 未知凭证各端点 -> 404
        check("PUT status 未知凭证 -> 404",
              _http("PUT", f"{base}/v1/credentials/vc_nope/status",
                    {"status": "active"})[0] == 404)
        check("GET status 未知凭证 -> 404",
              _http("GET", f"{base}/v1/credentials/vc_nope/status")[0] == 404)
        check("POST revoke 未知凭证 -> 404",
              _http("POST", f"{base}/v1/credentials/vc_nope/revoke",
                    {})[0] == 404)

        # 20.6 首次吊销 reason 省略：空体 / {} 均用默认原因
        st, r = _http("POST", f"{base}/v1/credentials/{cid4}/revoke")
        check("revoke 空体 -> 200 默认 reason",
              st == 200 and r.get("credential_id") == cid4
              and r.get("status") == "revoked"
              and r.get("reason") == "持证人主动吊销"
              and isinstance(r.get("revoked_at"), str) and r["revoked_at"]
              and r.get("updated_at") == r["revoked_at"])
        revoked_at = r["revoked_at"]
        # 重复吊销：任何 reason（含非法值）均忽略，返回首次结果
        for body in ({"reason": "其他原因"}, {"reason": "   "},
                     {"reason": None}, {"reason": 7}):
            stx, rr = _http("POST", f"{base}/v1/credentials/{cid4}/revoke",
                            body)
            check(f"重复吊销忽略 {body}",
                  stx == 200 and rr.get("reason") == "持证人主动吊销"
                  and rr.get("revoked_at") == revoked_at
                  and rr.get("updated_at") == revoked_at)

        # 20.7 已 revoked 再 PUT active -> 409 非空 error，字段保持不变
        st, rr = _http("PUT", f"{base}/v1/credentials/{cid4}/status",
                       {"status": "active"})
        check("已吊销 PUT active -> 409 非空 error",
              st == 409 and isinstance(rr.get("error"), str) and rr["error"])
        st, r = _http("GET", f"{base}/v1/credentials/{cid4}/status")
        check("409 后状态字段保持 revoked 且时间不变",
              st == 200 and r.get("status") == "revoked"
              and r.get("updated_at") == revoked_at)

        # 20.8 verify：签名锚定成功后吊销 -> 200 valid:false + 原因前缀
        st, r = _http("POST", f"{base}/v1/credentials/{cid4}/verify",
                      {"body": body4, "signature": sig4})
        check("verify 已吊销 -> 200 valid:false 且原因含保存 reason",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：持证人主动吊销")
        # active 与无状态凭证维持 valid:true
        st, r = _http("POST", f"{base}/v1/credentials/{cid3}/verify",
                      {"body": body3, "signature": sig3})
        check("verify active 凭证维持 valid:true",
              st == 200 and r == {"valid": True})

        # 20.9 自定义 reason：非法值仅首次 400；合法值保存裁剪结果
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": issuer, "subject_did": alice, "claims": {}})
        cid5 = r["credential_id"]
        sig5 = r["signature"]
        body5 = _http("GET", f"{base}/v1/credentials/{cid5}")[1]["body"]
        for bad in ({"reason": "   "}, {"reason": ""},
                    {"reason": None}, {"reason": 9}):
            stx, rr = _http("POST", f"{base}/v1/credentials/{cid5}/revoke",
                            bad)
            check(f"首次吊销非法 reason {bad} -> 400",
                  stx == 400 and rr.get("error"))
        st, r = _http("POST", f"{base}/v1/credentials/{cid5}/revoke",
                      {"reason": "  违规使用  "})
        check("首次吊销合法 reason 裁剪保存 -> 200",
              st == 200 and r.get("reason") == "违规使用"
              and r.get("status") == "revoked"
              and set(r) == {"credential_id", "status", "reason",
                             "revoked_at", "updated_at"})
        st, r = _http("POST", f"{base}/v1/credentials/{cid5}/verify",
                      {"body": body5, "signature": sig5})
        check("verify 吊销原因使用裁剪后的值",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：违规使用")

        # 20.10 状态跨重启保留：终止主服务并以同一 store 重启
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port), "主服务重启超时"
        st, r = _http("GET", f"{base}/v1/credentials/{cid4}/status")
        check("重启后 revoked 状态与时间保留",
              st == 200 and r.get("status") == "revoked"
              and r.get("updated_at") == revoked_at)
        st, r = _http("POST", f"{base}/v1/credentials/{cid4}/verify",
                      {"body": body4, "signature": sig4})
        check("重启后 verify 仍判吊销",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：持证人主动吊销")
        st, r = _http("GET", f"{base}/v1/credentials/{cid3}/status")
        check("重启后 active 状态与首次 updated_at 保留",
              st == 200 and r.get("status") == "active"
              and r.get("updated_at") == first_updated)

        # 21. CLI verify：成功 true/0；未知凭证非 0
        env_cli = dict(env, VCBACKEND_URL=base)
        cp = subprocess.run(
            [sys.executable, "-m", "vcbackend.cli", "verify", cid2],
            cwd=ROOT, env=env_cli, capture_output=True, text=True)
        check("CLI verify 成功输出 true/0",
              cp.returncode == 0 and cp.stdout.strip() == "true")
        cp = subprocess.run(
            [sys.executable, "-m", "vcbackend.cli", "verify", "vc_nope"],
            cwd=ROOT, env=env_cli, capture_output=True, text=True)
        check("CLI verify 未知凭证 -> 退出码 1",
              cp.returncode == 1 and cp.stderr.strip())

        # 22. 旧状态文件迁移 + 旧凭证（无 issuer_key_version）按 1 验签
        with open(store, encoding="utf-8") as fh:
            state = json.load(fh)
        issuer_row = state["dids"][issuer]
        old_body = {
            "credential_id": "vc_old",
            "issuer_did": issuer,
            "subject_did": alice,
            "claims": {"n": 1},
            "issued_at": "2025-01-01T00:00:00Z",
        }
        old_sig = crypto.sign(old_body, issuer_row["private_key_pem"])
        bad_body = dict(old_body, credential_id="vc_bad")
        bad_sig = crypto.sign(bad_body, issuer_row["private_key_pem"])
        old_state = {
            "dids": {
                issuer: {
                    "method": "example",
                    "public_key": issuer_row["public_key"],
                    "submitted_public_key": "issuer-key",
                    "created_at": issuer_row["created_at"],
                    "private_key_pem": issuer_row["private_key_pem"],
                }
            },
            "credentials": {
                "vc_old": {"body": old_body, "signature": old_sig},
                # 存储正文与签名不匹配（claims 被改），验签应失败
                "vc_bad": {
                    "body": dict(bad_body, claims={"n": 999}),
                    "signature": bad_sig,
                },
            },
        }
        old_store = tempfile.mktemp(suffix=".json")
        with open(old_store, "w", encoding="utf-8") as fh:
            json.dump(old_state, fh)
        port2 = 8942
        env2 = dict(os.environ, VCBACKEND_STORE=old_store)
        proc2 = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port2), "--host", "127.0.0.1"],
            cwd=ROOT, env=env2,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base2 = f"http://127.0.0.1:{port2}"
        try:
            assert wait_up(port2), "第二个服务启动超时"
            st, r = _http("GET", f"{base2}/v1/dids/{issuer}")
            check("旧 DID 迁移为 server/1 且句柄为提交原文",
                  st == 200 and r.get("key_mode") == "server"
                  and r.get("key_version") == 1
                  and r.get("key_handle") == "issuer-key")
            st, r = _http("POST", f"{base2}/v1/credentials/vc_old/verify",
                          {"body": old_body, "signature": old_sig})
            check("旧凭证(无版本)按 1 验签 valid=true",
                  st == 200 and r.get("valid") is True)
            tampered_old = dict(old_body, claims={"n": 2})
            st, r = _http("POST", f"{base2}/v1/credentials/vc_old/verify",
                          {"body": tampered_old, "signature": old_sig})
            check("旧凭证篡改 valid=false 且 reason 非空",
                  st == 200 and r.get("valid") is False and r.get("reason"))
            # CLI verify 失败路径：false + stderr 原因 + 退出码 1
            cp = subprocess.run(
                [sys.executable, "-m", "vcbackend.cli", "verify", "vc_bad"],
                cwd=ROOT, env=dict(env2, VCBACKEND_URL=base2),
                capture_output=True, text=True)
            check("CLI verify 失败输出 false/stderr 原因/退出码 1",
                  cp.returncode == 1 and cp.stdout.strip() == "false"
                  and cp.stderr.strip())
        finally:
            proc2.terminate()
            try:
                proc2.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc2.kill()
            if os.path.exists(old_store):
                os.remove(old_store)

        # 23. 选择性披露演示（含防重放：challenge / expires_at / 一次性消费）
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "sd-issuer"})
        sd_issuer = r["did"]
        _, r = _http("POST", f"{base}/v1/dids",
                     {"method": "example", "public_key": "sd-subject"})
        sd_subject = r["did"]
        sd_claims = {
            "role": "admin",
            "level": 3,
            "addr": {"city": "BJ", "zip": "100000"},
            "tags": ["a", "b"],
            "a/b": 1,
            "m~n": 2,
        }
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": sd_issuer, "subject_did": sd_subject,
            "claims": sd_claims})
        sd_cid = r["credential_id"]

        def post_raw(url, raw_bytes):
            req = urllib.request.Request(url, data=raw_bytes, method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read().decode() or "{}")
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode() or "{}")

        # 23.1 present 成功：201 与全部字段；投影仅含所选值
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/role", "/addr/city"]})
        check("present -> 201", st == 201)
        check("presentation_id 为 vp_ 加 32 位小写 hex",
              bool(re.fullmatch(r"vp_[0-9a-f]{32}", r.get("presentation_id", ""))))
        check("present 回显 credential_id/issuer_did",
              r.get("credential_id") == sd_cid and r.get("issuer_did") == sd_issuer)
        check("present issuer_key_version=1",
              r.get("issuer_key_version") == 1)
        check("present disclose 原样回显",
              r.get("disclose") == ["/role", "/addr/city"])
        check("present claims 仅含投影（嵌套仅保留所选叶子）",
              r.get("claims") == {"role": "admin", "addr": {"city": "BJ"}})
        check("present proof 为非空无填充 base64url",
              isinstance(r.get("proof"), str) and r["proof"]
              and "=" not in r["proof"])
        check("present 缺省 challenge 为 32 位小写 hex",
              bool(re.fullmatch(r"[0-9a-f]{32}", r.get("challenge", ""))))
        check("present expires_at 为 Z 结尾秒精度",
              bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                                r.get("expires_at", ""))))
        check("present 响应恰为九个字段",
              set(r) == {"presentation_id", "credential_id", "issuer_did",
                         "issuer_key_version", "disclose", "claims",
                         "challenge", "expires_at", "proof"})
        vp1 = r
        pid1 = vp1["presentation_id"]

        # 23.2 verify 成功：200 且响应恰为 {"valid": true}；随后被消费
        st, r = _http("POST", f"{base}/v1/presentations/{pid1}/verify",
                      {"presentation": vp1, "challenge": vp1["challenge"]})
        check("presentation verify valid=true 且无多余字段",
              st == 200 and r == {"valid": True})
        st, r = _http("POST", f"{base}/v1/presentations/{pid1}/verify",
                      {"presentation": vp1, "challenge": vp1["challenge"]})
        check("重复验证 -> 200 valid:false 演示已消费",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

        # 23.3 零披露：disclose [] / claims {}
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": []})
        check("零披露 present -> 201", st == 201 and r.get("disclose") == []
              and r.get("claims") == {})
        pid0 = r["presentation_id"]
        st, r = _http("POST", f"{base}/v1/presentations/{pid0}/verify",
                      {"presentation": r, "challenge": r["challenge"]})
        check("零披露 verify valid=true", st == 200 and r == {"valid": True})

        # 23.4 数组整值可披露、数组索引禁止
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/tags"]})
        check("数组整值披露 -> 201 且投影保留完整数组",
              st == 201 and r.get("claims") == {"tags": ["a", "b"]})
        st, rr = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                       {"disclose": ["/tags/0"]})
        check("数组索引 -> 400", st == 400 and rr.get("error"))

        # 23.5 RFC6901 转义路径
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/a~1b", "/m~0n"]})
        check("~0/~1 转义路径 -> 201 且投影正确",
              st == 201 and r.get("claims") == {"a/b": 1, "m~n": 2})

        # 23.6 present 各类 400
        def present_400(name, payload=None, raw=None):
            if raw is None:
                raw = json.dumps(payload).encode("utf-8")
            stx, rr2 = post_raw(
                f"{base}/v1/credentials/{sd_cid}/present", raw)
            check(name, stx == 400 and isinstance(rr2.get("error"), str)
                  and rr2["error"])

        present_400("present 缺 disclose -> 400", {})
        present_400("present disclose 非数组 -> 400", {"disclose": {}})
        present_400("present 多余字段 -> 400",
                    {"disclose": [], "x": 1})
        present_400("present 元素非字符串 -> 400", {"disclose": [1]})
        present_400("present 路径不以 / 开头 -> 400",
                    {"disclose": ["role"]})
        present_400("present 根路径 -> 400", {"disclose": [""]})
        present_400("present 路径重复 -> 400",
                    {"disclose": ["/role", "/role"]})
        present_400("present 祖先重叠 -> 400",
                    {"disclose": ["/addr", "/addr/city"]})
        present_400("present 后代祖先重叠(逆序) -> 400",
                    {"disclose": ["/addr/city", "/addr"]})
        present_400("present 越界 -> 400", {"disclose": ["/nope"]})
        present_400("present 深层越界 -> 400",
                    {"disclose": ["/addr/nope"]})
        present_400("present 非法 JSON -> 400", raw=b"{not json")
        present_400("present 空请求体 -> 400", raw=b"")
        present_400("present 非对象 -> 400", raw=b"[1]")
        # challenge / expires_in 字段校验
        present_400("present challenge 空串 -> 400",
                    {"disclose": [], "challenge": ""})
        present_400("present challenge 非字符串 -> 400",
                    {"disclose": [], "challenge": 7})
        present_400("present challenge 超 256 码点 -> 400",
                    {"disclose": [], "challenge": "c" * 257})
        present_400("present expires_in 布尔 -> 400",
                    {"disclose": [], "expires_in": True})
        present_400("present expires_in 非整数 -> 400",
                    {"disclose": [], "expires_in": 1.5})
        present_400("present expires_in=0 -> 400",
                    {"disclose": [], "expires_in": 0})
        present_400("present expires_in=86401 -> 400",
                    {"disclose": [], "expires_in": 86401})
        present_400("present expires_in 字符串 -> 400",
                    {"disclose": [], "expires_in": "300"})

        # 边界合法值：256 码点 challenge、expires_in 1 与 86400
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": [], "challenge": "c" * 256,
                       "expires_in": 86400})
        check("present 256 码点 challenge + expires_in=86400 -> 201",
              st == 201 and r.get("challenge") == "c" * 256)
        # 自定义 challenge 原样回显并用于验证
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/role"], "challenge": "我的挑战-1"})
        check("present 自定义 challenge 回显",
              st == 201 and r.get("challenge") == "我的挑战-1")
        vpc = r
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vpc['presentation_id']}/verify",
                      {"presentation": vpc, "challenge": "我的挑战-1"})
        check("自定义 challenge verify valid=true",
              st == 200 and r == {"valid": True})

        # 23.7 未知凭证 present -> 404
        st, _ = _http("POST", f"{base}/v1/credentials/vc_nope/present",
                      {"disclose": []})
        check("present 未知凭证 -> 404", st == 404)

        # 23.8 verify 统一 200 + valid:false + 非空中文 reason
        def vp_invalid(name, pid, payload=None, raw=None, needle=""):
            if raw is None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            stx, rr2 = post_raw(
                f"{base}/v1/presentations/{pid}/verify", raw)
            ok = (stx == 200 and rr2.get("valid") is False
                  and isinstance(rr2.get("reason"), str)
                  and rr2["reason"].strip()
                  and any("一" <= ch <= "鿿" for ch in rr2["reason"]))
            if needle:
                ok = ok and needle in rr2["reason"]
            check(name, ok)
            return rr2

        # 专用于失败用例的演示（失败不消费，可反复使用）
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/role", "/addr/city"]})
        vpx = r
        pidx = vpx["presentation_id"]
        chx = vpx["challenge"]

        vp_invalid("vp verify 空请求体", pidx, raw=b"")
        vp_invalid("vp verify 非法 JSON", pidx, raw=b"{not json")
        vp_invalid("vp verify 非对象", pidx, raw=b"[1]")
        vp_invalid("vp verify 缺 presentation", pidx, {"x": 1})
        vp_invalid("vp verify 多余顶层字段", pidx,
                   {"presentation": vpx, "challenge": chx, "x": 1})
        vp_invalid("vp verify presentation 非对象", pidx,
                   {"presentation": []})
        vp_invalid("vp verify 路径 ID 未持久化", "vp_nope",
                   {"presentation": {}})
        # 新演示请求必须携带非空 challenge
        vp_invalid("vp verify 缺 challenge", pidx,
                   {"presentation": vpx}, needle="challenge")
        vp_invalid("vp verify challenge 空串", pidx,
                   {"presentation": vpx, "challenge": ""},
                   needle="challenge")
        vp_invalid("vp verify challenge 非字符串", pidx,
                   {"presentation": vpx, "challenge": 1},
                   needle="challenge")
        vp_invalid("vp verify 请求 challenge 不匹配", pidx,
                   {"presentation": vpx, "challenge": "错误的挑战"},
                   needle="challenge")
        bad = json.loads(json.dumps(vpx))
        bad["challenge"] = "被篡改的挑战"
        vp_invalid("vp verify 演示 challenge 被改", pidx,
                   {"presentation": bad, "challenge": chx},
                   needle="challenge")
        bad = json.loads(json.dumps(vpx))
        bad["expires_at"] = "2999-01-01T00:00:00Z"
        vp_invalid("vp verify expires_at 被改", pidx,
                   {"presentation": bad, "challenge": chx},
                   needle="expires_at")
        bad = json.loads(json.dumps(vpx))
        bad["presentation_id"] = "vp_other"
        vp_invalid("vp verify 对象 ID 与路径不一致", pidx,
                   {"presentation": bad, "challenge": chx},
                   needle="presentation_id")
        bad = json.loads(json.dumps(vpx))
        bad["credential_id"] = "vc_other"
        vp_invalid("vp verify credential_id 被改", pidx,
                   {"presentation": bad, "challenge": chx}, needle="锚定")
        bad = json.loads(json.dumps(vpx))
        bad["issuer_did"] = sd_subject
        vp_invalid("vp verify issuer_did 被改", pidx,
                   {"presentation": bad, "challenge": chx}, needle="锚定")
        bad = json.loads(json.dumps(vpx))
        bad["issuer_key_version"] = 2
        vp_invalid("vp verify issuer_key_version 被改", pidx,
                   {"presentation": bad, "challenge": chx}, needle="锚定")
        bad = json.loads(json.dumps(vpx))
        bad["disclose"] = ["/addr/city", "/role"]
        vp_invalid("vp verify disclose 顺序调换", pidx,
                   {"presentation": bad, "challenge": chx},
                   needle="disclose")
        bad = json.loads(json.dumps(vpx))
        bad["disclose"] = []
        bad["claims"] = {}
        vp_invalid("vp verify disclose 被替换", pidx,
                   {"presentation": bad, "challenge": chx},
                   needle="disclose")
        # claims 投影篡改：加未披露字段 / 改值 / 删键
        bad = json.loads(json.dumps(vpx))
        bad["claims"]["secret"] = "leak"
        vp_invalid("vp verify claims 加未披露字段", pidx,
                   {"presentation": bad, "challenge": chx}, needle="claims")
        bad = json.loads(json.dumps(vpx))
        bad["claims"]["role"] = "root"
        vp_invalid("vp verify claims 值被改", pidx,
                   {"presentation": bad, "challenge": chx}, needle="claims")
        bad = json.loads(json.dumps(vpx))
        del bad["claims"]["role"]
        vp_invalid("vp verify claims 缺所选值", pidx,
                   {"presentation": bad, "challenge": chx}, needle="claims")
        bad = json.loads(json.dumps(vpx))
        bad["proof"] = bad["proof"][:-2] + ("ab" if bad["proof"][-2:] != "ab"
                                            else "cd")
        vp_invalid("vp verify proof 被改", pidx,
                   {"presentation": bad, "challenge": chx}, needle="签名校验")
        bad = json.loads(json.dumps(vpx))
        bad["proof"] = "@@@"
        vp_invalid("vp verify proof 编码非法", pidx,
                   {"presentation": bad, "challenge": chx}, needle="签名格式")
        bad = json.loads(json.dumps(vpx))
        bad["extra"] = 1
        vp_invalid("vp verify presentation 多字段", pidx,
                   {"presentation": bad, "challenge": chx})
        bad = json.loads(json.dumps(vpx))
        del bad["claims"]
        vp_invalid("vp verify presentation 缺字段", pidx,
                   {"presentation": bad, "challenge": chx})
        # 全部失败均不消费：正确请求随后仍应成功（随后即被消费）
        st, r = _http("POST", f"{base}/v1/presentations/{pidx}/verify",
                      {"presentation": vpx, "challenge": chx})
        check("失败用例不消费，合法验证仍 valid=true",
              st == 200 and r == {"valid": True})

        # 23.9 轮换后旧演示仍按历史版本验真
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/role"]})
        vp_pre = r
        st, r = _http("POST", f"{base}/v1/dids/{sd_issuer}/keys/rotate",
                      {"key_handle": "sd-issuer-v2"})
        check("SD 签发者轮换 -> 200 key_version=2",
              st == 200 and r.get("key_version") == 2)
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vp_pre['presentation_id']}/verify",
                      {"presentation": vp_pre, "challenge": vp_pre["challenge"]})
        check("轮换后旧演示仍 valid=true（历史版本公钥）",
              st == 200 and r == {"valid": True})
        # 轮换后新凭证演示用 v2 密钥
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": sd_issuer, "subject_did": sd_subject,
            "claims": {"role": "user"}})
        sd_cid2 = r["credential_id"]
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid2}/present",
                      {"disclose": ["/role"]})
        check("轮换后演示 issuer_key_version=2",
              st == 201 and r.get("issuer_key_version") == 2)
        pid2 = r["presentation_id"]
        st, r = _http("POST", f"{base}/v1/presentations/{pid2}/verify",
                      {"presentation": r, "challenge": r["challenge"]})
        check("v2 演示 valid=true", st == 200 and r == {"valid": True})

        # 23.10 已吊销凭证：验签成功后返回“凭证已吊销：<原因>”且不消费
        st, r = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": sd_issuer, "subject_did": sd_subject,
            "claims": {"kind": "revoke-vp"}})
        sd_cid3 = r["credential_id"]
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid3}/present",
                      {"disclose": ["/kind"]})
        pid3, vp3 = r["presentation_id"], r
        _http("POST", f"{base}/v1/credentials/{sd_cid3}/revoke",
              {"reason": "演示吊销测试"})
        st, r = _http("POST", f"{base}/v1/presentations/{pid3}/verify",
                      {"presentation": vp3, "challenge": vp3["challenge"]})
        check("已吊销凭证演示 valid:false 且附保存原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：演示吊销测试")
        st, r = _http("POST", f"{base}/v1/presentations/{pid3}/verify",
                      {"presentation": vp3, "challenge": vp3["challenge"]})
        check("吊销失败不消费（仍返回吊销原因而非已消费）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：演示吊销测试")

        # 23.11 过期：expires_in=1，过期后验证失败且不消费
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/role"], "expires_in": 1})
        check("present expires_in=1 -> 201", st == 201)
        vpe = r
        time.sleep(1.3)
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vpe['presentation_id']}/verify",
                      {"presentation": vpe, "challenge": vpe["challenge"]})
        check("过期演示 valid:false 且 reason 含已过期",
              st == 200 and r.get("valid") is False
              and "已过期" in r.get("reason", ""))
        st, r = _http("POST",
                      f"{base}/v1/presentations/{vpe['presentation_id']}/verify",
                      {"presentation": vpe, "challenge": vpe["challenge"]})
        check("过期不消费（仍返回已过期而非已消费）",
              st == 200 and r.get("valid") is False
              and "已过期" in r.get("reason", ""))

        # 23.12 并发验证：同一演示并发请求仅一次成功
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/level"]})
        vpg = r
        urlg = f"{base}/v1/presentations/{vpg['presentation_id']}/verify"
        payloadg = {"presentation": vpg, "challenge": vpg["challenge"]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(
                lambda _: _http("POST", urlg, payloadg), range(8)))
        oks = [rr for stx, rr in results if rr.get("valid") is True]
        consumed = [rr for stx, rr in results
                    if "已消费" in rr.get("reason", "")]
        check("并发验证恰一次成功，其余均为已消费",
              all(stx == 200 for stx, _ in results)
              and len(oks) == 1 and len(consumed) == 7)

        # 23.13 演示记录跨重启持久化：消费记录保留，重启后重复验证判已消费
        st, r = _http("POST", f"{base}/v1/credentials/{sd_cid}/present",
                      {"disclose": ["/role"]})
        vpp = r
        pidp = vpp["presentation_id"]
        st, r = _http("POST", f"{base}/v1/presentations/{pidp}/verify",
                      {"presentation": vpp, "challenge": vpp["challenge"]})
        check("重启前验证 valid=true", st == 200 and r == {"valid": True})
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port), "主服务（SD 用例）重启超时"
        st, r = _http("POST", f"{base}/v1/presentations/{pidp}/verify",
                      {"presentation": vpp, "challenge": vpp["challenge"]})
        check("重启后重复验证 -> 演示已消费（消费记录跨重启保留）",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))
        st, r = _http("POST", f"{base}/v1/presentations/{pid3}/verify",
                      {"presentation": vp3, "challenge": vp3["challenge"]})
        check("重启后吊销演示仍返回吊销原因",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已吊销：演示吊销测试")

        # 23.14 旧演示（存储记录缺少 challenge）：恰含 presentation 即可，
        # 不检查挑战、过期与消费
        leg_priv = crypto.generate_private_key_pem()
        leg_pub = crypto.public_key_pem_from_private(leg_priv).strip()
        leg_did = f"did:example:{'0' * 32}"
        leg_unsigned = {
            "presentation_id": f"vp_{'1' * 32}",
            "credential_id": "vc_leg",
            "issuer_did": leg_did,
            "issuer_key_version": 1,
            "disclose": ["/role"],
            "claims": {"role": "admin"},
        }
        leg_vp = dict(leg_unsigned, proof=crypto.sign(leg_unsigned, leg_priv))
        leg_body = {
            "credential_id": "vc_leg",
            "issuer_did": leg_did,
            "subject_did": leg_did,
            "claims": {"role": "admin"},
            "issued_at": "2025-01-01T00:00:00Z",
            "issuer_key_version": 1,
        }
        leg_state = {
            "dids": {
                leg_did: {
                    "method": "example",
                    "public_key": leg_pub,
                    "created_at": "2025-01-01T00:00:00Z",
                    "private_key_pem": leg_priv,
                }
            },
            "credentials": {
                "vc_leg": {
                    "body": leg_body,
                    "signature": crypto.sign(leg_body, leg_priv),
                }
            },
            "presentations": {leg_vp["presentation_id"]: leg_vp},
        }
        leg_store = tempfile.mktemp(suffix=".json")
        with open(leg_store, "w", encoding="utf-8") as fh:
            json.dump(leg_state, fh)
        port3 = 8943
        env3 = dict(os.environ, VCBACKEND_STORE=leg_store)
        proc3 = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port3), "--host", "127.0.0.1"],
            cwd=ROOT, env=env3,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base3 = f"http://127.0.0.1:{port3}"
        try:
            assert wait_up(port3), "旧演示服务启动超时"
            leg_pid = leg_vp["presentation_id"]
            st, r = _http("POST",
                          f"{base3}/v1/presentations/{leg_pid}/verify",
                          {"presentation": leg_vp})
            check("旧演示恰含 presentation -> valid=true",
                  st == 200 and r == {"valid": True})
            st, r = _http("POST",
                          f"{base3}/v1/presentations/{leg_pid}/verify",
                          {"presentation": leg_vp})
            check("旧演示不消费，重复验证仍 valid=true",
                  st == 200 and r == {"valid": True})
            st, r = _http("POST",
                          f"{base3}/v1/presentations/{leg_pid}/verify",
                          {"presentation": leg_vp, "challenge": "x"})
            check("旧演示携带 challenge -> valid:false",
                  st == 200 and r.get("valid") is False
                  and r.get("reason"))
        finally:
            proc3.terminate()
            try:
                proc3.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc3.kill()
            if os.path.exists(leg_store):
                os.remove(leg_store)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("全部端到端测试通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
