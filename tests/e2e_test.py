#!/usr/bin/env python3
"""端到端测试：临时启动 HTTP 服务，覆盖 DID/凭证接口与签名验真。

直接运行：python3 tests/e2e_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
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
