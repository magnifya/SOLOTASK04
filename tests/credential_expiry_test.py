#!/usr/bin/env python3
"""凭证有效期（expires_at）能力的端到端测试。

覆盖：
- POST /v1/credentials 可选 expires_at：严格 UTC 秒精度 Z 格式、必须
  严格晚于当前时刻，否则 400；未提供不注入字段；GET 原样返回；
- verify 在请求/资源/锚定/签名均成功后判过期，返回 HTTP 200、
  valid:false、reason“凭证已过期”；签名/吊销等原因优先；只读不记审计；
- 选择性披露演示、谓词证明 verify 在自身绑定与签名通过后拒绝已过期
  凭证（同一原因、不消费、不记消费审计），生成接口协议不变；
- POST /v1/trust/credentials/verify 外部凭证带 expires_at 时校验格式
  并在到期时返回该原因，缺失保持兼容；
- 有效期随状态文件持久化，重启后结论一致。

直接运行：python3 tests/credential_expiry_test.py
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

EXPIRED_REASON = "凭证已过期"


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


def utc_z(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


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
    port = 8961
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
    T = {"X-Tenant-ID": "expiry-a"}

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    # 重启阶段需要继续存在的凭证
    expired_cid = {"id": None}
    future_cid = {"id": None}
    eternal_cid = {"id": None}

    try:
        assert wait_up(port), "服务启动超时"

        # 注册签发者/持有者 DID
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "issuer-exp"},
                      headers=T)
        check("注册签发者 DID -> 201", st == 201)
        issuer = r["did"]
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "subject-exp"},
                      headers=T)
        check("注册持有者 DID -> 201", st == 201)
        subject = r["did"]

        def issue(payload):
            return _http("POST", f"{base}/v1/credentials", payload, headers=T)

        def get_cred(cid):
            return _http("GET", f"{base}/v1/credentials/{cid}", headers=T)

        def verify_cred(cid, body, signature):
            return _http(
                "POST", f"{base}/v1/credentials/{cid}/verify",
                {"body": body, "signature": signature}, headers=T,
            )

        audit_url = f"{base}/v1/audit?limit=200"

        # -------------------------------------------------------------- #
        # 1. 签发：expires_at 校验（400）
        # -------------------------------------------------------------- #
        now = datetime.now(timezone.utc)
        bad_values = [
            ("毫秒小数", "2026-09-21T00:00:00.000Z"),
            ("时区偏移", "2030-09-21T00:00:00+00:00"),
            ("空格分隔", "2030-09-21 00:00:00Z"),
            ("缺 Z 后缀", "2030-09-21T00:00:00"),
            ("未补零", "2030-9-21T00:00:00Z"),
            ("非法时刻", "2030-13-40T99:99:99Z"),
            ("过去时刻", "2000-01-01T00:00:00Z"),
            ("当前时刻（相等）", utc_z(now)),
        ]
        for label, value in bad_values:
            st, r = issue({
                "issuer_did": issuer, "subject_did": subject,
                "claims": {"k": 1}, "expires_at": value,
            })
            check(f"非法 expires_at（{label}）-> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])
        for label, value in [("数字", 123), ("null", None), ("对象", {}),
                             ("数组", []), ("布尔", True)]:
            st, r = issue({
                "issuer_did": issuer, "subject_did": subject,
                "claims": {"k": 1}, "expires_at": value,
            })
            check(f"非字符串 expires_at（{label}）-> 400", st == 400)

        # -------------------------------------------------------------- #
        # 2. 未提供 expires_at：正文不注入、签发响应格式不变
        # -------------------------------------------------------------- #
        st, r = issue({
            "issuer_did": issuer, "subject_did": subject,
            "claims": {"role": "admin"},
        })
        check("无 expires_at 签发 -> 201", st == 201)
        check("签发响应字段保持原样",
              set(r) == {"credential_id", "signature", "issuer_key_version"})
        eternal_id = r["credential_id"]
        eternal_cid["id"] = eternal_id
        st, r = get_cred(eternal_id)
        check("GET 200", st == 200)
        body = r["body"]
        check("无 expires_at 时正文不注入该字段", "expires_at" not in body)
        eternal_body, eternal_sig = body, r["signature"]

        # -------------------------------------------------------------- #
        # 3. 提供未来 expires_at：写入正文、参与签名、GET 原样返回
        # -------------------------------------------------------------- #
        future_str = utc_z(now + timedelta(days=365))
        st, r = issue({
            "issuer_did": issuer, "subject_did": subject,
            "claims": {"role": "admin"}, "expires_at": future_str,
        })
        check("未来 expires_at 签发 -> 201", st == 201)
        check("带期限签发响应字段保持原样",
              set(r) == {"credential_id", "signature", "issuer_key_version"})
        future_id = r["credential_id"]
        future_cid["id"] = future_id
        st, got = get_cred(future_id)
        check("GET 200", st == 200)
        check("GET 原样返回 expires_at",
              got["body"].get("expires_at") == future_str)
        future_body, future_sig = got["body"], got["signature"]

        # 篡改 expires_at 必须使验签失败（证明其参与规范化签名）
        tampered = dict(future_body)
        tampered["expires_at"] = utc_z(now + timedelta(days=2))
        st, r = verify_cred(future_id, tampered, future_sig)
        check("篡改 expires_at -> 签名校验失败（参与签名）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 未到期、未改动 -> valid:true
        st, r = verify_cred(future_id, future_body, future_sig)
        check("未到期凭证 verify valid:true",
              st == 200 and r == {"valid": True})
        # 无期限旧凭证 -> valid:true
        st, r = verify_cred(eternal_id, eternal_body, eternal_sig)
        check("无期限凭证 verify valid:true",
              st == 200 and r == {"valid": True})

        # -------------------------------------------------------------- #
        # 4. 已到期凭证：verify 200/valid:false/“凭证已过期”，只读不记审计
        # -------------------------------------------------------------- #
        soon_str = utc_z(datetime.now(timezone.utc) + timedelta(seconds=3))
        st, r = issue({
            "issuer_did": issuer, "subject_did": subject,
            "claims": {"role": "temp"}, "expires_at": soon_str,
        })
        check("短期凭证签发 -> 201", st == 201)
        soon_id = r["credential_id"]
        expired_cid["id"] = soon_id
        st, soon = get_cred(soon_id)
        soon_body, soon_sig = soon["body"], soon["signature"]
        # 到期前仍有效
        st, r = verify_cred(soon_id, soon_body, soon_sig)
        check("到期前 verify valid:true", st == 200 and r.get("valid") is True)

        time.sleep(4)  # 等待跨过 expires_at（当前时间 >= 到期时刻）
        st, n_before = _http("GET", audit_url, headers=T)
        st, r = verify_cred(soon_id, soon_body, soon_sig)
        check("到期 verify 200/valid:false/凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)
        # 多次到期判定不记审计
        for _ in range(2):
            verify_cred(soon_id, soon_body, soon_sig)
        st, n_after = _http("GET", audit_url, headers=T)
        check("到期判定只读、不记审计",
              len(n_after["events"]) == len(n_before["events"]))

        # 锚定/签名等失败优先于过期：篡改正文返回签名类原因
        tampered_soon = dict(soon_body)
        tampered_soon["claims"] = {"role": "root"}
        st, r = verify_cred(soon_id, tampered_soon, soon_sig)
        check("到期凭证正文被篡改 -> 签名校验失败优先",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 未知凭证仍返回资源类原因（即使请求体看起来是到期凭证）
        st, r = verify_cred("vc_not_exist", soon_body, soon_sig)
        check("未知凭证 -> 凭证不存在优先",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证不存在"))

        # -------------------------------------------------------------- #
        # 5. 吊销与过期的优先级
        # -------------------------------------------------------------- #
        # 未到期凭证被吊销 -> 吊销原因
        st, _ = _http("POST", f"{base}/v1/credentials/{future_id}/revoke",
                      {"reason": "违规"}, headers=T)
        check("吊销未到期凭证 -> 200", st == 200)
        st, r = verify_cred(future_id, future_body, future_sig)
        check("未到期但已吊销 -> 凭证已吊销原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证已吊销"))
        # 已到期凭证再吊销：过期优先于吊销
        st, _ = _http("POST", f"{base}/v1/credentials/{soon_id}/revoke",
                      {"reason": "违规"}, headers=T)
        check("吊销已到期凭证 -> 200", st == 200)
        st, r = verify_cred(soon_id, soon_body, soon_sig)
        check("既过期又吊销 -> 凭证已过期优先",
              st == 200 and r.get("reason") == EXPIRED_REASON)

        # -------------------------------------------------------------- #
        # 6. 选择性披露演示：生成协议不变；凭证到期后 verify 拒绝、不消费
        # -------------------------------------------------------------- #
        # 6a. 已到期凭证上仍可生成演示（生成接口不查有效期）
        st, pres = _http(
            "POST", f"{base}/v1/credentials/{soon_id}/present",
            {"disclose": ["/role"], "challenge": "ch-soon",
             "expires_in": 300},
            headers=T,
        )
        check("到期凭证生成演示 -> 201", st == 201)
        check("演示字段协议不变",
              set(pres) == {
                  "presentation_id", "credential_id", "issuer_did",
                  "issuer_key_version", "disclose", "claims",
                  "challenge", "expires_at", "proof",
              })
        vp_soon = pres["presentation_id"]
        st, n_before = _http("GET", audit_url, headers=T)
        for _ in range(2):
            st, r = _http(
                "POST", f"{base}/v1/presentations/{vp_soon}/verify",
                {"presentation": pres, "challenge": "ch-soon"}, headers=T,
            )
            check("到期凭证演示 verify 200/凭证已过期",
                  st == 200 and r.get("valid") is False
                  and r.get("reason") == EXPIRED_REASON)
        st, n_after = _http("GET", audit_url, headers=T)
        created = [e for e in n_after["events"]
                   if e["action"] == "presentation.consumed"
                   and e["resource_id"] == vp_soon]
        check("到期演示不消费、不记消费审计", not created)

        # 6b. 未到期凭证的演示正常消费（回归）
        st, pres_ok = _http(
            "POST", f"{base}/v1/credentials/{eternal_id}/present",
            {"disclose": ["/role"], "challenge": "ch-ok"},
            headers=T,
        )
        check("正常凭证生成演示 -> 201", st == 201)
        vp_ok = pres_ok["presentation_id"]
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp_ok}/verify",
            {"presentation": pres_ok, "challenge": "ch-ok"}, headers=T,
        )
        check("正常演示首次 verify valid:true",
              st == 200 and r == {"valid": True})
        st, r = _http(
            "POST", f"{base}/v1/presentations/{vp_ok}/verify",
            {"presentation": pres_ok, "challenge": "ch-ok"}, headers=T,
        )
        check("正常演示重复 verify -> 演示已消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已消费")

        # -------------------------------------------------------------- #
        # 7. 谓词证明：凭证到期后 verify 拒绝、不消费
        # -------------------------------------------------------------- #
        st, proof = _http(
            "POST", f"{base}/v1/credentials/{soon_id}/prove",
            {"predicates": [{"path": "/role", "op": "eq",
                             "value": "temp"}],
             "challenge": "zp-soon", "expires_in": 300},
            headers=T,
        )
        check("到期凭证生成谓词证明 -> 201", st == 201)
        check("谓词证明字段协议不变",
              set(proof) == {
                  "proof_id", "credential_id", "issuer_did",
                  "issuer_key_version", "predicates", "results",
                  "challenge", "expires_at", "proof",
              })
        zp_soon = proof["proof_id"]
        for _ in range(2):
            st, r = _http(
                "POST", f"{base}/v1/proofs/{zp_soon}/verify",
                {"proof": proof, "challenge": "zp-soon"}, headers=T,
            )
            check("到期凭证谓词证明 verify 200/凭证已过期",
                  st == 200 and r.get("valid") is False
                  and r.get("reason") == EXPIRED_REASON)
        st, ev = _http("GET", audit_url, headers=T)
        consumed_proof = [e for e in ev["events"]
                          if e["action"] == "proof.consumed"
                          and e["resource_id"] == zp_soon]
        check("到期谓词证明不消费、不记消费审计", not consumed_proof)

        # 正常凭证谓词证明回归
        st, proof_ok = _http(
            "POST", f"{base}/v1/credentials/{eternal_id}/prove",
            {"predicates": [{"path": "/role", "op": "exists"}],
             "challenge": "zp-ok"},
            headers=T,
        )
        check("正常凭证生成谓词证明 -> 201", st == 201)
        zp_ok = proof_ok["proof_id"]
        st, r = _http(
            "POST", f"{base}/v1/proofs/{zp_ok}/verify",
            {"proof": proof_ok, "challenge": "zp-ok"}, headers=T,
        )
        check("正常谓词证明 verify valid:true",
              st == 200 and r == {"valid": True})

        # -------------------------------------------------------------- #
        # 8. 外部凭证 /v1/trust/credentials/verify 的有效期
        # -------------------------------------------------------------- #
        priv_ext, pub_ext = gen_keypair()
        ext_did = "did:web:expiry-external.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": ext_did, "public_key": pub_ext,
                       "key_version": 1},
                      headers=T)
        check("注册外部锚点 -> 201", st == 201)

        ext_path = "/v1/trust/credentials/verify"

        def ext_verify(body):
            sig = crypto.sign(body, priv_ext)
            return _http("POST", f"{base}{ext_path}",
                         {"body": body, "signature": sig}, headers=T)

        def ext_body(expires_at=_DELETE, **overrides):
            b = {
                "credential_id": "vc_ext_exp",
                "issuer_did": ext_did,
                "subject_did": "did:web:subject.example",
                "claims": {"level": 7},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
            if expires_at is not _DELETE:
                b["expires_at"] = expires_at
            b.update(overrides)
            return b

        # 缺失 expires_at：保持兼容，验签成功
        st, r = ext_verify(ext_body())
        check("外部凭证缺 expires_at 兼容 valid:true",
              st == 200 and r == {"valid": True})
        # 未来 expires_at：成功
        st, r = ext_verify(ext_body(expires_at=utc_z(now + timedelta(days=1))))
        check("外部凭证未到期 valid:true", st == 200 and r == {"valid": True})
        # 已到期：同一原因
        st, r = ext_verify(ext_body(expires_at="2020-01-01T00:00:00Z"))
        check("外部凭证到期 valid:false/凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)
        # 非法格式：凭证类原因（签名仍成功，格式判定在签名之后）
        for label, value in [("毫秒", "2030-01-01T00:00:00.000Z"),
                             ("偏移", "2030-01-01T00:00:00+00:00"),
                             ("数字", 123), ("null", None)]:
            st, r = ext_verify(ext_body(expires_at=value))
            check(f"外部凭证 expires_at 非法（{label}）-> 凭证类原因",
                  st == 200 and r.get("valid") is False
                  and r.get("reason", "").startswith("凭证字段 expires_at"))
        # 签名失败优先于过期判定
        good = ext_body(expires_at="2020-01-01T00:00:00Z")
        bad_sig = crypto.sign(good, priv_ext) + "AA"  # 改尾巴：仍 64 字节但 R||S 变
        # 直接构造一个用别的私钥的签名，保证密码学验签失败
        priv_other, _ = gen_keypair()
        wrong_sig = crypto.sign(good, priv_other)
        st, r = _http("POST", f"{base}{ext_path}",
                      {"body": good, "signature": wrong_sig}, headers=T)
        check("外部凭证签名错误优先于过期",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # bad_sig 长度可能改变，这里仅确保不会误判为过期
        st, r = _http("POST", f"{base}{ext_path}",
                      {"body": good, "signature": bad_sig}, headers=T)
        check("外部凭证篡改签名不返回过期原因",
              st == 200 and r.get("reason") != EXPIRED_REASON)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 9. 跨重启：有效期持久化，结论一致
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"

        def body_sig(cid):
            st, r = _http("GET", f"{base}/v1/credentials/{cid}", headers=T)
            assert st == 200, f"GET {cid} 失败: {st}"
            return r["body"], r["signature"]

        cid = expired_cid["id"]
        body, sig = body_sig(cid)
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/verify",
                      {"body": body, "signature": sig}, headers=T)
        check("重启后到期结论一致（凭证已过期）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)
        check("重启后 expires_at 仍在正文中", body.get("expires_at"))

        cid = future_cid["id"]
        body, sig = body_sig(cid)
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/verify",
                      {"body": body, "signature": sig}, headers=T)
        check("重启后未到期凭证仍判吊销（状态持久化）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证已吊销"))

        cid = eternal_cid["id"]
        body, sig = body_sig(cid)
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/verify",
                      {"body": body, "signature": sig}, headers=T)
        check("重启后无期限旧凭证仍 valid:true",
              st == 200 and r == {"valid": True})
        check("重启后无期限凭证正文仍无 expires_at",
              "expires_at" not in body)
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


_DELETE = object()


if __name__ == "__main__":
    raise SystemExit(main())
