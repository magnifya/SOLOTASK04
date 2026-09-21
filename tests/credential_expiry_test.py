#!/usr/bin/env python3
"""凭证有效期（credential expires_at）端到端测试。

覆盖：
- 签发：缺省无 expires_at 字段；提供时严格秒精度 Z 格式且须严格晚于
  服务接收时刻，各类非法值（null/非字符串/偏移/毫秒/非法时刻/过去）
  返回 400；GET 原样返回；响应字段保持 credential_id/signature/
  issuer_key_version；expires_at 写入正文并参与 ES256 签名；
- verify：未过期 valid:true；当前时间 >= expires_at 返回 200、
  valid:false、reason“凭证已过期”；其他失败（篡改/不存在/锚定）
  仍优先原分类原因；过期判定只读、不记审计；
- 选择性披露演示、谓词证明 verify 在自身绑定与签名成功后拒绝已过期
  凭证（同一原因、不消费、不记消费审计），其生成接口协议不变；
- POST /v1/trust/credentials/verify 外部凭证：含 expires_at 时按同
  一格式校验，到期返回同一原因；缺失保持兼容；
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

PORT = 8962
BASE = f"http://127.0.0.1:{PORT}"
STORE = tempfile.mktemp(suffix=".json")
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


def start_server(store=STORE):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(PORT), "服务启动超时"
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


def utc_z(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(PORT), "服务启动超时"

        # ---------------- 准备：签发者/持有者 DID ---------------- #
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "exp-issuer"})
        assert st == 201, r
        issuer = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "exp-subject"})
        assert st == 201, r
        subject = r["did"]

        def issue(payload):
            return _http("POST", f"{BASE}/v1/credentials", payload)

        def get_cred(cid):
            return _http("GET", f"{BASE}/v1/credentials/{cid}")

        base_payload = {
            "issuer_did": issuer,
            "subject_did": subject,
            "claims": {"role": "admin", "age": 30},
        }

        # ---------------- 签发：未提供 expires_at ---------------- #
        st, r = issue(dict(base_payload))
        check("未提供 expires_at -> 201", st == 201)
        check(
            "签发响应字段保持 credential_id/signature/issuer_key_version",
            st == 201
            and set(r) == {"credential_id", "signature", "issuer_key_version"},
        )
        cred_noexp = r["credential_id"]
        st, g = get_cred(cred_noexp)
        check("GET 原样返回且未注入 expires_at",
              st == 200 and "expires_at" not in g["body"])

        # ---------------- 签发：合法未来 expires_at ---------------- #
        future = utc_z(datetime.now(timezone.utc) + timedelta(days=365))
        st, r = issue(dict(base_payload, expires_at=future))
        check("提供未来 expires_at -> 201", st == 201)
        cred_future = r["credential_id"]
        st, g = get_cred(cred_future)
        check("GET 原样返回 expires_at",
              st == 200 and g["body"].get("expires_at") == future)

        # 恰好 1 秒后也必须接受（严格晚于，秒精度）
        soon = utc_z(datetime.now(timezone.utc) + timedelta(seconds=2))
        st, r = issue(dict(base_payload, expires_at=soon))
        check("2 秒后 expires_at -> 201", st == 201)

        # ---------------- 签发：各类非法 expires_at -> 400 -------- #
        now_str = utc_z(datetime.now(timezone.utc))
        bad_values = [
            None,                                   # 显式 null
            123, True, [], {},                      # 非字符串
            "",                                     # 空串
            "2020-01-01T00:00:00Z",                 # 过去时刻
            now_str,                                # 等于当前时刻
            "2026-1-1T00:00:00Z",                   # 非零填充
            "2026-01-01T00:00:00.000Z",             # 毫秒
            "2026-01-01 00:00:00Z",                 # 空格分隔
            "2026-01-01T00:00:00+00:00",            # 偏移
            "2026-01-01T00:00:00",                  # 无 Z
            "2026-01-01T25:00:00Z",                 # 非法时刻
            "2026-13-01T00:00:00Z",                 # 非法月份
        ]
        for bad in bad_values:
            st, r = issue(dict(base_payload, expires_at=bad))
            check(
                f"非法 expires_at {bad!r} -> 400 且说明字段",
                st == 400 and "expires_at" in r.get("error", ""),
            )

        # ---------------- 凭证 verify：未过期 ---------------- #
        def verify(cid, body, signature):
            return _http(
                "POST", f"{BASE}/v1/credentials/{cid}/verify",
                {"body": body, "signature": signature},
            )

        def stored(cid):
            st, g = get_cred(cid)
            assert st == 200, g
            return g

        st, r = verify(
            cred_future,
            stored(cred_future)["body"],
            stored(cred_future)["signature"],
        )
        check("未过期凭证 verify -> 200 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(
            cred_noexp,
            stored(cred_noexp)["body"],
            stored(cred_noexp)["signature"],
        )
        check("无 expires_at 凭证 verify 保持 valid:true",
              st == 200 and r == {"valid": True})

        # ---------------- 凭证 verify：等待到期 ---------------- #
        exp = utc_z(datetime.now(timezone.utc) + timedelta(seconds=2))
        st, r = issue(dict(base_payload, expires_at=exp))
        assert st == 201, r
        cred_expiring = r["credential_id"]
        g = stored(cred_expiring)
        # 到期前有效
        st, r = verify(cred_expiring, g["body"], g["signature"])
        check("到期前 verify valid:true", st == 200 and r == {"valid": True})

        # 到期前按原协议生成演示与谓词证明（生成接口协议不变）
        st, vp = _http(
            "POST", f"{BASE}/v1/credentials/{cred_expiring}/present",
            {"disclose": ["/role"], "challenge": "exp-ch", "expires_in": 3600},
        )
        assert st == 201, vp
        vp_id = vp["presentation_id"]
        st, zp = _http(
            "POST", f"{BASE}/v1/credentials/{cred_expiring}/prove",
            {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
             "challenge": "exp-pz", "expires_in": 3600},
        )
        assert st == 201, zp
        zp_id = zp["proof_id"]
        # 演示/证明自身的 expires_at 均在 1 小时后，先确保凭证未过期时
        # 二者可正常消费（证明凭证级检查不影响正常路径）
        st, r = _http("POST", f"{BASE}/v1/presentations/{vp_id}/verify",
                      {"presentation": vp, "challenge": "exp-ch"})
        check("未过期时演示可正常消费", st == 200 and r == {"valid": True})
        st, r = _http("POST", f"{BASE}/v1/proofs/{zp_id}/verify",
                      {"proof": zp, "challenge": "exp-pz"})
        check("未过期时谓词证明可正常消费", st == 200 and r == {"valid": True})

        # 重新各生成一份未消费的，供到期后验证
        st, vp = _http(
            "POST", f"{BASE}/v1/credentials/{cred_expiring}/present",
            {"disclose": ["/role"], "challenge": "exp-ch2", "expires_in": 3600},
        )
        assert st == 201, vp
        vp_id2 = vp["presentation_id"]
        st, zp = _http(
            "POST", f"{BASE}/v1/credentials/{cred_expiring}/prove",
            {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
             "challenge": "exp-pz2", "expires_in": 3600},
        )
        assert st == 201, zp
        zp_id2 = zp["proof_id"]

        time.sleep(3)
        # 记录审计事件数（verify 只读，过期判定不得记审计）
        st, audit_before = _http("GET", f"{BASE}/v1/audit?limit=200")
        assert st == 200
        n_before = len(audit_before["events"])
        st, r = verify(cred_expiring, g["body"], g["signature"])
        check(
            "到期后 verify -> 200 valid:false 凭证已过期",
            st == 200 and r.get("valid") is False
            and r.get("reason") == EXPIRED_REASON,
        )

        # 演示 verify：自身绑定/签名通过、演示本身未到期，但凭证已过期
        st, r = _http("POST", f"{BASE}/v1/presentations/{vp_id2}/verify",
                      {"presentation": vp, "challenge": "exp-ch2"})
        check("演示 verify 对过期凭证 -> 凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)
        # 谓词证明 verify：同一原因
        st, r = _http("POST", f"{BASE}/v1/proofs/{zp_id2}/verify",
                      {"proof": zp, "challenge": "exp-pz2"})
        check("谓词证明 verify 对过期凭证 -> 凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)

        st, audit_after = _http("GET", f"{BASE}/v1/audit?limit=200")
        check(
            "凭证/演示/证明过期判定均只读：无消费审计",
            st == 200 and len(audit_after["events"]) == n_before,
        )
        # 重复验证仍过期，且记录未被标记已消费
        st, r = _http("POST", f"{BASE}/v1/presentations/{vp_id2}/verify",
                      {"presentation": vp, "challenge": "exp-ch2"})
        check("演示再次验证仍为凭证已过期",
              st == 200 and r.get("reason") == EXPIRED_REASON)
        st, r = _http("POST", f"{BASE}/v1/proofs/{zp_id2}/verify",
                      {"proof": zp, "challenge": "exp-pz2"})
        check("谓词证明再次验证仍为凭证已过期",
              st == 200 and r.get("reason") == EXPIRED_REASON)
        st, audit_after = _http("GET", f"{BASE}/v1/audit?limit=200")
        check("过期判定只读，不记审计",
              st == 200 and len(audit_after["events"]) == n_before)
        # 重复验证结论一致
        st, r = verify(cred_expiring, g["body"], g["signature"])
        check("再次验证仍为凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)

        # 生成接口继续遵守原协议：对已过期凭证仍可生成演示与证明
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred_expiring}/present",
            {"disclose": [], "challenge": "late-vp", "expires_in": 60},
        )
        check("对过期凭证 present 仍按原协议 201", st == 201)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred_expiring}/prove",
            {"predicates": [{"path": "/role", "op": "exists"}],
             "challenge": "late-zp", "expires_in": 60},
        )
        check("对过期凭证 prove 仍按原协议 201", st == 201)

        # expires_at 参与签名：把过期值改成未来值不能绕过过期判定
        tampered = dict(g["body"])
        tampered["expires_at"] = utc_z(
            datetime.now(timezone.utc) + timedelta(days=1)
        )
        st, r = verify(cred_expiring, tampered, g["signature"])
        check("篡改 expires_at 为未来 -> 签名校验失败优先",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        # 删除 expires_at 同样签名失败（不回退为无期限）
        tampered2 = dict(g["body"])
        tampered2.pop("expires_at")
        st, r = verify(cred_expiring, tampered2, g["signature"])
        check("删除 expires_at -> 签名校验失败（不回退无期限）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # 凭证不存在等原分类原因不受影响
        st, r = verify("vc_not_exist", {"credential_id": "vc_not_exist"}, "x")
        check("不存在凭证仍返回资源类原因",
              st == 200 and r.get("valid") is False
              and "凭证不存在" in r.get("reason", ""))

        # 吊销但未过期：仍返回吊销原因（有效期通过后才查状态）
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred_future}/revoke",
            {"reason": "违规"},
        )
        assert st == 200, r
        g = stored(cred_future)
        st, r = verify(cred_future, g["body"], g["signature"])
        check("未过期但已吊销 -> 凭证已吊销原因",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证已吊销"))

        # ---------------- 外部凭证 trust verify ---------------- #
        ext_priv, ext_pub = gen_keypair()
        ext_did = "did:web:expiry-external.example"
        st, r = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": ext_did, "public_key": ext_pub,
                       "key_version": 1})
        assert st == 201, r
        st, audit_before = _http("GET", f"{BASE}/v1/audit?limit=200")
        assert st == 200
        n_before_ext = len(audit_before["events"])

        def ext_body(expires_at=...):
            body = {
                "credential_id": "vc_ext_exp",
                "issuer_did": ext_did,
                "subject_did": "did:web:subject",
                "claims": {"role": "member"},
                "issued_at": "2026-01-01T00:00:00Z",
                "issuer_key_version": 1,
            }
            if expires_at is not ...:
                body["expires_at"] = expires_at
            return body

        def trust_verify(body, priv=ext_priv, resign=True):
            sig = crypto.sign(body, priv) if resign else "x"
            return _http("POST", f"{BASE}/v1/trust/credentials/verify",
                         {"body": body, "signature": sig})

        st, r = trust_verify(ext_body())
        check("外部凭证缺 expires_at 保持兼容 valid:true",
              st == 200 and r == {"valid": True})
        st, r = trust_verify(
            ext_body(utc_z(datetime.now(timezone.utc) + timedelta(days=1)))
        )
        check("外部凭证未过期 valid:true", st == 200 and r == {"valid": True})
        st, r = trust_verify(ext_body("2020-01-01T00:00:00Z"))
        check("外部凭证已过期 -> 凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)

        # 格式非法：凭证字段类原因（先于锚定/签名结论）
        for bad in [None, 123, True, "2020-1-1T00:00:00Z",
                    "2020-01-01T00:00:00.000Z", "2020-01-01 00:00:00Z",
                    "2020-01-01T00:00:00+00:00", "2020-13-01T00:00:00Z"]:
            st, r = trust_verify(ext_body(bad))
            check(f"外部凭证非法 expires_at {bad!r} -> 凭证字段类原因",
                  st == 200 and r.get("valid") is False
                  and r.get("reason", "").startswith("凭证字段 expires_at"))

        # 篡改：签名校验失败优先于过期
        body_signed = ext_body(
            utc_z(datetime.now(timezone.utc) + timedelta(days=1))
        )
        sig = crypto.sign(body_signed, ext_priv)
        body_signed["expires_at"] = "2020-01-01T00:00:00Z"
        st, r = _http("POST", f"{BASE}/v1/trust/credentials/verify",
                      {"body": body_signed, "signature": sig})
        check("外部凭证篡改 expires_at -> 签名校验失败",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))

        # 批量：逐项继承，过期项返回同一原因
        b1 = ext_body(utc_z(datetime.now(timezone.utc) + timedelta(days=1)))
        b1["credential_id"] = "vc_ext_b1"
        b2 = ext_body("2020-01-01T00:00:00Z")
        b2["credential_id"] = "vc_ext_b2"
        b3 = ext_body()
        b3["credential_id"] = "vc_ext_b3"
        st, r = _http("POST", f"{BASE}/v1/trust/credentials/verify-batch",
                      {"credentials": [
                          {"body": b1, "signature": crypto.sign(b1, ext_priv)},
                          {"body": b2, "signature": crypto.sign(b2, ext_priv)},
                          {"body": b3, "signature": crypto.sign(b3, ext_priv)},
                      ]})
        check("批量外部凭证逐项判有效期",
              st == 200 and r.get("results") == [
                  {"valid": True},
                  {"valid": False, "reason": EXPIRED_REASON},
                  {"valid": True},
              ])
        st, audit_ext_after = _http("GET", f"{BASE}/v1/audit?limit=200")
        check("外部凭证验真（含过期）只读不记审计",
              st == 200
              and len(audit_ext_after["events"]) == n_before_ext)

        # ---------------- 重启持久化 ---------------- #
        proc.terminate()
        proc.wait()

        # 停机期间注入一条旧格式演示（无 challenge/expires_at），引用
        # 已过期凭证：凭证级有效期检查对旧演示同样生效
        with open(STORE, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        bucket0 = state["tenants"]["default"]
        issuer_priv = bucket0["dids"][issuer]["private_key_pem"]
        old_vp_unsigned = {
            "presentation_id": "vp_old_expiry",
            "credential_id": cred_expiring,
            "issuer_did": issuer,
            "issuer_key_version": 1,
            "disclose": ["/role"],
            "claims": {"role": "admin"},
        }
        old_vp = dict(old_vp_unsigned)
        old_vp["proof"] = crypto.sign(old_vp_unsigned, issuer_priv)
        bucket0["presentations"]["vp_old_expiry"] = old_vp
        with open(STORE, "w", encoding="utf-8") as fh:
            json.dump(state, fh)

        proc = start_server()
        assert wait_up(PORT), "重启超时"

        g = stored(cred_expiring)
        check("重启后 expires_at 原样持久化",
              g["body"].get("expires_at") == exp)
        st, r = verify(cred_expiring, g["body"], g["signature"])
        check("重启后过期结论一致：凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)
        # 未过期与无期限凭证重启后仍 valid
        g = stored(cred_noexp)
        st, r = verify(cred_noexp, g["body"], g["signature"])
        check("重启后无期限凭证仍 valid:true",
              st == 200 and r == {"valid": True})
        # 到期前生成、未消费的演示/证明重启后对过期凭证仍拒绝且不消费
        st, r = _http("POST", f"{BASE}/v1/presentations/{vp_id2}/verify",
                      {"presentation": vp, "challenge": "exp-ch2"})
        check("重启后演示 verify 仍为凭证已过期",
              st == 200 and r.get("reason") == EXPIRED_REASON)
        st, r = _http("POST", f"{BASE}/v1/proofs/{zp_id2}/verify",
                      {"proof": zp, "challenge": "exp-pz2"})
        check("重启后谓词证明 verify 仍为凭证已过期",
              st == 200 and r.get("reason") == EXPIRED_REASON)

        # 旧格式演示（无 challenge）自身绑定/签名成功后同样拒绝过期凭证
        n_audit_before_restart = len(
            _http("GET", f"{BASE}/v1/audit?limit=200")[1]["events"]
        )
        st, r = _http("POST", f"{BASE}/v1/presentations/vp_old_expiry/verify",
                      {"presentation": old_vp})
        check("旧格式演示对过期凭证 -> 凭证已过期",
              st == 200 and r.get("valid") is False
              and r.get("reason") == EXPIRED_REASON)
        st, ev = _http("GET", f"{BASE}/v1/audit?limit=200")
        check("旧格式演示过期判定不记审计",
              st == 200 and len(ev["events"]) == n_audit_before_restart)
    finally:
        proc.terminate()
        proc.wait()

    if failures:
        print(f"\n{len(failures)} 项失败")
        for name in failures:
            print(" -", name)
        return 1
    print("\n全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
