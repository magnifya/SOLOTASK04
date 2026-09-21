#!/usr/bin/env python3
"""选择性披露演示的可选持有者绑定（holder binding）端到端测试。

覆盖：
- present 未绑定（缺省 / holder_binding=false）响应字段与旧流程完全一致；
- holder_binding=true 201 新增 holder_did/holder_key_version/holder_proof，
  holder_did 为 subject DID、holder_key_version 为持有者当前版本，
  holder_proof 可外部用持有者公钥验真（覆盖去掉 proof、holder_proof 的
  完整演示对象 + tenant_id）；issuer proof 覆盖范围不变（不含 holder_*）；
- holder_binding 非布尔 400、未知凭证 404；
- 绑定演示 verify：成功仅一次并消费；holder 字段缺失/篡改、holder_proof
  格式错误/签名不匹配、跨租户均 200 valid:false 且非空中文 reason，不消费；
- challenge/过期/吊销/并发防重放对绑定演示同样生效；
- 持有者密钥轮换后旧绑定演示用历史公钥验证、新演示用新版本；
- 重启后绑定记录与消费标记保留；
- 直连 store 的防御路径：subject 未注册时绑定生成 400、holder_did 与
  凭证 subject_did 不一致、持有者历史公钥不可用均 valid:false 且不消费。

直接运行：python3 tests/holder_binding_test.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

PORT = 8955
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

UNBOUND_KEYS = {
    "presentation_id", "credential_id", "issuer_did",
    "issuer_key_version", "disclose", "claims",
    "challenge", "expires_at", "proof",
}
BOUND_KEYS = UNBOUND_KEYS | {
    "holder_did", "holder_key_version", "holder_proof",
}


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


def start_server():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(PORT), "服务启动超时"
    return proc


def _external_holder_payload(vp, tenant_id):
    """holder_proof 的覆盖对象：去掉 proof、holder_proof 后加 tenant_id。"""
    payload = {k: v for k, v in vp.items()
               if k not in ("proof", "holder_proof")}
    payload["tenant_id"] = tenant_id
    return payload


def _external_issuer_payload(vp):
    """issuer proof 覆盖对象：不含任何 holder_* 字段与 tenant_id。"""
    return {k: v for k, v in vp.items()
            if k not in ("proof", "holder_did",
                         "holder_key_version", "holder_proof")}


def run_direct_store_checks(failures, check):
    """直连 VCStore 的防御路径（HTTP 无法构造 subject 未注册等状态）。"""
    from vcbackend.store import VCStore, ValidationError

    direct_path = tempfile.mktemp(suffix=".json")
    try:
        store = VCStore(direct_path)
        issuer_rec = store.create_did("t1", "example", "direct-issuer")
        subject_rec = store.create_did("t1", "example", "direct-subject")
        cred = store.create_credential(
            "t1", issuer_rec.did, subject_rec.did, {"a": 1}
        )
        bucket = store._tenants["t1"]  # noqa: SLF001 测试直查内部状态

        # subject_did 未注册时绑定生成必须 400
        saved_subject = bucket["dids"].pop(subject_rec.did)
        try:
            raised = False
            try:
                store.create_presentation(
                    "t1", cred.credential_id, ["/a"],
                    challenge="c", holder_binding=True,
                )
            except ValidationError:
                raised = True
            check("直连: subject 未注册时绑定生成抛 ValidationError", raised)
        finally:
            bucket["dids"][subject_rec.did] = saved_subject

        # 正常绑定生成
        rec = store.create_presentation(
            "t1", cred.credential_id, ["/a"],
            challenge="c", holder_binding=True,
        )
        row = bucket["presentations"][rec.presentation_id]

        def request_view():
            # 模拟 HTTP 客户端：请求对象不含存储侧消费标记
            return {k: v for k, v in row.items()
                    if k not in ("consumed", "consumed_at")}

        # holder_did 与凭证 subject_did 不一致 -> valid:false 不消费
        other_rec = store.create_did("t1", "example", "direct-other")
        original_holder_did = row["holder_did"]
        row["holder_did"] = other_rec.did
        forged = request_view()
        valid, reason = store.verify_presentation(
            "t1", rec.presentation_id, forged, "c"
        )
        check(
            "直连: holder_did 与 subject_did 不一致 -> valid:false",
            not valid and "subject_did" in reason,
        )
        row["holder_did"] = original_holder_did

        # 持有者历史公钥不可用 -> valid:false 且不消费
        history = bucket["dids"][subject_rec.did]["key_history"]
        entry = next(e for e in history if e["version"] == rec.holder_key_version)
        saved_pub = entry.pop("public_key")
        valid, reason = store.verify_presentation(
            "t1", rec.presentation_id, request_view(), "c"
        )
        check(
            "直连: 持有者历史公钥不可用 -> valid:false",
            not valid and "历史公钥不可用" in reason and "持有者" in reason,
        )
        entry["public_key"] = saved_pub

        # 公钥恢复后此前失败均未消费，首次验证成功
        valid, reason = store.verify_presentation(
            "t1", rec.presentation_id, request_view(), "c"
        )
        check("直连: 公钥恢复后绑定演示 valid:true（失败不消费）", valid)
        valid, reason = store.verify_presentation(
            "t1", rec.presentation_id, request_view(), "c"
        )
        check("直连: 再次验证 -> 演示已消费",
              not valid and "已消费" in reason)
    finally:
        if os.path.exists(direct_path):
            os.unlink(direct_path)


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        # ---------------- 准备：DID 与凭证 ---------------- #
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "hb-issuer"})
        assert st == 201, r
        issuer = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "hb-subject"})
        assert st == 201, r
        subject = r["did"]
        subject_pem_v1 = r["public_key"]
        claims = {"role": "admin", "addr": {"city": "Shanghai"}, "age": 30}
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": claims})
        assert st == 201, r
        cred = r["credential_id"]

        def present(body, headers=None):
            return _http("POST",
                         f"{BASE}/v1/credentials/{cred}/present",
                         body, headers=headers)

        def verify_vp(vp_id, vp, challenge, headers=None):
            return _http("POST",
                         f"{BASE}/v1/presentations/{vp_id}/verify",
                         {"presentation": vp, "challenge": challenge},
                         headers=headers)

        # ---------------- 未绑定完全兼容 ---------------- #
        st, r = present({"disclose": ["/role"], "challenge": "plain"})
        check("未绑定（缺省 holder_binding）201", st == 201)
        check("未绑定响应字段集合与旧流程一致", set(r) == UNBOUND_KEYS)
        st, vr = verify_vp(r["presentation_id"], r, "plain")
        check("未绑定演示 verify valid:true", st == 200 and vr == {"valid": True})

        st, r = present({"disclose": [], "challenge": "plain-f",
                         "holder_binding": False})
        check("显式 holder_binding=false 201", st == 201)
        check("显式 false 响应不含 holder_*", set(r) == UNBOUND_KEYS)
        st, vr = verify_vp(r["presentation_id"], r, "plain-f")
        check("显式 false 演示 verify valid:true",
              st == 200 and vr == {"valid": True})

        # ---------------- holder_binding 入参校验 ---------------- #
        for name, value in [("字符串 true", "true"), ("数字 1", 1),
                            ("null", None), ("列表", []), ("对象", {})]:
            st, r = present({"disclose": ["/role"], "holder_binding": value})
            check(f"holder_binding 非布尔 400: {name}",
                  st == 400 and bool(r.get("error")))
        st, r = _http(
            "POST",
            f"{BASE}/v1/credentials/vc_{'0' * 32}/present",
            {"disclose": ["/role"], "holder_binding": True},
        )
        check("holder_binding=true 未知凭证 -> 404", st == 404)

        # ---------------- 绑定生成 201 与字段 ---------------- #
        st, vp = present({"disclose": ["/role", "/addr/city"],
                          "challenge": "bind-1", "holder_binding": True})
        check("绑定 present -> 201", st == 201)
        check("绑定响应恰含 12 个字段", set(vp) == BOUND_KEYS)
        check("holder_did 为 subject DID", vp.get("holder_did") == subject)
        check("holder_key_version 为持有者当前版本 1",
              vp.get("holder_key_version") == 1)
        check("claims 投影正确",
              vp.get("claims") == {"role": "admin",
                                   "addr": {"city": "Shanghai"}})
        vp1_id = vp["presentation_id"]

        # holder_proof 外部密码学验真：覆盖去 proof/holder_proof + tenant_id
        try:
            crypto.verify(
                _external_holder_payload(vp, "default"),
                vp["holder_proof"], subject_pem_v1,
            )
            check("holder_proof 可用持有者公钥外部验真", True)
        except Exception:  # noqa: BLE001
            check("holder_proof 可用持有者公钥外部验真", False)
        # tenant_id 是签名内容的一部分：错误租户验签失败
        try:
            crypto.verify(
                _external_holder_payload(vp, "other-tenant"),
                vp["holder_proof"], subject_pem_v1,
            )
            check("holder_proof 篡改 tenant_id 后验签失败", False)
        except crypto.InvalidSignature:
            check("holder_proof 篡改 tenant_id 后验签失败", True)
        # holder_proof 为 64 字节裸 R||S 的无填充 base64url
        import base64
        raw = base64.urlsafe_b64decode(vp["holder_proof"] + "==")
        check("holder_proof 为 64 字节裸 R||S base64url",
              len(raw) == 64 and "=" not in vp["holder_proof"])

        # issuer proof 不变：覆盖对象不含 holder_*、不含 tenant_id
        try:
            crypto.verify(_external_issuer_payload(vp), vp["proof"],
                          _http("GET", f"{BASE}/v1/dids/{issuer}")[1]["public_key"])
            check("issuer proof 按旧覆盖对象验真成功", True)
        except Exception:  # noqa: BLE001
            check("issuer proof 按旧覆盖对象验真成功", False)
        try:
            crypto.verify(
                {k: v for k, v in vp.items() if k != "proof"},
                vp["proof"],
                _http("GET", f"{BASE}/v1/dids/{issuer}")[1]["public_key"],
            )
            check("issuer proof 不含 holder_*（含则验签应失败）", False)
        except crypto.InvalidSignature:
            check("issuer proof 不含 holder_*（含则验签应失败）", True)

        # ---------------- 绑定 verify 成功与消费 ---------------- #
        st, r = verify_vp(vp1_id, vp, "bind-1")
        check("绑定演示 verify -> valid:true 且恰含 valid",
              st == 200 and r == {"valid": True})
        st, r = verify_vp(vp1_id, vp, "bind-1")
        check("绑定演示重复 verify -> 演示已消费",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

        # ---------------- 缺失/篡改均 valid:false 且不消费 ---------------- #
        st, fresh = present({"disclose": ["/role"],
                             "challenge": "bind-tamper",
                             "holder_binding": True})
        assert st == 201, fresh
        fid = fresh["presentation_id"]

        def expect_invalid(name, bad_vp):
            st, r = verify_vp(fid, bad_vp, "bind-tamper")
            ok = st == 200 and r.get("valid") is False \
                and isinstance(r.get("reason"), str) and bool(r["reason"])
            check(name, ok)

        expect_invalid("缺 holder_did -> valid:false",
                       {k: v for k, v in fresh.items() if k != "holder_did"})
        expect_invalid("缺 holder_key_version -> valid:false",
                       {k: v for k, v in fresh.items()
                        if k != "holder_key_version"})
        expect_invalid("缺 holder_proof -> valid:false",
                       {k: v for k, v in fresh.items()
                        if k != "holder_proof"})
        expect_invalid("多余字段 -> valid:false",
                       dict(fresh, extra=1))
        expect_invalid("篡改 holder_did -> valid:false",
                       dict(fresh, holder_did="did:example:" + "0" * 32))
        expect_invalid("篡改 holder_key_version -> valid:false",
                       dict(fresh, holder_key_version=2))
        expect_invalid("篡改 challenge -> valid:false",
                       dict(fresh, challenge="other"))
        expect_invalid("篡改 claims -> valid:false",
                       dict(fresh, claims={"role": "user"}))
        # holder_proof 格式错误（合法 base64url 但长度不对）
        expect_invalid("holder_proof 格式错误 -> valid:false",
                       dict(fresh, holder_proof="AAAA"))
        # holder_proof 换成 64 字节随机 R||S -> 签名校验失败
        import os as _os
        rand_sig = base64.urlsafe_b64encode(
            _os.urandom(64)).rstrip(b"=").decode()
        st, r = verify_vp(fid, dict(fresh, holder_proof=rand_sig),
                          "bind-tamper")
        check("holder_proof 签名不匹配 -> valid:false 中文 reason",
              st == 200 and r.get("valid") is False
              and "holder_proof" in r.get("reason", ""))
        # challenge 错误
        st, r = verify_vp(fid, fresh, "wrong-challenge")
        check("请求 challenge 错误 -> valid:false",
              st == 200 and r.get("valid") is False and bool(r.get("reason")))
        # 此前全部失败均不消费
        st, r = verify_vp(fid, fresh, "bind-tamper")
        check("绑定演示篡改尝试均不消费，原演示 valid:true",
              st == 200 and r == {"valid": True})

        # ---------------- 跨租户 ---------------- #
        st, fresh = present({"disclose": ["/role"], "challenge": "bind-x",
                             "holder_binding": True})
        assert st == 201, fresh
        xid = fresh["presentation_id"]
        st, r = verify_vp(xid, fresh, "bind-x",
                          headers={"X-Tenant-ID": "other"})
        check("跨租户 verify 绑定演示 -> 200 valid:false 不存在",
              st == 200 and r.get("valid") is False
              and "不存在" in r.get("reason", ""))
        st, r = verify_vp(xid, fresh, "bind-x")
        check("本租户再验证 -> valid:true（跨租户失败不消费）",
              st == 200 and r == {"valid": True})

        # ---------------- 过期与吊销不消费 ---------------- #
        st, fresh = present({"disclose": ["/role"], "expires_in": 1,
                             "holder_binding": True})
        assert st == 201, fresh
        time.sleep(2)
        st, r = verify_vp(fresh["presentation_id"], fresh,
                          fresh["challenge"])
        check("绑定演示过期 -> valid:false 演示已过期",
              st == 200 and r.get("valid") is False
              and "已过期" in r.get("reason", ""))

        st, fresh = present({"disclose": ["/role"], "challenge": "bind-rev",
                             "holder_binding": True})
        assert st == 201, fresh
        st, _ = _http("POST", f"{BASE}/v1/credentials/{cred}/revoke",
                      {"reason": "持证人造假"})
        assert st == 200
        st, r = verify_vp(fresh["presentation_id"], fresh, "bind-rev")
        check("凭证吊销后绑定演示 -> valid:false 凭证已吊销 不消费",
              st == 200 and r.get("valid") is False
              and "凭证已吊销" in r.get("reason", "")
              and "持证人造假" in r.get("reason", ""))
        st, r = verify_vp(fresh["presentation_id"], fresh, "bind-rev")
        check("吊销后重复验证仍失败（未消费）",
              st == 200 and r.get("valid") is False)

        # ---------------- 密钥轮换：历史公钥验证 ---------------- #
        # 新凭证（旧凭证已吊销）：issuer2/subject 仍为同一持有者
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"role": "user"}})
        assert st == 201, r
        cred2 = r["credential_id"]
        st, before = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/present",
            {"disclose": ["/role"], "challenge": "pre-rotate",
             "holder_binding": True},
        )
        assert st == 201, before
        check("轮换前绑定演示 holder_key_version=1",
              before["holder_key_version"] == 1)

        st, r = _http("POST",
                      f"{BASE}/v1/dids/{subject}/keys/rotate",
                      {"key_handle": "hb-subject-v2"})
        assert st == 200, r
        subject_pem_v2 = r["public_key"]
        check("持有者轮换后 key_version=2", r["key_version"] == 2)

        # 旧绑定演示用 v1 历史公钥仍可验证
        st, rr = _http(
            "POST",
            f"{BASE}/v1/presentations/{before['presentation_id']}/verify",
            {"presentation": before, "challenge": "pre-rotate"},
        )
        check("轮换后旧绑定演示以历史公钥验证 valid:true",
              st == 200 and rr == {"valid": True})
        try:
            crypto.verify(_external_holder_payload(before, "default"),
                          before["holder_proof"], subject_pem_v1)
            check("旧 holder_proof 外部以 v1 公钥验真", True)
        except Exception:  # noqa: BLE001
            check("旧 holder_proof 外部以 v1 公钥验真", False)

        # 新绑定演示使用新版本密钥
        st, after = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/present",
            {"disclose": ["/role"], "challenge": "post-rotate",
             "holder_binding": True},
        )
        assert st == 201, after
        check("轮换后新绑定演示 holder_key_version=2",
              after["holder_key_version"] == 2)
        try:
            crypto.verify(_external_holder_payload(after, "default"),
                          after["holder_proof"], subject_pem_v2)
            check("新 holder_proof 外部以 v2 公钥验真", True)
        except Exception:  # noqa: BLE001
            check("新 holder_proof 外部以 v2 公钥验真", False)
        # v1 公钥验新签名必须失败
        try:
            crypto.verify(_external_holder_payload(after, "default"),
                          after["holder_proof"], subject_pem_v1)
            check("v1 公钥不能验 v2 holder_proof", False)
        except crypto.InvalidSignature:
            check("v1 公钥不能验 v2 holder_proof", True)
        st, rr = _http(
            "POST",
            f"{BASE}/v1/presentations/{after['presentation_id']}/verify",
            {"presentation": after, "challenge": "post-rotate"},
        )
        check("轮换后新绑定演示 verify valid:true",
              st == 200 and rr == {"valid": True})

        # ---------------- 并发仅一次成功 ---------------- #
        st, race = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/present",
            {"disclose": ["/role"], "challenge": "race",
             "holder_binding": True},
        )
        assert st == 201, race
        race_id = race["presentation_id"]

        def one_verify(_):
            return _http(
                "POST", f"{BASE}/v1/presentations/{race_id}/verify",
                {"presentation": race, "challenge": "race"},
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(one_verify, range(8)))
        valids = [r for st, r in outcomes
                  if st == 200 and r.get("valid") is True]
        consumed = [r for st, r in outcomes
                    if st == 200 and r.get("valid") is False
                    and "已消费" in r.get("reason", "")]
        check("绑定演示并发验证仅一次 valid:true",
              len(valids) == 1 and len(consumed) == 7)

        # ---------------- 重启持久化 ---------------- #
        st, keep = _http(
            "POST", f"{BASE}/v1/credentials/{cred2}/present",
            {"disclose": ["/role"], "challenge": "restart-bind",
             "holder_binding": True},
        )
        assert st == 201, keep
        keep_id = keep["presentation_id"]
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{keep_id}/verify",
            {"presentation": keep, "challenge": "restart-bind"},
        )
        check("重启后绑定演示双签名验证 valid:true",
              st == 200 and r == {"valid": True})
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{keep_id}/verify",
            {"presentation": keep, "challenge": "restart-bind"},
        )
        check("重启后消费标记保留（演示已消费）",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

        # ---------------- 直连 store 防御路径 ---------------- #
        run_direct_store_checks(failures, check)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
