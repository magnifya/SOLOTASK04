#!/usr/bin/env python3
"""选择性披露演示的可选持有者绑定（holder binding）端到端测试。

覆盖：
- present holder_binding 缺省/ false 完全兼容（响应无持有者字段）；
- holder_binding:true 成功 201 且返回 holder_did/holder_key_version/
  holder_proof，holder_did 为 subject DID、版本为当前密钥版本；
- holder_binding 非布尔 400、未知凭证 404；
- holder_proof 可外部按历史公钥独立验真（覆盖去掉 proof、holder_proof
  的完整演示对象及 tenant_id）；
- verify 双签名：正常 valid:true 且仅消费一次；持有者字段缺失/多余、
  holder_did/holder_key_version/holder_proof/claims/challenge 篡改均
  HTTP 200 valid:false 且中文 reason，失败不消费；
- 轮换持有者密钥后用历史公钥验证仍通过；重启后绑定记录可验、消费
  标记保留；跨租户验证 200 valid:false；
- 已吊销凭证的绑定演示不消费；并发仅一次 valid:true。

直接运行：python3 tests/holder_binding_test.py
"""

import copy
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

HOLDER_KEYS = {"presentation", "holder_did", "holder_key_version",
               "holder_proof"}


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
                      {"method": "example", "public_key": "hb-holder"})
        assert st == 201, r
        holder = r["did"]
        holder_pub_v1 = r["public_key"]
        st, r = _http("GET", f"{BASE}/v1/dids/{holder}")
        assert st == 200 and r["key_version"] == 1, r

        claims = {"role": "admin", "addr": {"city": "Shanghai", "zip": "200000"}}
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": holder,
                       "claims": claims})
        assert st == 201, r
        cred = r["credential_id"]

        # 第二张凭证：吊销路径用
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": holder,
                       "claims": {"role": "user"}})
        assert st == 201, r
        cred_revoke = r["credential_id"]

        def present(cid, payload, headers=None):
            return _http("POST", f"{BASE}/v1/credentials/{cid}/present",
                         payload, headers=headers)

        def verify(pid, presentation, challenge, headers=None):
            return _http("POST", f"{BASE}/v1/presentations/{pid}/verify",
                         {"presentation": presentation, "challenge": challenge},
                         headers=headers)

        # ---------------- 1. 未绑定流程完全兼容 ---------------- #
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-legacy"})
        assert st == 201, r
        legacy_pid = r["presentation_id"]
        check("未绑定响应不含任何持有者字段",
              "holder_did" not in r and "holder_key_version" not in r
              and "holder_proof" not in r)
        st, vr = verify(legacy_pid, {k: r[k] for k in (
            "presentation_id", "credential_id", "issuer_did",
            "issuer_key_version", "disclose", "claims", "challenge",
            "expires_at", "proof")}, "c-legacy")
        check("未绑定演示验签成功", st == 200 and vr.get("valid") is True)

        st, r = present(cred, {"disclose": [], "challenge": "c-false",
                               "holder_binding": False})
        assert st == 201, r
        check("holder_binding:false 响应不含持有者字段",
              not ({k for k in r} & HOLDER_KEYS))
        st, vr = verify(r["presentation_id"], {
            k: r[k] for k in (
                "presentation_id", "credential_id", "issuer_did",
                "issuer_key_version", "disclose", "claims", "challenge",
                "expires_at", "proof")}, "c-false")
        check("holder_binding:false 验签成功", st == 200 and vr.get("valid") is True)

        # 未绑定演示携带持有者字段即字段集合不一致
        st, r2 = present(cred, {"disclose": ["/role"], "challenge": "c-extra"})
        assert st == 201, r2
        obj = dict(r2)
        obj.pop("proof", None)
        obj_full = dict(r2)
        obj_full["holder_did"] = holder
        obj_full["holder_key_version"] = 1
        obj_full["holder_proof"] = r2["proof"]
        st, vr = verify(r2["presentation_id"], obj_full, "c-extra")
        check("未绑定演示携带持有者字段 valid:false",
              st == 200 and vr.get("valid") is False and bool(vr.get("reason")))

        # ---------------- 2. holder_binding 字段错误 400 ---------------- #
        for bad in ("true", 1, 0, None, [], {}):
            st, r = present(cred, {"disclose": ["/role"],
                                   "holder_binding": bad})
            check(f"holder_binding={bad!r} -> 400", st == 400)
        st, r = present("vc_nonexistent", {"disclose": [],
                                           "holder_binding": True})
        check("未知凭证 holder_binding -> 404", st == 404)

        # ---------------- 3. 绑定演示生成与字段 ---------------- #
        st, r = present(cred, {"disclose": ["/role", "/addr/city"],
                               "challenge": "c-bound", "expires_in": 600,
                               "holder_binding": True})
        assert st == 201, r
        pid = r["presentation_id"]
        bound = dict(r)
        check("绑定响应 holder_did 为 subject DID",
              r.get("holder_did") == holder)
        check("绑定响应 holder_key_version 为当前版本 1",
              r.get("holder_key_version") == 1)
        check("绑定响应 holder_proof 为非空字符串",
              isinstance(r.get("holder_proof"), str)
              and len(r["holder_proof"]) > 0)
        check("绑定响应字段恰为 12 项", set(r) == {
            "presentation_id", "credential_id", "issuer_did",
            "issuer_key_version", "disclose", "claims", "challenge",
            "expires_at", "proof", "holder_did",
            "holder_key_version", "holder_proof"})
        check("投影仅含所选值", r["claims"] == {
            "role": "admin", "addr": {"city": "Shanghai"}})

        # holder_proof 外部独立验真：去掉 proof、holder_proof 的完整演示
        # 对象 + tenant_id=default
        msg = {k: v for k, v in bound.items()
               if k not in ("proof", "holder_proof")}
        msg["tenant_id"] = "default"
        try:
            crypto.verify(msg, bound["holder_proof"], holder_pub_v1)
            externally_ok = True
        except Exception:
            externally_ok = False
        check("holder_proof 可用持有者公钥外部验真", externally_ok)

        # tenant_id 不同则外部验签失败
        msg_other = dict(msg)
        msg_other["tenant_id"] = "other"
        try:
            crypto.verify(msg_other, bound["holder_proof"], holder_pub_v1)
            tenant_tamper_ok = False
        except crypto.InvalidSignature:
            tenant_tamper_ok = True
        check("holder_proof 覆盖 tenant_id（篡改租户即验签失败）",
              tenant_tamper_ok)

        # ---------------- 4. 绑定演示正常验证 ---------------- #
        st, vr = verify(pid, bound, "c-bound")
        check("绑定演示双签名验证 valid:true",
              st == 200 and vr == {"valid": True})
        st, vr = verify(pid, bound, "c-bound")
        check("重复验证返回演示已消费",
              st == 200 and vr.get("valid") is False
              and "已消费" in vr.get("reason", ""))

        # ---------------- 5. 各类篡改均 200/valid:false/中文 reason，不消费 #
        def fresh_bound(challenge="c-tamper", cid=cred):
            st, r = present(cid, {"disclose": ["/role"],
                                  "challenge": challenge,
                                  "holder_binding": True})
            assert st == 201, r
            return r

        def tamper_case(name, mutate, bad_challenge="c-tamper"):
            r = fresh_bound(bad_challenge)
            obj = dict(r)
            mutate(obj, r)
            st, vr = verify(r["presentation_id"], obj, bad_challenge)
            bad = st == 200 and vr.get("valid") is False and bool(vr.get("reason"))
            check(name, bad)
            if not bad:
                return
            # 失败不消费：原样对象仍可成功一次
            st2, vr2 = verify(r["presentation_id"], r, bad_challenge)
            check(name + "（失败不消费，随后可成功）",
                  st2 == 200 and vr2.get("valid") is True)

        tamper_case("缺 holder_did",
                    lambda obj, r: obj.pop("holder_did"))
        tamper_case("缺 holder_key_version",
                    lambda obj, r: obj.pop("holder_key_version"))
        tamper_case("缺 holder_proof",
                    lambda obj, r: obj.pop("holder_proof"))
        tamper_case("holder_did 被篡改",
                    lambda obj, r: obj.update(holder_did="did:example:deadbeef"))
        tamper_case("holder_key_version 被篡改",
                    lambda obj, r: obj.update(holder_key_version=2))
        tamper_case("holder_proof 被篡改",
                    lambda obj, r: obj.update(holder_proof=r["proof"]))
        tamper_case("claims 被篡改（签发者签名先失败）",
                    lambda obj, r: obj.update(claims={"role": "root"}))
        tamper_case("演示内 challenge 被篡改",
                    lambda obj, r: obj.update(challenge="c-forged"))
        tamper_case("expires_at 被篡改",
                    lambda obj, r: obj.update(expires_at="2099-01-01T00:00:00Z"))

        # 请求 challenge 与演示不一致：演示按 c-tamper 生成，请求传 c-other
        r = fresh_bound("c-tamper")
        st, vr = verify(r["presentation_id"], r, "c-other")
        check("请求 challenge 不一致 valid:false",
              st == 200 and vr.get("valid") is False and bool(vr.get("reason")))
        st, vr = verify(r["presentation_id"], r, "c-tamper")
        check("challenge 失败不消费，正确挑战随后 valid:true",
              st == 200 and vr.get("valid") is True)

        # ---------------- 6. 轮换持有者密钥后历史公钥仍可验 ---------------- #
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-rot",
                               "holder_binding": True})
        assert st == 201, r
        rot_pid = r["presentation_id"]
        rot_pres = dict(r)
        check("轮换前绑定版本为 1", r["holder_key_version"] == 1)
        st, r = _http("POST", f"{BASE}/v1/dids/{holder}/keys/rotate",
                      {"key_handle": "hb-holder-v2"})
        assert st == 200 and r["key_version"] == 2, r
        st, r = _http("GET", f"{BASE}/v1/dids/{holder}")
        assert st == 200 and r["key_version"] == 2, r

        # 旧绑定演示用版本 1 历史公钥验证通过
        st, vr = verify(rot_pid, rot_pres, "c-rot")
        check("轮换后旧绑定演示仍 valid:true",
              st == 200 and vr.get("valid") is True)

        # 轮换后新绑定演示版本为 2，可用旧/新公钥区分验真
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-v2",
                               "holder_binding": True})
        assert st == 201, r
        v2_pid = r["presentation_id"]
        v2_pres = dict(r)
        check("轮换后绑定版本为 2", r["holder_key_version"] == 2)
        holder_pub_v2 = r2_pub = None
        st, did_r = _http("GET", f"{BASE}/v1/dids/{holder}")
        holder_pub_v2 = did_r["public_key"]
        msg = {k: v for k, v in v2_pres.items()
               if k not in ("proof", "holder_proof")}
        msg["tenant_id"] = "default"
        try:
            crypto.verify(msg, v2_pres["holder_proof"], holder_pub_v2)
            v2_ext = True
        except Exception:
            v2_ext = False
        check("版本 2 holder_proof 用新公钥外部验真", v2_ext)
        try:
            crypto.verify(msg, v2_pres["holder_proof"], holder_pub_v1)
            v2_oldkey = False
        except crypto.InvalidSignature:
            v2_oldkey = True
        check("版本 2 holder_proof 不能被旧公钥验真", v2_oldkey)
        st, vr = verify(v2_pid, v2_pres, "c-v2")
        check("版本 2 绑定演示验签成功", st == 200 and vr.get("valid") is True)

        # ---------------- 7. 跨租户 200/valid:false ---------------- #
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-tenant",
                               "holder_binding": True})
        assert st == 201, r
        tenant_pid = r["presentation_id"]
        st, vr = verify(tenant_pid, r, "c-tenant",
                        headers={"X-Tenant-ID": "acme"})
        check("跨租户验证 200/valid:false/中文原因",
              st == 200 and vr.get("valid") is False and bool(vr.get("reason")))
        # 跨租户失败不影响本租户消费
        st, vr = verify(tenant_pid, r, "c-tenant")
        check("跨租户失败不消费，本租户随后 valid:true",
              st == 200 and vr.get("valid") is True)

        # ---------------- 8. 凭证吊销：不消费 ---------------- #
        st, r = present(cred_revoke, {"disclose": ["/role"],
                                      "challenge": "c-rev",
                                      "holder_binding": True})
        assert st == 201, r
        rev_pid = r["presentation_id"]
        st, rr = _http("POST", f"{BASE}/v1/credentials/{cred_revoke}/revoke",
                       {"reason": "持证人违规"})
        assert st == 200, rr
        st, vr = verify(rev_pid, r, "c-rev")
        check("已吊销凭证的绑定演示 valid:false 且原因含吊销",
              st == 200 and vr.get("valid") is False
              and "吊销" in vr.get("reason", ""))
        st, vr = verify(rev_pid, r, "c-rev")
        check("吊销演示重复验证仍为吊销原因（未消费）",
              st == 200 and vr.get("valid") is False
              and "吊销" in vr.get("reason", ""))

        # ---------------- 9. 并发仅一次成功 ---------------- #
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-conc",
                               "holder_binding": True, "expires_in": 3600})
        assert st == 201, r
        conc_pid = r["presentation_id"]

        def one_verify(_):
            return verify(conc_pid, r, "c-conc")

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(one_verify, range(8)))
        truths = sum(1 for _, vr in results if vr.get("valid") is True)
        check("并发验证仅一次 valid:true", truths == 1)
        st, vr = verify(conc_pid, r, "c-conc")
        check("并发后再验证为演示已消费",
              vr.get("valid") is False and "已消费" in vr.get("reason", ""))

        # ---------------- 10. 重启持久化（未消费可验、已消费保留、轮换历史公钥） #
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-restart",
                               "holder_binding": True})
        assert st == 201, r
        restart_pid = r["presentation_id"]
        restart_pres = dict(r)
        st, r_consumed = present(
            cred, {"disclose": ["/role"], "challenge": "c-restart-done",
                   "holder_binding": True})
        assert st == 201, r_consumed
        consumed_pid = r_consumed["presentation_id"]
        st, vr = verify(consumed_pid, r_consumed, "c-restart-done")
        assert st == 200 and vr.get("valid") is True, vr

        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()

        st, vr = verify(restart_pid, restart_pres, "c-restart")
        check("重启后绑定记录双签名验证 valid:true",
              st == 200 and vr.get("valid") is True)
        st, vr = verify(restart_pid, restart_pres, "c-restart")
        check("重启后消费标记保留（演示已消费）",
              st == 200 and vr.get("valid") is False
              and "已消费" in vr.get("reason", ""))
        st, vr = verify(consumed_pid, r_consumed, "c-restart-done")
        check("重启前消费记录仍保留",
              st == 200 and vr.get("valid") is False
              and "已消费" in vr.get("reason", ""))

        # 重启后轮换前的旧版本公钥仍可验
        st, r = present(cred, {"disclose": ["/role"], "challenge": "c-post",
                               "holder_binding": True})
        assert st == 201, r
        check("重启后新绑定使用持有者当前版本 2",
              r["holder_key_version"] == 2)
        st, vr = verify(r["presentation_id"], r, "c-post")
        check("重启后绑定演示验签成功", st == 200 and vr.get("valid") is True)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    if failures:
        print(f"{len(failures)} 项失败:", failures)
        sys.exit(1)
    print("全部持有者绑定测试通过")


if __name__ == "__main__":
    main()
