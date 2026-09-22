#!/usr/bin/env python3
"""批量跨系统演示验真 POST /v1/trust/presentations/verify-batch 的端到端测试。

直接运行：python3 tests/trust_presentation_verify_batch_test.py
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


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
    path = "/v1/trust/presentations/verify-batch"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload, headers=headers, raw=raw)

    def request_level_invalid(name, payload=None, raw=None, headers=None):
        st, r = verify(payload=payload, raw=raw, headers=headers)
        check(
            name,
            st == 200
            and isinstance(r.get("results"), list)
            and r["results"] == []
            and isinstance(r.get("reason"), str)
            and r["reason"].startswith("请求")
            and set(r) == {"results", "reason"},
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tpbp-a"}
        T2 = {"X-Tenant-ID": "tpbp-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:external-presentation-batch.example"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify(payload={"presentations": []},
                       headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 注册信任锚点：无需登记 DID/凭证/演示
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册外部锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册外部锚点 v2 -> 201", st == 201)

        def make_presentation(version=2, challenge="chal-1",
                              expires_at="2099-01-01T00:00:00Z",
                              issuer=did):
            return {
                "presentation_id": "vp_" + "b" * 32,
                "credential_id": "vc_external_pres_batch_1",
                "issuer_did": issuer,
                "issuer_key_version": version,
                "disclose": ["/role", "/addr/city"],
                "claims": {"role": "admin", "addr": {"city": "北京"}},
                "challenge": challenge,
                "expires_at": expires_at,
            }

        def sign_presentation(p, priv):
            message = {k: v for k, v in p.items() if k != "proof"}
            p["proof"] = crypto.sign(message, priv)
            return p

        def signed(version=2, priv=None, **kwargs):
            p = make_presentation(version=version, **kwargs)
            return sign_presentation(p, priv or priv2)

        def req(p, challenge="chal-1"):
            return {"presentation": p, "challenge": challenge}

        good = signed()

        # 1. 请求级结构非法：统一 200 + {"results": [], "reason": "请求..."}
        request_level_invalid("空请求体", raw=b"")
        request_level_invalid("非法 JSON", raw=b"not-json")
        request_level_invalid("UTF-8 非法", raw=b"\xff\xfe")
        request_level_invalid("JSON 数组非对象", raw=b"[1,2]")
        request_level_invalid("JSON null 非对象", raw=b"null")
        request_level_invalid("空对象（缺 presentations）", {}, headers=T1)
        request_level_invalid("缺 presentations",
                              {"presentation": []}, headers=T1)
        request_level_invalid("多余字段",
                              {"presentations": [req(good)], "extra": 1},
                              headers=T1)
        request_level_invalid("presentations 非数组（对象）",
                              {"presentations": {"a": 1}}, headers=T1)
        request_level_invalid("presentations 非数组（字符串）",
                              {"presentations": "x"}, headers=T1)
        request_level_invalid("presentations 为空数组",
                              {"presentations": []}, headers=T1)
        request_level_invalid(
            "presentations 超过 100 项",
            {"presentations": [req(good)] * 101}, headers=T1)

        # 2. 单项批次成功：响应恰为 {"results": [{"valid": true}]}
        st, r = verify({"presentations": [req(good)]}, headers=T1)
        check("单项批次成功且响应恰为 results",
              st == 200 and r == {"results": [{"valid": True}]})

        # 3. 100 项边界：全部成功
        st, r = verify({"presentations": [req(good)] * 100}, headers=T1)
        check("100 项批次全部成功",
              st == 200 and r == {"results": [{"valid": True}] * 100})

        # 4. 混合批次：失败不短路，长度与顺序与输入一致
        bad_field = json.loads(json.dumps(good))
        bad_field.pop("credential_id")  # 演示缺字段
        bad_challenge = req(good, challenge="chal-2")  # 挑战不匹配
        unknown = signed(issuer="did:web:unknown-pres-batch.example")
        fmt_bad_proof = json.loads(json.dumps(good))
        fmt_bad_proof["proof"] = "!!!not-b64!!!"  # 签名格式错误
        tampered = json.loads(json.dumps(good))
        tampered["credential_id"] = "vc_other"  # 验签失败
        expired = signed(expires_at="2020-01-01T00:00:00Z")  # 已过期
        not_obj = "not-an-object"  # 项级请求错误
        with_holder = json.loads(json.dumps(good))
        with_holder["holder_did"] = "did:web:holder.example"  # holder_* 字段
        with_source = dict(req(good), source_tenant_id="src")  # 绑定形态但演示缺 holder_*
        with_extra = dict(req(good), extra=1)  # 其他多余字段
        batch = [
            req(good),
            req(bad_field),
            bad_challenge,
            req(unknown),
            req(fmt_bad_proof),
            req(tampered),
            req(expired),
            not_obj,
            req(with_holder),
            with_source,
            with_extra,
            req(good),
        ]
        st, r = verify({"presentations": batch}, headers=T1)
        ok = st == 200 and set(r) == {"results"} and len(r["results"]) == 12
        results = r.get("results", [])
        check("混合批次长度与输入一致且顶层不含 reason", ok)
        check("混合批次第 1 项成功", ok and results[0] == {"valid": True})
        check("混合批次缺字段项 -> 演示",
              ok and results[1].get("valid") is False
              and results[1].get("reason", "").startswith("演示"))
        check("混合批次挑战项 -> 挑战",
              ok and results[2].get("valid") is False
              and results[2].get("reason", "").startswith("挑战"))
        check("混合批次锚点项 -> 锚点",
              ok and results[3].get("valid") is False
              and results[3].get("reason", "").startswith("锚点"))
        check("混合批次签名格式项 -> 签名格式错误",
              ok and results[4].get("valid") is False
              and results[4].get("reason", "").startswith("签名格式错误"))
        check("混合批次篡改项 -> 签名校验失败",
              ok and results[5].get("valid") is False
              and results[5].get("reason", "").startswith("签名校验失败"))
        check("混合批次过期项 -> 演示已过期",
              ok and results[6] == {"valid": False, "reason": "演示已过期"})
        check("混合批次非对象项 -> 请求",
              ok and results[7].get("valid") is False
              and results[7].get("reason", "").startswith("请求"))
        check("混合批次 holder_* 字段项 -> 演示",
              ok and results[8].get("valid") is False
              and results[8].get("reason", "").startswith("演示")
              and "holder" in results[8].get("reason", ""))
        check("混合批次绑定形态但演示缺 holder 字段 -> 演示",
              ok and results[9].get("valid") is False
              and results[9].get("reason", "").startswith("演示")
              and "holder" in results[9].get("reason", ""))
        check("混合批次其他多余字段项 -> 请求",
              ok and results[10].get("valid") is False
              and results[10].get("reason", "").startswith("请求"))
        check("混合批次失败不短路（末项仍成功）",
              ok and results[11] == {"valid": True})
        check("成功项恰为 valid 一字段",
              ok and all(
                  set(item) == {"valid"}
                  for item in results if item.get("valid") is True))
        check("失败项恰为 valid+reason 两字段",
              ok and all(
                  set(item) == {"valid", "reason"} and item["reason"]
                  for item in results if item.get("valid") is False))

        # 5. 只读：不登记资源、不消费、不记审计
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            verify({"presentations": [req(good), req(unknown)]}, headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("批量验签（含失败与重复成功）不记审计",
              len(after["events"]) == n_before)
        st, r = verify({"presentations": [req(good)]}, headers=T1)
        check("重复批量验签始终成功（不消费）",
              st == 200 and r == {"results": [{"valid": True}]})

        # 6. 跨租户：各自使用本租户锚点
        st, r = verify({"presentations": [req(good)]}, headers=T2)
        check("T2 无锚点 -> 项级锚点失败",
              st == 200 and r["results"][0].get("valid") is False
              and r["results"][0].get("reason", "").startswith("锚点"))
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        t2_pres = sign_presentation(make_presentation(), priv1)
        st, r = verify({"presentations": [req(t2_pres)]}, headers=T2)
        check("T2 按自己的锚点批量验签成功",
              st == 200 and r == {"results": [{"valid": True}]})

        # 7. 单项与本地演示接口不受影响
        st, r = _http("POST", f"{base}/v1/trust/presentations/verify",
                      req(good), headers=T1)
        check("单项跨系统演示接口仍正常",
              st == 200 and r == {"valid": True})
        # 单项接口接受持有者绑定形态（批量同样接受）
        bound_priv, bound_pub = gen_keypair()
        holder_did = "did:web:holder-batch.example"
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": holder_did, "public_key": bound_pub,
                       "key_version": 1},
                      headers=T1)
        check("注册持有者锚点 -> 201", st == 201)
        bound = json.loads(json.dumps(good))
        bound["holder_did"] = holder_did
        bound["holder_key_version"] = 1
        bound_message = {
            k: v for k, v in bound.items()
            if k != "proof" and not k.startswith("holder_")
        }
        bound_message["holder_did"] = holder_did
        bound_message["holder_key_version"] = 1
        bound_message["tenant_id"] = "source-tenant"
        bound["holder_proof"] = crypto.sign(bound_message, bound_priv)
        st, r = _http("POST", f"{base}/v1/trust/presentations/verify",
                      {"presentation": bound, "challenge": "chal-1",
                       "source_tenant_id": "source-tenant"},
                      headers=T1)
        check("单项接口持有者绑定形态仍正常",
              st == 200 and r == {"valid": True})
        st, r = verify({"presentations": [
            {"presentation": bound, "challenge": "chal-1",
             "source_tenant_id": "source-tenant"}]}, headers=T1)
        check("批量接口接受持有者绑定形态（项级成功）",
              st == 200 and r == {"results": [{"valid": True}]})

        # 8. 批量混合未绑定与持有者绑定项：等长同序、失败不短路
        bound_unknown_holder = json.loads(json.dumps(bound))
        bound_unknown_holder["holder_did"] = "did:web:nobody-holder"
        st, r = verify({"presentations": [
            req(good),
            {"presentation": bound, "challenge": "chal-1",
             "source_tenant_id": "source-tenant"},
            {"presentation": bound, "challenge": "chal-2",
             "source_tenant_id": "source-tenant"},
            {"presentation": bound_unknown_holder, "challenge": "chal-1",
             "source_tenant_id": "source-tenant"},
            {"presentation": bound, "challenge": "chal-1",
             "source_tenant_id": "other-tenant"},
            req(good),
        ]}, headers=T1)
        ok = st == 200 and set(r) == {"results"} and len(r["results"]) == 6
        bres = r.get("results", [])
        check("混合形态批次长度一致", ok)
        check("混合形态第 1 项未绑定成功", ok and bres[0] == {"valid": True})
        check("混合形态第 2 项绑定成功", ok and bres[1] == {"valid": True})
        check("混合形态第 3 项绑定挑战不匹配 -> 挑战",
              ok and bres[2].get("valid") is False
              and bres[2].get("reason", "").startswith("挑战"))
        check("混合形态第 4 项未知持有者锚点 -> 持有者锚点不存在",
              ok and bres[3].get("valid") is False
              and bres[3].get("reason", "").startswith("持有者锚点不存在"))
        check("混合形态第 5 项 tenant_id 不符 -> holder_proof 验签失败",
              ok and bres[4].get("valid") is False
              and bres[4].get("reason", "").startswith(
                  "签名校验失败: holder_proof"))
        check("混合形态末项未绑定仍成功（不短路）",
              ok and bres[5] == {"valid": True})

        # source_tenant_id 项级类型/空值错误仍为项级失败（不清空整批）
        st, r = verify({"presentations": [
            {"presentation": bound, "challenge": "chal-1",
             "source_tenant_id": ""},
            {"presentation": bound, "challenge": "chal-1",
             "source_tenant_id": 123},
        ]}, headers=T1)
        check("绑定项空/非字符串 source_tenant_id -> 项级请求失败",
              st == 200 and len(r["results"]) == 2
              and all(item.get("valid") is False
                      and item.get("reason", "").startswith("请求")
                      for item in r["results"]))

        # 绑定演示缺任一 holder 字段 -> 项级“演示”失败
        bound_missing = json.loads(json.dumps(bound))
        bound_missing.pop("holder_proof")
        st, r = verify({"presentations": [
            {"presentation": bound_missing, "challenge": "chal-1",
             "source_tenant_id": "source-tenant"}]}, headers=T1)
        check("绑定演示缺 holder_proof -> 项级演示失败",
              st == 200 and r["results"][0].get("valid") is False
              and r["results"][0].get("reason", "").startswith("演示"))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 8. 跨重启：锚点持久化，批量结论稳定
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tpbp-a"}
        p2 = signed()
        st, r = _http("POST", f"{base}{path}",
                      {"presentations": [req(p2)]}, headers=T1)
        check("重启后批量验签结论稳定",
              st == 200 and r == {"results": [{"valid": True}]})
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


if __name__ == "__main__":
    raise SystemExit(main())
