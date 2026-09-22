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
    port = 8962
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

        T1 = {"X-Tenant-ID": "tpvb-a"}
        T2 = {"X-Tenant-ID": "tpvb-b"}

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
                "presentation_id": "vp_" + "c" * 32,
                "credential_id": "vc_external_presentation_batch_1",
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
            return sign_presentation(
                make_presentation(version=version, **kwargs), priv or priv2
            )

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
        request_level_invalid("缺 presentations", {"proofs": []}, headers=T1)
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
        unknown = signed(issuer="did:web:unknown-pbatch.example")  # 锚点缺失
        fmt_bad_proof = json.loads(json.dumps(good))
        fmt_bad_proof["proof"] = "!!!not-b64!!!"  # 签名格式错误
        tampered = json.loads(json.dumps(good))
        tampered["credential_id"] = "vc_other"  # 验签失败
        expired = signed(expires_at="2020-01-01T00:00:00Z")  # 已过期
        # holder_* 字段：项级失败（前缀“演示”）
        holder_item = json.loads(json.dumps(good))
        holder_item.update({
            "holder_did": "did:web:holder.example",
            "holder_key_version": 1,
            "holder_proof": "x",
        })
        # 项内含 source_tenant_id：项级多余字段（前缀“请求”）
        source_item = dict(req(good))
        source_item["source_tenant_id"] = "source-tenant"
        not_obj = "not-an-object"  # 项级请求错误
        batch = [
            req(good),
            req(bad_field),
            bad_challenge,
            req(unknown),
            req(fmt_bad_proof),
            req(tampered),
            req(expired),
            req(holder_item),
            source_item,
            not_obj,
            req(good),
        ]
        st, r = verify({"presentations": batch}, headers=T1)
        ok = st == 200 and set(r) == {"results"} and len(r["results"]) == 11
        results = r.get("results", [])
        check("混合批次长度与输入一致且不含顶层 reason", ok)
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
        check("混合批次 holder_* 项 -> 演示",
              ok and results[7].get("valid") is False
              and results[7].get("reason", "").startswith("演示"))
        check("混合批次 source_tenant_id 项 -> 请求",
              ok and results[8].get("valid") is False
              and results[8].get("reason", "").startswith("请求"))
        check("混合批次非对象项 -> 请求",
              ok and results[9].get("valid") is False
              and results[9].get("reason", "").startswith("请求"))
        check("混合批次失败不短路（末项仍成功）",
              ok and results[10] == {"valid": True})
        check("成功项恰为 valid 单字段",
              ok and all(set(item) == {"valid"}
                         for item in results if item.get("valid") is True))
        check("失败项恰为 valid+reason 两字段",
              ok and all(
                  set(item) == {"valid", "reason"} and item["reason"]
                  for item in results if item.get("valid") is False))

        # 5. 只读：不登记凭证/演示、不写状态、不记审计
        st, _ = _http(
            "GET",
            f"{base}/v1/credentials/vc_external_presentation_batch_1",
            headers=T1)
        check("批量验签后凭证仍未登记（GET 404）", st == 404)
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
        t2_pres = make_presentation()
        t2_pres["proof"] = crypto.sign(
            {k: v for k, v in t2_pres.items() if k != "proof"}, priv1)
        st, r = verify({"presentations": [req(t2_pres)]}, headers=T2)
        check("T2 按自己的锚点批量验签成功",
              st == 200 and r == {"results": [{"valid": True}]})

        # 7. 单项与本地接口不受影响
        st, r = _http("POST", f"{base}/v1/trust/presentations/verify",
                      req(good), headers=T1)
        check("单项未绑定接口仍正常", st == 200 and r == {"valid": True})

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
        T1 = {"X-Tenant-ID": "tpvb-a"}
        p2 = make_presentation()
        p2["proof"] = crypto.sign(
            {k: v for k, v in p2.items() if k != "proof"}, priv2)
        st, r = _http("POST", f"{base}{path}",
                      {"presentations": [{"presentation": p2,
                                          "challenge": "chal-1"}]},
                      headers=T1)
        check("重启后批量验签结论稳定",
              st == 200 and r == {"results": [{"valid": True}]})
        st, _ = _http(
            "GET",
            f"{base}/v1/credentials/vc_external_presentation_batch_1",
            headers=T1)
        check("重启后凭证仍未登记", st == 404)
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
