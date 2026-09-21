#!/usr/bin/env python3
"""批量外部凭证验真 POST /v1/trust/credentials/verify-batch 的端到端测试。

直接运行：python3 tests/trust_credential_verify_batch_test.py
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
    port = 8954
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    path = "/v1/trust/credentials/verify-batch"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def verify_batch(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{path}", payload,
                     headers=headers, raw=raw)

    def request_invalid(name, payload=None, raw=None, headers=None):
        # 请求级非法：HTTP 200 + {"results": [], "reason": "请求..."}
        st, r = verify_batch(payload=payload, raw=raw, headers=headers)
        check(
            name,
            st == 200
            and r.get("results") == []
            and isinstance(r.get("reason"), str)
            and r["reason"].startswith("请求"),
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tbv-a"}
        T2 = {"X-Tenant-ID": "tbv-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        _, pub_other = gen_keypair()
        did = "did:web:external-batch.example"

        # 显式空租户头仍按通用协议 400（在进入验签前判定）
        st, _ = verify_batch(
            payload={"credentials": [{"body": {}, "signature": "x"}]},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID -> 400", st == 400)

        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册外部锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册外部锚点 v2 -> 201", st == 201)

        def make_body(cred_id="vc_batch_0001", version=2, extra=None,
                      issuer=None):
            body = {
                "credential_id": cred_id,
                "issuer_did": issuer or did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin", "level": 3,
                           "nested": {"city": "北京"}},
                "issued_at": "2026-09-21T00:00:00Z",
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        body2 = make_body(version=2)
        sig2 = crypto.sign(body2, priv2)
        body1 = make_body(version=None, cred_id="vc_batch_0002")
        sig1 = crypto.sign(body1, priv1)
        good_item = {"body": body2, "signature": sig2}
        good_v1_item = {"body": body1, "signature": sig1}

        # 1. 全成功批次：长度与顺序一致
        st, r = verify_batch(
            {"credentials": [good_item, good_v1_item]}, headers=T1
        )
        check(
            "全成功批次",
            st == 200 and r == {"results": [{"valid": True},
                                            {"valid": True}]},
        )

        # 2. 混合结果，顺序校验、失败不短路：
        #    成功 / 请求错误 / 凭证错误 / 锚点错误 / 签名格式 / 签名校验
        body_unknown = make_body(cred_id="vc_batch_x", version=2,
                                 issuer="did:web:unknown.example")
        sig_unknown = crypto.sign(body_unknown, priv2)
        bad_cred_body = dict(body2)
        del bad_cred_body["credential_id"]
        sig_wrong_key = crypto.sign(body2, priv1)
        items = [
            good_item,                                   # 0 成功
            {"body": body2},                             # 1 请求：缺 signature
            "not-an-object",                             # 2 请求：项非对象
            {"body": bad_cred_body, "signature": sig2},  # 3 凭证：缺字段
            {"body": body_unknown, "signature": sig_unknown},  # 4 锚点缺失
            {"body": body2, "signature": "!!!bad!!!"},   # 5 签名格式错误
            {"body": body2, "signature": sig_wrong_key}, # 6 签名校验失败
            {"body": body2, "signature": sig2,
             "extra": 1},                                # 7 请求：多余字段
            good_v1_item,                                # 8 成功（证明不短路）
        ]
        st, r = verify_batch({"credentials": items}, headers=T1)
        results = r.get("results")
        check("混合批次 HTTP 200 且结果长度一致",
              st == 200 and isinstance(results, list)
              and len(results) == len(items))
        check("results[0] 成功", results[0] == {"valid": True})
        check("results[8] 成功（失败不短路）",
              results[8] == {"valid": True})
        for idx, prefix in [
            (1, "请求"), (2, "请求"), (3, "凭证"), (4, "锚点"),
            (5, "签名格式错误"), (6, "签名校验失败"), (7, "请求"),
        ]:
            check(
                f"results[{idx}] 原因为“{prefix}”类",
                results[idx].get("valid") is False
                and isinstance(results[idx].get("reason"), str)
                and results[idx]["reason"].startswith(prefix),
            )
        # 成功项不得带 reason
        check("成功项恰为 {valid:true}",
              set(results[0].keys()) == {"valid"}
              and set(results[8].keys()) == {"valid"})
        # 失败项恰为 valid + reason
        check("失败项恰为 valid:false + reason",
              all(set(results[i].keys()) == {"valid", "reason"}
                  for i in (1, 2, 3, 4, 5, 6, 7)))

        # 3. 省略 issuer_key_version 按 v1；注入版本字段的签名不能通过
        injected = dict(body1, issuer_key_version=1)
        sig_injected = crypto.sign(injected, priv1)
        st, r = verify_batch(
            {"credentials": [
                good_v1_item,
                {"body": body1, "signature": sig_injected},
            ]},
            headers=T1,
        )
        check(
            "省略版本按 v1 成功 / 注入版本签名失败",
            st == 200
            and r["results"][0] == {"valid": True}
            and r["results"][1].get("valid") is False
            and r["results"][1]["reason"].startswith("签名校验失败"),
        )

        # 4. 扩展字段参与签名；篡改即失败
        body_ext = make_body(extra={"ext_a": "x", "ext_b": [1, 2]})
        sig_ext = crypto.sign(body_ext, priv2)
        tampered = dict(body_ext)
        tampered["ext_a"] = "y"
        st, r = verify_batch(
            {"credentials": [
                {"body": body_ext, "signature": sig_ext},
                {"body": tampered, "signature": sig_ext},
            ]},
            headers=T1,
        )
        check(
            "扩展字段参与签名 / 篡改失败",
            st == 200
            and r["results"][0] == {"valid": True}
            and r["results"][1].get("valid") is False
            and r["results"][1]["reason"].startswith("签名校验失败"),
        )

        # 5. 请求级非法 -> 200 + {"results": [], "reason": "请求..."}
        request_invalid("空请求体", raw=b"")
        request_invalid("非法 JSON", raw=b"not-json")
        request_invalid("UTF-8 非法", raw=b"\xff\xfe")
        request_invalid("JSON 数组非对象", raw=b"[1,2]")
        request_invalid("JSON 字符串非对象", raw=b'"x"')
        request_invalid("JSON 数字非对象", raw=b"123")
        request_invalid("JSON null 非对象", raw=b"null")
        request_invalid("JSON true 非对象", raw=b"true")
        request_invalid("空对象", {})
        request_invalid("缺 credentials", {"items": []})
        request_invalid("多余字段",
                        {"credentials": [good_item], "other": 1})
        request_invalid("credentials 为对象",
                        {"credentials": good_item})
        request_invalid("credentials 为字符串",
                        {"credentials": "x"})
        request_invalid("credentials 为 null",
                        {"credentials": None})
        request_invalid("空数组", {"credentials": []})

        # 6. 上限：100 项处理、101 项整批拒绝
        st, r = verify_batch(
            {"credentials": [good_item] * 100}, headers=T1
        )
        check(
            "100 项全部处理",
            st == 200
            and isinstance(r.get("results"), list)
            and len(r["results"]) == 100
            and all(x == {"valid": True} for x in r["results"]),
        )
        request_invalid("101 项超过上限 -> 空 results",
                        {"credentials": [good_item] * 101})

        # 7. 吊销锚点：正确签名也失败，锚点类原因优先于签名格式
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        st, r = verify_batch(
            {"credentials": [
                good_v1_item,
                {"body": body1, "signature": "!!!bad!!!"},
            ]},
            headers=T1,
        )
        check(
            "吊销锚点 -> 锚点失败（含坏签名）",
            st == 200
            and r["results"][0].get("valid") is False
            and r["results"][0]["reason"].startswith("锚点")
            and r["results"][1].get("valid") is False
            and r["results"][1]["reason"].startswith("锚点"),
        )

        # 8. 只读：不登记凭证、不记审计
        st, _ = _http("GET", f"{base}/v1/credentials/vc_batch_0001",
                      headers=T1)
        check("批量验真后凭证仍未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        verify_batch({"credentials": [
            good_item,
            {"body": body_unknown, "signature": sig_unknown},
            {"body": body2, "signature": "bad"},
        ]}, headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("批量验真（含失败）不记审计",
              len(after["events"]) == n_before)

        # 9. 跨租户锚点隔离：T2 无锚点 -> 锚点失败；
        #    T2 注册同 DID 的 v2 为 pub1，priv1 签名在 T2 成功、T1 失败
        st, r = verify_batch({"credentials": [good_item]}, headers=T2)
        check(
            "T2 无锚点 -> 锚点失败",
            st == 200 and r["results"][0].get("valid") is False
            and r["results"][0]["reason"].startswith("锚点"),
        )
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        sig_t2 = crypto.sign(body2, priv1)
        st, r = verify_batch(
            {"credentials": [{"body": body2, "signature": sig_t2}]},
            headers=T2,
        )
        check("T2 按自己的锚点验签成功",
              st == 200 and r["results"][0] == {"valid": True})
        st, r = verify_batch(
            {"credentials": [{"body": body2, "signature": sig_t2}]},
            headers=T1,
        )
        check(
            "同一签名在 T1 公钥不匹配 -> 失败",
            st == 200 and r["results"][0].get("valid") is False
            and r["results"][0]["reason"].startswith("签名校验失败"),
        )

        # 10. 缺省租户 default 与显式 default 行为一致
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers={"X-Tenant-ID": "default"})
        check("default 租户注册锚点 -> 201", st == 201)
        st, r = verify_batch({"credentials": [good_item]})
        check("缺省 X-Tenant-ID 按 default 验签成功",
              st == 200 and r["results"][0] == {"valid": True})

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
