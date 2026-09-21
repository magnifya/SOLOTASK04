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

    def batch(items, headers=None):
        return _http("POST", f"{base}{path}",
                     {"credentials": items}, headers=headers)

    def batch_raw(payload=None, raw=None, headers=None):
        return _http("POST", f"{base}{path}", payload=payload,
                     raw=raw, headers=headers)

    def reason_prefix(reason):
        # 单项实现的 reason 为前缀式分类（如“请求缺少字段: …”无分隔符），
        # 按已知类别前缀归类，长类别优先以免“签名”互相遮蔽。
        for category in ("签名格式错误", "签名校验失败", "锚点", "凭证", "请求"):
            if reason.startswith(category):
                return category
        return reason

    def envelope_invalid(name, payload=None, raw=None, headers=None):
        st, r = batch_raw(payload=payload, raw=raw, headers=headers)
        check(
            name,
            st == 200
            and r.get("results") == []
            and isinstance(r.get("reason"), str)
            and r["reason"].startswith("请求"),
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "tcb-a"}
        T2 = {"X-Tenant-ID": "tcb-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        _, pub_other = gen_keypair()
        did = "did:web:batch-external.example"

        # 显式空租户头仍按通用协议 400（在进入批量流程前判定）
        st, _ = batch_raw({"credentials": [{"body": {}, "signature": "x"}]},
                          headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册批量外部锚点 v1 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册批量外部锚点 v2 -> 201", st == 201)

        def make_body(credential_id="vc_batch_0001", version=1, extra=None,
                      issuer=did):
            body = {
                "credential_id": credential_id,
                "issuer_did": issuer,
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

        body_v2 = make_body(version=2)
        sig_v2 = crypto.sign(body_v2, priv2)
        body_v1 = make_body(version=None, credential_id="vc_batch_0002")
        sig_v1 = crypto.sign(body_v1, priv1)
        body_ext = make_body(version=2, credential_id="vc_batch_0003",
                             extra={"ext_a": "x", "ext_b": [1, 2]})
        sig_ext = crypto.sign(body_ext, priv2)

        # 1. 全成功批次：v2、省略版本按 v1、扩展字段，结果同序全 valid
        st, r = batch([
            {"body": body_v2, "signature": sig_v2},
            {"body": body_v1, "signature": sig_v1},
            {"body": body_ext, "signature": sig_ext},
        ], headers=T1)
        check("全成功批次",
              st == 200 and r == {"results": [
                  {"valid": True}, {"valid": True}, {"valid": True}]})

        # 2. 单项兼容：同样三项走单项端点结果一致
        single = []
        for item in (
            {"body": body_v2, "signature": sig_v2},
            {"body": body_v1, "signature": sig_v1},
            {"body": body_ext, "signature": sig_ext},
        ):
            st, r1 = _http("POST",
                           f"{base}/v1/trust/credentials/verify",
                           item, headers=T1)
            single.append((st, r1))
        check("单项端点对同样输入均成功",
              all(st == 200 and r1 == {"valid": True} for st, r1 in single))

        # 3. 省略版本时服务端不得注入签名正文
        injected = dict(body_v1, issuer_key_version=1)
        sig_injected = crypto.sign(injected, priv1)
        st, r = batch(
            [{"body": body_v1, "signature": sig_injected}], headers=T1
        )
        check("省略版本时注入版签名不能通过",
              st == 200 and len(r["results"]) == 1
              and r["results"][0].get("valid") is False
              and r["results"][0]["reason"].startswith("签名校验失败"))

        # 4. 混合批次：成功/签名失败/请求/凭证/锚点/签名格式，顺序固定、
        #    长度与输入一致、失败不短路（首项失败后各项仍各自给出结果）
        tampered = json.loads(json.dumps(body_ext))
        tampered["ext_a"] = "y"
        body_unknown = make_body(credential_id="vc_batch_0004", version=2,
                                 issuer="did:web:unknown.example")
        sig_unknown = crypto.sign(body_unknown, priv2)
        mixed_items = [
            {"body": body_v2, "signature": sig_v2},          # 0 成功
            {"body": body_v2, "signature": "!!!bad!!!"},     # 1 签名格式
            {"body": body_v2},                               # 2 请求（缺 signature）
            {"body": {"credential_id": "x"},
             "signature": sig_v2},                           # 3 凭证字段
            {"body": body_unknown, "signature": sig_unknown},  # 4 锚点
            {"body": tampered, "signature": sig_ext},        # 5 签名校验
            "not-an-object",                                 # 6 请求（项非对象）
            ["body", "signature"],                           # 7 请求（项非对象）
            None,                                            # 8 请求（项为 null）
        ]
        st, r = batch(mixed_items, headers=T1)
        expected_valid = [True, False, False, False, False,
                          False, False, False, False]
        expected_prefixes = [
            None, "签名格式错误", "请求", "凭证", "锚点",
            "签名校验失败", "请求", "请求", "请求",
        ]
        got_valid = [x.get("valid") for x in r.get("results", [])]
        got_prefixes = [
            None if x.get("valid") else reason_prefix(x["reason"])
            for x in r.get("results", [])
        ]
        check("混合批次 HTTP 200 且长度同输入",
              st == 200 and len(r.get("results", [])) == len(mixed_items))
        check("混合批次 valid 序列", got_valid == expected_valid)
        check("混合批次 reason 分类与顺序", got_prefixes == expected_prefixes)
        check("失败项均无非空以外字段",
              all(set(x) == {"valid"} or
                  (set(x) == {"valid", "reason"}
                   and isinstance(x["reason"], str) and x["reason"])
                  for x in r.get("results", [])))

        # 5. 信封层非法：统一 200 + {"results": [], "reason": "请求…"}
        envelope_invalid("空请求体", raw=b"")
        envelope_invalid("非法 JSON", raw=b"not-json")
        envelope_invalid("UTF-8 非法", raw=b"\xff\xfe")
        envelope_invalid("顶层数组", raw=b"[1,2]")
        envelope_invalid("顶层字符串", raw=b'"x"')
        envelope_invalid("顶层数字", raw=b"123")
        envelope_invalid("顶层 null", raw=b"null")
        envelope_invalid("顶层 true", raw=b"true")
        envelope_invalid("空对象", {})
        envelope_invalid("缺 credentials", {"items": []})
        envelope_invalid("多余字段", {"credentials": [], "extra": 1})
        envelope_invalid("两个多余字段",
                         {"credentials": [], "a": 1, "b": 2})
        envelope_invalid("credentials 为空数组", {"credentials": []})
        envelope_invalid("credentials 为对象",
                         {"credentials": {"body": {}, "signature": "x"}})
        envelope_invalid("credentials 为字符串", {"credentials": "x"})
        envelope_invalid("credentials 为数字", {"credentials": 1})
        envelope_invalid("credentials 为 null", {"credentials": None})

        # 6. 上限：100 项受理（长度 100），101 项信封非法
        st, r = batch(
            [{"body": body_v2, "signature": sig_v2}] * 100, headers=T1
        )
        check("恰好 100 项受理",
              st == 200 and len(r.get("results", [])) == 100
              and all(x.get("valid") for x in r["results"]))
        envelope_invalid("101 项超过上限",
                         {"credentials":
                          [{"body": body_v2, "signature": sig_v2}] * 101})

        # 7. 项级请求错误仍逐项返回（不升级为信封错误），全部前缀"请求"
        st, r = batch([
            [],                                  # 数组
            "x",                                 # 字符串
            123,                                 # 数字
            None,                                # null
            {},                                  # 空对象
            {"body": body_v2},                   # 缺 signature
            {"signature": sig_v2},               # 缺 body
            {"body": body_v2, "signature": sig_v2, "extra": 1},  # 多余
            {"body": [], "signature": sig_v2},   # body 非对象
            {"body": body_v2, "signature": ""},  # signature 空串
            {"body": body_v2, "signature": 1},   # signature 非字符串
        ], headers=T1)
        check("项级请求错误逐项归类",
              st == 200 and len(r["results"]) == 11
              and all(x["valid"] is False
                      and reason_prefix(x["reason"]) == "请求"
                      for x in r["results"]))

        # 8. 凭证字段错误逐项前缀"凭证"
        bad_cred_items = []
        for field in ("credential_id", "issuer_did", "subject_did",
                      "claims", "issued_at"):
            b = json.loads(json.dumps(body_v2))
            b.pop(field)
            bad_cred_items.append({"body": b, "signature": sig_v2})
        for bad_version in (True, 0, -1, 1.5, "1"):
            b = json.loads(json.dumps(body_v2))
            b["issuer_key_version"] = bad_version
            bad_cred_items.append({"body": b, "signature": sig_v2})
        st, r = batch(bad_cred_items, headers=T1)
        check("凭证字段错误逐项归类",
              st == 200 and len(r["results"]) == len(bad_cred_items)
              and all(x["valid"] is False
                      and reason_prefix(x["reason"]) == "凭证"
                      for x in r["results"]))

        # 9. 锚点优先级：吊销锚点 + 坏签名仍返回"锚点"
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 v1 锚点 -> 200", st == 200)
        st, r = batch([
            {"body": body_v1, "signature": "!!!bad!!!"},
            {"body": body_v1, "signature": sig_v1},
        ], headers=T1)
        check("吊销锚点优先于签名格式",
              st == 200
              and all(reason_prefix(x["reason"]) == "锚点"
                      for x in r["results"]))
        # v2 仍 active，同批次中一项锚点失败一项成功互不影响
        st, r = batch([
            {"body": body_v1, "signature": sig_v1},
            {"body": body_v2, "signature": sig_v2},
        ], headers=T1)
        check("吊销 v1 失败而 v2 成功",
              st == 200
              and reason_prefix(r["results"][0]["reason"]) == "锚点"
              and r["results"][1] == {"valid": True})

        # 10. 只读：不登记凭证、不写状态、不记审计（含大量失败项）
        st, _ = _http("GET", f"{base}/v1/credentials/vc_batch_0001",
                      headers=T1)
        check("批量验签后凭证未登记（GET 404）", st == 404)
        st, before = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        n_before = len(before["events"])
        for _ in range(3):
            batch(mixed_items, headers=T1)
            batch_raw({"credentials": []}, headers=T1)
        st, after = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        check("批量验签（含失败与信封错误）不记审计",
              len(after["events"]) == n_before)
        st, _ = _http("GET", f"{base}/v1/credentials/vc_batch_0001",
                      headers=T1)
        check("多次批量验签后凭证仍未登记", st == 404)

        # 11. 跨租户锚点隔离
        st, r = batch(
            [{"body": body_v2, "signature": sig_v2}], headers=T2
        )
        check("T2 无锚点 -> 锚点不存在",
              st == 200 and r["results"][0]["valid"] is False
              and reason_prefix(r["results"][0]["reason"]) == "锚点")
        # T2 注册同 DID v2 为 pub1：priv1 签的名在 T2 成功、T1 失败
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 2},
                      headers=T2)
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        sig_t2 = crypto.sign(body_v2, priv1)
        st, r = batch(
            [{"body": body_v2, "signature": sig_t2},
             {"body": body_v2, "signature": sig_v2}],
            headers=T2,
        )
        check("T2 按自己的锚点逐项验签",
              st == 200 and r["results"][0] == {"valid": True}
              and r["results"][1]["valid"] is False
              and reason_prefix(r["results"][1]["reason"])
              == "签名校验失败")
        st, r = batch(
            [{"body": body_v2, "signature": sig_t2}], headers=T1
        )
        check("同一签名在 T1 公钥不匹配 -> 失败",
              st == 200 and r["results"][0]["valid"] is False
              and reason_prefix(r["results"][0]["reason"])
              == "签名校验失败")

        # 12. 缺省租户头为 default，与命名租户隔离
        st, r = batch(
            [{"body": body_v2, "signature": sig_v2}]
        )
        check("缺省租户 default 无锚点 -> 锚点失败",
              st == 200 and r["results"][0]["valid"] is False
              and reason_prefix(r["results"][0]["reason"]) == "锚点")

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 13. 跨重启：锚点与吊销状态持久化，批量行为不变
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "tcb-a"}
        st, r = batch(
            [{"body": body_v2, "signature": sig_v2},
             {"body": body_v1, "signature": sig_v1}],
            headers=T1,
        )
        check("重启后 v2 成功、吊销 v1 仍锚点失败",
              st == 200 and r["results"][0] == {"valid": True}
              and r["results"][1]["valid"] is False
              and reason_prefix(r["results"][1]["reason"]) == "锚点")
        st, _ = _http("GET", f"{base}/v1/credentials/vc_batch_0001",
                      headers=T1)
        check("重启后凭证仍未登记（只读）", st == 404)
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
