#!/usr/bin/env python3
"""信任锚点注册表的端到端测试。

直接运行：python3 tests/trust_anchor_test.py
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
    port = 8947
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

        T1 = {"X-Tenant-ID": "anchor-a"}
        T2 = {"X-Tenant-ID": "anchor-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:example.com:issuer"

        # 0. 租户头：缺省 default；显式空串 400
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "did:x:y", "public_key": pub1, "key_version": 9},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # 1. 注册 201 与精确返回体
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册锚点 201", st == 201)
        check("201 返回体字段精确",
              r == {"did": did, "public_key": pub1, "key_version": 1,
                    "status": "active", "updated_at": None})

        # 2. 同 DID/版本同 PEM 幂等 200
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("同 DID/版本同 PEM -> 200", st == 200)
        check("200 返回体一致",
              r == {"did": did, "public_key": pub1, "key_version": 1,
                    "status": "active", "updated_at": None})

        # 3. 同 DID/版本不同 PEM -> 409
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 1},
                      headers=T1)
        check("同 DID/版本不同 PEM -> 409", st == 409)
        check("409 含 error", isinstance(r.get("error"), str) and r["error"])

        # 4. 字段校验 400
        bad_bodies = [
            {"public_key": pub1, "key_version": 1},            # 缺 did
            {"did": did, "public_key": pub1},                  # 缺 key_version
            {"did": "", "public_key": pub1, "key_version": 1}, # 空 did
            {"did": 123, "public_key": pub1, "key_version": 1},
            {"did": did, "public_key": "not-a-pem", "key_version": 1},
            {"did": did, "public_key": pub1, "key_version": 0},
            {"did": did, "public_key": pub1, "key_version": -3},
            {"did": did, "public_key": pub1, "key_version": True},
            {"did": did, "public_key": pub1, "key_version": 1.5},
            {"did": did, "public_key": pub1, "key_version": "1"},
            {"did": did, "public_key": pub1, "key_version": 1,
             "extra": 1},
        ]
        for body in bad_bodies:
            st, r = _http("POST", f"{base}/v1/trust/anchors", body,
                          headers=T1)
            check(f"非法注册体 400: {list(body)} -> {st}",
                  st == 400 and isinstance(r.get("error"), str))

        # 5. 注册 v2；GET 返回全数组
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub2, "key_version": 2},
                      headers=T1)
        check("注册 v2 -> 201", st == 201)
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        check("GET 已知 DID -> 200 全数组", st == 200 and len(r) == 2)
        check("数组按版本升序",
              [a["key_version"] for a in r] == [1, 2])
        check("数组元素字段完整",
              all(set(a) == {"did", "public_key", "key_version",
                             "status", "updated_at"} for a in r))
        st, _ = _http("GET", f"{base}/v1/trust/anchors/did:web:unknown",
                      headers=T1)
        check("GET 未知 DID -> 404", st == 404)

        # 6. 吊销
        st, r = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("首次吊销 -> 200", st == 200 and r["status"] == "revoked")
        ts1 = r["updated_at"]
        check("updated_at 为 UTC 秒精度 Z 时间",
              isinstance(ts1, str) and ts1.endswith("Z") and len(ts1) == 20)
        time.sleep(1.1)
        st, r = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("重复吊销 -> 200 且 updated_at 不变",
              st == 200 and r["updated_at"] == ts1)

        # 吊销请求体/路径校验
        for body in [{}, {"status": "active"}, {"status": "revoked", "x": 1}]:
            st, _ = _http("PUT",
                          f"{base}/v1/trust/anchors/{did}/2/status",
                          body, headers=T1)
            check(f"非法吊销体 400: {body}", st == 400)
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/9/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销未知版本 -> 404", st == 404)
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/0/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销路径版本 0 -> 400", st == 400)
        # v2 仍 active
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        v1 = next(a for a in r if a["key_version"] == 1)
        v2 = next(a for a in r if a["key_version"] == 2)
        check("v1 已吊销 / v2 仍 active",
              v1["status"] == "revoked" and v2["status"] == "active"
              and v2["updated_at"] is None)

        # 7. verify：签名覆盖去掉 signature 的整个请求对象
        message = {"issuer_did": did, "issuer_key_version": 2,
                   "doc": {"hello": "世界", "n": [1, 2, 3]}}
        sig = crypto.sign(message, priv2)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": sig}, headers=T1)
        check("active 锚点验签成功", st == 200 and r == {"valid": True})

        # 篡改负载 -> 失败
        bad = dict(message)
        bad["doc"] = {"hello": "篡改", "n": [1, 2, 3]}
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**bad, "signature": sig}, headers=T1)
        check("负载被改 -> valid:false 带原因",
              st == 200 and r.get("valid") is False
              and isinstance(r.get("reason"), str) and r["reason"])

        # 坏签名编码
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": "!!!not-b64!!!"}, headers=T1)
        check("签名编码非法 -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 空签名
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": ""}, headers=T1)
        check("空 signature -> valid:false",
              st == 200 and r.get("valid") is False)

        # 缺字段 / 类型非法
        for body in [
            {},
            {"issuer_key_version": 2, "signature": sig},
            {"issuer_did": did, "signature": sig},
            {"issuer_did": did, "issuer_key_version": 2},
            {"issuer_did": "", "issuer_key_version": 2, "signature": sig},
            {"issuer_did": did, "issuer_key_version": "2", "signature": sig},
            {"issuer_did": did, "issuer_key_version": True, "signature": sig},
            {"issuer_did": did, "issuer_key_version": 0, "signature": sig},
        ]:
            st, r = _http("POST", f"{base}/v1/trust/verify", body,
                          headers=T1)
            check(f"verify 非法请求 200/valid:false: {list(body)}",
                  st == 200 and r.get("valid") is False
                  and isinstance(r.get("reason"), str) and r["reason"])
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      raw=b"not-json", headers=T1)
        check("verify 非法 JSON -> 200/valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 未知锚点
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {"issuer_did": "did:web: nobody",
                       "issuer_key_version": 2, "signature": sig},
                      headers=T1)
        check("未知锚点 -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))

        # 已吊销 v1：即便签名正确也失败
        sig1 = crypto.sign(message, priv1)
        msg1 = dict(message, issuer_key_version=1)
        sig1 = crypto.sign(msg1, priv1)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**msg1, "signature": sig1}, headers=T1)
        check("吊销锚点验签 -> valid:false",
              st == 200 and r.get("valid") is False and "吊销" in r.get("reason", ""))

        # 8. 租户隔离：T2 同 DID 注册不同 PEM，互不影响
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T2)
        check("跨租户同 DID 可独立注册 201", st == 201)
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T2)
        check("T2 仅见自己的锚点数组",
              st == 200 and len(r) == 1 and r[0]["key_version"] == 1
              and r[0]["status"] == "active")
        st, _ = _http("GET", f"{base}/v1/trust/anchors/did:web:other",
                      headers=T2)
        check("T2 未见 T1 独有 DID -> 404", st == 404)
        # T2 的 v1 是 pub1（未吊销）：用 priv1 签名在 T2 验签成功
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**msg1, "signature": sig1}, headers=T2)
        check("跨租户 active 锚点验签成功", st == 200 and r == {"valid": True})
        # T1 查 T2 独有 DID -> 404（T1 无 v? 实际 did 相同，换一个）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": "did:web:t2-only", "public_key": pub2,
                       "key_version": 1}, headers=T2)
        st, _ = _http("GET", f"{base}/v1/trust/anchors/did:web:t2-only",
                      headers=T1)
        check("T1 访问 T2 独有 DID -> 404", st == 404)

        # 9. 审计
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        events = r["events"]
        registered = [e for e in events
                      if e["action"] == "trust.anchor.registered"]
        revoked = [e for e in events
                   if e["action"] == "trust.anchor.revoked"]
        # v1 注册 + 1 次幂等重试；v2 注册 1 次；409 不记 => 3
        check("registered 审计 = 注册 2 + 幂等 1（409 不记）",
              len(registered) == 3)
        check("revoked 审计 = 首次 + 重试 = 2", len(revoked) == 2)
        check("审计 resource_type/resource_id",
              all(e["resource_type"] == "trust_anchor"
                  and e["resource_id"] == f"{did}#1" for e in revoked))
        check("registered 资源含版本号",
              sorted(e["resource_id"] for e in registered)
              == [f"{did}#1", f"{did}#1", f"{did}#2"])
        check("审计事件字段完整且 seq 连续",
              all(set(e) == {"seq", "timestamp", "tenant_id", "action",
                             "resource_type", "resource_id"}
                  for e in registered + revoked)
              and isinstance(events[0]["seq"], int)
              and all(isinstance(e["timestamp"], int) for e in events))
        verify_audit = [e for e in events if "trust" in e["action"]
                        and e["action"] not in
                        ("trust.anchor.registered", "trust.anchor.revoked")]
        check("验签不记审计", not verify_audit)
        # seq 全局连续（跨租户）：取两个租户页内的全局最大 seq
        st, page2 = _http("GET", f"{base}/v1/audit?limit=200", headers=T2)
        all_seqs = [e["seq"] for e in r["events"]] + [
            e["seq"] for e in page2["events"]
        ]
        max_seq = max(all_seqs)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 10. 跨重启持久化
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "anchor-a"}
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        check("重启后锚点保留", st == 200 and len(r) == 2)
        v1 = next(a for a in r if a["key_version"] == 1)
        check("重启后吊销状态与 updated_at 保留",
              v1["status"] == "revoked" and v1["updated_at"] == ts1)
        # 吊销后 v1 验签仍失败；v2 仍成功
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**msg1, "signature": sig1}, headers=T1)
        check("重启后吊销仍生效", r.get("valid") is False)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**message, "signature": sig}, headers=T1)
        check("重启后 active 锚点仍可验签", r == {"valid": True})
        # 再注册一个锚点，确认 seq 跨重启接续
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 3},
                      headers=T1)
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        new_events = [e for e in r["events"] if e["seq"] > max_seq]
        check("seq 跨重启接续",
              any(e["action"] == "trust.anchor.registered"
                  and e["resource_id"] == f"{did}#3" for e in new_events)
              and min(e["seq"] for e in new_events) == max_seq + 1)
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
