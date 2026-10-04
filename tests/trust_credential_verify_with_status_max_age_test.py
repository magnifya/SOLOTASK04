#!/usr/bin/env python3
"""外部凭证验真合并状态的可选状态时效限制（max_status_age）。

覆盖 POST /v1/trust/credentials/verify-with-status 与
POST /v1/trust/credentials/verify-batch-with-status：
- 最外层 max_status_age 仅接受 0..86400 非布尔整数；显式 null、布尔、
  其他类型、越界值均非法，且先于凭证校验返回（单条 valid=false、
  批量 results=[]，reason 均为“状态时效参数非法”）；
- 启用后先完成既有验真（字段/锚点/签名/有效期/外部 DID 停用）并保留
  其失败原因，再合并同步状态；未同步、revoked、suspended、unknown
  结论不因陈旧或超前改变；仅 active 按签发方声明的 updated_at 计算
  年龄：负值“外部凭证状态时间超前”、超过上限“外部凭证状态已过期”、
  零到上限（含边界）有效；
- 批量参数统一生效，凭证项保持原协议（逐项携带按多余字段拒绝）；
- 省略参数时两入口保持既有行为；只读，不写状态/历史/审计；重启后按
  持久化 updated_at 与新的判定时刻计算。

直接运行：python3 tests/trust_credential_verify_with_status_max_age_test.py
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


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def fresh_second_start():
    """等到某一秒的前 300ms 内，保证随后不到 1s 的操作与服务端取整秒
    落在同一整数秒，便于构造精确的状态年龄边界。"""
    while True:
        now = datetime.now(timezone.utc)
        if now.microsecond < 300_000:
            return now
        time.sleep(0.02)


def main():
    port = 8971
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    single = "/v1/trust/credentials/verify-with-status"
    batch = "/v1/trust/credentials/verify-batch-with-status"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port), "服务启动超时"
        T1 = {"X-Tenant-ID": "tma-a"}
        T2 = {"X-Tenant-ID": "tma-b"}

        priv1, pub1 = gen_keypair()
        did = "did:web:ext-ma.example"
        for headers in (T1, T2):
            st, _ = _http("POST", f"{base}/v1/trust/anchors",
                          {"did": did, "public_key": pub1, "key_version": 1},
                          headers=headers)
            check(f"注册锚点({headers['X-Tenant-ID']}) -> 201", st == 201)

        def make_body(cred_id, **extra):
            body = {
                "credential_id": cred_id,
                "issuer_did": did,
                "subject_did": "did:web:subject.example",
                "claims": {"role": "admin"},
                "issued_at": "2026-09-21T00:00:00Z",
                "issuer_key_version": 1,
            }
            body.update(extra)
            return body

        def item(body, priv=priv1, bad_sig=False):
            sig = crypto.sign(body, priv)
            if bad_sig:
                sig = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
            return {"body": body, "signature": sig}

        def call(body, max_age=_OMIT, headers=T1, **kw):
            payload = item(body, **kw)
            if max_age is not _OMIT:
                payload["max_status_age"] = max_age
            return _http("POST", f"{base}{single}", payload, headers=headers)

        def call_batch(items, max_age=_OMIT, headers=T1, **extra):
            payload = {"credentials": items}
            if max_age is not _OMIT:
                payload["max_status_age"] = max_age
            payload.update(extra)
            return _http("POST", f"{base}{batch}", payload, headers=headers)

        def sync(cred_id, status, reason=_OMIT, updated_at=None, headers=T1):
            sb = {
                "issuer_did": did,
                "credential_id": cred_id,
                "status": status,
                "updated_at": updated_at or utc_z(timedelta(days=-1)),
                "issuer_key_version": 1,
            }
            if reason is not _OMIT:
                sb["reason"] = reason
            return _http("POST",
                         f"{base}/v1/trust/credential-status/sync",
                         {"body": sb, "signature": crypto.sign(sb, priv1)},
                         headers=headers)

        # ---- 准备同步状态 ----
        check("同步 fresh active -> 201",
              sync("ma_fresh", "active",
                   updated_at=utc_z(timedelta(seconds=-30)))[0] == 201)
        check("同步 stale active（2 天前）-> 201",
              sync("ma_stale", "active",
                   updated_at=utc_z(timedelta(days=-2)))[0] == 201)
        check("同步 future active（1 小时后）-> 201",
              sync("ma_future", "active",
                   updated_at=utc_z(timedelta(hours=1)))[0] == 201)
        check("同步 stale revoked -> 201",
              sync("ma_rev", "revoked", reason="持证人违规",
                   updated_at=utc_z(timedelta(days=-2)))[0] == 201)
        check("同步 stale suspended -> 201",
              sync("ma_sus", "suspended", reason="风险核查",
                   updated_at=utc_z(timedelta(days=-2)))[0] == 201)
        check("同步 stale unknown -> 201",
              sync("ma_unk", "unknown",
                   updated_at=utc_z(timedelta(days=-2)))[0] == 201)

        # ---- 参数校验（先于凭证校验）----
        for bad in (None, "10", 3.5, True, -1, 86401, [1], {"x": 1}):
            st, r = call(make_body("ma_fresh"), max_age=bad)
            check(f"单条 max_status_age={bad!r} 非法",
                  st == 200 and r == {"valid": False,
                                      "reason": "状态时效参数非法"})
        # 参数非法先于凭证校验：body 缺字段也返回参数错误
        st, r = _http("POST", f"{base}{single}",
                      {"body": {}, "signature": "", "max_status_age": "x"},
                      headers=T1)
        check("参数非法先于凭证字段校验",
              st == 200 and r == {"valid": False,
                                  "reason": "状态时效参数非法"})
        st, r = call_batch([item(make_body("ma_fresh"))], max_age="10")
        check("批量 max_status_age 字符串非法 -> results=[]",
              st == 200 and r == {"results": [],
                                  "reason": "状态时效参数非法"})
        st, r = call_batch([item(make_body("ma_fresh"))], max_age=None)
        check("批量 max_status_age 显式 null 非法",
              st == 200 and r == {"results": [],
                                  "reason": "状态时效参数非法"})
        st, r = call_batch([item(make_body("ma_fresh"))], max_age=86401)
        check("批量 max_status_age 越界非法",
              st == 200 and r == {"results": [],
                                  "reason": "状态时效参数非法"})
        # 合法参数 + 其他多余外层字段仍按请求错误
        st, r = _http("POST", f"{base}{single}",
                      dict(item(make_body("ma_fresh")),
                           max_status_age=10, foo=1), headers=T1)
        check("单条合法参数+多余字段 -> 请求含多余字段",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("请求含多余字段"))
        st, r = call_batch([item(make_body("ma_fresh"))], max_age=10, foo=1)
        check("批量合法参数+多余字段 -> 请求含多余字段",
              st == 200 and r.get("results") == []
              and r.get("reason", "").startswith("请求含多余字段"))

        # ---- 省略参数保持既有行为 ----
        st, r = call(make_body("ma_stale"))
        check("省略参数：陈旧 active 仍 valid:true",
              st == 200 and r == {"valid": True})
        st, r = call_batch([item(make_body("ma_stale"))])
        check("批量省略参数：陈旧 active 仍 valid:true",
              st == 200 and r == {"results": [{"valid": True}]})

        # ---- 启用限制：active 时效判定 ----
        st, r = call(make_body("ma_fresh"), max_age=86400)
        check("active 新鲜（30s）上限 86400 -> valid:true",
              st == 200 and r == {"valid": True})
        st, r = call(make_body("ma_fresh"), max_age=0)
        check("active 30s 前 + 上限 0 -> 已过期",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态已过期"})
        st, r = call(make_body("ma_stale"), max_age=86400)
        check("active 2 天前 + 上限 86400 -> 已过期（不用接收时间刷新）",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态已过期"})
        st, r = call(make_body("ma_future"), max_age=86400)
        check("active updated_at 超前 -> 时间超前",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态时间超前"})
        st, r = call(make_body("ma_future"), max_age=0)
        check("超前优先于过期上限（上限 0 仍判超前）",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态时间超前"})

        # 边界含端点：年龄恰等于上限有效，超一秒过期
        now = fresh_second_start()
        bound_at = (now - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        check("同步边界 active（恰 5 秒前）-> 201",
              sync("ma_bound", "active", updated_at=bound_at)[0] == 201)
        st, r = call(make_body("ma_bound"), max_age=5)
        check("年龄==上限（5s/5）-> valid:true",
              st == 200 and r == {"valid": True})
        st, r = call(make_body("ma_bound"), max_age=4)
        check("年龄>上限（5s/4）-> 已过期",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态已过期"})

        # ---- 非 active 状态不查时效 ----
        st, r = call(make_body("ma_rev"), max_age=0)
        check("revoked 陈旧仍返回吊销原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：持证人违规"})
        st, r = call(make_body("ma_sus"), max_age=0)
        check("suspended 陈旧仍返回暂停原因",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已暂停：风险核查"})
        st, r = call(make_body("ma_unk"), max_age=0)
        check("unknown 陈旧仍返回状态未知",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未知"})
        check("同步 future revoked -> 201",
              sync("ma_rev_fut", "revoked", reason="密钥泄露",
                   updated_at=utc_z(timedelta(hours=1)))[0] == 201)
        st, r = call(make_body("ma_rev_fut"), max_age=0)
        check("revoked 超前仍返回吊销原因（不判超前）",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证已吊销：密钥泄露"})

        # ---- 未同步与既有验真失败原因保留 ----
        st, r = call(make_body("ma_nosync"), max_age=10)
        check("未同步 + 限制 -> 未同步",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未同步"})
        st, r = call(make_body("ma_fresh"), max_age=10, bad_sig=True)
        check("签名失败优先于时效判定",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("签名校验失败"))
        st, r = call(make_body("ma_fresh",
                               expires_at=utc_z(timedelta(hours=-1))),
                     max_age=86400)
        check("凭证过期优先于状态时效",
              st == 200 and r == {"valid": False, "reason": "凭证已过期"})
        st, r = call(make_body("ma_fresh"), max_age=10, headers=T2)
        check("他租户同步状态视为未同步",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态未同步"})
        st, _ = _http("POST", f"{base}{single}",
                      dict(item(make_body("ma_fresh")), max_status_age=10),
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

        # ---- 批量：统一生效、等长同序、失败不短路 ----
        items = [
            item(make_body("ma_fresh")),                 # valid
            item(make_body("ma_stale")),                 # 已过期
            item(make_body("ma_future")),                # 超前
            item(make_body("ma_rev")),                   # 吊销原因
            item(make_body("ma_unk")),                   # 状态未知
            item(make_body("ma_nosync")),                # 未同步
            item(make_body("ma_fresh"), bad_sig=True),   # 签名校验失败
        ]
        st, r = call_batch(items, max_age=86400)
        check("批量限制：等长同序、失败不短路",
              st == 200 and r.get("results") == [
                  {"valid": True},
                  {"valid": False, "reason": "外部凭证状态已过期"},
                  {"valid": False, "reason": "外部凭证状态时间超前"},
                  {"valid": False, "reason": "外部凭证已吊销：持证人违规"},
                  {"valid": False, "reason": "外部凭证状态未知"},
                  {"valid": False, "reason": "外部凭证状态未同步"},
                  r["results"][6],
              ] and r["results"][6].get("valid") is False
              and r["results"][6].get("reason", "").startswith("签名校验失败"))
        # 凭证项保持原协议：逐项携带 max_status_age 按多余字段拒绝
        st, r = call_batch([dict(item(make_body("ma_fresh")),
                                 max_status_age=10)], max_age=86400)
        check("批量逐项覆盖被拒绝（多余字段）",
              st == 200 and len(r.get("results", [])) == 1
              and r["results"][0].get("valid") is False
              and r["results"][0].get("reason", "").startswith("请求含多余字段"))
        st, r = call_batch([item(make_body("ma_fresh"))], max_age=0)
        check("批量上限 0：30s 前 active -> 已过期",
              st == 200 and r == {"results": [
                  {"valid": False, "reason": "外部凭证状态已过期"}]})

        # ---- 只读：不新增审计、同步记录不变 ----
        _, before = _http("GET", f"{base}/v1/audit?limit=500&after=0",
                          headers=T1)
        call(make_body("ma_fresh"), max_age=10)
        call(make_body("ma_stale"), max_age=10)
        call_batch(items, max_age=10)
        _, after = _http("GET", f"{base}/v1/audit?limit=500&after=0",
                         headers=T1)
        check("只读：不新增审计",
              len(before.get("events", [])) == len(after.get("events", [])))
        st, r = _http(
            "GET",
            f"{base}/v1/trust/credential-status/ma_stale?issuer_did={did}",
            headers=T1)
        check("同步记录保持持久化 updated_at 不变",
              st == 200 and r.get("status") == "active"
              and r.get("updated_at", "") < utc_z(timedelta(days=-1)))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 重启持久化：同一状态文件新起服务，按持久化 updated_at 与新的判定
    # 时刻重新计算年龄。
    port2 = port + 100
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port2), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base2 = f"http://127.0.0.1:{port2}"
    T1 = {"X-Tenant-ID": "tma-a"}
    try:
        assert wait_up(port2), "重启服务启动超时"
        body = {
            "credential_id": "ma_stale",
            "issuer_did": did,
            "subject_did": "did:web:subject.example",
            "claims": {"role": "admin"},
            "issued_at": "2026-09-21T00:00:00Z",
            "issuer_key_version": 1,
        }
        sig = crypto.sign(body, priv1)
        st, r = _http("POST", f"{base2}{single}",
                      {"body": body, "signature": sig,
                       "max_status_age": 86400}, headers=T1)
        check("重启后按持久化 updated_at 判已过期",
              st == 200 and r == {"valid": False,
                                  "reason": "外部凭证状态已过期"})
        st, r = _http("POST", f"{base2}{single}",
                      {"body": body, "signature": sig}, headers=T1)
        check("重启后省略参数仍 valid:true",
              st == 200 and r == {"valid": True})
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        sys.exit(1)
    print("全部通过")


_OMIT = object()


if __name__ == "__main__":
    main()
