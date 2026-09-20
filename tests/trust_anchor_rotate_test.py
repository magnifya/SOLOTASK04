#!/usr/bin/env python3
"""信任锚点密钥轮换（POST /v1/trust/anchors/{did}/rotate）端到端测试。

直接运行：python3 tests/trust_anchor_rotate_test.py
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


def register(base, tenant, did, pub, version):
    return _http(
        "POST", f"{base}/v1/trust/anchors",
        {"did": did, "public_key": pub, "key_version": version},
        headers=tenant,
    )


def rotate(base, tenant, did, frm, pub):
    return _http(
        "POST", f"{base}/v1/trust/anchors/{did}/rotate",
        {"from_key_version": frm, "public_key": pub},
        headers=tenant,
    )


def main():
    port = 8953
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

        T1 = {"X-Tenant-ID": "rot-a"}
        T2 = {"X-Tenant-ID": "rot-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        priv3, pub3 = gen_keypair()
        priv4, pub4 = gen_keypair()
        did = "did:web:rotate.example"

        # 1. 前置 v1 注册
        st, r = register(base, T1, did, pub1, 1)
        check("注册前置 v1 -> 201", st == 201)

        # 2. 轮换 1 -> 2 成功，返回字段同 GET 元素、200、active
        st, r = rotate(base, T1, did, 1, pub2)
        check("轮换 1->2 -> 200", st == 200)
        check("轮换返回体字段精确",
              r == {"did": did, "public_key": pub2, "key_version": 2,
                    "status": "active", "updated_at": None})

        # GET 后旧版本保留 active、新版本 active
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        check("GET 含两个版本且升序",
              st == 200 and [a["key_version"] for a in r] == [1, 2])
        check("旧版本仍 active",
              all(a["status"] == "active" for a in r))

        # 3. 幂等重试：同前置同 PEM -> 200 原锚点
        st, r = rotate(base, T1, did, 1, pub2)
        check("幂等重试 -> 200", st == 200)
        check("幂等返回原 v2 锚点",
              r == {"did": did, "public_key": pub2, "key_version": 2,
                    "status": "active", "updated_at": None})
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        check("幂等不新增版本", len(r) == 2)

        # 4. 目标吊销后幂等：状态照原样返回（revoked）
        st, rr = _http("PUT",
                       f"{base}/v1/trust/anchors/{did}/2/status",
                       {"status": "revoked"}, headers=T1)
        check("吊销目标 v2 -> 200", st == 200 and rr["status"] == "revoked")
        ts2 = rr["updated_at"]
        st, r = rotate(base, T1, did, 1, pub2)
        check("目标吊销后幂等 -> 200 且状态不变",
              st == 200 and r["key_version"] == 2
              and r["status"] == "revoked" and r["updated_at"] == ts2
              and r["public_key"] == pub2)

        # 5. 前置吊销后幂等：仍 200（即使前置后来被吊销也幂等）
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销前置 v1 -> 200", st == 200)
        st, r = rotate(base, T1, did, 1, pub2)
        check("前置吊销后幂等 -> 200 原锚点",
              st == 200 and r["key_version"] == 2
              and r["status"] == "revoked" and r["updated_at"] == ts2)
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}", headers=T1)
        check("幂等路径始终不新增版本", len(r) == 2)

        # 6. 目标已有不同 PEM -> 409
        did_b = "did:web:rotate-b.example"
        register(base, T1, did_b, pub1, 1)
        rotate(base, T1, did_b, 1, pub2)   # 建立 v2=pub2
        st, r = rotate(base, T1, did_b, 1, pub3)
        check("目标不同 PEM -> 409", st == 409 and isinstance(r.get("error"), str))
        st, arr = _http("GET", f"{base}/v1/trust/anchors/{did_b}", headers=T1)
        check("409 后版本不改动", [a["key_version"] for a in arr] == [1, 2])

        # 7. 同 PEM 但前置不同 -> 409：目标版本由直接注册产生（无 created_from）
        did_c = "did:web:rotate-c.example"
        register(base, T1, did_c, pub1, 1)
        register(base, T1, did_c, pub3, 3)   # 跳号直接注册 v3
        st, r = rotate(base, T1, did_c, 2, pub3)  # 目标 v3 已存在、PEM 同
        check("同 PEM 前置不同 -> 409", st == 409)

        # 8. 前置不存在且目标不存在 -> 404
        st, r = rotate(base, T1, did_c, 5, pub4)
        check("前置不存在 -> 404", st == 404)

        # 9. 前置非最高（目标不存在）-> 400：v1、v3 跳号，from=1 目标 2 不存在
        st, r = rotate(base, T1, did_c, 1, pub2)
        check("前置非最高 -> 400", st == 400)
        st, arr = _http("GET", f"{base}/v1/trust/anchors/{did_c}", headers=T1)
        check("400 后不补建版本",
              [a["key_version"] for a in arr] == [1, 3])

        # 10. 前置为最高但已吊销、目标不存在 -> 400
        did_d = "did:web:rotate-d.example"
        register(base, T1, did_d, pub1, 1)
        rotate(base, T1, did_d, 1, pub2)        # v2 active 最高
        _http("PUT", f"{base}/v1/trust/anchors/{did_d}/2/status",
              {"status": "revoked"}, headers=T1)
        st, r = rotate(base, T1, did_d, 2, pub3)
        check("最高前置已吊销 -> 400", st == 400)
        st, arr = _http("GET", f"{base}/v1/trust/anchors/{did_d}", headers=T1)
        check("吊销前置 400 不新增版本",
              [a["key_version"] for a in arr] == [1, 2])

        # 11. 请求体校验 400
        bad_bodies = [
            {"public_key": pub2},                    # 缺 from_key_version
            {"from_key_version": 1},                 # 缺 public_key
            {},                                      # 全缺
            {"from_key_version": 1, "public_key": pub2, "x": 1},  # 多余
            {"from_key_version": True, "public_key": pub2},
            {"from_key_version": False, "public_key": pub2},
            {"from_key_version": 1.5, "public_key": pub2},
            {"from_key_version": 0, "public_key": pub2},
            {"from_key_version": -2, "public_key": pub2},
            {"from_key_version": "1", "public_key": pub2},
            {"from_key_version": [1], "public_key": pub2},
            {"from_key_version": 1, "public_key": "not-a-pem"},
            {"from_key_version": 1, "public_key": ""},
            {"from_key_version": 1, "public_key": 123},
        ]
        for body in bad_bodies:
            st, r = _http(
                "POST", f"{base}/v1/trust/anchors/{did_b}/rotate",
                body, headers=T1)
            check(f"非法轮换体 400: {list(body)} -> {st}",
                  st == 400 and isinstance(r.get("error"), str))

        # 非法 JSON / 非对象 -> 400
        st, _ = _http("POST", f"{base}/v1/trust/anchors/{did_b}/rotate",
                      raw=b"not-json", headers=T1)
        check("非法 JSON -> 400", st == 400)
        st, _ = _http("POST", f"{base}/v1/trust/anchors/{did_b}/rotate",
                      raw=b"[1,2]", headers=T1)
        check("非对象请求体 -> 400", st == 400)

        # 12. DID 不存在（本租户/他租户）-> 404
        st, _ = rotate(base, T1, "did:web:no-such-anchor", 1, pub2)
        check("未知 DID 轮换 -> 404", st == 404)
        st, _ = rotate(base, T2, did_b, 1, pub2)
        check("跨租户轮换他租户 DID -> 404", st == 404)

        # 13. 链继续轮换：v2 active 最高 -> v3；新旧版本均可验签直至吊销
        did_e = "did:web:rotate-e.example"
        register(base, T1, did_e, pub1, 1)
        st, _ = rotate(base, T1, did_e, 1, pub2)
        check("e: 1->2", st == 200)
        st, r = rotate(base, T1, did_e, 2, pub3)
        check("e: 2->3 连续轮换", st == 200 and r["key_version"] == 3
              and r["status"] == "active")

        def trust_verify(tenant, did_, version, priv):
            msg = {"issuer_did": did_, "issuer_key_version": version,
                   "doc": {"k": "值"}}
            sig = crypto.sign(msg, priv)
            return _http("POST", f"{base}/v1/trust/verify",
                         {**msg, "signature": sig}, headers=tenant)

        # 旧版本（active）仍可验签，新版本可验签
        st, r = trust_verify(T1, did_e, 1, priv1)
        check("旧 active 版本仍可验签", r == {"valid": True})
        st, r = trust_verify(T1, did_e, 2, priv2)
        check("中间版本可验签", r == {"valid": True})
        st, r = trust_verify(T1, did_e, 3, priv3)
        check("新版本可验签", r == {"valid": True})
        # 显式吊销旧版本后旧版本验签失败，新版本不受影响
        _http("PUT", f"{base}/v1/trust/anchors/{did_e}/1/status",
              {"status": "revoked"}, headers=T1)
        st, r = trust_verify(T1, did_e, 1, priv1)
        check("旧版本吊销后验签失败",
              r.get("valid") is False and "吊销" in r.get("reason", ""))
        st, r = trust_verify(T1, did_e, 3, priv3)
        check("旧版本吊销不影响新版本验签", r == {"valid": True})

        # 跨租户验签：T2 无该 DID -> 200/valid:false
        st, r = trust_verify(T2, did_e, 3, priv3)
        check("跨租户验签 -> 200/valid:false",
              st == 200 and r.get("valid") is False)

        # 14. 审计：新建与幂等均记 trust.anchor.rotated；冲突/校验失败不记
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        events = r["events"]
        rotated = [e for e in events
                   if e["action"] == "trust.anchor.rotated"]
        # did: 1 新建（步骤2）+ 3 次幂等（步骤3/4/5）；b: 1 新建 +
        # 409 不记；c: 无成功；d: 1 新建 + 400 不记；e: 2 新建
        # did=4, did_b=1, did_d=1, did_e=2 => 8
        expected_ids = (
            [f"{did}#2"] * 4
            + [f"{did_b}#2"]
            + [f"{did_d}#2"]
            + [f"{did_e}#2", f"{did_e}#3"]
        )
        check("rotated 审计条数（新建+幂等，失败不记）",
              len(rotated) == len(expected_ids))
        check("rotated resource_type/resource_id",
              all(e["resource_type"] == "trust_anchor" for e in rotated)
              and sorted(e["resource_id"] for e in rotated)
              == sorted(expected_ids))
        check("rotated 事件字段完整",
              all(set(e) == {"seq", "timestamp", "tenant_id", "action",
                             "resource_type", "resource_id"}
                  for e in rotated))
        max_seq = max(e["seq"] for e in events)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 15. 跨重启持久化：版本、状态、审计保留；重启后幂等仍 200
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "rot-a"}
        st, r = _http("GET", f"{base}/v1/trust/anchors/did:web:rotate-e.example",
                      headers=T1)
        check("重启后版本与状态保留",
              st == 200
              and [(a["key_version"], a["status"]) for a in r]
              == [(1, "revoked"), (2, "active"), (3, "active")])
        # 重启后对 did_b 的 1->2（v2 已存在 active）幂等仍 200 且只加一条审计
        st, r = rotate(base, T1, "did:web:rotate-b.example", 1, pub2)
        check("重启后幂等轮换 -> 200",
              st == 200 and r["key_version"] == 2
              and r["status"] == "active" and r["public_key"] == pub2)
        st, page = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        new_events = [e for e in page["events"] if e["seq"] > max_seq]
        check("重启后幂等记一条 rotated 且 seq 接续",
              len(new_events) == 1
              and new_events[0]["action"] == "trust.anchor.rotated"
              and new_events[0]["resource_id"]
              == "did:web:rotate-b.example#2"
              and new_events[0]["seq"] == max_seq + 1)
        # 重启后新版本仍可验签
        msg = {"issuer_did": "did:web:rotate-e.example",
               "issuer_key_version": 3, "doc": {"k": "值"}}
        sig = crypto.sign(msg, priv3)
        st, r = _http("POST", f"{base}/v1/trust/verify",
                      {**msg, "signature": sig}, headers=T1)
        check("重启后新版本仍可验签", r == {"valid": True})
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
