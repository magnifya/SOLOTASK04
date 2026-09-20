#!/usr/bin/env python3
"""信任锚点密钥轮换接口（POST /v1/trust/anchors/{did}/rotate）端到端测试。

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


def main():
    port = 8948
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

    def rotate(did, body, headers):
        return _http("POST",
                     f"{base}/v1/trust/anchors/{did}/rotate",
                     body, headers=headers)

    def versions(did, headers):
        st, r = _http("GET", f"{base}/v1/trust/anchors/{did}",
                      headers=headers)
        assert st == 200, (st, r)
        return r

    def verify(did, version, priv_pem, headers):
        message = {"issuer_did": did, "issuer_key_version": version,
                   "doc": {"hello": "世界", "n": [1, 2, 3]}}
        sig = crypto.sign(message, priv_pem)
        return _http("POST", f"{base}/v1/trust/verify",
                     {**message, "signature": sig}, headers=headers)

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "rot-a"}
        T2 = {"X-Tenant-ID": "rot-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        priv3, pub3 = gen_keypair()
        did = "did:web:rotate.example.com:issuer"

        # 0. 注册前置锚点 v1
        st, r = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub1, "key_version": 1},
                      headers=T1)
        check("注册 v1 -> 201", st == 201)

        # 1. 请求体严格校验：缺失/多余/类型/PEM 非法 -> 400
        bad_bodies = [
            {"public_key": pub2},                              # 缺 from
            {"from_key_version": 1},                           # 缺 public_key
            {},                                                # 全缺
            {"from_key_version": 1, "public_key": pub2,
             "extra": 1},                                      # 多余字段
            {"from_key_version": 0, "public_key": pub2},
            {"from_key_version": -2, "public_key": pub2},
            {"from_key_version": True, "public_key": pub2},
            {"from_key_version": False, "public_key": pub2},
            {"from_key_version": "1", "public_key": pub2},
            {"from_key_version": 1.0, "public_key": pub2},
            {"from_key_version": 1.5, "public_key": pub2},
            {"from_key_version": 1, "public_key": "not-a-pem"},
            {"from_key_version": 1, "public_key": ""},
            {"from_key_version": 1, "public_key": 123},
        ]
        for body in bad_bodies:
            st, r = rotate(did, body, T1)
            check(f"非法轮换体 400: {list(body)} -> {st}",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])
        st, _ = rotate(did, None, T1)
        check("空请求体 -> 400", st == 400)
        st, _ = rotate(did, None, {**T1, "X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)
        st, rr = _http("POST", f"{base}/v1/trust/anchors/{did}/rotate",
                       raw=b"not-json", headers=T1)
        check("非法 JSON -> 400",
              st == 400 and isinstance(rr.get("error"), str))

        # 校验失败不得改动版本
        check("400 后版本不变",
              [a["key_version"] for a in versions(did, T1)] == [1])

        # 2. DID 不存在 / 跨租户 -> 404
        st, r = rotate("did:web:missing",
                       {"from_key_version": 1, "public_key": pub2}, T1)
        check("未知 DID 轮换 -> 404",
              st == 404 and isinstance(r.get("error"), str))
        st, r = rotate(did,
                       {"from_key_version": 1, "public_key": pub2}, T2)
        check("跨租户 DID 轮换 -> 404", st == 404)

        # 3. 成功轮换 1 -> 2：201，字段同 GET 元素
        st, r = rotate(did, {"from_key_version": 1, "public_key": pub2}, T1)
        check("轮换 v2 -> 201", st == 201)
        check("201 返回体字段同 GET 元素",
              r == {"did": did, "public_key": pub2, "key_version": 2,
                    "status": "active", "updated_at": None})
        arr = versions(did, T1)
        check("轮换后数组两版本且升序",
              [a["key_version"] for a in arr] == [1, 2])
        check("旧版本状态保留 active",
              arr[0] == {"did": did, "public_key": pub1,
                         "key_version": 1, "status": "active",
                         "updated_at": None})

        # 4. 幂等重试：同前置同 PEM -> 200 原锚点，状态不变
        st, r = rotate(did, {"from_key_version": 1, "public_key": pub2}, T1)
        check("幂等重试 -> 200", st == 200)
        check("200 返回原锚点",
              r == {"did": did, "public_key": pub2, "key_version": 2,
                    "status": "active", "updated_at": None})
        check("幂等不新增版本",
              [a["key_version"] for a in versions(did, T1)] == [1, 2])

        # 5. 目标已有不同 PEM -> 409；同 PEM 但前置不同 -> 409
        st, r = rotate(did, {"from_key_version": 1, "public_key": pub3}, T1)
        check("目标不同 PEM -> 409",
              st == 409 and isinstance(r.get("error"), str))
        check("409 不改动版本",
              [a["key_version"] for a in versions(did, T1)] == [1, 2])

        # 同 PEM 但前置不同：另一个 DID 上用注册接口直建 v2（无前置），
        # 再以 from=1+同 PEM 轮换应判 409。
        did2 = "did:web:rotate2"
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": did2, "public_key": pub1, "key_version": 1},
              headers=T1)
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": did2, "public_key": pub2, "key_version": 2},
              headers=T1)
        st, r = rotate(did2,
                       {"from_key_version": 1, "public_key": pub2}, T1)
        check("同 PEM 但前置不同 -> 409", st == 409)

        # 6. 前置不存在 404；非最高 400；已吊销 400 —— 用版本空洞构造
        gapped = "did:web:gapped"
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": gapped, "public_key": pub1, "key_version": 1},
              headers=T1)
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": gapped, "public_key": pub3, "key_version": 3},
              headers=T1)
        # from=4 target=5 不存在：前置不存在 -> 404（即便也非最高）
        st, r = rotate(gapped,
                       {"from_key_version": 4, "public_key": pub2}, T1)
        check("前置版本不存在 -> 404", st == 404)
        # from=2 target=3 已存在且 PEM 不同 -> 409（目标冲突优先）
        st, _ = rotate(gapped,
                       {"from_key_version": 2, "public_key": pub2}, T1)
        check("空洞前置且目标已被占 -> 409", st == 409)
        # from=1 target=2 不存在：from 存在但非最高（最高=3）-> 400
        st, r = rotate(gapped,
                       {"from_key_version": 1, "public_key": pub2}, T1)
        check("前置非最高 -> 400",
              st == 400 and isinstance(r.get("error"), str))
        check("非最高失败不改动版本",
              sorted(a["key_version"] for a in versions(gapped, T1))
              == [1, 3])

        # 前置已吊销且目标不存在 -> 400
        revoked = "did:web:revoked-src"
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": revoked, "public_key": pub1, "key_version": 1},
              headers=T1)
        _http("PUT", f"{base}/v1/trust/anchors/{revoked}/1/status",
              {"status": "revoked"}, headers=T1)
        st, r = rotate(revoked,
                       {"from_key_version": 1, "public_key": pub2}, T1)
        check("前置已吊销 -> 400",
              st == 400 and isinstance(r.get("error"), str))
        check("吊销前置失败不新增版本",
              [a["key_version"] for a in versions(revoked, T1)] == [1])

        # 7. 幂等即使前置/目标后来被吊销：仍 200，返回原锚点状态不变
        # did 上 v2 由 from=1 创建。先吊销前置 v1，重试仍 200 且 v2 active
        _http("PUT", f"{base}/v1/trust/anchors/{did}/1/status",
              {"status": "revoked"}, headers=T1)
        st, r = rotate(did, {"from_key_version": 1, "public_key": pub2}, T1)
        check("前置吊销后幂等重试 -> 200", st == 200)
        check("幂等返回目标原状态（active 不变）",
              r["status"] == "active" and r["updated_at"] is None)
        # 再吊销目标 v2，重试仍 200，返回吊销态原锚点（状态/时间不变）
        st, rev = _http("PUT", f"{base}/v1/trust/anchors/{did}/2/status",
                        {"status": "revoked"}, headers=T1)
        ts2 = rev["updated_at"]
        st, r = rotate(did, {"from_key_version": 1, "public_key": pub2}, T1)
        check("目标吊销后幂等重试 -> 200 且原状态不变",
              st == 200 and r["status"] == "revoked"
              and r["updated_at"] == ts2)
        # 目标吊销后换 PEM 仍是 409
        st, _ = rotate(did, {"from_key_version": 1, "public_key": pub3}, T1)
        check("目标吊销后不同 PEM -> 409", st == 409)

        # 8. 连续轮换与验签：旧版本吊销前可验签，新版本可验签
        chain = "did:web:chain"
        _http("POST", f"{base}/v1/trust/anchors",
              {"did": chain, "public_key": pub1, "key_version": 1},
              headers=T1)
        st, _ = rotate(chain,
                       {"from_key_version": 1, "public_key": pub2}, T1)
        check("链轮换 v2 -> 201", st == 201)
        st, r = rotate(chain,
                       {"from_key_version": 2, "public_key": pub3}, T1)
        check("链轮换 v3 -> 201", st == 201 and r["key_version"] == 3)
        # 旧版本（未吊销）与新版本均可验签
        st, r = verify(chain, 1, priv1, T1)
        check("旧版本 v1 未吊销可验签", st == 200 and r == {"valid": True})
        st, r = verify(chain, 2, priv2, T1)
        check("中间版本 v2 可验签", st == 200 and r == {"valid": True})
        st, r = verify(chain, 3, priv3, T1)
        check("新版本 v3 可验签", st == 200 and r == {"valid": True})
        # 显式吊销 v1 后：v1 验签失败（valid:false 带吊销），v2/v3 仍可
        _http("PUT", f"{base}/v1/trust/anchors/{chain}/1/status",
              {"status": "revoked"}, headers=T1)
        st, r = verify(chain, 1, priv1, T1)
        check("旧版本吊销后验签失败",
              st == 200 and r.get("valid") is False
              and "吊销" in r.get("reason", ""))
        st, r = verify(chain, 3, priv3, T1)
        check("吊销旧版后新版本仍可验签", r == {"valid": True})

        # 9. 跨租户隔离：T2 无 chain -> 轮换 404，验签 200/valid:false
        st, _ = rotate(chain,
                       {"from_key_version": 3, "public_key": pub1}, T2)
        check("跨租户轮换 -> 404", st == 404)
        st, r = verify(chain, 3, priv3, T2)
        check("跨租户验签 -> 200/valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        # 跨租户失败不改动 T1 版本
        check("跨租户失败后 T1 版本不变",
              [a["key_version"] for a in versions(chain, T1)] == [1, 2, 3])

        # 10. 审计：新建与幂等都记 trust.anchor.rotated，
        #     resource_type=trust_anchor，resource_id=<did>#<new_version>；
        #     冲突、校验失败不记。
        st, page = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        events = page["events"]
        rotated = [e for e in events
                   if e["action"] == "trust.anchor.rotated"]
        # chain: v2 新建、v3 新建；did: v2 新建 + 3 次幂等（吊销前、吊销
        # 前置后、吊销目标后）= 共 5 条
        expected_ids = (
            [f"{chain}#2", f"{chain}#3"]
            + [f"{did}#2"] * 4
        )
        check("rotated 审计条数与资源 ID",
            sorted(e["resource_id"] for e in rotated)
            == sorted(expected_ids))
        check("rotated 审计 resource_type",
              all(e["resource_type"] == "trust_anchor" for e in rotated))
        check("rotated 审计事件字段完整",
              all(set(e) == {"seq", "timestamp", "tenant_id", "action",
                             "resource_type", "resource_id"}
                  for e in rotated))
        # 冲突 / 400 / 验签均不为 rotated（成功条数已精确锁定，天然验证）
        check("冲突/校验失败未多记 rotated",
              len(rotated) == len(expected_ids))
        max_seq = max(e["seq"] for e in events)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 11. 跨重启持久化：版本、状态、审计保留；幂等仍 200
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "rot-a"}

        arr = versions("did:web:chain", T1)
        check("重启后版本全部保留",
              [a["key_version"] for a in arr] == [1, 2, 3])
        by_ver = {a["key_version"]: a for a in arr}
        check("重启后 v1 吊销状态保留", by_ver[1]["status"] == "revoked")
        check("重启后 v2/v3 active 保留",
              by_ver[2]["status"] == "active"
              and by_ver[3]["status"] == "active")

        # 新版本重启后仍可验签
        st, r = verify("did:web:chain", 3, priv3, T1)
        check("重启后新版本仍可验签", r == {"valid": True})

        # 幂等重试重启后仍 200 且只再记一条审计
        st, r = rotate(did,
                       {"from_key_version": 1, "public_key": pub2}, T1)
        check("重启后幂等重试 -> 200",
              st == 200 and r["key_version"] == 2
              and r["status"] == "revoked")

        st, page = _http("GET", f"{base}/v1/audit?limit=200", headers=T1)
        new_events = [e for e in page["events"] if e["seq"] > max_seq]
        check("重启后幂等再记一条 rotated 且 seq 接续",
              len(new_events) == 1
              and new_events[0]["action"] == "trust.anchor.rotated"
              and new_events[0]["resource_id"] == f"{did}#2"
              and new_events[0]["seq"] == max_seq + 1)

        # 重启后失败规则依旧（from=2 目标 v3 已存在且 PEM 不同 -> 409）
        st, _ = rotate("did:web:chain",
                       {"from_key_version": 2, "public_key": pub1}, T1)
        check("重启后目标冲突仍 409", st == 409)
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
