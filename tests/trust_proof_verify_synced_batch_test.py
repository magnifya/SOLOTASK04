#!/usr/bin/env python3
"""POST /v1/trust/proofs/verify-synced-batch 批量同步锚点验真测试。

直接运行：python3 tests/trust_proof_verify_synced_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：恰含 signer_did/at/proofs（非空字符串、非布尔非负整数、
  1–100 项数组）；空体、非法 JSON、非对象、键集或类型错误、空数组或
  超限均 400 且仅 {"error":"请求非法"}；显式空租户头 400；
- 404/409：来源未同步或跨租户 404 仅 {"error":"同步来源不存在"}；
  at 超过检查点 409 仅 {"error":"同步游标冲突"}，先于项校验；
- 200：仅 {"results":[...]}，逐项不短路、等长同序；项须恰含 proof
  对象、非空 challenge、非空 source_tenant_id，否则“请求项非法”；
  合法项沿用单条 verify-synced 的证明九字段、谓词/results、RFC6901
  路径、挑战、锚点、签名格式错误/签名校验失败/证明已过期；成功项仅
  {"valid":true}，失败项键序 valid、reason；
- 纯只读：不推进检查点、不改同步页/锚点/证明/状态、不记审计；重启
  一致；租户头缺省 default 并隔离。
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

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
BATCH_PATH = "/v1/trust/proofs/verify-synced-batch"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
CHALLENGE = "ch-batch-synced"
SOURCE_TENANT = "tenant-src"

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


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
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


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
    priv = crypto.generate_private_key_pem()
    return priv, crypto.public_key_pem_from_private(priv)


def make_event(cursor, did, key_version=1, action="registered",
               status="active", uses=None, pub="pem"):
    return {
        "cursor": cursor,
        "action": action,
        "did": did,
        "key_version": key_version,
        "public_key": pub,
        "status": status,
        "uses": list(uses if uses is not None else ALL_USES),
    }


def build_changes(events, after, did, signer_priv):
    signed = {
        "events": events,
        "next_after": events[-1]["cursor"] if events else after,
        "signer_did": did,
        "signer_key_version": 1,
    }
    signature = crypto.sign(signed, signer_priv)
    changes = dict(signed)
    changes["signature"] = signature
    return {"changes": changes, "after": after}


def make_proof(issuer_did, **overrides):
    proof = {
        "proof_id": "prf-ext-1",
        "credential_id": "vc-ext-1",
        "issuer_did": issuer_did,
        "issuer_key_version": 1,
        "predicates": [{"path": "/age", "op": "gte", "value": 18}],
        "results": [True],
        "challenge": CHALLENGE,
        "expires_at": "2999-01-01T00:00:00Z",
    }
    proof.update(overrides)
    return proof


def sign_proof(proof, priv, source_tenant_id=SOURCE_TENANT):
    message = {k: v for k, v in proof.items() if k != "proof"}
    message["tenant_id"] = source_tenant_id
    signed = dict(proof)
    signed["proof"] = crypto.sign(message, priv)
    return signed


def test_http():
    port = 9189
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"
    TA = {"X-Tenant-ID": "tenant-a"}
    TB = {"X-Tenant-ID": "tenant-b"}
    TC = {"X-Tenant-ID": "tenant-c"}

    signer_did = "did:web:remote-signer"
    signer_priv, signer_pub = gen_keypair()
    issuer_did = "did:web:issuer"
    issuer_priv, issuer_pub = gen_keypair()
    issuer_priv2, issuer_pub2 = gen_keypair()

    def verify(payload=None, headers=None, raw=None):
        return _http("POST", base + BATCH_PATH, payload,
                     headers=headers if headers is not None else TA,
                     raw=raw)

    def expect_exact_error(name, st, raw, status, message):
        try:
            body = json.loads(raw.decode() or "{}")
        except ValueError:
            body = None
        check(
            name,
            st == status
            and isinstance(body, dict)
            and body == {"error": message},
        )

    def expect_400(name, payload=None, headers=None, raw=None):
        st, resp = verify(payload=payload, headers=headers or TA, raw=raw)
        expect_exact_error(name, st, resp, 400, "请求非法")

    def item(proof, priv=issuer_priv, challenge=CHALLENGE,
             source=SOURCE_TENANT):
        return {"proof": sign_proof(proof, priv, source),
                "challenge": challenge, "source_tenant_id": source}

    def batch(items, at=1, signer=signer_did):
        return {"signer_did": signer, "at": at, "proofs": items}

    try:
        # 登记签名方锚点（两个租户），供 sync 验真通过
        for headers in (TA, TB):
            st, raw = _http(
                "POST",
                f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": signer_pub,
                 "key_version": 1},
                headers,
            )
            assert st in (200, 201), raw

        # 同步两页（tenant-a 检查点=4；tenant-b 仅首页，检查点=2）
        # c1: issuer#1 注册(active, 全用途)；c2: noproof#1 注册(无 proof)
        # c3: issuer#1 吊销；c4: issuer#2 轮换(active)
        page1 = build_changes(
            [
                make_event(1, issuer_did, 1, pub=issuer_pub),
                make_event(2, "did:web:noproof", 1,
                           uses=["generic", "vc"], pub=issuer_pub),
            ],
            0, signer_did, signer_priv,
        )
        page2 = build_changes(
            [
                make_event(3, issuer_did, 1, action="revoked",
                           status="revoked", pub=issuer_pub),
                make_event(4, issuer_did, 2, action="rotated",
                           pub=issuer_pub2),
            ],
            2, signer_did, signer_priv,
        )
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TA)
        assert st == 201
        st, _ = _http("POST", base + SYNC_PATH, page2, headers=TA)
        assert st == 200
        st, _ = _http("POST", base + SYNC_PATH, page1, headers=TB)
        assert st == 201

        good_proof = make_proof(issuer_did)
        good_item = item(good_proof)

        # ---------------------------------------------------------- #
        # 1. 400 族：请求协议，仅 {"error":"请求非法"}
        # ---------------------------------------------------------- #
        expect_400("空体 400", raw=b"")
        expect_400("非法 JSON 400", raw=b"{not json")
        expect_400("非对象 400", raw=b"[1,2]")
        expect_400("空对象 400", payload={})
        expect_400("缺 signer_did 400",
                   payload={"at": 1, "proofs": [good_item]})
        expect_400("缺 at 400",
                   payload={"signer_did": signer_did,
                            "proofs": [good_item]})
        expect_400("缺 proofs 400",
                   payload={"signer_did": signer_did, "at": 1})
        expect_400("多余字段 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "proofs": [good_item], "extra": 1})
        expect_400("signer_did 空串 400",
                   payload=batch([good_item], signer=""))
        expect_400("signer_did 非字符串 400",
                   payload=batch([good_item], signer=1))
        expect_400("at 布尔 400",
                   payload={"signer_did": signer_did, "at": True,
                            "proofs": [good_item]})
        expect_400("at 负数 400",
                   payload=batch([good_item], at=-1))
        expect_400("at 字符串 400",
                   payload={"signer_did": signer_did, "at": "1",
                            "proofs": [good_item]})
        expect_400("at 小数 400",
                   payload=batch([good_item], at=1.5))
        expect_400("proofs 非数组 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "proofs": {}})
        expect_400("空数组 400", payload=batch([]))
        expect_400("超过 100 项 400",
                   payload=batch([good_item] * 101))
        st, raw = verify(payload=batch([good_item]),
                         headers={"X-Tenant-ID": ""})
        check("显式空租户头 400",
              st == 400 and json.loads(raw) == {"error": "X-Tenant-ID 不能为空"})

        # ---------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户，仅 {"error":"同步来源不存在"}
        # ---------------------------------------------------------- #
        st, raw = verify(payload=batch([good_item], signer="did:web:nobody"))
        expect_exact_error("未知签名方 404", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=batch([good_item]), headers=TC)
        expect_exact_error("跨租户未同步 404", st, raw, 404, "同步来源不存在")

        # ---------------------------------------------------------- #
        # 3. 409：at 超过检查点，仅 {"error":"同步游标冲突"}，先于项校验
        # ---------------------------------------------------------- #
        st, raw = verify(payload=batch([good_item], at=5))
        expect_exact_error("at 超过检查点 409", st, raw, 409, "同步游标冲突")
        st, raw = verify(payload=batch([good_item], at=3), headers=TB)
        expect_exact_error("tenant-b at 超过其检查点 409", st, raw, 409,
                           "同步游标冲突")
        st, raw = verify(payload=batch([{"proof": {}}], at=5))
        expect_exact_error("409 优先于项非法", st, raw, 409, "同步游标冲突")

        # ---------------------------------------------------------- #
        # 4. 200：逐项不短路、等长同序、键序
        # ---------------------------------------------------------- #
        no_pid = make_proof(issuer_did)
        del no_pid["proof_id"]
        tampered_item = item(good_proof)
        tampered_item["proof"] = sign_proof(good_proof, issuer_priv)
        tampered_item["proof"]["results"] = [False]
        bad_proof_item = item(good_proof)
        bad_proof_item["proof"]["proof"] = "not-a-signature"
        expired = make_proof(issuer_did,
                             expires_at="2020-01-01T00:00:00Z")
        items = [
            good_item,                                            # valid
            {"proof": sign_proof(good_proof, issuer_priv),
             "challenge": CHALLENGE},                             # 缺 source
            {"proof": sign_proof(good_proof, issuer_priv),
             "source_tenant_id": SOURCE_TENANT},                  # 缺 challenge
            {"challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},                  # 缺 proof
            {"proof": sign_proof(good_proof, issuer_priv),
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT,
             "extra": 1},                                         # 多余键
            {"proof": [], "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},                  # 非对象证明
            {"proof": sign_proof(good_proof, issuer_priv),
             "challenge": "", "source_tenant_id": SOURCE_TENANT},  # 空挑战
            {"proof": sign_proof(good_proof, issuer_priv),
             "challenge": CHALLENGE, "source_tenant_id": ""},     # 空来源租户
            {"proof": sign_proof(good_proof, issuer_priv),
             "challenge": 1, "source_tenant_id": SOURCE_TENANT},  # 挑战非串
            "not-an-object",                                      # 非对象项
            item(no_pid),                                         # 证明缺字段
            item(good_proof, challenge="other-challenge"),        # 挑战不匹配
            item(make_proof("did:web:unknown")),                  # 锚点缺失
            item(make_proof("did:web:noproof")),                  # uses 无 proof
            bad_proof_item,                                       # 格式错
            tampered_item,                                        # 验签失败
            item(expired),                                        # 已过期
            item(make_proof(issuer_did, issuer_key_version=2),
                 priv=issuer_priv2),                              # at=1 时 v2 未注册
            good_item,                                            # valid
        ]
        st, raw = verify(payload=batch(items, at=1))
        body = json.loads(raw)
        expected = [
            {"valid": True},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "请求项非法"},
            {"valid": False, "reason": "证明缺少字段: proof_id"},
            {"valid": False,
             "reason": "挑战不匹配: 请求 challenge 与证明 challenge 不一致"},
            {"valid": False, "reason": "同步锚点不可用"},
            {"valid": False, "reason": "同步锚点不可用"},
            {"valid": False, "reason": "签名格式错误"},
            {"valid": False, "reason": "签名校验失败"},
            {"valid": False, "reason": "证明已过期"},
            {"valid": False, "reason": "同步锚点不可用"},
            {"valid": True},
        ]
        check("混合批次等长同序逐项结果",
              st == 200 and body == {"results": expected})
        check("失败项键序 valid,reason",
              all(list(r) == ["valid", "reason"]
                  for r in body["results"] if not r["valid"]))
        check("成功项仅 valid 键",
              all(list(r) == ["valid"]
                  for r in body["results"] if r["valid"]))

        # 证明字段错误分类：非空字符串、正整数版本、results 规则
        st, raw = verify(payload=batch([
            item(make_proof(issuer_did, proof_id="")),
            item(make_proof(issuer_did, issuer_key_version=0)),
            item(make_proof(issuer_did, results=[1])),
        ], at=1))
        body = json.loads(raw)
        check("证明字段错误分类",
              st == 200 and body["results"] == [
                  {"valid": False,
                   "reason": "证明字段 proof_id 必须为非空字符串"},
                  {"valid": False,
                   "reason": "证明字段 issuer_key_version 必须为正整数"},
                  {"valid": False,
                   "reason": "证明字段 results 仅能包含布尔值"},
              ])

        # source_tenant_id 参与签名覆盖：签名按 tenant-src、项声明
        # tenant-other 即验签失败
        wrong_tenant_item = {
            "proof": sign_proof(good_proof, issuer_priv, SOURCE_TENANT),
            "challenge": CHALLENGE,
            "source_tenant_id": "tenant-other",
        }
        st, raw = verify(payload=batch([wrong_tenant_item], at=1))
        check("来源租户不符签名校验失败",
              st == 200 and json.loads(raw)["results"] == [
                  {"valid": False, "reason": "签名校验失败"}])

        # at=4 视图：issuer#1 已吊销、issuer#2 可用
        st, raw = verify(payload=batch([
            item(good_proof),
            item(make_proof(issuer_did, issuer_key_version=2),
                 priv=issuer_priv2),
        ], at=4))
        body = json.loads(raw)
        check("at=4 末事件视图",
              st == 200 and body["results"] == [
                  {"valid": False, "reason": "同步锚点不可用"},
                  {"valid": True},
              ])

        # tenant-b 视图（检查点=2）：issuer#1 仍 active
        st, raw = verify(payload=batch([good_item], at=2), headers=TB)
        check("tenant-b 视图内验真成功",
              st == 200 and json.loads(raw) == {"results": [{"valid": True}]})

        # 缺省租户头为 default（与 tenant-a 隔离，未同步 -> 404）
        st, raw = _http("POST", base + BATCH_PATH, batch([good_item]))
        expect_exact_error("缺省租户 default 隔离 404", st, raw, 404,
                           "同步来源不存在")

        # ---------------------------------------------------------- #
        # 5. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=batch(items, at=1))
        verify(payload=batch([good_item], at=4))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("批量验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("批量验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        # 检查点未推进：重放第二页仍 accepted=0
        st, raw = _http("POST", base + SYNC_PATH, page2, headers=TA)
        check("批量验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 6. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(payload=batch(
            [good_item, item(make_proof("did:web:noproof"))], at=1))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=batch(
            [good_item, item(make_proof("did:web:noproof"))], at=1))
        check("重启后批量响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=batch([good_item], at=5))
        expect_exact_error("重启后 at 超检查点仍 409", st, raw, 409,
                           "同步游标冲突")
        st, raw = verify(payload=batch([good_item]), headers=TC)
        expect_exact_error("重启后跨租户仍 404", st, raw, 404,
                           "同步来源不存在")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.unlink(store_path)


def main():
    test_http()
    if failures:
        print(f"\n{len(failures)} 项失败: {failures}")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
