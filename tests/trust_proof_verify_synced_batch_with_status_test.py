#!/usr/bin/env python3
"""POST /v1/trust/proofs/verify-synced-batch-with-status
批量同步锚点谓词证明验真并合并批初状态快照测试。

直接运行：python3 tests/trust_proof_verify_synced_batch_with_status_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议与 verify-synced-batch 一致：恰含 signer_did/at/proofs；
  空体、非法 JSON、非对象、键集或类型错误、空数组或超限均 400 且仅
  {"error":"请求非法"}；显式空租户头 400；
- 404/409 先于项校验：来源未同步或跨租户 404 仅 {"error":"同步来源不存在"}；
  at 超过检查点 409 仅 {"error":"同步游标冲突"}；
- 200 仅 {"results":[...]}，逐项不短路、等长同序：项结构非法为
  “请求项非法”；证明字段、挑战不匹配、锚点不可用、签名格式/验签/
  证明过期沿用 verify-synced-batch 原因；验真通过后按证明的
  (issuer_did,credential_id) 查批初状态快照：未同步/revoked/
  unknown 分别返“外部凭证状态未同步”“外部凭证已吊销：<reason>”
  （空原因用“未知原因”）“外部凭证状态未知”，active 成功；成功项
  仅 {"valid":true}，失败项键序 valid、reason；
- 纯只读：不推进检查点、不改同步视图、不记审计；重启一致；租户隔离。
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

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/anchor-changes/sync"
STATE_PATH = "/v1/trust/anchor-changes/synced-state"
STATUS_SYNC_PATH = "/v1/trust/credential-status/sync"
BATCH_PATH = "/v1/trust/proofs/verify-synced-batch-with-status"
ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
CHALLENGE = "ch-batch-synced-status"
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


def utc_z(delta):
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def make_proof(cred_id, issuer_did, **overrides):
    proof = {
        "proof_id": "prf-ext-1",
        "credential_id": cred_id,
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
    port = 9198
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

    def item(cred_id="prf_active", issuer=issuer_did, priv=issuer_priv,
             challenge=CHALLENGE, source=SOURCE_TENANT, **proof_overrides):
        proof = make_proof(cred_id, issuer, **proof_overrides)
        return {"proof": sign_proof(proof, priv, source),
                "challenge": challenge, "source_tenant_id": source}

    def batch(items, at=1, signer=signer_did):
        return {"signer_did": signer, "at": at, "proofs": items}

    def sync_status(cred_id, status, reason=None, headers=TA):
        sb = {
            "issuer_did": issuer_did,
            "credential_id": cred_id,
            "status": status,
            "updated_at": utc_z(timedelta(days=-1)),
            "issuer_key_version": 1,
        }
        if reason is not None:
            sb["reason"] = reason
        return _http("POST", base + STATUS_SYNC_PATH,
                     {"body": sb, "signature": crypto.sign(sb, issuer_priv)},
                     headers=headers)

    try:
        # 签名方锚点（sync 变更页验真用）与签发者锚点（status sync
        # 验签用，本地锚点），两个租户均登记
        for headers in (TA, TB):
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": signer_did, "public_key": signer_pub,
                 "key_version": 1}, headers,
            )
            assert st in (200, 201), raw
            st, raw = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": issuer_did, "public_key": issuer_pub,
                 "key_version": 1}, headers,
            )
            assert st in (200, 201), raw

        # 同步锚点变更页：c1 issuer#1 注册(active, 全用途)；
        # c2 noproof#1 注册(无 proof)。tenant-a 与 tenant-b 检查点均为 2。
        page1 = build_changes(
            [
                make_event(1, issuer_did, 1, pub=issuer_pub),
                make_event(2, "did:web:noproof", 1,
                           uses=["generic", "vc"], pub=issuer_pub),
            ],
            0, signer_did, signer_priv,
        )
        for headers in (TA, TB):
            st, _ = _http("POST", base + SYNC_PATH, page1, headers=headers)
            assert st == 201

        # tenant-a 同步凭证状态；tenant-b 不同步（隔离验证）
        check("同步 active -> 201", sync_status("prf_active", "active")[0] == 201)
        check("同步 revoked 带原因 -> 201",
              sync_status("prf_rev", "revoked", reason="持证人违规")[0] == 201)
        check("同步 revoked 无原因 -> 201",
              sync_status("prf_rev_nr", "revoked")[0] == 201)
        check("同步 unknown -> 201",
              sync_status("prf_unk", "unknown")[0] == 201)

        good_item = item()

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
        expect_400("at 负数 400", payload=batch([good_item], at=-1))
        expect_400("at 字符串 400",
                   payload={"signer_did": signer_did, "at": "1",
                            "proofs": [good_item]})
        expect_400("at 小数 400", payload=batch([good_item], at=1.5))
        expect_400("proofs 非数组 400",
                   payload={"signer_did": signer_did, "at": 1,
                            "proofs": {}})
        expect_400("空数组 400", payload=batch([]))
        expect_400("超过 100 项 400", payload=batch([good_item] * 101))
        st, raw = verify(payload=batch([good_item]),
                         headers={"X-Tenant-ID": ""})
        check("显式空租户头 400",
              st == 400
              and json.loads(raw) == {"error": "X-Tenant-ID 不能为空"})

        # ---------------------------------------------------------- #
        # 2. 404/409 先于项校验
        # ---------------------------------------------------------- #
        st, raw = verify(payload=batch([good_item], signer="did:web:nobody"))
        expect_exact_error("未知签名方 404", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=batch([good_item]), headers=TC)
        expect_exact_error("跨租户未同步 404", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=batch([good_item], at=3))
        expect_exact_error("at 超过检查点 409", st, raw, 409, "同步游标冲突")
        # 404/409 优先于项结构非法
        st, raw = verify(payload=batch([{"proof": {}}],
                                       signer="did:web:nobody"))
        expect_exact_error("404 优先于项非法", st, raw, 404, "同步来源不存在")
        st, raw = verify(payload=batch([{"proof": {}}], at=9))
        expect_exact_error("409 优先于项非法", st, raw, 409, "同步游标冲突")

        # ---------------------------------------------------------- #
        # 3. 200：状态合并、逐项不短路、等长同序、键序
        # ---------------------------------------------------------- #
        no_pid = make_proof("prf_active", issuer_did)
        del no_pid["proof_id"]
        tampered_item = item()
        tampered_item["proof"] = sign_proof(
            make_proof("prf_active", issuer_did), issuer_priv
        )
        tampered_item["proof"]["results"] = [False]
        bad_proof_item = item()
        bad_proof_item["proof"]["proof"] = "not-a-signature"
        wrong_tenant_item = {
            "proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv, SOURCE_TENANT
            ),
            "challenge": CHALLENGE,
            "source_tenant_id": "tenant-other",
        }
        items = [
            item(),                                          # active -> valid
            item("prf_nosync"),                              # 未同步
            item("prf_rev"),                                 # revoked+原因
            item("prf_rev_nr"),                              # revoked 无原因
            item("prf_unk"),                                 # unknown
            {"proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv),
             "challenge": CHALLENGE},                        # 缺 source
            {"proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv),
             "source_tenant_id": SOURCE_TENANT},             # 缺 challenge
            {"challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},             # 缺 proof
            {"proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv),
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT,
             "extra": 1},                                    # 多余键
            {"proof": [], "challenge": CHALLENGE,
             "source_tenant_id": SOURCE_TENANT},             # 非对象证明
            {"proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv),
             "challenge": "", "source_tenant_id": SOURCE_TENANT},  # 空挑战
            {"proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv),
             "challenge": CHALLENGE, "source_tenant_id": ""},  # 空来源租户
            {"proof": sign_proof(
                make_proof("prf_active", issuer_did), issuer_priv),
             "challenge": 1, "source_tenant_id": SOURCE_TENANT},  # 挑战非串
            "not-an-object",                                 # 非对象项
            {"proof": sign_proof(no_pid, issuer_priv),
             "challenge": CHALLENGE, "source_tenant_id": SOURCE_TENANT},
            # 证明缺字段
            item(challenge="other-challenge"),              # 挑战不匹配
            item(issuer="did:web:unknown"),                 # 锚点缺失
            item(issuer="did:web:noproof"),                 # uses 无 proof
            bad_proof_item,                                 # 格式错
            tampered_item,                                  # 验签失败
            item(expires_at="2020-01-01T00:00:00Z"),        # 已过期
            wrong_tenant_item,                              # 来源租户不符
            item(),                                          # active -> valid
        ]
        st, raw = verify(payload=batch(items, at=1))
        body = json.loads(raw)
        expected = [
            {"valid": True},
            {"valid": False, "reason": "外部凭证状态未同步"},
            {"valid": False, "reason": "外部凭证已吊销：持证人违规"},
            {"valid": False, "reason": "外部凭证已吊销：未知原因"},
            {"valid": False, "reason": "外部凭证状态未知"},
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
            {"valid": False, "reason": "签名校验失败"},
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

        # 验真失败优先于状态查询：已同步 active 的证明若验签失败，
        # 仍返回验签原因而非状态结论
        st, raw = verify(payload=batch([tampered_item], at=1))
        check("验真失败不查状态",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": False, "reason": "签名校验失败"}]})

        # 吊销状态的证明若锚点不可用，返回锚点原因而非吊销结论
        st, raw = verify(payload=batch(
            [item("prf_rev", issuer="did:web:noproof")], at=2))
        check("锚点失败优先于状态结论",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": False, "reason": "同步锚点不可用"}]})

        # tenant-b：锚点已同步但状态未同步 -> 外部凭证状态未同步
        st, raw = verify(payload=batch([good_item], at=2), headers=TB)
        check("tenant-b 状态隔离（未同步）",
              st == 200 and json.loads(raw) == {"results": [
                  {"valid": False, "reason": "外部凭证状态未同步"}]})

        # 缺省租户头为 default（未同步来源 -> 404）
        st, raw = _http("POST", base + BATCH_PATH, batch([good_item]))
        expect_exact_error("缺省租户 default 隔离 404", st, raw, 404,
                           "同步来源不存在")

        # ---------------------------------------------------------- #
        # 4. 只读：不推进检查点、不改同步视图、不记审计
        # ---------------------------------------------------------- #
        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_before = len(json.loads(raw).get("events", []))
        st, state_before = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        assert st == 200

        verify(payload=batch(items, at=1))
        verify(payload=batch([good_item], at=2))

        st, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        audit_after = len(json.loads(raw).get("events", []))
        check("批量验真不记审计", audit_after == audit_before)
        st, state_after = _http(
            "GET", f"{base}{STATE_PATH}?signer_did={signer_did}",
            headers=TA)
        check("批量验真不改同步视图（逐字节一致）",
              st == 200 and state_after == state_before)
        # 检查点未推进：重放首页仍 accepted=0
        st, raw = _http("POST", base + SYNC_PATH, page1, headers=TA)
        check("批量验真不推进检查点",
              st == 200 and json.loads(raw)["accepted"] == 0)

        # ---------------------------------------------------------- #
        # 5. 重启一致
        # ---------------------------------------------------------- #
        st, ok_before = verify(payload=batch(
            [item(), item("prf_rev"), item("prf_unk")], at=1))
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, raw = verify(payload=batch(
            [item(), item("prf_rev"), item("prf_unk")], at=1))
        check("重启后批量响应逐字节一致", st == 200 and raw == ok_before)
        st, raw = verify(payload=batch([good_item], at=9))
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
