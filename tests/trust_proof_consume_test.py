#!/usr/bin/env python3
"""跨系统谓词证明验真并一次性消费 POST /v1/trust/proofs/consume 端到端测试。

直接运行：python3 tests/trust_proof_consume_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import hashlib
import json
import os
import re
import shutil
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

UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
VERIFY_PATH = "/v1/trust/proofs/verify"
CONSUME_PATH = "/v1/trust/proofs/consume"
DEACTIVATE_SYNC_PATH = "/v1/trust/dids/deactivate-sync"


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(payload).encode() if payload is not None else None
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


def start_server(port, store):
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


PREDS = [
    {"path": "/age", "op": "gte", "value": 18},
    {"path": "/role", "op": "eq", "value": "admin"},
    {"path": "/name", "op": "exists"},
]


def make_proof(priv, *, proof_id="zp_" + "a" * 32, credential_id="vc_ext_1",
               issuer_did="did:web:proof-issuer.example", version=1,
               challenge="chal-1", expires_at="2099-01-01T00:00:00Z",
               predicates=None, results=None, source="source-tenant"):
    p = {
        "proof_id": proof_id,
        "credential_id": credential_id,
        "issuer_did": issuer_did,
        "issuer_key_version": version,
        "predicates": PREDS if predicates is None else predicates,
        "results": [True, True, True] if results is None else results,
        "challenge": challenge,
        "expires_at": expires_at,
    }
    message = dict(p)
    message["tenant_id"] = source
    p["proof"] = crypto.sign(message, priv)
    return p


def make_req(priv, **kwargs):
    source = kwargs.pop("source", "source-tenant")
    challenge = kwargs.get("challenge", "chal-1")
    p = make_proof(priv, source=source, **kwargs)
    return {"proof": p, "challenge": challenge,
            "source_tenant_id": source}


def main():
    port = 8973
    store = tempfile.mktemp(suffix=".json")
    proc = start_server(port, store)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def consume(payload=None, headers=None, raw=None):
        return _http("POST", f"{base}{CONSUME_PATH}", payload,
                     headers=headers, raw=raw)

    def verify(payload=None, headers=None):
        return _http("POST", f"{base}{VERIFY_PATH}", payload, headers=headers)

    def consumed_audits(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return [e for e in r["events"]
                if e["action"] == "trust.proof.consumed"]

    try:
        T1 = {"X-Tenant-ID": "tpc-a"}
        T2 = {"X-Tenant-ID": "tpc-b"}

        priv, pub = gen_keypair()
        did = "did:web:proof-issuer.example"

        # 显式空租户头 -> 400 且仅非空中文 error，先于请求体验真
        st, r = consume(raw=b"", headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 空体 -> 400 非空中文 error",
              st == 400 and list(r.keys()) == ["error"]
              and isinstance(r["error"], str) and r["error"])
        st, r = consume(raw=b"not-json", headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 非法 JSON -> 400（先于体校验）",
              st == 400 and isinstance(r.get("error"), str) and r["error"])

        # T1 注册锚点
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub, "key_version": 1},
                      headers=T1)
        check("注册锚点 -> 201", st == 201)

        req1 = make_req(priv, proof_id="zp_" + "1" * 32)
        want_cid = hashlib.sha256(crypto.canonicalize(req1)).hexdigest()

        # 首次消费成功
        st, r = consume(req1, headers=T1)
        check("首次消费 -> 200 键序恰为 valid,consumption_id,consumed_at",
              st == 200 and list(r.keys())
              == ["valid", "consumption_id", "consumed_at"]
              and r["valid"] is True
              and r["consumption_id"] == want_cid
              and SHA256_HEX_RE.fullmatch(r["consumption_id"])
              and UTC_Z_RE.fullmatch(r["consumed_at"]))

        # 审计事件
        audits = consumed_audits(T1)
        check("恰有一条 trust.proof.consumed 审计",
              len(audits) == 1
              and audits[0]["action"] == "trust.proof.consumed"
              and audits[0]["resource_type"] == "trust_proof"
              and audits[0]["resource_id"] == want_cid
              and audits[0]["tenant_id"] == "tpc-a"
              and isinstance(audits[0]["seq"], int))

        # 同组合重放 -> 外部证明已消费（内容不同但 proof_id 相同、验真通过）
        replay = make_req(priv, proof_id="zp_" + "1" * 32,
                          credential_id="vc_other_cred",
                          results=[False, False, False])
        st, r = consume(replay, headers=T1)
        check("同组合重放（内容不同）-> 外部证明已消费",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        check("重放不追加审计", len(consumed_audits(T1)) == 1)

        # results 含 false 不影响首次消费（新 proof_id）
        req_false = make_req(priv, proof_id="zp_" + "f" * 32,
                             results=[False, True, False])
        st, r = consume(req_false, headers=T1)
        check("results 含 false 仍可首次消费",
              st == 200 and r.get("valid") is True
              and r["consumption_id"]
              == hashlib.sha256(crypto.canonicalize(req_false)).hexdigest())

        # 不同 proof_id / source / issuer 各自独立判重
        req_other_pid = make_req(priv, proof_id="zp_" + "2" * 32)
        st, r = consume(req_other_pid, headers=T1)
        check("不同 proof_id 独立消费", st == 200 and r.get("valid") is True)
        req_other_src = make_req(priv, proof_id="zp_" + "1" * 32,
                                 source="other-tenant")
        st, r = consume(req_other_src, headers=T1)
        check("不同 source_tenant_id 独立消费",
              st == 200 and r.get("valid") is True
              and r["consumption_id"]
              == hashlib.sha256(
                  crypto.canonicalize(req_other_src)).hexdigest())

        # 验真失败（及请求级错误）不消费、不审计：失败后同组合仍可首次消费
        pid3 = "zp_" + "3" * 32
        failed_audits = consumed_audits(T1)
        for label, payload, raw in (
            ("空请求体", None, b""),
            ("非法 JSON", None, b"not-json"),
            ("非法 UTF-8", None, b"\xff\xfe"),
            ("JSON 非对象", None, b"[1]"),
        ):
            st, r = consume(payload=payload, raw=raw, headers=T1)
            check(f"{label} -> 200 valid:false 非空中文 reason",
                  st == 200 and list(r.keys()) == ["valid", "reason"]
                  and r["valid"] is False
                  and isinstance(r["reason"], str) and r["reason"])
        # 缺字段 / 多余字段
        st, r = consume({"proof": {}, "challenge": "chal-1"}, headers=T1)
        check("缺 source_tenant_id -> 200 valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        good = make_req(priv, proof_id=pid3)
        st, r = consume({**good, "extra": 1}, headers=T1)
        check("多余字段 -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and r["reason"].startswith("请求"))
        # 挑战不匹配
        st, r = consume({"proof": good["proof"], "challenge": "nope",
                         "source_tenant_id": "source-tenant"}, headers=T1)
        check("挑战不匹配 -> 200 valid:false（前缀 挑战）",
              st == 200 and r.get("valid") is False
              and r["reason"].startswith("挑战"))
        # 篡改签名
        bad_sig = json.loads(json.dumps(good))
        bad_sig["proof"]["proof"] = "!!!bad!!!"
        st, r = consume(bad_sig, headers=T1)
        check("签名格式错误 -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and r["reason"].startswith("签名格式错误"))
        # 过期
        expired = make_req(priv, proof_id=pid3,
                           expires_at="2020-01-01T00:00:00Z")
        st, r = consume(expired, headers=T1)
        check("已过期 -> 证明已过期",
              st == 200 and r == {"valid": False, "reason": "证明已过期"})
        check("各类失败均不记审计",
              consumed_audits(T1) == failed_audits)
        # 失败后同组合同证明首次消费成功
        st, r = consume(good, headers=T1)
        check("失败后同组合仍可首次消费",
              st == 200 and r.get("valid") is True
              and r["consumption_id"]
              == hashlib.sha256(crypto.canonicalize(good)).hexdigest())

        # 已消费证明在只读 verify 上仍按原规则验真
        st, r = verify(req1, headers=T1)
        check("已消费证明只读验真仍 valid:true",
              st == 200 and r == {"valid": True})
        st_before_audit = len(consumed_audits(T1))
        verify(req1, headers=T1)
        check("只读验真不追加消费审计",
              len(consumed_audits(T1)) == st_before_audit)

        # 锚点用途收紧：无 proof 用途时消费同样失败
        did2 = "did:web:proof-issuer-2.example"
        priv2, pub2 = gen_keypair()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did2, "public_key": pub2, "key_version": 1},
                      headers=T1)
        assert st == 201
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did2}/1/uses",
                      {"from_uses": ["generic", "vc", "vp", "proof",
                                     "did", "status", "deactivation"],
                       "uses": ["vp"]}, headers=T1)
        assert st == 200
        no_proof_use = make_req(
            priv2, issuer_did=did2, proof_id="zp_" + "9" * 32)
        st, r = consume(no_proof_use, headers=T1)
        check("锚点无 proof 用途 -> 200 valid:false（前缀 锚点）",
              st == 200 and r.get("valid") is False
              and r["reason"].startswith("锚点"))

        # 外部 DID 停用通告：消费失败、reason 一致、不记审计
        deact_body = {
            "did": did, "key_version": 1, "reason": "签发机构业务终止",
            "deactivated_at": "2026-09-20T10:00:00Z",
        }
        st, _ = _http("POST", f"{base}{DEACTIVATE_SYNC_PATH}",
                      {"body": deact_body,
                       "signature": crypto.sign(deact_body, priv)},
                      headers=T1)
        check("登记停用通告 -> 201/200", st in (200, 201))
        deact_req = make_req(priv, proof_id="zp_" + "d" * 32)
        st, r = consume(deact_req, headers=T1)
        check("停用通告命中 -> 外部签发DID已停用：<reason>",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "外部签发DID已停用：签发机构业务终止")
        st, r = verify(deact_req, headers=T1)
        check("只读验真 reason 与消费一致",
              st == 200 and r == {"valid": False,
                                  "reason": "外部签发DID已停用：签发机构业务终止"})

        # 落盘失败 -> 500 仅 {error:存储失败}，回滚后可重试
        # （停用通告使新 proof_id 无法消费；先在 T2 做存储失败场景）
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did, "public_key": pub, "key_version": 1},
                      headers=T2)
        assert st == 201
        t2_req = make_req(priv, proof_id="zp_" + "7" * 32)
        os.unlink(store)
        os.mkdir(store)
        try:
            st, r = consume(t2_req, headers=T2)
            check("落盘失败 -> 500 恰返 {error:存储失败}",
                  st == 500 and r == {"error": "存储失败"})
        finally:
            os.rmdir(store)
        check("落盘失败不记审计（T2）", consumed_audits(T2) == [])
        st, r = consume(t2_req, headers=T2)
        check("恢复后重试首次消费成功",
              st == 200 and r.get("valid") is True
              and r["consumption_id"]
              == hashlib.sha256(crypto.canonicalize(t2_req)).hexdigest())

        # 租户隔离：T2 同组合独立消费成功；T2 用自身锚点
        st, r = consume(req1, headers=T2)
        check("T2 同 (source,issuer,proof_id) 独立消费",
              st == 200 and r.get("valid") is True)
        st, r = consume(req1, headers=T2)
        check("T2 重放被拒绝",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        t2_audits = consumed_audits(T2)
        check("T2 恰两条消费审计且 resource_type 为 trust_proof",
              len(t2_audits) == 2
              and all(e["tenant_id"] == "tpc-b"
                      and e["resource_type"] == "trust_proof"
                      for e in t2_audits))

        # 缺省租户头 -> default
        default_req = make_req(priv, proof_id="zp_" + "c" * 32)
        st, r = consume(default_req)
        check("缺省租户头按 default 处理（无锚点 -> 锚点失败）",
              st == 200 and r.get("valid") is False
              and r["reason"].startswith("锚点"))

        # 存储内容仅含标识、摘要与时间，不含证明原文
        with open(store, encoding="utf-8") as fh:
            raw_state = fh.read()
        state = json.loads(raw_state)
        t1_markers = state["tenants"]["tpc-a"]["consumed_trust_proofs"]
        sample_row = t1_markers["source-tenant"][did]["zp_" + "1" * 32]
        check("消费标记恰含 consumption_id,consumed_at",
              set(sample_row) == {"consumption_id", "consumed_at"}
              and set(t1_markers) == {"source-tenant", "other-tenant"})
        check("存储不含证明签名原文",
              req1["proof"]["proof"] not in raw_state)
        check("存储不含 predicates/results 等证明原文（标记层）",
              "predicates" not in json.dumps(t1_markers, ensure_ascii=False)
              and "results" not in json.dumps(t1_markers, ensure_ascii=False))

        # 跨重启：判重与审计保留（T1 的停用通告同样持久化，故 T1 重放
        # 先在验真阶段失败；T2 无通告可验证判重）
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server(port, store)
        st, r = consume(req1, headers=T1)
        check("重启后 T1 停用通告仍先于判重生效",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("外部签发DID已停用"))
        st, r = consume(req1, headers=T2)
        check("重启后 T2 重放仍被拒绝",
              st == 200 and r == {"valid": False, "reason": "外部证明已消费"})
        st, r = verify(req1, headers=T2)
        check("重启后 T2 只读验真仍成功", st == 200 and r == {"valid": True})
        check("重启后审计事件保留",
              len(consumed_audits(T1)) == 5
              and len(consumed_audits(T2)) == 2)

    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if os.path.isdir(store):
            shutil.rmtree(store)
        elif os.path.exists(store):
            os.unlink(store)

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
