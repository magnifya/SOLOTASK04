#!/usr/bin/env python3
"""谓词证明（predicate proof）端到端测试。

覆盖：prove 201 字段/结果/默认 challenge 与 expires_in、各类 400
（predicates 结构、op、路径、数值、challenge、expires_in）、未知凭证
404、签名外部验真；verify 的 valid:true、消费（重复验证/失败不消费/
并发仅一次）、过期、篡改与跨租户失败、审计 proof.created/proof.consumed
与跨重启保留。

直接运行：python3 tests/predicate_proof_test.py
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

PORT = 8944
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"


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


def start_server():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(PORT), "服务启动超时"
    return proc


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        # ---------------- 准备：DID 与凭证 ---------------- #
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "zp-issuer"})
        assert st == 201, r
        issuer = r["did"]
        issuer_pem = r["public_key"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "zp-subject"})
        assert st == 201, r
        subject = r["did"]
        claims = {
            "name": "Alice",
            "age": 30,
            "role": "admin",
            "addr": {"city": "Shanghai", "zip": "200000"},
            "tags": ["a", "b"],
            "score": 88.5,
            "vip": True,
        }
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": claims})
        assert st == 201, r
        cred = r["credential_id"]

        def prove(payload, headers=None):
            return _http("POST", f"{BASE}/v1/credentials/{cred}/prove",
                         payload, headers=headers)

        def verify(proof_id, payload=None, raw=None, headers=None):
            return _http("POST", f"{BASE}/v1/proofs/{proof_id}/verify",
                         payload, raw=raw, headers=headers)

        # ---------------- prove 201 与字段 ---------------- #
        predicates = [
            {"path": "/age", "op": "gte", "value": 18},
            {"path": "/role", "op": "eq", "value": "admin"},
            {"path": "/name", "op": "exists"},
            {"path": "/addr/city", "op": "eq", "value": "Shanghai"},
            {"path": "/score", "op": "lte", "value": 100},
        ]
        st, r = prove({"predicates": predicates})
        check("prove -> 201", st == 201)
        check("prove 返回恰 9 个字段",
              set(r) == {"proof_id", "credential_id", "issuer_did",
                         "issuer_key_version", "predicates", "results",
                         "challenge", "expires_at", "proof"})
        check("proof_id 为 zp_+32hex",
              bool(re.fullmatch(r"zp_[0-9a-f]{32}", r.get("proof_id", ""))))
        check("credential_id/issuer_did 回显",
              r.get("credential_id") == cred and r.get("issuer_did") == issuer)
        check("issuer_key_version 为 1", r.get("issuer_key_version") == 1)
        check("predicates 原样回显", r.get("predicates") == predicates)
        check("results 同序全真",
              r.get("results") == [True, True, True, True, True])
        check("challenge 默认 32 位小写 hex",
              bool(re.fullmatch(r"[0-9a-f]{32}", r.get("challenge", ""))))
        check("expires_at 为 Z 结尾秒精度",
              bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                                r.get("expires_at", ""))))
        proof1 = r
        # 外部验真：签名覆盖余字段 + tenant_id
        unsigned = {k: proof1[k] for k in (
            "proof_id", "credential_id", "issuer_did", "issuer_key_version",
            "predicates", "results", "challenge", "expires_at")}
        unsigned["tenant_id"] = "default"
        try:
            crypto.verify(unsigned, proof1["proof"], issuer_pem)
            check("proof 签名可用签发者公钥外部验真", True)
        except Exception:
            check("proof 签名可用签发者公钥外部验真", False)

        # results 求值：假值与 eq 精确匹配（同一次证明路径不得重复，
        # 故逐项单独 prove）
        eval_cases = [
            ({"path": "/age", "op": "gte", "value": 31}, False),
            ({"path": "/role", "op": "eq", "value": "user"}, False),
            ({"path": "/age", "op": "lte", "value": 30}, True),
            ({"path": "/vip", "op": "eq", "value": True}, True),
            ({"path": "/age", "op": "eq", "value": True}, False),
            ({"path": "/age", "op": "eq", "value": 30}, True),
            ({"path": "/tags", "op": "eq", "value": ["a", "b"]}, True),
            ({"path": "/addr", "op": "eq",
              "value": {"city": "Shanghai", "zip": "200000"}}, True),
        ]
        eval_ok = True
        for pred, expected in eval_cases:
            st, r = prove({"predicates": [pred]})
            if not (st == 201 and r.get("results") == [expected]):
                eval_ok = False
        check("results 求值（含 eq 精确与容器相等）", eval_ok)

        # 自定义 challenge 与 expires_in 回显
        st, r = prove({"predicates": [{"path": "/name", "op": "exists"}],
                       "challenge": "chal-1", "expires_in": 600})
        check("自定义 challenge/expires_in 回显",
              st == 201 and r["challenge"] == "chal-1")

        # ---------------- prove 400 ---------------- #
        bad_bodies = [
            ("缺 predicates", {}),
            ("predicates 空数组", {"predicates": []}),
            ("predicates 非数组", {"predicates": "/age"}),
            ("元素非对象", {"predicates": ["/age"]}),
            ("元素缺 path", {"predicates": [{"op": "exists"}]}),
            ("元素缺 op", {"predicates": [{"path": "/age"}]}),
            ("元素多余字段", {"predicates": [
                {"path": "/age", "op": "exists", "x": 1}]}),
            ("exists 禁 value", {"predicates": [
                {"path": "/age", "op": "exists", "value": 1}]}),
            ("eq 缺 value", {"predicates": [{"path": "/age", "op": "eq"}]}),
            ("gte 缺 value", {"predicates": [{"path": "/age", "op": "gte"}]}),
            ("op 非法", {"predicates": [
                {"path": "/age", "op": "gt", "value": 1}]}),
            ("路径非字符串", {"predicates": [{"path": 1, "op": "exists"}]}),
            ("路径不以 / 开头", {"predicates": [
                {"path": "age", "op": "exists"}]}),
            ("根路径", {"predicates": [{"path": "/", "op": "exists"}]}),
            ("数组索引", {"predicates": [
                {"path": "/tags/0", "op": "exists"}]}),
            ("路径越界", {"predicates": [{"path": "/nope", "op": "exists"}]}),
            ("路径重复", {"predicates": [
                {"path": "/age", "op": "exists"},
                {"path": "/age", "op": "gte", "value": 1}]}),
            ("祖先重叠", {"predicates": [
                {"path": "/addr", "op": "exists"},
                {"path": "/addr/city", "op": "exists"}]}),
            ("gte value 非数字", {"predicates": [
                {"path": "/age", "op": "gte", "value": "18"}]}),
            ("gte value 布尔", {"predicates": [
                {"path": "/age", "op": "gte", "value": True}]}),
            ("gte claims 值非数字", {"predicates": [
                {"path": "/name", "op": "gte", "value": 1}]}),
            ("lte claims 值布尔", {"predicates": [
                {"path": "/vip", "op": "lte", "value": 1}]}),
            ("多余请求字段", {"predicates": [
                {"path": "/age", "op": "exists"}], "foo": 1}),
            ("challenge 空串", {"predicates": [
                {"path": "/age", "op": "exists"}], "challenge": ""}),
            ("challenge 超 256 码点", {"predicates": [
                {"path": "/age", "op": "exists"}], "challenge": "x" * 257}),
            ("challenge 非字符串", {"predicates": [
                {"path": "/age", "op": "exists"}], "challenge": 1}),
            ("expires_in 为 0", {"predicates": [
                {"path": "/age", "op": "exists"}], "expires_in": 0}),
            ("expires_in 超界", {"predicates": [
                {"path": "/age", "op": "exists"}], "expires_in": 86401}),
            ("expires_in 布尔", {"predicates": [
                {"path": "/age", "op": "exists"}], "expires_in": True}),
            ("expires_in 非整数", {"predicates": [
                {"path": "/age", "op": "exists"}], "expires_in": "300"}),
        ]
        for name, body in bad_bodies:
            st, r = prove(body)
            check(f"prove 400: {name}",
                  st == 400 and bool(r.get("error")))

        # expires_in 边界 1 与 86400 合法
        st, r = prove({"predicates": [{"path": "/age", "op": "exists"}],
                       "expires_in": 86400})
        check("expires_in=86400 合法", st == 201)

        # 未知凭证 404
        st, r = _http("POST", f"{BASE}/v1/credentials/vc_{'0'*32}/prove",
                      {"predicates": [{"path": "/age", "op": "exists"}]})
        check("prove 未知凭证 -> 404", st == 404 and bool(r.get("error")))

        # ---------------- verify 成功与消费 ---------------- #
        st, r = verify(proof1["proof_id"],
                       {"proof": proof1, "challenge": proof1["challenge"]})
        check("verify -> 200 valid:true（恰含 valid）",
              st == 200 and r == {"valid": True})
        st, r = verify(proof1["proof_id"],
                       {"proof": proof1, "challenge": proof1["challenge"]})
        check("重复 verify -> valid:false 证明已消费",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

        # 失败不消费：先错 challenge 再正确 challenge
        st, r = prove({"predicates": [{"path": "/age", "op": "gte",
                                       "value": 18}]})
        assert st == 201, r
        proof2 = r
        st, r = verify(proof2["proof_id"],
                       {"proof": proof2, "challenge": "wrong"})
        check("challenge 不一致 -> valid:false",
              st == 200 and r.get("valid") is False
              and bool(r.get("reason")))
        st, r = verify(proof2["proof_id"],
                       {"proof": proof2, "challenge": proof2["challenge"]})
        check("失败不消费，纠正后 valid:true",
              st == 200 and r == {"valid": True})

        # 篡改 results / predicates / 签名 / 锚定字段
        st, r = prove({"predicates": [{"path": "/age", "op": "gte",
                                       "value": 18}]})
        assert st == 201, r
        proof3 = r
        tampered = dict(proof3, results=[False])
        st, r = verify(proof3["proof_id"],
                       {"proof": tampered, "challenge": proof3["challenge"]})
        check("篡改 results -> valid:false",
              st == 200 and r.get("valid") is False)
        tampered = dict(proof3, predicates=[
            {"path": "/age", "op": "gte", "value": 60}])
        st, r = verify(proof3["proof_id"],
                       {"proof": tampered, "challenge": proof3["challenge"]})
        check("篡改 predicates -> valid:false",
              st == 200 and r.get("valid") is False)
        tampered = dict(proof3, proof=proof3["proof"][:-2] + "AA")
        st, r = verify(proof3["proof_id"],
                       {"proof": tampered, "challenge": proof3["challenge"]})
        check("篡改 proof 签名 -> valid:false",
              st == 200 and r.get("valid") is False)
        tampered = dict(proof3, issuer_key_version=2)
        st, r = verify(proof3["proof_id"],
                       {"proof": tampered, "challenge": proof3["challenge"]})
        check("篡改 issuer_key_version -> valid:false",
              st == 200 and r.get("valid") is False)
        tampered = dict(proof3)
        del tampered["expires_at"]
        st, r = verify(proof3["proof_id"],
                       {"proof": tampered, "challenge": proof3["challenge"]})
        check("proof 对象缺字段 -> valid:false",
              st == 200 and r.get("valid") is False)
        st, r = verify(proof3["proof_id"],
                       {"proof": proof3, "challenge": proof3["challenge"]})
        check("篡改尝试均不消费，原证明仍 valid:true",
              st == 200 and r == {"valid": True})

        # 请求体协议：缺 proof/多余字段/非对象/空体均 200 valid:false
        st, r = verify(proof3["proof_id"], {"challenge": "x"})
        check("verify 缺 proof -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = verify(proof3["proof_id"],
                       {"proof": proof3, "challenge": "x", "foo": 1})
        check("verify 多余字段 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = verify(proof3["proof_id"], raw=b"[]")
        check("verify 非对象 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = verify(proof3["proof_id"], raw=b"")
        check("verify 空体 -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = verify(f"zp_{'0'*32}",
                       {"proof": proof3, "challenge": "x"})
        check("未知 proof_id -> 200 valid:false 证明不存在",
              st == 200 and r.get("valid") is False
              and "不存在" in r.get("reason", ""))

        # 过期
        st, r = prove({"predicates": [{"path": "/age", "op": "exists"}],
                       "expires_in": 1})
        assert st == 201, r
        proof_exp = r
        time.sleep(2)
        st, r = verify(proof_exp["proof_id"],
                       {"proof": proof_exp,
                        "challenge": proof_exp["challenge"]})
        check("过期 -> valid:false 证明已过期",
              st == 200 and r.get("valid") is False
              and "已过期" in r.get("reason", ""))

        # 跨租户：他租户验证按不存在处理（200 valid:false）
        st, r = prove({"predicates": [{"path": "/age", "op": "exists"}]})
        assert st == 201, r
        proof4 = r
        st, r = verify(proof4["proof_id"],
                       {"proof": proof4, "challenge": proof4["challenge"]},
                       headers={"X-Tenant-ID": "other"})
        check("跨租户 verify -> 200 valid:false",
              st == 200 and r.get("valid") is False)
        st, r = verify(proof4["proof_id"],
                       {"proof": proof4, "challenge": proof4["challenge"]})
        check("本租户 verify -> valid:true",
              st == 200 and r == {"valid": True})

        # 并发仅一次成功
        st, r = prove({"predicates": [{"path": "/age", "op": "exists"}]})
        assert st == 201, r
        proof5 = r

        def one_verify(_):
            return verify(proof5["proof_id"],
                          {"proof": proof5,
                           "challenge": proof5["challenge"]})

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(one_verify, range(8)))
        valids = [r for st, r in outcomes if st == 200
                  and r.get("valid") is True]
        consumed = [r for st, r in outcomes if st == 200
                    and r.get("valid") is False
                    and "已消费" in r.get("reason", "")]
        check("并发验证仅一次 valid:true",
              len(valids) == 1 and len(consumed) == 7)

        # 审计：proof.created / proof.consumed
        st, r = _http("GET", f"{BASE}/v1/audit?limit=200")
        check("审计查询 200", st == 200)
        created = [e for e in r["events"]
                   if e["action"] == "proof.created"
                   and e["resource_type"] == "predicate_proof"]
        consumed_ev = [e for e in r["events"]
                       if e["action"] == "proof.consumed"
                       and e["resource_type"] == "predicate_proof"]
        check("审计含 proof.created（resource_id 为 proof_id）",
              any(e["resource_id"] == proof1["proof_id"] for e in created)
              and any(e["resource_id"] == proof5["proof_id"]
                      for e in created))
        check("审计 proof.consumed 每次成功消费仅一条",
              len([e for e in consumed_ev
                   if e["resource_id"] == proof5["proof_id"]]) == 1
              and any(e["resource_id"] == proof1["proof_id"]
                      for e in consumed_ev))

        # ---------------- 跨重启保留 ---------------- #
        st, r = prove({"predicates": [{"path": "/age", "op": "exists"}],
                       "challenge": "restart"})
        assert st == 201, r
        proof6 = r
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, r = verify(proof6["proof_id"],
                       {"proof": proof6, "challenge": "restart"})
        check("重启后 verify 仍 valid:true", st == 200 and r == {"valid": True})
        st, r = verify(proof6["proof_id"],
                       {"proof": proof6, "challenge": "restart"})
        check("重启后消费标记保留（已消费）",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
