#!/usr/bin/env python3
"""谓词证明端到端测试：prove 签发与 proofs verify 核验。

直接运行：python3 tests/predicate_proof_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402


def _http(method, url, payload=None, tenant=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None
    )
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if tenant is not None:
        req.add_header("X-Tenant-ID", tenant)
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


def main():
    port = 8945
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

        # 准备：两个 DID 与一份凭证
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "issuer-key"})
        issuer = r["did"]
        issuer_pub = r["public_key"]
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "holder-key"})
        holder = r["did"]
        claims = {
            "age": 30,
            "score": 88,
            "name": "ann",
            "vip": True,
            "addr": {"city": "sh", "zip": "200000"},
            "tags": ["a", "b"],
        }
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": holder,
                       "claims": claims})
        check("签发凭证 -> 201", st == 201)
        cid = r["credential_id"]

        predicates = [
            {"path": "/age", "op": "gte", "value": 18},
            {"path": "/score", "op": "lte", "value": 100},
            {"path": "/name", "op": "eq", "value": "ann"},
            {"path": "/vip", "op": "eq", "value": False},
            {"path": "/addr/city", "op": "exists"},
        ]

        # 1. prove 成功：201 与全部字段
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": predicates})
        check("prove -> 201", st == 201)
        check("proof_id 为 zp_ 加 32 位小写 hex",
              bool(re.fullmatch(r"zp_[0-9a-f]{32}", r.get("proof_id", ""))))
        check("prove 回显 credential_id/issuer_did",
              r.get("credential_id") == cid and r.get("issuer_did") == issuer)
        check("prove issuer_key_version=1", r.get("issuer_key_version") == 1)
        check("prove predicates 原样回显", r.get("predicates") == predicates)
        check("results 同序布尔",
              r.get("results") == [True, True, True, False, True])
        check("challenge 缺省为 32 位小写 hex",
              bool(re.fullmatch(r"[0-9a-f]{32}", r.get("challenge", ""))))
        check("expires_at 为 Z 结尾秒精度",
              bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                                r.get("expires_at", ""))))
        check("proof 为 base64url 无填充 64 字节签名",
              bool(re.fullmatch(r"[A-Za-z0-9_-]{86}", r.get("proof", ""))))
        proof_obj = {k: r[k] for k in (
            "proof_id", "credential_id", "issuer_did", "issuer_key_version",
            "predicates", "results", "challenge", "expires_at", "proof")}
        pid = r["proof_id"]

        # 1.1 签名可独立验真：覆盖余字段 JSON + tenant
        unsigned = dict(proof_obj)
        unsigned.pop("proof")
        unsigned["tenant_id"] = "default"
        try:
            crypto.verify(unsigned, proof_obj["proof"], issuer_pub)
            sig_ok = True
        except Exception:
            sig_ok = False
        check("proof 签名覆盖余字段+tenant 且可验真", sig_ok)

        # 1.2 自定义 challenge/expires_in
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": [{"path": "/age", "op": "gte", "value": 1}],
                       "challenge": "my-challenge", "expires_in": 60})
        check("prove 自定义 challenge/expires_in -> 201",
              st == 201 and r.get("challenge") == "my-challenge")

        # 2. prove 字段校验 -> 400
        bad_bodies = [
            ("缺 predicates", {}),
            ("predicates 空数组", {"predicates": []}),
            ("predicates 非数组", {"predicates": "/age"}),
            ("元素非对象", {"predicates": ["/age"]}),
            ("缺 path", {"predicates": [{"op": "exists"}]}),
            ("缺 op", {"predicates": [{"path": "/age"}]}),
            ("op 非法", {"predicates": [{"path": "/age", "op": "gt", "value": 1}]}),
            ("exists 禁 value",
             {"predicates": [{"path": "/age", "op": "exists", "value": 1}]}),
            ("eq 缺 value", {"predicates": [{"path": "/age", "op": "eq"}]}),
            ("元素多余字段",
             {"predicates": [{"path": "/age", "op": "eq", "value": 1, "x": 1}]}),
            ("根路径", {"predicates": [{"path": "", "op": "exists"}]}),
            ("路径不以 / 开头",
             {"predicates": [{"path": "age", "op": "exists"}]}),
            ("数组索引",
             {"predicates": [{"path": "/tags/0", "op": "exists"}]}),
            ("越界路径", {"predicates": [{"path": "/nope", "op": "exists"}]}),
            ("路径重复",
             {"predicates": [{"path": "/age", "op": "exists"},
                             {"path": "/age", "op": "eq", "value": 30}]}),
            ("祖先重叠",
             {"predicates": [{"path": "/addr", "op": "exists"},
                             {"path": "/addr/city", "op": "exists"}]}),
            ("gte value 非数字",
             {"predicates": [{"path": "/age", "op": "gte", "value": "18"}]}),
            ("gte value 布尔",
             {"predicates": [{"path": "/age", "op": "gte", "value": True}]}),
            ("gte claims 非数字",
             {"predicates": [{"path": "/name", "op": "gte", "value": 1}]}),
            ("challenge 空串",
             {"predicates": [{"path": "/age", "op": "exists"}], "challenge": ""}),
            ("challenge 超 256 码点",
             {"predicates": [{"path": "/age", "op": "exists"}],
              "challenge": "x" * 257}),
            ("expires_in 布尔",
             {"predicates": [{"path": "/age", "op": "exists"}],
              "expires_in": True}),
            ("expires_in 越界",
             {"predicates": [{"path": "/age", "op": "exists"}],
              "expires_in": 86401}),
            ("多余字段",
             {"predicates": [{"path": "/age", "op": "exists"}], "foo": 1}),
        ]
        for name, body in bad_bodies:
            st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove", body)
            check(f"prove {name} -> 400", st == 400 and "error" in r)

        # 2.1 未知凭证 -> 404；他租户凭证 -> 404
        st, r = _http("POST", f"{base}/v1/credentials/vc_none/prove",
                      {"predicates": [{"path": "/age", "op": "exists"}]})
        check("prove 未知凭证 -> 404", st == 404)
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": [{"path": "/age", "op": "exists"}]},
                      tenant="other")
        check("prove 他租户凭证 -> 404", st == 404)

        # 3. verify 成功：{"valid": true}
        st, r = _http("POST", f"{base}/v1/proofs/{pid}/verify",
                      {"proof": proof_obj, "challenge": proof_obj["challenge"]})
        check("verify -> 200 valid:true", st == 200 and r == {"valid": True})

        # 3.1 已消费：第二次核验 valid:false 且 reason 非空中文
        st, r = _http("POST", f"{base}/v1/proofs/{pid}/verify",
                      {"proof": proof_obj, "challenge": proof_obj["challenge"]})
        check("重复 verify -> valid:false 已消费",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

        # 3.2 审计：proof.created 与 proof.consumed 各一条
        st, r = _http("GET", f"{base}/v1/audit?limit=200")
        acts = [(e["action"], e["resource_type"], e["resource_id"])
                for e in r["events"]]
        check("审计含 proof.created/predicate_proof",
              ("proof.created", "predicate_proof", pid) in acts)
        check("审计含 proof.consumed/predicate_proof",
              ("proof.consumed", "predicate_proof", pid) in acts)
        check("proof.consumed 仅一条",
              acts.count(("proof.consumed", "predicate_proof", pid)) == 1)

        # 4. 失败不耗：先错挑战失败，再正挑战成功
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
                       "challenge": "ch-4"})
        p4 = {k: r[k] for k in proof_obj}
        p4id = r["proof_id"]
        st, r = _http("POST", f"{base}/v1/proofs/{p4id}/verify",
                      {"proof": p4, "challenge": "wrong"})
        check("错误 challenge -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/{p4id}/verify",
                      {"proof": p4, "challenge": "ch-4"})
        check("失败不耗：纠正后 valid:true", st == 200 and r == {"valid": True})

        # 5. 篡改与请求非法 -> 200 valid:false
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": [{"path": "/name", "op": "eq", "value": "ann"}],
                       "challenge": "ch-5"})
        p5 = {k: r[k] for k in proof_obj}
        p5id = r["proof_id"]
        tampered = dict(p5, results=[False])
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"proof": tampered, "challenge": "ch-5"})
        check("篡改 results -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"proof": p5})
        check("缺 challenge -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"challenge": "ch-5"})
        check("缺 proof -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"proof": p5, "challenge": "ch-5", "x": 1})
        check("多余字段 -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"proof": dict(p5, proof="AAAA"), "challenge": "ch-5"})
        check("签名格式错误 -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/zp_none/verify",
                      {"proof": p5, "challenge": "ch-5"})
        check("未知证明 -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"proof": p5, "challenge": "ch-5"}, tenant="other")
        check("他租户证明 -> valid:false",
              st == 200 and r.get("valid") is False and r.get("reason"))
        # 以上失败均不消费，正确核验仍成功
        st, r = _http("POST", f"{base}/v1/proofs/{p5id}/verify",
                      {"proof": p5, "challenge": "ch-5"})
        check("系列失败后正确核验 valid:true",
              st == 200 and r == {"valid": True})

        # 6. 过期：expires_in=1，等待后核验 -> 证明已过期
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": [{"path": "/age", "op": "exists"}],
                       "challenge": "ch-6", "expires_in": 1})
        p6 = {k: r[k] for k in proof_obj}
        p6id = r["proof_id"]
        time.sleep(1.3)
        st, r = _http("POST", f"{base}/v1/proofs/{p6id}/verify",
                      {"proof": p6, "challenge": "ch-6"})
        check("过期 -> valid:false 已过期",
              st == 200 and r.get("valid") is False
              and "已过期" in r.get("reason", ""))

        # 7. 凭证吊销后核验 -> 凭证已吊销
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": holder,
                       "claims": {"age": 20}})
        cid7 = r["credential_id"]
        st, r = _http("POST", f"{base}/v1/credentials/{cid7}/prove",
                      {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
                       "challenge": "ch-7"})
        p7 = {k: r[k] for k in proof_obj}
        p7id = r["proof_id"]
        _http("POST", f"{base}/v1/credentials/{cid7}/revoke",
              {"reason": "测试吊销"})
        st, r = _http("POST", f"{base}/v1/proofs/{p7id}/verify",
                      {"proof": p7, "challenge": "ch-7"})
        check("凭证已吊销 -> valid:false",
              st == 200 and r.get("valid") is False
              and "已吊销" in r.get("reason", ""))

        # 8. 并发核验：仅一次成功
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/prove",
                      {"predicates": [{"path": "/age", "op": "gte", "value": 18}],
                       "challenge": "ch-8"})
        p8 = {k: r[k] for k in proof_obj}
        p8id = r["proof_id"]
        outcomes = []

        def race():
            s8, r8 = _http("POST", f"{base}/v1/proofs/{p8id}/verify",
                           {"proof": p8, "challenge": "ch-8"})
            outcomes.append(r8.get("valid") is True)

        threads = [threading.Thread(target=race) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("并发核验仅一次成功", outcomes.count(True) == 1)

        # 9. 跨重启持久：重启服务后已消费状态保留
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务重启超时"
        st, r = _http("POST", f"{base}/v1/proofs/{p8id}/verify",
                      {"proof": p8, "challenge": "ch-8"})
        check("重启后已消费保留",
              st == 200 and r.get("valid") is False
              and "已消费" in r.get("reason", ""))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"共 {len(failures)} 项失败")
        return 1
    print("谓词证明测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
