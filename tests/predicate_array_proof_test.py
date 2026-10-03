#!/usr/bin/env python3
"""谓词证明数组路径端到端回归测试。

覆盖 prove / prove-batch 的 predicates 路径穿过对象、数组、嵌套数组
与数组元素内对象：RFC6901 ~0/~1 转义、合法下标（0 或无前导零 ASCII
十进制）、对象数字字符串按属性名；非法下标（负数、正号、前导零、
非 ASCII 数字、-、越界、经过标量）、空根路径、非法转义、未命中、
重复与祖先/后代重叠均 400 且含非空中文 error，兄弟路径共存；
exists 命中 null 为 true、eq 递归比较且区分布尔与数字、gte/lte
双方须非布尔数字；假条件正常出 false 结果且不影响验真；终点命中
整个对象/数组保留整值语义。本地 verify 重算新路径结果、消费一次、
失败不消费、重启与签发者轮换后按历史密钥验签；跨系统验真/消费/
批量入口接受数组路径证明；批量任一项非法整批 400 不留证明与审计；
未知/跨租户凭证 404、空租户头 400；旧对象路径行为不变。

直接运行：python3 tests/predicate_array_proof_test.py
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

PORT = 8946
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

PROOF_FIELDS = {"proof_id", "credential_id", "issuer_did",
                "issuer_key_version", "predicates", "results",
                "challenge", "expires_at", "proof"}


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
        # ---------------- 准备：DID 与含数组的凭证 ---------------- #
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "pa-issuer"})
        assert st == 201, r
        issuer = r["did"]
        issuer_pem = r["public_key"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "pa-subject"})
        assert st == 201, r
        subject = r["did"]
        claims = {
            "name": "Alice",
            "age": 30,
            "addr": {"city": "Shanghai", "zip": "200000"},
            "tags": ["a", "b", "c"],
            "rows": [
                {"name": "甲", "score": 80},
                {"name": "乙", "score": 90},
            ],
            "matrix": [[1, 2], [3, 4]],
            "mixed": [None, True, {"k": [10, 20]}],
            "0": "数字键",
            "a/b": {"m~n": 7},
        }
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": claims})
        assert st == 201, r
        cred = r["credential_id"]

        def prove(payload, headers=None, credential_id=None):
            return _http(
                "POST",
                f"{BASE}/v1/credentials/{credential_id or cred}/prove",
                payload, headers=headers)

        def prove_batch(payload, headers=None, credential_id=None):
            return _http(
                "POST",
                f"{BASE}/v1/credentials/{credential_id or cred}/prove-batch",
                payload, headers=headers)

        def verify(proof_id, payload, headers=None):
            return _http("POST", f"{BASE}/v1/proofs/{proof_id}/verify",
                         payload, headers=headers)

        def proof_created_audits(headers=None):
            st, r = _http("GET", f"{BASE}/v1/audit?limit=200",
                          headers=headers)
            assert st == 200
            return [e for e in r["events"]
                    if e["action"] == "proof.created"]

        # ---------------- 1. 数组新路径 prove 201 ---------------- #
        predicates = [
            {"path": "/tags/0", "op": "eq", "value": "a"},
            {"path": "/rows/1/name", "op": "eq", "value": "乙"},
            {"path": "/rows/0/score", "op": "gte", "value": 60},
            {"path": "/matrix/1/0", "op": "eq", "value": 3},
            {"path": "/mixed/2/k/1", "op": "lte", "value": 25},
            {"path": "/mixed/0", "op": "exists"},
            {"path": "/a~1b/m~0n", "op": "eq", "value": 7},
            {"path": "/0", "op": "eq", "value": "数字键"},
        ]
        st, r = prove({"predicates": predicates})
        check("数组/嵌套/转义/数字键路径 -> 201", st == 201)
        check("返回恰 9 个字段（不额外返回命中值或 claims）",
              set(r) == PROOF_FIELDS)
        check("predicates 原样保留", r.get("predicates") == predicates)
        check("results 与谓词同序",
              r.get("results") == [True] * len(predicates))
        check("exists 命中 null 为 true", r.get("results")[5] is True)
        proof_arr = r
        unsigned = {k: proof_arr[k] for k in (
            "proof_id", "credential_id", "issuer_did", "issuer_key_version",
            "predicates", "results", "challenge", "expires_at")}
        unsigned["tenant_id"] = "default"
        try:
            crypto.verify(unsigned, proof_arr["proof"], issuer_pem)
            check("数组路径证明 ES256 签名覆盖范围不变", True)
        except Exception:
            check("数组路径证明 ES256 签名覆盖范围不变", False)

        # 兄弟元素路径共存
        st, r = prove({"predicates": [
            {"path": "/rows/0/name", "op": "exists"},
            {"path": "/rows/1/name", "op": "exists"},
            {"path": "/tags/0", "op": "exists"},
            {"path": "/tags/2", "op": "exists"},
        ]})
        check("兄弟元素路径共存 -> 201", st == 201
              and r.get("results") == [True, True, True, True])

        # 终点命中整个数组/对象：整值语义保留
        st, r = prove({"predicates": [
            {"path": "/tags", "op": "eq", "value": ["a", "b", "c"]},
            {"path": "/rows/0", "op": "eq",
             "value": {"name": "甲", "score": 80}},
            {"path": "/matrix", "op": "exists"},
        ]})
        check("终点命中整个数组/对象保留整值语义",
              st == 201 and r.get("results") == [True, True, True])

        # eq 递归比较且区分布尔与数字
        st, r = prove({"predicates": [
            {"path": "/mixed/1", "op": "eq", "value": True}]})
        check("eq 布尔命中布尔 -> true", st == 201
              and r.get("results") == [True])
        st, r = prove({"predicates": [
            {"path": "/mixed/1", "op": "eq", "value": 1}]})
        check("eq 布尔与数字不互通 -> false", st == 201
              and r.get("results") == [False])
        st, r = prove({"predicates": [
            {"path": "/matrix/0", "op": "eq", "value": [1, 2]}]})
        check("eq 数组递归比较 -> true", st == 201
              and r.get("results") == [True])

        # 条件为假：正常生成 false 结果
        st, r = prove({"predicates": [
            {"path": "/rows/0/score", "op": "gte", "value": 100}]})
        check("假条件 -> 201 且 results 为 false", st == 201
              and r.get("results") == [False])
        proof_false = r

        # 旧对象路径行为不变
        st, r = prove({"predicates": [
            {"path": "/age", "op": "gte", "value": 18},
            {"path": "/addr/city", "op": "eq", "value": "Shanghai"},
        ]})
        check("旧对象路径不变 -> 201 全真",
              st == 201 and r.get("results") == [True, True])

        # ---------------- 2. 数组路径 400 协议 ---------------- #
        bad_paths = [
            ("空字符串根路径", ""),
            ("斜杠根路径", "/"),
            ("非法转义 ~2", "/a~2b"),
            ("非法转义末尾 ~", "/a~"),
            ("未命中属性", "/nope"),
            ("数组未命中属性", "/rows/0/nope"),
            ("负数下标", "/tags/-1"),
            ("正号下标", "/tags/+1"),
            ("前导零下标", "/tags/01"),
            ("非 ASCII 数字下标", "/tags/٠"),
            ("横杠下标", "/tags/-"),
            ("越界下标", "/tags/3"),
            ("嵌套数组越界", "/matrix/5/0"),
            ("经过标量", "/tags/0/0"),
            ("经过数字标量", "/age/0"),
        ]
        for name, path in bad_paths:
            st, r = prove({"predicates": [{"path": path, "op": "exists"}]})
            check(f"prove 400: {name}",
                  st == 400 and bool(r.get("error")))

        overlap_bodies = [
            ("数组路径重复", [
                {"path": "/tags/0", "op": "exists"},
                {"path": "/tags/0", "op": "eq", "value": "a"}]),
            ("数组祖先覆盖后代", [
                {"path": "/rows/1", "op": "exists"},
                {"path": "/rows/1/name", "op": "exists"}]),
            ("数组后代被祖先覆盖", [
                {"path": "/rows/1/name", "op": "exists"},
                {"path": "/rows/1", "op": "exists"}]),
            ("数组与对象混合重叠", [
                {"path": "/rows", "op": "exists"},
                {"path": "/rows/0/score", "op": "gte", "value": 1}]),
        ]
        for name, preds in overlap_bodies:
            st, r = prove({"predicates": preds})
            check(f"prove 400: {name}", st == 400 and bool(r.get("error")))

        numeric_bodies = [
            ("gte value 非数字",
             [{"path": "/rows/0/score", "op": "gte", "value": "80"}]),
            ("gte value 布尔",
             [{"path": "/rows/0/score", "op": "gte", "value": True}]),
            ("gte 命中字符串",
             [{"path": "/tags/0", "op": "gte", "value": 1}]),
            ("lte 命中布尔",
             [{"path": "/mixed/1", "op": "lte", "value": 1}]),
            ("lte 命中 null",
             [{"path": "/mixed/0", "op": "lte", "value": 1}]),
            ("gte 命中数组",
             [{"path": "/matrix/0", "op": "gte", "value": 1}]),
        ]
        for name, preds in numeric_bodies:
            st, r = prove({"predicates": preds})
            check(f"prove 400: {name}", st == 400 and bool(r.get("error")))

        # 未知/跨租户凭证 404、空租户头 400
        st, r = prove({"predicates": [{"path": "/tags/0", "op": "exists"}]},
                      credential_id=f"vc_{'0'*32}")
        check("prove 未知凭证 -> 404", st == 404 and bool(r.get("error")))
        st, r = prove({"predicates": [{"path": "/tags/0", "op": "exists"}]},
                      headers={"X-Tenant-ID": "other"})
        check("prove 跨租户凭证 -> 404", st == 404 and bool(r.get("error")))
        st, r = prove({"predicates": [{"path": "/tags/0", "op": "exists"}]},
                      headers={"X-Tenant-ID": ""})
        check("prove 空租户头 -> 400", st == 400 and bool(r.get("error")))

        # ---------------- 3. prove-batch 数组路径 ---------------- #
        st, r = prove_batch({"items": [
            {"predicates": [{"path": "/tags/1", "op": "eq", "value": "b"}]},
            {"predicates": [
                {"path": "/rows/1/score", "op": "gte", "value": 90}],
             "challenge": "pb-1", "expires_in": 600},
            {"predicates": [{"path": "/matrix/0/1", "op": "exists"}]},
        ]})
        check("prove-batch 数组路径 -> 201", st == 201)
        check("prove-batch 等长同序、每项恰 9 字段",
              isinstance(r.get("proofs"), list) and len(r["proofs"]) == 3
              and all(set(p) == PROOF_FIELDS for p in r["proofs"])
              and [p["results"] for p in r["proofs"]]
              == [[True], [True], [True]]
              and r["proofs"][1]["challenge"] == "pb-1")

        # 任一项非法 -> 整批 400，不保存证明、不追加审计
        audits_before = len(proof_created_audits())
        st, r = prove_batch({"items": [
            {"predicates": [{"path": "/tags/0", "op": "exists"}]},
            {"predicates": [{"path": "/tags/99", "op": "exists"}]},
        ]})
        check("prove-batch 任一项非法 -> 整批 400",
              st == 400 and bool(r.get("error")))
        check("prove-batch 400 不保存证明不追加审计",
              len(proof_created_audits()) == audits_before)

        st, r = prove_batch(
            {"items": [{"predicates": [{"path": "/tags/0", "op": "exists"}]}]},
            credential_id=f"vc_{'0'*32}")
        check("prove-batch 未知凭证 -> 404",
              st == 404 and bool(r.get("error")))
        st, r = prove_batch(
            {"items": [{"predicates": [{"path": "/tags/0", "op": "exists"}]}]},
            headers={"X-Tenant-ID": "other"})
        check("prove-batch 跨租户凭证 -> 404",
              st == 404 and bool(r.get("error")))
        st, r = prove_batch(
            {"items": [{"predicates": [{"path": "/tags/0", "op": "exists"}]}]},
            headers={"X-Tenant-ID": ""})
        check("prove-batch 空租户头 -> 400",
              st == 400 and bool(r.get("error")))

        # ---------------- 4. 本地 verify 重算新路径 ---------------- #
        st, r = verify(proof_arr["proof_id"],
                       {"proof": proof_arr,
                        "challenge": proof_arr["challenge"]})
        check("数组路径证明 verify -> valid:true（消费一次）",
              st == 200 and r == {"valid": True})
        st, r = verify(proof_arr["proof_id"],
                       {"proof": proof_arr,
                        "challenge": proof_arr["challenge"]})
        check("重复 verify -> 200 证明已消费",
              st == 200
              and r == {"valid": False, "reason": "证明已消费"})

        # false 结果不影响验真结论
        st, r = verify(proof_false["proof_id"],
                       {"proof": proof_false,
                        "challenge": proof_false["challenge"]})
        check("false 结果证明验真仍 valid:true",
              st == 200 and r == {"valid": True})

        # 失败不消费：错 challenge 后纠正仍有效
        st, r = prove({"predicates": [
            {"path": "/rows/1/score", "op": "lte", "value": 90}]})
        assert st == 201, r
        proof_keep = r
        st, r = verify(proof_keep["proof_id"],
                       {"proof": proof_keep, "challenge": "wrong"})
        check("错 challenge -> valid:false 且不消费",
              st == 200 and r.get("valid") is False
              and bool(r.get("reason")))
        tampered = dict(proof_keep, results=[False])
        st, r = verify(proof_keep["proof_id"],
                       {"proof": tampered,
                        "challenge": proof_keep["challenge"]})
        check("篡改 results -> valid:false 且不消费",
              st == 200 and r.get("valid") is False)
        st, r = verify(proof_keep["proof_id"],
                       {"proof": proof_keep,
                        "challenge": proof_keep["challenge"]})
        check("失败不消费，纠正后 valid:true",
              st == 200 and r == {"valid": True})

        # ---------------- 5. 重启与签发者轮换 ---------------- #
        st, r = prove({"predicates": [
            {"path": "/matrix/1/1", "op": "eq", "value": 4}],
            "challenge": "restart-arr"})
        assert st == 201, r
        proof_restart = r
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, r = verify(proof_restart["proof_id"],
                       {"proof": proof_restart, "challenge": "restart-arr"})
        check("重启后数组路径证明仍 valid:true",
              st == 200 and r == {"valid": True})

        # 轮换签发者密钥：旧版本证明按历史密钥验签
        st, rot = _http("POST", f"{BASE}/v1/dids/{issuer}/keys/rotate",
                        {"key_handle": "pa-issuer-2"})
        check("签发者轮换 -> 200", st == 200 and rot.get("key_version") == 2)
        issuer_pem_v2 = rot["public_key"]
        st, r = prove({"predicates": [
            {"path": "/tags/2", "op": "eq", "value": "c"}],
            "challenge": "rot-old"})
        assert st == 201, r
        proof_v1 = r
        check("轮换后旧凭证证明仍用版本 1 签名",
              proof_v1.get("issuer_key_version") == 1)
        st, r = verify(proof_v1["proof_id"],
                       {"proof": proof_v1, "challenge": "rot-old"})
        check("轮换后历史密钥验签 valid:true",
              st == 200 and r == {"valid": True})
        # 轮换后新签凭证为版本 2，数组路径证明同样可验
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"vals": [5, 6]}})
        assert st == 201, r
        cred2 = r["credential_id"]
        st, r = prove({"predicates": [
            {"path": "/vals/1", "op": "gte", "value": 6}]},
            credential_id=cred2)
        assert st == 201, r
        proof_v2 = r
        check("新凭证证明用版本 2 签名",
              proof_v2.get("issuer_key_version") == 2)
        st, r = verify(proof_v2["proof_id"],
                       {"proof": proof_v2,
                        "challenge": proof_v2["challenge"]})
        check("版本 2 数组路径证明 valid:true",
              st == 200 and r == {"valid": True})

        # ---------------- 6. 跨系统入口接受数组路径证明 ---------------- #
        t2 = {"X-Tenant-ID": "pa-verifier"}
        st, r = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": issuer, "public_key": issuer_pem,
                       "key_version": 1}, headers=t2)
        check("注册版本 1 锚点 -> 201", st == 201)
        st, r = _http("POST", f"{BASE}/v1/trust/anchors",
                      {"did": issuer, "public_key": issuer_pem_v2,
                       "key_version": 2}, headers=t2)
        check("注册版本 2 锚点 -> 201", st == 201)

        # 重新生成未消费的数组路径证明用于跨系统验证
        st, r = prove({"predicates": [
            {"path": "/rows/0/name", "op": "eq", "value": "甲"},
            {"path": "/mixed/2/k/0", "op": "gte", "value": 10}],
            "challenge": "cross-1"})
        assert st == 201, r
        proof_cross = r
        cross_req = {"proof": proof_cross, "challenge": "cross-1",
                     "source_tenant_id": "default"}
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/verify",
                      cross_req, headers=t2)
        check("跨系统验真数组路径证明 -> valid:true",
              st == 200 and r == {"valid": True})
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/verify-batch",
                      {"proofs": [cross_req]}, headers=t2)
        check("跨系统批量验真 -> results 同序有效",
              st == 200 and r.get("results") == [{"valid": True}])
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/consume",
                      cross_req, headers=t2)
        check("跨系统首次消费 -> valid:true",
              st == 200 and r.get("valid") is True)
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/consume",
                      cross_req, headers=t2)
        check("跨系统重复消费 -> 外部证明已消费",
              st == 200
              and r == {"valid": False, "reason": "外部证明已消费"})
        # 只读验真不受消费影响
        st, r = _http("POST", f"{BASE}/v1/trust/proofs/verify",
                      cross_req, headers=t2)
        check("消费后只读验真仍 valid:true",
              st == 200 and r == {"valid": True})
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
