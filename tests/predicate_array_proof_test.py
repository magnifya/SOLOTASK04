#!/usr/bin/env python3
"""谓词证明数组路径端到端回归测试。

在谓词证明支持数组单值路径后的公开接口回归：

- prove / prove-batch 的 predicates path 仍相对 claims，遵循 RFC6901
  （~0/~1 转义），可穿过对象、数组、嵌套数组与数组元素内对象；
  对象中的数字字符串仍是普通属性名；
- 数组下标只接受 0 或无前导零 ASCII 十进制非负整数：负数、正号、
  前导零、非 ASCII 数字、-、越界、经过标量均 400 且含非空中文 error；
  空字符串根路径、非法转义、未命中属性、重复或祖先后代重叠同样 400，
  兄弟元素路径可共存；
- exists 命中 null 为 true、未命中 400；eq 递归 JSON 比较且区分布尔
  与数字；gte/lte 双方均须非布尔数字否则 400；条件为假正常生成
  false 结果且不影响验真；终点命中整个对象/数组保留整值语义；
- 成功 201 沿用九字段与 ES256 签名覆盖范围，predicates 原样保留，
  results 与谓词同序，不额外返回命中值或原始 claims；
- 本地 verify 按存储 claims 重算新路径结果，首次有效验证消费一次，
  重复返回 200 {"valid":false,"reason":"证明已消费"}，失败不消费；
  重启与签发者轮换后仍按历史密钥验签；
- prove-batch 任一项非法整批 400 且不保存证明、不追加审计；
  未知/跨租户凭证 404，显式空租户头 400；旧对象路径行为不变。

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

PORT = 8971
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

PROOF_KEYS = [
    "proof_id", "credential_id", "issuer_did",
    "issuer_key_version", "predicates", "results",
    "challenge", "expires_at", "proof",
]

failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


def http(method, url, payload=None, headers=None, raw=None):
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


def wait_up():
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def start():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up()
    return proc


def make_did(handle):
    st, r = http("POST", f"{BASE}/v1/dids",
                 {"method": "example", "public_key": handle})
    assert st == 201, r
    return r["did"], r["public_key"]


def main():
    proc = start()
    try:
        issuer, issuer_pem = make_did("arr-issuer")
        holder, _ = make_did("arr-holder")

        claims = {
            "name": "Alice",
            "age": 30,
            "vip": True,
            "tags": ["a", "b", "c"],
            "rows": [
                {"name": "甲", "score": 90, "note": None},
                {"name": "乙", "score": 75},
            ],
            "matrix": [[10, 11], [20, 21, 22]],
            "addr": {"city": "Shanghai", "codes": [200000, 200001]},
            "0": "数字键",
            "a/b": [{"x~y": 7}],
        }
        st, r = http("POST", f"{BASE}/v1/credentials",
                     {"issuer_did": issuer, "subject_did": holder,
                      "claims": claims})
        assert st == 201, r
        cred = r["credential_id"]

        def prove(payload, headers=None, cred_id=cred):
            return http("POST", f"{BASE}/v1/credentials/{cred_id}/prove",
                        payload, headers=headers)

        def batch(items, headers=None, cred_id=cred):
            return http("POST",
                        f"{BASE}/v1/credentials/{cred_id}/prove-batch",
                        {"items": items}, headers=headers)

        def verify(proof, challenge=None):
            return http("POST",
                        f"{BASE}/v1/proofs/{proof['proof_id']}/verify",
                        {"proof": proof,
                         "challenge": proof["challenge"]
                         if challenge is None else challenge})

        def external_verify(proof, pem=issuer_pem):
            unsigned = {k: proof[k] for k in PROOF_KEYS if k != "proof"}
            unsigned["tenant_id"] = "default"
            crypto.verify(unsigned, proof["proof"], pem)

        # ---------- 1. 数组新路径：对象/数组/嵌套/元素内对象 ---------- #
        predicates = [
            {"path": "/tags/0", "op": "eq", "value": "a"},
            {"path": "/rows/1/name", "op": "eq", "value": "乙"},
            {"path": "/rows/0/score", "op": "gte", "value": 60},
            {"path": "/matrix/1/2", "op": "eq", "value": 22},
            {"path": "/matrix/0/1", "op": "lte", "value": 11},
            {"path": "/addr/codes/0", "op": "eq", "value": 200000},
            {"path": "/rows/1/score", "op": "exists"},
            {"path": "/0", "op": "eq", "value": "数字键"},
            {"path": "/a~1b/0/x~0y", "op": "eq", "value": 7},
        ]
        st, r = prove({"predicates": predicates})
        check("数组混合路径 prove -> 201", st == 201)
        check("返回恰九字段且键序固定", list(r.keys()) == PROOF_KEYS)
        check("predicates 原样保留", r.get("predicates") == predicates)
        check("results 与谓词同序全真",
              r.get("results") == [True] * len(predicates))
        check("不额外返回命中值或原始 claims",
              "claims" not in r and "values" not in r
              and "hits" not in r)
        proof_main = r
        try:
            external_verify(proof_main)
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("数组路径证明 ES256 外部可验", sig_ok)

        # 兄弟元素路径共存（同数组不同下标、同元素不同属性）
        st, r = prove({"predicates": [
            {"path": "/tags/0", "op": "exists"},
            {"path": "/tags/1", "op": "exists"},
            {"path": "/rows/0/name", "op": "exists"},
            {"path": "/rows/0/score", "op": "exists"},
        ]})
        check("兄弟元素路径共存 -> 201",
              st == 201 and r.get("results") == [True] * 4)

        # ---------- 2. 终点命中整个对象/数组保留整值语义 ---------- #
        st, r = prove({"predicates": [
            {"path": "/tags", "op": "eq", "value": ["a", "b", "c"]},
            {"path": "/rows/0", "op": "eq",
             "value": {"name": "甲", "score": 90, "note": None}},
            {"path": "/matrix", "op": "exists"},
        ]})
        check("终点命中整个数组/对象元素 -> 201 且递归相等",
              st == 201 and r.get("results") == [True, True, True])

        # ---------- 3. exists 命中 null 为 true；未命中 400 ---------- #
        st, r = prove({"predicates": [
            {"path": "/rows/0/note", "op": "exists"}]})
        check("exists 命中 null -> true",
              st == 201 and r.get("results") == [True])
        st, r = prove({"predicates": [
            {"path": "/rows/1/note", "op": "exists"}]})
        check("exists 未命中 -> 400", st == 400 and bool(r.get("error")))

        # ---------- 4. eq 区分布尔与数字；gte/lte 数值约束 ---------- #
        eval_cases = [
            ({"path": "/matrix/0/0", "op": "eq", "value": True}, False),
            ({"path": "/matrix/0/0", "op": "eq", "value": 10}, True),
            ({"path": "/vip", "op": "eq", "value": 1}, False),
            ({"path": "/rows/0/score", "op": "eq", "value": 90.0}, True),
            ({"path": "/rows/0/score", "op": "gte", "value": 91}, False),
            ({"path": "/tags/0", "op": "eq", "value": "b"}, False),
        ]
        eval_ok = True
        for pred, expected in eval_cases:
            st, r = prove({"predicates": [pred]})
            if not (st == 201 and r.get("results") == [expected]):
                eval_ok = False
        check("eq 布尔/数字区分与假值结果", eval_ok)

        # 条件为假不影响证明验真
        st, r = prove({"predicates": [
            {"path": "/rows/0/score", "op": "gte", "value": 95}]})
        assert st == 201 and r["results"] == [False], r
        proof_false = r
        st, r = verify(proof_false)
        check("假结果证明 verify 仍 valid:true",
              st == 200 and r == {"valid": True})

        # ---------- 5. 400：非法下标/越界/穿标量/根/转义/未命中 ---------- #
        bad_paths = [
            "/tags/-1", "/tags/+1", "/tags/01", "/tags/00", "/tags/-",
            "/tags/٠", "/tags/１", "/tags/1.0", "/tags/ ", "/tags/3",
            "/matrix/0/2", "/matrix/2/0", "/rows/0/score/0",
            "/tags/0/0", "/rows/name", "/rows/0/missing", "/nope/0",
            "/tags~2/0", "/tags/0~", "/a~1b/0/x~0y/0",
        ]
        for bad in bad_paths:
            st, r = prove({"predicates": [{"path": bad, "op": "exists"}]})
            check(f"非法/越界路径 {bad} -> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and bool(r["error"]))
        st, r = prove({"predicates": [{"path": "", "op": "exists"}]})
        check("空字符串根路径 -> 400", st == 400 and bool(r.get("error")))

        # 重复与祖先后代重叠（含数组路径）
        overlap_cases = [
            [{"path": "/tags/0", "op": "exists"},
             {"path": "/tags/0", "op": "exists"}],
            [{"path": "/rows/0", "op": "exists"},
             {"path": "/rows/0/name", "op": "exists"}],
            [{"path": "/rows/0/name", "op": "exists"},
             {"path": "/rows/0", "op": "exists"}],
            [{"path": "/rows", "op": "exists"},
             {"path": "/rows/1/score", "op": "exists"}],
            [{"path": "/matrix/1", "op": "exists"},
             {"path": "/matrix/1/2", "op": "exists"}],
        ]
        for preds in overlap_cases:
            st, r = prove({"predicates": preds})
            check(f"重复/祖先重叠 -> 400",
                  st == 400 and bool(r.get("error")))

        # gte/lte 双方均须非布尔数字
        bad_numeric = [
            {"path": "/rows/0/score", "op": "gte", "value": True},
            {"path": "/rows/0/score", "op": "lte", "value": "90"},
            {"path": "/tags/0", "op": "gte", "value": 1},
            {"path": "/rows/0/note", "op": "lte", "value": 1},
        ]
        for pred in bad_numeric:
            st, r = prove({"predicates": [pred]})
            check(f"数值约束 {pred['op']} -> 400",
                  st == 400 and bool(r.get("error")))

        # ---------- 6. 旧对象路径行为不变 ---------- #
        st, r = prove({"predicates": [
            {"path": "/age", "op": "gte", "value": 18},
            {"path": "/addr/city", "op": "eq", "value": "Shanghai"},
            {"path": "/name", "op": "exists"},
        ]})
        check("旧对象路径 -> 201 全真",
              st == 201 and r.get("results") == [True, True, True])
        st, r = prove({"predicates": [
            {"path": "/addr", "op": "exists"},
            {"path": "/addr/city", "op": "exists"}]})
        check("旧对象路径祖先重叠仍 400",
              st == 400 and bool(r.get("error")))

        # ---------- 7. 未知/跨租户 404，空租户头 400 ---------- #
        st, r = prove({"predicates": [{"path": "/tags/0", "op": "exists"}]},
                      cred_id=f"vc_{'0'*32}")
        check("未知凭证 -> 404", st == 404 and bool(r.get("error")))
        st, r = prove({"predicates": [{"path": "/tags/0", "op": "exists"}]},
                      headers={"X-Tenant-ID": "other"})
        check("跨租户凭证 -> 404", st == 404 and bool(r.get("error")))
        st, r = prove({"predicates": [{"path": "/tags/0", "op": "exists"}]},
                      headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400", st == 400 and bool(r.get("error")))

        # ---------- 8. prove-batch：数组路径与整批回滚 ---------- #
        st, r = batch([
            {"predicates": [
                {"path": "/rows/0/score", "op": "gte", "value": 60},
                {"path": "/matrix/1/2", "op": "eq", "value": 22}]},
            {"predicates": [{"path": "/tags/2", "op": "eq", "value": "c"}],
             "challenge": "arr-batch", "expires_in": 600},
        ])
        check("批量数组路径 -> 201", st == 201 and len(r.get("proofs")) == 2)
        proofs_b = r["proofs"]
        check("批量每项九字段键序固定",
              all(list(p.keys()) == PROOF_KEYS for p in proofs_b))
        check("批量 results 同序",
              proofs_b[0]["results"] == [True, True]
              and proofs_b[1]["results"] == [True])
        check("批量显式 challenge 回显",
              proofs_b[1]["challenge"] == "arr-batch")
        for p in proofs_b:
            try:
                external_verify(p)
                one_sig = True
            except Exception:  # noqa: BLE001
                one_sig = False
            check("批量证明外部可验", one_sig)

        def count_created():
            st2, rr = http("GET", f"{BASE}/v1/audit?limit=200")
            assert st2 == 200
            return sum(1 for e in rr["events"]
                       if e["action"] == "proof.created"
                       and e["tenant_id"] == "default")

        audit_before = count_created()
        st, r = batch([
            {"predicates": [{"path": "/tags/0", "op": "exists"}]},
            {"predicates": [{"path": "/tags/9", "op": "exists"}]},
        ])
        check("批量中非法数组下标 -> 整批 400",
              st == 400 and bool(r.get("error")))
        st, r = batch([
            {"predicates": [{"path": "/rows/0", "op": "exists"},
                            {"path": "/rows/0/name", "op": "exists"}]},
        ])
        check("批量项内祖先重叠 -> 整批 400",
              st == 400 and bool(r.get("error")))
        check("非法批次不追加审计", count_created() == audit_before)
        # 非法批次未保存证明：随后合法批量仍正常
        st, r = batch([{"predicates": [{"path": "/tags/1", "op": "exists"}]}])
        check("回滚后合法批量 -> 201", st == 201)
        check("合法批量恰追加一条审计",
              count_created() == audit_before + 1)

        st, r = batch([{"predicates": [{"path": "/tags/0", "op": "exists"}]}],
                      cred_id=f"vc_{'0'*32}")
        check("批量未知凭证 -> 404", st == 404 and bool(r.get("error")))
        st, r = batch([{"predicates": [{"path": "/tags/0", "op": "exists"}]}],
                      headers={"X-Tenant-ID": ""})
        check("批量显式空租户头 -> 400", st == 400 and bool(r.get("error")))

        # ---------- 9. verify：重算、消费一次、失败不消费 ---------- #
        st, r = prove({"predicates": [
            {"path": "/rows/1/score", "op": "gte", "value": 60},
            {"path": "/matrix/0/0", "op": "eq", "value": 10}]})
        assert st == 201, r
        proof_v = r
        tampered = dict(proof_v, results=[False, True])
        st, r = verify(tampered, proof_v["challenge"])
        check("篡改 results -> valid:false（重算新路径结果）",
              st == 200 and r.get("valid") is False
              and bool(r.get("reason")))
        st, r = verify(proof_v)
        check("失败不消费，原证明 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(proof_v)
        check("重复验证 -> 证明已消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "证明已消费")

        # ---------- 10. 重启与签发者轮换后历史密钥验签 ---------- #
        st, r = prove({"predicates": [
            {"path": "/a~1b/0/x~0y", "op": "eq", "value": 7}]})
        assert st == 201, r
        proof_keep = r
        check("轮换前证明版本为 1", proof_keep["issuer_key_version"] == 1)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        # 重启后未消费证明仍可验真并消费
        st, r = verify(proof_keep)
        check("重启后数组路径证明 verify valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(proof_keep)
        check("重启后消费标记保留",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "证明已消费")

        # 轮换签发者密钥：旧证明按历史密钥验签
        st, r = prove({"predicates": [
            {"path": "/tags/0", "op": "eq", "value": "a"}]})
        assert st == 201, r
        proof_old = r
        st, r = http("POST", f"{BASE}/v1/dids/{issuer}/keys/rotate",
                     {"key_handle": "arr-issuer-v2"})
        assert st == 200, r
        # 轮换后新签发凭证的证明使用新版本密钥
        st, r = http("POST", f"{BASE}/v1/credentials",
                     {"issuer_did": issuer, "subject_did": holder,
                      "claims": {"vals": [5, 6]}})
        assert st == 201, r
        cred_v2 = r["credential_id"]
        st, r = prove({"predicates": [
            {"path": "/vals/1", "op": "eq", "value": 6}]}, cred_id=cred_v2)
        assert st == 201, r
        proof_new = r
        check("轮换后新凭证证明版本为 2",
              proof_new["issuer_key_version"] == 2)
        check("旧凭证轮换后证明仍按签发版本 1",
              proof_old["issuer_key_version"] == 1)
        st, r = verify(proof_old)
        check("轮换后旧证明按历史密钥验签 valid:true",
              st == 200 and r == {"valid": True})
        st, r = verify(proof_new)
        check("轮换后新证明验签 valid:true",
              st == 200 and r == {"valid": True})
        try:
            external_verify(proof_old)
            old_sig_ok = True
        except Exception:  # noqa: BLE001
            old_sig_ok = False
        check("轮换后旧证明仍可用旧公钥外部验真", old_sig_ok)

        # 主证明在轮换后仍可验（尚未消费）
        st, r = verify(proof_main)
        check("主数组路径证明轮换后 verify valid:true",
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
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("谓词证明数组路径回归测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
