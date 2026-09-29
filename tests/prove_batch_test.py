#!/usr/bin/env python3
"""POST /v1/credentials/{id}/prove-batch 端到端验证脚本。"""

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

PORT = 8978
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
    status, resp = http("POST", f"{BASE}/v1/dids",
                        {"method": "example", "public_key": handle})
    assert status == 201, resp
    return resp["did"], resp["public_key"]


def exists_pred(path):
    return {"path": path, "op": "exists"}


def main():
    proc = start()
    try:
        issuer, issuer_pem = make_did("issuer-key")
        holder, _ = make_did("holder-key")

        status, resp = http("POST", f"{BASE}/v1/credentials", {
            "issuer_did": issuer,
            "subject_did": holder,
            "claims": {"name": "alice", "age": 30,
                       "addr": {"city": "SH", "zip": "200000"},
                       "tags": ["a", "b"], "score": 88.5, "vip": True},
        })
        assert status == 201, resp
        cred = resp["credential_id"]

        batch_url = f"{BASE}/v1/credentials/{cred}/prove-batch"

        def batch(items, headers=None):
            return http("POST", batch_url, {"items": items},
                        headers=headers)

        # ---- 1. 成功批量：默认值/显式值/同序/results ---- #
        item1 = [exists_pred("/name"),
                 {"path": "/age", "op": "gte", "value": 18}]
        item4 = [{"path": "/age", "op": "eq", "value": 31},
                 {"path": "/score", "op": "lte", "value": 100}]
        items = [
            {"predicates": item1},
            {"predicates": [exists_pred("/addr/city")],
             "challenge": "chal-2", "expires_in": 60},
            {"predicates": [{"path": "/tags", "op": "eq",
                             "value": ["a", "b"]}],
             "challenge": "混合-挑战", "expires_in": 86400},
            {"predicates": item4},
        ]
        status, resp = batch(items)
        check("批量成功 201", status == 201)
        check("成功仅含 proofs 键", set(resp) == {"proofs"})
        proofs = resp.get("proofs")
        check("返回数量与输入一致",
              isinstance(proofs, list) and len(proofs) == 4)
        check("每项九字段且键序固定",
              all(list(proof.keys()) == PROOF_KEYS for proof in proofs))
        check("results 按项计算且同序",
              proofs[0]["results"] == [True, True]
              and proofs[1]["results"] == [True]
              and proofs[2]["results"] == [True]
              and proofs[3]["results"] == [False, True])
        check("predicates 原样回显",
              proofs[0]["predicates"] == item1
              and proofs[3]["predicates"] == item4)
        check("显式 challenge 回显",
              proofs[1]["challenge"] == "chal-2"
              and proofs[2]["challenge"] == "混合-挑战")
        check("缺省 challenge 各自独立 32hex",
              re.fullmatch(r"[0-9a-f]{32}", proofs[0]["challenge"]) is not None
              and re.fullmatch(r"[0-9a-f]{32}",
                               proofs[3]["challenge"]) is not None
              and proofs[0]["challenge"] != proofs[3]["challenge"])
        check("expires_at 均为 UTC Z 秒精度",
              all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                               proof["expires_at"]) for proof in proofs))
        proof_ids = [proof["proof_id"] for proof in proofs]
        check("proof_id 两两不同且 zp_ 前缀",
              len(set(proof_ids)) == 4
              and all(proof_id.startswith("zp_") for proof_id in proof_ids))
        check("credential_id/issuer_did/版本回显",
              all(proof["credential_id"] == cred
                  and proof["issuer_did"] == issuer
                  and proof["issuer_key_version"] == 1
                  for proof in proofs))

        # ---- 2. 外部 ES256 验签 ---- #
        def external_verify(proof):
            unsigned = {key: proof[key] for key in PROOF_KEYS
                        if key != "proof"}
            unsigned["tenant_id"] = "default"
            crypto.verify(unsigned, proof["proof"], issuer_pem)

        for index, proof in enumerate(proofs):
            try:
                external_verify(proof)
                sig_ok = True
            except Exception as exc:  # noqa: BLE001
                sig_ok = False
                print("   验签异常:", exc)
            check(f"第 {index + 1} 项 ES256 外部可验", sig_ok)

        # ---- 3. 既有 verify 入口逐条可验（一次性消费） ---- #
        for index, proof in enumerate(proofs):
            status2, rr = http(
                "POST", f"{BASE}/v1/proofs/{proof['proof_id']}/verify",
                {"proof": proof, "challenge": proof["challenge"]})
            check(f"第 {index + 1} 项 verify valid:true",
                  status2 == 200 and rr.get("valid") is True)
            status2, rr = http(
                "POST", f"{BASE}/v1/proofs/{proof['proof_id']}/verify",
                {"proof": proof, "challenge": proof["challenge"]})
            check(f"第 {index + 1} 项重复验证已消费",
                  status2 == 200 and rr.get("valid") is False
                  and bool(rr.get("reason")))

        # ---- 4. 请求级非法 -> 400 且不写审计 ---- #
        def count_created():
            status2, rr = http("GET", f"{BASE}/v1/audit?limit=200")
            assert status2 == 200
            return sum(1 for event in rr["events"]
                       if event["action"] == "proof.created"
                       and event["tenant_id"] == "default")

        audit_before = count_created()

        def expect_400(name, payload=None, raw=None, url=batch_url,
                       headers=None):
            status2, rr = http("POST", url, payload, raw=raw,
                               headers=headers)
            check(name, status2 == 400
                  and isinstance(rr.get("error"), str)
                  and bool(rr["error"]))

        expect_400("空体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"{bad")
        expect_400("非对象 JSON -> 400", raw=b"[1,2]")
        expect_400("缺 items -> 400", {"predicates": []})
        expect_400("外层多余字段 -> 400", {"items": [], "x": 1})
        expect_400("items 非数组 -> 400", {"items": {}})
        expect_400("items 空数组 -> 400", {"items": []})
        expect_400("超过 50 项 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")]}
                              for _ in range(51)]})
        expect_400("项非对象 -> 400", {"items": [1]})
        expect_400("项缺 predicates -> 400",
                   {"items": [{"challenge": "c"}]})
        expect_400("项多余字段 -> 400",
                   {"items": [{"predicates": [], "x": 1}]})
        expect_400("项 challenge 空串 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "challenge": ""}]})
        expect_400("项 challenge 非串 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "challenge": 1}]})
        expect_400("项 challenge 超 256 码点 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "challenge": "好" * 257}]})
        expect_400("项 expires_in 布尔 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "expires_in": True}]})
        expect_400("项 expires_in=0 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "expires_in": 0}]})
        expect_400("项 expires_in=86401 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "expires_in": 86401}]})
        expect_400("项 expires_in 串 -> 400",
                   {"items": [{"predicates": [exists_pred("/name")],
                               "expires_in": "60"}]})
        expect_400("显式空 X-Tenant-ID -> 400",
                   {"items": [{"predicates": [exists_pred("/name")]}]},
                   headers={"X-Tenant-ID": ""})

        # ---- 5. store 级谓词非法（整体回滚） ---- #
        expect_400("predicates 空 -> 400",
                   {"items": [{"predicates": []}]})
        expect_400("predicates 非数组 -> 400",
                   {"items": [{"predicates": "/name"}]})
        expect_400("元素缺 op -> 400",
                   {"items": [{"predicates": [{"path": "/name"}]}]})
        expect_400("op 非法 -> 400",
                   {"items": [{"predicates": [
                       {"path": "/age", "op": "gt", "value": 1}]}]})
        expect_400("越界路径 -> 400",
                   {"items": [{"predicates": [exists_pred("/nope")]}]})
        expect_400("项内重复路径 -> 400",
                   {"items": [{"predicates": [
                       exists_pred("/name"), exists_pred("/name")]}]})
        expect_400("项内祖先重叠 -> 400",
                   {"items": [{"predicates": [
                       exists_pred("/addr"),
                       exists_pred("/addr/city")]}]})
        expect_400("gte value 非数字 -> 400",
                   {"items": [{"predicates": [
                       {"path": "/age", "op": "gte", "value": "x"}]}]})
        expect_400("批内后置项非法整体 400",
                   {"items": [
                       {"predicates": [exists_pred("/name")],
                        "challenge": "ok-first"},
                       {"predicates": [exists_pred("/missing")]}]})

        # 先全项请求级校验再查凭证：未知凭证 + 结构非法项 -> 400
        status2, rr = http(
            "POST", f"{BASE}/v1/credentials/vc_nope/prove-batch",
            {"items": [{"predicates": [exists_pred("/name")]},
                       {"expires_in": 0}]})
        check("未知凭证且项非法优先 400", status2 == 400)
        status2, rr = http(
            "POST", f"{BASE}/v1/credentials/vc_nope/prove-batch",
            {"items": [{"predicates": [exists_pred("/name")]}]})
        check("未知凭证 -> 404", status2 == 404
              and "不存在" in rr.get("error", ""))
        status2, rr = batch(
            [{"predicates": [exists_pred("/name")]}],
            headers={"X-Tenant-ID": "tenant-zz"})
        check("跨租户凭证 -> 404", status2 == 404
              and "不存在" in rr.get("error", ""))

        check("全部非法批次均不写审计",
              count_created() == audit_before)

        # 不同项路径互不约束：同路径出现在两项中应成功（不计入回滚检查）
        status2, rr = batch([{"predicates": [exists_pred("/name")]},
                             {"predicates": [exists_pred("/name")]}])
        check("不同项同路径互不约束 -> 201",
              status2 == 201 and len(rr["proofs"]) == 2)

        # ---- 6. challenge 恰好 256 码点 ---- #
        status2, rr = batch([{"predicates": [exists_pred("/name")],
                             "challenge": "好" * 256}])
        check("challenge 恰好 256 码点 -> 201", status2 == 201)
        proof256 = rr["proofs"][0]

        # ---- 7. 状态顺序：停用 409 / 密钥吊销 400 / 暂停 409 ---- #
        serial = {"n": 0}

        def fresh_credential():
            serial["n"] += 1
            iss, _ = make_did(f"issuer-status-{serial['n']}")
            stt, rrr = http("POST", f"{BASE}/v1/credentials", {
                "issuer_did": iss, "subject_did": holder,
                "claims": {"k": 1}})
            assert stt == 201, rrr
            return iss, rrr["credential_id"]

        one = {"items": [{"predicates": [exists_pred("/k")]}]}

        did_suspend, cred_suspend = fresh_credential()
        stt, rrr = http("PUT",
                        f"{BASE}/v1/credentials/{cred_suspend}/status",
                        {"status": "suspended", "reason": "暂停审计"})
        assert stt == 200, rrr
        stt, rrr = http(
            "POST",
            f"{BASE}/v1/credentials/{cred_suspend}/prove-batch", one)
        check("凭证暂停 -> 409", stt == 409 and bool(rrr.get("error")))

        did_revoked_key, cred_revoked_key = fresh_credential()
        stt, rrr = http("POST",
                        f"{BASE}/v1/dids/{did_revoked_key}/keys/rotate",
                        {"key_handle": "revoked-issuer-v2"})
        assert stt == 200, rrr
        stt, rrr = http("POST",
                        f"{BASE}/v1/dids/{did_revoked_key}/keys/1/revoke",
                        {"reason": "换发"})
        assert stt == 200, rrr
        # 密钥吊销优先于暂停：再暂停凭证仍应返回 400
        stt, rrr = http("PUT",
                        f"{BASE}/v1/credentials/{cred_revoked_key}/status",
                        {"status": "suspended", "reason": "暂停审计"})
        assert stt == 200, rrr
        stt, rrr = http(
            "POST",
            f"{BASE}/v1/credentials/{cred_revoked_key}/prove-batch", one)
        check("签发密钥吊销 -> 400（优先于暂停）",
              stt == 400 and bool(rrr.get("error")))

        did_off, cred_off = fresh_credential()
        stt, rrr = http("POST", f"{BASE}/v1/dids/{did_off}/deactivate",
                        {"reason": "停用审计"})
        assert stt == 200, rrr
        # DID 停用优先：同时暂停凭证仍应返回 409
        stt, rrr = http("PUT",
                        f"{BASE}/v1/credentials/{cred_off}/status",
                        {"status": "suspended", "reason": "暂停审计"})
        assert stt == 200, rrr
        stt, rrr = http(
            "POST",
            f"{BASE}/v1/credentials/{cred_off}/prove-batch", one)
        check("签发 DID 停用 -> 409（优先于吊销/暂停）",
              stt == 409 and bool(rrr.get("error")))

        check("状态失败均不写审计",
              count_created() == audit_before + 3)

        # 已吊销凭证仍可批量生成，但 verify 按吊销拒绝
        _, cred_rev = fresh_credential()
        stt, rrr = http("POST",
                        f"{BASE}/v1/credentials/{cred_rev}/revoke",
                        {"reason": "批量吊销用"})
        assert stt == 200, rrr
        stt, rrr = http(
            "POST", f"{BASE}/v1/credentials/{cred_rev}/prove-batch",
            {"items": [{"predicates": [exists_pred("/k")]},
                       {"predicates": [{"path": "/k", "op": "eq",
                                        "value": 1}]}]})
        check("已吊销凭证仍可批量生成 -> 201",
              stt == 201 and len(rrr["proofs"]) == 2)
        # 既有 prove 对已吊销凭证同样可生成；verify 的吊销/过期拒绝
        # 行为属既有入口，由 predicate_proof 既有测试覆盖，保持不变。

        # ---- 8. 审计：每条证明一条 proof.created，顺序与 proofs 一致 ---- #
        stt, rr = http("GET", f"{BASE}/v1/audit?limit=200")
        created = [event["resource_id"] for event in rr["events"]
                   if event["action"] == "proof.created"
                   and event["tenant_id"] == "default"]
        positions = [created.index(pid) for pid in proof_ids]
        check("审计含全部 proof_id",
              all(pid in created for pid in proof_ids))
        check("审计顺序与 proofs 一致", positions == sorted(positions)
              and len(set(positions)) == len(positions))

        # ---- 9. 并发：各批独立 proof_id ---- #
        def fire_batch():
            return batch([{"predicates": [exists_pred("/name")]}
                          for _ in range(10)])

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: fire_batch(), range(2)))
        concurrent_ids = []
        concurrent_ok = True
        for stt, rrr in results:
            if stt != 201 or len(rrr["proofs"]) != 10:
                concurrent_ok = False
            else:
                concurrent_ids.extend(p["proof_id"] for p in rrr["proofs"])
        check("并发两批均 201 且 20 个 proof_id 两两不同",
              concurrent_ok and len(set(concurrent_ids)) == 20)

        # ---- 10. 50 项边界 ---- #
        stt, rr = batch([{"predicates": [exists_pred("/name")]}
                        for _ in range(50)])
        check("恰好 50 项 -> 201",
              stt == 201 and len(rr["proofs"]) == 50)
        check("50 项键序全部固定",
              all(list(proof.keys()) == PROOF_KEYS
                  for proof in rr["proofs"]))
        check("50 项 id 互不相同",
              len({proof["proof_id"] for proof in rr["proofs"]}) == 50)

        # ---- 11. 重启后外部验签与既有 verify 入口 ---- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        for index, proof in enumerate(proofs):
            try:
                external_verify(proof)
                sig_ok = True
            except Exception:  # noqa: BLE001
                sig_ok = False
            check(f"重启后第 {index + 1} 项签名仍可外部验", sig_ok)
        stt, rr = http(
            "POST", f"{BASE}/v1/proofs/{proof256['proof_id']}/verify",
            {"proof": proof256, "challenge": proof256["challenge"]})
        check("重启后证明 verify valid:true",
              stt == 200 and rr.get("valid") is True)
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
        print(f"{len(failures)} 个失败")
        for name in failures:
            print(" -", name)
        return 1
    print("prove-batch 端到端验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
