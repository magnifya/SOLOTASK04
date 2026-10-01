#!/usr/bin/env python3
"""密钥轮换可独立验证证明的端到端测试。

覆盖：
- 每次成功轮换原子写入 12 字段证明；首条 previous_proof_digest 为 null，
  后续等于上一条 proof_digest；from_proof/to_proof 分别为旧、新私钥对
  去掉三个 proof 字段记录的 ES256 签名；proof_digest 为含两个 proof、
  不含自身记录的 SHA-256 小写 hex；
- GET /v1/dids/{did}/keys/rotations?limit=&after=：恰 did/events/
  next_after，分页语义与 keys/history 一致（游标为 to_key_version），
  空页表示尚无证明；未知/跨租户 DID 404；非法参数与空租户头 400；
- POST /v1/dids/rotation-proofs/verify：自版本 1 起连续链成功；
  篡改按 DID 不一致、版本不连续、前序摘要不匹配、记录摘要不匹配、
  旧钥签名失败、新钥签名失败排序返回 200+valid:false；
- 缺字段、非法 JSON、数组非 1..100 个对象、空 X-Tenant-ID 等 400；
- 旧钥事后吊销不使证明失效；只读不记审计；
- 重启后证明稳定；升级前无证明版本不补造，新证明链从头开始；
- 落盘失败全回滚（版本、文档、历史、审计、证明均不变）；
- 失败轮换（句柄重复 400）不写证明。

直接运行：python3 tests/key_rotation_proofs_test.py
"""

import copy
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

PORT = 8957
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

LIST_FIELDS = {"did", "events", "next_after"}
PROOF_FIELDS = {
    "did",
    "from_key_version",
    "to_key_version",
    "from_key_handle",
    "to_key_handle",
    "from_public_key",
    "to_public_key",
    "rotated_at",
    "previous_proof_digest",
    "from_proof",
    "to_proof",
    "proof_digest",
}
SIGNED_FIELDS = [
    "did",
    "from_key_version",
    "to_key_version",
    "from_key_handle",
    "to_key_handle",
    "from_public_key",
    "to_public_key",
    "rotated_at",
    "previous_proof_digest",
]
DIGEST_FIELDS = SIGNED_FIELDS + ["from_proof", "to_proof"]


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


def start_server(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def independent_check(proof):
    """不依赖服务端，按规范独立核验单条证明。"""
    signed = {key: proof[key] for key in SIGNED_FIELDS}
    crypto.verify(signed, proof["from_proof"], proof["from_public_key"])
    crypto.verify(signed, proof["to_proof"], proof["to_public_key"])
    digest_body = {key: proof[key] for key in DIGEST_FIELDS}
    digest = __import__("hashlib").sha256(
        crypto.canonicalize(digest_body)
    ).hexdigest()
    assert digest == proof["proof_digest"]


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "rp-a"}
    T2 = {"X-Tenant-ID": "rp-b"}

    def rotations(did, headers=None, query=None):
        url = f"{base}/v1/dids/{did}/keys/rotations"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    def verify(payload, headers=None, raw=None):
        return _http(
            "POST", f"{base}/v1/dids/rotation-proofs/verify",
            payload=payload, headers=headers, raw=raw,
        )

    try:
        # ---- 准备：A 轮换两次（v2、v3），B 仅轮换一次，C 在 T2 不轮换 ----
        st, a = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "rp-handle-a"}, headers=T1,
        )
        assert st == 201, a
        did_a = a["did"]
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
            {"key_handle": "rp-handle-a-v2"}, headers=T1,
        )
        assert st == 200
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
            {"key_handle": "rp-handle-a-v3"}, headers=T1,
        )
        assert st == 200

        st, b = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "rp-handle-b"}, headers=T1,
        )
        assert st == 201, b
        did_b = b["did"]
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_b}/keys/rotate",
            {"key_handle": "rp-handle-b-v2"}, headers=T1,
        )
        assert st == 200

        st, c = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": "rp-handle-c"}, headers=T2,
        )
        assert st == 201, c
        did_c = c["did"]

        # ---- 1. 列表：恰三字段，事件恰 12 字段，哈希链与双签成立 ----
        st, h = rotations(did_a, headers=T1)
        ok_shape = False
        proofs = []
        if st == 200 and set(h) == LIST_FIELDS and h["did"] == did_a:
            proofs = h["events"]
            ok_shape = (
                len(proofs) == 2
                and all(set(p) == PROOF_FIELDS for p in proofs)
                and [p["to_key_version"] for p in proofs] == [2, 3]
                and [p["from_key_version"] for p in proofs] == [1, 2]
                and proofs[0]["previous_proof_digest"] is None
                and proofs[1]["previous_proof_digest"]
                == proofs[0]["proof_digest"]
                and all(
                    HEX64_RE.match(p["proof_digest"])
                    and bool(Z_RE.match(p["rotated_at"]))
                    for p in proofs
                )
                and proofs[0]["from_key_handle"] == "rp-handle-a"
                and proofs[0]["to_key_handle"] == "rp-handle-a-v2"
                and proofs[1]["from_key_handle"] == "rp-handle-a-v2"
                and proofs[1]["to_key_handle"] == "rp-handle-a-v3"
                and h["next_after"] == 3
                and "private" not in json.dumps(h)
            )
        check("rotations 列表字段/版本/链/摘要形状正确", ok_shape)

        independent_ok = True
        try:
            for p in proofs:
                independent_check(p)
        except Exception as exc:  # noqa: BLE001
            independent_ok = False
            print("   独立核验异常:", exc)
        check("独立按规范核验双签与记录摘要均成立", independent_ok)

        # ---- 2. 尚无证明的 DID 空页 ----
        st, h0 = rotations(did_c, headers=T2)
        check(
            "无证明 DID 返回空页、next_after=0",
            st == 200 and h0 == {"did": did_c, "events": [],
                                 "next_after": 0},
        )

        # 未知 / 跨租户 404；空租户头 400
        st, _ = rotations(
            "did:example:00000000000000000000000000000000", headers=T1)
        check("未知 DID rotations -> 404", st == 404)
        st, _ = rotations(did_a, headers=T2)
        check("跨租户 rotations 不可探测 -> 404", st == 404)
        st, r = rotations(did_a, headers={"X-Tenant-ID": ""})
        check("显式空租户头 rotations -> 400", st == 400
              and isinstance(r.get("error"), str) and r["error"])

        # ---- 3. 分页（游标为 to_key_version，语义同 keys/history）----
        st, pg = rotations(did_a, headers=T1, query="limit=1")
        check("limit=1 仅返回首项、next_after=2",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["to_key_version"] == 2
              and pg["next_after"] == 2)
        st, pg = rotations(did_a, headers=T1, query="limit=1&after=2")
        check("after=2 排除首项",
              st == 200 and len(pg["events"]) == 1
              and pg["events"][0]["to_key_version"] == 3
              and pg["next_after"] == 3)
        st, pg = rotations(did_a, headers=T1, query="after=9")
        check("越界 after 空页保持 after",
              st == 200 and pg["events"] == [] and pg["next_after"] == 9)
        st, _ = rotations(did_a, headers=T1, query="limit=200")
        check("limit=200 合法", st == 200)

        def q_400(query, name):
            st, r = rotations(did_a, headers=T1, query=query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        q_400("limit=0", "limit=0 -> 400")
        q_400("limit=201", "limit=201 -> 400")
        q_400("limit=-1", "limit=-1 -> 400")
        q_400("limit=1.5", "limit=1.5 -> 400")
        q_400("limit=true", "limit=true -> 400")
        q_400("limit=", "空 limit -> 400")
        q_400("limit=%20", "空白 limit -> 400")
        q_400("limit=abc", "字母 limit -> 400")
        q_400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        q_400("limit=1&limit=2", "重复 limit -> 400")
        q_400("after=-1", "after=-1 -> 400")
        q_400("after=1.0", "after=1.0 -> 400")
        q_400("after=abc", "字母 after -> 400")
        q_400("after=", "空 after -> 400")
        q_400("after=0&after=1", "重复 after -> 400")

        # ---- 4. verify：完整链与自版本 1 起前缀均合法 ----
        st, r = verify({"did": did_a, "rotations": proofs}, headers=T1)
        check("完整链 verify 200 valid:true", st == 200 and r == {"valid": True})
        st, r = verify({"did": did_a, "rotations": proofs[:1]}, headers=T1)
        check("自版本 1 起的前缀合法", st == 200 and r == {"valid": True})
        # 证明自包含：换租户头验真结论不变
        st, r = verify({"did": did_a, "rotations": proofs}, headers=T2)
        check("verify 仅凭提交内容、跨租户结论不变",
              st == 200 and r == {"valid": True})

        # 不从版本 1 开始 -> 版本不连续
        st, r = verify({"did": did_a, "rotations": proofs[1:]}, headers=T1)
        check("缺首条记录 -> 200 版本不连续",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "版本不连续")

        # ---- 5. 篡改原因按固定优先级排序 ----
        def tamper(rows, fn):
            rows = copy.deepcopy(rows)
            fn(rows)
            st, r = verify({"did": did_a, "rotations": rows}, headers=T1)
            return st, r

        # 5a. DID 不一致（改末条 did，其余仍通过链前序检查）
        def t_did(rows):
            rows[-1]["did"] = "did:example:deadbeef"
        st, r = tamper(proofs, t_did)
        check("篡改 did -> DID 不一致",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "DID 不一致")

        # 5b. 版本不连续：第二条 from 改成 9（链与签名均未重算，但版本
        # 检查先于其他检查）
        def t_ver(rows):
            rows[1]["from_key_version"] = 9
        st, r = tamper(proofs, t_ver)
        check("篡改版本 -> 版本不连续",
              st == 200 and r.get("reason") == "版本不连续")

        # 5c. 前序摘要不匹配：仅改第二条 previous_proof_digest
        def t_prev(rows):
            rows[1]["previous_proof_digest"] = "0" * 64
        st, r = tamper(proofs, t_prev)
        check("篡改前序摘要 -> 前序摘要不匹配",
              st == 200 and r.get("reason") == "前序摘要不匹配")

        # 首条 previous 非 null 亦为前序摘要不匹配
        def t_prev_first(rows):
            rows[0]["previous_proof_digest"] = "0" * 64
        st, r = tamper(proofs[:1], t_prev_first)
        check("首条 previous 非 null -> 前序摘要不匹配",
              st == 200 and r.get("reason") == "前序摘要不匹配")

        # 5d. 记录摘要不匹配：改 rotated_at 但不重算 proof_digest
        def t_digest(rows):
            rows[0]["rotated_at"] = "2000-01-01T00:00:00Z"
        st, r = tamper(proofs[:1], t_digest)
        check("改内容不重算摘要 -> 记录摘要不匹配",
              st == 200 and r.get("reason") == "记录摘要不匹配")

        def t_digest_value(rows):
            rows[0]["proof_digest"] = "0" * 64
        st, r = tamper(proofs[:1], t_digest_value)
        check("proof_digest 值错误 -> 记录摘要不匹配",
              st == 200 and r.get("reason") == "记录摘要不匹配")

        def t_missing_field(rows):
            del rows[0]["rotated_at"]
        st, r = tamper(proofs[:1], t_missing_field)
        check("记录缺字段 -> 记录摘要不匹配",
              st == 200 and r.get("reason") == "记录摘要不匹配")

        def t_extra_field(rows):
            rows[0]["extra"] = 1
        st, r = tamper(proofs[:1], t_extra_field)
        check("记录多字段 -> 记录摘要不匹配",
              st == 200 and r.get("reason") == "记录摘要不匹配")

        # 5e/5f 需要私钥重签：直接读本地状态文件取各版本私钥（测试用途）
        raw = json.load(open(store_path, encoding="utf-8"))
        hist = raw["tenants"]["rp-a"]["dids"][did_a]["key_history"]
        priv = {int(e["version"]): e["private_key_pem"] for e in hist}

        def recompute_digest(row):
            body = {key: row[key] for key in DIGEST_FIELDS}
            row["proof_digest"] = __import__("hashlib").sha256(
                crypto.canonicalize(body)
            ).hexdigest()

        # 旧钥签名失败：改 from_key_handle（签名负载变化），用新钥重签
        # to_proof，保持 from_proof 为旧值，重算摘要 -> 双负载一致但
        # from_proof 失效，故命中旧钥签名失败而非摘要问题。
        def t_from_sig(rows):
            row = rows[0]
            row["from_key_handle"] = "tampered-handle"
            signed = {key: row[key] for key in SIGNED_FIELDS}
            row["to_proof"] = crypto.sign(signed, priv[2])
            recompute_digest(row)
        st, r = tamper(proofs[:1], t_from_sig)
        check("旧钥签名失效 -> 旧钥签名失败",
              st == 200 and r.get("reason") == "旧钥签名失败")

        # 新钥签名失败：改 to_key_handle，用旧钥重签 from_proof，保留
        # 原 to_proof（对新负载失效），重算摘要 -> 旧钥通过、新钥失败。
        def t_to_sig(rows):
            row = rows[0]
            row["to_key_handle"] = "tampered-new-handle"
            signed = {key: row[key] for key in SIGNED_FIELDS}
            row["from_proof"] = crypto.sign(signed, priv[1])
            recompute_digest(row)
        st, r = tamper(proofs[:1], t_to_sig)
        check("新钥签名失效 -> 新钥签名失败",
              st == 200 and r.get("reason") == "新钥签名失败")

        # 乱序提交（先 v2 再 v1）-> 首条版本不连续
        st, r = verify(
            {"did": did_a, "rotations": [proofs[1], proofs[0]]}, headers=T1)
        check("乱序提交 -> 版本不连续",
              st == 200 and r.get("reason") == "版本不连续")

        # ---- 6. verify 请求 400 协议 ----
        def v_400(payload=None, raw=None, headers=None, name=""):
            st, r = verify(payload, headers=headers, raw=raw)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"])

        v_400(raw=b"{", name="非法 JSON -> 400")
        v_400(payload=[], name="JSON 数组体 -> 400")
        v_400(payload={"rotations": proofs}, name="缺 did -> 400")
        v_400(payload={"did": did_a}, name="缺 rotations -> 400")
        v_400(payload={"did": did_a, "rotations": proofs, "x": 1},
              name="多余字段 -> 400")
        v_400(payload={"did": "", "rotations": proofs}, name="空 did -> 400")
        v_400(payload={"did": 1, "rotations": proofs}, name="非串 did -> 400")
        v_400(payload={"did": did_a, "rotations": {}},
              name="rotations 非数组 -> 400")
        v_400(payload={"did": did_a, "rotations": []},
              name="空数组 -> 400")
        v_400(payload={"did": did_a, "rotations": [1]},
              name="元素非对象 -> 400")
        v_400(payload={"did": did_a, "rotations": [proofs[0], "x"]},
              name="混有非对象元素 -> 400")
        v_400(payload={"did": did_a, "rotations": [{}] * 101},
              name="101 个对象 -> 400")
        v_400(payload={"did": did_a, "rotations": proofs},
              headers={"X-Tenant-ID": ""}, name="空租户头 -> 400")

        # 布尔值不得冒充整数版本：通过 400 外的内容校验给出 200 失败
        bool_rows = copy.deepcopy(proofs)
        bool_rows[0]["to_key_version"] = True
        st, r = verify({"did": did_a, "rotations": bool_rows[:1]}, headers=T1)
        check("布尔版本号不被当作整数 -> 版本不连续",
              st == 200 and r.get("reason") == "版本不连续")

        # ---- 7. 旧钥事后吊销不使证明失效 ----
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/1/revoke",
            {"reason": "v1 泄漏"}, headers=T1,
        )
        assert st == 200
        st, h = rotations(did_a, headers=T1)
        check("吊销旧钥不新增/改写证明", len(h["events"]) == 2)
        st, r = verify({"did": did_a, "rotations": h["events"]}, headers=T1)
        check("旧钥吊销后证明链仍 valid", st == 200 and r == {"valid": True})

        # ---- 8. 失败轮换不写证明（句柄重复 400）----
        st, before = rotations(did_a, headers=T1)
        st, _ = _http(
            "POST", f"{base}/v1/dids/{did_a}/keys/rotate",
            {"key_handle": "rp-handle-a-v2"}, headers=T1,
        )
        check("重复句柄轮换 -> 400", st == 400)
        st, after = rotations(did_a, headers=T1)
        check("失败轮换不写证明", after == before)

        # ---- 9. 只读：查询与验真不记审计 ----
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        n_before = len(audit_before["events"])
        rotations(did_a, headers=T1)
        verify({"did": did_a, "rotations": proofs}, headers=T1)
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("rotations/verify 不记审计",
              len(audit_after["events"]) == n_before)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 跨重启：证明与链稳定 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = rotations(did_a, headers=T1)
        check(
            "重启后证明稳定（字段/链/双签仍可独立核验）",
            st == 200 and len(h["events"]) == 2
            and h["events"][0]["previous_proof_digest"] is None
            and h["events"][1]["previous_proof_digest"]
            == h["events"][0]["proof_digest"],
        )
        try:
            for p in h["events"]:
                independent_check(p)
            restart_ok = True
        except Exception:  # noqa: BLE001
            restart_ok = False
        check("重启后独立验签仍成立", restart_ok)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 11. 升级前版本无证明：不补造；后续新证明链从头开始 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "legacy"}
    try:
        st, ld = _http("POST", f"{lbase}/v1/dids",
                       {"method": "example", "public_key": "leg-a"},
                       headers=L)
        assert st == 201
        leg_did = ld["did"]
        for hdl in ("leg-a2", "leg-a3"):
            st, _ = _http(
                "POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
                {"key_handle": hdl}, headers=L)
            assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 删除证明命名空间，模拟升级前状态文件（版本/生命周期历史保留）
    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket.pop("key_rotation_proofs", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/rotations", headers=L)
        check("升级前版本不补造证明（空页）",
              st == 200 and h["events"] == [] and h["next_after"] == 0)
        st, doc = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/document", headers=L)
        check("原 DID 文档历史保留 1/2/3",
              st == 200
              and [m["key_version"] for m in doc["verification_methods"]]
              == [1, 2, 3])
        st, hist = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/history", headers=L)
        check("原密钥生命周期历史保留",
              st == 200
              and sorted(e["key_version"] for e in hist["events"])
              == [1, 2, 3])

        # 升级后轮换到 v4：新证明 previous_proof_digest 为 null（链从头）
        st, _ = _http(
            "POST", f"{lbase}/v1/dids/{leg_did}/keys/rotate",
            {"key_handle": "leg-a4"}, headers=L)
        assert st == 200
        st, h = _http(
            "GET", f"{lbase}/v1/dids/{leg_did}/keys/rotations", headers=L)
        ok_new = (
            st == 200 and len(h["events"]) == 1
            and h["events"][0]["from_key_version"] == 3
            and h["events"][0]["to_key_version"] == 4
            and h["events"][0]["previous_proof_digest"] is None
        )
        check("升级后新证明链从头（previous=null、3->4）", ok_new)
        if ok_new:
            independent_check(h["events"][0])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 12. 直连 store：落盘失败全回滚 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("dt", "example", "rollback-rp")
    store.rotate_key("dt", d.did, "rollback-rp2")

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.rotate_key("dt", d.did, "rollback-rp3")
    except OSError:
        raised = True
    check("落盘失败时轮换抛错", raised)

    rec = store.get_did("dt", d.did)
    proofs_db, _ = store.list_rotation_proofs("dt", d.did, 0, 50)
    audit_events = store.list_audit("dt", 0, 200)[0]
    check(
        "回滚后版本/证明/审计均不变",
        rec.key_version == 2
        and len(proofs_db) == 1
        and proofs_db[0].to_key_version == 2
        and [e.action for e in audit_events].count("key.rotated") == 1,
    )

    del store._save_locked
    rec2 = store.rotate_key("dt", d.did, "rollback-rp3")
    proofs_db, _ = store.list_rotation_proofs("dt", d.did, 0, 50)
    first_digest = proofs_db[0].proof_digest
    chain_ok = (
        rec2.key_version == 3
        and len(proofs_db) == 2
        and [p.to_key_version for p in proofs_db] == [2, 3]
        and proofs_db[0].previous_proof_digest is None
        and proofs_db[1].previous_proof_digest == first_digest
    )
    check("恢复后轮换成功且证明链接续", chain_ok)
    try:
        import dataclasses

        for p in proofs_db:
            independent_check(dataclasses.asdict(p))
        check("恢复后证明均可独立核验", True)
    except Exception:  # noqa: BLE001
        check("恢复后证明均可独立核验", False)

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("密钥轮换证明测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
