#!/usr/bin/env python3
"""POST /v1/credentials/{id}/present-batch 端到端验证脚本。"""

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

PORT = 8977
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

UNBOUND_KEYS = [
    "presentation_id", "credential_id", "issuer_did",
    "issuer_key_version", "disclose", "claims",
    "challenge", "expires_at", "proof",
]
BOUND_KEYS = UNBOUND_KEYS + [
    "holder_did", "holder_key_version", "holder_proof",
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
    for k, v in (headers or {}).items():
        req.add_header(k, v)
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
    p = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up()
    return p


def make_did(handle):
    st, r = http("POST", f"{BASE}/v1/dids",
                 {"method": "example", "public_key": handle})
    assert st == 201, r
    return r["did"]


def pubkey(did):
    st, r = http("GET", f"{BASE}/v1/dids/{did}/document")
    assert st == 200, r
    return r["verification_methods"][0]["public_key"]


def main():
    proc = start()
    try:
        issuer = make_did("issuer-key")
        holder = make_did("holder-key")
        other = make_did("other-key")
        issuer_pub = pubkey(issuer)
        holder_pub = pubkey(holder)

        st, r = http("POST", f"{BASE}/v1/credentials", {
            "issuer_did": issuer,
            "subject_did": holder,
            "claims": {"name": "alice", "age": 30,
                       "addr": {"city": "SH", "zip": "200000"},
                       "tags": ["a", "b"]},
        })
        assert st == 201, r
        cred = r["credential_id"]

        # 以 holder 为 subject 的第二凭证（用于跨凭证不存在场景）
        st, r = http("POST", f"{BASE}/v1/credentials", {
            "issuer_did": issuer, "subject_did": holder,
            "claims": {"k": "v"},
        })
        cred2 = r["credential_id"]

        batch_url = f"{BASE}/v1/credentials/{cred}/present-batch"

        # ---------- 1. 成功批量：混合形态、默认值与显式值 ---------- #
        items = [
            {"disclose": ["/name"]},
            {"disclose": [], "challenge": "zero-disclose",
             "expires_in": 60, "holder_binding": False},
            {"disclose": ["/addr/city", "/age"],
             "challenge": "mixed-挑战", "expires_in": 86400},
            {"disclose": ["/tags"], "holder_binding": True},
        ]
        st, r = http("POST", batch_url, {"presentations": items})
        check("批量成功 201", st == 201)
        vps = r.get("presentations")
        check("返回数量与输入一致", isinstance(vps, list) and len(vps) == 4)

        # 同序
        check("同序: claims 投影一致",
              vps[0]["claims"] == {"name": "alice"}
              and vps[1]["claims"] == {}
              and vps[2]["claims"] == {"addr": {"city": "SH"}, "age": 30}
              and vps[3]["claims"] == {"tags": ["a", "b"]})
        # 固定键序（未绑定）
        check("未绑定项键序固定九字段",
              list(vps[0].keys()) == UNBOUND_KEYS
              and list(vps[1].keys()) == UNBOUND_KEYS
              and list(vps[2].keys()) == UNBOUND_KEYS)
        # 绑定项键序
        check("绑定项键序固定十二字段",
              list(vps[3].keys()) == BOUND_KEYS)
        # challenge 默认值为 32 位小写 hex
        import re
        check("缺省 challenge 为 32 位小写 hex",
              re.fullmatch(r"[0-9a-f]{32}", vps[0]["challenge"]) is not None
              and re.fullmatch(r"[0-9a-f]{32}", vps[3]["challenge"]) is not None)
        # 显式 challenge 回显
        check("显式 challenge/expires_in 生效",
              vps[1]["challenge"] == "zero-disclose"
              and vps[2]["challenge"] == "mixed-挑战")
        # expires_at 存在
        check("expires_at 均为 UTC Z 串",
              all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                              vp["expires_at"]) for vp in vps))
        # 绑定字段
        check("绑定项 holder_did=subject、版本 1",
              vps[3]["holder_did"] == holder
              and vps[3]["holder_key_version"] == 1)
        # presentation_id 唯一
        ids = [vp["presentation_id"] for vp in vps]
        check("presentation_id 两两不同", len(set(ids)) == 4
              and all(i.startswith("vp_") for i in ids))

        # ---------- 2. 外部验签 issuer/holder proof ---------- #
        def check_proof(vp):
            issuer_payload = {k: v for k, v in vp.items()
                              if not k.startswith("holder_") and k != "proof"}
            crypto.verify(issuer_payload, vp["proof"], issuer_pub)
            if "holder_proof" in vp:
                hp = {k: v for k, v in vp.items()
                      if k not in ("proof", "holder_proof")}
                hp["tenant_id"] = "default"
                crypto.verify(hp, vp["holder_proof"], holder_pub)

        for i, vp in enumerate(vps):
            try:
                check_proof(vp)
                ok = True
            except Exception as exc:  # noqa: BLE001
                ok = False
                print("   验签异常:", exc)
            check(f"第 {i+1} 项 ES256 双签名外部可验", ok)

        # ---------- 3. 每条演示可在 /verify 验证（存储锚点） ---------- #
        for i, vp in enumerate(vps):
            st2, rr = http(
                "POST",
                f"{BASE}/v1/presentations/{vp['presentation_id']}/verify",
                {"presentation": vp, "challenge": vp["challenge"]})
            check(f"第 {i+1} 项 verify valid:true",
                  st2 == 200 and rr.get("valid") is True)

        # ---------- 4. 请求级非法 -> 400 且不写入 ---------- #
        def count_created():
            st2, rr = http("GET", f"{BASE}/v1/audit?limit=200")
            assert st2 == 200
            return sum(1 for e in rr["events"]
                       if e["action"] == "presentation.created"
                       and e["tenant_id"] == "default")

        audit_before = count_created()

        def expect_400(name, payload, raw=None, url=batch_url):
            st2, rr = http("POST", url, payload, raw=raw)
            check(name, st2 == 400 and isinstance(rr.get("error"), str)
                  and bool(rr["error"]))

        expect_400("缺 presentations -> 400", {"items": []})
        expect_400("多余字段 -> 400",
                   {"presentations": [], "x": 1})
        expect_400("presentations 非数组 -> 400", {"presentations": {}})
        expect_400("空数组 -> 400", {"presentations": []})
        expect_400("超过 50 项 -> 400",
                   {"presentations": [{"disclose": []} for _ in range(51)]})
        expect_400("项非对象 -> 400", {"presentations": [1]})
        expect_400("项缺 disclose -> 400",
                   {"presentations": [{"challenge": "c"}]})
        expect_400("项多余字段 -> 400",
                   {"presentations": [{"disclose": [], "x": 1}]})
        expect_400("challenge 空串 -> 400",
                   {"presentations": [{"disclose": [], "challenge": ""}]})
        expect_400("challenge 非串 -> 400",
                   {"presentations": [{"disclose": [], "challenge": 1}]})
        expect_400("challenge 超 256 码点 -> 400",
                   {"presentations": [{"disclose": [],
                                       "challenge": "好" * 257}]})
        expect_400("expires_in 布尔 -> 400",
                   {"presentations": [{"disclose": [], "expires_in": True}]})
        expect_400("expires_in=0 -> 400",
                   {"presentations": [{"disclose": [], "expires_in": 0}]})
        expect_400("expires_in=86401 -> 400",
                   {"presentations": [{"disclose": [], "expires_in": 86401}]})
        expect_400("expires_in 串 -> 400",
                   {"presentations": [{"disclose": [], "expires_in": "60"}]})
        expect_400("holder_binding 非布尔 -> 400",
                   {"presentations": [{"disclose": [],
                                       "holder_binding": "true"}]})
        # 非 JSON / 非对象请求体
        st_raw, rr_raw = http("POST", batch_url, None, raw=b"{not json")
        check("非法 JSON -> 400", st_raw == 400 and bool(rr_raw.get("error")))
        st_raw, rr_raw = http("POST", batch_url, None, raw=b"[1,2]")
        check("非对象请求体 -> 400",
              st_raw == 400 and bool(rr_raw.get("error")))

        # ---------- 5. store 级非法（整体回滚） ---------- #
        expect_400("根指针 -> 400",
                   {"presentations": [{"disclose": ["/"]}]})
        expect_400("数组索引 -> 400",
                   {"presentations": [{"disclose": ["/tags/0"]}]})
        expect_400("越界 -> 400",
                   {"presentations": [{"disclose": ["/nope"]}]})
        expect_400("重复路径 -> 400",
                   {"presentations": [{"disclose": ["/name", "/name"]}]})
        expect_400("祖先重叠 -> 400",
                   {"presentations": [
                       {"disclose": ["/addr", "/addr/city"]}]})
        # 批内第 2 项非法：第 1 项也不得写入
        expect_400("批内后置项非法整体 400",
                   {"presentations": [
                       {"disclose": ["/name"], "challenge": "ok-first"},
                       {"disclose": ["/missing"]}]})
        # 批内首项非法（未知路径在第 1 项）
        expect_400("批内首项非法整体 400",
                   {"presentations": [
                       {"disclose": ["/missing"]},
                       {"disclose": ["/name"]}]})
        # 他租户不可见凭证
        st_other, r_other = http(
            "POST",
            f"{BASE}/v1/credentials/{cred}/present-batch",
            {"presentations": [{"disclose": ["/name"],
                                "holder_binding": True}]},
            headers={"X-Tenant-ID": "tenant-zz"})
        check("他租户凭证批量绑定 -> 404",
              st_other == 404 and "不存在" in r_other.get("error", ""))

        # 未知凭证
        st2, rr = http(
            "POST", f"{BASE}/v1/credentials/vc_nonexistent/present-batch",
            {"presentations": [{"disclose": []}]})
        check("未知凭证 -> 404", st2 == 404
              and "不存在" in rr.get("error", ""))

        check("全部非法批次均不写审计",
              count_created() == audit_before)

        # ---------- 6. challenge 恰好 256 码点成功 ---------- #
        st2, rr256 = http("POST", batch_url,
                          {"presentations": [{"disclose": ["/name"],
                                              "challenge": "好" * 256}]})
        check("challenge 恰好 256 码点 -> 201", st2 == 201)
        vp256 = rr256["presentations"][0]
        check("256 码点 challenge 回显", vp256["challenge"] == "好" * 256)

        # ---------- 7. subject 在本租户的绑定成功 ---------- #
        st_cred_other_subj, rcred = http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer, "subject_did": other,
             "claims": {"x": 1}})
        assert st_cred_other_subj == 201
        st2, rr = http(
            "POST",
            f"{BASE}/v1/credentials/{rcred['credential_id']}/present-batch",
            {"presentations": [{"disclose": ["/x"],
                                "holder_binding": True}]})
        check("subject 本租户已注册 -> 绑定 201", st2 == 201)
        check("绑定项含 holder_proof",
              "holder_proof" in rr["presentations"][0])

        # ---------- 8. 审计：成功批每条演示各留一条 ---------- #
        st2, rr = http("GET", f"{BASE}/v1/audit?limit=200")
        created = [e for e in rr["events"]
                   if e["action"] == "presentation.created"
                   and e["tenant_id"] == "default"]
        vp_ids = {vp["presentation_id"] for vp in vps}
        audit_ids = {e["resource_id"] for e in created}
        check("初始 4 条演示均有审计", vp_ids <= audit_ids)

        # ---------- 9. 重启后可验签、可 verify ---------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        for i, vp in enumerate(vps):
            # 外部密码学验签
            try:
                check_proof(vp)
                sig_ok = True
            except Exception:  # noqa: BLE001
                sig_ok = False
            check(f"重启后第 {i+1} 项签名仍可外部验", sig_ok)
        # 256 challenge 那条重启后以存储锚点 verify
        st2, rrverify = http(
            "POST", f"{BASE}/v1/presentations/{vp256['presentation_id']}/verify",
            {"presentation": vp256, "challenge": vp256["challenge"]})
        check("重启后演示 verify valid:true",
              st2 == 200 and rrverify.get("valid") is True)

        # ---------- 10. X-Tenant-ID 规则 ---------- #
        st2, rr = http(
            "POST",
            f"{BASE}/v1/credentials/{cred}/present-batch",
            {"presentations": [{"disclose": ["/name"]}]},
            headers={"X-Tenant-ID": ""})
        check("空 X-Tenant-ID -> 400", st2 == 400)
        st2, rr = http(
            "POST",
            f"{BASE}/v1/credentials/{cred}/present-batch",
            {"presentations": [{"disclose": ["/name"]}]},
            headers={"X-Tenant-ID": "tenant-a"})
        check("他租户不可见凭证 -> 404", st2 == 404)

        # ---------- 11. 50 项边界 ---------- #
        st2, rr = http("POST", batch_url,
                       {"presentations": [{"disclose": ["/name"]}
                                          for _ in range(50)]})
        check("恰好 50 项 -> 201",
              st2 == 201 and len(rr["presentations"]) == 50)
        check("50 项键序全部固定",
              all(list(v.keys()) == UNBOUND_KEYS
                  for v in rr["presentations"]))
        check("50 项 id 互不相同",
              len({v["presentation_id"] for v in rr["presentations"]}) == 50)

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
        for f in failures:
            print(" -", f)
        return 1
    print("present-batch 端到端验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
