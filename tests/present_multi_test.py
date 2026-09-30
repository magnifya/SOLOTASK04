#!/usr/bin/env python3
"""POST /v1/presentations/multi 与组合验签端到端验证脚本。"""

import json
import os
import re
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

PORT = 8988
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

ITEM_KEYS = [
    "credential_id", "issuer_did", "issuer_key_version",
    "disclose", "claims", "proof",
]
TOP_KEYS = ["presentation_id", "items", "challenge", "expires_at"]
BOUND_TOP_KEYS = TOP_KEYS + [
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


def issue(issuer, subject, claims, expires_at=None):
    body = {"issuer_did": issuer, "subject_did": subject, "claims": claims}
    if expires_at is not None:
        body["expires_at"] = expires_at
    st, r = http("POST", f"{BASE}/v1/credentials", body)
    assert st == 201, r
    return r["credential_id"]


def verify(mvp_id, presentation, challenge, headers=None):
    return http(
        "POST", f"{BASE}/v1/presentations/{mvp_id}/verify",
        {"presentation": presentation, "challenge": challenge},
        headers=headers,
    )


def main():
    proc = start()
    try:
        issuer1 = make_did("issuer1-key")
        issuer2 = make_did("issuer2-key")
        holder = make_did("holder-key")
        other = make_did("other-key")
        issuer1_pub = pubkey(issuer1)
        issuer2_pub = pubkey(issuer2)
        holder_pub = pubkey(holder)
        issuer_pubs = {issuer1: issuer1_pub, issuer2: issuer2_pub}

        cred_a = issue(issuer1, holder, {
            "name": "alice", "age": 30,
            "addr": {"city": "SH", "zip": "200000"},
            "tags": ["a", "b"],
        })
        cred_b = issue(issuer2, holder, {"level": 5, "email": "a@x"})
        cred_c = issue(issuer1, other, {"x": 1})

        multi_url = f"{BASE}/v1/presentations/multi"

        # ---------- 1. 成功创建组合：默认值、同序、只含所选叶子 ---------- #
        req_items = [
            {"credential_id": cred_a, "disclose": ["/name", "/addr/city"]},
            {"credential_id": cred_b, "disclose": ["/level"]},
        ]
        st, r = http("POST", multi_url, {"items": req_items})
        check("组合创建 201", st == 201)
        check("presentation_id 为 mvp_+32hex",
              re.fullmatch(r"mvp_[0-9a-f]{32}", r.get("presentation_id", ""))
              is not None)
        check("顶层键序四字段", list(r.keys()) == TOP_KEYS)
        check("items 与输入等长同序",
              [it["credential_id"] for it in r["items"]] == [cred_a, cred_b])
        check("条目键序六字段",
              all(list(it.keys()) == ITEM_KEYS for it in r["items"]))
        check("投影只含所选叶子 claim",
              r["items"][0]["claims"] == {"name": "alice",
                                          "addr": {"city": "SH"}}
              and r["items"][1]["claims"] == {"level": 5})
        check("disclose 原样回显",
              r["items"][0]["disclose"] == ["/name", "/addr/city"])
        check("issuer_key_version=1",
              all(it["issuer_key_version"] == 1 for it in r["items"]))
        check("缺省 challenge 为 32 位小写 hex",
              re.fullmatch(r"[0-9a-f]{32}", r["challenge"]) is not None)
        check("expires_at 为 UTC Z 秒精度",
              re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                           r["expires_at"]) is not None)

        # ---------- 2. 外部密码学验各凭证签发证明 ---------- #
        def check_item_proofs(mvp):
            for it in mvp["items"]:
                unsigned = {
                    "presentation_id": mvp["presentation_id"],
                    "credential_id": it["credential_id"],
                    "issuer_did": it["issuer_did"],
                    "issuer_key_version": it["issuer_key_version"],
                    "disclose": it["disclose"],
                    "claims": it["claims"],
                    "challenge": mvp["challenge"],
                    "expires_at": mvp["expires_at"],
                }
                crypto.verify(unsigned, it["proof"],
                              issuer_pubs[it["issuer_did"]])

        try:
            check_item_proofs(r)
            proofs_ok = True
        except Exception as exc:  # noqa: BLE001
            proofs_ok = False
            print("   验签异常:", exc)
        check("各条目签发证明外部 ES256 可验", proofs_ok)

        # ---------- 3. 首次验证成功并原子消费 ---------- #
        st, vr = verify(r["presentation_id"], r, r["challenge"])
        check("首次 verify 200 valid:true", st == 200 and vr == {"valid": True})
        st, vr = verify(r["presentation_id"], r, r["challenge"])
        check("重复 verify -> 展示已消费",
              st == 200 and vr.get("valid") is False
              and vr.get("reason") == "展示已消费")

        # ---------- 4. 显式 challenge/expires_in/holder_binding ---------- #
        st, rb = http("POST", multi_url, {
            "items": [
                {"credential_id": cred_a, "disclose": ["/age"]},
                {"credential_id": cred_b, "disclose": []},
            ],
            "challenge": "combo-挑战",
            "expires_in": 60,
            "holder_binding": True,
        })
        check("绑定组合创建 201", st == 201)
        check("绑定顶层键序七字段", list(rb.keys()) == BOUND_TOP_KEYS)
        check("challenge/expires_in 生效", rb["challenge"] == "combo-挑战")
        check("holder_did=共同 subject、版本 1",
              rb["holder_did"] == holder and rb["holder_key_version"] == 1)
        try:
            hp = {k: v for k, v in rb.items() if k != "holder_proof"}
            hp["tenant_id"] = "default"
            crypto.verify(hp, rb["holder_proof"], holder_pub)
            check_item_proofs(rb)
            bound_sig_ok = True
        except Exception as exc:  # noqa: BLE001
            bound_sig_ok = False
            print("   绑定验签异常:", exc)
        check("绑定 holder_proof 与条目证明外部可验", bound_sig_ok)
        st, vr = verify(rb["presentation_id"], rb, rb["challenge"])
        check("绑定组合首次 verify valid:true",
              st == 200 and vr.get("valid") is True)
        st, vr = verify(rb["presentation_id"], rb, rb["challenge"])
        check("绑定组合重复 verify -> 展示已消费",
              vr.get("reason") == "展示已消费")

        # ---------- 5. 失败不消耗 + 固定 reason ---------- #
        st, rf = http("POST", multi_url, {
            "items": [
                {"credential_id": cred_a, "disclose": ["/name"]},
                {"credential_id": cred_b, "disclose": ["/email"]},
            ],
            "challenge": "fail-safe",
        })
        assert st == 201, rf
        mvp_f = rf["presentation_id"]

        # 5.1 字段集不一致：条目缺字段
        tampered = json.loads(json.dumps(rf))
        del tampered["items"][0]["proof"]
        st, vr = verify(mvp_f, tampered, "fail-safe")
        check("条目缺字段 -> 字段集不一致",
              vr.get("reason") == "字段集不一致")

        # 顶层多字段
        tampered = json.loads(json.dumps(rf))
        tampered["holder_proof"] = "x"
        st, vr = verify(mvp_f, tampered, "fail-safe")
        check("顶层多字段 -> 字段集不一致",
              vr.get("reason") == "字段集不一致")

        # 5.2 锚定校验失败：credential_id 被改
        tampered = json.loads(json.dumps(rf))
        tampered["items"][0]["credential_id"] = cred_c
        st, vr = verify(mvp_f, tampered, "fail-safe")
        check("改 credential_id -> 锚定校验失败",
              vr.get("reason") == "锚定校验失败")

        # 统一 challenge：body challenge 错误
        st, vr = verify(mvp_f, rf, "wrong-challenge")
        check("请求 challenge 不符 -> 锚定校验失败",
              vr.get("reason") == "锚定校验失败")
        tampered = json.loads(json.dumps(rf))
        tampered["challenge"] = "other"
        st, vr = verify(mvp_f, tampered, "other")
        check("演示 challenge 被改 -> 锚定校验失败",
              vr.get("reason") == "锚定校验失败")

        # 5.3 签名校验失败：改某条目 proof
        tampered = json.loads(json.dumps(rf))
        tampered["items"][1]["proof"] = rf["items"][0]["proof"]
        st, vr = verify(mvp_f, tampered, "fail-safe")
        check("换 proof -> 签名校验失败",
              vr.get("reason") == "签名校验失败")

        # 5.4 持有人绑定失败：holder_proof 被改
        st, rh = http("POST", multi_url, {
            "items": [{"credential_id": cred_a, "disclose": ["/name"]}],
            "challenge": "bound-fail", "holder_binding": True,
        })
        assert st == 201, rh
        tampered = json.loads(json.dumps(rh))
        tampered["holder_proof"] = rh["items"][0]["proof"]
        st, vr = verify(rh["presentation_id"], tampered, "bound-fail")
        check("holder_proof 被改 -> 持有人绑定失败",
              vr.get("reason") == "持有人绑定失败")

        # 5.5 上述全部失败均未消耗：原组合首次验证仍成功
        st, vr = verify(mvp_f, rf, "fail-safe")
        check("失败不消耗：原组合首次 verify valid:true",
              st == 200 and vr.get("valid") is True)
        st, vr = verify(mvp_f, rf, "fail-safe")
        check("再次验证 -> 展示已消费", vr.get("reason") == "展示已消费")
        # holder 那条此前只做过失败验证，仍可成功一次
        st, vr = verify(rh["presentation_id"], rh, "bound-fail")
        check("绑定组合失败后首次成功 valid:true", vr.get("valid") is True)

        # ---------- 6. 凭证状态：停用/吊销/过期 ---------- #
        # 6.1 凭证已停用
        st, rs = http("POST", multi_url, {
            "items": [{"credential_id": cred_a, "disclose": ["/name"]},
                      {"credential_id": cred_b, "disclose": ["/level"]}],
            "challenge": "suspended-case",
        })
        assert st == 201, rs
        st, _ = http("PUT", f"{BASE}/v1/credentials/{cred_a}/status",
                     {"status": "suspended", "reason": "审核暂停"})
        assert st in (200, 201)
        st, vr = verify(rs["presentation_id"], rs, "suspended-case")
        check("凭证暂停 -> 凭证已停用",
              vr.get("reason") == "凭证已停用")
        st, _ = http("PUT", f"{BASE}/v1/credentials/{cred_a}/status",
                     {"status": "active"})
        assert st == 200
        st, vr = verify(rs["presentation_id"], rs, "suspended-case")
        check("恢复后首次验证成功（失败未消耗）", vr.get("valid") is True)

        # 6.2 凭证已吊销
        st, rr2 = http("POST", multi_url, {
            "items": [{"credential_id": cred_a, "disclose": ["/name"]},
                      {"credential_id": cred_b, "disclose": ["/level"]}],
            "challenge": "revoked-case",
        })
        assert st == 201, rr2
        st, _ = http("POST", f"{BASE}/v1/credentials/{cred_b}/revoke",
                     {"reason": "违规吊销"})
        assert st == 200
        st, vr = verify(rr2["presentation_id"], rr2, "revoked-case")
        check("凭证吊销 -> 凭证已吊销",
              vr.get("reason") == "凭证已吊销")
        st, vr = verify(rr2["presentation_id"], rr2, "revoked-case")
        check("吊销后重复验证仍为凭证已吊销（不消耗）",
              vr.get("reason") == "凭证已吊销")

        # 6.3 凭证已过期
        future = (datetime.now(timezone.utc) + timedelta(seconds=3)
                  ).strftime("%Y-%m-%dT%H:%M:%SZ")
        cred_exp = issue(issuer1, holder, {"e": 1}, expires_at=future)
        st, rexp = http("POST", multi_url, {
            "items": [{"credential_id": cred_exp, "disclose": ["/e"]}],
            "challenge": "cred-exp",
        })
        assert st == 201, rexp
        time.sleep(4)
        st, vr = verify(rexp["presentation_id"], rexp, "cred-exp")
        check("凭证到期 -> 凭证已过期",
              vr.get("reason") == "凭证已过期")

        # ---------- 7. 展示已过期 ---------- #
        st, rexp2 = http("POST", multi_url, {
            "items": [{"credential_id": cred_a, "disclose": ["/name"]}],
            "challenge": "vp-exp", "expires_in": 1,
        })
        assert st == 201, rexp2
        time.sleep(2)
        st, vr = verify(rexp2["presentation_id"], rexp2, "vp-exp")
        check("展示到期 -> 展示已过期",
              vr.get("reason") == "展示已过期")
        st, vr = verify(rexp2["presentation_id"], rexp2, "vp-exp")
        check("过期展示重复验证仍为展示已过期",
              vr.get("reason") == "展示已过期")

        # ---------- 8. 创建期 400 ---------- #
        def expect_400(name, payload):
            st2, rr = http("POST", multi_url, payload)
            check(name, st2 == 400 and isinstance(rr.get("error"), str)
                  and bool(rr["error"]))

        expect_400("缺 items", {"challenge": "c"})
        expect_400("多余字段", {"items": [], "x": 1})
        expect_400("items 非数组", {"items": {}})
        expect_400("items 为空", {"items": []})
        expect_400("items 超 100",
                   {"items": [{"credential_id": cred_a, "disclose": []}
                              for _ in range(101)]})
        expect_400("项非对象", {"items": [1]})
        expect_400("项缺 credential_id",
                   {"items": [{"disclose": []}]})
        expect_400("项缺 disclose",
                   {"items": [{"credential_id": cred_a}]})
        expect_400("项多余字段",
                   {"items": [{"credential_id": cred_a, "disclose": [],
                               "x": 1}]})
        expect_400("credential_id 空串",
                   {"items": [{"credential_id": "", "disclose": []}]})
        expect_400("credential_id 非串",
                   {"items": [{"credential_id": 1, "disclose": []}]})
        expect_400("disclose 非数组",
                   {"items": [{"credential_id": cred_a, "disclose": {}}]})
        expect_400("批内 credential_id 重复",
                   {"items": [
                       {"credential_id": cred_a, "disclose": ["/name"]},
                       {"credential_id": cred_a, "disclose": ["/age"]}]})
        expect_400("challenge 空串",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "challenge": ""})
        expect_400("challenge 非串",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "challenge": 1})
        expect_400("challenge 超 256 码点",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "challenge": "好" * 257})
        expect_400("expires_in 布尔",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "expires_in": True})
        expect_400("expires_in=0",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "expires_in": 0})
        expect_400("expires_in=86401",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "expires_in": 86401})
        expect_400("holder_binding 非布尔",
                   {"items": [{"credential_id": cred_a, "disclose": []}],
                    "holder_binding": "yes"})
        # disclose 语义错误（沿用 RFC6901 叶子规则）
        expect_400("根路径",
                   {"items": [{"credential_id": cred_a,
                               "disclose": ["/"]}]})
        expect_400("越界",
                   {"items": [{"credential_id": cred_a,
                               "disclose": ["/nope"]}]})
        expect_400("数组索引",
                   {"items": [{"credential_id": cred_a,
                               "disclose": ["/tags/0"]}]})
        expect_400("重复路径",
                   {"items": [{"credential_id": cred_a,
                               "disclose": ["/name", "/name"]}]})
        expect_400("嵌套覆盖",
                   {"items": [{"credential_id": cred_a,
                               "disclose": ["/addr", "/addr/city"]}]})
        # subject_did 错误：组合内持证人不一致（本地签发凭证的
        # subject_did 必为本租户已注册 DID，绑定以共同 subject 锚定）
        expect_400("绑定 subject 不一致 -> 400",
                   {"items": [
                       {"credential_id": cred_a, "disclose": ["/name"]},
                       {"credential_id": cred_c, "disclose": ["/x"]}],
                    "holder_binding": True})
        # 非法 JSON
        st_raw, rr_raw = http("POST", multi_url, raw=b"{bad")
        check("非法 JSON -> 400", st_raw == 400 and bool(rr_raw.get("error")))

        # ---------- 9. 404：未知 / 跨租户凭证 ---------- #
        st, rr = http("POST", multi_url,
                      {"items": [{"credential_id": "vc_nope",
                                  "disclose": []}]})
        check("未知凭证 -> 404", st == 404 and "不存在" in rr.get("error", ""))
        st, rr = http("POST", multi_url,
                      {"items": [{"credential_id": cred_a,
                                  "disclose": ["/name"]}]},
                      headers={"X-Tenant-ID": "tenant-zz"})
        check("跨租户凭证 -> 404",
              st == 404 and "不存在" in rr.get("error", ""))

        # 未知/跨租户组合验证均为 200 语义失败
        st, vr = http(
            "POST", f"{BASE}/v1/presentations/mvp_{'0' * 32}/verify",
            {"presentation": {"x": 1}, "challenge": "c"})
        check("未知组合 verify -> 200 锚定校验失败",
              st == 200 and vr.get("reason") == "锚定校验失败")
        st, vr = http(
            "POST", f"{BASE}/v1/presentations/{rb['presentation_id']}/verify",
            {"presentation": rb, "challenge": rb["challenge"]},
            headers={"X-Tenant-ID": "tenant-zz"})
        check("跨租户组合 verify -> 200 锚定校验失败",
              st == 200 and vr.get("reason") == "锚定校验失败")

        # ---------- 10. 审计 ---------- #
        all_events = []
        after = 0
        while True:
            st, ar = http("GET", f"{BASE}/v1/audit?limit=200&after={after}")
            assert st == 200, ar
            page = ar["events"]
            all_events.extend(page)
            if not page or ar["next_after"] == after:
                break
            after = ar["next_after"]
        actions = [e["action"] for e in all_events
                   if e["tenant_id"] == "default"]
        check("组合创建有 multi_presentation.created",
              "multi_presentation.created" in actions)
        check("组合消费有 multi_presentation.consumed",
              "multi_presentation.consumed" in actions)
        check("每次成功创建/消费各留审计",
              actions.count("multi_presentation.created") >= 5
              and actions.count("multi_presentation.consumed") >= 5)

        # ---------- 11. 100 项边界 ---------- #
        many_creds = [issue(issuer1, holder, {f"k{i}": i}) for i in range(100)]
        st, r100 = http("POST", multi_url, {
            "items": [{"credential_id": c, "disclose": [f"/k{i}"]}
                      for i, c in enumerate(many_creds)],
        })
        check("恰好 100 项 -> 201",
              st == 201 and len(r100["items"]) == 100)
        st, vr = verify(r100["presentation_id"], r100, r100["challenge"])
        check("100 项组合 verify valid:true", vr.get("valid") is True)

        # ---------- 12. 重启稳定 ---------- #
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        # 已消费状态保留
        st, vr = verify(r["presentation_id"], r, r["challenge"])
        check("重启后已消费组合仍为展示已消费",
              vr.get("reason") == "展示已消费")
        # 未消费组合重启后仍可完整验真并消费
        st, rn = http("POST", multi_url, {
            "items": [{"credential_id": cred_c, "disclose": ["/x"]}],
            "challenge": "after-restart",
        })
        assert st == 201, rn
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        try:
            check_item_proofs(rn)
            ext_ok = True
        except Exception:  # noqa: BLE001
            ext_ok = False
        check("重启后条目证明外部仍可验", ext_ok)
        st, vr = verify(rn["presentation_id"], rn, "after-restart")
        check("重启后未消费组合 verify valid:true", vr.get("valid") is True)

        # ---------- 13. 空租户头 400 ---------- #
        st, rr = http("POST", multi_url,
                      {"items": [{"credential_id": cred_c, "disclose": []}]},
                      headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400", st == 400)

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
    print("multi-presentation 端到端验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
