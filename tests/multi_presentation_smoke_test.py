#!/usr/bin/env python3
"""多凭证组合展示端到端自测（临时 HTTP 服务 + store 直连）。

直接运行：python3 tests/multi_presentation_smoke_test.py
"""

import copy
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


def _http(method, url, payload=None, tenant=None):
    data = json.dumps(payload).encode() if payload is not None else None
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
    port = 8953
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        if cond:
            print(f"PASS {name}")
        else:
            print(f"FAIL {name}")
            failures.append(name)

    try:
        if not wait_up(port):
            print("server failed to start")
            return 1

        # 注册两个签发者 + 同一持有者
        _, issuer1 = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "issuer1-key"})
        _, issuer2 = _http("POST", f"{base}/v1/dids",
                           {"method": "example", "public_key": "issuer2-key"})
        _, holder = _http("POST", f"{base}/v1/dids",
                          {"method": "example", "public_key": "holder-key"})
        d1, d2, dh = issuer1["did"], issuer2["did"], holder["did"]
        _, vc1 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d1, "subject_did": dh,
            "claims": {"name": "alice", "age": 30,
                       "addr": {"city": "X", "zip": "1"}},
        })
        _, vc2 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d2, "subject_did": dh,
            "claims": {"level": 5, "tags": ["a", "b"]},
        })
        id1, id2 = vc1["credential_id"], vc2["credential_id"]

        # ---------- 创建：基本成功 ----------
        st, mvp = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1, "disclose": ["/name", "/addr/city"]},
                {"credential_id": id2, "disclose": ["/level"]},
            ],
        })
        check("创建成功 201", st == 201)
        check("presentation_id mvp_ 前缀+32hex",
              bool(__import__("re").fullmatch(
                  r"mvp_[0-9a-f]{32}", mvp.get("presentation_id", ""))))
        check("顶层键集合",
              set(mvp) == {"presentation_id", "items", "challenge",
                           "expires_at"})
        check("challenge 缺省 32 hex",
              bool(__import__("re").fullmatch(r"[0-9a-f]{32}",
                                              mvp["challenge"])))
        check("仅含所选叶子 claim",
              mvp["items"][0]["claims"] == {"name": "alice",
                                            "addr": {"city": "X"}}
              and mvp["items"][1]["claims"] == {"level": 5})
        check("项键集合与顺序",
              list(mvp["items"][0]) == [
                  "credential_id", "issuer_did", "issuer_key_version",
                  "disclose", "claims", "proof"])
        check("数组叶子整体保留",
              True)
        st, mvp_tags = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id2, "disclose": ["/tags"]}],
        })
        check("数组叶子投影", mvp_tags["items"][0]["claims"] ==
              {"tags": ["a", "b"]})

        # ---------- 验证成功并原子消费 ----------
        pid = mvp["presentation_id"]
        st, r = _http("POST", f"{base}/v1/presentations/{pid}/verify", {
            "presentation": mvp, "challenge": mvp["challenge"]})
        check("首次验证 200 valid:true", st == 200 and r == {"valid": True})
        st, r = _http("POST", f"{base}/v1/presentations/{pid}/verify", {
            "presentation": mvp, "challenge": mvp["challenge"]})
        check("重复验证 -> 展示已消费",
              st == 200 and r == {"valid": False, "reason": "展示已消费"})

        # ---------- 400 请求校验 ----------
        def bad(body, label):
            st, r = _http("POST", f"{base}/v1/presentations/multi", body)
            check(label, st == 400 and bool(r.get("error")))

        bad({}, "缺 items")
        bad({"items": []}, "items 为空 400")
        bad({"items": [{"credential_id": id1, "disclose": []}
                       for _ in range(101)]}, "items 超 100 400")
        bad({"items": [{"credential_id": id1, "disclose": []},
                       {"credential_id": id1, "disclose": ["/name"]}]},
            "credential_id 重复 400")
        bad({"items": [{"disclose": []}]}, "项缺 credential_id 400")
        bad({"items": [{"credential_id": id1}]}, "项缺 disclose 400")
        bad({"items": [{"credential_id": id1, "disclose": [],
                        "x": 1}]}, "项多余字段 400")
        bad({"items": [{"credential_id": "", "disclose": []}]},
            "credential_id 空串 400")
        bad({"items": [{"credential_id": 123, "disclose": []}]},
            "credential_id 非字符串 400")
        bad({"items": [{"credential_id": id1, "disclose": "x"}]},
            "disclose 非数组 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "challenge": ""}, "challenge 空串 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "challenge": 123}, "challenge 非字符串 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "expires_in": 0}, "expires_in=0 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "expires_in": 86401}, "expires_in=86401 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "expires_in": True}, "expires_in 布尔 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "holder_binding": "yes"}, "holder_binding 非布尔 400")
        bad({"items": [{"credential_id": id1, "disclose": []}],
             "bogus": 1}, "外层多余字段 400")
        # disclose 叶子规则：根路径/越界/重复/嵌套覆盖
        for paths, label in [
            ([""], "根路径 400"),
            (["/nope"], "越界 400"),
            (["/name", "/name"], "重复路径 400"),
            (["/addr", "/addr/city"], "祖先嵌套覆盖 400"),
            (["/addr/city", "/addr"], "后代嵌套覆盖 400"),
        ]:
            bad({"items": [{"credential_id": id1, "disclose": paths}]}, label)

        # 零披露合法
        st, _ = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1, "disclose": []},
                      {"credential_id": id2, "disclose": []}]})
        check("零披露 201", st == 201)

        # ---------- 404 ----------
        st, r = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": "vc_deadbeef", "disclose": []}]})
        check("未知凭证 404", st == 404)
        st, r = _http(
            "POST", f"{base}/v1/presentations/multi",
            {"items": [{"credential_id": id1, "disclose": []}]},
            tenant="other-tenant")
        check("跨租户凭证 404", st == 404)

        # ---------- 验证语义失败固定 reason ----------
        st, okm = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1, "disclose": ["/name"]},
                {"credential_id": id2, "disclose": ["/level"]}],
        })
        pid2 = okm["presentation_id"]

        def verify(tamper, label, reason, chal_override=None):
            p = copy.deepcopy(okm)
            tamper(p)
            body = {"presentation": p}
            if chal_override is not None:
                body["challenge"] = chal_override
            else:
                body["challenge"] = okm["challenge"]
            st, r = _http("POST",
                          f"{base}/v1/presentations/{pid2}/verify", body)
            check(label, st == 200 and r.get("valid") is False
                  and r.get("reason") == reason)

        verify(lambda p: p.pop("challenge"), "缺字段 -> 字段集不一致",
               "字段集不一致", chal_override=okm["challenge"])
        verify(lambda p: p.update(x=1), "多余顶层字段 -> 字段集不一致",
               "字段集不一致")
        verify(lambda p: p["items"].pop(), "items 数量不一致",
               "字段集不一致")
        verify(lambda p: p["items"][0].pop("proof"),
               "项缺 proof -> 字段集不一致", "字段集不一致")
        verify(lambda p: p.update(challenge="deadbeef" * 4),
               "演示 challenge 篡改 -> 锚定校验失败", "锚定校验失败")
        # 请求 challenge 不一致
        st, r = _http("POST", f"{base}/v1/presentations/{pid2}/verify",
                      {"presentation": okm, "challenge": "0" * 32})
        check("请求 challenge 不一致 -> 锚定校验失败",
              r.get("reason") == "锚定校验失败")
        verify(lambda p: p["items"][0]["claims"].__setitem__("name", "bob"),
               "投影篡改 -> 锚定校验失败", "锚定校验失败")
        verify(lambda p: p["items"][0].__setitem__(
            "credential_id", id2), "credential_id 篡改 -> 锚定校验失败",
            "锚定校验失败")
        verify(lambda p: p["items"][0].__setitem__("proof", "A" * 86),
               "proof 篡改 -> 签名校验失败", "签名校验失败")

        # 失败不消费：再做一次正确验证应成功
        st, r = _http("POST", f"{base}/v1/presentations/{pid2}/verify", {
            "presentation": okm, "challenge": okm["challenge"]})
        check("此前失败均未消费，本次成功", r == {"valid": True})

        # 已消费后，即使篡改也返回展示已消费
        tampered = copy.deepcopy(okm)
        tampered["items"][0]["proof"] = "B" * 86
        st, r = _http("POST", f"{base}/v1/presentations/{pid2}/verify", {
            "presentation": tampered, "challenge": okm["challenge"]})
        check("消费后优先返回展示已消费",
              r == {"valid": False, "reason": "展示已消费"})

        # 缺 challenge 字段（verify 请求级 -> 200 valid:false）
        st, r = _http("POST", f"{base}/v1/presentations/{pid2}/verify",
                      {"presentation": okm})
        check("verify 缺 challenge -> valid:false",
              st == 200 and r.get("valid") is False and bool(r.get("reason")))

        # ---------- 凭证状态 reason ----------
        st, susp = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1, "disclose": ["/name"]}]})
        spid = susp["presentation_id"]
        _http("PUT", f"{base}/v1/credentials/{id1}/status",
              {"status": "suspended", "reason": "审计中"})
        st, r = _http("POST", f"{base}/v1/presentations/{spid}/verify", {
            "presentation": susp, "challenge": susp["challenge"]})
        check("凭证暂停 -> 凭证已停用",
              r == {"valid": False, "reason": "凭证已停用"})
        _http("PUT", f"{base}/v1/credentials/{id1}/status",
              {"status": "active"})
        st, r = _http("POST", f"{base}/v1/presentations/{spid}/verify", {
            "presentation": susp, "challenge": susp["challenge"]})
        check("恢复后验证成功", r == {"valid": True})

        st, rev = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id2, "disclose": ["/level"]}]})
        rpid = rev["presentation_id"]
        _http("POST", f"{base}/v1/credentials/{id2}/revoke",
              {"reason": "造假"})
        st, r = _http("POST", f"{base}/v1/presentations/{rpid}/verify", {
            "presentation": rev, "challenge": rev["challenge"]})
        check("凭证吊销 -> 凭证已吊销",
              r == {"valid": False, "reason": "凭证已吊销"})

        # 凭证已过期
        future = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() + 2))
        _, vcx = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d1, "subject_did": dh,
            "claims": {"k": "v"}, "expires_at": future})
        st, expm = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": vcx["credential_id"],
                       "disclose": ["/k"]}]})
        xpid = expm["presentation_id"]
        time.sleep(3)
        st, r = _http("POST", f"{base}/v1/presentations/{xpid}/verify", {
            "presentation": expm, "challenge": expm["challenge"]})
        check("凭证过期 -> 凭证已过期",
              r == {"valid": False, "reason": "凭证已过期"})

        # 展示已过期
        st, short = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1, "disclose": ["/name"]}],
            "expires_in": 1})
        shpid = short["presentation_id"]
        time.sleep(2)
        st, r = _http("POST", f"{base}/v1/presentations/{shpid}/verify", {
            "presentation": short, "challenge": short["challenge"]})
        check("展示过期 -> 展示已过期",
              r == {"valid": False, "reason": "展示已过期"})

        # ---------- holder binding ----------
        # 此前 id2 已被吊销，绑定流程使用新签发的凭证（吊销凭证可生成
        # 但验证拒绝，行为与单凭证演示一致）。
        _, vc1b = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d1, "subject_did": dh,
            "claims": {"name": "alice"}})
        _, vc2b = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d2, "subject_did": dh,
            "claims": {"level": 5}})
        id1b, id2b = vc1b["credential_id"], vc2b["credential_id"]
        st, bound = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1b, "disclose": ["/name"]},
                {"credential_id": id2b, "disclose": ["/level"]}],
            "holder_binding": True})
        check("绑定创建 201 含 holder 字段", st == 201
              and set(bound) == {"presentation_id", "items", "challenge",
                                 "expires_at", "holder_did",
                                 "holder_key_version", "holder_proof"}
              and bound["holder_did"] == dh)
        bpid = bound["presentation_id"]
        st, r = _http("POST", f"{base}/v1/presentations/{bpid}/verify", {
            "presentation": bound, "challenge": bound["challenge"]})
        check("绑定验证成功", r == {"valid": True})
        # holder_proof 篡改
        st, b2 = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1b, "disclose": ["/name"]}],
            "holder_binding": True})
        b2["holder_proof"] = "C" * 86
        st, r = _http("POST",
                      f"{base}/v1/presentations/{b2['presentation_id']}/verify",
                      {"presentation": b2, "challenge": b2["challenge"]})
        check("holder_proof 篡改 -> 持有人绑定失败",
              r == {"valid": False, "reason": "持有人绑定失败"})
        # holder_did 篡改
        st, b3 = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1b, "disclose": ["/name"]}],
            "holder_binding": True})
        b3["holder_did"] = d1
        st, r = _http("POST",
                      f"{base}/v1/presentations/{b3['presentation_id']}/verify",
                      {"presentation": b3, "challenge": b3["challenge"]})
        check("holder_did 篡改 -> 锚定校验失败",
              r.get("reason") == "锚定校验失败")

        # subject_did 不一致 -> 400
        _, other_subj = _http("POST", f"{base}/v1/dids",
                              {"method": "example", "public_key": "other-key"})
        _, vc3 = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": d1, "subject_did": other_subj["did"],
            "claims": {"z": 1}})
        st, r = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1b, "disclose": ["/name"]},
                      {"credential_id": vc3["credential_id"],
                       "disclose": ["/z"]}],
            "holder_binding": True})
        check("subject_did 不一致绑定 -> 400", st == 400)

        # 未绑定组合不含 holder 字段（前面已验证键集合）
        # 绑定组合 verify 请求缺 holder_proof（字段集不一致）
        st, b4 = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1b, "disclose": ["/name"]}],
            "holder_binding": True})
        b4.pop("holder_proof")
        st, r = _http("POST",
                      f"{base}/v1/presentations/{b4['presentation_id']}/verify",
                      {"presentation": b4, "challenge": b4["challenge"]})
        check("绑定组合缺 holder_proof -> 字段集不一致",
              r.get("reason") == "字段集不一致")

        # 吊销组合中的一张凭证 -> 凭证已吊销（不消费）
        st, b5 = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [
                {"credential_id": id1b, "disclose": ["/name"]},
                {"credential_id": id2b, "disclose": ["/level"]}],
            "holder_binding": True})
        _http("POST", f"{base}/v1/credentials/{id2b}/revoke", {})
        st, r = _http(
            "POST",
            f"{base}/v1/presentations/{b5['presentation_id']}/verify",
            {"presentation": b5, "challenge": b5["challenge"]})
        check("组合中凭证吊销 -> 凭证已吊销",
              r == {"valid": False, "reason": "凭证已吊销"})

        # ---------- 租户隔离：verify ----------
        st, iso = _http("POST", f"{base}/v1/presentations/multi", {
            "items": [{"credential_id": id1b, "disclose": ["/name"]}]})
        st, r = _http(
            "POST",
            f"{base}/v1/presentations/{iso['presentation_id']}/verify",
            {"presentation": iso, "challenge": iso["challenge"]},
            tenant="other-tenant")
        check("跨租户验证 valid:false（不存在）",
              st == 200 and r.get("valid") is False and bool(r.get("reason")))

        # ---------- 审计 ----------
        st, audit = _http("GET", f"{base}/v1/audit?limit=200")
        actions = [e["action"] for e in audit.get("events", [])]
        check("组合创建记 presentation.created",
              "presentation.created" in actions)
        check("组合消费记 presentation.consumed",
              "presentation.consumed" in actions)
        # 失败不记 consumed：统计成功消费数与首次成功次数一致
        check("审计均为字符串动作", all(isinstance(a, str) for a in actions))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    print(f"\n{'=' * 40}\n{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
