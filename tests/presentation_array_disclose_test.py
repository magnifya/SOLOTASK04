#!/usr/bin/env python3
"""数组元素选择性披露端到端自测（单张/present-batch/多凭证/展示请求）。

直接运行：python3 tests/presentation_array_disclose_test.py
覆盖：
- 合法数组索引投影（占位、合并、嵌套数组/对象、null、次序无关）；
- 非法索引（负号/正号/前导零/全角数字/"-"/越界/穿过标量）400；
- 展示请求创建只校验语法与重叠（索引与命中留到生成时）；
- 篡改所选值/占位/数组顺序验真 200 valid:false 且不消费；
- 生成与消费状态跨重启保留、租户隔离。
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
from vcbackend import crypto  # noqa: E402

PORT = 8949
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

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


def restart(proc):
    proc.terminate()
    proc.wait(timeout=10)
    return start()


def main():
    proc = start()
    try:
        # ---------------- 准备：DID 与凭证 ---------------- #
        st, r = http("POST", f"{BASE}/v1/dids",
                     {"method": "example", "public_key": "arr-issuer"})
        assert st == 201, r
        issuer = r["did"]
        issuer_pub = r["public_key"]
        st, r = http("POST", f"{BASE}/v1/dids",
                     {"method": "example", "public_key": "arr-holder"})
        assert st == 201, r
        holder = r["did"]
        holder_pub = r["public_key"]

        # rows：对象数组（任务示例）；tags：标量数组；matrix：嵌套数组；
        # misc：数字字符串属性名 + null 值 + 元素为 null
        claims = {
            "rows": [
                {"name": "甲", "secret": 1},
                {"name": "乙", "secret": 2},
            ],
            "tags": ["a", "b", "c"],
            "matrix": [[10, 20], [30, 40, 50]],
            "misc": {"0": "数字字符串属性", "null_prop": None,
                     "arr": [1, None, 3]},
        }
        st, r = http("POST", f"{BASE}/v1/credentials", {
            "issuer_did": issuer, "subject_did": holder,
            "claims": claims})
        assert st == 201, r
        cid = r["credential_id"]

        def present(paths, **extra):
            return http("POST", f"{BASE}/v1/credentials/{cid}/present",
                        {"disclose": paths, **extra})

        def verify(pid, vp, challenge=None):
            return http(
                "POST", f"{BASE}/v1/presentations/{pid}/verify",
                {"presentation": vp,
                 "challenge": vp["challenge"] if challenge is None
                 else challenge})

        def expect_projection(name, paths, expected, **extra):
            st, r = present(paths, **extra)
            check(name, st == 201 and r.get("claims") == expected
                  and r.get("disclose") == paths)
            return r

        # ---------- 1. 任务示例 ---------- #
        vp = expect_projection(
            "示例 /rows/1/name 投影",
            ["/rows/1/name"], {"rows": [None, {"name": "乙"}]})
        st, vr = verify(vp["presentation_id"], vp)
        check("示例演示验真 valid=true", st == 200 and vr == {"valid": True})

        # ---------- 2. 投影规则 ---------- #
        expect_projection("同元素多属性合并",
                          ["/rows/0/name", "/rows/0/secret"],
                          {"rows": [{"name": "甲", "secret": 1}]})
        vp_swap = expect_projection(
            "调换无重叠路径次序不改变投影",
            ["/rows/0/secret", "/rows/0/name", "/rows/1/name"],
            {"rows": [{"name": "甲", "secret": 1}, {"name": "乙"}]})
        # 与相反次序的 claims 完全一致
        vp_other = expect_projection(
            "另一次序同投影",
            ["/rows/1/name", "/rows/0/name", "/rows/0/secret"],
            {"rows": [{"name": "甲", "secret": 1}, {"name": "乙"}]})
        check("两种次序 claims 相等", vp_swap["claims"] == vp_other["claims"])

        expect_projection("标量数组保留下标、长度=最大下标+1",
                          ["/tags/2"], {"tags": [None, None, "c"]})
        expect_projection("不输出剩余元素（原长 3 截到 2）",
                          ["/tags/1"], {"tags": [None, "b"]})
        expect_projection("嵌套数组逐层占位",
                          ["/matrix/1/2"],
                          {"matrix": [None, [None, None, 50]]})
        expect_projection("嵌套数组多分支",
                          ["/matrix/0/1", "/matrix/1/0"],
                          {"matrix": [[None, 20], [30]]})
        expect_projection("元素内对象+数组混合",
                          ["/rows/0/name", "/tags/0"],
                          {"rows": [{"name": "甲"}], "tags": ["a"]})
        expect_projection("数字字符串按属性名而非索引",
                          ["/misc/0"], {"misc": {"0": "数字字符串属性"}})
        expect_projection("所选值为 null 的属性保留",
                          ["/misc/null_prop"], {"misc": {"null_prop": None}})
        expect_projection("选中的 null 数组元素保留",
                          ["/misc/arr/1"],
                          {"misc": {"arr": [None, None]}})
        expect_projection("直接选中对象整值披露",
                          ["/rows/0"],
                          {"rows": [{"name": "甲", "secret": 1}]})
        expect_projection("直接选中数组整值披露",
                          ["/matrix/1"], {"matrix": [None, [30, 40, 50]]})
        expect_projection("整值披露顶层数组保持不变",
                          ["/tags"], {"tags": ["a", "b", "c"]})
        expect_projection("零披露空投影", [], {})

        # 持有人绑定 + 数组元素披露
        vp_bound = expect_projection(
            "holder_binding 数组元素披露 201",
            ["/rows/1/name"], {"rows": [None, {"name": "乙"}]},
            holder_binding=True)
        check("绑定演示含 holder 三字段",
              set(vp_bound) == {
                  "presentation_id", "credential_id", "issuer_did",
                  "issuer_key_version", "disclose", "claims", "challenge",
                  "expires_at", "proof", "holder_did",
                  "holder_key_version", "holder_proof"})
        issuer_obj = {k: v for k, v in vp_bound.items()
                      if not k.startswith("holder_") and k != "proof"}
        crypto.verify(issuer_obj, vp_bound["proof"], issuer_pub)
        holder_obj = {k: v for k, v in vp_bound.items()
                      if k not in ("proof", "holder_proof")}
        holder_obj["tenant_id"] = "default"
        crypto.verify(holder_obj, vp_bound["holder_proof"], holder_pub)
        st, vr = verify(vp_bound["presentation_id"], vp_bound)
        check("绑定数组演示验真 valid=true", st == 200 and vr ==
              {"valid": True})

        # RFC6901 转义在数组场景仍然生效
        st, r = http("POST", f"{BASE}/v1/credentials", {
            "issuer_did": issuer, "subject_did": holder,
            "claims": {"a/b": [{"m~n": 7}]}})
        cid_esc = r["credential_id"]
        st, r = http("POST", f"{BASE}/v1/credentials/{cid_esc}/present",
                     {"disclose": ["/a~1b/0/m~0n"]})
        check("数组场景 ~0/~1 转义命中",
              st == 201 and r["claims"] == {"a/b": [{"m~n": 7}]})

        # ---------- 3. 非法路径 400 ---------- #
        def present_400(name, paths):
            st, r = present(paths)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and bool(r["error"]))

        for bad in ["/rows/-1", "/rows/+0", "/rows/00", "/rows/01",
                    "/rows/-", "/rows/1.0", "/rows/ 1", "/rows/１",
                    "/rows/abc", "/rows/3", "/tags/-1"]:
            present_400(f"非法数组索引 {bad} -> 400", [bad])
        present_400("穿过对象数组内标量 -> 400", ["/tags/0/x"])
        present_400("穿过嵌套数组内标量 -> 400", ["/matrix/0/0/0"])
        present_400("缺失属性 -> 400", ["/rows/0/nope"])
        present_400("中间越界 -> 400", ["/rows/9/name"])
        present_400("根路径 -> 400", ["/"])
        present_400("数组整值与元素祖先重叠 -> 400",
                    ["/rows", "/rows/0"])
        present_400("元素与数组整值后代重叠（逆序）-> 400",
                    ["/rows/0", "/rows"])
        present_400("深层祖先重叠 -> 400",
                    ["/rows/0/name", "/rows/0/name/first"])

        # 非法转义仍 400
        st, r = present(["/rows/0/a~2b"])
        check("非法转义 -> 400", st == 400 and bool(r.get("error")))

        # ---------- 4. 非法路径不产生演示/审计 ---------- #
        st, audit_before = http("GET", f"{BASE}/v1/audit?limit=200")
        created_before = sum(
            1 for e in audit_before["events"]
            if e["action"] == "presentation.created")
        present(["/rows/-1"])
        st, audit_after = http("GET", f"{BASE}/v1/audit?limit=200")
        created_after = sum(
            1 for e in audit_after["events"]
            if e["action"] == "presentation.created")
        check("非法数组索引不写审计", created_after == created_before)

        # ---------- 5. 篡改所选值/占位/顺序：200 valid:false 且不消费 ---------- #
        st, vp_t = present(["/rows/1/name", "/rows/0/secret"])
        assert st == 201 and vp_t["claims"] == {
            "rows": [{"secret": 1}, {"name": "乙"}]}, vp_t["claims"]
        pid_t = vp_t["presentation_id"]

        def expect_invalid_unchanged(tamper, label, reason_contains=None):
            tampered = copy.deepcopy(vp_t)
            tamper(tampered)
            st, r = verify(pid_t, tampered)
            ok = st == 200 and r.get("valid") is False and bool(r.get("reason"))
            if reason_contains:
                ok = ok and reason_contains in r.get("reason", "")
            check(label, ok)

        expect_invalid_unchanged(
            lambda p: p["claims"]["rows"][1].__setitem__("name", "丙"),
            "篡改所选值 -> valid:false", "重算")
        expect_invalid_unchanged(
            lambda p: p["claims"]["rows"][0].__setitem__("secret", 9),
            "篡改另一所选值 -> valid:false", "重算")
        expect_invalid_unchanged(
            lambda p: p["claims"]["rows"].__setitem__(0, None),
            "把被选位置篡改为 null 占位 -> valid:false", "重算")
        expect_invalid_unchanged(
            lambda p: p["claims"]["rows"].__setitem__(
                0, {"name": "甲", "secret": 1}),
            "占位补出未披露属性 -> valid:false", "重算")
        expect_invalid_unchanged(
            lambda p: p["claims"]["rows"].append({"name": "丁"}),
            "数组末尾追加元素 -> valid:false", "重算")
        expect_invalid_unchanged(
            lambda p: p["claims"]["rows"].__setitem__(
                0, {"name": "乙"}),
            "数组顺序调换 -> valid:false", "重算")
        expect_invalid_unchanged(
            lambda p: p["claims"].__setitem__("rows", [None, None]),
            "占位数量变化 -> valid:false", "重算")

        # 所有篡改均未消费：合法验证仍成功并消费一次
        st, r = verify(pid_t, vp_t)
        check("篡改验真不消费，随后合法验证成功",
              st == 200 and r == {"valid": True})
        st, r = verify(pid_t, vp_t)
        check("合法验证消费一次后为已消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已消费")

        # ---------- 6. present-batch：任一路径非法整次 400，不落盘 ---------- #
        batch_url = f"{BASE}/v1/credentials/{cid}/present-batch"
        st, rr = http("POST", batch_url, {"presentations": [
            {"disclose": ["/rows/0/name"]},
            {"disclose": ["/rows/9/name"]},
        ]})
        check("批量含非法索引整次 400", st == 400 and bool(rr.get("error")))
        st, rr = http("POST", batch_url, {"presentations": [
            {"disclose": ["/rows/-1"]},
        ]})
        check("批量单项非法索引 400", st == 400 and bool(rr.get("error")))
        st, rr = http("POST", batch_url, {"presentations": [
            {"disclose": ["/rows/1/name"], "challenge": "arr-batch-1"},
            {"disclose": ["/tags/0"], "challenge": "arr-batch-2"},
        ]})
        check("批量合法数组元素披露 201", st == 201
              and rr["presentations"][0]["claims"] ==
              {"rows": [None, {"name": "乙"}]}
              and rr["presentations"][1]["claims"] == {"tags": ["a"]})
        for item in rr["presentations"]:
            stx, vx = verify(item["presentation_id"], item)
            check("批量数组演示验真成功",
                  stx == 200 and vx == {"valid": True})

        # ---------- 7. 多凭证组合：非法整次 400；合法可验 ---------- #
        st, r = http("POST", f"{BASE}/v1/credentials", {
            "issuer_did": issuer, "subject_did": holder,
            "claims": {"level": 5, "tags": ["x", "y"]}})
        cid2 = r["credential_id"]
        st, rr = http("POST", f"{BASE}/v1/presentations/multi", {"items": [
            {"credential_id": cid, "disclose": ["/rows/0/name"]},
            {"credential_id": cid2, "disclose": ["/tags/-1"]},
        ]})
        check("组合含非法索引整次 400", st == 400 and bool(rr.get("error")))
        st, rr = http("POST", f"{BASE}/v1/presentations/multi", {"items": [
            {"credential_id": cid, "disclose": ["/rows/0/name"]},
            {"credential_id": cid2, "disclose": ["/tags/1"]},
        ]})
        check("组合数组元素披露 201", st == 201
              and rr["items"][0]["claims"] == {"rows": [{"name": "甲"}]}
              and rr["items"][1]["claims"] == {"tags": [None, "y"]})
        mvp = rr
        mpid = mvp["presentation_id"]
        # 篡改组合中数组占位（须在消费之前，否则已消费优先）
        mt = copy.deepcopy(mvp)
        mt["items"][0]["claims"]["rows"][0] = {"name": "乙"}
        st, vr = verify(mpid, mt)
        check("组合数组篡改 -> 锚定校验失败",
              st == 200 and vr.get("valid") is False
              and vr.get("reason") == "锚定校验失败")
        # 篡改不消费：合法验证随后成功
        st, vr = verify(mpid, mvp)
        check("组合数组演示验真 valid=true", st == 200 and vr ==
              {"valid": True})
        # 未知/跨租户凭证 404
        st, rr = http("POST", f"{BASE}/v1/presentations/multi", {"items": [
            {"credential_id": "vc_deadbeefdead", "disclose": ["/rows/0"]},
        ]})
        check("组合未知凭证 404", st == 404)
        st, rr = http("POST", f"{BASE}/v1/presentations/multi",
                      {"items": [
                          {"credential_id": cid,
                           "disclose": ["/rows/0/name"]}]},
                      headers={"X-Tenant-ID": "tenant-other"})
        check("组合跨租户凭证 404", st == 404)

        # ---------- 8. 展示请求：创建仅查语法/重叠 ---------- #
        # 非法索引语法（-1/01）在 RFC6901 token 层面合法：创建接受，
        # 命中检查留到生成时 -> present 400。
        st, req = http("POST", f"{BASE}/v1/presentation-requests", {
            "challenge": "arr-challenge",
            "disclose": ["/rows/01/name"]})
        check("请求接受前导零 token（生成时才判索引）", st == 201
              and req["disclose"] == ["/rows/01/name"])
        st, rr = http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"request_id": req["request_id"]})
        check("按请求生成遇前导零索引 -> 400",
              st == 400 and bool(rr.get("error")))

        st, req_neg = http("POST", f"{BASE}/v1/presentation-requests", {
            "challenge": "arr-neg", "disclose": ["/rows/-1"]})
        check("请求接受负号 token", st == 201)
        st, rr = http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"request_id": req_neg["request_id"]})
        check("按请求生成遇负索引 -> 400", st == 400 and bool(rr.get("error")))

        # 语法非法/重叠/根/重复仍在创建时 400
        def req_400(name, body):
            st, rr = http("POST", f"{BASE}/v1/presentation-requests", body)
            check(name, st == 400 and bool(rr.get("error")))

        req_400("请求非法转义 -> 400",
                {"challenge": "c", "disclose": ["/rows/0/a~2"]})
        req_400("请求根路径 -> 400", {"challenge": "c", "disclose": ["/"]})
        req_400("请求重复路径 -> 400",
                {"challenge": "c", "disclose": ["/rows/0", "/rows/0"]})
        req_400("请求祖先重叠 -> 400",
                {"challenge": "c", "disclose": ["/rows", "/rows/0"]})
        req_400("请求未以 / 开头 -> 400",
                {"challenge": "c", "disclose": ["rows/0"]})

        # 合法数组路径的请求：生成与验真成功
        st, req_ok = http("POST", f"{BASE}/v1/presentation-requests", {
            "challenge": "arr-ok", "disclose": ["/rows/1/name"],
            "holder_binding": True})
        check("合法数组路径请求 201", st == 201)
        st, rv = http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"request_id": req_ok["request_id"]})
        check("按请求生成数组演示 201", st == 201
              and rv["claims"] == {"rows": [None, {"name": "乙"}]}
              and rv["request_id"] == req_ok["request_id"]
              and rv["challenge"] == "arr-ok")
        # 先篡改占位：request_id 模式同样 200 valid:false 且不消费
        rt = copy.deepcopy(rv)
        rt["claims"]["rows"][0] = {"name": "甲", "secret": 1}
        st, vrx_bad = http(
            "POST", f"{BASE}/v1/presentations/{rv['presentation_id']}/verify",
            {"presentation": rt, "request_id": req_ok["request_id"]})
        check("请求模式数组占位篡改 -> valid:false",
              st == 200 and vrx_bad.get("valid") is False
              and bool(vrx_bad.get("reason")))
        st, vrx = http(
            "POST", f"{BASE}/v1/presentations/{rv['presentation_id']}/verify",
            {"presentation": rv, "request_id": req_ok["request_id"]})
        check("请求模式数组演示验真成功（篡改未消费）",
              st == 200 and vrx == {"valid": True})
        # 展示请求同步标记已消费
        st, got = http(
            "GET", f"{BASE}/v1/presentation-requests/{req_ok['request_id']}")
        check("验真后展示请求 status=consumed",
              st == 200 and got.get("status") == "consumed"
              and got.get("consumed_presentation_id") ==
              rv["presentation_id"])

        # ---------- 9. 跨重启：生成结果与消费状态保留 ---------- #
        st, vp_persist = present(
            ["/matrix/1/2", "/rows/0/name"],
            challenge="persist-challenge")
        assert st == 201, vp_persist
        persist_pid = vp_persist["presentation_id"]
        persist_expected = vp_persist["claims"]
        proc = restart(proc)
        # 重启后验真成功并消费
        st, vr = verify(persist_pid, vp_persist)
        check("重启后数组演示验真成功", st == 200 and vr == {"valid": True})
        proc = restart(proc)
        st, vr = verify(persist_pid, vp_persist)
        check("消费状态跨重启保留 -> 已消费",
              st == 200 and vr.get("valid") is False
              and vr.get("reason") == "演示已消费")
        check("投影内容跨重启一致", persist_expected ==
              {"matrix": [None, [None, None, 50]],
               "rows": [{"name": "甲"}]})

        # ---------- 10. 租户隔离 ---------- #
        st, other_r = http(
            "POST", f"{BASE}/v1/credentials/{cid}/present",
            {"disclose": ["/rows/0/name"]},
            headers={"X-Tenant-ID": "tenant-arr-other"})
        check("他租户生成 -> 404", st == 404)
        st, other_r = http(
            "POST", f"{BASE}/v1/presentations/{persist_pid}/verify",
            {"presentation": vp_persist, "challenge": "persist-challenge"},
            headers={"X-Tenant-ID": "tenant-arr-other"})
        check("他租户验真 -> 演示不存在",
              st == 200 and other_r.get("valid") is False
              and "不存在" in other_r.get("reason", ""))

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
        for item in failures:
            print(" -", item)
        return 1
    print("数组元素选择性披露端到端验证全部通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
