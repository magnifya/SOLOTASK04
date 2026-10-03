#!/usr/bin/env python3
"""数组元素选择性披露端到端验证脚本。

覆盖单项 present、present-batch、多凭证组合展示、展示请求模式与本地
验真：RFC6901 数组索引语法/越界 400、保留下标的 null 填充投影、null
值保留、多属性合并、嵌套容器、整值披露兼容、disclose 次序无关、篡改
所选值/占位/数组顺序时验真失败且不消费、合法验真消费一次、重启持久化、
批量/组合整次 400 不落盘、请求创建只校验语法与重叠、谓词证明数组路径。
"""

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

PORT = 8991
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


def make_did(handle):
    st, r = http("POST", f"{BASE}/v1/dids",
                 {"method": "example", "public_key": handle})
    assert st == 201, r
    return r["did"]


def issue(issuer, holder, claims):
    st, r = http("POST", f"{BASE}/v1/credentials",
                 {"issuer_did": issuer, "subject_did": holder,
                  "claims": claims})
    assert st == 201, r
    return r["credential_id"]


def present(cred, disclose, **extra):
    body = {"disclose": disclose}
    body.update(extra)
    return http("POST", f"{BASE}/v1/credentials/{cred}/present", body)


def verify(vp, *, request_id=None):
    body = {"presentation": vp}
    if request_id is None:
        body["challenge"] = vp["challenge"]
    else:
        body["request_id"] = request_id
    return http("POST",
                f"{BASE}/v1/presentations/{vp['presentation_id']}/verify",
                body)


def main():
    proc = start()
    try:
        issuer = make_did("issuer-key")
        holder = make_did("holder-key")

        claims = {
            "rows": [
                {"name": "甲", "secret": 1, "note": None},
                {"name": "乙", "secret": 2},
            ],
            "matrix": [[10, 11], [20, 21, 22]],
            "tags": ["a", "b", "c"],
            "0": "数字键按属性名",
        }
        cid = issue(issuer, holder, claims)

        # ---------- 1. 规格示例：/rows/1/name ---------- #
        st, vp = present(cid, ["/rows/1/name"])
        check("规格示例 -> 201", st == 201)
        check("投影保留下标、空位 null、不输出原长度",
              vp.get("claims") == {"rows": [None, {"name": "乙"}]})
        check("disclose 原样回显",
              vp.get("disclose") == ["/rows/1/name"])
        st, r = verify(vp)
        check("合法数组元素演示验真", st == 200 and r == {"valid": True})

        # ---------- 2. 同元素多属性合并、null 值保留 ---------- #
        st, vp = present(cid, ["/rows/0/name", "/rows/0/note",
                               "/rows/1/name"])
        check("多属性合并 -> 201", st == 201)
        check("null 值正常保留、多属性合并到同一元素",
              vp.get("claims") == {
                  "rows": [
                      {"name": "甲", "note": None},
                      {"name": "乙"},
                  ]})
        st, r = verify(vp)
        check("合并投影验真", st == 200 and r == {"valid": True})

        # ---------- 3. 嵌套数组 ---------- #
        st, vp = present(cid, ["/matrix/1/2", "/matrix/0/1"])
        check("嵌套数组选择 -> 201", st == 201)
        check("每层数组独立按最大下标+null 填充",
              vp.get("claims") == {
                  "matrix": [[None, 11], [None, None, 22]]})
        st, r = verify(vp)
        check("嵌套数组投影验真", st == 200 and r == {"valid": True})

        # ---------- 4. 直接选中数组/对象元素：整值披露 ---------- #
        st, vp = present(cid, ["/tags"])
        check("数组整值披露兼容",
              st == 201 and vp.get("claims") == {"tags": ["a", "b", "c"]})
        st, r = verify(vp)
        check("整值数组验真", st == 200 and r == {"valid": True})
        st, vp = present(cid, ["/rows/0"])
        check("直接选中数组元素对象 -> 整值披露",
              st == 201
              and vp.get("claims") == {"rows": [
                  {"name": "甲", "secret": 1, "note": None}]})
        st, r = verify(vp)
        check("整值元素验真", st == 200 and r == {"valid": True})

        # ---------- 5. 对象数字字符串按属性名 ---------- #
        st, vp = present(cid, ["/0"])
        check("对象数字字符串属性 -> 201",
              st == 201
              and vp.get("claims") == {"0": "数字键按属性名"})

        # ---------- 6. RFC6901 转义在数组路径中仍生效 ---------- #
        esc_claims = {"a/b": [{"x~y": 1}]}
        esc_cid = issue(issuer, holder, esc_claims)
        st, vp = present(esc_cid, ["/a~1b/0/x~0y"])
        check("转义键 + 数组索引 -> 201",
              st == 201
              and vp.get("claims") == {"a/b": [{"x~y": 1}]})

        # ---------- 7. 次序无关：调换无重叠路径投影相同 ---------- #
        st, vp_ab = present(cid, ["/tags/0", "/rows/1/name",
                                  "/matrix/0/0"])
        st2, vp_ba = present(cid, ["/matrix/0/0", "/rows/1/name",
                                   "/tags/0"])
        expected = {"tags": ["a"],
                    "rows": [None, {"name": "乙"}],
                    "matrix": [[10]]}
        check("两种次序均 201", st == 201 and st2 == 201)
        check("调换次序不改变投影",
              vp_ab.get("claims") == expected
              and vp_ba.get("claims") == expected)

        # ---------- 8. 空列表零披露 ---------- #
        st, vp = present(cid, [])
        check("空列表零披露",
              st == 201 and vp.get("claims") == {}
              and vp.get("disclose") == [])

        # ---------- 9. 非法索引/越界/穿标量均 400 ---------- #
        bad_paths = [
            "/tags/-1", "/tags/+1", "/tags/01", "/tags/00",
            "/tags/-", "/tags/٠", "/tags/１", "/tags/1.0",
            "/tags/3", "/matrix/0/2",
            "/tags/0/0", "/rows/name", "/rows/0/missing",
            "/nope/0", "/tags/0/",
        ]
        for bad in bad_paths:
            st, r = present(cid, [bad])
            check(f"{bad} -> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and bool(r["error"]))

        # 根/非法转义/重复/祖先后代重叠（含数组路径）
        overlap_cases = [
            [""], ["/tags~2/0"],
            ["/tags/0", "/tags/0"],
            ["/rows/0", "/rows/0/name"],
            ["/rows/0/name", "/rows/0"],
            ["/rows", "/rows/1"],
        ]
        for paths in overlap_cases:
            st, r = present(cid, paths)
            check(f"重叠/根/非法转义 {paths} -> 400",
                  st == 400 and bool(r.get("error")))

        # ---------- 10. 篡改：所选值/占位/数组顺序均 valid:false ---------- #
        def tampered_verify(name, mutate):
            st0, vp0 = present(cid, ["/rows/0/name", "/rows/1/name"])
            assert st0 == 201, vp0
            mutate(vp0)
            stv, rv = verify(vp0)
            check(name, stv == 200 and rv.get("valid") is False
                  and isinstance(rv.get("reason"), str)
                  and bool(rv["reason"]))
            return vp0

        tampered_verify(
            "篡改所选值 -> valid:false",
            lambda v: v["claims"]["rows"][1].__setitem__("name", "丙"))
        # 该演示仅经历一次失败验真，应保持未消费
        st0, vp_t = present(cid, ["/rows/0/name", "/rows/1/name"])
        assert st0 == 201, vp_t
        vp_bad = json.loads(json.dumps(vp_t))
        vp_bad["claims"]["rows"][1]["name"] = "丙"
        st, rv = verify(vp_bad)
        check("失败验真不消费（前置：一次篡改验真）",
              st == 200 and rv.get("valid") is False)
        tampered_verify(
            "null 占位替换为伪造对象 -> valid:false",
            lambda v: v["claims"]["rows"].__setitem__(
                0, {"name": "甲", "secret": 1}))
        tampered_verify(
            "数组顺序调换 -> valid:false",
            lambda v: v["claims"]["rows"].reverse())
        tampered_verify(
            "删除尾元素 -> valid:false",
            lambda v: v["claims"]["rows"].pop())
        tampered_verify(
            "占位 null 改成字符串 -> valid:false",
            lambda v: v["claims"]["rows"].__setitem__(0, "x"))

        # 篡改验真不消费：随后原样合法验证仍成功（仅消费一次）
        st, r = verify(vp_t)
        check("失败验真不消费、随后合法验真成功",
              st == 200 and r == {"valid": True})
        st, r = verify(vp_t)
        check("重复合法验真 -> 演示已消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已消费")

        # ---------- 11. present-batch：成功投影与整次 400 回滚 ---------- #
        batch_url = f"{BASE}/v1/credentials/{cid}/present-batch"
        st, r = http("POST", batch_url, {"presentations": [
            {"disclose": ["/rows/1/name"]},
            {"disclose": ["/matrix/1/2", "/tags/2"]},
        ]})
        check("批量数组投影 -> 201", st == 201 and len(
            r.get("presentations", [])) == 2)
        vps = r["presentations"]
        check("批量投影同序正确",
              vps[0]["claims"] == {"rows": [None, {"name": "乙"}]}
              and vps[1]["claims"] == {
                  "matrix": [None, [None, None, 22]],
                  "tags": [None, None, "c"]})
        for one in vps:
            st, rr = verify(one)
            check("批量产物可验真", st == 200 and rr == {"valid": True})

        st, au_before = http("GET", f"{BASE}/v1/audit?limit=200")
        created_before = sum(
            1 for e in au_before.get("events", [])
            if e.get("action") == "presentation.created")
        st, r = http("POST", batch_url, {"presentations": [
            {"disclose": ["/rows/1/name"]},
            {"disclose": ["/tags/9"]},
        ]})
        check("批量中非法下标 -> 整次 400",
              st == 400 and bool(r.get("error")))
        st, au_after = http("GET", f"{BASE}/v1/audit?limit=200")
        created_after = sum(
            1 for e in au_after.get("events", [])
            if e.get("action") == "presentation.created")
        check("非法批次不写审计", created_after == created_before)

        # 未知/跨租户凭证 -> 404
        st, r = http(
            "POST", f"{BASE}/v1/credentials/vc_nope/present-batch",
            {"presentations": [{"disclose": ["/rows/0"]}]})
        check("批量未知凭证 -> 404", st == 404)
        st, r = http(
            "POST", f"{BASE}/v1/credentials/{cid}/present-batch",
            {"presentations": [{"disclose": ["/rows/0"]}]},
            headers={"X-Tenant-ID": "other-tenant"})
        check("批量跨租户凭证 -> 404", st == 404)

        # ---------- 12. 多凭证组合展示 ---------- #
        cid2 = issue(issuer, holder, {"items": [{"k": "v1"}, {"k": "v2"}]})
        st, r = http("POST", f"{BASE}/v1/presentations/multi", {
            "items": [
                {"credential_id": cid, "disclose": ["/rows/1/name"]},
                {"credential_id": cid2, "disclose": ["/items/0/k"]},
            ]})
        check("组合展示数组投影 -> 201", st == 201)
        mvp = r
        check("组合各项投影正确",
              mvp["items"][0]["claims"] == {
                  "rows": [None, {"name": "乙"}]}
              and mvp["items"][1]["claims"] == {"items": [{"k": "v1"}]})
        st, rv = http("POST",
                      f"{BASE}/v1/presentations/{mvp['presentation_id']}/verify",
                      {"presentation": mvp, "challenge": mvp["challenge"]})
        check("组合展示验真", st == 200 and rv == {"valid": True})

        st, au_before = http("GET", f"{BASE}/v1/audit?limit=200")
        created_before = sum(
            1 for e in au_before.get("events", [])
            if e.get("action") == "presentation.created")
        st, r = http("POST", f"{BASE}/v1/presentations/multi", {
            "items": [
                {"credential_id": cid, "disclose": ["/rows/1/name"]},
                {"credential_id": cid2, "disclose": ["/items/9/k"]},
            ]})
        check("组合中非法路径 -> 整次 400",
              st == 400 and bool(r.get("error")))
        st, au_after = http("GET", f"{BASE}/v1/audit?limit=200")
        created_after = sum(
            1 for e in au_after.get("events", [])
            if e.get("action") == "presentation.created")
        check("非法组合不写审计", created_after == created_before)

        st, r = http("POST", f"{BASE}/v1/presentations/multi", {
            "items": [
                {"credential_id": cid, "disclose": ["/rows/0"]},
                {"credential_id": "vc_nope", "disclose": ["/items/0"]},
            ]})
        check("组合未知凭证 -> 404", st == 404)

        # 组合绑定仍工作
        st, r = http("POST", f"{BASE}/v1/presentations/multi", {
            "items": [
                {"credential_id": cid, "disclose": ["/rows/1/name"]},
                {"credential_id": cid2, "disclose": ["/items/1"]},
            ],
            "holder_binding": True})
        check("组合持有者绑定 -> 201",
              st == 201 and "holder_proof" in r
              and r["items"][1]["claims"] == {"items": [None, {"k": "v2"}]})

        # ---------- 13. 展示请求：创建只校验语法/重叠 ---------- #
        # 创建时数组下标“看起来非法”也允许（不做索引与命中检查）
        st, req = http("POST", f"{BASE}/v1/presentation-requests", {
            "challenge": "ch-array-1",
            "disclose": ["/rows/01/name", "/rows/9/name", "/tags/-"],
        })
        check("请求阶段不校验索引语法与命中 -> 201", st == 201)
        check("请求 disclose 原样保存",
              req.get("disclose") == [
                  "/rows/01/name", "/rows/9/name", "/tags/-"])
        # 创建期仍拒绝根/重复/重叠/非法转义
        for bad_disclose in [[""], ["/a", "/a"], ["/a", "/a/b"],
                             ["/a~2"]]:
            st, r = http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "ch-bad", "disclose": bad_disclose})
            check(f"请求创建 disclose 非法 {bad_disclose} -> 400",
                  st == 400 and bool(r.get("error")))
        # 用含非法索引的请求生成 -> 400
        st, r = http("POST", f"{BASE}/v1/credentials/{cid}/present",
                     {"request_id": req["request_id"]})
        check("请求模式生成时索引非法 -> 400",
              st == 400 and bool(r.get("error")))

        # 合法请求模式
        st, req2 = http("POST", f"{BASE}/v1/presentation-requests", {
            "challenge": "ch-array-2",
            "disclose": ["/rows/1/name"],
            "issuer_dids": [issuer],
        })
        assert st == 201, req2
        st, rvp = http("POST", f"{BASE}/v1/credentials/{cid}/present",
                       {"request_id": req2["request_id"]})
        check("请求模式生成数组投影 -> 201",
              st == 201
              and rvp.get("claims") == {"rows": [None, {"name": "乙"}]}
              and rvp.get("request_id") == req2["request_id"])
        st, rv = verify(rvp, request_id=req2["request_id"])
        check("请求模式验真成功并消费",
              st == 200 and rv == {"valid": True})
        st, rv = verify(rvp, request_id=req2["request_id"])
        check("请求模式重复验真 -> 演示已消费",
              st == 200 and rv.get("valid") is False
              and rv.get("reason") == "演示已消费")

        # ---------- 14. 谓词证明同样支持数组索引 ---------- #
        st, r = http("POST", f"{BASE}/v1/credentials/{cid}/prove",
                     {"predicates": [{"path": "/tags/0", "op": "exists"}]})
        check("谓词数组索引 -> 201", st == 201
              and r.get("results") == [True])
        st, r = http("POST", f"{BASE}/v1/credentials/{cid}/prove",
                     {"predicates": [{"path": "/tags/01", "op": "exists"}]})
        check("谓词非法数组索引 -> 400", st == 400 and bool(r.get("error")))
        st, r = http("POST", f"{BASE}/v1/credentials/{cid}/prove",
                     {"predicates": [{"path": "/tags", "op": "exists"}]})
        check("谓词数组整值路径仍可用", st == 201)

        # ---------- 15. 重启后投影与消费状态保留 ---------- #
        st, vp_keep = present(cid, ["/rows/1/name", "/matrix/1/2"])
        assert st == 201, vp_keep
        keep_id = vp_keep["presentation_id"]
        keep_projection = vp_keep["claims"]
        assert keep_projection == {
            "rows": [None, {"name": "乙"}],
            "matrix": [None, [None, None, 22]]}
        st, rv = verify(vp_keep)
        assert st == 200 and rv == {"valid": True}, rv
        proc = restart(proc)
        st, rv = verify(vp_keep)
        check("重启后已消费状态保留（投影锚定仍一致）",
              st == 200 and rv.get("valid") is False
              and rv.get("reason") == "演示已消费")
        check("生成结果投影值", keep_projection == {
            "rows": [None, {"name": "乙"}],
            "matrix": [None, [None, None, 22]]})

        # 重启后未消费的数组演示仍可验真
        st, vp_fresh = present(cid, ["/rows/0/note"])
        assert st == 201, vp_fresh
        fresh_id = vp_fresh["presentation_id"]
        proc = restart(proc)
        st, rv = verify(vp_fresh)
        check("重启后数组演示签名与投影仍可验真",
              st == 200 and rv == {"valid": True}
              and vp_fresh["claims"] == {"rows": [{"note": None}]})

        # ---------- 16. 租户隔离 ---------- #
        st, r = http(
            "POST",
            f"{BASE}/v1/presentations/{fresh_id}/verify",
            {"presentation": vp_fresh, "challenge": vp_fresh["challenge"]},
            headers={"X-Tenant-ID": "tenant-b"})
        check("他租户验真本租户演示 -> 演示不存在",
              st == 200 and r.get("valid") is False
              and "不存在" in r.get("reason", ""))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n数组元素选择性披露测试全部通过 ✔")


if __name__ == "__main__":
    main()
