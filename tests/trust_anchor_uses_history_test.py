#!/usr/bin/env python3
"""信任锚点用途历史（GET .../uses/history）的端到端测试。

直接运行：python3 tests/trust_anchor_uses_history_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ALL_USES = ["generic", "vc", "vp", "proof", "did", "status", "deactivation"]
UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


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


def gen_pub():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def audit_events(base, headers):
    st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
    assert st == 200
    return r["events"]


def history_url(base, did, version, query=""):
    suffix = f"/v1/trust/anchors/{did}/{version}/uses/history"
    if query:
        suffix += "?" + query
    return base + suffix


def main():
    port = 8972
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

        T1 = {"X-Tenant-ID": "uses-hist-a"}
        T2 = {"X-Tenant-ID": "uses-hist-b"}

        did_full = "did:web:example.com:histfull"
        did_rest = "did:web:example.com:histrest"
        did_other_tenant = "did:web:example.com:shared-did"

        # 1. 注册全用途（省略 uses）与受限用途锚点
        pub_full = gen_pub()
        pub_rest = gen_pub()
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_full, "public_key": pub_full,
                       "key_version": 1}, headers=T1)
        check("注册全用途锚点 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_rest, "public_key": pub_rest,
                       "key_version": 1,
                       "uses": ["generic", "vc", "vp"]}, headers=T1)
        check("注册受限用途锚点 201", st == 201)

        # 2. 初始历史恰一条 registered 事件，响应形状严格
        st, r = _http("GET", history_url(base, did_rest, 1), headers=T1)
        check("初始历史 200", st == 200)
        check("顶层键序恰为 did/key_version/events/next_after",
              list(r) == ["did", "key_version", "events", "next_after"])
        check("顶层值",
              r["did"] == did_rest and r["key_version"] == 1
              and r["next_after"] == r["events"][0]["cursor"])
        events = r["events"]
        check("初始恰一条事件", len(events) == 1)
        ev = events[0]
        check("事件键序恰为 cursor/action/from_uses/uses/updated_at",
              list(ev) == ["cursor", "action", "from_uses", "uses",
                           "updated_at"])
        check("registered 事件内容",
              ev["action"] == "trust.anchor.registered"
              and ev["from_uses"] is None
              and ev["uses"] == ["generic", "vc", "vp"]
              and isinstance(ev["cursor"], int) and ev["cursor"] >= 1
              and UTC_Z_RE.match(ev["updated_at"]))
        rest_reg_cursor = ev["cursor"]

        # 3. 全用途锚点 registered 事件 uses 为全量规范序
        st, r = _http("GET", history_url(base, did_full, 1), headers=T1)
        ev = r["events"][0]
        check("全用途 registered uses 为规范序全量",
              ev["action"] == "trust.anchor.registered"
              and ev["from_uses"] is None
              and ev["uses"] == ALL_USES)
        check("跨 DID 游标递增（同租户）",
              0 < ev["cursor"] < rest_reg_cursor)

        # 4. 幂等重试注册（同 PEM 同 uses）不追加用途历史
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_full, "public_key": pub_full,
                       "key_version": 1}, headers=T1)
        check("全用途锚点幂等注册 200", st == 200)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_rest, "public_key": pub_rest,
                       "key_version": 1,
                       "uses": ["generic", "vc", "vp"]}, headers=T1)
        check("受限用途锚点幂等注册 200", st == 200)
        st, r = _http("GET", history_url(base, did_rest, 1), headers=T1)
        check("幂等注册不追加（仍恰一条）", len(r["events"]) == 1)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_rest, "public_key": gen_pub(),
                       "key_version": 1,
                       "uses": ["generic", "vc", "vp"]}, headers=T1)
        check("不同公钥冲突注册 -> 409", st == 409)
        st, r = _http("GET", history_url(base, did_rest, 1), headers=T1)
        check("冲突注册不追加", len(r["events"]) == 1)

        # 5. 轮换：新版本追加 rotated、继承用途，旧版本不变
        new_pub = gen_pub()
        st, r = _http("POST", f"{base}/v1/trust/anchors/{did_rest}/rotate",
                      {"from_key_version": 1, "public_key": new_pub},
                      headers=T1)
        check("轮换 201", st == 201 and r["key_version"] == 2)
        st, r = _http("GET", history_url(base, did_rest, 2), headers=T1)
        check("新版本历史 200 恰一条", st == 200 and len(r["events"]) == 1)
        ev2 = r["events"][0]
        check("rotated 事件内容",
              list(ev2) == ["cursor", "action", "from_uses", "uses",
                            "updated_at"]
              and ev2["action"] == "trust.anchor.rotated"
              and ev2["from_uses"] is None
              and ev2["uses"] == ["generic", "vc", "vp"]
              and UTC_Z_RE.match(ev2["updated_at"])
              and ev2["cursor"] > rest_reg_cursor)
        # 幂等轮换重试不追加
        st, _ = _http("POST", f"{base}/v1/trust/anchors/{did_rest}/rotate",
                      {"from_key_version": 1, "public_key": new_pub},
                      headers=T1)
        check("幂等轮换重试 200", st == 200)
        st, r = _http("GET", history_url(base, did_rest, 2), headers=T1)
        check("幂等轮换不追加", len(r["events"]) == 1)
        # 旧版本历史不变
        st, r = _http("GET", history_url(base, did_rest, 1), headers=T1)
        check("旧版本历史仍恰一条", len(r["events"]) == 1)

        # 6. 连续收紧 7→…→1，每步一条 updated，保存前后数组
        chains = [
            ["generic", "vc", "vp", "proof", "did", "status"],
            ["generic", "vc", "vp", "proof", "did"],
            ["generic", "vc", "vp", "proof"],
            ["generic", "vc", "vp"],
            ["generic", "vc"],
            ["generic"],
        ]
        before = list(ALL_USES)
        for target in chains:
            st, r = _http("PUT", f"{base}/v1/trust/anchors/{did_full}/1/uses",
                          {"from_uses": before, "uses": target}, headers=T1)
            check(f"收紧到 {len(target)} 用途 200", st == 200)
            before = list(target)
        st, r = _http("GET", history_url(base, did_full, 1),
                      "limit=200", headers=T1)
        events = r["events"]
        check("registered + 6 次收紧 = 7 条事件", len(events) == 7)
        check("事件按 cursor 升序",
              all(events[i]["cursor"] < events[i + 1]["cursor"]
                  for i in range(len(events) - 1)))
        check("首条为 registered/from_uses=null",
              events[0]["action"] == "trust.anchor.registered"
              and events[0]["from_uses"] is None
              and events[0]["uses"] == ALL_USES)
        for i, target in enumerate(chains, start=1):
            ev = events[i]
            expected_from = (ALL_USES if i == 1 else chains[i - 2])
            ok = (
                ev["action"] == "trust.anchor.uses.updated"
                and ev["from_uses"] == expected_from
                and ev["uses"] == target
                and UTC_Z_RE.match(ev["updated_at"])
            )
            check(f"updated 事件[{i}] 保存前后数组", ok)

        # 7. 幂等收紧 / 冲突 / 吊销均不追加
        n_events = len(events)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_full}/1/uses",
                      {"from_uses": ["generic"], "uses": ["generic"]},
                      headers=T1)
        check("幂等收紧 200", st == 200)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_full}/1/uses",
                      {"from_uses": ["vc"], "uses": ["vc"]}, headers=T1)
        check("前置不匹配 409", st == 409)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_full}/1/uses",
                      {"from_uses": ["generic"],
                       "uses": ["generic", "vc"]}, headers=T1)
        check("扩权 409", st == 409)
        st, _ = _http("PUT",
                      f"{base}/v1/trust/anchors/{did_full}/1/status",
                      {"status": "revoked"}, headers=T1)
        check("吊销 200", st == 200)
        st, _ = _http("PUT", f"{base}/v1/trust/anchors/{did_full}/1/uses",
                      {"from_uses": ["generic"], "uses": ["generic"]},
                      headers=T1)
        check("吊销后收紧 409", st == 409)
        st, r = _http("GET", history_url(base, did_full, 1),
                      "limit=200", headers=T1)
        check("幂等/冲突/吊销不追加事件", len(r["events"]) == n_events)

        # 8. 分页：limit/after、next_after、空页
        all_cursors = [e["cursor"] for e in r["events"]]
        st, p1 = _http("GET", history_url(base, did_full, 1, "limit=3"),
                       headers=T1)
        check("limit=3 第一页 3 条",
              st == 200 and [e["cursor"] for e in p1["events"]]
              == all_cursors[:3]
              and p1["next_after"] == all_cursors[2])
        st, p2 = _http(
            "GET",
            history_url(base, did_full, 1,
                        f"limit=3&after={all_cursors[2]}"),
            headers=T1)
        check("第二页接续 3 条",
              [e["cursor"] for e in p2["events"]] == all_cursors[3:6]
              and p2["next_after"] == all_cursors[5])
        st, p3 = _http(
            "GET",
            history_url(base, did_full, 1,
                        f"limit=3&after={all_cursors[5]}"),
            headers=T1)
        check("第三页 1 条",
              [e["cursor"] for e in p3["events"]] == all_cursors[6:]
              and p3["next_after"] == all_cursors[6])
        st, p4 = _http(
            "GET",
            history_url(base, did_full, 1,
                        f"after={all_cursors[6]}"),
            headers=T1)
        check("空页 events=[] 且 next_after=after",
              st == 200 and p4["events"] == []
              and p4["next_after"] == all_cursors[6])
        st, p5 = _http(
            "GET",
            history_url(base, did_full, 1, "after=999999999999"),
            headers=T1)
        check("超大 after 空页且 next_after 回显",
              p5["events"] == [] and p5["next_after"] == 999999999999)
        # 缺省 limit=50、after=0
        st, p6 = _http("GET", history_url(base, did_full, 1), headers=T1)
        check("缺省分页返回全部 7 条", len(p6["events"]) == 7)
        # after 只返 cursor>after（不回含同 cursor 项）
        st, p7 = _http(
            "GET",
            history_url(base, did_full, 1,
                        f"after={all_cursors[0]}&limit=1"),
            headers=T1)
        check("cursor>after 严格",
              [e["cursor"] for e in p7["events"]] == [all_cursors[1]])

        # 9. 非法路径版本 -> 400，仅含非空中文 error
        for bad_ver in ["0", "-1", "1.0", "abc", "", "１２", "+1", " 1"]:
            st, rr = _http(
                "GET",
                f"{base}/v1/trust/anchors/{did_rest}/"
                f"{urllib.parse.quote(bad_ver)}/uses/history",
                headers=T1)
            check(f"路径版本 {bad_ver!r} -> 400", st == 400)
            check(f"路径版本 {bad_ver!r} 仅含非空中文 error",
                  set(rr) == {"error"} and isinstance(rr["error"], str)
                  and bool(rr["error"]))

        # 10. 非法查询参数 -> 400，仅含非空中文 error
        bad_queries = [
            "limit=0", "limit=201", "limit=-1", "limit=1.0", "limit=abc",
            "limit=", "limit=true", "limit=１", "limit=1&limit=2",
            "limit= 1", "after=-1", "after=1.5", "after=abc", "after=",
            "after=false", "after=１", "after=1&after=2", "after= 1",
            "foo=1", "limit=50&foo=1",
        ]
        for q in bad_queries:
            encoded_q = urllib.parse.quote(q, safe="=&")
            st, rr = _http("GET", history_url(base, did_rest, 2, encoded_q),
                           headers=T1)
            check(f"查询 {q!r} -> 400", st == 400)
            check(f"查询 {q!r} 仅含非空中文 error",
                  set(rr) == {"error"} and bool(rr.get("error")))

        # 11. 未知版本 / 未知 DID / 跨租户 -> 404 同形
        st, rr = _http("GET", history_url(base, did_rest, 99), headers=T1)
        check("未知版本 -> 404", st == 404 and set(rr) == {"error"}
              and bool(rr["error"]))
        st, rr = _http(
            "GET", history_url(base, "did:web:none.example", 1), headers=T1)
        check("未知 DID -> 404", st == 404 and set(rr) == {"error"})
        # 他租户注册同 DID
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_other_tenant, "public_key": gen_pub(),
                       "key_version": 1}, headers=T2)
        check("他租户注册 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/trust/anchors",
                      {"did": did_other_tenant, "public_key": gen_pub(),
                       "key_version": 1, "uses": ["did"]}, headers=T1)
        check("本租户同 DID 注册 201", st == 201)
        st, rr = _http(
            "GET", history_url(base, did_other_tenant, 1), headers=T2)
        check("本租户视角不受他租户数据影响",
              st == 200 and rr["events"][0]["uses"] == ALL_USES)
        # 删除本租户该锚点视角不可达：用未注册的版本验证跨租户 404
        st, rr = _http(
            "GET", history_url(base, did_other_tenant, 5), headers=T1)
        check("本租户未知版本 -> 404", st == 404)
        st, rr = _http(
            "GET", history_url(base, did_other_tenant, 5), headers=T2)
        check("他租户未知版本 -> 404", st == 404)

        # 12. 租户游标各自从 1 计起
        st, rr = _http(
            "GET", history_url(base, did_other_tenant, 1), headers=T2)
        check("租户游标独立（他租户首事件 cursor=1）",
              rr["events"][0]["cursor"] == 1)

        # 13. 显式空租户头 -> 400；缺省走 default
        st, rr = _http("GET", history_url(base, did_rest, 2),
                       headers={"X-Tenant-ID": ""})
        check("显式空租户头 -> 400", st == 400 and set(rr) == {"error"})
        st, rr = _http("GET", history_url(base, did_rest, 2))
        check("default 租户看不到他租户锚点 -> 404", st == 404)

        # 14. 纯只读：连续查询不产生审计
        n_audit = len(audit_events(base, T1))
        for _ in range(5):
            _http("GET", history_url(base, did_rest, 2, "limit=1"),
                  headers=T1)
        check("历史查询不记审计",
              len(audit_events(base, T1)) == n_audit)

        # 15. 与既有路由共存：生命周期历史与 GET uses 不受影响
        st, rr = _http(
            "GET", f"{base}/v1/trust/anchors/{did_rest}/history",
            headers=T1)
        check("生命周期历史仍可用", st == 200 and "events" in rr)
        st, rr = _http(
            "GET", f"{base}/v1/trust/anchors/{did_rest}/2/uses",
            headers=T1)
        check("GET uses 仍可用",
              st == 200 and rr["uses"] == ["generic", "vc", "vp"])

        # 16. 同租户跨 DID 游标持久递增（按追加序：full 注册、rest 注册、
        # rest 轮换、full 六次收紧）
        st, rr = _http("GET", history_url(base, did_rest, 1, "limit=200"),
                       headers=T1)
        c_rest1 = rr["events"][0]["cursor"]
        st, rr = _http("GET", history_url(base, did_rest, 2, "limit=200"),
                       headers=T1)
        c_rest2 = rr["events"][0]["cursor"]
        st, rr = _http("GET", history_url(base, did_full, 1, "limit=200"),
                       headers=T1)
        c_full = [e["cursor"] for e in rr["events"]]
        check("跨 DID 游标全局唯一递增",
              len({c_rest1, c_rest2, *c_full}) == 2 + len(c_full)
              and c_full[0] < c_rest1 < c_rest2 < c_full[1]
              and c_full == sorted(c_full))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 17. 重启后用途历史与游标稳定
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "uses-hist-a"}
        st, r = _http("GET", history_url(base, did_full, 1, "limit=200"),
                      headers=T1)
        check("重启后 7 条事件稳定", st == 200 and len(r["events"]) == 7)
        check("重启后事件内容与游标稳定",
              [e["cursor"] for e in r["events"]] == c_full
              and r["events"][-1]["uses"] == ["generic"]
              and r["events"][-1]["from_uses"] == ["generic", "vc"]
              and r["events"][0]["from_uses"] is None)
        st, r = _http("GET", history_url(base, did_rest, 2), headers=T1)
        check("重启后 rotated 事件稳定",
              r["events"][0]["action"] == "trust.anchor.rotated"
              and r["events"][0]["uses"] == ["generic", "vc", "vp"]
              and r["events"][0]["cursor"] == c_rest2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 18. 旧状态文件补 snapshot：from_uses/updated_at=null、uses=当前值
    legacy_port = 8973
    legacy_store = tempfile.mktemp(suffix=".json")
    legacy_pub = gen_pub()
    legacy_payload = {
        "tenants": {
            "default": {
                "trust_anchors": {
                    "did:web:legacy": {
                        "1": {"key_version": 1, "public_key": legacy_pub,
                              "status": "active", "updated_at": None,
                              "uses": ["did"]},
                        "2": {"key_version": 2, "public_key": legacy_pub,
                              "status": "revoked",
                              "updated_at": "2026-01-02T03:04:05Z",
                              "from_key_version": 1,
                              "uses": ["did", "status"]},
                    }
                }
            }
        },
        "audit": [],
        "audit_seq": 0,
    }
    with open(legacy_store, "w", encoding="utf-8") as fh:
        json.dump(legacy_payload, fh)
    legacy_env = dict(os.environ, VCBACKEND_STORE=legacy_store)
    lproc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(legacy_port), "--host", "127.0.0.1"],
        cwd=ROOT, env=legacy_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    lbase = f"http://127.0.0.1:{legacy_port}"
    try:
        assert wait_up(legacy_port), "旧状态服务启动超时"
        st, r = _http("GET", history_url(lbase, "did:web:legacy", 1))
        check("旧锚点 v1 snapshot 200 恰一条",
              st == 200 and len(r["events"]) == 1)
        ev = r["events"][0]
        check("旧锚点 v1 snapshot 内容",
              ev["action"] == "trust.anchor.registered"
              and ev["from_uses"] is None and ev["updated_at"] is None
              and ev["uses"] == ["did"] and ev["cursor"] == 1)
        st, r = _http("GET", history_url(lbase, "did:web:legacy", 2))
        ev = r["events"][0]
        check("旧锚点 v2 snapshot 为 rotated + 当前用途",
              ev["action"] == "trust.anchor.rotated"
              and ev["from_uses"] is None and ev["updated_at"] is None
              and ev["uses"] == ["did", "status"] and ev["cursor"] == 2)
        check("旧锚点 snapshot 事件键序",
              list(r["events"][0]) == ["cursor", "action", "from_uses",
                                       "uses", "updated_at"])
        # 只读不写：重启重建 cursor 稳定
    finally:
        lproc.terminate()
        try:
            lproc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            lproc.kill()

    lproc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(legacy_port), "--host", "127.0.0.1"],
        cwd=ROOT, env=legacy_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(legacy_port), "旧状态服务重启超时"
        st, r1 = _http("GET", history_url(lbase, "did:web:legacy", 1))
        st2, r2 = _http("GET", history_url(lbase, "did:web:legacy", 2))
        check("旧锚点 snapshot 跨重启 cursor 稳定",
              r1["events"][0]["cursor"] == 1
              and r2["events"][0]["cursor"] == 2
              and r1["events"][0]["uses"] == ["did"]
              and r2["events"][0]["uses"] == ["did", "status"])
    finally:
        lproc.terminate()
        try:
            lproc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            lproc.kill()
        for path in (store, legacy_store):
            if os.path.exists(path):
                os.unlink(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
