#!/usr/bin/env python3
"""GET /v1/credential-schemas 租户内只读模式发现目录的端到端测试。

覆盖：
- 成功 200：正文恰含 schemas、next_after；每项恰含 cursor、schema_id、
  version、issuer_did、claim_types、required_claims、digest、status、
  reason、updated_at；内容字段与单条模式读取一致；active 的
  reason/updated_at 为 null，deprecated/revoked 反映当前生命周期；
- 排序与游标：按注册事件游标升序，cursor 与该模式 history 注册事件
  游标一致；after 排除不大于它的项，next_after 取本页末项 cursor，
  空页保持 after；limit 缺省 50、边界 1/200；
- 过滤：issuer_did、schema_id、status 及组合；未知/他租户筛选值与
  status 无匹配均返回空结果（存在性不可探测）；
- 400：未知/重复参数、空值、空白、符号、小数、布尔词、Unicode 数字、
  格式或范围错误，统一恰返 {"error": "请求非法"}；显式空 X-Tenant-ID
  同样 400；
- 租户隔离：缺省 default 与其他租户只见本租户目录；
- 纯只读：列表（含 400）不记审计、不触发落盘；
- 跨重启分页结果稳定；旧状态文件（无历史/游标）加载补录后目录可用、
  游标与 history 一致且再次重启稳定；
- 现有单项查询、签发门禁语义不变。

直接运行：python3 tests/credential_schema_catalog_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import atexit
import hashlib
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

# 统一以 --port 0 让内核分配空闲端口，并解析服务自身输出的
# VCBACKEND_READY 行取得实际端口，避免误连占用固定端口的残留进程。
BASE = "http://127.0.0.1:0"
INVALID = {"error": "请求非法"}
UNAVAILABLE = {"error": "credential schema unavailable"}

PAGE_FIELDS = ["schemas", "next_after"]
ITEM_FIELDS = [
    "cursor", "schema_id", "version", "issuer_did", "claim_types",
    "required_claims", "digest", "status", "reason", "updated_at",
]

_PROCS = []


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


def _wait_health(base, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"{base}/health")
            return True
        except OSError:
            time.sleep(0.1)
    return False


def start_server(env):
    global BASE
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", "0", "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    _PROCS.append(proc)
    base = None
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError("服务进程提前退出")
            time.sleep(0.05)
            continue
        if line.startswith("VCBACKEND_READY"):
            match = re.search(r"port=(\d+)", line)
            if match:
                base = f"http://127.0.0.1:{match.group(1)}"
                break
    if base is None:
        raise RuntimeError("未取得服务实际端口")
    if not _wait_health(base):
        raise RuntimeError("服务启动超时")
    BASE = base
    return proc


def _cleanup_procs():
    for proc in _PROCS:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    atexit.register(_cleanup_procs)
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    T = {"X-Tenant-ID": "cat-a"}
    T2 = {"X-Tenant-ID": "cat-b"}

    proc = start_server(env)

    def catalog(query=None, headers=None):
        url = f"{BASE}/v1/credential-schemas"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers if headers is not None else T)

    def audit_events(headers=None):
        st, r = _http("GET", f"{BASE}/v1/audit?limit=200",
                      headers=headers if headers is not None else T)
        assert st == 200, (st, r)
        return r["events"]

    def register(schema_id, version, issuer, headers=None,
                 claim_types=None, required=None):
        return _http(
            "POST", f"{BASE}/v1/credential-schemas",
            {
                "schema_id": schema_id,
                "version": version,
                "issuer_did": issuer,
                "claim_types": claim_types or {"/name": "string"},
                "required_claims": required or ["/name"],
            },
            headers=headers if headers is not None else T,
        )

    def history(schema_id, version, issuer, headers=None):
        url = (
            f"{BASE}/v1/credential-schemas/{schema_id}/{version}/history"
            f"?issuer_did={urllib.parse.quote(issuer, safe='')}&limit=200"
        )
        return _http(
            "GET", url, headers=headers if headers is not None else T
        )

    def single_get(schema_id, version, issuer, headers=None):
        url = (
            f"{BASE}/v1/credential-schemas/{schema_id}/{version}"
            f"?issuer_did={urllib.parse.quote(issuer, safe='')}"
        )
        return _http(
            "GET", url, headers=headers if headers is not None else T
        )

    try:
        # ---- 准备：两个租户的 DID ----
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-cat-1"},
                      headers=T)
        assert st == 201, (st, r)
        issuer1 = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-cat-2"},
                      headers=T)
        assert st == 201, (st, r)
        issuer2 = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "subject-cat"},
                      headers=T)
        assert st == 201, (st, r)
        subject = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "issuer-cat-b"},
                      headers=T2)
        assert st == 201, (st, r)
        issuer_b = r["did"]

        claim_types_full = {
            "/name": "string",
            "/age": "integer",
            "/tags": "array",
            "/tags/0": "string",
        }
        required_full = ["/name", "/age"]

        # ---- 准备：租户 A 的模式（含三种生命周期状态）----
        st, _ = register("alpha_doc", 1, issuer1,
                         claim_types=claim_types_full,
                         required=required_full)
        assert st == 201
        st, alpha_v2 = register("alpha_doc", 2, issuer1,
                                claim_types=claim_types_full,
                                required=required_full)
        assert st == 201
        alpha_v2_digest = alpha_v2["digest"]
        st, beta_v1 = register("beta_doc", 1, issuer1)
        assert st == 201
        # 同 schema_id 的第二个签发者（验证目录跨 issuer 聚合同名模式）
        st, _ = register("alpha_doc", 1, issuer2,
                         claim_types=claim_types_full,
                         required=required_full)
        assert st == 201
        # 租户 B 同名模式（验证租户隔离）
        st, _ = register("alpha_doc", 1, issuer_b, headers=T2)
        assert st == 201

        # alpha_doc v1 弃用；beta_doc v1 吊销
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/alpha_doc/1/status",
            {"issuer_did": issuer1, "status": "deprecated",
             "reason": "旧版本"}, headers=T)
        assert st == 201, (st,)
        st, _ = _http(
            "POST", f"{BASE}/v1/credential-schemas/beta_doc/1/status",
            {"issuer_did": issuer1, "status": "revoked"}, headers=T)
        assert st == 201, (st,)

        # page_doc 51 个版本：仅用于缺省 limit=50 与翻页验证
        for ver in range(1, 52):
            st, _ = register("page_doc", ver, issuer1)
            assert st == 201, (ver, st)

        # ========================================================== #
        # 1. 成功响应形状与全部状态列出
        # ========================================================== #
        st, master = catalog("limit=200")
        check("无过滤 200", st == 200)
        check("正文恰含 schemas、next_after（键序）",
              list(master.keys()) == PAGE_FIELDS)
        items = master["schemas"]
        check("租户 A 共 55 个模式版本", len(items) == 55)
        check("每项恰含十字段（键序）",
              all(list(item.keys()) == ITEM_FIELDS for item in items))
        cursors = [item["cursor"] for item in items]
        check("cursor 严格升序",
              all(cursors[i] < cursors[i + 1]
                  for i in range(len(cursors) - 1)))
        check("未过滤时列出全部状态",
              {item["status"] for item in items}
              == {"active", "deprecated", "revoked"})

        def find_item(schema_id, version, issuer):
            for item in items:
                if (
                    item["schema_id"] == schema_id
                    and item["version"] == version
                    and item["issuer_did"] == issuer
                ):
                    return item
            return None

        a1 = find_item("alpha_doc", 1, issuer1)
        a2 = find_item("alpha_doc", 2, issuer1)
        b1 = find_item("beta_doc", 1, issuer1)
        a1_i2 = find_item("alpha_doc", 1, issuer2)
        check("三个样本均在目录中",
              a1 is not None and a2 is not None and b1 is not None
              and a1_i2 is not None)
        check("active 样本 status/reason/updated_at",
              a2["status"] == "active" and a2["reason"] is None
              and a2["updated_at"] is None)
        check("deprecated 样本反映生命周期",
              a1["status"] == "deprecated" and a1["reason"] == "旧版本"
              and isinstance(a1["updated_at"], str)
              and a1["updated_at"].endswith("Z"))
        check("revoked 样本反映生命周期（缺省原因）",
              b1["status"] == "revoked"
              and b1["reason"] == "模式版本已吊销"
              and isinstance(b1["updated_at"], str))

        # 内容字段与单条模式读取一致
        st, single = single_get("alpha_doc", 2, issuer1)
        check("单条模式读取 200", st == 200)
        check("目录内容字段与单条读取一致",
              all(a2[key] == single[key] for key in (
                  "schema_id", "version", "issuer_did", "claim_types",
                  "required_claims", "digest"))
              and a2["digest"] == alpha_v2_digest)
        st, single_page = single_get("page_doc", 51, issuer1)
        page51 = find_item("page_doc", 51, issuer1)
        check("page_doc v51 内容一致",
              st == 200 and page51 is not None
              and page51["digest"] == single_page["digest"]
              and page51["claim_types"] == single_page["claim_types"])

        # cursor 与该模式 history 注册事件游标一致
        for schema_id, version, issuer in (
            ("alpha_doc", 1, issuer1),     # deprecated
            ("alpha_doc", 2, issuer1),     # active
            ("beta_doc", 1, issuer1),      # revoked
            ("alpha_doc", 1, issuer2),     # 另一签发者
            ("page_doc", 1, issuer1),
            ("page_doc", 51, issuer1),
        ):
            st, hist = history(schema_id, version, issuer)
            registered = [
                e for e in hist["events"]
                if e["action"] == "credential.schema.registered"
            ]
            item = find_item(schema_id, version, issuer)
            check(
                f"cursor 与注册事件一致 {schema_id} v{version}",
                st == 200 and len(registered) == 1
                and item is not None
                and item["cursor"] == registered[0]["cursor"],
            )

        # ========================================================== #
        # 2. 分页：after / limit / next_after
        # ========================================================== #
        # 缺省 limit=50（page_doc 恰 51 个版本）
        st, p_default = catalog(f"schema_id=page_doc&issuer_did={issuer1}")
        check("缺省 limit 为 50",
              st == 200 and len(p_default["schemas"]) == 50)
        st, p50 = catalog(
            f"schema_id=page_doc&issuer_did={issuer1}&limit=50"
        )
        check("显式 limit=50 与缺省一致",
              st == 200 and p_default["schemas"] == p50["schemas"]
              and p_default["next_after"] == p50["next_after"])
        st, p_rest = catalog(
            f"schema_id=page_doc&issuer_did={issuer1}"
            f"&limit=50&after={p50['next_after']}"
        )
        check("第二页恰剩 1 项（v51）",
              st == 200 and len(p_rest["schemas"]) == 1
              and p_rest["schemas"][0]["version"] == 51)
        last_cursor = p_rest["schemas"][0]["cursor"]
        check("next_after 取本页末项 cursor",
              p_rest["next_after"] == last_cursor)
        st, p_empty = catalog(
            f"schema_id=page_doc&issuer_did={issuer1}"
            f"&after={last_cursor}"
        )
        check("无结果时 next_after 保持 after",
              st == 200 and p_empty["schemas"] == []
              and p_empty["next_after"] == last_cursor)
        page_versions = [
            item["version"]
            for item in p50["schemas"] + p_rest["schemas"]
        ]
        check("page_doc 51 个版本按注册游标升序即版本升序",
              page_versions == list(range(1, 52)))

        # after 排除不大于它的项
        pivot = items[10]["cursor"]
        st, p_after = catalog(f"limit=200&after={pivot}")
        check("after 排除 cursor 不大于它的项",
              st == 200 and len(p_after["schemas"]) == 44
              and all(item["cursor"] > pivot
                      for item in p_after["schemas"])
              and p_after["schemas"] == items[11:])

        # limit 边界
        for value, ok in (("1", 1), ("200", 55), ("0", None), ("201", None)):
            st, r = catalog(f"limit={value}")
            if ok is not None:
                check(f"limit={value} -> 200 且 {ok} 项",
                      st == 200 and len(r["schemas"]) == ok)
            else:
                check(f"limit={value} -> 400", st == 400 and r == INVALID)
        st, r = catalog("limit=01")
        check("前导零数字按值接受", st == 200 and len(r["schemas"]) == 1)

        # ========================================================== #
        # 3. 过滤条件与存在性不可探测
        # ========================================================== #
        st, r = catalog(f"issuer_did={issuer1}&limit=200")
        check("按 issuer1 过滤 54 项",
              st == 200 and len(r["schemas"]) == 54
              and all(i["issuer_did"] == issuer1 for i in r["schemas"]))
        st, r = catalog(f"issuer_did={issuer2}")
        check("按 issuer2 过滤 1 项",
              st == 200 and len(r["schemas"]) == 1
              and r["schemas"][0]["issuer_did"] == issuer2)
        st, r = catalog("issuer_did=did:web:ghost")
        check("未知 issuer_did 返回空结果而非 404",
              st == 200 and r == {"schemas": [], "next_after": 0})
        # 租户 B 的签发者在租户 A 目录中不可见（存在性不可探测）
        st, r = catalog(f"issuer_did={issuer_b}")
        check("跨租户 issuer_did 过滤返回空",
              st == 200 and r == {"schemas": [], "next_after": 0})

        st, r = catalog("schema_id=alpha_doc")
        check("按 schema_id 聚合跨签发者 3 项",
              st == 200 and len(r["schemas"]) == 3
              and {i["issuer_did"] for i in r["schemas"]}
              == {issuer1, issuer2})
        st, r = catalog("schema_id=ghost_doc")
        check("未知 schema_id 返回空结果",
              st == 200 and r == {"schemas": [], "next_after": 0})
        st, r = catalog(f"schema_id=alpha_doc&issuer_did={issuer1}")
        check("issuer + schema 组合过滤 2 项",
              st == 200 and len(r["schemas"]) == 2
              and {i["version"] for i in r["schemas"]} == {1, 2})

        st, r = catalog("status=active&limit=200")
        check("status=active 53 项",
              st == 200 and len(r["schemas"]) == 53
              and all(i["status"] == "active" for i in r["schemas"]))
        st, r = catalog("status=deprecated")
        check("status=deprecated 1 项",
              st == 200 and len(r["schemas"]) == 1
              and r["schemas"][0]["schema_id"] == "alpha_doc"
              and r["schemas"][0]["version"] == 1)
        st, r = catalog("status=revoked")
        check("status=revoked 1 项",
              st == 200 and len(r["schemas"]) == 1
              and r["schemas"][0]["schema_id"] == "beta_doc")
        st, r = catalog("status=revoked&schema_id=alpha_doc")
        check("status 无匹配返回空结果",
              st == 200 and r == {"schemas": [], "next_after": 0})

        # ========================================================== #
        # 4. 非法查询参数：统一恰返 {"error": "请求非法"}
        # ========================================================== #
        bad_queries = [
            # 未知参数
            "foo=1", "limit=50&foo=", "after=1&unknown=2",
            # issuer_did
            "issuer_did=", "issuer_did=%20", "issuer_did=%09",
            "issuer_did=x&issuer_did=y",
            # schema_id
            "schema_id=", "schema_id=%20", "schema_id=BAD",
            "schema_id=1abc", "schema_id=has.dot",
            "schema_id=" + "a" * 65,
            "schema_id=alpha_doc&schema_id=beta_doc",
            # status
            "status=", "status=%20", "status=ACTIVE", "status=Revoked",
            "status=suspended", "status=foo", "status=active%20",
            "status=active&status=revoked",
            # limit
            "limit=", "limit=%20", "limit=0", "limit=201", "limit=-1",
            "limit=abc", "limit=1.5", "limit=1.0", "limit=true",
            "limit=false", "limit=%2B1", "limit=%201", "limit=1%20",
            "limit=1&limit=2",
            # after
            "after=", "after=%20", "after=-1", "after=abc", "after=1.0",
            "after=true", "after=%2B1", "after=1&after=2",
            "after=%D9%A1", "after=%DB111",
        ]
        bad_results = [catalog(q) for q in bad_queries]
        check(
            "未知/重复/空值/空白/符号/小数/布尔词/Unicode/越界均 400"
            "且恰返请求非法",
            all(st == 400 and r == INVALID for st, r in bad_results),
        )

        # 显式空 X-Tenant-ID 与缺省租户
        st, r = catalog(headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400 且恰返请求非法",
              st == 400 and r == INVALID)
        st, r = catalog(
            "limit=0", headers={"X-Tenant-ID": ""}
        )
        check("空租户头时参数错误也统一请求非法", st == 400 and r == INVALID)
        st, r = catalog(headers={})
        check("缺省租户头走 default 租户（空目录）",
              st == 200 and r == {"schemas": [], "next_after": 0})

        # ========================================================== #
        # 5. 租户隔离
        # ========================================================== #
        st, r = catalog(headers=T2)
        check("租户 B 只见本租户 1 项",
              st == 200 and len(r["schemas"]) == 1
              and r["schemas"][0]["issuer_did"] == issuer_b
              and r["schemas"][0]["schema_id"] == "alpha_doc")
        st, r = catalog(f"issuer_did={issuer1}", headers=T2)
        check("租户 B 按租户 A 签发者过滤为空",
              st == 200 and r == {"schemas": [], "next_after": 0})

        # ========================================================== #
        # 6. 纯只读：不记审计、不触发落盘
        # ========================================================== #
        before_audit = audit_events()
        digest_before = file_digest(store_path)
        catalog("limit=200")
        catalog("status=active")
        catalog(f"issuer_did={issuer2}&schema_id=alpha_doc")
        catalog(f"after={items[20]['cursor']}&limit=7")
        catalog("limit=0")             # 400
        catalog("foo=1")               # 400
        catalog(headers={"X-Tenant-ID": ""})  # 400
        catalog(headers=T2)
        digest_after = file_digest(store_path)
        after_audit = audit_events()
        check("目录查询不触发落盘", digest_before == digest_after)
        check("目录查询（含 400）不记审计", before_audit == after_audit)

        # ========================================================== #
        # 7. 现有语义回归：单项查询与签发门禁不变
        # ========================================================== #
        st, r = single_get("beta_doc", 1, issuer1)
        check("单项读取仍 200", st == 200 and r["digest"] == b1["digest"])
        st, r = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer1, "subject_did": subject,
             "claims": {"name": "Bob"},
             "schema_id": "beta_doc", "schema_version": 1},
            headers=T)
        check("引用 revoked 模式签发仍 409 门禁",
              st == 409 and r == UNAVAILABLE)
        st, issue = _http(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer1, "subject_did": subject,
             "claims": {"name": "Bob", "age": 12, "tags": ["x"]},
             "schema_id": "alpha_doc", "schema_version": 2},
            headers=T)
        check("引用 active 模式签发仍 201", st == 201)

        # 签发不影响目录只读内容（新凭证不属于模式目录）
        st, r = catalog("limit=200")
        check("签发后模式目录不变", r["schemas"] == items)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ============================================================== #
    # 8. 跨重启：目录与分页结果稳定
    # ============================================================== #
    proc = start_server(env)
    try:
        st, master2 = catalog("limit=200")
        check("重启后目录 200", st == 200)
        check("重启后目录（含游标/顺序/状态）完全一致",
              master2["schemas"] == items and master2["next_after"])
        st, p = catalog(f"schema_id=page_doc&issuer_did={issuer1}&limit=37")
        check("重启后首页分页一致",
              st == 200 and len(p["schemas"]) == 37
              and p["schemas"] == [
                  it for it in items if it["schema_id"] == "page_doc"
              ][:37])
        st, p = catalog(
            f"schema_id=page_doc&issuer_did={issuer1}"
            f"&limit=37&after={p['next_after']}"
        )
        page_all = [it for it in items if it["schema_id"] == "page_doc"]
        check("重启后次页分页一致",
              st == 200 and [i["version"] for i in p["schemas"]]
              == [i["version"] for i in page_all[37:]])
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ============================================================== #
    # 9. 旧状态文件迁移：删除历史与游标后补录，目录可用且重启稳定
    # ============================================================== #
    raw = json.load(open(store_path, encoding="utf-8"))
    bucket = raw["tenants"]["cat-a"]
    bucket["credential_schema_history"] = {}
    raw.pop("credential_schema_history_cursors", None)
    with open(store_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, ensure_ascii=False)

    proc = start_server(env)
    try:
        st, migrated = catalog("limit=200")
        check("旧文件补录后目录 200 且不缺项",
              st == 200 and len(migrated["schemas"]) == 55)
        mc = [i["cursor"] for i in migrated["schemas"]]
        check("补录游标严格升序",
              all(mc[i] < mc[i + 1] for i in range(len(mc) - 1)))
        # 补录游标须与各自 history 的注册事件一致
        consistent = True
        for item in migrated["schemas"]:
            st, hist = history(
                item["schema_id"], item["version"], item["issuer_did"])
            registered = [
                e for e in hist["events"]
                if e["action"] == "credential.schema.registered"
            ]
            if not (st == 200 and len(registered) == 1
                    and registered[0]["cursor"] == item["cursor"]):
                consistent = False
                break
        check("补录后目录游标与 history 注册事件一致", consistent)
        # after 分页在补录数据上同样成立
        st, p = catalog(
            f"after={migrated['schemas'][9]['cursor']}&limit=200"
        )
        check("补录数据 after 排除语义不变",
              st == 200 and p["schemas"] == migrated["schemas"][10:]
              and p["next_after"] == migrated["next_after"])
        migrated_snapshot = migrated
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 再重启：无写操作时补录游标稳定
    proc = start_server(env)
    try:
        st, migrated2 = catalog("limit=200")
        check("补录游标跨重启稳定",
              st == 200 and migrated2 == migrated_snapshot)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

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
