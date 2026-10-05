#!/usr/bin/env python3
"""GET /v1/credentials 只读分页列出本租户凭证元数据的端到端测试。

覆盖：
- 响应恰含 credentials/next_after；每项恰含 cursor、credential_id、
  issuer_did、subject_did、issued_at、expires_at、issuer_key_version、
  status、status_updated_at、status_reason、revoked_at、schema_id、
  schema_version，不含 claims/签名/私钥；按 cursor 升序；
- 查询参数仅限 limit/after/issuer_did/subject_did/status/schema_id/
  schema_version：未知、重复、空值、非 ASCII 十进制、越界、status
  非法、schema 未成对均 400（非空中文 error）；显式空 X-Tenant-ID 400；
- limit 默认 50/限 1–200，after 默认 0；next_after 为末项 cursor，
  空页保持 after；未知或他租户筛选值返回空结果；
- 未登记状态按 active（相关时间/原因/revoked_at 为 null）；suspended
  带原因；revoked 带原因与 revoked_at；无期限/未绑定模式字段为 null；
- cursor 仅成功签发分配：批量按输入顺序、失败/回滚/幂等重放不消耗；
  跨重启稳定；旧记录缺游标按 (issued_at, credential_id) 补齐且不改写
  正文或签名；
- 入口纯只读：不记审计、不改变状态；租户隔离不变。

直接运行：python3 tests/credential_list_test.py
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

PORT = 8991
Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

ITEM_FIELDS = {
    "cursor", "credential_id", "issuer_did", "subject_did", "issued_at",
    "expires_at", "issuer_key_version", "status", "status_updated_at",
    "status_reason", "revoked_at", "schema_id", "schema_version",
}


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


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    T1 = {"X-Tenant-ID": "lc-a"}
    T2 = {"X-Tenant-ID": "lc-b"}

    def make_did(headers, handle):
        st, body = _http(
            "POST", f"{base}/v1/dids",
            {"method": "example", "public_key": handle}, headers=headers,
        )
        assert st == 201, body
        return body["did"]

    def issue(headers, issuer, subject, claims=None, **extra):
        payload = {
            "issuer_did": issuer,
            "subject_did": subject,
            "claims": claims if claims is not None else {"role": "admin"},
        }
        payload.update(extra)
        return _http("POST", f"{base}/v1/credentials", payload,
                     headers=headers)

    def list_creds(headers, query=None):
        url = f"{base}/v1/credentials"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    try:
        issuer_a = make_did(T1, "lc-issuer-a")
        subject_a = make_did(T1, "lc-subject-a")
        issuer_b = make_did(T2, "lc-issuer-b")

        # T1：三张普通凭证（issuer_a -> subject_a / issuer_a 自签）
        st, c1 = issue(T1, issuer_a, subject_a)
        assert st == 201, c1
        st, c2 = issue(T1, issuer_a, issuer_a,
                       expires_at="2099-01-01T00:00:00Z")
        assert st == 201, c2
        cid1, cid2 = c1["credential_id"], c2["credential_id"]

        # 模式绑定凭证
        st, sch = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": "employee-badge", "version": 2,
             "issuer_did": issuer_a,
             "claim_types": {"/role": "string"},
             "required_claims": ["/role"]},
            headers=T1,
        )
        assert st == 201, sch
        st, c3 = issue(T1, issuer_a, subject_a,
                       schema_id="employee-badge", schema_version=2)
        assert st == 201, c3
        cid3 = c3["credential_id"]

        # T2：一张凭证（租户隔离对照）
        st, c4 = issue(T2, issuer_b, issuer_b)
        assert st == 201, c4
        cid4 = c4["credential_id"]

        # ---- 1. 基本列表：字段、排序、隔离、不含敏感内容 ----
        st, body = list_creds(T1)
        ok = (
            st == 200 and set(body) == {"credentials", "next_after"}
            and len(body["credentials"]) == 3
        )
        if ok:
            items = body["credentials"]
            ok = (
                all(set(it) == ITEM_FIELDS for it in items)
                and [it["cursor"] for it in items] == [1, 2, 3]
                and [it["credential_id"] for it in items]
                == [cid1, cid2, cid3]
                and body["next_after"] == 3
            )
        check("列表恰两键、三项恰 13 字段、cursor 1..3 升序", ok)

        it1 = body["credentials"][0]
        check(
            "无期限/未绑定/未登记状态字段均为 null",
            it1["expires_at"] is None
            and it1["schema_id"] is None
            and it1["schema_version"] is None
            and it1["status"] == "active"
            and it1["status_updated_at"] is None
            and it1["status_reason"] is None
            and it1["revoked_at"] is None
            and it1["issuer_did"] == issuer_a
            and it1["subject_did"] == subject_a
            and bool(Z_RE.match(it1["issued_at"]))
            and it1["issuer_key_version"] == 1,
        )
        it2 = body["credentials"][1]
        check("有期限凭证 expires_at 原样返回",
              it2["expires_at"] == "2099-01-01T00:00:00Z")
        it3 = body["credentials"][2]
        check("模式绑定凭证带 schema_id/schema_version",
              it3["schema_id"] == "employee-badge"
              and it3["schema_version"] == 2)
        raw_text = json.dumps(body, ensure_ascii=False)
        check("响应不含 claims/签名/私钥材料",
              "claims" not in raw_text and "signature" not in raw_text
              and "private_key" not in raw_text
              and "admin" not in raw_text)

        st, body2 = list_creds(T2)
        check("他租户仅见自己的一张（cursor 自 1 起）",
              st == 200 and len(body2["credentials"]) == 1
              and body2["credentials"][0]["credential_id"] == cid4
              and body2["credentials"][0]["cursor"] == 1
              and body2["next_after"] == 1)

        # 只读：不记审计
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        list_creds(T1)
        list_creds(T1, "issuer_did=" + issuer_a)
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("列表查询只读不记审计",
              len(audit_after["events"]) == len(audit_before["events"]))

        # ---- 2. 筛选 ----
        st, body = list_creds(T1, f"issuer_did={issuer_a}")
        check("按 issuer_did 筛选", st == 200
              and len(body["credentials"]) == 3)
        st, body = list_creds(T1, f"subject_did={issuer_a}")
        check("按 subject_did 筛选",
              st == 200 and [it["credential_id"] for it in body["credentials"]]
              == [cid2])
        st, body = list_creds(
            T1, f"issuer_did={issuer_a}&subject_did={subject_a}")
        check("组合筛选 issuer+subject",
              st == 200 and [it["credential_id"] for it in body["credentials"]]
              == [cid1, cid3])
        st, body = list_creds(T1, "status=active")
        check("按 status=active 筛选（未登记按 active）",
              st == 200 and len(body["credentials"]) == 3)
        st, body = list_creds(T1, "status=suspended")
        check("无匹配状态返回空页、next_after 保持 after",
              st == 200 and body["credentials"] == []
              and body["next_after"] == 0)
        st, body = list_creds(T1, "status=suspended&after=7")
        check("空页 next_after 等于传入 after",
              st == 200 and body["next_after"] == 7)
        st, body = list_creds(
            T1, "schema_id=employee-badge&schema_version=2")
        check("按模式对筛选",
              st == 200 and [it["credential_id"] for it in body["credentials"]]
              == [cid3])
        st, body = list_creds(
            T1, "schema_id=employee-badge&schema_version=1")
        check("模式版本不匹配返回空", st == 200
              and body["credentials"] == [])
        st, body = list_creds(T1, "issuer_did=did:example:unknown")
        check("未知 issuer_did 筛选返回空", st == 200
              and body["credentials"] == [])
        st, body = list_creds(T1, f"issuer_did={issuer_b}")
        check("他租户 issuer_did 筛选返回空", st == 200
              and body["credentials"] == [])

        # ---- 3. 状态反映 ----
        st, _ = _http("PUT", f"{base}/v1/credentials/{cid1}/status",
                      {"status": "suspended", "reason": "  临时冻结  "},
                      headers=T1)
        assert st == 200, _
        st, rv = _http("POST", f"{base}/v1/credentials/{cid2}/revoke",
                       {"reason": "泄露"}, headers=T1)
        assert st == 200, rv
        st, body = list_creds(T1)
        items = {it["credential_id"]: it for it in body["credentials"]}
        check(
            "suspended 项带裁剪原因、revoked 项带原因与 revoked_at",
            items[cid1]["status"] == "suspended"
            and items[cid1]["status_reason"] == "临时冻结"
            and items[cid1]["status_updated_at"] is not None
            and items[cid1]["revoked_at"] is None
            and items[cid2]["status"] == "revoked"
            and items[cid2]["status_reason"] == "泄露"
            and items[cid2]["revoked_at"] == rv["revoked_at"]
            and items[cid2]["status_updated_at"] == rv["revoked_at"],
        )
        st, body = list_creds(T1, "status=revoked")
        check("按 status=revoked 筛选",
              st == 200 and [it["credential_id"] for it in body["credentials"]]
              == [cid2])
        st, body = list_creds(T1, "status=active")
        check("状态变更后 active 仅剩模式绑定项",
              st == 200 and [it["credential_id"] for it in body["credentials"]]
              == [cid3])

        # ---- 4. 分页 ----
        st, body = list_creds(T1, "limit=2")
        check("limit=2 取前两项、next_after 为末项 cursor",
              st == 200 and [it["cursor"] for it in body["credentials"]]
              == [1, 2] and body["next_after"] == 2)
        st, body = list_creds(T1, "limit=2&after=2")
        check("after 翻页取剩余项",
              st == 200 and [it["cursor"] for it in body["credentials"]]
              == [3] and body["next_after"] == 3)
        st, body = list_creds(T1, "after=3")
        check("末项之后空页保持 after",
              st == 200 and body["credentials"] == []
              and body["next_after"] == 3)
        st, body = list_creds(T1, "limit=200")
        check("limit=200 合法", st == 200)

        # ---- 5. 非法查询参数一律 400 且非空中文 error ----
        def bad(query, name, headers=T1):
            st, r = list_creds(headers, query)
            check(name, st == 400 and isinstance(r.get("error"), str)
                  and r["error"] and set(r) == {"error"})

        bad("foo=1", "未知查询参数 -> 400")
        bad("limit=1&limit=2", "重复 limit -> 400")
        bad("after=1&after=2", "重复 after -> 400")
        bad("issuer_did=a&issuer_did=b", "重复 issuer_did -> 400")
        bad("status=active&status=revoked", "重复 status -> 400")
        bad("schema_id=x&schema_id=y", "重复 schema_id -> 400")
        bad("limit=", "空 limit -> 400")
        bad("limit=%20", "空白 limit -> 400")
        bad("limit=0", "limit=0 -> 400")
        bad("limit=201", "limit=201 -> 400")
        bad("limit=-1", "负 limit -> 400")
        bad("limit=+1", "带符号 limit -> 400")
        bad("limit=1.0", "小数 limit -> 400")
        bad("limit=true", "布尔词 limit -> 400")
        bad("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        bad("after=", "空 after -> 400")
        bad("after=-1", "负 after -> 400")
        bad("after=1.5", "小数 after -> 400")
        bad("after=abc", "字母 after -> 400")
        bad("issuer_did=", "空 issuer_did -> 400")
        bad("subject_did=", "空 subject_did -> 400")
        bad("status=", "空 status -> 400")
        bad("status=ACTIVE", "大写 status -> 400")
        bad("status=deleted", "非法 status -> 400")
        bad("schema_id=employee-badge", "仅 schema_id -> 400")
        bad("schema_version=2", "仅 schema_version -> 400")
        bad("schema_id=&schema_version=2", "空 schema_id -> 400")
        bad("schema_id=employee-badge&schema_version=", "空版本 -> 400")
        bad("schema_id=employee-badge&schema_version=0", "版本 0 -> 400")
        bad("schema_id=employee-badge&schema_version=-1", "负版本 -> 400")
        bad("schema_id=employee-badge&schema_version=2.0", "小数版本 -> 400")

        st, r = list_creds({"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and isinstance(r.get("error"), str) and r["error"])

        # ---- 6. 批量签发按输入顺序分配游标；失败不消耗 ----
        st, batch = _http(
            "POST", f"{base}/v1/credentials/issue-batch",
            {"items": [
                {"issuer_did": issuer_a, "subject_did": subject_a,
                 "claims": {"n": 1}},
                {"issuer_did": issuer_a, "subject_did": subject_a,
                 "claims": {"n": 2}},
            ]},
            headers=T1,
        )
        assert st == 201, batch
        batch_ids = [r["credential_id"] for r in batch["results"]]
        st, body = list_creds(T1, "after=3")
        check("批量两项按输入顺序接续游标 4、5",
              st == 200
              and [it["credential_id"] for it in body["credentials"]]
              == batch_ids
              and [it["cursor"] for it in body["credentials"]] == [4, 5])

        # 失败批次（第二项 DID 未知）整批回滚，不消耗游标
        st, _ = _http(
            "POST", f"{base}/v1/credentials/issue-batch",
            {"items": [
                {"issuer_did": issuer_a, "subject_did": subject_a,
                 "claims": {"n": 3}},
                {"issuer_did": "did:example:nobody",
                 "subject_did": subject_a, "claims": {"n": 4}},
            ]},
            headers=T1,
        )
        check("含未知 DID 的批次 -> 400", st == 400)
        # 失败单张签发（未知 subject）不消耗游标
        st, _ = issue(T1, issuer_a, "did:example:nobody")
        check("未知 subject 单张签发 -> 400", st == 400)
        st, c6 = issue(T1, issuer_a, subject_a)
        assert st == 201, c6
        st, body = list_creds(T1, "after=5")
        check("失败签发不消耗游标，新签发为 6",
              st == 200 and len(body["credentials"]) == 1
              and body["credentials"][0]["cursor"] == 6
              and body["credentials"][0]["credential_id"]
              == c6["credential_id"])

        # 幂等重放不消耗游标
        idem = {"Idempotency-Key": "lc-idem-1", **T1}
        st, c7 = issue(idem, issuer_a, subject_a)
        assert st == 201, c7
        st, c7r = issue(idem, issuer_a, subject_a)
        check("幂等重放返回 200 与首次 credential_id",
              st == 200
              and c7r["credential_id"] == c7["credential_id"])
        st, c8 = issue(T1, issuer_a, subject_a)
        assert st == 201, c8
        st, body = list_creds(T1, "after=6")
        check("幂等重放不消耗游标（7、8 连续）",
              st == 200
              and [it["cursor"] for it in body["credentials"]] == [7, 8]
              and [it["credential_id"] for it in body["credentials"]]
              == [c7["credential_id"], c8["credential_id"]])

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 7. 跨重启游标稳定 ----
    proc = start_server(PORT, store_path)
    try:
        st, body = list_creds(T1)
        check("重启后列表与游标稳定",
              st == 200 and len(body["credentials"]) == 8
              and [it["cursor"] for it in body["credentials"]]
              == list(range(1, 9))
              and body["next_after"] == 8)
        st, c9 = issue(T1, issuer_a, subject_a)
        assert st == 201, c9
        st, body = list_creds(T1, "after=8")
        check("重启后新签发接续游标 9",
              st == 200 and len(body["credentials"]) == 1
              and body["credentials"][0]["cursor"] == 9)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 旧状态兼容：缺 cursor 记录按 (issued_at, credential_id) 补齐，
    #         不改写正文或签名；无写重启游标稳定 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "lc-legacy"}
    try:
        leg_issuer = make_did_legacy = None
        st, d = _http("POST", f"{lbase}/v1/dids",
                      {"method": "example", "public_key": "lc-leg"},
                      headers=L)
        assert st == 201, d
        leg_issuer = d["did"]
        leg_ids = []
        leg_bodies = {}
        for idx in range(3):
            st, c = _http(
                "POST", f"{lbase}/v1/credentials",
                {"issuer_did": leg_issuer, "subject_did": leg_issuer,
                 "claims": {"i": idx}},
                headers=L,
            )
            assert st == 201, c
            leg_ids.append(c["credential_id"])
            st, full = _http(
                "GET", f"{lbase}/v1/credentials/{c['credential_id']}",
                headers=L)
            leg_bodies[c["credential_id"]] = full
            time.sleep(1)  # 保证 issued_at 秒级递增
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 手工移除 cursor 字段与计数器，模拟旧版本状态文件
    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        for rec in bucket.get("credentials", {}).values():
            rec.pop("cursor", None)
    raw.pop("credential_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, body = _http("GET", f"{lbase}/v1/credentials", headers=L)
        check("旧记录按 (issued_at, credential_id) 补齐游标 1..3",
              st == 200 and len(body["credentials"]) == 3
              and [it["credential_id"] for it in body["credentials"]]
              == leg_ids
              and [it["cursor"] for it in body["credentials"]] == [1, 2, 3])
        # 正文与签名未被改写
        ok_body = True
        for cid, full in leg_bodies.items():
            st, now = _http("GET", f"{lbase}/v1/credentials/{cid}",
                            headers=L)
            ok_body = (
                ok_body and st == 200
                and now["body"] == full["body"]
                and now["signature"] == full["signature"]
            )
        check("补齐游标不改写正文或签名", ok_body)
        first_cursors = [it["cursor"] for it in body["credentials"]]
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 无写操作直接重启：补齐游标重建为相同值
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, body = _http("GET", f"{lbase}/v1/credentials", headers=L)
        check("无写重启后补齐游标稳定",
              st == 200
              and [it["cursor"] for it in body["credentials"]]
              == first_cursors)
        # 新签发接续补齐后的游标
        st, c = _http(
            "POST", f"{lbase}/v1/credentials",
            {"issuer_did": leg_issuer, "subject_did": leg_issuer,
             "claims": {"i": 9}},
            headers=L,
        )
        assert st == 201, c
        st, body = _http("GET", f"{lbase}/v1/credentials?after=3",
                         headers=L)
        check("补齐后新签发接续游标 4",
              st == 200 and len(body["credentials"]) == 1
              and body["credentials"][0]["cursor"] == 4
              and body["next_after"] == 4)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 落盘后重启仍稳定
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, body = _http("GET", f"{lbase}/v1/credentials", headers=L)
        check("落盘重启后全部游标稳定",
              st == 200
              and [it["cursor"] for it in body["credentials"]]
              == [1, 2, 3, 4])
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 9. 直连 store：签发落盘失败回滚不消耗游标 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("dl", "example", "lc-direct")
    cred = store.create_credential("dl", d.did, d.did, {"k": "v"})
    items, next_after = store.list_credentials("dl")
    check("直连列表返回单项 cursor=1",
          len(items) == 1 and items[0].cursor == 1 and next_after == 1
          and items[0].status == "active"
          and items[0].expires_at is None)

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.create_credential("dl", d.did, d.did, {"k": "v2"})
    except OSError:
        raised = True
    check("签发落盘失败时抛错", raised)
    check("回滚后游标计数未前进",
          store._credential_cursors.get("dl") == 1)  # noqa: SLF001
    items, _ = store.list_credentials("dl")
    check("回滚后列表仍仅首项", len(items) == 1)
    del store._save_locked
    cred2 = store.create_credential("dl", d.did, d.did, {"k": "v3"})
    items, next_after = store.list_credentials("dl")
    check("恢复后新签发接续游标 2",
          len(items) == 2 and items[1].cursor == 2
          and items[1].credential_id == cred2.credential_id
          and next_after == 2)

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("凭证列表测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
