#!/usr/bin/env python3
"""GET /v1/credentials 本租户凭证元数据只读检索的端到端测试。

覆盖：
- 响应恰含 credentials/next_after；每项恰含 cursor、credential_id、
  issuer_did、subject_did、issued_at、expires_at、issuer_key_version、
  status、status_updated_at、status_reason、revoked_at、schema_id、
  schema_version 十三字段，不含 claims/signature/私钥；
- 未登记状态按 active（三字段为 null）；无期限/未绑定模式字段为 null；
  suspended/revoked 分别携带裁剪原因与 revoked_at；
- issuer_did/subject_did/status/schema_id+schema_version 筛选；未知或
  他租户筛选值返回空结果；schema 筛选必须成对且版本为正整数；
- limit 默认 50/限 1–200，after 默认 0，仅 ASCII 十进制；未知、重复、
  空值、数字格式非法、越界、成对错误及显式空 X-Tenant-ID 均 400；
- cursor 仅成功签发分配：批量按输入顺序，失败/重复幂等/回滚不消耗；
  跨重启稳定；旧记录缺游标按 (issued_at, credential_id) 补齐且不改写
  正文或签名；
- 纯只读不记审计；租户隔离；其余端点行为不变。

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

PORT = 8962
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
    T1 = {"X-Tenant-ID": "cl-a"}
    T2 = {"X-Tenant-ID": "cl-b"}

    def make_did(headers, handle, base_url=None):
        base_url = base_url or base
        st, body = _http(
            "POST", f"{base_url}/v1/dids",
            {"method": "example", "public_key": handle}, headers=headers,
        )
        assert st == 201, body
        return body["did"]

    def issue(headers, issuer, subject, extra=None, base_url=None):
        base_url = base_url or base
        payload = {
            "issuer_did": issuer, "subject_did": subject,
            "claims": {"role": "admin", "level": 3},
        }
        payload.update(extra or {})
        st, body = _http(
            "POST", f"{base_url}/v1/credentials", payload, headers=headers,
        )
        assert st == 201, body
        return body

    def list_creds(headers, query=None, base_url=None):
        base_url = base_url or base
        url = f"{base_url}/v1/credentials"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers)

    try:
        did_a = make_did(T1, "cl-handle-a")
        did_b = make_did(T1, "cl-handle-b")
        did_t2 = make_did(T2, "cl-handle-c")

        # 注册模式并签发各类凭证
        st, schema = _http(
            "POST", f"{base}/v1/credential-schemas",
            {"schema_id": "member", "version": 2, "issuer_did": did_a,
             "claim_types": {"/role": "string", "/level": "integer"},
             "required_claims": ["/role"]},
            headers=T1,
        )
        assert st == 201, schema

        future = "2099-01-01T00:00:00Z"
        c1 = issue(T1, did_a, did_b)  # 无期限、无模式、无状态
        c2 = issue(T1, did_a, did_b, {
            "expires_at": future, "schema_id": "member", "schema_version": 2,
        })
        # 批量签发两张（输入顺序即游标顺序）
        st, batch = _http(
            "POST", f"{base}/v1/credentials/issue-batch",
            {"items": [
                {"issuer_did": did_b, "subject_did": did_a,
                 "claims": {"role": "user", "level": 1}},
                {"issuer_did": did_a, "subject_did": did_a,
                 "claims": {"role": "ops", "level": 2},
                 "expires_at": future},
            ]},
            headers=T1,
        )
        assert st == 201, batch
        c3, c4 = batch["results"]
        c5 = issue(T2, did_t2, did_t2)

        # 暂停 c3、吊销 c4
        st, sus = _http(
            "PUT", f"{base}/v1/credentials/{c3['credential_id']}/status",
            {"status": "suspended", "reason": "  临时冻结  "}, headers=T1,
        )
        assert st == 200, sus
        st, rev = _http(
            "POST", f"{base}/v1/credentials/{c4['credential_id']}/revoke",
            {"reason": "  泄露吊销  "}, headers=T1,
        )
        assert st == 200, rev

        # ---- 1. 基本列表：字段、游标顺序、null 语义 ----
        st, page = list_creds(T1)
        check("响应恰含 credentials/next_after",
              st == 200 and set(page) == {"credentials", "next_after"})
        items = page["credentials"]
        check("本租户 4 张、按 cursor 升序",
              len(items) == 4
              and [it["cursor"] for it in items] == [1, 2, 3, 4]
              and page["next_after"] == 4)
        check("每项恰十三字段",
              all(set(it) == ITEM_FIELDS for it in items))
        check("签发顺序即 cursor 顺序（批量按输入顺序）",
              [it["credential_id"] for it in items] == [
                  c1["credential_id"], c2["credential_id"],
                  c3["credential_id"], c4["credential_id"],
              ])
        it1 = items[0]
        check("未登记状态按 active、相关字段为 null",
              it1["status"] == "active"
              and it1["status_updated_at"] is None
              and it1["status_reason"] is None
              and it1["revoked_at"] is None)
        check("无期限/未绑定模式字段为 null",
              it1["expires_at"] is None
              and it1["schema_id"] is None
              and it1["schema_version"] is None)
        check("元数据来自正文且不含私钥",
              it1["issuer_did"] == did_a and it1["subject_did"] == did_b
              and bool(Z_RE.match(it1["issued_at"]))
              and it1["issuer_key_version"] == 1)
        it2 = items[1]
        check("有期限/绑定模式字段如实返回",
              it2["expires_at"] == future
              and it2["schema_id"] == "member"
              and it2["schema_version"] == 2)
        it3 = items[2]
        check("suspended 项带裁剪原因、revoked_at 为 null",
              it3["status"] == "suspended"
              and it3["status_reason"] == "临时冻结"
              and bool(Z_RE.match(it3["status_updated_at"] or ""))
              and it3["revoked_at"] is None)
        it4 = items[3]
        check("revoked 项带原因与 revoked_at",
              it4["status"] == "revoked"
              and it4["status_reason"] == "泄露吊销"
              and bool(Z_RE.match(it4["revoked_at"] or ""))
              and it4["status_updated_at"] == it4["revoked_at"])

        # ---- 2. 筛选 ----
        st, page = list_creds(T1, f"issuer_did={did_b}")
        check("按 issuer_did 筛选",
              st == 200 and [it["credential_id"] for it in page["credentials"]]
              == [c3["credential_id"]])
        st, page = list_creds(T1, f"subject_did={did_b}")
        check("按 subject_did 筛选",
              st == 200 and len(page["credentials"]) == 2)
        st, page = list_creds(T1, "status=active")
        check("按 status=active 筛选（含未登记）",
              st == 200 and [it["credential_id"] for it in page["credentials"]]
              == [c1["credential_id"], c2["credential_id"]])
        st, page = list_creds(T1, "status=suspended")
        check("按 status=suspended 筛选",
              st == 200 and [it["credential_id"] for it in page["credentials"]]
              == [c3["credential_id"]])
        st, page = list_creds(T1, "status=revoked")
        check("按 status=revoked 筛选",
              st == 200 and [it["credential_id"] for it in page["credentials"]]
              == [c4["credential_id"]])
        st, page = list_creds(T1, "schema_id=member&schema_version=2")
        check("按 schema_id+schema_version 筛选",
              st == 200 and [it["credential_id"] for it in page["credentials"]]
              == [c2["credential_id"]])
        st, page = list_creds(T1, "issuer_did=did:example:nobody")
        check("未知 issuer_did 返回空结果且 next_after 保持 after",
              st == 200 and page["credentials"] == []
              and page["next_after"] == 0)
        st, page = list_creds(
            T1, f"issuer_did={did_t2}&after=2")
        check("他租户筛选值返回空结果",
              st == 200 and page["credentials"] == []
              and page["next_after"] == 2)
        st, page = list_creds(T1, "schema_id=member&schema_version=9")
        check("未知模式版本返回空结果",
              st == 200 and page["credentials"] == [])
        st, page = list_creds(
            T1, f"issuer_did={did_a}&status=revoked")
        check("组合筛选取交集",
              st == 200 and [it["credential_id"] for it in page["credentials"]]
              == [c4["credential_id"]])

        # ---- 3. 租户隔离与只读 ----
        st, page = list_creds(T2)
        check("他租户仅见本租户凭证（cursor 自 1 起）",
              st == 200 and len(page["credentials"]) == 1
              and page["credentials"][0]["credential_id"]
              == c5["credential_id"]
              and page["credentials"][0]["cursor"] == 1)
        st, audit_before = _http("GET", f"{base}/v1/audit?limit=200",
                                 headers=T1)
        list_creds(T1)
        list_creds(T1, "status=active&limit=2")
        st, audit_after = _http("GET", f"{base}/v1/audit?limit=200",
                                headers=T1)
        check("检索只读不记审计",
              len(audit_after["events"]) == len(audit_before["events"]))

        # ---- 4. 分页 ----
        st, p1 = list_creds(T1, "limit=2")
        check("limit=2 首页", st == 200
              and [it["cursor"] for it in p1["credentials"]] == [1, 2]
              and p1["next_after"] == 2)
        st, p2 = list_creds(T1, f"limit=2&after={p1['next_after']}")
        check("after 续页", st == 200
              and [it["cursor"] for it in p2["credentials"]] == [3, 4]
              and p2["next_after"] == 4)
        st, p3 = list_creds(T1, "limit=2&after=4")
        check("末页之后空页、next_after 等于 after",
              st == 200 and p3["credentials"] == []
              and p3["next_after"] == 4)
        st, p4 = list_creds(T1, "limit=200")
        check("limit=200 合法", st == 200 and len(p4["credentials"]) == 4)

        # ---- 5. 非法参数一律 400 且仅含非空中文 error ----
        def list_400(query, name, headers=None):
            st, r = list_creds(headers or T1, query)
            check(name, st == 400 and set(r) == {"error"}
                  and isinstance(r["error"], str) and r["error"])

        list_400("limit=0", "limit=0 -> 400")
        list_400("limit=201", "limit=201 -> 400")
        list_400("limit=-1", "limit=-1 -> 400")
        list_400("limit=+1", "limit=+1 -> 400")
        list_400("limit=1.5", "limit=1.5 -> 400")
        list_400("limit=true", "limit=true -> 400")
        list_400("limit=", "空 limit -> 400")
        list_400("limit=%20", "空白 limit -> 400")
        list_400("limit=%E0%A5%91", "Unicode 数字 limit -> 400")
        list_400("limit=1&limit=2", "重复 limit -> 400")
        list_400("after=-1", "after=-1 -> 400")
        list_400("after=1.0", "after=1.0 -> 400")
        list_400("after=", "空 after -> 400")
        list_400("after=0&after=1", "重复 after -> 400")
        list_400("status=deleted", "非法 status -> 400")
        list_400("status=", "空 status -> 400")
        list_400("status=active&status=revoked", "重复 status -> 400")
        list_400("issuer_did=", "空 issuer_did -> 400")
        list_400("subject_did=", "空 subject_did -> 400")
        list_400("issuer_did=a&issuer_did=b", "重复 issuer_did -> 400")
        list_400("schema_id=member", "缺 schema_version -> 400")
        list_400("schema_version=2", "缺 schema_id -> 400")
        list_400("schema_id=&schema_version=2", "空 schema_id -> 400")
        list_400("schema_id=member&schema_version=", "空版本 -> 400")
        list_400("schema_id=member&schema_version=0", "版本 0 -> 400")
        list_400("schema_id=member&schema_version=-2", "负版本 -> 400")
        list_400("schema_id=member&schema_version=2.0", "小数版本 -> 400")
        list_400("schema_id=member&schema_version=abc", "字母版本 -> 400")
        list_400("schema_id=a&schema_id=b&schema_version=1",
                 "重复 schema_id -> 400")
        list_400("foo=1", "未知参数 -> 400")
        list_400("cursor=1", "未知参数 cursor -> 400")
        st, r = list_creds({"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400 且仅含非空 error",
              st == 400 and set(r) == {"error"} and bool(r["error"]))

        # ---- 6. 失败签发与重复幂等不消耗游标 ----
        st, _ = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": did_a, "subject_did": "did:example:ghost",
             "claims": {}},
            headers=T1,
        )
        check("未知 subject 签发失败 400", st == 400)
        idem = {"X-Tenant-ID": "cl-a", "Idempotency-Key": "cl-idem-1"}
        st, first = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": did_a, "subject_did": did_b,
             "claims": {"role": "k", "level": 1}},
            headers=idem,
        )
        assert st == 201, first
        st, replay = _http(
            "POST", f"{base}/v1/credentials",
            {"issuer_did": did_a, "subject_did": did_b,
             "claims": {"role": "k", "level": 1}},
            headers=idem,
        )
        check("同内容幂等重放 200 且同 credential_id",
              st == 200
              and replay["credential_id"] == first["credential_id"])
        st, page = list_creds(T1)
        cursors = {it["credential_id"]: it["cursor"]
                   for it in page["credentials"]}
        check("失败与重复幂等不消耗游标（幂等首签 cursor=5）",
              cursors[first["credential_id"]] == 5
              and page["next_after"] == 5)
        c6 = issue(T1, did_a, did_b)
        st, page = list_creds(T1)
        check("后续签发游标接续（=6）",
              page["credentials"][-1]["credential_id"]
              == c6["credential_id"]
              and page["credentials"][-1]["cursor"] == 6)

        # 既有按 ID 查询与验签行为不变
        st, one = _http(
            "GET", f"{base}/v1/credentials/{c1['credential_id']}",
            headers=T1,
        )
        check("GET /v1/credentials/{id} 行为不变",
              st == 200 and set(one) == {
                  "credential_id", "body", "signature"}
              and one["body"]["claims"] == {"role": "admin", "level": 3})
        st, ver = _http(
            "POST", f"{base}/v1/credentials/{c1['credential_id']}/verify",
            {"body": one["body"], "signature": one["signature"]},
            headers=T1,
        )
        check("验签端点行为不变", st == 200 and ver.get("valid") is True)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 7. 跨重启游标稳定；新签发接续 ----
    proc = start_server(PORT, store_path)
    try:
        st, page = list_creds(T1)
        check("重启后 cursor 稳定",
              st == 200
              and [it["cursor"] for it in page["credentials"]]
              == [1, 2, 3, 4, 5, 6])
        c7 = issue(T1, did_a, did_b)
        st, page = list_creds(T1)
        check("重启后新签发游标接续（=7）",
              page["credentials"][-1]["cursor"] == 7
              and page["credentials"][-1]["credential_id"]
              == c7["credential_id"])
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 8. 旧状态兼容：缺游标记录按 (issued_at, credential_id) 补齐 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lp = start_server(PORT + 1, legacy_path)
    lbase = f"http://127.0.0.1:{PORT + 1}"
    L = {"X-Tenant-ID": "legacy"}
    try:
        ldid = make_did(L, "leg-1", lbase)
        la = issue(L, ldid, ldid, base_url=lbase)
        time.sleep(1)
        lb = issue(L, ldid, ldid, base_url=lbase)
        lc = issue(L, ldid, ldid, base_url=lbase)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 手工抹除游标字段与计数，模拟旧版本状态文件
    raw = json.load(open(legacy_path, encoding="utf-8"))
    saved_rows = {}
    for bucket in raw["tenants"].values():
        for cid, rec in bucket.get("credentials", {}).items():
            saved_rows[cid] = (rec["body"], rec["signature"])
            rec.pop("cursor", None)
    raw.pop("credential_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT + 1, legacy_path)
    try:
        st, page = list_creds(L, base_url=lbase)
        items = page["credentials"]
        # issued_at 秒级相同（la 与 lb/lc 间隔 1 秒），同秒按
        # credential_id 字典序
        expect_order = sorted(
            [lb["credential_id"], lc["credential_id"]]
        )
        expected = [la["credential_id"]] + expect_order
        check("旧记录按 (issued_at, credential_id) 补齐游标",
              st == 200 and len(items) == 3
              and [it["credential_id"] for it in items] == expected
              and [it["cursor"] for it in items] == [1, 2, 3])
        # 正文与签名未被改写
        st, one = _http(
            "GET", f"{lbase}/v1/credentials/{la['credential_id']}",
            headers=L,
        )
        body0, sig0 = saved_rows[la["credential_id"]]
        check("补游标不改写正文或签名",
              st == 200 and one["body"] == body0
              and one["signature"] == sig0)
        st, ver = _http(
            "POST",
            f"{lbase}/v1/credentials/{la['credential_id']}/verify",
            {"body": one["body"], "signature": one["signature"]},
            headers=L,
        )
        check("补游标后验签仍有效", st == 200 and ver.get("valid") is True)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 无写操作直接重启：补齐游标稳定重建
    lp = start_server(PORT + 1, legacy_path)
    try:
        st, page = list_creds(L, base_url=lbase)
        check("无写重启后补齐游标稳定",
              st == 200
              and [it["cursor"] for it in page["credentials"]] == [1, 2, 3])
        # 新签发接续补齐后的游标
        ld = issue(L, ldid, ldid, base_url=lbase)
        st, page = list_creds(L, base_url=lbase)
        check("补齐后新签发游标接续（=4）",
              page["credentials"][-1]["credential_id"]
              == ld["credential_id"]
              and page["credentials"][-1]["cursor"] == 4)
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # ---- 9. 直连 store：签发落盘失败回滚不消耗游标 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d = store.create_did("dt", "example", "cl-rollback")
    ok1 = store.create_credential("dt", d.did, d.did, {"k": "v"})

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.create_credential("dt", d.did, d.did, {"k": "v2"})
    except OSError:
        raised = True
    check("签发落盘失败时抛错", raised)
    check("回滚后游标未前进",
          store._credential_cursors.get("dt") == 1)  # noqa: SLF001
    items, next_after = store.list_credentials("dt")
    check("回滚后列表仍仅首张、cursor=1",
          len(items) == 1
          and items[0].credential_id == ok1.credential_id
          and items[0].cursor == 1 and next_after == 1)
    del store._save_locked
    ok2 = store.create_credential("dt", d.did, d.did, {"k": "v3"})
    items, next_after = store.list_credentials("dt")
    check("恢复后签发游标接续（=2）",
          len(items) == 2 and items[1].credential_id == ok2.credential_id
          and items[1].cursor == 2 and next_after == 2)
    # 批量回滚同样不消耗游标
    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.create_credentials_batch("dt", [
            {"issuer_did": d.did, "subject_did": d.did, "claims": {}},
            {"issuer_did": d.did, "subject_did": d.did, "claims": {}},
        ])
    except OSError:
        raised = True
    check("批量落盘失败时抛错且游标未前进",
          raised and store._credential_cursors.get("dt") == 2)  # noqa: SLF001
    del store._save_locked
    store.create_credentials_batch("dt", [
        {"issuer_did": d.did, "subject_did": d.did, "claims": {"n": 1}},
        {"issuer_did": d.did, "subject_did": d.did, "claims": {"n": 2}},
    ])
    items, _ = store.list_credentials("dt")
    check("恢复后批量按输入顺序分配游标（=3,4）",
          [it.cursor for it in items] == [1, 2, 3, 4])

    for path in (store_path, legacy_path, direct_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("凭证列表检索测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
