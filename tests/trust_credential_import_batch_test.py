#!/usr/bin/env python3
"""外部凭证原子批量导入端到端测试。

POST /v1/trust/credentials/import-batch

直接运行：python3 tests/trust_credential_import_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
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
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402
from vcbackend.store import VCStore  # noqa: E402

BATCH_PATH = "/v1/trust/credentials/import-batch"
IMPORT_PATH = "/v1/trust/credentials/import"

FAIL_KEYS = ["imported", "http_status", "reason"]
SUCCESS_KEYS = [
    "imported", "http_status", "issuer_did", "credential_id",
    "body", "signature",
]


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
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def wait_up(proc, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def gen_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def main():
    port = 8968
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
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def call(method, path, payload=None, raw=None, headers=None):
        st, text = _http(
            method, f"{base}{path}", payload=payload, raw=raw,
            headers=headers,
        )
        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError:
            parsed = None
        return st, parsed, text

    def batch(payload=None, raw=None, headers=None):
        return call("POST", BATCH_PATH, payload=payload, raw=raw,
                    headers=headers)

    def get_imported(credential_id, issuer, headers):
        url = (f"/v1/trust/credentials/imported/{quote(credential_id)}"
               f"?issuer_did={quote(issuer)}")
        return call("GET", url, headers=headers)

    def imported_verify(credential_id, issuer, headers):
        url = (f"/v1/trust/credentials/imported/{quote(credential_id)}"
               f"/verify?issuer_did={quote(issuer)}")
        return call("POST", url, payload={}, headers=headers)

    def audit_events(headers):
        st, r, _ = call("GET", "/v1/audit?limit=200", headers=headers)
        assert st == 200
        return r["events"]

    try:
        assert wait_up(proc, port), "服务启动超时"

        T1 = {"X-Tenant-ID": "ib-a"}
        T2 = {"X-Tenant-ID": "ib-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:importer-batch.example"
        did_rev = "did:web:revoked-batch.example"
        no_anchor = "did:web:no-anchor-batch.example"

        # 显式空租户头：进入批处理前判 400
        st, r, _ = batch({"items": []}, headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID -> 400",
              st == 400 and isinstance(r, dict) and set(r) == {"error"}
              and isinstance(r["error"], str) and r["error"])

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1}, headers=T1,
        )
        check("注册 active 锚点 -> 201", st == 201)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did_rev, "public_key": pub2, "key_version": 1},
            headers=T1,
        )
        check("注册将吊销锚点 -> 201", st == 201)
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did_rev}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销锚点 -> 200", st == 200)

        def make_body(cred="vc_b_0001", issuer=did, version=1, extra=None):
            body = {
                "credential_id": cred,
                "issuer_did": issuer,
                "subject_did": "did:web:holder.example",
                "claims": {"level": 7, "note": "批量外部凭证"},
                "issued_at": "2026-09-20T00:00:00Z",
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        def signed(body, priv=priv1):
            return {"body": body, "signature": crypto.sign(body, priv)}

        # ---- 1. 外层请求级非法 -> 400 仅 {error}，不写入不审计 ----
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, r, _ = batch(payload=payload, raw=raw, headers=headers)
            check(
                name,
                st == 400 and isinstance(r, dict) and set(r) == {"error"}
                and isinstance(r["error"], str) and r["error"],
            )

        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("JSON 非对象（数组）-> 400", raw=b"[1]")
        expect_400("缺 items -> 400", {})
        expect_400("顶层多余字段 -> 400", {"items": [], "x": 1})
        expect_400("items 非数组 -> 400", {"items": {}})
        expect_400("items 空数组 -> 400", {"items": []})
        expect_400(
            "items 51 项超上限 -> 400",
            {"items": [{"body": make_body(f"vc_over_{i}"),
                        "signature": "x"} for i in range(51)]},
        )

        # ---- 2. 混合批：逐项 400/200 失败且失败不短路（整批回滚）----
        body_ok = make_body("vc_new_1")                          # 本应 201
        item_not_object = [1, 2, 3]                              # 400
        item_missing_body = {"signature": "x"}                   # 400
        item_missing_sig = {"body": body_ok}                     # 400
        item_extra = {"body": body_ok, "signature": "x", "z": 0}  # 400
        item_body_not_obj = {"body": "x", "signature": "x"}      # 400
        item_sig_empty = {"body": body_ok, "signature": ""}      # 400
        body_missing_field = dict(body_ok)
        body_missing_field.pop("subject_did")
        item_body_field = {"body": body_missing_field,
                           "signature": "x"}                     # 400
        item_bad_version = {"body": dict(body_ok,
                                         issuer_key_version=0),
                            "signature": "x"}                    # 400
        body_no_anchor = make_body("vc_no_anchor", issuer=no_anchor)
        item_no_anchor = signed(body_no_anchor)                  # 200 锚点
        body_revoked = make_body("vc_revoked", issuer=did_rev)
        item_revoked_anchor = signed(body_revoked, priv2)        # 200 锚点
        item_bad_sig_fmt = {"body": make_body("vc_badsig"),
                            "signature": "!!!bad!!!"}            # 200 签名格式
        item_bad_sig = signed(make_body("vc_wrongsig"), priv2)   # 200 验签
        tampered = make_body("vc_tampered")
        tampered_sig = crypto.sign(tampered, priv1)
        tampered["claims"]["level"] = 999
        item_tampered = {"body": tampered, "signature": tampered_sig}
        # 200 篡改
        body_expired = make_body(
            "vc_expired", extra={"expires_at": "2000-01-01T00:00:00Z"}
        )
        item_expired = signed(body_expired)                     # 200 过期
        body_bad_exp = make_body(
            "vc_bad_exp", extra={"expires_at": "not-a-date"}
        )
        item_bad_expires = signed(body_bad_exp)                 # 200 格式

        items = [
            signed(body_ok),
            item_not_object,
            item_missing_body,
            item_missing_sig,
            item_extra,
            item_body_not_obj,
            item_sig_empty,
            item_body_field,
            item_bad_version,
            item_no_anchor,
            item_revoked_anchor,
            item_bad_sig_fmt,
            item_bad_sig,
            item_tampered,
            item_expired,
            item_bad_expires,
        ]
        st, r, text = batch({"items": items}, headers=T1)
        check("混合批外层合法 -> HTTP 200 且仅 results",
              st == 200 and isinstance(r, dict)
              and list(r.keys()) == ["results"]
              and len(r["results"]) == len(items))
        # 原始 JSON 顶层键序
        check("顶层键序为 results",
              list(json.loads(text).keys()) == ["results"])

        if isinstance(r, dict) and len(r.get("results", [])) == len(items):
            res = r["results"]

            def fail_row(row):
                return (
                    isinstance(row, dict)
                    and list(row.keys()) == FAIL_KEYS
                    and row["imported"] is False
                    and isinstance(row["http_status"], int)
                    and isinstance(row["reason"], str)
                    and row["reason"]
                )

            # [0] 校验通过但因整批含失败而回滚：结果仍报告 201 成功
            check(
                "results[0] 通过项为成功 201 键序/内容",
                list(res[0].keys()) == SUCCESS_KEYS
                and res[0]["imported"] is True
                and res[0]["http_status"] == 201
                and res[0]["issuer_did"] == did
                and res[0]["credential_id"] == "vc_new_1"
                and res[0]["body"] == body_ok
                and res[0]["signature"] == items[0]["signature"],
            )
            for idx in range(1, 9):
                check(f"results[{idx}] 请求类失败 400 前缀'请求'",
                      fail_row(res[idx]) and res[idx]["http_status"] == 400
                      and res[idx]["reason"].startswith("请求"))
            check("results[1] 项非对象 400",
                  res[1]["reason"].startswith("请求项")
                  and "JSON 对象" in res[1]["reason"])
            check("results[7] 凭证字段错 400 前缀'请求'",
                  res[7]["reason"].startswith("请求凭证"))
            check("results[9] 锚点缺失 200",
                  fail_row(res[9]) and res[9]["http_status"] == 200
                  and res[9]["reason"].startswith("锚点不存在"))
            check("results[10] 锚点已吊销 200",
                  fail_row(res[10]) and res[10]["http_status"] == 200
                  and res[10]["reason"].startswith("锚点已吊销"))
            check("results[11] 签名格式错 200",
                  fail_row(res[11]) and res[11]["http_status"] == 200
                  and res[11]["reason"].startswith("签名格式错误"))
            check("results[12] 验签失败 200",
                  fail_row(res[12]) and res[12]["http_status"] == 200
                  and res[12]["reason"].startswith("签名校验失败"))
            check("results[13] 篡改正文 200",
                  fail_row(res[13]) and res[13]["http_status"] == 200
                  and res[13]["reason"].startswith("签名校验失败"))
            check("results[14] 凭证已过期 200",
                  fail_row(res[14]) and res[14]["http_status"] == 200
                  and res[14]["reason"] == "凭证已过期")
            check("results[15] expires_at 格式错 200",
                  fail_row(res[15]) and res[15]["http_status"] == 200
                  and res[15]["reason"].startswith("凭证字段 expires_at"))

        # ---- 3. 整批回滚：所有凭证均未落盘、无 imported 审计 ----
        for cred in ("vc_new_1", "vc_no_anchor", "vc_revoked", "vc_badsig",
                     "vc_wrongsig", "vc_tampered", "vc_expired",
                     "vc_bad_exp"):
            issuer = did_rev if cred == "vc_revoked" else (
                no_anchor if cred == "vc_no_anchor" else did)
            st, _, _ = get_imported(cred, issuer, T1)
            check(f"回滚: {cred} 未落盘（404）", st == 404)
        check(
            "回滚: 整批不记 trust.credential.imported 审计",
            all(e["action"] != "trust.credential.imported"
                for e in audit_events(T1)),
        )

        # ---- 4. 全部成功的原子批：201/201，逐笔记审计 ----
        body_a = make_body("vc_ok_a")
        body_b = make_body("vc_ok_b")
        # ECDSA 签名随机化：同内容重放必须复用同一签名串，故签名项只构造
        # 一次并在后续重放中复用同一对象。
        item_a = signed(body_a)
        item_b = signed(body_b)
        st, r, text = batch(
            {"items": [item_a, item_b]}, headers=T1
        )
        check("成功批 HTTP 200 等长",
              st == 200 and len(r["results"]) == 2)
        check(
            "两项均 201、键序正确",
            all(list(row.keys()) == SUCCESS_KEYS for row in r["results"])
            and [row["http_status"] for row in r["results"]] == [201, 201]
            and [row["credential_id"] for row in r["results"]]
            == ["vc_ok_a", "vc_ok_b"],
        )
        imported_audits = [
            e for e in audit_events(T1)
            if e["action"] == "trust.credential.imported"
        ]
        check(
            "逐笔记审计且 resource 字段正确",
            [(e["resource_type"], e["resource_id"]) for e in imported_audits]
            == [
                ("imported_credential", f"{did}#vc_ok_a"),
                ("imported_credential", f"{did}#vc_ok_b"),
            ],
        )

        # ---- 5. 批内同键同内容首 201 后 200；异内容 409 ----
        body_same = make_body("vc_dup")
        item_same = signed(body_same)
        body_other = make_body("vc_conflict")
        item_other = signed(body_other)
        changed = dict(body_other)
        changed["claims"] = dict(changed["claims"], note="被改动内容")
        item_changed = signed(changed)
        st, r, _ = batch(
            {"items": [item_same, item_same, item_other, item_changed]},
            headers=T1,
        )
        check("含冲突批 HTTP 200 等长", st == 200 and len(r["results"]) == 4)
        res = r["results"]
        check(
            "同键同内容 201->200",
            res[0]["imported"] is True and res[0]["http_status"] == 201
            and res[1]["imported"] is True and res[1]["http_status"] == 200
            and list(res[1].keys()) == SUCCESS_KEYS
            and res[1]["body"] == body_same
            and res[1]["signature"] == item_same["signature"],
        )
        check(
            "批内异内容 409 前缀'冲突'",
            res[2]["imported"] is True and res[2]["http_status"] == 201
            and list(res[3].keys()) == FAIL_KEYS
            and res[3]["imported"] is False
            and res[3]["http_status"] == 409
            and res[3]["reason"].startswith("冲突")
            and f"{did}#vc_conflict" in res[3]["reason"],
        )
        # 整批回滚：vc_dup 与 vc_conflict 均未落盘
        st, _, _ = get_imported("vc_dup", did, T1)
        check("回滚: vc_dup 未落盘（404）", st == 404)
        st, _, _ = get_imported("vc_conflict", did, T1)
        check("回滚: vc_conflict 未落盘（404）", st == 404)
        # 之前成功批的审计仍恰为 2 条（本批未追加）
        check(
            "冲突回滚不新增审计",
            sum(1 for e in audit_events(T1)
                if e["action"] == "trust.credential.imported") == 2,
        )

        # ---- 6. 与已落盘记录：重放 200 不重复审计；异内容 409 ----
        st, r, _ = batch({"items": [item_a]}, headers=T1)
        check("已落盘同内容批内重放 -> 200",
              st == 200 and r["results"][0]["http_status"] == 200
              and r["results"][0]["body"] == body_a)
        st, r, _ = batch({"items": [item_a, item_b]},
                         headers=T1)
        check("整批重放两项均 200",
              st == 200
              and [x["http_status"] for x in r["results"]] == [200, 200])
        check("重放不新增审计（仍 2 条）",
              sum(1 for e in audit_events(T1)
                  if e["action"] == "trust.credential.imported") == 2)

        changed_a = dict(body_a)
        changed_a["claims"] = dict(changed_a["claims"], level=42)
        st, r, _ = batch({"items": [signed(changed_a)]}, headers=T1)
        check("与已落盘异内容 -> 409 前缀'冲突'",
              st == 200 and r["results"][0]["http_status"] == 409
              and r["results"][0]["reason"].startswith("冲突"))
        # 单项导入契约对该双键仍冲突（409 {error}），原记录不变
        st, r2, _ = call("POST", IMPORT_PATH, signed(changed_a), headers=T1)
        check("单项导入异内容仍 409 {error}",
              st == 409 and isinstance(r2, dict) and set(r2) == {"error"})
        st, r2, _ = get_imported("vc_ok_a", did, T1)
        check("冲突后已落盘原记录不变",
              st == 200 and r2["body"] == body_a)

        # ---- 7. 新凭证 + 已存在重放混合成功批：仅新凭证记一条审计 ----
        body_c = make_body("vc_ok_c")
        item_c = signed(body_c)
        st, r, _ = batch(
            {"items": [item_a, item_c]}, headers=T1
        )
        check("重放+新建混合批 200/201",
              st == 200
              and [x["http_status"] for x in r["results"]] == [200, 201])
        check("仅新建凭证记一条审计（共 3 条）",
              [(e["resource_type"], e["resource_id"])
               for e in audit_events(T1)
               if e["action"] == "trust.credential.imported"]
              == [
                  ("imported_credential", f"{did}#vc_ok_a"),
                  ("imported_credential", f"{did}#vc_ok_b"),
                  ("imported_credential", f"{did}#vc_ok_c"),
              ])

        # ---- 8. 单项导入建立的记录可被批量 200 重放 ----
        body_single = make_body("vc_single_then_batch")
        item_single = signed(body_single)
        st, r, _ = call("POST", IMPORT_PATH, item_single, headers=T1)
        check("单项先导入 -> 201", st == 201)
        st, r, _ = batch({"items": [item_single]}, headers=T1)
        check("批量重放单项已建凭证 -> 200",
              st == 200 and r["results"][0]["http_status"] == 200)

        # ---- 9. 50 项上限：全部新建成功 ----
        bodies50 = [make_body(f"vc_fifty_{i:02d}") for i in range(50)]
        st, r, _ = batch(
            {"items": [signed(b) for b in bodies50]}, headers=T1
        )
        check("50 项批合法且全 201",
              st == 200 and len(r["results"]) == 50
              and all(x["http_status"] == 201 for x in r["results"]))

        # ---- 10. 缺省租户 default：无头独立工作 ----
        body_def = make_body("vc_default_batch")
        # default 租户无锚点 -> 项失败、整批回滚
        st, r, _ = batch({"items": [signed(body_def)]})
        check("default 无锚点 -> HTTP 200 项失败 200",
              st == 200 and r["results"][0]["http_status"] == 200
              and r["results"][0]["imported"] is False)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        check("default 注册锚点 -> 201", st == 201)
        st, r, _ = batch({"items": [signed(body_def)]})
        check("default 批量导入 -> 201",
              st == 200 and r["results"][0]["http_status"] == 201
              and r["results"][0]["imported"] is True)

        # ---- 11. 跨租户隔离 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1}, headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        body_t2 = make_body("vc_ok_a")  # 与 T1 同双键
        sig_t2 = crypto.sign(body_t2, priv2)
        st, r, _ = batch({"items": [{"body": body_t2, "signature": sig_t2}]},
                         headers=T2)
        check("T2 独立首次导入同双键 -> 201",
              st == 200 and r["results"][0]["http_status"] == 201)
        st, r1, _ = get_imported("vc_ok_a", did, T1)
        st2, r2, _ = get_imported("vc_ok_a", did, T2)
        check("T1/T2 同双键视图隔离（签名不同）",
              st == st2 == 200
              and r1["signature"] != r2["signature"]
              and r2["signature"] == sig_t2)
        # 审计按租户隔离
        check("T2 审计独立",
              any(e["action"] == "trust.credential.imported"
                  and e["resource_id"] == f"{did}#vc_ok_a"
                  for e in audit_events(T2)))

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 12. 跨重启：读取/重验一致，重放仍 200 ----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(proc, port), "服务重启超时"
        T1 = {"X-Tenant-ID": "ib-a"}
        body_a = make_body("vc_ok_a")
        st, r, _ = get_imported("vc_ok_a", did, T1)
        check("重启后读取批量导入凭证 -> 200 内容一致",
              st == 200 and r["issuer_did"] == did
              and r["credential_id"] == "vc_ok_a"
              and r["body"] == body_a)
        st, r, _ = imported_verify("vc_ok_a", did, T1)
        check("重启后重新验真 -> {valid:true}",
              st == 200 and r == {"valid": True})
        st, r, _ = batch({"items": [item_a]}, headers=T1)
        check("重启后批内重放 -> 200",
              st == 200 and r["results"][0]["http_status"] == 200)
        check(
            "重启后审计保留",
            [(e["resource_type"], e["resource_id"])
             for e in audit_events(T1)
             if e["action"] == "trust.credential.imported"][:2]
            == [
                ("imported_credential", f"{did}#vc_ok_a"),
                ("imported_credential", f"{did}#vc_ok_b"),
            ],
        )
        # 回滚过的凭证重启后仍不存在
        st, _, _ = get_imported("vc_dup", did, T1)
        check("回滚凭证重启后仍 404", st == 404)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 13. 落盘失败：整批回滚，不写记录、不记审计 ----
    rollback_path = tempfile.mktemp(suffix=".json")
    try:
        rs = VCStore(rollback_path)
        rs.register_trust_anchor("rb", did, pub1, 1)
        rs._save_locked = lambda: (_ for _ in ()).throw(
            OSError("模拟落盘失败"))  # type: ignore[assignment]
        rb_items = [
            signed(make_body("vc_rb_a")),
            signed(make_body("vc_rb_b")),
        ]
        try:
            rs.import_trust_credentials_batch("rb", {"items": rb_items})
            check("落盘失败时批量导入抛错", False)
        except OSError:
            check("落盘失败时批量导入抛错", True)
        for cred in ("vc_rb_a", "vc_rb_b"):
            try:
                rs.get_imported_credential("rb", did, cred)
                check(f"落盘失败回滚: {cred} 不写入", False)
            except Exception:
                check(f"落盘失败回滚: {cred} 不写入", True)
        events, _ = rs.list_audit("rb", 0, 200)
        check("落盘失败不记 imported 审计",
              all(e.action != "trust.credential.imported" for e in events))
    finally:
        if os.path.exists(rollback_path):
            os.remove(rollback_path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
