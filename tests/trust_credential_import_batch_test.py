#!/usr/bin/env python3
"""批量外部凭证导入端到端测试。

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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402


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


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
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


FAIL_KEYS = ["imported", "http_status", "reason"]
OK_KEYS = [
    "imported", "http_status", "issuer_did", "credential_id",
    "body", "signature",
]


def main():
    port = 8973
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    batch_path = "/v1/trust/credentials/import-batch"
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

    def post_batch(payload=None, raw=None, headers=None):
        return call("POST", batch_path, payload=payload, raw=raw,
                    headers=headers)

    def expect_400(name, payload=None, raw=None, headers=None):
        st, parsed, _ = post_batch(payload=payload, raw=raw,
                                   headers=headers)
        check(
            name,
            st == 400
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"error"}
            and isinstance(parsed["error"], str)
            and parsed["error"],
        )

    def expect_item_fail(name, item, http_status, reason_prefix=None):
        check(
            name,
            isinstance(item, dict)
            and list(item.keys()) == FAIL_KEYS
            and item.get("imported") is False
            and item.get("http_status") == http_status
            and isinstance(item.get("reason"), str)
            and item["reason"]
            and (reason_prefix is None
                 or item["reason"].startswith(reason_prefix)),
        )

    try:
        assert wait_up(port), "服务启动超时"

        T1 = {"X-Tenant-ID": "impb-a"}
        T2 = {"X-Tenant-ID": "impb-b"}

        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:batch-importer.example"
        did_rev = "did:web:batch-revoked.example"

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
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

        def make_body(cred, issuer=did, version=1, extra=None,
                      issued_at="2026-09-20T00:00:00Z"):
            body = {
                "credential_id": cred,
                "issuer_did": issuer,
                "subject_did": "did:web:holder.example",
                "claims": {"level": 7, "note": "批量外部凭证"},
                "issued_at": issued_at,
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        def make_item(cred, issuer=did, priv=priv1, extra=None):
            body = make_body(cred, issuer=issuer, extra=extra)
            return body, crypto.sign(body, priv)

        # ---- 外层请求错误 -> 400 仅 {error} ----
        expect_400("空请求体 -> 400", raw=b"")
        expect_400("非法 JSON -> 400", raw=b"not-json")
        expect_400("JSON 数组 -> 400", raw=b"[1]")
        expect_400("空对象缺 items -> 400", {}, headers=T1)
        expect_400(
            "多余字段 -> 400",
            {"items": [{"a": 1}], "x": 1}, headers=T1,
        )
        expect_400("items 非数组 -> 400", {"items": {}}, headers=T1)
        expect_400("items 空数组 -> 400", {"items": []}, headers=T1)
        expect_400(
            "items 超 50 项 -> 400",
            {"items": [{"body": {}, "signature": "s"}] * 51},
            headers=T1,
        )
        body50, sig50 = make_item("vc_b50")
        st, parsed, _ = post_batch(
            {"items": [{"body": body50, "signature": sig50}] * 50},
            headers=T1,
        )
        check(
            "items 恰 50 项 -> 200 等长结果",
            st == 200
            and isinstance(parsed, dict)
            and set(parsed.keys()) == {"results"}
            and len(parsed["results"]) == 50,
        )

        # ---- 显式空 X-Tenant-ID -> 400 ----
        expect_400(
            "显式空 X-Tenant-ID -> 400",
            {"items": [{"body": body50, "signature": sig50}]},
            headers={"X-Tenant-ID": ""},
        )

        # ---- 混合批：逐项不短路，失败/成功键序与状态码 ----
        body_a, sig_a = make_item("vc_b_a")
        body_b, sig_b = make_item("vc_b_b")
        body_no_anchor = make_body("vc_b_noanchor",
                                   issuer="did:web:nope.example")
        sig_no_anchor = crypto.sign(body_no_anchor, priv1)
        body_rev = make_body("vc_b_rev", issuer=did_rev)
        sig_rev = crypto.sign(body_rev, priv2)
        body_expired = make_body(
            "vc_b_expired",
            extra={"expires_at": "2000-01-01T00:00:00Z"},
        )
        sig_expired = crypto.sign(body_expired, priv1)
        body_badexp = make_body(
            "vc_b_badexp", extra={"expires_at": "not-a-date"}
        )
        sig_badexp = crypto.sign(body_badexp, priv1)
        bad_field_body = make_body("vc_b_badfield")
        bad_field_body.pop("claims")

        items = [
            {"body": body_a, "signature": sig_a},          # 0: 201
            "not-an-object",                                # 1: 400 项非对象
            {"body": body_b},                               # 2: 400 缺 signature
            {"body": body_b, "signature": sig_b, "x": 1},   # 3: 400 多余字段
            {"body": bad_field_body, "signature": "s"},     # 4: 400 凭证字段
            {"body": body_no_anchor, "signature": sig_no_anchor},  # 5: 200
            {"body": body_rev, "signature": sig_rev},       # 6: 200 吊销
            {"body": body_a, "signature": "!!!bad!!!"},     # 7: 200 签名格式
            {"body": body_expired, "signature": sig_expired},  # 8: 200 过期
            {"body": body_badexp, "signature": sig_badexp},  # 9: 200 有效期格式
            {"body": body_b, "signature": sig_b},           # 10: 201
        ]
        st, parsed, _ = post_batch({"items": items}, headers=T1)
        check("混合批 -> 200 仅 {results}", st == 200
              and isinstance(parsed, dict)
              and set(parsed.keys()) == {"results"})
        results = parsed["results"] if parsed else []
        check("结果与输入等长", len(results) == len(items))

        r = results[0] if len(results) > 0 else {}
        check(
            "成功项键序 imported,http_status,issuer_did,credential_id,"
            "body,signature 且 201",
            list(r.keys()) == OK_KEYS
            and r.get("imported") is True
            and r.get("http_status") == 201
            and r.get("issuer_did") == did
            and r.get("credential_id") == "vc_b_a"
            and r.get("body") == body_a
            and r.get("signature") == sig_a,
        )
        if len(results) == len(items):
            expect_item_fail("项非对象 -> 400 前缀请求", results[1],
                             400, "请求")
            expect_item_fail("缺 signature -> 400 前缀请求", results[2],
                             400, "请求")
            expect_item_fail("多余字段 -> 400 前缀请求", results[3],
                             400, "请求")
            expect_item_fail("凭证字段错 -> 400 前缀请求", results[4],
                             400, "请求")
            expect_item_fail("锚点缺失 -> 200", results[5], 200)
            check("锚点缺失 reason 沿用单项措辞",
                  "锚点" in results[5]["reason"])
            expect_item_fail("锚点吊销 -> 200", results[6], 200)
            expect_item_fail("签名格式错 -> 200", results[7], 200)
            expect_item_fail("已过期 -> 200", results[8], 200)
            check("过期 reason 为凭证已过期",
                  "凭证已过期" in results[8]["reason"])
            expect_item_fail("expires_at 格式错 -> 200", results[9], 200)
            check(
                "expires_at 格式 reason 沿用单项措辞",
                "凭证字段 expires_at" in results[9]["reason"],
            )
            check(
                "失败项之后的成功项仍 201（不短路）",
                list(results[10].keys()) == OK_KEYS
                and results[10].get("imported") is True
                and results[10].get("http_status") == 201,
            )

        # ---- 失败项不写入 ----
        for cred, issuer in (
            ("vc_b_noanchor", "did:web:nope.example"),
            ("vc_b_rev", did_rev),
            ("vc_b_expired", did),
            ("vc_b_badexp", did),
        ):
            st, _, _ = call(
                "GET",
                f"/v1/trust/credentials/imported/{cred}"
                f"?issuer_did={issuer}",
                headers=T1,
            )
            check(f"失败项 {cred} 不写入（GET 404）", st == 404)

        # ---- 批内同键：同内容首 201 后 200，异内容 409 前缀冲突 ----
        body_c, sig_c = make_item("vc_b_c")
        changed_c = json.loads(json.dumps(body_c))
        changed_c["claims"]["note"] = "批内篡改"
        sig_changed_c = crypto.sign(changed_c, priv1)
        st, parsed, _ = post_batch(
            {"items": [
                {"body": body_c, "signature": sig_c},
                {"body": body_c, "signature": sig_c},
                {"body": changed_c, "signature": sig_changed_c},
            ]},
            headers=T1,
        )
        check("批内同键批 -> 200", st == 200)
        rs = parsed["results"] if parsed else []
        check(
            "批内同键同内容首 201 后 200",
            len(rs) == 3
            and rs[0].get("imported") is True
            and rs[0].get("http_status") == 201
            and rs[1].get("imported") is True
            and rs[1].get("http_status") == 200
            and list(rs[1].keys()) == OK_KEYS,
        )
        check(
            "批内同键异内容 409 前缀冲突",
            len(rs) == 3
            and list(rs[2].keys()) == FAIL_KEYS
            and rs[2].get("imported") is False
            and rs[2].get("http_status") == 409
            and rs[2].get("reason", "").startswith("冲突"),
        )
        # 原记录未被覆盖
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/vc_b_c?issuer_did={did}",
            headers=T1,
        )
        check(
            "批内冲突后原记录保持不变",
            st == 200
            and parsed.get("body") == body_c
            and parsed.get("signature") == sig_c,
        )

        # ---- 跨请求幂等：批量导入后单项重放 200、异内容 409 ----
        st, parsed, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_a, "signature": sig_a}, headers=T1,
        )
        check("批量导入后单项同内容重放 -> 200",
              st == 200 and parsed.get("imported") is True)
        changed_a = json.loads(json.dumps(body_a))
        changed_a["claims"]["level"] = 8
        st, parsed, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": changed_a, "signature": crypto.sign(changed_a, priv1)},
            headers=T1,
        )
        check("批量导入后单项异内容 -> 409", st == 409)
        # 单项导入后批量重放 200
        st, parsed, _ = post_batch(
            {"items": [{"body": body_a, "signature": sig_a}]},
            headers=T1,
        )
        check(
            "批量重放已导入凭证 -> 200",
            st == 200
            and parsed["results"][0].get("imported") is True
            and parsed["results"][0].get("http_status") == 200,
        )

        # ---- 审计：成功项记 trust.credential.imported，失败项不记 ----
        st, audit_text = _http(
            "GET", f"{base}/v1/audit?limit=200", headers=T1
        )
        audit = json.loads(audit_text) if st == 200 else {}
        check("审计查询 -> 200", st == 200)
        imported_evs = [
            e for e in audit["events"]
            if e["action"] == "trust.credential.imported"
        ]
        check(
            "导入审计恰为成功首次导入条数且字段正确",
            len(imported_evs) == 4
            and all(
                e["resource_type"] == "imported_credential"
                for e in imported_evs
            )
            and {e["resource_id"] for e in imported_evs}
            == {
                f"{did}#vc_b50",
                f"{did}#vc_b_a",
                f"{did}#vc_b_b",
                f"{did}#vc_b_c",
            },
        )

        # ---- 缺省租户 default：无头独立导入/读取 ----
        body_def, sig_def = make_item("vc_b_default")
        st, parsed, _ = post_batch(
            {"items": [{"body": body_def, "signature": sig_def}]}
        )
        check(
            "default 租户无锚点 -> 项 200 imported:false",
            st == 200
            and parsed["results"][0].get("imported") is False
            and parsed["results"][0].get("http_status") == 200,
        )
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
        )
        check("default 租户注册锚点 -> 201", st == 201)
        st, parsed, _ = post_batch(
            {"items": [{"body": body_def, "signature": sig_def}]}
        )
        check(
            "缺省租户批量导入 -> 201",
            st == 200
            and parsed["results"][0].get("imported") is True
            and parsed["results"][0].get("http_status") == 201,
        )
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/vc_b_default"
            f"?issuer_did={did}",
        )
        check("缺省租户读取 -> 200",
              st == 200 and parsed.get("body") == body_def)

        # ---- 跨租户隔离：T2 看不到 T1 记录，可独立导入同双键 ----
        st, _, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/vc_b_a?issuer_did={did}",
            headers=T2,
        )
        check("T2 读 T1 导入记录 -> 404", st == 404)
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1},
            headers=T2,
        )
        check("T2 注册同 DID 锚点 -> 201", st == 201)
        body_t2 = make_body("vc_b_a")
        sig_t2 = crypto.sign(body_t2, priv2)
        st, parsed, _ = post_batch(
            {"items": [{"body": body_t2, "signature": sig_t2}]},
            headers=T2,
        )
        check(
            "T2 独立导入同双键 -> 201",
            st == 200
            and parsed["results"][0].get("imported") is True
            and parsed["results"][0].get("http_status") == 201,
        )
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/vc_b_a?issuer_did={did}",
            headers=T1,
        )
        check("T1 记录与 T2 隔离（签名仍为 sig_a）",
              st == 200 and parsed.get("signature") == sig_a)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 持久化：重启后读取/重验一致，重放 200 ----
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        T1 = {"X-Tenant-ID": "impb-a"}
        did = "did:web:batch-importer.example"
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/vc_b_a?issuer_did={did}",
            headers=T1,
        )
        check(
            "重启后 GET 已导入凭证 -> 200 且内容一致",
            st == 200
            and parsed.get("issuer_did") == did
            and parsed.get("credential_id") == "vc_b_a"
            and parsed.get("signature") == sig_a,
        )
        st, parsed, _ = call(
            "POST",
            "/v1/trust/credentials/imported/vc_b_a/verify"
            f"?issuer_did={did}",
            payload={},
            headers=T1,
        )
        check("重启后重验已落盘凭证 -> valid:true",
              st == 200 and parsed.get("valid") is True)
        st, parsed, _ = post_batch(
            {"items": [{"body": body_a, "signature": sig_a}]},
            headers=T1,
        )
        check(
            "重启后批量重放 -> 200",
            st == 200
            and parsed["results"][0].get("imported") is True
            and parsed["results"][0].get("http_status") == 200,
        )
        st, _, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/vc_b_expired"
            f"?issuer_did={did}",
            headers=T1,
        )
        check("重启后失败项仍未写入（GET 404）", st == 404)
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
    raise SystemExit(main())
