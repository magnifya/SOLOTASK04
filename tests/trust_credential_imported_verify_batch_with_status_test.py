#!/usr/bin/env python3
"""已导入外部凭证批量重验并合并同步状态的端到端测试。

POST /v1/trust/credentials/imported/verify-batch-with-status

直接运行：python3 tests/trust_credential_imported_verify_batch_with_status_test.py
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

BATCH_PATH = (
    "/v1/trust/credentials/imported/verify-batch-with-status"
)
ITEM_KEYS = ["valid", "http_status", "reason"]
_UNSET = object()


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
    port = 8981
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(proc, port), "服务启动超时"
        return proc
    def stop(proc):
        proc.terminate()
        proc.wait(timeout=10)

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
        return call(
            "POST", BATCH_PATH, payload=payload, raw=raw, headers=headers
        )

    def item(cred, issuer=None):
        return {"issuer_did": did if issuer is None else issuer,
                "credential_id": cred}

    def audit_seqs(headers):
        st, parsed, _ = call("GET", "/v1/audit?limit=200&after=0",
                             headers=headers)
        assert st == 200
        return [e["seq"] for e in parsed["events"]]

    proc = start()
    T1 = {"X-Tenant-ID": "ivb-a"}
    T2 = {"X-Tenant-ID": "ivb-b"}

    priv1, pub1 = gen_keypair()
    priv2, pub2 = gen_keypair()
    priv3, pub3 = gen_keypair()
    did = "did:web:ivb-issuer.example"
    did_anchor_revoked = "did:web:ivb-revoked-anchor.example"

    c_active = "vc_ivb_active"
    c_rev = "vc_ivb_rev"
    c_rev_noreason = "vc_ivb_rev_noreason"
    c_unknown = "vc_ivb_unknown"
    c_nosync = "vc_ivb_nosync"
    c_v2 = "vc_ivb_v2"
    c_scratch = "vc_ivb_scratch"
    c_anchor_rev = "vc_ivb_anchor_rev"
    c_cross = "vc_ivb_cross"

    def make_body(cred, version=1, issuer=did, extra=None,
                  issued_at="2026-09-20T00:00:00Z"):
        body = {
            "credential_id": cred,
            "issuer_did": issuer,
            "subject_did": "did:web:holder.example",
            "claims": {"level": 7},
            "issued_at": issued_at,
        }
        if version is not None:
            body["issuer_key_version"] = version
        if extra:
            body.update(extra)
        return body

    def import_cred(body, priv):
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body, "signature": crypto.sign(body, priv)},
            headers=T1,
        )
        return st

    def sync_body(cred, status, updated="2026-09-21T00:00:00Z", version=1,
                  reason=_UNSET, issuer=did):
        b = {
            "issuer_did": issuer,
            "credential_id": cred,
            "status": status,
            "updated_at": updated,
            "issuer_key_version": version,
        }
        if reason is not _UNSET:
            b["reason"] = reason
        return b

    def sync_one(cred, status, reason=_UNSET, priv=priv1, version=1,
                 issuer=did, headers=T1, updated="2026-09-21T00:00:00Z"):
        b = sync_body(cred, status, updated=updated, version=version,
                      reason=reason, issuer=issuer)
        return call(
            "POST", "/v1/trust/credential-status/sync",
            {"body": b, "signature": crypto.sign(b, priv)},
            headers=headers,
        )

    body_active = make_body(c_active)
    body_rev = make_body(c_rev)
    body_rev_nr = make_body(c_rev_noreason)
    body_unknown = make_body(c_unknown)
    body_nosync = make_body(c_nosync)
    body_scratch = make_body(
        c_scratch, extra={"expires_at": "2030-01-01T00:00:00Z"}
    )

    try:
        # ---- 准备 T1 锚点与导入/同步数据 ----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T1,
        )
        check("T1 注册 v1 锚点 -> 201", st == 201)
        st, _, _ = call(
            "POST", f"/v1/trust/anchors/{did}/rotate",
            {"from_key_version": 1, "public_key": pub2}, headers=T1,
        )
        check("T1 锚点轮换 v2", st in (200, 201))
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did_anchor_revoked, "public_key": pub3,
             "key_version": 1},
            headers=T1,
        )
        check("T1 注册待吊销锚点 -> 201", st == 201)

        check("导入 active 凭证 -> 201", import_cred(body_active, priv1) == 201)
        check("导入 revoked 凭证 -> 201", import_cred(body_rev, priv1) == 201)
        check("导入 revoked(无 reason) 凭证 -> 201",
              import_cred(body_rev_nr, priv1) == 201)
        check("导入 unknown 凭证 -> 201",
              import_cred(body_unknown, priv1) == 201)
        check("导入未同步凭证 -> 201",
              import_cred(body_nosync, priv1) == 201)
        check("导入 scratch 凭证 -> 201",
              import_cred(body_scratch, priv1) == 201)
        body_v2 = make_body(c_v2, version=2)
        check("导入 v2 凭证 -> 201", import_cred(body_v2, priv2) == 201)
        body_anchor_rev = make_body(
            c_anchor_rev, issuer=did_anchor_revoked
        )
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_anchor_rev,
             "signature": crypto.sign(body_anchor_rev, priv3)},
            headers=T1,
        )
        check("导入待吊销锚点凭证 -> 201", st == 201)

        st, _, _ = sync_one(c_active, "active")
        check("同步 active -> 201", st == 201)
        st, _, _ = sync_one(c_rev, "revoked", reason="证书违规吊销")
        check("同步 revoked(带 reason) -> 201", st == 201)
        st, _, _ = sync_one(c_rev_noreason, "revoked")
        check("同步 revoked(无 reason) -> 201", st == 201)
        st, _, _ = sync_one(c_unknown, "unknown")
        check("同步 unknown -> 201", st == 201)
        st, _, _ = sync_one(c_scratch, "active")
        check("同步 scratch active -> 201", st == 201)
        st, _, _ = sync_one(c_v2, "active", priv=priv2, version=2)
        check("同步 v2 active -> 201", st == 201)
        st, _ = _http(
            "PUT",
            f"{base}/v1/trust/anchors/{did_anchor_revoked}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销待吊销锚点 -> 200", st == 200)

        # ---- T2 同双键数据（跨租户隔离）----
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub1, "key_version": 1},
            headers=T2,
        )
        check("T2 注册同 DID v1 锚点 -> 201", st == 201)
        body_cross = make_body(c_cross)
        st, _, _ = call(
            "POST", "/v1/trust/credentials/import",
            {"body": body_cross,
             "signature": crypto.sign(body_cross, priv1)},
            headers=T2,
        )
        check("T2 导入同 DID 凭证 -> 201", st == 201)
        st, _, _ = sync_one(c_cross, "active", headers=T2)
        check("T2 同步 active -> 201", st == 201)

        # ---- 显式空 X-Tenant-ID -> 400 仅 {error} ----
        st, parsed, _ = batch({"items": []}, headers={"X-Tenant-ID": ""})
        check(
            "显式空 X-Tenant-ID -> 400",
            st == 400 and isinstance(parsed, dict)
            and set(parsed.keys()) == {"error"} and parsed["error"],
        )

        # ---- 请求级非法：统一 200 {"results":[],"reason":"请求..."} ----
        def expect_bad_envelope(name, payload=None, raw=None):
            st, parsed, text = batch(payload=payload, raw=raw, headers=T1)
            check(
                name,
                st == 200
                and list(json.loads(text).keys()) == ["results", "reason"]
                and parsed.get("results") == []
                and isinstance(parsed.get("reason"), str)
                and parsed["reason"].startswith("请求"),
            )

        expect_bad_envelope("空请求体", raw=b"")
        expect_bad_envelope("非法 JSON", raw=b"{bad")
        expect_bad_envelope("JSON 数组", raw=b"[1,2]")
        expect_bad_envelope("JSON 标量", raw=b'"x"')
        expect_bad_envelope("缺 items", {})
        expect_bad_envelope("顶层多余字段", {"items": [], "x": 1})
        expect_bad_envelope("items 非数组（对象）", {"items": {}})
        expect_bad_envelope("items 非数组（字符串）", {"items": "nope"})
        expect_bad_envelope("items 空数组", {"items": []})
        expect_bad_envelope(
            "items 101 项超上限",
            {"items": [item(f"vc_over_{i}") for i in range(101)]},
        )

        # ---- 项级非法：false/400/请求项非法，键序固定，不短路 ----
        bad_items = [
            "scalar",
            42,
            None,
            ["a", "b"],
            {},
            {"issuer_did": did},
            {"credential_id": c_active},
            {"issuer_did": did, "credential_id": c_active, "x": 1},
            {"issuer_did": "", "credential_id": c_active},
            {"issuer_did": did, "credential_id": ""},
            {"issuer_did": 123, "credential_id": c_active},
            {"issuer_did": did, "credential_id": 456},
            {"issuer_did": True, "credential_id": c_active},
        ]
        st, parsed, text = batch({"items": bad_items}, headers=T1)
        ok_len = (
            st == 200 and list(json.loads(text).keys()) == ["results"]
            and isinstance(parsed, dict)
            and len(parsed["results"]) == len(bad_items)
        )
        check("项级非法批 HTTP 200、results 等长同序、外层仅 results",
              ok_len)
        if ok_len:
            check(
                "全部坏项均 false/400/请求项非法 且键序固定",
                all(
                    list(row.keys()) == ITEM_KEYS
                    and row == {"valid": False, "http_status": 400,
                                "reason": "请求项非法"}
                    for row in parsed["results"]
                ),
            )

        # ---- 混合批：成功/404/各类 200 原因，不短路 ----
        mixed = [
            item(c_active),              # 0 active -> true/200/null
            item("vc_never_imported"),   # 1 不存在 -> 404
            item(c_active, "did:web:no-such-issuer.example"),  # 2 错配 404
            item(c_cross),               # 3 他租户双键 -> 404
            item(c_rev),                 # 4 revoked 带 reason
            item(c_rev_noreason),        # 5 revoked 空 reason -> 未知原因
            item(c_unknown),             # 6 unknown
            item(c_nosync),              # 7 未同步
            item(c_v2),                  # 8 v2 active
            item(c_anchor_rev, did_anchor_revoked),  # 9 锚点不可用
            {"issuer_did": did, "credential_id": c_active},  # 10 再成功
            "bad-item",                  # 11 项非法 400
        ]
        st, parsed, text = batch({"items": mixed}, headers=T1)
        check("混合批 HTTP 200、results 等长",
              st == 200 and len(parsed["results"]) == len(mixed))
        if st == 200 and len(parsed.get("results", [])) == len(mixed):
            r = parsed["results"]

            def exact(idx, valid, http_status, reason):
                row = r[idx]
                return (
                    list(row.keys()) == ITEM_KEYS
                    and row["valid"] is valid
                    and row["http_status"] == http_status
                    and row["reason"] == reason
                )

            check("results[0] active -> true/200/null",
                  exact(0, True, 200, None))
            check("results[1] 不存在 -> 404/资源不存在",
                  exact(1, False, 404, "资源不存在"))
            check("results[2] issuer 错配 -> 404/资源不存在",
                  exact(2, False, 404, "资源不存在"))
            check("results[3] 跨租户 -> 404/资源不存在",
                  exact(3, False, 404, "资源不存在"))
            check("results[4] revoked 带 reason",
                  exact(4, False, 200, "外部凭证已吊销：证书违规吊销"))
            check("results[5] revoked 空 reason -> 未知原因",
                  exact(5, False, 200, "外部凭证已吊销：未知原因"))
            check("results[6] unknown",
                  exact(6, False, 200, "外部凭证状态未知"))
            check("results[7] 未同步",
                  exact(7, False, 200, "外部凭证状态未同步"))
            check("results[8] v2 active -> true/200/null",
                  exact(8, True, 200, None))
            check("results[9] 锚点吊销 -> 锚点不可用",
                  exact(9, False, 200, "锚点不可用"))
            check("results[10] 再次成功", exact(10, True, 200, None))
            check("results[11] 项非法 -> 400/请求项非法",
                  exact(11, False, 400, "请求项非法"))

        # ---- T2 视角跨租户：同 DID 的 c_cross 在 T2 为 active，
        #      T1 的 c_active 在 T2 为 404 ----
        st, parsed, _ = batch(
            {"items": [item(c_cross), item(c_active)]}, headers=T2
        )
        check(
            "T2 跨租户视图：自有 active、他租户 404",
            st == 200 and parsed["results"] == [
                {"valid": True, "http_status": 200, "reason": None},
                {"valid": False, "http_status": 404,
                 "reason": "资源不存在"},
            ],
        )

        # ---- 缺省租户 default：无头独立视图，全部 404 ----
        st, parsed, _ = batch({"items": [item(c_active)]})
        check(
            "缺省租户 default 无导入记录 -> 404/资源不存在",
            st == 200 and parsed["results"] == [
                {"valid": False, "http_status": 404,
                 "reason": "资源不存在"},
            ],
        )

        # ---- 100 项上限：100 合法项全部成功 ----
        st, parsed, _ = batch(
            {"items": [item(c_active) for _ in range(100)]}, headers=T1
        )
        check(
            "100 项批合法且全部 true/200/null",
            st == 200 and len(parsed["results"]) == 100
            and all(
                row == {"valid": True, "http_status": 200, "reason": None}
                for row in parsed["results"]
            ),
        )

        # ---- 纯只读：审计不增加 ----
        seqs_before = audit_seqs(T1)
        for _ in range(3):
            batch({"items": mixed}, headers=T1)
            batch({"items": bad_items}, headers=T1)
            batch({"items": []}, headers=T1)
            batch(raw=b"{bad", headers=T1)
        check("各类批量重验不记审计", audit_seqs(T1) == seqs_before)

        # ---- 纯只读：导入原文与同步记录保持不变 ----
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{c_active}?issuer_did={did}",
            headers=T1,
        )
        check(
            "批量重验后导入原文不变",
            st == 200 and parsed.get("body") == body_active
            and isinstance(parsed.get("signature"), str)
            and parsed["signature"],
        )
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credential-status/{c_rev}?issuer_did={did}",
            headers=T1,
        )
        check(
            "批量重验后同步记录不变",
            st == 200 and parsed == {
                "status": "revoked",
                "reason": "证书违规吊销",
                "updated_at": "2026-09-21T00:00:00Z",
            },
        )

        # ---- 既有接口不受影响：单项重验仍成功 ----
        st, parsed, _ = call(
            "POST",
            f"/v1/trust/credentials/imported/{c_active}/verify"
            f"?issuer_did={did}",
            payload={}, headers=T1,
        )
        check("既有单项重验行为不变 -> 200 {valid:true}",
              st == 200 and parsed == {"valid": True})
    finally:
        stop(proc)

    # ---- 重启稳定性 + 落盘原文被篡改的分类原因 ----
    proc = start()
    try:
        st, parsed, _ = batch(
            {"items": [item(c_active), item(c_rev), item(c_nosync),
                       item(c_anchor_rev, did_anchor_revoked)]},
            headers=T1,
        )
        check(
            "重启后结论稳定（active/revoked/未同步/锚点不可用）",
            st == 200 and parsed["results"] == [
                {"valid": True, "http_status": 200, "reason": None},
                {"valid": False, "http_status": 200,
                 "reason": "外部凭证已吊销：证书违规吊销"},
                {"valid": False, "http_status": 200,
                 "reason": "外部凭证状态未同步"},
                {"valid": False, "http_status": 200,
                 "reason": "锚点不可用"},
            ],
        )

        # 篡改 scratch 正文（不重签）-> 签名校验失败
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivb-a"]["imported_credentials"][did][
            c_scratch
        ]
        row["body"]["claims"]["level"] = 999
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        st, parsed, _ = batch({"items": [item(c_scratch)]}, headers=T1)
        check(
            "重启后正文被篡改 -> 签名校验失败",
            st == 200 and parsed["results"] == [
                {"valid": False, "http_status": 200,
                 "reason": "签名校验失败"}
            ],
        )

        # 签名格式错误（且已过期）：签名格式优先于过期
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivb-a"]["imported_credentials"][did][
            c_scratch
        ]
        row["signature"] = "!!!not-base64url!!!"
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        st, parsed, _ = batch({"items": [item(c_scratch)]}, headers=T1)
        check(
            "重启后签名格式非法 -> 签名格式错误（优先于过期）",
            st == 200 and parsed["results"] == [
                {"valid": False, "http_status": 200,
                 "reason": "签名格式错误"}
            ],
        )

        # 用锚点私钥重签已过期正文 -> 凭证已过期（先验签成功，过期先于
        # 同步状态合并）
        data = json.load(open(store_path, encoding="utf-8"))
        row = data["tenants"]["ivb-a"]["imported_credentials"][did][
            c_scratch
        ]
        row["body"]["claims"]["level"] = 7
        row["body"]["expires_at"] = "2000-01-01T00:00:00Z"
        row["signature"] = crypto.sign(row["body"], priv1)
        json.dump(data, open(store_path, "w", encoding="utf-8"))
    finally:
        stop(proc)

    proc = start()
    try:
        st, parsed, _ = batch({"items": [item(c_scratch)]}, headers=T1)
        check(
            "重启后已过期 -> 凭证已过期（优先于同步状态）",
            st == 200 and parsed["results"] == [
                {"valid": False, "http_status": 200,
                 "reason": "凭证已过期"}
            ],
        )

        # 既有导入/读取仍正常
        st, parsed, _ = call(
            "GET",
            f"/v1/trust/credentials/imported/{c_active}?issuer_did={did}",
            headers=T1,
        )
        check("重启后 GET 导入原文仍 200", st == 200)
    finally:
        stop(proc)

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
