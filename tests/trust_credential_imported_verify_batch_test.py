#!/usr/bin/env python3
"""已导入外部凭证批量重验（不合并同步状态）端到端测试。

POST /v1/trust/credentials/imported/verify-batch

直接运行：python3 tests/trust_credential_imported_verify_batch_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto, store as store_mod  # noqa: E402


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


PATH = "/v1/trust/credentials/imported/verify-batch"
failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def main():
    port = 8977
    store_path = tempfile.mktemp(suffix=".json")

    def start():
        env = dict(os.environ, VCBACKEND_STORE=store_path)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    def stop(proc):
        proc.terminate()
        proc.wait(timeout=10)

    base = f"http://127.0.0.1:{port}"

    def call(payload=None, raw=None, headers=None):
        st, text = _http(
            "POST", f"{base}{PATH}", payload=payload, raw=raw,
            headers=headers,
        )
        try:
            parsed = json.loads(text or "{}")
        except json.JSONDecodeError:
            parsed = None
        return st, parsed, text

    def expect_bad_request(name, **kwargs):
        st, parsed, text = call(**kwargs)
        check(
            name,
            st == 200
            and parsed == {"results": [], "reason": "请求非法"}
            and list(json.loads(text).keys()) == ["results", "reason"],
        )

    T1 = {"X-Tenant-ID": "vb-a"}
    T2 = {"X-Tenant-ID": "vb-b"}

    proc = start()
    try:
        # ---- 请求级非法：统一 200 + 空 results + 恰为“请求非法” ----
        expect_bad_request("空体 -> 请求非法", raw=b"")
        expect_bad_request("非法 JSON -> 请求非法", raw=b"{not json")
        expect_bad_request("非法 UTF-8 -> 请求非法", raw=b"\xff\xfe")
        expect_bad_request("JSON 非对象(数组) -> 请求非法", payload=[])
        expect_bad_request("JSON 非对象(字符串) -> 请求非法", raw=b'"x"')
        expect_bad_request("JSON 非对象(数字) -> 请求非法", raw=b"1")
        expect_bad_request("外层缺 items -> 请求非法", payload={})
        expect_bad_request(
            "外层多余字段 -> 请求非法",
            payload={"items": [], "extra": 1},
        )
        expect_bad_request("items 非数组 -> 请求非法", payload={"items": {}})
        expect_bad_request("items 为空 -> 请求非法", payload={"items": []})
        expect_bad_request(
            "items 超过 100 -> 请求非法",
            payload={"items": [
                {"issuer_did": "d", "credential_id": "c"}] * 101},
        )

        # ---- 显式空 X-Tenant-ID -> 400 且仅含 error“请求非法” ----
        st, parsed, text = call(
            payload={"items": [{"issuer_did": "d", "credential_id": "c"}]},
            headers={"X-Tenant-ID": ""},
        )
        check(
            "显式空 X-Tenant-ID -> 400 {error:请求非法}",
            st == 400
            and parsed == {"error": "请求非法"}
            and list(json.loads(text).keys()) == ["error"],
        )

        # ---- 准备数据 ----
        priv1, pub1 = gen_keypair()
        priv2, pub2 = gen_keypair()
        did = "did:web:vb-issuer.example"
        did_rev = "did:web:vb-revoked.example"
        did_key = "did:web:vb-key.example"
        did_vc = "did:web:vb-uses.example"

        def make_body(cred, issuer=did, version=1, extra=None):
            body = {
                "credential_id": cred,
                "issuer_did": issuer,
                "subject_did": "did:web:vb-holder.example",
                "claims": {"level": 7},
                "issued_at": "2026-09-20T00:00:00Z",
            }
            if version is not None:
                body["issuer_key_version"] = version
            if extra:
                body.update(extra)
            return body

        def import_cred(body, priv):
            st, _ = _http(
                "POST", f"{base}/v1/trust/credentials/import",
                {"body": body, "signature": crypto.sign(body, priv)},
                headers=T1,
            )
            assert st == 201, (st, body["credential_id"])

        for d, pub in (
            (did, pub1), (did_rev, pub1), (did_key, pub1), (did_vc, pub1),
        ):
            st, _ = _http(
                "POST", f"{base}/v1/trust/anchors",
                {"did": d, "public_key": pub, "key_version": 1},
                headers=T1,
            )
            assert st == 201, (st, d)

        c_ok = "vc_ok"
        c_noversion = "vc_noversion"
        c_badsig = "vc_badsig"
        c_malformed = "vc_malformed"
        c_expired = "vc_expired"
        c_revoked = "vc_revoked"
        c_badkey = "vc_badkey"
        c_novc = "vc_novc"
        c_v2 = "vc_v2"

        import_cred(make_body(c_ok), priv1)
        import_cred(make_body(c_noversion, version=None), priv1)
        import_cred(make_body(c_badsig), priv1)
        import_cred(
            make_body(c_malformed,
                      extra={"expires_at": "2030-01-01T00:00:00Z"}),
            priv1,
        )
        import_cred(
            make_body(c_expired,
                      extra={"expires_at": "2030-01-01T00:00:00Z"}),
            priv1,
        )
        import_cred(make_body(c_revoked, issuer=did_rev), priv1)
        import_cred(make_body(c_badkey, issuer=did_key), priv1)
        import_cred(make_body(c_novc, issuer=did_vc), priv1)

        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors/{did}/rotate",
            {"from_key_version": 1, "public_key": pub2}, headers=T1,
        )
        assert st in (200, 201)
        import_cred(make_body(c_v2, version=2), priv2)

        # T2 同双键导入（跨租户不可见）
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pub2, "key_version": 1},
            headers=T2,
        )
        assert st == 201
        c_t2 = "vc_t2_only"
        body_t2 = make_body(c_t2)
        st, _ = _http(
            "POST", f"{base}/v1/trust/credentials/import",
            {"body": body_t2, "signature": crypto.sign(body_t2, priv2)},
            headers=T2,
        )
        assert st == 201

        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/{did_rev}/1/status",
            {"status": "revoked"}, headers=T1,
        )
        check("吊销 did_rev v1 -> 200", st == 200)

        def audit_seqs(head):
            st, text = _http(
                "GET", f"{base}/v1/audit?limit=200&after=0", headers=head,
            )
            assert st == 200
            parsed = json.loads(text)
            return [e["seq"] for e in parsed["events"]]

        seqs_before = audit_seqs(T1)
    finally:
        stop(proc)

    # ---- 落盘篡改：重启后对存储原文复核的各类失败分类 ----
    data = json.load(open(store_path, encoding="utf-8"))
    imported = data["tenants"]["vb-a"]["imported_credentials"]
    anchors = data["tenants"]["vb-a"]["trust_anchors"]
    imported[did][c_badsig]["body"]["claims"]["level"] = 999
    imported[did][c_malformed]["signature"] = "!!!not-base64url!!!"
    imported[did][c_malformed]["body"]["expires_at"] = "2000-01-01T00:00:00Z"
    row_exp = imported[did][c_expired]
    row_exp["body"]["expires_at"] = "2000-01-01T00:00:00Z"
    row_exp["signature"] = crypto.sign(row_exp["body"], priv1)
    anchors[did_key]["1"]["public_key"] = "not-a-pem"
    anchors[did_vc]["1"]["uses"] = ["generic"]
    json.dump(data, open(store_path, "w", encoding="utf-8"))

    proc = start()
    try:
        def item(issuer, cred):
            return {"issuer_did": issuer, "credential_id": cred}

        def rr(valid, status, reason):
            return {"valid": valid, "http_status": status, "reason": reason}

        bad_item = rr(False, 400, "请求项非法")
        ok_item = rr(True, 200, None)
        missing_item = rr(False, 404, "资源不存在")

        items = [
            "not-object",
            {},
            {"issuer_did": did},
            {"credential_id": c_ok},
            {"issuer_did": did, "credential_id": c_ok, "x": 1},
            {"issuer_did": "", "credential_id": c_ok},
            {"issuer_did": did, "credential_id": ""},
            {"issuer_did": 1, "credential_id": c_ok},
            {"issuer_did": did, "credential_id": None},
            item(did, c_ok),
            item(did, c_noversion),
            item(did, c_v2),
            item(did, "vc_missing"),
            item("did:web:nobody.example", c_ok),
            item(did, c_badsig),
            item(did, c_malformed),
            item(did, c_expired),
            item(did_rev, c_revoked),
            item(did_key, c_badkey),
            item(did_vc, c_novc),
            item(did, c_t2),
        ]
        expected = [bad_item] * 9 + [
            ok_item,
            ok_item,
            ok_item,
            missing_item,
            missing_item,
            rr(False, 200, "签名校验失败"),
            rr(False, 200, "签名格式错误"),
            rr(False, 200, "凭证已过期"),
            rr(False, 200, "锚点不可用"),
            rr(False, 200, "锚点不可用"),
            rr(False, 200, "锚点不可用"),
            missing_item,
        ]
        st, parsed, text = call(payload={"items": items}, headers=T1)
        check(
            "混合批次等长同序、键序固定、失败不短路",
            st == 200
            and parsed == {"results": expected}
            and list(json.loads(text).keys()) == ["results"]
            and all(
                list(row.keys()) == ["valid", "http_status", "reason"]
                for row in parsed["results"]
            )
            and len(parsed["results"]) == len(items),
        )

        # 跨租户：T2 只见自己的记录，T1 记录对 T2 恒不可见
        st, parsed, _ = call(
            payload={"items": [item(did, c_t2), item(did, c_ok)]},
            headers=T2,
        )
        check(
            "跨租户隔离",
            st == 200
            and parsed["results"] == [ok_item, missing_item],
        )

        # 边界：恰 100 项合法
        st, parsed, _ = call(
            payload={"items": [item(did, c_ok)] * 100}, headers=T1,
        )
        check(
            "恰 100 项 -> 100 个成功结果",
            st == 200 and parsed["results"] == [ok_item] * 100,
        )

        # 纯只读：审计不增加、导入原文不变、不消费任何内容
        seqs_after = audit_seqs(T1)
        for _ in range(3):
            call(payload={"items": items}, headers=T1)
            call(raw=b"bad", headers=T1)
        check("批量重验不记审计", audit_seqs(T1) == seqs_after)
        st, text = _http(
            "GET",
            f"{base}/v1/trust/credentials/imported/{c_badsig}"
            f"?issuer_did={did}",
            headers=T1,
        )
        parsed = json.loads(text)
        check(
            "批量重验不改导入原文",
            st == 200
            and parsed["body"]["claims"]["level"] == 999,
        )
    finally:
        stop(proc)

    # ---- 重启后结论与顺序保持一致 ----
    proc = start()
    try:
        st, parsed, _ = call(
            payload={"items": [
                {"issuer_did": did, "credential_id": c_ok},
                {"issuer_did": did_rev, "credential_id": c_revoked},
                {"issuer_did": did, "credential_id": c_expired},
            ]},
            headers=T1,
        )
        check(
            "重启后结论稳定（锚点吊销/过期落盘保持）",
            parsed["results"] == [
                {"valid": True, "http_status": 200, "reason": None},
                {"valid": False, "http_status": 200,
                 "reason": "锚点不可用"},
                {"valid": False, "http_status": 200,
                 "reason": "凭证已过期"},
            ],
        )
    finally:
        stop(proc)

    # ---- 批初锚点快照：批内并发吊销不得混入不同状态（进程内并发）----
    snapshot_path = tempfile.mktemp(suffix=".json")
    vc = store_mod.VCStore(snapshot_path)
    snap_did = "did:web:vb-snap.example"
    spriv, spub = gen_keypair()
    vc.register_trust_anchor("snap", snap_did, spub, 1)
    snap_items = []
    for idx in range(100):
        body = {
            "credential_id": f"vc_snap_{idx:03d}",
            "issuer_did": snap_did,
            "subject_did": "did:web:vb-holder.example",
            "claims": {"i": idx},
            "issued_at": "2026-09-20T00:00:00Z",
            "issuer_key_version": 1,
        }
        vc.import_trust_credential(
            "snap",
            {"body": body, "signature": crypto.sign(body, spriv)},
        )
        snap_items.append(
            {"issuer_did": snap_did,
             "credential_id": body["credential_id"]}
        )

    real_verify = store_mod.crypto.verify

    def slow_verify(body, signature, public_pem):
        time.sleep(0.002)
        return real_verify(body, signature, public_pem)

    observed = []
    barrier = threading.Event()

    def worker(delay):
        barrier.wait()
        time.sleep(delay)
        ok, _reason, results = vc.verify_imported_credentials_batch(
            "snap", {"items": snap_items}
        )
        assert ok
        verdicts = {(row["valid"], row["reason"]) for row in results}
        observed.append(verdicts)

    # 4 个批次错峰启动（0/60/120/180ms），吊销发生在 90ms 前后：
    # 吊销前取得快照的批次必须全部成功，吊销后的批次必须全部锚点
    # 不可用，任何批次都不得出现混合判定。
    store_mod.crypto.verify = slow_verify
    threads = [
        threading.Thread(target=worker, args=(idx * 0.06,))
        for idx in range(4)
    ]
    for t in threads:
        t.start()
    barrier.set()
    time.sleep(0.09)
    vc.revoke_trust_anchor("snap", snap_did, 1)
    for t in threads:
        t.join()
    store_mod.crypto.verify = real_verify

    uniform = all(
        verdicts == {(True, None)}
        or verdicts == {(False, "锚点不可用")}
        for verdicts in observed
    )
    saw_both = (
        {(True, None)} in observed
        and {(False, "锚点不可用")} in observed
    )
    check(
        "批初锚点快照：并发吊销下同批不混入混合状态",
        uniform and saw_both and len(observed) == 4,
    )

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


if __name__ == "__main__":
    main()
