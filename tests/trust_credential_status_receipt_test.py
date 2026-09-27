#!/usr/bin/env python3
"""POST /v1/trust/credential-status/receipt 凭证状态同步签名回执
端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

覆盖：
- 请求协议：体恰含 issuer_did、credential_id、verifier_did、nonce，
  均为非空字符串，nonce 限 1..256 码点；空体、非法 JSON、非对象、
  键集或类型非法（含布尔/数字/null）均 400 且仅
  {"error":"请求非法"}；显式空租户头 400；
- 404：本租户未同步双键 / 跨租户、验证者未知 / 跨租户，仅
  {"error":"资源不存在"}；
- 409：验证者已停用，仅 {"error":"验证者已停用"}；
- 200 键序恰为 receipt、signature；receipt 九键键序
  issuer_did、credential_id、status、reason、updated_at、
  issuer_key_version、verifier_did、verifier_key_version、nonce；
  前六项取同步记录，reason 无值为 null，两版本为正整数（禁布尔）；
- signature 由验证者当前私钥按既有 ES256 裸 R||S 无填充 base64url
  签署 receipt 递归键升序紧凑 UTF-8 JSON，可用验证者对应版本公钥
  验签；
- 纯只读：不改同步状态、不写审计；
- 并发更新同步状态 / 轮换验证者密钥时，每张收据内部一致，全部结果
  只属写前或写后快照；
- 缺省租户头 default、租户隔离；重启后收据内容稳定、签名可验。
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
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from vcbackend import crypto  # noqa: E402

RECEIPT_PATH = "/v1/trust/credential-status/receipt"
SYNC_PATH = "/v1/trust/credential-status/sync"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

RECEIPT_KEYS = [
    "issuer_did",
    "credential_id",
    "status",
    "reason",
    "updated_at",
    "issuer_key_version",
    "verifier_did",
    "verifier_key_version",
    "nonce",
]
OK_KEYS = ["receipt", "signature"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None, raw=None):
    if raw is None:
        data = (
            json.dumps(payload).encode("utf-8")
            if payload is not None
            else None
        )
    else:
        data = raw
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def _keypair():
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


def parse_ordered(raw_bytes):
    """解析 JSON 并保留每层对象的键序。"""
    return json.loads(
        raw_bytes.decode("utf-8"),
        object_pairs_hook=lambda pairs: pairs,
    )


def main():
    port = 9081
    store_path = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store_path)

    def start():
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert wait_up(port), "服务启动超时"
        return proc

    proc = start()
    base = f"http://127.0.0.1:{port}"

    def post(path, payload=None, headers=None, raw=None):
        return _http("POST", base + path, payload=payload,
                     headers=headers, raw=raw)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        T1 = {"X-Tenant-ID": "csr-tenant-a"}
        T2 = {"X-Tenant-ID": "csr-tenant-b"}

        issuer_priv, issuer_pub = _keypair()
        issuer_did = "did:web:csr-issuer.example"
        credential_id = "vc_csr_0001"

        # 注册全用途信任锚点（含 status）。
        st, _ = post(ANCHORS_PATH,
                     {"did": issuer_did, "public_key": issuer_pub,
                      "key_version": 1}, T1)
        assert st in (200, 201), st

        # 本租户活动本地验证者 DID（托管私钥，回执签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-status-receipt-verifier"},
                       T1)
        assert st == 201, (st, raw)
        verifier = json.loads(raw)
        verifier_did = verifier["did"]
        verifier_pub = verifier["public_key"]

        def status_body(status, updated_at, reason=None, key_version=1):
            body = {
                "issuer_did": issuer_did,
                "credential_id": credential_id,
                "status": status,
                "updated_at": updated_at,
                "issuer_key_version": key_version,
            }
            if reason is not None:
                body["reason"] = reason
            return body

        def sync_status(body):
            payload = {"body": body, "signature": crypto.sign(body, issuer_priv)}
            st, raw = post(SYNC_PATH, payload, T1)
            return st, json.loads(raw)

        def receipt(payload, headers=T1, raw=None):
            st, raw_body = post(RECEIPT_PATH, payload=payload,
                                headers=headers, raw=raw)
            return st, raw_body

        good_payload = {
            "issuer_did": issuer_did,
            "credential_id": credential_id,
            "verifier_did": verifier_did,
            "nonce": "nonce-一",
        }

        # -------------------------------------------------------------- #
        # 1. 400：请求协议，仅 {"error":"请求非法"}
        # -------------------------------------------------------------- #
        def expect_400(name, payload=None, raw=None, headers=T1):
            st, body = receipt(payload, headers=headers, raw=raw)
            ok = st == 400 and json.loads(body) == {"error": "请求非法"}
            check(name, ok)

        expect_400("空体", raw=b"")
        expect_400("纯空白非 JSON", raw=b"   ")
        expect_400("非法 JSON", raw=b'{"issuer_did":')
        expect_400("UTF-8 非法编码", raw=b'{"issuer_did":\xff}')
        expect_400("JSON 非对象（数组）", raw=b"[1,2,3]")
        expect_400("JSON 非对象（字符串）", raw=b'"hello"')
        expect_400("JSON 非对象（null）", raw=b"null")
        expect_400("缺 issuer_did",
                   {"credential_id": credential_id,
                    "verifier_did": verifier_did, "nonce": "n"})
        expect_400("缺 credential_id",
                   {"issuer_did": issuer_did,
                    "verifier_did": verifier_did, "nonce": "n"})
        expect_400("缺 verifier_did",
                   {"issuer_did": issuer_did,
                    "credential_id": credential_id, "nonce": "n"})
        expect_400("缺 nonce",
                   {"issuer_did": issuer_did,
                    "credential_id": credential_id,
                    "verifier_did": verifier_did})
        expect_400("多余字段", dict(good_payload, extra="x"))
        expect_400("issuer_did 空串",
                   dict(good_payload, issuer_did=""))
        expect_400("credential_id 空串",
                   dict(good_payload, credential_id=""))
        expect_400("verifier_did 空串",
                   dict(good_payload, verifier_did=""))
        expect_400("nonce 空串", dict(good_payload, nonce=""))
        expect_400("issuer_did 数字", dict(good_payload, issuer_did=123))
        expect_400("credential_id 布尔",
                   dict(good_payload, credential_id=True))
        expect_400("verifier_did null",
                   dict(good_payload, verifier_did=None))
        expect_400("nonce 数字", dict(good_payload, nonce=1))
        expect_400("nonce 布尔", dict(good_payload, nonce=True))
        expect_400("nonce 数组", dict(good_payload, nonce=["n"]))
        expect_400("nonce 257 ASCII 码点",
                   dict(good_payload, nonce="a" * 257))
        long_nonce = "a" * 200 + "中" * 57
        check("构造 nonce 恰为 257 Unicode 码点", len(long_nonce) == 257)
        expect_400("nonce 257 Unicode 码点",
                   dict(good_payload, nonce=long_nonce))

        # 显式空租户头 400（沿用全局限定文案，不要求为“请求非法”）。
        st, body = receipt(good_payload, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # -------------------------------------------------------------- #
        # 2. 404：未同步 / 跨租户 / 验证者未知
        # -------------------------------------------------------------- #
        st, body = receipt(good_payload)
        check("未同步双键 404",
              st == 404 and json.loads(body) == {"error": "资源不存在"})
        st, body = receipt(good_payload, headers=T2)
        check("跨租户 404 同形",
              st == 404 and json.loads(body) == {"error": "资源不存在"})
        st, body = receipt(dict(good_payload,
                                verifier_did="did:web:no-such.example"))
        check("未知验证者 404",
              st == 404 and json.loads(body) == {"error": "资源不存在"})
        st, body = receipt(dict(good_payload,
                                issuer_did="did:web:no-such.example"))
        check("未知签发者双键 404",
              st == 404 and json.loads(body) == {"error": "资源不存在"})

        # 同步一条 suspended（带原因）。
        suspended_body = status_body(
            "suspended", "2026-01-10T00:00:00Z", reason="违规调查中")
        st, r = sync_status(suspended_body)
        assert st == 201, (st, r)

        # 同步后跨租户：T2 既无同步记录也无验证者。
        st, body = receipt(good_payload, headers=T2)
        check("同步后跨租户仍 404",
              st == 404 and json.loads(body) == {"error": "资源不存在"})
        # T2 建同 DID 验证者也不可探测 T1 的同步记录。
        st, raw_v2 = post(DIDS_PATH,
                          {"method": "web",
                           "public_key": "csr-verifier-in-tenant-b"},
                          T2)
        assert st == 201, st
        t2_verifier = json.loads(raw_v2)["did"]
        st, body = receipt(dict(good_payload, verifier_did=t2_verifier),
                           headers=T2)
        check("他租户验证者 + 他租户无同步 404",
              st == 404 and json.loads(body) == {"error": "资源不存在"})
        # T1 有同步记录但验证者属 T2：跨租户不可探测。
        st, body = receipt(dict(good_payload, verifier_did=t2_verifier),
                           headers=T1)
        check("跨租户验证者 404 同形",
              st == 404 and json.loads(body) == {"error": "资源不存在"})

        # -------------------------------------------------------------- #
        # 3. 200：结构、键序、字段值、签名
        # -------------------------------------------------------------- #
        nonce = "nonce-一"
        st, raw = receipt(good_payload)
        check("suspended 回执 200", st == 200)
        ordered = parse_ordered(raw)
        check("原始字节顶层键序 receipt,signature",
              [k for k, _ in ordered] == OK_KEYS)
        receipt_pairs = ordered[0][1]
        check("原始字节 receipt 九键键序",
              [k for k, _ in receipt_pairs] == RECEIPT_KEYS)
        body = json.loads(raw)
        rcp = body["receipt"]
        check("issuer_did 取同步记录", rcp["issuer_did"] == issuer_did)
        check("credential_id 取同步记录",
              rcp["credential_id"] == credential_id)
        check("status=suspended", rcp["status"] == "suspended")
        check("reason 取同步裁剪值", rcp["reason"] == "违规调查中")
        check("updated_at 取同步记录",
              rcp["updated_at"] == "2026-01-10T00:00:00Z")
        check("issuer_key_version 正整数",
              isinstance(rcp["issuer_key_version"], int)
              and not isinstance(rcp["issuer_key_version"], bool)
              and rcp["issuer_key_version"] == 1)
        check("verifier_did 回显", rcp["verifier_did"] == verifier_did)
        check("verifier_key_version 正整数",
              isinstance(rcp["verifier_key_version"], int)
              and not isinstance(rcp["verifier_key_version"], bool)
              and rcp["verifier_key_version"] >= 1)
        check("nonce 回显", rcp["nonce"] == nonce)
        check("signature 非空字符串",
              isinstance(body["signature"], str) and body["signature"])
        try:
            crypto.verify(rcp, body["signature"], verifier_pub)
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("signature 可由验证者当前公钥验签", sig_ok)

        # 规范化签名覆盖：篡改 receipt 任一字段后验签必失败。
        tampered = dict(rcp, nonce="other")
        try:
            crypto.verify(tampered, body["signature"], verifier_pub)
            tamper_ok = False
        except Exception:  # noqa: BLE001
            tamper_ok = True
        check("篡改 receipt 后验签失败", tamper_ok)

        # 不同 nonce 仅收据末项变化，签名仍可验。
        st, raw2 = receipt(dict(good_payload, nonce="n-2"))
        assert st == 200
        body2 = json.loads(raw2)
        check("不同 nonce 前八项一致",
              {k: body2["receipt"][k] for k in RECEIPT_KEYS[:-1]}
              == {k: rcp[k] for k in RECEIPT_KEYS[:-1]})
        try:
            crypto.verify(body2["receipt"], body2["signature"], verifier_pub)
            sig_ok2 = True
        except Exception:  # noqa: BLE001
            sig_ok2 = False
        check("不同 nonce 签名可验", sig_ok2)

        # nonce 恰 256 码点（200 ASCII + 56 中文）合法。
        boundary = "a" * 200 + "中" * 56
        check("构造 nonce 恰 256 码点", len(boundary) == 256)
        st, raw3 = receipt(dict(good_payload, nonce=boundary))
        check("nonce 256 码点合法",
              st == 200 and json.loads(raw3)["receipt"]["nonce"] == boundary)

        # 更新为 active（更晚 updated_at）：reason 为 null。
        active_body = status_body("active", "2026-02-10T00:00:00Z")
        st, r = sync_status(active_body)
        assert st == 200, (st, r)
        st, raw = receipt(dict(good_payload, nonce="n-active"))
        check("active 回执 200", st == 200)
        body = json.loads(raw)
        rcp_active = body["receipt"]
        check("active status", rcp_active["status"] == "active")
        check("active reason 为 null", rcp_active["reason"] is None)
        check("active updated_at 取新记录",
              rcp_active["updated_at"] == "2026-02-10T00:00:00Z")
        try:
            crypto.verify(rcp_active, body["signature"], verifier_pub)
            sig_ok3 = True
        except Exception:  # noqa: BLE001
            sig_ok3 = False
        check("active 收据签名可验", sig_ok3)

        # revoked 同样可取（reason 为吊销原因）。
        revoked_body = status_body(
            "revoked", "2026-03-10T00:00:00Z", reason="持证人违规")
        st, r = sync_status(revoked_body)
        assert st == 200, (st, r)
        st, raw = receipt(dict(good_payload, nonce="n-revoked"))
        assert st == 200
        rcp_revoked = json.loads(raw)["receipt"]
        check("revoked status/reason",
              rcp_revoked["status"] == "revoked"
              and rcp_revoked["reason"] == "持证人违规"
              and rcp_revoked["updated_at"] == "2026-03-10T00:00:00Z")

        # 回到 active 便于后续并发/重启阶段。
        active_body2 = status_body("active", "2026-04-10T00:00:00Z")
        st, r = sync_status(active_body2)
        assert st == 200, (st, r)
        old_row = ("active", None, "2026-04-10T00:00:00Z", 1)

        # -------------------------------------------------------------- #
        # 4. 409：验证者停用
        # -------------------------------------------------------------- #
        st, _ = post(f"{DIDS_PATH}/{verifier_did}/deactivate", {}, T1)
        assert st == 200
        st, b = receipt(dict(good_payload, nonce="n-dead"))
        check("验证者停用 409",
              st == 409 and json.loads(b) == {"error": "验证者已停用"})
        # 未同步双键优先 404（存在性先于停用判定）。
        st, b = receipt(dict(good_payload, credential_id="vc_none",
                             nonce="n-dead"))
        check("未同步优先于停用 409 -> 404",
              st == 404 and json.loads(b) == {"error": "资源不存在"})

        # 第二个活动验证者恢复服务。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-status-receipt-verifier-2"},
                       T1)
        assert st == 201, (st, raw)
        verifier2 = json.loads(raw)
        st, raw = receipt(dict(good_payload,
                               verifier_did=verifier2["did"], nonce="n-v2"))
        check("活动验证者2 200",
              st == 200 and json.loads(raw)["receipt"]["verifier_did"]
              == verifier2["did"])

        # -------------------------------------------------------------- #
        # 5. 只读：不改同步状态、不写审计
        # -------------------------------------------------------------- #
        st, status_raw = get(
            f"/v1/trust/credential-status/{quote(credential_id)}"
            f"?issuer_did={quote(issuer_did)}", headers=T1)
        assert st == 200
        before_status = status_raw
        st, audit_before = get("/v1/audit?limit=200", headers=T1)
        assert st == 200
        for i in range(5):
            st, _ = receipt(dict(good_payload,
                                 verifier_did=verifier2["did"],
                                 nonce=f"n-ro-{i}"))
            assert st == 200
        st, status_after = get(
            f"/v1/trust/credential-status/{quote(credential_id)}"
            f"?issuer_did={quote(issuer_did)}", headers=T1)
        check("回执不改同步状态", before_status == status_after)
        st, audit_after = get("/v1/audit?limit=200", headers=T1)
        check("回执不写审计", audit_before == audit_after)

        # -------------------------------------------------------------- #
        # 6. 并发：状态更新与密钥轮换期间，每张收据只属写前或写后
        # -------------------------------------------------------------- #
        suspended_new = status_body(
            "suspended", "2026-05-10T00:00:00Z", reason="并发暂停原因")
        new_row = ("suspended", "并发暂停原因", "2026-05-10T00:00:00Z", 1)
        results = []
        results_lock = threading.Lock()

        def worker(worker_nonce):
            st, raw_b = receipt(
                dict(good_payload, verifier_did=verifier2["did"],
                     nonce=worker_nonce))
            if st != 200:
                with results_lock:
                    results.append(("error", st, raw_b))
                return
            obj = json.loads(raw_b)
            r = obj["receipt"]
            with results_lock:
                results.append(
                    (
                        (r["status"], r["reason"], r["updated_at"],
                         r["issuer_key_version"]),
                        r["verifier_key_version"],
                        obj["signature"],
                    )
                )

        threads = []
        barrier = threading.Event()

        def run_worker(i):
            barrier.wait()
            worker(f"n-conc-{i}")

        for i in range(24):
            threads.append(threading.Thread(target=run_worker, args=(i,)))
        for t in threads:
            t.start()
        barrier.set()
        # 工人启动后执行一次严格更新（写）。
        time.sleep(0.02)
        st, r = sync_status(suspended_new)
        assert st == 200, (st, r)
        for t in threads:
            t.join()

        check("并发全部 200",
              all(item[0] != "error" for item in results))
        rows_seen = {item[0] for item in results}
        check("并发状态快照仅写前/写后两种",
              rows_seen <= {old_row, new_row} and len(rows_seen) >= 1)

        # 轮换验证者2 的密钥后并发：收据的 verifier_key_version 与
        # signature 必须配套（用该版本公钥验签通过）。
        st, doc_raw = get(
            f"/v1/dids/{quote(verifier2['did'])}/document", headers=T1)
        assert st == 200
        methods_before = {
            m["key_version"]: m["public_key"]
            for m in json.loads(doc_raw)["verification_methods"]
        }
        st, rot_raw = post(
            f"/v1/dids/{quote(verifier2['did'])}/keys/rotate",
            {"key_handle": "csr-verifier-2-v2"}, T1)
        assert st == 200, (st, rot_raw)
        st, doc_raw = get(
            f"/v1/dids/{quote(verifier2['did'])}/document", headers=T1)
        assert st == 200
        methods_after = {
            m["key_version"]: m["public_key"]
            for m in json.loads(doc_raw)["verification_methods"]
        }

        rot_results = []
        rot_lock = threading.Lock()
        barrier2 = threading.Event()

        def rot_worker(i):
            barrier2.wait()
            st, raw_b = receipt(
                dict(good_payload, verifier_did=verifier2["did"],
                     nonce=f"n-rot-{i}"))
            with rot_lock:
                rot_results.append((st, raw_b))

        threads = [
            threading.Thread(target=rot_worker, args=(i,)) for i in range(16)
        ]
        for t in threads:
            t.start()
        barrier2.set()
        time.sleep(0.01)
        # 再轮换一次，制造 v1/v2/v3 三个版本窗口。
        st, _ = post(
            f"/v1/dids/{quote(verifier2['did'])}/keys/rotate",
            {"key_handle": "csr-verifier-2-v3"}, T1)
        assert st == 200
        for t in threads:
            t.join()
        st, doc_raw = get(
            f"/v1/dids/{quote(verifier2['did'])}/document", headers=T1)
        methods_final = {
            m["key_version"]: m["public_key"]
            for m in json.loads(doc_raw)["verification_methods"]
        }
        all_methods = {**methods_before, **methods_after, **methods_final}

        version_snapshots = set()
        sig_all_ok = True
        for st, raw_b in rot_results:
            if st != 200:
                sig_all_ok = False
                continue
            obj = json.loads(raw_b)
            r = obj["receipt"]
            version = r["verifier_key_version"]
            version_snapshots.add(version)
            pub_pem = all_methods.get(version)
            try:
                crypto.verify(r, obj["signature"], pub_pem)
            except Exception:  # noqa: BLE001
                sig_all_ok = False
        check("轮换窗口全部 200",
              all(st == 200 for st, _ in rot_results))
        check("签名版本与验证者快照一致且均可验签", sig_all_ok)
        check("观察到的版本均为正整数",
              all(isinstance(v, int) and not isinstance(v, bool) and v >= 1
                  for v in version_snapshots))

        # -------------------------------------------------------------- #
        # 7. 缺省租户头：default 隔离
        # -------------------------------------------------------------- #
        st, b = receipt(good_payload, headers=None)  # 不带租户头
        check("缺省租户头在 default 内 404",
              st == 404 and json.loads(b) == {"error": "资源不存在"})

        # -------------------------------------------------------------- #
        # 8. 重启稳定：receipt 内容一致、签名可验
        # -------------------------------------------------------------- #
        st, before_raw = receipt(
            dict(good_payload, verifier_did=verifier2["did"],
                 nonce="重启-nonce-𝄞"))
        assert st == 200
        before = json.loads(before_raw)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, after_raw = receipt(
            dict(good_payload, verifier_did=verifier2["did"],
                 nonce="重启-nonce-𝄞"))
        check("重启后 200", st == 200)
        after = json.loads(after_raw)
        check("重启后 receipt 逐字段一致",
              after["receipt"] == before["receipt"])
        current_pub = all_methods[max(all_methods)]
        try:
            crypto.verify(after["receipt"], after["signature"], current_pub)
            restart_ok = True
        except Exception:  # noqa: BLE001
            restart_ok = False
        check("重启后以当前版本公钥验签通过", restart_ok)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store_path):
            os.remove(store_path)

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
