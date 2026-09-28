#!/usr/bin/env python3
"""GET /v1/trust/credential-status/receipt-sync/receipt 凭证状态回执消费
同步进度签名回执端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_sync_receipt_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

同步数据直接用合规清单（status 用途锚点签名）+ NDJSON 灌入
credential-status/receipt-sync（稠密游标空间），回执摘要的期望 NDJSON
全部从 receipt-sync history 端点实际落盘行重建，不硬编码。

覆盖（完整对齐 GET /v1/trust/presentation-sync/receipt，差异仅状态空间、
事件五键与 status 用途）：
- 参数协议：仅 signer_did/verifier_did/nonce 三项且唯一，均须非空串；
  nonce 限 1..256 个 Unicode 码点；缺失、重复、空值、未知参数、
  nonce 越界均 400 且仅 {"error":"请求非法"}；
- 显式空租户头 400 且仅 {"error":"X-Tenant-ID 不能为空"}；
- 404：同步来源不存在 / 跨租户、验证者 DID 不存在 / 跨租户，仅
  {"error":"资源不存在"}；
- 409：验证者已停用，仅 {"error":"验证者已停用"}；
- 200 键序恰为 receipt、signature；receipt 键序恰为 signer_did、
  next_after、digest、verifier_did、verifier_key_version、nonce；
  next_after 为非负整数、verifier_key_version 为正整数；
- digest 为 cursor 升序、逐行沿用 receipt-sync history 五键 NDJSON
  编码行字节的 SHA-256 小写 64 位 hex（含非 ASCII 不转义）；signature
  以验证者当前公钥按既有规范化 JSON 与 ES256 裸签名协议可验；
- 只读：不推进检查点（续页仍衔接）、不写审计；
- 缺省租户头为 default；重启后 receipt 与 digest 相同且签名可验。
"""

import hashlib
import json
import os
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

from vcbackend import crypto  # noqa: E402

SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
HISTORY_PATH = "/v1/trust/credential-status/receipt-sync/history"
RECEIPT_PATH = "/v1/trust/credential-status/receipt-sync/receipt"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"

EVENT_KEYS = ["cursor", "receipt_id", "verifier_did", "nonce",
              "consumed_at"]
RECEIPT_KEYS = ["signer_did", "next_after", "digest", "verifier_did",
                "verifier_key_version", "nonce"]
OK_KEYS = ["receipt", "signature"]

failures = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        failures.append(name)


def _http(method, url, payload=None, headers=None):
    data = (
        json.dumps(payload).encode("utf-8")
        if payload is not None
        else None
    )
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


VERIFIER_DID = "did:web:cs-rcpt-sync-verifier.example"


def make_row(cursor, index):
    # receipt_id 含非 ASCII，校验 digest 必须按 ensure_ascii=False 的
    # UTF-8 行字节计算。
    return {
        "cursor": cursor,
        "receipt_id": f"rcpt-演-{index:055d}",
        "verifier_did": VERIFIER_DID,
        "nonce": f"cs-rcpt-sync-nonce-{index:03d}",
        "consumed_at": "2099-01-01T00:00:00Z",
    }


def to_ndjson(rows):
    return "".join(
        json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in rows
    )


def main():
    port = 9058
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

    def post(path, payload=None, headers=None):
        return _http("POST", base + path, payload=payload, headers=headers)

    def get(path, headers=None):
        return _http("GET", base + path, headers=headers)

    try:
        DST = {"X-Tenant-ID": "cs-rcpt-dst-tenant"}
        OTHER = {"X-Tenant-ID": "cs-rcpt-other-tenant"}

        signer_priv, signer_pub = _keypair()
        signer_did = "did:web:cs-rcpt-sync-signer.example"
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, DST)
        assert st in (200, 201), st

        # 本租户活动本地验证者 DID（托管私钥，回执签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-status-receipt-sync-rcpt"},
                       DST)
        assert st == 201, (st, raw)
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]

        def signed_manifest(snapshot, after, ndjson):
            manifest = {
                "snapshot": snapshot,
                "filters": {"after": after, "limit": 1000},
                "count": ndjson.count("\n"),
                "alg": "SHA-256",
                "digest": hashlib.sha256(
                    ndjson.encode("utf-8")).hexdigest(),
                "signer_did": signer_did,
                "key_version": 1,
            }
            manifest["signature"] = crypto.sign(
                {k: manifest[k] for k in (
                    "snapshot", "filters", "count", "alg", "digest",
                    "signer_did", "key_version")}, signer_priv)
            return manifest

        def sync(rows, after, snapshot):
            ndjson = to_ndjson(rows)
            st, raw = post(
                SYNC_PATH,
                {"manifest": signed_manifest(snapshot, after, ndjson),
                 "ndjson": ndjson},
                headers=DST)
            return st, json.loads(raw)

        def receipt(qs, headers=DST):
            st, raw = get(f"{RECEIPT_PATH}?{qs}", headers=headers)
            return st, json.loads(raw.decode() or "null")

        def qs(nonce="nonce-一"):
            return urllib.parse.urlencode(
                {"signer_did": signer_did,
                 "verifier_did": verifier_did,
                 "nonce": nonce})

        def expected_digest():
            # 从 receipt-sync history 端点实际落盘行重建 NDJSON
            # （缺省 at=检查点）。
            st, raw = get(
                f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
            assert st == 200, raw
            body = json.loads(raw)
            ndjson = to_ndjson(body["events"])
            return body["next_after"], hashlib.sha256(
                ndjson.encode("utf-8")).hexdigest()

        # -------------------------------------------------------------- #
        # 1. 400：参数协议，仅 {"error":"请求非法"}
        # -------------------------------------------------------------- #
        good = (
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier_did)}"
            "&nonce=n-1"
        )

        def expect_400(name, qs_text, headers=DST):
            st, body = receipt(qs_text, headers=headers)
            check(name, st == 400 and body == {"error": "请求非法"})

        expect_400("空查询", "")
        expect_400("缺 signer_did",
                   f"verifier_did={urllib.parse.quote(verifier_did)}"
                   "&nonce=n-1")
        expect_400("缺 verifier_did", f"signer_did={signer_did}&nonce=n-1")
        expect_400("缺 nonce",
                   f"signer_did={signer_did}"
                   f"&verifier_did={urllib.parse.quote(verifier_did)}")
        expect_400("signer_did 空值",
                   f"signer_did=&verifier_did="
                   f"{urllib.parse.quote(verifier_did)}&nonce=n-1")
        expect_400("verifier_did 空值",
                   f"signer_did={signer_did}&verifier_did=&nonce=n-1")
        expect_400("nonce 空值",
                   f"signer_did={signer_did}"
                   f"&verifier_did={urllib.parse.quote(verifier_did)}&nonce=")
        expect_400("未知参数", good + "&x=1")
        expect_400("signer_did 重复",
                   f"signer_did={signer_did}&signer_did={signer_did}"
                   f"&verifier_did={urllib.parse.quote(verifier_did)}"
                   "&nonce=n-1")
        expect_400("verifier_did 重复",
                   f"signer_did={signer_did}"
                   f"&verifier_did=a&verifier_did=b&nonce=n-1")
        expect_400("nonce 重复", good + "&nonce=n-2")
        expect_400("nonce 257 码点",
                   f"signer_did={signer_did}"
                   f"&verifier_did={urllib.parse.quote(verifier_did)}"
                   f"&nonce={'a' * 257}")
        long_nonce = "a" * 200 + "中" * 57
        check("构造 nonce 恰为 257 码点", len(long_nonce) == 257)
        expect_400(
            "nonce 257 Unicode 码点",
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier_did)}"
            f"&nonce={urllib.parse.quote(long_nonce)}")
        # 显式空租户头由路由统一判 400，固定中文文案。
        st, body = receipt(good, headers={"X-Tenant-ID": ""})
        check("显式空租户头 400 且仅固定文案",
              st == 400 and body == {"error": "X-Tenant-ID 不能为空"})

        # -------------------------------------------------------------- #
        # 2. 404：来源未同步 / 跨租户；验证者未知
        # -------------------------------------------------------------- #
        st, body = receipt(good)
        check("未同步来源 404",
              st == 404 and body == {"error": "资源不存在"})

        unknown_signer = (
            "signer_did=did:web:no-such-signer.example"
            f"&verifier_did={urllib.parse.quote(verifier_did)}&nonce=n-1"
        )
        st, body = receipt(unknown_signer)
        check("未知来源 404 固定文案",
              st == 404 and body == {"error": "资源不存在"})
        st, body = receipt(
            "signer_did=did:web:no-such-signer.example"
            "&verifier_did=did:web:no-such-verifier.example&nonce=n-1",
            headers=OTHER)
        check("跨租户 404 同形",
              st == 404 and body == {"error": "资源不存在"})

        # 灌入稠密首页（cursor 1..3，snapshot=3，next_after=3）。
        rows = [make_row(i, i) for i in range(1, 6)]
        st, r = sync(rows[:3], 0, 3)
        assert st == 201 and r["next_after"] == 3, (st, r)

        # 来源已存在，但验证者 DID 未知 / 跨租户。
        unknown_verifier = (
            f"signer_did={signer_did}"
            "&verifier_did=did:web:no-such-verifier.example&nonce=n-1"
        )
        st, body = receipt(unknown_verifier)
        check("未知验证者 404",
              st == 404 and body == {"error": "资源不存在"})
        st, body = receipt(good, headers=OTHER)
        check("同步后跨租户仍 404（来源跨租户）",
              st == 404 and body == {"error": "资源不存在"})
        # 他租户内无该验证者：在 OTHER 建他租户来源后再查仍 404。
        st, _ = post(ANCHORS_PATH,
                     {"did": signer_did, "public_key": signer_pub,
                      "key_version": 1,
                      "uses": ["generic", "status"]}, OTHER)
        assert st in (200, 201), st
        other_nd = to_ndjson(rows[:1])
        st, _ = post(
            SYNC_PATH,
            {"manifest": signed_manifest(1, 0, other_nd),
             "ndjson": other_nd},
            headers=OTHER)
        assert st == 201, st
        st, body = receipt(
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier_did)}&nonce=n-1",
            headers=OTHER)
        check("跨租户验证者 404",
              st == 404 and body == {"error": "资源不存在"})

        # -------------------------------------------------------------- #
        # 3. 200：结构、键序、digest、签名
        # -------------------------------------------------------------- #
        nonce = "nonce-一"
        st, body = receipt(qs(nonce))
        check("正常回执 200", st == 200)
        check("顶层键序恰为 receipt/signature",
              list(body.keys()) == OK_KEYS)
        receipt_obj = body["receipt"]
        check("receipt 键序", list(receipt_obj.keys()) == RECEIPT_KEYS)
        check("signer_did 回显", receipt_obj["signer_did"] == signer_did)
        check("verifier_did 回显",
              receipt_obj["verifier_did"] == verifier_did)
        check("nonce 回显", receipt_obj["nonce"] == nonce)
        check("next_after 为非负整数",
              isinstance(receipt_obj["next_after"], int)
              and not isinstance(receipt_obj["next_after"], bool)
              and receipt_obj["next_after"] >= 0)
        check("verifier_key_version 为正整数",
              isinstance(receipt_obj["verifier_key_version"], int)
              and not isinstance(receipt_obj["verifier_key_version"], bool)
              and receipt_obj["verifier_key_version"] >= 1)
        check("digest 为 64 位小写 hex",
              isinstance(receipt_obj["digest"], str)
              and len(receipt_obj["digest"]) == 64
              and receipt_obj["digest"] == receipt_obj["digest"].lower()
              and all(ch in "0123456789abcdef"
                      for ch in receipt_obj["digest"]))
        check("signature 为非空字符串",
              isinstance(body["signature"], str) and body["signature"])

        next_after, want_digest = expected_digest()
        check("next_after=检查点 3", receipt_obj["next_after"] == 3)
        check("next_after 与 history 一致", next_after == 3)
        check("digest=history 行字节 SHA-256",
              receipt_obj["digest"] == want_digest)

        # 手工按五键顺序重建行，确认服务端行编码逐字节一致。
        st, hist_raw = get(
            f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        hist_events = json.loads(hist_raw)["events"]
        check("history 事件五键键序",
              all(list(e.keys()) == EVENT_KEYS for e in hist_events))
        manual = "".join(
            json.dumps(
                {"cursor": e["cursor"],
                 "receipt_id": e["receipt_id"],
                 "verifier_did": e["verifier_did"],
                 "nonce": e["nonce"],
                 "consumed_at": e["consumed_at"]},
                separators=(",", ":"), ensure_ascii=False) + "\n"
            for e in hist_events
        ).encode("utf-8")
        check("手工重建 digest 一致",
              hashlib.sha256(manual).hexdigest()
              == receipt_obj["digest"])

        # 签名以验证者当前公钥对 receipt 规范化 JSON 验证通过。
        try:
            crypto.verify(receipt_obj, body["signature"], verifier_pub)
            sig_ok = True
        except Exception:  # noqa: BLE001
            sig_ok = False
        check("receipt_signature 可由验证者公钥验签", sig_ok)

        # 不同 nonce：digest 不变、receipt 仅 nonce 变化、签名仍可验。
        st, body2 = receipt(qs("other-nonce"))
        assert st == 200
        check("nonce 不影响 digest",
              body2["receipt"]["digest"] == receipt_obj["digest"])
        check("nonce 不影响 next_after",
              body2["receipt"]["next_after"] == 3)
        try:
            crypto.verify(body2["receipt"], body2["signature"],
                          verifier_pub)
            sig_ok2 = True
        except Exception:  # noqa: BLE001
            sig_ok2 = False
        check("不同 nonce 签名可验", sig_ok2)

        # nonce 恰 256 码点（200 ASCII + 56 个中文字符）合法。
        boundary_nonce = "a" * 200 + "中" * 56
        check("构造 nonce 恰为 256 码点", len(boundary_nonce) == 256)
        st, body3 = receipt(
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier_did)}"
            f"&nonce={urllib.parse.quote(boundary_nonce)}")
        check("nonce 256 码点合法",
              st == 200 and body3["receipt"]["nonce"] == boundary_nonce)

        # -------------------------------------------------------------- #
        # 4. 409：验证者停用
        # -------------------------------------------------------------- #
        st, raw = post(f"{DIDS_PATH}/{verifier_did}/deactivate", {}, DST)
        assert st == 200, (st, raw)
        st, body = receipt(good)
        check("验证者停用 409",
              st == 409 and body == {"error": "验证者已停用"})
        # 来源仍不存在时优先 404（来源先于验证者判定）。
        st, body = receipt(unknown_signer)
        check("来源未知优先于停用 409 -> 404",
              st == 404 and body == {"error": "资源不存在"})

        # 恢复：登记第二个活动验证者，200 不受停用影响。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "credential-status-receipt-sync-rcpt-2"},
                       DST)
        assert st == 201, (st, raw)
        verifier2 = json.loads(raw)
        st, body4 = receipt(
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier2['did'])}"
            "&nonce=n-9")
        check("活动验证者 200",
              st == 200 and body4["receipt"]["verifier_did"]
              == verifier2["did"])

        # -------------------------------------------------------------- #
        # 5. 只读：不推进检查点、不写审计
        # -------------------------------------------------------------- #
        st, audit_before = get("/v1/audit?limit=200", headers=DST)
        assert st == 200
        # 续页仍衔接 next_after=3：查询回执未推进/回退检查点。
        st, r = sync(rows[3:], 3, 5)
        check("回执查询后续页正常 200（检查点未受只读影响）",
              st == 200 and r["next_after"] == 5 and r["count"] == 2)
        # digest 随新行变化且与新检查点一致。
        st, body5 = receipt(
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier2['did'])}"
            "&nonce=n-9")
        assert st == 200
        next_after2, want_digest2 = expected_digest()
        check("追平后 next_after=5",
              body5["receipt"]["next_after"] == 5 == next_after2)
        check("追平后 digest 与新 history 一致",
              body5["receipt"]["digest"] == want_digest2
              and want_digest2 != want_digest)
        check("事件按 cursor 升序",
              [e["cursor"] for e in hist_events] == sorted(
                  e["cursor"] for e in hist_events))

        st, audit_after = get("/v1/audit?limit=200", headers=DST)
        assert st == 200
        check("回执查询不写审计", audit_before == audit_after)

        # -------------------------------------------------------------- #
        # 6. 缺省租户头：沿用 default 租户隔离规则
        # -------------------------------------------------------------- #
        st, raw = get(f"{RECEIPT_PATH}?{good}")  # 不带 X-Tenant-ID
        body = json.loads(raw.decode() or "null")
        check("缺省租户头在 default 内来源不存在 404",
              st == 404 and body == {"error": "资源不存在"})

        # -------------------------------------------------------------- #
        # 7. 重启稳定：receipt 与 digest 相同，签名可验
        # -------------------------------------------------------------- #
        captured_qs = (
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier2['did'])}"
            "&nonce=" + urllib.parse.quote("重启-nonce-𝄞"))
        st, before_raw = get(f"{RECEIPT_PATH}?{captured_qs}", headers=DST)
        assert st == 200
        before = json.loads(before_raw)
        proc.terminate()
        proc.wait(timeout=10)
        proc = start()
        st, after_raw = get(f"{RECEIPT_PATH}?{captured_qs}", headers=DST)
        check("重启后 200", st == 200)
        after = json.loads(after_raw)
        check("重启后 receipt 逐字节一致",
              after["receipt"] == before["receipt"])
        check("重启后 digest 相同",
              after["receipt"]["digest"] == before["receipt"]["digest"]
              and after["receipt"]["next_after"] == 5)
        try:
            crypto.verify(after["receipt"], after["signature"],
                          verifier2["public_key"])
            restart_sig_ok = True
        except Exception:  # noqa: BLE001
            restart_sig_ok = False
        check("重启后签名可验", restart_sig_ok)
        # 检查点未被任何回执查询推进。
        st, hist_raw = get(
            f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        check("重启后检查点仍为 5",
              st == 200 and json.loads(hist_raw)["next_after"] == 5)

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
