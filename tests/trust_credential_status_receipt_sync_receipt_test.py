#!/usr/bin/env python3
"""GET /v1/trust/credential-status/receipt-sync/receipt 凭证状态回执
消费同步进度签名回执端到端测试。

直接运行：python3 tests/trust_credential_status_receipt_sync_receipt_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。

数据来源：来源租户先经 credential-status/receipt/consume 产生真实状态
回执消费历史，再经 export/manifest 与 credential-status/receipt-sync
同步至目标租户；回执摘要的期望 NDJSON 全部从 receipt-sync/history
端点实际落盘行重建，不硬编码。

覆盖（完整对齐 GET /v1/trust/presentation-sync/receipt，差异为独立
凭证状态回执同步状态空间与 history 五键）：
- 参数协议：仅 signer_did/verifier_did/nonce 三项且唯一，均须非空串；
  nonce 限 1..256 个 Unicode 码点；缺失、重复、空值、未知参数、
  nonce 越界均 400 且仅 {"error":"请求非法"}；显式空租户头 400 且仅
  {"error":"X-Tenant-ID 不能为空"}；
- 404：同步来源不存在 / 跨租户、验证者 DID 不存在 / 跨租户，仅
  {"error":"资源不存在"}；
- 409：验证者已停用，仅 {"error":"验证者已停用"}；
- 200 键序恰为 receipt、signature；receipt 键序恰为 signer_did、
  next_after、digest、verifier_did、verifier_key_version、nonce；
  next_after 为非负整数、verifier_key_version 为正整数；
- digest 为 cursor 升序、逐行沿用 history 五键
  cursor/receipt_id/verifier_did/nonce/consumed_at 的 NDJSON 编码行
  字节的 SHA-256 小写 64 位 hex（含非 ASCII 不转义）；signature 以
  验证者当前公钥按既有规范化 JSON 与 ES256 裸签名协议可验；
- 只读：不推进检查点（续页仍衔接）、不写审计；
- 重启后 receipt 与 digest 相同且签名可验。
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
EXPORT_PATH = (
    "/v1/trust/credential-status/receipt/consumptions/export"
)
MANIFEST_PATH = (
    "/v1/trust/credential-status/receipt/consumptions/manifest"
)
CONSUME_PATH = "/v1/trust/credential-status/receipt/consume"
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


def main():
    port = 9079
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
        SRC = {"X-Tenant-ID": "csr-src-tenant"}
        DST = {"X-Tenant-ID": "csr-dst-tenant"}
        OTHER = {"X-Tenant-ID": "csr-other-tenant"}

        # 来源租户托管验证者 DID（消费签名者），其公钥在来源与目标均
        # 以含 status 用途的信任锚点登记。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "cs-receipt-sync-receipt-signer"},
                       SRC)
        assert st == 201, (st, raw)
        signer_rec = json.loads(raw)
        signer_did = signer_rec["did"]
        signer_pub = signer_rec["public_key"]
        with open(store_path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        signer_priv = state["tenants"]["csr-src-tenant"]["dids"][
            signer_did]["key_history"][0]["private_key_pem"]

        for tenant in (SRC, DST):
            st, _ = post(ANCHORS_PATH,
                         {"did": signer_did, "public_key": signer_pub,
                          "key_version": 1,
                          "uses": ["generic", "status"]}, tenant)
            assert st in (200, 201), st

        def make_receipt(index, nonce):
            rcpt = {
                "issuer_did": "did:web:csr-issuer.example",
                # 首行 credential 语义不参与本端点；nonce 含非 ASCII，
                # 校验 digest 必须按 ensure_ascii=False 的 UTF-8 行字节。
                "credential_id": f"vc_csr_{index:03d}",
                "status": "active",
                "reason": None,
                "updated_at": "2099-01-01T00:00:00Z",
                "issuer_key_version": 1,
                "verifier_did": signer_did,
                "verifier_key_version": 1,
                "nonce": nonce,
            }
            return rcpt, crypto.sign(rcpt, signer_priv)

        packs = []

        def consume_one(index):
            nonce = f"csr-nonce-{'一' if index == 1 else index}"
            rcpt, sig = make_receipt(index, nonce)
            st, raw = post(CONSUME_PATH,
                           {"receipt": rcpt, "signature": sig,
                            "nonce": nonce}, SRC)
            assert st == 200 and json.loads(raw)["valid"] is True, raw
            packs.append(nonce)

        for i in range(1, 6):
            consume_one(i)

        def export_page(after, limit, snapshot, headers=SRC):
            st, raw = get(
                f"{EXPORT_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}", headers=headers)
            assert st == 200, (st, raw)
            return raw.decode("utf-8")

        def manifest_page(after, limit, snapshot, headers=SRC):
            st, raw = get(
                f"{MANIFEST_PATH}?after={after}&limit={limit}"
                f"&snapshot={snapshot}&signer_did={signer_did}",
                headers=headers)
            assert st == 200, (st, raw)
            return json.loads(raw)

        def sync(ndjson_text, manifest_obj, headers=DST):
            st, raw = post(SYNC_PATH,
                           {"manifest": manifest_obj,
                            "ndjson": ndjson_text}, headers=headers)
            return st, json.loads(raw)

        # 目标租户活动本地验证者 DID（托管私钥，回执签名者）。
        st, raw = post(DIDS_PATH,
                       {"method": "web",
                        "public_key": "cs-receipt-sync-receipt-verifier"},
                       DST)
        assert st == 201, (st, raw)
        verifier_rec = json.loads(raw)
        verifier_did = verifier_rec["did"]
        verifier_pub = verifier_rec["public_key"]

        def receipt(qs_text, headers=DST):
            st, raw = get(f"{RECEIPT_PATH}?{qs_text}", headers=headers)
            return st, json.loads(raw.decode() or "null")

        def qs(nonce="nonce-一"):
            return urllib.parse.urlencode(
                {"signer_did": signer_did,
                 "verifier_did": verifier_did,
                 "nonce": nonce})

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
        # 显式空租户头由路由统一判 400 且文案固定。
        st, raw = get(f"{RECEIPT_PATH}?{good}",
                      headers={"X-Tenant-ID": ""})
        body = json.loads(raw.decode() or "null")
        check("显式空租户头 400",
              st == 400 and body == {"error": "X-Tenant-ID 不能为空"})

        # -------------------------------------------------------------- #
        # 2. 404：来源未同步 / 跨租户；验证者未知
        # -------------------------------------------------------------- #
        st, body = receipt(good)
        check("未同步来源 404",
              st == 404 and body == {"error": "资源不存在"})

        unknown_signer = (
            "signer_did=did:web:csr-no-such-signer.example"
            f"&verifier_did={urllib.parse.quote(verifier_did)}&nonce=n-1"
        )
        st, body = receipt(unknown_signer)
        check("未知来源 404 固定文案",
              st == 404 and body == {"error": "资源不存在"})
        st, body = receipt(
            "signer_did=did:web:csr-no-such-signer.example"
            "&verifier_did=did:web:csr-no-such-verifier.example&nonce=n-1",
            headers=OTHER)
        check("跨租户 404 同形",
              st == 404 and body == {"error": "资源不存在"})

        # 灌入首页（snapshot=3, after=0，cursor 1..3）。
        nd1 = export_page(0, 3, 3)
        m1 = manifest_page(0, 3, 3)
        st, r = sync(nd1, m1)
        assert st == 201 and r["next_after"] == 3, (st, r)

        # 来源已存在，但验证者 DID 未知 / 跨租户。
        unknown_verifier = (
            f"signer_did={signer_did}"
            "&verifier_did=did:web:csr-no-such-verifier.example&nonce=n-1"
        )
        st, body = receipt(unknown_verifier)
        check("未知验证者 404",
              st == 404 and body == {"error": "资源不存在"})
        st, body = receipt(good, headers=OTHER)
        check("同步后跨租户仍 404（来源跨租户）",
              st == 404 and body == {"error": "资源不存在"})

        # -------------------------------------------------------------- #
        # 3. 200：结构、键序、digest、签名
        # -------------------------------------------------------------- #
        nonce = "nonce-一"  # 含多字节字符
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

        # 期望 NDJSON 从 history 端点实际落盘行重建（缺省 at=检查点）。
        st, hist_raw = get(
            f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        assert st == 200, hist_raw
        hist = json.loads(hist_raw)
        check("history 事件五键键序",
              all(list(e.keys()) == EVENT_KEYS for e in hist["events"]))
        want_ndjson = "".join(
            json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n"
            for e in hist["events"])
        want_digest = hashlib.sha256(
            want_ndjson.encode("utf-8")).hexdigest()
        check("next_after=检查点 3", receipt_obj["next_after"] == 3)
        check("next_after 与 history 一致", hist["next_after"] == 3)
        check("digest=history 行字节 SHA-256",
              receipt_obj["digest"] == want_digest)

        # 手工按五键顺序重建，确认服务端行编码逐字节一致（首行 nonce
        # 含非 ASCII，须按 UTF-8 计摘要）。
        manual = "".join(
            json.dumps(
                {"cursor": e["cursor"],
                 "receipt_id": e["receipt_id"],
                 "verifier_did": e["verifier_did"],
                 "nonce": e["nonce"],
                 "consumed_at": e["consumed_at"]},
                separators=(",", ":"), ensure_ascii=False) + "\n"
            for e in hist["events"]
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
                        "public_key": "cs-receipt-sync-receipt-verifier-2"},
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
        nd2 = export_page(3, 2, 5)
        m2 = manifest_page(3, 2, 5)
        st, r = sync(nd2, m2)
        check("回执查询后续页正常 200（检查点未受只读影响）",
              st == 200 and r["next_after"] == 5 and r["count"] == 2)
        st, body5 = receipt(
            f"signer_did={signer_did}"
            f"&verifier_did={urllib.parse.quote(verifier2['did'])}"
            "&nonce=n-9")
        assert st == 200
        st, hist_raw2 = get(
            f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        hist2 = json.loads(hist_raw2)
        want2 = "".join(
            json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n"
            for e in hist2["events"])
        check("追平后 next_after=5",
              body5["receipt"]["next_after"] == 5
              == hist2["next_after"])
        check("追平后 digest 与新 history 一致",
              body5["receipt"]["digest"]
              == hashlib.sha256(want2.encode("utf-8")).hexdigest())
        check("事件按 cursor 升序",
              [e["cursor"] for e in hist2["events"]] == sorted(
                  e["cursor"] for e in hist2["events"]))

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
        check("重启后 digest/next_after 相同",
              after["receipt"]["digest"] == before["receipt"]["digest"]
              and after["receipt"]["next_after"] == 5)
        try:
            crypto.verify(after["receipt"], after["signature"],
                          verifier2["public_key"])
            restart_sig_ok = True
        except Exception:  # noqa: BLE001
            restart_sig_ok = False
        check("重启后签名可验", restart_sig_ok)
        st, hist_raw3 = get(
            f"{HISTORY_PATH}?signer_did={signer_did}", headers=DST)
        check("重启后检查点仍为 5",
              st == 200 and json.loads(hist_raw3)["next_after"] == 5)

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
