#!/usr/bin/env python3
"""GET/POST .../receipt-sync/receipt/consumptions/manifest 系列端点
凭证状态同步进度回执消费历史签名摘要清单与验真端到端测试。

直接运行：
python3 tests/trust_credential_status_receipt_sync_receipt_consumptions_manifest_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
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

BASE_PATH = "/v1/trust/credential-status/receipt-sync/receipt/consumptions"
MANIFEST_PATH = BASE_PATH + "/manifest"
VERIFY_PATH = MANIFEST_PATH + "/verify"
BATCH_PATH = MANIFEST_PATH + "/verify-batch"
EXPORT_PATH = BASE_PATH + "/export"
SYNC_PATH = "/v1/trust/credential-status/receipt-sync"
RECEIPT_PATH = "/v1/trust/credential-status/receipt-sync/receipt"
CONSUME_PATH = RECEIPT_PATH + "/consume"
ANCHORS_PATH = "/v1/trust/anchors"
DIDS_PATH = "/v1/dids"
MANIFEST_KEYS = [
    "snapshot", "filters", "count", "alg",
    "digest", "signer_did", "key_version", "signature",
]


def _http(method, url, payload=None, headers=None, raw_body=None):
    if raw_body is not None:
        data = raw_body
    else:
        data = json.dumps(payload).encode() if payload is not None else None
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


def _json(method, url, payload=None, headers=None, raw_body=None):
    st, raw = _http(method, url, payload=payload, headers=headers,
                    raw_body=raw_body)
    try:
        return st, json.loads(raw.decode() or "{}")
    except ValueError:
        return st, {"__raw__": raw}


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


def seed_world(base, headers, failures):
    """造数据：外部 status 锚点同步 3 行；本地 DID 消费 2 枚回执。"""
    signer_priv, signer_pub = _keypair()
    signer_did = "did:web:cssrm-remote.example"
    st, _ = _http("POST", f"{base}{ANCHORS_PATH}",
                  {"did": signer_did, "public_key": signer_pub,
                   "key_version": 1, "uses": ["generic", "status"]},
                  headers)
    assert st == 201, st

    def make_row(cursor, index):
        return {
            "cursor": cursor,
            "receipt_id": f"rcpt-cssrm-{index:040d}",
            "verifier_did": "did:web:cssrm-remote-verifier.example",
            "nonce": f"cssrm-nonce-{index:03d}",
            "consumed_at": "2099-01-01T00:00:00Z",
        }

    def to_ndjson(rows):
        return "".join(
            json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
            for row in rows)

    seed = to_ndjson([make_row(c, c) for c in (1, 2, 3)])
    remote_m = {
        "snapshot": 3,
        "filters": {"after": 0, "limit": 1000},
        "count": seed.count("\n"),
        "alg": "SHA-256",
        "digest": hashlib.sha256(seed.encode()).hexdigest(),
        "signer_did": signer_did,
        "key_version": 1,
    }
    remote_m["signature"] = crypto.sign(
        {k: remote_m[k] for k in MANIFEST_KEYS[:7]}, signer_priv)
    st, r = _json("POST", f"{base}{SYNC_PATH}",
                  {"manifest": remote_m, "ndjson": seed}, headers)
    assert st in (200, 201), (st, r)

    st, rec = _json("POST", f"{base}{DIDS_PATH}",
                    {"method": "web", "public_key": "cssrm-local"}, headers)
    assert st == 201, (st, rec)
    local_did = rec["did"]
    local_version = rec["key_version"]
    st, _ = _http("POST", f"{base}{ANCHORS_PATH}",
                  {"did": local_did, "public_key": rec["public_key"],
                   "key_version": local_version,
                   "uses": ["generic", "status"]}, headers)
    assert st in (200, 201), st

    for nonce in ("cssrm-n1", "cssrm-n2"):
        qs = urllib.parse.urlencode(
            {"signer_did": signer_did,
             "verifier_did": local_did, "nonce": nonce})
        st, issued = _json("GET", f"{base}{RECEIPT_PATH}?{qs}",
                           headers=headers)
        assert st == 200, (st, issued)
        st, r = _json("POST", f"{base}{CONSUME_PATH}",
                      {"receipt": issued["receipt"],
                       "signature": issued["signature"],
                       "ndjson": seed, "nonce": nonce}, headers)
        assert st == 200 and r.get("valid") is True, r
    return local_did, local_version, signer_did, signer_priv


def main():
    port = 9157
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
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def mget(query="", headers=None):
        url = (f"{base}{MANIFEST_PATH}?{query}" if query
               else base + MANIFEST_PATH)
        return _json("GET", url, headers=headers)

    try:
        TA = {"X-Tenant-ID": "cssrm-a"}
        TB = {"X-Tenant-ID": "cssrm-b"}
        local_did, local_version, remote_did, signer_priv = seed_world(
            base, TA, failures)
        did_q = urllib.parse.quote(local_did)

        manifest, ndjson_text = run_get_checks(
            base, TA, TB, local_did, did_q, mget, check)
        manifest = run_verify_checks(
            base, TA, TB, manifest, ndjson_text, remote_did,
            signer_priv, check)
        run_batch_checks(base, TA, manifest, ndjson_text, check)

        # 跨重启：验真结论与分页字节一致
        proc.terminate()
        proc.wait()
        proc = start()
        st, again = _http("GET",
                          f"{base}{EXPORT_PATH}?snapshot=2", headers=TA)
        st2, r = _json("POST", f"{base}{VERIFY_PATH}",
                       {"manifest": manifest,
                        "ndjson": again.decode("utf-8")}, TA)
        check("重启后 export 字节一致", st == 200 and again.decode()
              == ndjson_text)
        check("重启后验真仍 valid:true", st2 == 200 and r == {"valid": True})
    finally:
        proc.terminate()
        proc.wait()

    if failures:
        print(f"\n{len(failures)} 项失败")
        sys.exit(1)
    print("\n全部通过")


def run_get_checks(base, TA, TB, local_did, did_q, mget, check):
    def expect_400(name, query, headers=None):
        st, r = mget(query, headers=headers)
        check(f"GET 400: {name}",
              st == 400 and isinstance(r.get("error"), str)
              and bool(r["error"]))

    expect_400("缺 snapshot", f"signer_did={local_did}")
    expect_400("缺 signer_did", "snapshot=2")
    expect_400("snapshot 空", f"snapshot=&signer_did={local_did}")
    expect_400("signer_did 空", "snapshot=2&signer_did=")
    expect_400("未知参数",
               f"snapshot=2&signer_did={local_did}&verifier_did=x")
    expect_400("snapshot 重复",
               f"snapshot=1&snapshot=2&signer_did={local_did}")
    expect_400("signer_did 重复",
               f"snapshot=2&signer_did=x&signer_did=y")
    expect_400("非 ASCII 数字",
               f"snapshot=%E0%A9%91&signer_did={local_did}")
    expect_400("snapshot 超最大游标",
               f"snapshot=99&signer_did={local_did}")
    expect_400("after>snapshot",
               f"snapshot=1&after=2&signer_did={local_did}")
    expect_400("limit=0", f"snapshot=2&limit=0&signer_did={local_did}")
    expect_400("limit=10001",
               f"snapshot=2&limit=10001&signer_did={local_did}")
    expect_400("limit 字母",
               f"snapshot=2&limit=abc&signer_did={local_did}")
    expect_400("超长数字串",
               "snapshot=" + "9" * 5000 + f"&signer_did={local_did}")
    expect_400("400 优先于未知签名方",
               "snapshot=99&signer_did=did:web:unknown.example")
    st, r = mget(f"snapshot=2&signer_did={local_did}",
                 headers={"X-Tenant-ID": ""})
    check("显式空 X-Tenant-ID 400",
          st == 400 and isinstance(r.get("error"), str) and bool(r["error"]))

    st, r = mget("snapshot=2&signer_did=did:web:no-such.example", TA)
    check("未知签名 DID 404", st == 404 and bool(r.get("error")))
    # 租户 B 无事件（max cursor=0），snapshot=0 合法后签名 DID 未知 -> 404
    st, r = mget(f"snapshot=0&signer_did={local_did}", TB)
    check("跨租户签名 DID 404", st == 404 and bool(r.get("error")))

    # 200 清单
    st, manifest = mget(f"snapshot=2&signer_did={did_q}", TA)
    check("GET 200", st == 200)
    check("顶层键序", list(manifest.keys()) == MANIFEST_KEYS)
    check("filters 键序与缺省生效值",
          list(manifest["filters"].keys()) == ["after", "limit"]
          and manifest["filters"] == {"after": 0, "limit": 1000})
    check("snapshot/count/alg",
          manifest["snapshot"] == 2 and manifest["count"] == 2
          and manifest["alg"] == "SHA-256")
    check("签名方版本",
          manifest["signer_did"] == local_did
          and isinstance(manifest["key_version"], int)
          and isinstance(manifest["signature"], str)
          and manifest["signature"])
    check("digest 64 小写 hex",
          len(manifest["digest"]) == 64
          and manifest["digest"] == manifest["digest"].lower())
    st, export_bytes = _http("GET", f"{base}{EXPORT_PATH}?snapshot=2",
                             headers=TA)
    assert st == 200
    check("digest=export NDJSON SHA-256",
          manifest["digest"]
          == hashlib.sha256(export_bytes).hexdigest())
    check("count=LF 行数",
          manifest["count"] == export_bytes.count(b"\n") == 2)
    ndjson_text = export_bytes.decode("utf-8")

    # after/limit 过滤值
    st, m2 = mget(f"snapshot=2&after=1&limit=1&signer_did={did_q}", TA)
    st2, exp2 = _http("GET",
                      f"{base}{EXPORT_PATH}?snapshot=2&after=1&limit=1",
                      headers=TA)
    check("after/limit 清单与 export 一致",
          st == 200 and st2 == 200
          and m2["filters"] == {"after": 1, "limit": 1}
          and m2["count"] == 1
          and m2["digest"] == hashlib.sha256(exp2).hexdigest())

    # 空页：count=0、零字节摘要、LF 行数 0
    st, m3 = mget(f"snapshot=2&after=2&signer_did={did_q}", TA)
    st3, exp3 = _http("GET",
                      f"{base}{EXPORT_PATH}?snapshot=2&after=2",
                      headers=TA)
    empty_digest = hashlib.sha256(b"").hexdigest()
    check("空页清单 count=0 digest=sha256(空)",
          st == 200 and st3 == 200 and exp3 == b""
          and m3["count"] == 0 and m3["digest"] == empty_digest)
    return manifest, ndjson_text


def _craft_manifest(signer_did, key_version, private_pem, *,
                    snapshot=2, after=0, limit=1000, count=2,
                    digest=None, ndjson_for_digest=None):
    if digest is None:
        digest = hashlib.sha256(
            (ndjson_for_digest or "").encode()).hexdigest()
    m = {
        "snapshot": snapshot,
        "filters": {"after": after, "limit": limit},
        "count": count,
        "alg": "SHA-256",
        "digest": digest,
        "signer_did": signer_did,
        "key_version": key_version,
    }
    m["signature"] = crypto.sign(
        {k: m[k] for k in MANIFEST_KEYS[:7]}, private_pem)
    return m


def run_verify_checks(base, TA, TB, manifest, ndjson_text, remote_did,
                      signer_priv, check):
    def verify(payload=None, raw_body=None, headers=None):
        return _json("POST", f"{base}{VERIFY_PATH}", payload=payload,
                     raw_body=raw_body, headers=headers or TA)

    def expect_v400(name, payload=None, raw_body=None):
        st, r = verify(payload=payload, raw_body=raw_body)
        check(f"verify 400: {name}",
              st == 400 and isinstance(r.get("error"), str)
              and bool(r["error"]))

    expect_v400("非法 JSON", raw_body=b"{not json")
    expect_v400("空体", raw_body=b"")
    expect_v400("非对象", raw_body=b"[1,2]")
    expect_v400("JSON 标量", raw_body=b"1")
    expect_v400("缺 ndjson", {"manifest": manifest})
    expect_v400("缺 manifest", {"ndjson": ndjson_text})
    expect_v400("多余字段",
                {"manifest": manifest, "ndjson": ndjson_text, "x": 1})
    expect_v400("manifest 非对象",
                {"manifest": [], "ndjson": ndjson_text})
    expect_v400("ndjson 非字符串",
                {"manifest": manifest, "ndjson": 1})

    def expect_reason(name, m, text, reason, headers=None):
        st, r = verify({"manifest": m, "ndjson": text}, headers=headers)
        check(name, st == 200 and r == {"valid": False, "reason": reason})

    # 清单非法：结构缺陷
    bad = dict(manifest)
    bad["alg"] = "SHA-512"
    expect_reason("清单非法 alg", bad, ndjson_text, "清单非法")
    bad2 = dict(manifest)
    bad2["extra"] = 1
    expect_reason("清单非法 多余键", bad2, ndjson_text, "清单非法")
    bad3 = dict(manifest)
    bad3["filters"] = {"after": 0}
    expect_reason("清单非法 filters 缺键", bad3, ndjson_text,
                  "清单非法")

    # 锚点不可用：同结构但签名方无 active status 锚点
    other_priv, _ = _keypair()
    no_anchor = _craft_manifest(
        "did:web:cssrm-no-anchor.example", 1, other_priv,
        ndjson_for_digest=ndjson_text)
    expect_reason("锚点不可用 未知 DID", no_anchor, ndjson_text,
                  "锚点不可用")
    # 跨租户：A 的清单在 B 验，B 无该锚点
    expect_reason("锚点不可用 跨租户", manifest, ndjson_text,
                  "锚点不可用", headers=TB)

    # 签名格式错误
    fmt_bad = dict(manifest)
    fmt_bad["signature"] = "not-a-signature!"
    expect_reason("签名格式错误", fmt_bad, ndjson_text, "签名格式错误")

    # 签名校验失败：格式合法但由他钥签署
    wrong_priv, _ = _keypair()
    m_wrong = _craft_manifest(
        manifest["signer_did"], manifest["key_version"], wrong_priv,
        ndjson_for_digest=ndjson_text)
    expect_reason("签名校验失败", m_wrong, ndjson_text, "签名校验失败")

    # 导出内容不匹配：摘要不符
    tampered = ndjson_text.replace("cssrm-n1", "cssrm-nX")
    expect_reason("导出内容不匹配 摘要", manifest, tampered,
                  "导出内容不匹配")
    # LF 行数不符：用测试持有私钥的外部 status 锚点签署（锚点、签名
    # 均通过，仅 count 与 NDJSON 的 LF 行数不一致）。
    count_bad = _craft_manifest(
        remote_did, 1, signer_priv, count=99,
        ndjson_for_digest=ndjson_text)
    expect_reason("导出内容不匹配 LF 行数", count_bad, ndjson_text,
                  "导出内容不匹配")

    # 全通过
    st, r = verify({"manifest": manifest, "ndjson": ndjson_text})
    check("验真成功仅 valid:true", st == 200 and r == {"valid": True})
    return manifest


def run_batch_checks(base, TA, manifest, ndjson_text, check):
    def batch(payload=None, raw_body=None):
        return _json("POST", f"{base}{BATCH_PATH}", payload=payload,
                     raw_body=raw_body, headers=TA)

    def expect_request_invalid(name, payload=None, raw_body=None):
        st, r = batch(payload=payload, raw_body=raw_body)
        check(name, st == 200
              and r == {"results": [], "reason": "请求非法"})

    expect_request_invalid("空体", raw_body=b"")
    expect_request_invalid("非法 JSON", raw_body=b"{")
    expect_request_invalid("非对象", raw_body=b"[]")
    expect_request_invalid("缺 items", {"manifest": 1})
    expect_request_invalid("多余字段",
                           {"items": [], "x": 1})
    expect_request_invalid("items 非数组", {"items": {}})
    expect_request_invalid("items 空数组", {"items": []})
    expect_request_invalid("items 101 项",
                           {"items": [
                               {"manifest": {}, "ndjson": ""}
                               for _ in range(101)]})

    valid_item = {"manifest": manifest, "ndjson": ndjson_text}
    tampered = ndjson_text.replace("cssrm-n1", "cssrm-nX")
    items = [
        valid_item,
        {"manifest": manifest, "ndjson": tampered},
        {"manifest": {"unexpected": 1}, "ndjson": ndjson_text},
        "not-an-object",
        {"manifest": manifest, "ndjson": 123},
        valid_item,
    ]
    st, r = batch({"items": items})
    want = [
        {"valid": True},
        {"valid": False, "reason": "导出内容不匹配"},
        {"valid": False, "reason": "清单非法"},
        {"valid": False, "reason": "清单非法"},
        {"valid": False, "reason": "清单非法"},
        {"valid": True},
    ]
    check("批量结果等长同序不短路",
          st == 200 and r.get("results") == want
          and "reason" not in r)

    # 100 项边界合法
    st, r = batch({"items": [valid_item for _ in range(100)]})
    check("100 项合法且全 valid",
          st == 200 and len(r.get("results", [])) == 100
          and all(x == {"valid": True} for x in r["results"]))


if __name__ == "__main__":
    main()
