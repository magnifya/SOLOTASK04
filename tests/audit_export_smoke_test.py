#!/usr/bin/env python3
"""Smoke test for the new /v1/audit/export endpoints."""
import hashlib
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

EXPORT = "/v1/audit/export"
MANIFEST = "/v1/audit/export/manifest"
VERIFY = "/v1/audit/export/manifest/verify"


def _http(method, url, payload=None, headers=None, raw=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def main():
    port = 9777
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        assert wait_up(port)
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        # create some audit events in tenant-a (did register) and tenant-b
        st, _, raw = _http("POST", f"{base}/v1/dids",
                           {"method": "web", "public_key": "exp-signer"}, TA)
        assert st == 201, raw
        signer = json.loads(raw)
        signer_did, signer_pub = signer["did"], signer["public_key"]
        st, _, raw = _http("POST", f"{base}/v1/dids",
                           {"method": "web", "public_key": "exp-other"}, TA)
        assert st == 201, raw
        st, _, _ = _http("POST", f"{base}/v1/dids",
                         {"method": "web", "public_key": "exp-b"}, TB)
        assert st == 201

        # --- export: default snapshot = global max seq (3 events global)
        st, hdr, raw = _http("GET", base + EXPORT, headers=TA)
        check("export 200", st == 200)
        check("export content-type",
              hdr.get("Content-Type") == "application/x-ndjson; charset=utf-8")
        check("export X-Snapshot-Seq=3", hdr.get("X-Snapshot-Seq") == "3")
        lines = raw.decode().splitlines()
        check("export 2 lines for tenant-a", len(lines) == 2)
        rows = [json.loads(x) for x in lines]
        check("export line keys order", all(
            list(r.keys()) == ["seq", "timestamp", "tenant_id", "action",
                               "resource_type", "resource_id"] for r in rows))
        check("export seqs", [r["seq"] for r in rows] == [1, 2])
        check("export X-Next-After=2", hdr.get("X-Next-After") == "2")
        check("export ends with LF", raw.endswith(b"\n"))

        # compact json check: no spaces
        check("export compact", b'", "' not in raw and b'": ' not in raw)

        # --- paging: limit=1
        st, hdr, raw = _http("GET", f"{base}{EXPORT}?limit=1", headers=TA)
        check("page1 1 line", st == 200 and len(raw.decode().splitlines()) == 1
              and hdr.get("X-Next-After") == "1")
        st, hdr, raw2 = _http(
            "GET", f"{base}{EXPORT}?limit=1&after=1&snapshot=3", headers=TA)
        check("page2 next line", st == 200
              and json.loads(raw2.decode().splitlines()[0])["seq"] == 2
              and hdr.get("X-Next-After") == "2")
        # empty page: after=2 snapshot=2 -> zero bytes, cursor stays
        st, hdr, raw3 = _http(
            "GET", f"{base}{EXPORT}?after=2&snapshot=2", headers=TA)
        check("empty page zero bytes", st == 200 and raw3 == b""
              and hdr.get("X-Next-After") == "2"
              and hdr.get("X-Snapshot-Seq") == "2")

        # tenant isolation: tenant-b sees only its own event (seq 3)
        st, hdr, raw = _http("GET", base + EXPORT, headers=TB)
        check("tenant-b 1 line", len(raw.decode().splitlines()) == 1)
        check("tenant-b seq 3",
              json.loads(raw.decode().splitlines()[0])["seq"] == 3)

        # --- 400s, all exactly {"error":"请求非法"}
        def expect_bad(name, url, headers=TA, method="GET", payload=None,
                       raw_body=None):
            st, _, r = _http(method, url, payload=payload, headers=headers,
                             raw=raw_body)
            try:
                obj = json.loads(r.decode() or "{}")
            except ValueError:
                obj = {}
            check(f"400 请求非法: {name}",
                  st == 400 and obj == {"error": "请求非法"})

        expect_bad("unknown param", f"{base}{EXPORT}?foo=1")
        expect_bad("dup param", f"{base}{EXPORT}?limit=1&limit=2")
        expect_bad("empty limit", f"{base}{EXPORT}?limit=")
        expect_bad("limit 0", f"{base}{EXPORT}?limit=0")
        expect_bad("limit 10001", f"{base}{EXPORT}?limit=10001")
        expect_bad("limit alpha", f"{base}{EXPORT}?limit=abc")
        expect_bad("after negative", f"{base}{EXPORT}?after=-1")
        expect_bad("after>snapshot", f"{base}{EXPORT}?after=5&snapshot=2")
        expect_bad("snapshot>max", f"{base}{EXPORT}?snapshot=99")
        expect_bad("empty tenant", base + EXPORT, headers={"X-Tenant-ID": ""})
        expect_bad("manifest missing snapshot",
                   f"{base}{MANIFEST}?signer_did={signer_did}")
        expect_bad("manifest missing signer",
                   f"{base}{MANIFEST}?snapshot=3")
        expect_bad("manifest snapshot>max",
                   f"{base}{MANIFEST}?snapshot=99&signer_did={signer_did}")
        expect_bad("manifest empty tenant",
                   f"{base}{MANIFEST}?snapshot=3&signer_did={signer_did}",
                   headers={"X-Tenant-ID": ""})
        expect_bad("verify empty tenant", base + VERIFY, method="POST",
                   payload={"manifest": {}, "ndjson": ""},
                   headers={"X-Tenant-ID": ""})
        expect_bad("verify extra field", base + VERIFY, method="POST",
                   payload={"manifest": {}, "ndjson": "", "x": 1})
        expect_bad("verify missing ndjson", base + VERIFY, method="POST",
                   payload={"manifest": {}})
        expect_bad("verify bad json", base + VERIFY, method="POST",
                   raw_body=b"{not json")
        expect_bad("verify ndjson non-str", base + VERIFY, method="POST",
                   payload={"manifest": {}, "ndjson": 5})

        # --- manifest 404/409
        st, _, r = _http("GET",
                         f"{base}{MANIFEST}?snapshot=3&signer_did=did:web:nope",
                         headers=TA)
        check("manifest unknown did 404", st == 404)
        st, _, r = _http("GET",
                         f"{base}{MANIFEST}?snapshot=3&signer_did={signer_did}",
                         headers=TB)
        check("manifest cross-tenant did 404", st == 404)

        # --- manifest happy path
        st, _, r = _http(
            "GET",
            f"{base}{MANIFEST}?snapshot=3&signer_did={signer_did}"
            "&after=0&limit=1000",
            headers=TA)
        check("manifest 200", st == 200)
        m = json.loads(r)
        check("manifest keys order",
              list(m.keys()) == ["snapshot", "filters", "count", "alg",
                                 "digest", "signer_did", "key_version",
                                 "signature"])
        check("manifest filters", m["filters"] == {"after": 0, "limit": 1000})
        check("manifest alg", m["alg"] == "SHA-256")
        check("manifest count", m["count"] == 2)
        check("manifest snapshot", m["snapshot"] == 3)
        check("manifest key_version", m["key_version"] == 1)

        # digest must equal sha256 of export bytes for same params
        st, _, raw_exp = _http(
            "GET", f"{base}{EXPORT}?snapshot=3&after=0&limit=1000", headers=TA)
        check("manifest digest",
              m["digest"] == hashlib.sha256(raw_exp).hexdigest())
        ndjson = raw_exp.decode()

        # --- verify: no anchor yet -> 锚点不可用
        st, _, r = _http("POST", base + VERIFY,
                         {"manifest": m, "ndjson": ndjson}, TA)
        check("verify no anchor", st == 200
              and json.loads(r) == {"valid": False, "reason": "锚点不可用"})

        # register generic anchor
        st, _, _ = _http("POST", f"{base}/v1/trust/anchors", {
            "did": signer_did, "public_key": signer_pub,
            "key_version": 1, "uses": ["generic"]}, TA)
        check("anchor registered", st in (200, 201))

        st, _, r = _http("POST", base + VERIFY,
                         {"manifest": m, "ndjson": ndjson}, TA)
        check("verify valid", st == 200 and json.loads(r) == {"valid": True})

        # empty page manifest+verify
        st, _, r = _http(
            "GET",
            f"{base}{MANIFEST}?snapshot=2&signer_did={signer_did}&after=2",
            headers=TA)
        m0 = json.loads(r)
        check("empty manifest count 0", m0["count"] == 0
              and m0["digest"] == hashlib.sha256(b"").hexdigest())
        st, _, r = _http("POST", base + VERIFY,
                         {"manifest": m0, "ndjson": ""}, TA)
        check("verify empty valid", json.loads(r) == {"valid": True})

        # --- verify failure reasons
        def expect_reason(name, manifest, nd, reason):
            st, _, r = _http("POST", base + VERIFY,
                             {"manifest": manifest, "ndjson": nd}, TA)
            check(f"reason {name}", st == 200 and json.loads(r)
                  == {"valid": False, "reason": reason})

        bad = json.loads(json.dumps(m))
        del bad["count"]
        expect_reason("清单非法 keys", bad, ndjson, "清单非法")
        bad = json.loads(json.dumps(m))
        bad["filters"] = {"after": 0}
        expect_reason("清单非法 filters", bad, ndjson, "清单非法")
        bad = json.loads(json.dumps(m))
        bad["alg"] = "SHA-512"
        expect_reason("清单非法 alg", bad, ndjson, "清单非法")
        bad = json.loads(json.dumps(m))
        bad["signer_did"] = "did:web:unknown"
        expect_reason("锚点不可用 unknown", bad, ndjson, "锚点不可用")
        bad = json.loads(json.dumps(m))
        bad["signature"] = "@@@"
        expect_reason("签名格式错误", bad, ndjson, "签名格式错误")
        bad = json.loads(json.dumps(m))
        bad["signature"] = "A" * 86
        expect_reason("签名校验失败", bad, ndjson, "签名校验失败")
        # tampered ndjson (digest mismatch)
        expect_reason("内容不匹配 digest", m, ndjson.replace("web", "xxx", 1),
                      "导出内容不匹配")
        # tampered line structure: re-sign a manifest over bad ndjson
        # (need signing key -> use a manifest whose digest we control is
        # impossible server-side; instead craft bad-structure ndjson and
        # recompute digest, but signature won't match -> 签名校验失败.
        # So structure checks only reachable with valid signature: skip.)

        # deactivated signer DID -> 409 on manifest
        st, _, _ = _http("POST",
                         f"{base}/v1/dids/{signer_did}/deactivate",
                         {}, TA)
        if st == 404:  # try alternate deactivation route
            st, _, _ = _http(
                "PUT", f"{base}/v1/dids/{signer_did}/status",
                {"status": "deactivated"}, TA)
        st, _, r = _http(
            "GET",
            f"{base}{MANIFEST}?snapshot=3&signer_did={signer_did}",
            headers=TA)
        check("manifest deactivated did 409", st == 409)

        # --- restart stability
        proc.terminate()
        proc.wait(timeout=10)
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port)
        st, hdr, raw_after = _http(
            "GET", f"{base}{EXPORT}?snapshot=3&after=0&limit=1000", headers=TA)
        check("restart byte-identical export",
              st == 200 and raw_after == raw_exp)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.unlink(store)

    print()
    if failures:
        print(f"{len(failures)} FAILURES")
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
