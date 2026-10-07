#!/usr/bin/env python3
"""GET/POST /v1/audit/export 审计快照导出端到端测试。

覆盖 GET /v1/audit/export、GET /v1/audit/export/manifest 与
POST /v1/audit/export/manifest/verify：参数非法一律 400 且恰返
{"error": "请求非法"}；NDJSON 行结构、快照/游标语义、清单签名与
验真原因顺序、租户隔离与重启稳定性。

直接运行：python3 tests/audit_export_test.py
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
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

EXPORT_PATH = "/v1/audit/export"
MANIFEST_PATH = "/v1/audit/export/manifest"
VERIFY_PATH = "/v1/audit/export/manifest/verify"
MANIFEST_KEYS = [
    "snapshot", "filters", "count", "alg", "digest",
    "signer_did", "key_version", "signature",
]
EVENT_KEYS = [
    "seq", "timestamp", "tenant_id",
    "action", "resource_type", "resource_id",
]


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
    port = 9041
    store = tempfile.mktemp(suffix=".json")
    env = dict(os.environ, VCBACKEND_STORE=store)
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

    try:
        assert wait_up(port), "服务启动超时"
        TA = {"X-Tenant-ID": "tenant-a"}
        TB = {"X-Tenant-ID": "tenant-b"}

        def get_export(query="", headers=None):
            url = (f"{base}{EXPORT_PATH}?{query}" if query
                   else base + EXPORT_PATH)
            return _http("GET", url, headers=headers)

        def get_manifest(query="", headers=None):
            url = (f"{base}{MANIFEST_PATH}?{query}" if query
                   else base + MANIFEST_PATH)
            return _http("GET", url, headers=headers)

        def verify(manifest=None, ndjson=None, headers=None, raw=None):
            if raw is not None:
                return _http("POST", base + VERIFY_PATH, headers=headers,
                             raw=raw)
            return _http("POST", base + VERIFY_PATH,
                         {"manifest": manifest, "ndjson": ndjson},
                         headers=headers)

        # ---- 准备数据：tenant-a 签名 DID 与若干审计事件 -------------- #
        st, _, raw = _http("POST", f"{base}/v1/dids",
                           {"method": "web", "public_key": "export-signer"},
                           TA)
        assert st == 201, raw
        signer = json.loads(raw)
        signer_did = signer["did"]
        signer_pub = signer["public_key"]

        st, _, raw = _http("POST", f"{base}/v1/dids",
                           {"method": "web", "public_key": "subject-1"}, TA)
        assert st == 201
        sub_did = json.loads(raw)["did"]
        st, _, raw = _http("POST", f"{base}/v1/credentials", {
            "issuer_did": signer_did, "subject_did": sub_did,
            "claims": {"role": "admin"}}, TA)
        assert st == 201

        # tenant-b 也制造事件：全局序号包含他租户事件
        st, _, raw = _http("POST", f"{base}/v1/dids",
                           {"method": "web", "public_key": "b-subject"}, TB)
        assert st == 201

        _, _, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        events_a = json.loads(raw)["events"]
        _, _, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TB)
        events_b = json.loads(raw)["events"]
        global_max = max(e["seq"] for e in events_a + events_b)
        a_max = events_a[-1]["seq"]
        assert global_max > a_max, "需要 tenant-b 事件推高全局序号"

        # ---- 1. 导出 400 族：恰返 {"error": "请求非法"} -------------- #
        def expect_export_400(name, query, headers=None):
            stx, _, rawx = get_export(query, headers=headers)
            try:
                rr = json.loads(rawx.decode() or "{}")
            except ValueError:
                rr = {}
            check(f"导出 400: {name}",
                  stx == 400 and rr == {"error": "请求非法"})

        expect_export_400("未知参数", "snapshot=0&x=1")
        expect_export_400("snapshot 空值", "snapshot=")
        expect_export_400("snapshot 重复", "snapshot=0&snapshot=1")
        expect_export_400("after 重复", "after=1&after=2")
        expect_export_400("limit 重复", "limit=1&limit=2")
        expect_export_400("snapshot 非 ASCII 数字", "snapshot=%C2%B2")
        expect_export_400("limit Unicode 数字", "limit=%D9%A0")
        expect_export_400("snapshot 负数", "snapshot=-1")
        expect_export_400("snapshot 小数", "snapshot=1.0")
        expect_export_400("snapshot 符号", "snapshot=%2B1")
        expect_export_400("after 空值", "after=")
        expect_export_400("limit 空值", "limit=")
        expect_export_400("limit=0", "limit=0")
        expect_export_400("limit=10001", "limit=10001")
        expect_export_400("after 大于显式 snapshot",
                          "snapshot=1&after=2")
        expect_export_400("snapshot 越界(超过全局最大序号)",
                          "snapshot=999999999")
        expect_export_400("after 大于缺省 snapshot(全局最大)",
                          f"after={global_max + 1}")
        expect_export_400("signer_did 不是导出参数",
                          f"signer_did={signer_did}")
        stx, _, rawx = get_export("snapshot=0", headers={"X-Tenant-ID": ""})
        check("导出显式空租户头 400 请求非法",
              stx == 400 and json.loads(rawx) == {"error": "请求非法"})

        # ---- 2. 导出 200：缺省 snapshot 为全局最大序号 --------------- #
        stx, hdrs, body = get_export("", headers=TA)
        check("导出 200", stx == 200)
        check("Content-Type 为 NDJSON",
              (hdrs.get("Content-Type") or "").lower()
              == "application/x-ndjson; charset=utf-8")
        check("X-Snapshot-Seq 缺省为全局最大序号",
              hdrs.get("X-Snapshot-Seq") == str(global_max))
        check("X-Next-After 为本租户末行 seq",
              hdrs.get("X-Next-After") == str(a_max))
        check("正文 LF 结行", body.endswith(b"\n"))
        lines = body.split(b"\n")[:-1]
        check("行数等于本租户事件数", len(lines) == len(events_a))
        ok_lines = True
        for line, event in zip(lines, events_a):
            obj = json.loads(line.decode("utf-8"))
            if list(obj.keys()) != EVENT_KEYS or obj != {
                k: event[k] for k in EVENT_KEYS
            }:
                ok_lines = False
            # 紧凑 UTF-8 编码逐字节一致
            if line != json.dumps(
                obj, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8"):
                ok_lines = False
        check("每行六字段键序、内容与紧凑编码正确", ok_lines)
        check("行内容即本租户事件（不含他租户）",
              [json.loads(l)["tenant_id"] for l in lines]
              == ["tenant-a"] * len(lines))

        # ---- 3. 显式 snapshot / 分页 / 空页 -------------------------- #
        stx, hdrs, body = get_export(
            f"snapshot={a_max}&limit=2", headers=TA)
        page1 = body.split(b"\n")[:-1]
        check("显式 snapshot + limit 生效",
              stx == 200
              and hdrs.get("X-Snapshot-Seq") == str(a_max)
              and len(page1) == 2)
        next_after = hdrs.get("X-Next-After")
        check("X-Next-After 为末行 seq",
              next_after == str(json.loads(page1[-1])["seq"]))
        stx, hdrs, body = get_export(
            f"snapshot={a_max}&after={next_after}&limit=2",
            headers=TA)
        page2 = body.split(b"\n")[:-1]
        check("续页取后续事件",
              stx == 200
              and [json.loads(l)["seq"] for l in page1 + page2]
              == [e["seq"] for e in events_a])
        stx, hdrs, body = get_export(
            f"snapshot={a_max}&after={a_max}", headers=TA)
        check("空页零字节且游标保持 after",
              stx == 200 and body == b""
              and hdrs.get("X-Next-After") == str(a_max)
              and hdrs.get("Content-Length") == "0")

        # ---- 4. 租户隔离与缺省 default ------------------------------- #
        stx, hdrs, body = get_export("", headers=TB)
        check("tenant-b 仅见本租户事件",
              stx == 200
              and [json.loads(l)["tenant_id"] for l in body.split(b"\n")[:-1]]
              == ["tenant-b"] * len(events_b))
        stx, hdrs, body = get_export("")
        check("缺省 default 租户为空页但快照为全局最大",
              stx == 200 and body == b""
              and hdrs.get("X-Snapshot-Seq") == str(global_max)
              and hdrs.get("X-Next-After") == "0")

        # ---- 5. 清单 400 / 404 / 409 --------------------------------- #
        def expect_manifest_400(name, query, headers=None):
            stx, _, rawx = get_manifest(query, headers=headers)
            try:
                rr = json.loads(rawx.decode() or "{}")
            except ValueError:
                rr = {}
            check(f"清单 400: {name}",
                  stx == 400 and rr == {"error": "请求非法"})

        expect_manifest_400("缺 snapshot", f"signer_did={signer_did}")
        expect_manifest_400("缺 signer_did", "snapshot=0")
        expect_manifest_400("snapshot 空值",
                            f"snapshot=&signer_did={signer_did}")
        expect_manifest_400("signer_did 空值", "snapshot=0&signer_did=")
        expect_manifest_400("未知参数",
                            f"snapshot=0&signer_did={signer_did}&x=1")
        expect_manifest_400("snapshot 重复",
                            f"snapshot=0&snapshot=1&signer_did={signer_did}")
        expect_manifest_400("limit=0",
                            f"snapshot=0&signer_did={signer_did}&limit=0")
        expect_manifest_400("limit=10001",
                            f"snapshot=0&signer_did={signer_did}&limit=10001")
        expect_manifest_400("after 大于 snapshot",
                            f"snapshot=1&signer_did={signer_did}&after=2")
        expect_manifest_400("snapshot 越界",
                            f"snapshot=999999999&signer_did={signer_did}")
        stx, _, rawx = get_manifest(
            f"snapshot=0&signer_did={signer_did}",
            headers={"X-Tenant-ID": ""})
        check("清单显式空租户头 400 请求非法",
              stx == 400 and json.loads(rawx) == {"error": "请求非法"})

        stx, _, _ = get_manifest(
            f"snapshot=0&signer_did=did:web:unknown", headers=TA)
        check("未知签名 DID 404", stx == 404)
        stx, _, _ = get_manifest(
            f"snapshot=0&signer_did={signer_did}", headers=TB)
        check("跨租户签名 DID 404", stx == 404)
        st, _, raw = _http("POST", f"{base}/v1/dids",
                           {"method": "web", "public_key": "dead-signer"},
                           TA)
        dead_did = json.loads(raw)["did"]
        stx, _, _ = _http("POST", f"{base}/v1/dids/{dead_did}/deactivate",
                          {"reason": "停用"}, TA)
        assert stx == 200
        stx, _, _ = get_manifest(
            f"snapshot=0&signer_did={dead_did}", headers=TA)
        check("已停用签名 DID 409", stx == 409)

        # ---- 6. 清单 200：键序、filters、digest、签名 ---------------- #
        stx, _, raw = get_manifest(
            f"snapshot={a_max}&signer_did={signer_did}", headers=TA)
        check("清单 200", stx == 200)
        manifest = json.loads(raw)
        check("清单键序固定", list(manifest.keys()) == MANIFEST_KEYS)
        check("filters 恰含 after/limit 且缺省为 null",
              list(manifest["filters"].keys()) == ["after", "limit"]
              and manifest["filters"] == {"after": None, "limit": None})
        check("alg 恒为 SHA-256", manifest["alg"] == "SHA-256")
        check("count 为本页行数",
              manifest["count"] == len(events_a))
        stx, hdrs, body = get_export(
            f"snapshot={a_max}", headers=TA)
        check("digest 为导出字节 SHA-256",
              manifest["digest"]
              == hashlib.sha256(body).hexdigest()
              and manifest["count"] == len(body.split(b"\n")[:-1]))
        check("签名 DID/版本/签名长度",
              manifest["signer_did"] == signer_did
              and manifest["key_version"] == 1
              and len(manifest["signature"]) == 86)

        stx, _, raw = get_manifest(
            f"snapshot={a_max}&signer_did={signer_did}&after=1&limit=2",
            headers=TA)
        m2 = json.loads(raw)
        stx, _, body2 = get_export(
            f"snapshot={a_max}&after=1&limit=2", headers=TA)
        check("filters 记录显式值且 digest 对应窗口",
              m2["filters"] == {"after": 1, "limit": 2}
              and m2["count"] == 2
              and m2["digest"] == hashlib.sha256(body2).hexdigest())

        # ---- 7. 验真外层 400：恰返 {"error": "请求非法"} -------------- #
        def expect_verify_400(name, **kwargs):
            stx, _, rawx = verify(**kwargs)
            try:
                rr = json.loads(rawx.decode() or "{}")
            except ValueError:
                rr = {}
            check(f"验真 400: {name}",
                  stx == 400 and rr == {"error": "请求非法"})

        ndjson_text = body.decode("utf-8")
        expect_verify_400("空对象", manifest=None, ndjson=None,
                          raw=b"{}")
        expect_verify_400("非法 JSON", raw=b"{")
        expect_verify_400("空体", raw=b"")
        expect_verify_400("多余字段", manifest=manifest,
                          ndjson=ndjson_text, raw=json.dumps(
                              {"manifest": manifest, "ndjson": ndjson_text,
                               "x": 1}).encode())
        expect_verify_400("缺 ndjson", raw=json.dumps(
            {"manifest": manifest}).encode())
        expect_verify_400("manifest 非对象", raw=json.dumps(
            {"manifest": [], "ndjson": ndjson_text}).encode())
        expect_verify_400("ndjson 非字符串", raw=json.dumps(
            {"manifest": manifest, "ndjson": 1}).encode())
        stx, _, rawx = verify(manifest, ndjson_text,
                              headers={"X-Tenant-ID": ""})
        check("验真显式空租户头 400 请求非法",
              stx == 400 and json.loads(rawx) == {"error": "请求非法"})

        # ---- 8. 验真原因顺序 ------------------------------------------ #
        def expect_invalid(name, m, n, reason, headers=None):
            stx, _, rawx = verify(m, n, headers=headers)
            rr = json.loads(rawx)
            check(name,
                  stx == 200 and rr == {"valid": False, "reason": reason})

        # 无锚点：先 锚点不可用
        expect_invalid("无锚点 -> 锚点不可用",
                       manifest, ndjson_text, "锚点不可用", headers=TA)

        # 注册 generic 锚点后验真成功
        st, _, raw = _http("POST", f"{base}/v1/trust/anchors", {
            "did": signer_did, "public_key": signer_pub,
            "key_version": 1, "uses": ["generic"]}, TA)
        assert st == 201, raw
        stx, _, rawx = verify(manifest, ndjson_text, headers=TA)
        check("验真成功仅返回 valid:true",
              stx == 200 and json.loads(rawx) == {"valid": True})

        bad = dict(manifest)
        del bad["count"]
        expect_invalid("缺字段 -> 清单非法", bad, ndjson_text, "清单非法",
                       headers=TA)
        bad = dict(manifest)
        bad["filters"] = {"after": None}
        expect_invalid("filters 缺键 -> 清单非法", bad, ndjson_text,
                       "清单非法", headers=TA)
        bad = dict(manifest)
        bad["digest"] = "0" * 64
        expect_invalid("摘要被改 -> 签名校验失败", bad, ndjson_text,
                       "签名校验失败", headers=TA)
        bad = dict(manifest)
        bad["signature"] = "@@@"
        expect_invalid("签名乱码 -> 签名格式错误", bad, ndjson_text,
                       "签名格式错误", headers=TA)
        bad = dict(manifest)
        flipped = "A" if manifest["signature"][10] != "A" else "B"
        bad["signature"] = (manifest["signature"][:10] + flipped
                            + manifest["signature"][11:])
        expect_invalid("签名被替换 -> 签名校验失败", bad, ndjson_text,
                       "签名校验失败", headers=TA)
        tampered = ndjson_text[:5] + "X" + ndjson_text[6:]
        expect_invalid("内容被篡改 -> 导出内容不匹配",
                       manifest, tampered, "导出内容不匹配", headers=TA)
        expect_invalid("行数不符 -> 导出内容不匹配",
                       manifest, ndjson_text + ndjson_text.splitlines()[0]
                       + "\n", "导出内容不匹配", headers=TA)
        expect_invalid("跨租户验真 -> 锚点不可用",
                       manifest, ndjson_text, "锚点不可用", headers=TB)

        # 验真只读：不写审计
        _, _, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        n_before = len(json.loads(raw)["events"])
        verify(manifest, ndjson_text, headers=TA)
        _, _, raw = _http("GET", f"{base}/v1/audit?limit=200", headers=TA)
        check("验真不记审计",
              len(json.loads(raw)["events"]) == n_before)

        # ---- 9. 重启后导出与验真结论稳定 ------------------------------ #
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc = subprocess.Popen(
            [sys.executable, "-m", "vcbackend.cli", "serve",
             "--port", str(port), "--host", "127.0.0.1"],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert wait_up(port), "服务重启超时"
        stx, hdrs, body3 = get_export(
            f"snapshot={a_max}&limit=2", headers=TA)
        check("重启后同页导出字节一致",
              stx == 200 and body3 == b"".join(
                  line + b"\n" for line in page1))
        stx, _, rawx = verify(manifest, ndjson_text, headers=TA)
        check("重启后验真结论不变",
              stx == 200 and json.loads(rawx) == {"valid": True})

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(store):
            os.remove(store)

    print()
    if failures:
        print(f"{len(failures)} 项失败:", failures)
        return 1
    print("审计快照导出测试全部通过 ✔")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
