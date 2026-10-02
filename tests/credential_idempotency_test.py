#!/usr/bin/env python3
"""POST /v1/credentials 按租户隔离的幂等重试（Idempotency-Key）端到端测试。

覆盖：
- Idempotency-Key 格式：空值、非法字符、超长、重复头均 400；1-64 个
  ASCII 字母/数字/下划线/连字符可用，键值区分大小写；未提供该头时
  保持原行为（每次签发新凭证 201）；
- 首次成功 201 并绑定键；同租户同键同内容重放 200，credential_id、
  signature、issuer_key_version 与首次完全一致，不重新签名、不改变
  issued_at、不新增凭证或审计事件；
- 内容比较：忽略 JSON 空白与递归对象键顺序，保留数组次序与字段是否
  出现，字符串/布尔/数字/null 互不替代，1 与 1.0 视为相同数值；
- 已绑定键的异内容统一 409（error 为“幂等键已绑定不同签发请求”），
  不覆盖首次绑定；请求体非合法 JSON 对象 400 且先于重放判定；
- 只有成功签发才占键：400/404/409 失败后可用同键提交修正请求；
- 重放不受签发者停用/轮换、凭证吊销/过期影响，仍返回首次结果，且不
  恢复凭证状态、不改变验真结论；
- 租户隔离：同键跨租户独立，任何响应不泄露他租户绑定；显式空
  X-Tenant-ID 400；
- 绑定跨服务重启保留；旧状态文件不为历史凭证补造绑定；
- 冲突、重放和失败均不推进审计序号；幂等键不写入凭证正文或公开查询
  响应。

直接运行：python3 tests/credential_idempotency_test.py
不依赖第三方测试框架，仅用标准库 + cryptography。
"""

import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CONFLICT_MESSAGE = "幂等键已绑定不同签发请求"


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
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def _http_raw_headers(port, path, payload, header_pairs):
    """以原始头列表（允许重复头）发送 POST，返回 (status, json)。"""
    body = json.dumps(payload).encode()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.putrequest("POST", path)
        for name, value in header_pairs:
            conn.putheader(name, value)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode() or "{}")
    finally:
        conn.close()


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def utc_z(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    port = 8962
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
    TA = {"X-Tenant-ID": "idem-a"}
    TB = {"X-Tenant-ID": "idem-b"}

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    def make_did(headers, public_key):
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": public_key},
                      headers=headers)
        assert st == 201, f"注册 DID 失败: {st} {r}"
        return r["did"]

    def issue(payload, headers=TA, key=None, raw=None):
        h = dict(headers)
        if key is not None:
            h["Idempotency-Key"] = key
        return _http("POST", f"{base}/v1/credentials", payload,
                     headers=h, raw=raw)

    def audit_count(headers):
        st, r = _http("GET", f"{base}/v1/audit?limit=200", headers=headers)
        assert st == 200
        return len(r["events"])

    # 跨重启仍需重放的键
    restart_case = {"key": "restart-key", "payload": None, "result": None}

    try:
        assert wait_up(port), "服务启动超时"

        issuer_a = make_did(TA, "issuer-idem-a")
        subject_a = make_did(TA, "subject-idem-a")
        issuer_b = make_did(TB, "issuer-idem-b")
        subject_b = make_did(TB, "subject-idem-b")

        def base_payload(n=1):
            return {
                "issuer_did": issuer_a,
                "subject_did": subject_a,
                "claims": {"role": "admin", "level": n},
            }

        # -------------------------------------------------------------- #
        # 1. Idempotency-Key 格式校验（400）
        # -------------------------------------------------------------- #
        st, r = issue(base_payload(), key="")
        check("空 Idempotency-Key -> 400", st == 400 and "error" in r)
        for label, bad in [("含空格", "abc def"), ("含点", "abc.def"),
                           ("含斜杠", "ab/c"), ("非 ASCII", "café"),
                           ("超长（65）", "a" * 65)]:
            st, r = issue(base_payload(), key=bad)
            check(f"非法键（{label}）-> 400", st == 400 and "error" in r)
        # 重复提供该头 -> 400
        st, r = _http_raw_headers(
            port, "/v1/credentials", base_payload(),
            [("X-Tenant-ID", "idem-a"),
             ("Idempotency-Key", "dup-key"),
             ("Idempotency-Key", "dup-key")],
        )
        check("重复 Idempotency-Key 头 -> 400", st == 400 and "error" in r)
        # 边界：1 与 64 字符可用
        st, r = issue(base_payload(), key="K")
        check("1 字符键 -> 201", st == 201)
        st, r = issue(base_payload(), key="k")
        check("键值区分大小写（K 与 k 各自独立）-> 201", st == 201)
        st, r = issue(base_payload(), key="a" * 64)
        check("64 字符键 -> 201", st == 201)
        st, r = issue(base_payload(), key="Az_09-x")
        check("字母/数字/下划线/连字符键 -> 201", st == 201)

        # -------------------------------------------------------------- #
        # 2. 未提供该头：保持原行为，每次签发新凭证
        # -------------------------------------------------------------- #
        st, r1 = issue(base_payload())
        st2, r2 = issue(base_payload())
        check("无幂等键两次签发均 201", st == 201 and st2 == 201)
        check("无幂等键每次生成新凭证",
              r1["credential_id"] != r2["credential_id"])

        # -------------------------------------------------------------- #
        # 3. 首次 201 绑定；同内容重放 200 且结果完全一致
        # -------------------------------------------------------------- #
        payload = base_payload()
        st, first = issue(payload, key="replay-1")
        check("首次使用键 -> 201", st == 201)
        check("签发响应字段保持原样",
              set(first) == {"credential_id", "signature",
                             "issuer_key_version"})
        n_audit = audit_count(TA)
        st, replay = issue(payload, key="replay-1")
        check("同内容重放 -> 200", st == 200)
        check("重放结果与首次完全一致", replay == first)
        # 忽略 JSON 空白与递归对象键顺序（原始报文重排）
        raw = (
            '{  "claims" : { "level": 1, "role": "admin" },'
            ' "subject_did": "%s", "issuer_did": "%s" }'
            % (subject_a, issuer_a)
        ).encode()
        st, replay2 = issue(None, key="replay-1", raw=raw)
        check("键序/空白不同的同内容重放 -> 200 且一致",
              st == 200 and replay2 == first)
        # issued_at 未改变、未新增凭证
        st, got = _http("GET",
                        f"{base}/v1/credentials/{first['credential_id']}",
                        headers=TA)
        check("重放后 GET 正文 issued_at 不变",
              st == 200 and isinstance(got["body"].get("issued_at"), str))
        check("幂等键不写入凭证正文",
              all("Idempotency" not in k and "idempotency" not in k
                  for k in got["body"]))
        check("重放不推进审计序号", audit_count(TA) == n_audit)

        # -------------------------------------------------------------- #
        # 4. 内容比较语义
        # -------------------------------------------------------------- #
        # 1 与 1.0 视为相同数值
        p_int = dict(base_payload(), claims={"n": 1})
        st, r1 = issue(p_int, key="num-1")
        check("数值键首次 -> 201", st == 201)
        st, r2 = issue(dict(base_payload(), claims={"n": 1.0}), key="num-1")
        check("1 与 1.0 视为相同 -> 200 重放", st == 200 and r2 == r1)
        # 字符串不能替代数字
        st, r = issue(dict(base_payload(), claims={"n": "1"}), key="num-1")
        check("字符串 \"1\" 不能替代 1 -> 409",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)
        # 布尔不能替代数字
        st, r = issue(dict(base_payload(), claims={"n": True}), key="num-1")
        check("true 不能替代 1 -> 409",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)
        # null 不能替代缺省/其他类型
        st, r1 = issue(dict(base_payload(), claims={"n": None}), key="null-1")
        check("null 首次 -> 201", st == 201)
        st, r = issue(dict(base_payload(), claims={}), key="null-1")
        check("字段是否出现参与比较（缺省 vs null）-> 409",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)
        st, r = issue(dict(base_payload(), claims={"n": 0}), key="null-1")
        check("null 与 0 互不替代 -> 409",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)
        # 数组次序保留
        st, r1 = issue(dict(base_payload(), claims={"a": [1, 2]}), key="arr-1")
        check("数组首次 -> 201", st == 201)
        st, r = issue(dict(base_payload(), claims={"a": [2, 1]}), key="arr-1")
        check("数组次序不同 -> 409",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)
        st, r = issue(dict(base_payload(), claims={"a": [1, 2]}), key="arr-1")
        check("数组次序相同 -> 200 重放", st == 200 and r == r1)
        # 嵌套对象键序忽略
        st, r1 = issue(dict(base_payload(), claims={"o": {"x": 1, "y": 2}}),
                       key="nest-1")
        check("嵌套对象首次 -> 201", st == 201)
        st, r = issue(dict(base_payload(), claims={"o": {"y": 2, "x": 1}}),
                      key="nest-1")
        check("嵌套对象键序忽略 -> 200 重放", st == 200 and r == r1)
        # 冲突不覆盖首次绑定：原内容重放仍 200
        st, r = issue(p_int, key="num-1")
        check("409 后首次绑定未被覆盖", st == 200 and r == issue(
            dict(base_payload(), claims={"n": 1}), key="num-1")[1])

        # -------------------------------------------------------------- #
        # 5. 校验顺序：租户头/键/JSON 对象格式先于重放判定
        # -------------------------------------------------------------- #
        st, r = _http("POST", f"{base}/v1/credentials", base_payload(),
                      headers={"X-Tenant-ID": "", "Idempotency-Key": "replay-1"})
        check("显式空 X-Tenant-ID -> 400", st == 400 and "error" in r)
        st, r = _http("POST", f"{base}/v1/credentials", None,
                      headers={**TA, "Idempotency-Key": "replay-1"},
                      raw=b"[1, 2]")
        check("请求体非 JSON 对象（数组）-> 400", st == 400 and "error" in r)
        st, r = _http("POST", f"{base}/v1/credentials", None,
                      headers={**TA, "Idempotency-Key": "replay-1"},
                      raw=b"not-json{")
        check("请求体非法 JSON -> 400", st == 400 and "error" in r)
        st, r = _http("POST", f"{base}/v1/credentials", None,
                      headers={**TA, "Idempotency-Key": "replay-1"},
                      raw=b"")
        check("空请求体 -> 400", st == 400 and "error" in r)
        # 非法键即使内容可重放也先 400
        st, r = issue(base_payload(), key="bad key!")
        check("非法键先于重放判定 -> 400", st == 400)

        # -------------------------------------------------------------- #
        # 6. 只有成功签发才占键：失败后可同键修正重试
        # -------------------------------------------------------------- #
        bad = {"issuer_did": issuer_a,
               "subject_did": "did:example:missing",
               "claims": {"k": 1}}
        n_audit = audit_count(TA)
        st, r = issue(bad, key="retry-1")
        check("未知 subject_did -> 400", st == 400)
        st, r = issue({"issuer_did": issuer_a}, key="retry-1")
        check("缺字段 -> 400", st == 400)
        st, r = issue(dict(base_payload(), expires_at="2000-01-01T00:00:00Z"),
                      key="retry-1")
        check("非法 expires_at -> 400", st == 400)
        check("失败不推进审计序号", audit_count(TA) == n_audit)
        st, r1 = issue(base_payload(), key="retry-1")
        check("失败后同键修正重试 -> 201 首次签发", st == 201)
        st, r2 = issue(base_payload(), key="retry-1")
        check("修正后的键可正常重放 -> 200", st == 200 and r2 == r1)

        # -------------------------------------------------------------- #
        # 7. 租户隔离：同键跨租户独立，互不泄露
        # -------------------------------------------------------------- #
        payload_b = {"issuer_did": issuer_b, "subject_did": subject_b,
                     "claims": {"role": "admin", "level": 1}}
        st, rb1 = issue(payload_b, headers=TB, key="replay-1")
        check("同键在他租户首次使用 -> 201", st == 201)
        check("跨租户绑定相互独立",
              rb1["credential_id"] != first["credential_id"])
        st, rb2 = issue(payload_b, headers=TB, key="replay-1")
        check("他租户同内容重放 -> 200 且一致", st == 200 and rb2 == rb1)
        st, r = issue(payload, key="replay-1")
        check("本租户重放不受他租户影响", st == 200 and r == first)
        # 缺省 default 租户：同键亦独立
        st, rd = _http("POST", f"{base}/v1/credentials", payload,
                       headers={"Idempotency-Key": "replay-1"})
        check("default 租户无该 DID -> 400（不泄露他租户绑定）", st == 400)

        # -------------------------------------------------------------- #
        # 8. 重放不受签发者/凭证状态变化影响，且不改变验真结论
        # -------------------------------------------------------------- #
        st, r1 = issue(base_payload(7), key="state-1")
        check("状态用例首次 -> 201", st == 201)
        cid = r1["credential_id"]
        st, got = _http("GET", f"{base}/v1/credentials/{cid}", headers=TA)
        body, sig = got["body"], got["signature"]
        # 吊销凭证后重放仍返回首次结果
        st, _ = _http("POST", f"{base}/v1/credentials/{cid}/revoke",
                      {"reason": "违规"}, headers=TA)
        check("吊销凭证 -> 200", st == 200)
        st, r2 = issue(base_payload(7), key="state-1")
        check("凭证吊销后同内容重放 -> 200 首次结果", st == 200 and r2 == r1)
        st, r = _http("POST", f"{base}/v1/credentials/{cid}/verify",
                      {"body": body, "signature": sig}, headers=TA)
        check("重放不恢复凭证状态（验真仍判吊销）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证已吊销"))
        # 签发者停用后重放仍返回首次结果
        issuer_c = make_did(TA, "issuer-idem-c")
        subject_c = make_did(TA, "subject-idem-c")
        payload_c = {"issuer_did": issuer_c, "subject_did": subject_c,
                     "claims": {"k": "v"}}
        st, rc1 = issue(payload_c, key="state-2")
        check("停用用例首次 -> 201", st == 201)
        st, _ = _http("POST", f"{base}/v1/dids/{issuer_c}/deactivate",
                      {"reason": "测试"}, headers=TA)
        check("停用签发者 -> 200", st == 200)
        st, r = issue(payload_c, key="state-2-new")
        check("停用后新键签发 -> 409", st == 409)
        st, rc2 = issue(payload_c, key="state-2")
        check("签发者停用后同内容重放 -> 200 首次结果",
              st == 200 and rc2 == rc1)

        # -------------------------------------------------------------- #
        # 9. 过期凭证的重放仍返回首次结果
        # -------------------------------------------------------------- #
        soon = utc_z(datetime.now(timezone.utc) + timedelta(seconds=3))
        payload_exp = dict(base_payload(), expires_at=soon)
        st, re1 = issue(payload_exp, key="exp-1")
        check("短期凭证首次 -> 201", st == 201)
        time.sleep(4)
        st, re2 = issue(payload_exp, key="exp-1")
        check("凭证过期后同内容重放 -> 200 首次结果",
              st == 200 and re2 == re1)
        st, got = _http("GET",
                        f"{base}/v1/credentials/{re1['credential_id']}",
                        headers=TA)
        st, r = _http("POST",
                      f"{base}/v1/credentials/{re1['credential_id']}/verify",
                      {"body": got["body"], "signature": got["signature"]},
                      headers=TA)
        check("重放不改变验真结论（已过期）",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "凭证已过期")

        # -------------------------------------------------------------- #
        # 10. 跨重启重放用例
        # -------------------------------------------------------------- #
        restart_case["payload"] = base_payload(99)
        st, r1 = issue(restart_case["payload"], key=restart_case["key"])
        check("重启用例首次 -> 201", st == 201)
        restart_case["result"] = r1
        st, r2 = issue(restart_case["payload"], key=restart_case["key"])
        check("重启前重放 -> 200", st == 200 and r2 == r1)

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 11. 重启后：绑定保留，重放仍返回首次结果
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"
        st, r = _http("POST", f"{base}/v1/credentials",
                      restart_case["payload"],
                      headers={**TA, "Idempotency-Key": restart_case["key"]})
        check("重启后同内容重放 -> 200 且与首次一致",
              st == 200 and r == restart_case["result"])
        st, r2 = _http(
            "POST", f"{base}/v1/credentials",
            dict(restart_case["payload"], claims={"role": "admin",
                                                  "level": 100}),
            headers={**TA, "Idempotency-Key": restart_case["key"]})
        check("重启后异内容 -> 409",
              st == 409 and r2.get("error") == CONFLICT_MESSAGE)
        # 旧状态文件不为历史凭证补造绑定：无键签发的凭证不占用任何键，
        # 用新键提交相同内容属于首次绑定（201 新凭证）。
        st, r = _http("POST", f"{base}/v1/credentials",
                      restart_case["payload"],
                      headers={**TA, "Idempotency-Key": "fresh-after-restart"})
        check("新键提交已存在内容 -> 201 首次签发（不补造绑定）", st == 201)
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
