#!/usr/bin/env python3
"""签发幂等键（Idempotency-Key）能力的端到端测试。

覆盖：
- 头格式校验：空值、非法字符、超长、重复提供均 400；键区分大小写；
  未提供该头时每次签发 201 生成新凭证（既有行为不变）；
- 首次成功 201 并绑定键；同租户同键同内容重放 200，credential_id、
  signature、issuer_key_version 与首次完全一致，不新增凭证或审计事件；
- 内容比较：忽略 JSON 空白与递归对象键顺序，保留数组次序与字段是否
  出现；字符串/布尔/数字/null 互不替代，1 与 1.0 视为相同数值；
- 已绑定键异内容统一 409（error 为“幂等键已绑定不同签发请求”），
  不覆盖首次绑定；绑定按租户隔离，同键跨租户独立使用；
- 只有成功签发才占用键：400/404/409 失败后可用同键提交修正请求；
- 重放不受签发者轮换/停用、模式弃用/吊销、凭证吊销影响，仍返回首次
  结果且不恢复凭证状态、不改变验真结论；
- 绑定跨服务重启保留；旧状态文件不为历史凭证补造绑定；
- 冲突、重放与失败均不推进审计序号；幂等键不写入凭证正文或公开响应。

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


def _http_raw(port, path, raw_body, headers):
    """底层 POST：支持重复请求头。返回 (status, 解析后的 JSON)。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(
            "POST", path, body=raw_body,
            headers={"Content-Type": "application/json", **headers},
        )
        resp = conn.getresponse()
        body = resp.read().decode() or "{}"
        return resp.status, json.loads(body)
    finally:
        conn.close()


def _http_dup_key(port, path, payload, keys, tenant=None):
    """以重复 Idempotency-Key 头发送请求。"""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.putrequest("POST", path)
        conn.putheader("Content-Type", "application/json")
        if tenant is not None:
            conn.putheader("X-Tenant-ID", tenant)
        for key in keys:
            conn.putheader("Idempotency-Key", key)
        body = json.dumps(payload).encode()
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        resp = conn.getresponse()
        raw = resp.read().decode() or "{}"
        return resp.status, json.loads(raw)
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

    # 跨重启仍需重放的键与首签响应
    persist = {}

    try:
        assert wait_up(port), "服务启动超时"

        def register_did(headers, public_key):
            st, r = _http("POST", f"{base}/v1/dids",
                          {"method": "example", "public_key": public_key},
                          headers=headers)
            assert st == 201, f"注册 DID 失败: {st} {r}"
            return r["did"]

        issuer_a = register_did(TA, "idem-issuer-a")
        subject_a = register_did(TA, "idem-subject-a")
        issuer_b = register_did(TB, "idem-issuer-b")
        subject_b = register_did(TB, "idem-subject-b")
        issuer_d = register_did({}, "idem-issuer-d")  # 缺省 default 租户

        def issue(payload, headers=TA, key=None, raw=None):
            h = dict(headers)
            if key is not None:
                h["Idempotency-Key"] = key
            return _http("POST", f"{base}/v1/credentials", payload,
                         headers=h, raw=raw)

        def simple_payload(**overrides):
            p = {
                "issuer_did": issuer_a,
                "subject_did": subject_a,
                "claims": {"role": "admin", "level": 1},
            }
            p.update(overrides)
            return p

        audit_url = f"{base}/v1/audit?limit=200"

        def audit_count(headers=TA):
            st, r = _http("GET", audit_url, headers=headers)
            assert st == 200
            return len(r["events"])

        # ---------------------------------------------------------- #
        # 1. 未提供 Idempotency-Key：既有行为不变，每次 201 新凭证
        # ---------------------------------------------------------- #
        st, r1 = issue(simple_payload())
        check("无幂等键签发 -> 201", st == 201)
        check("签发响应恰为三字段",
              set(r1) == {"credential_id", "signature", "issuer_key_version"})
        st, r2 = issue(simple_payload())
        check("无幂等键重复提交仍 -> 201", st == 201)
        check("无幂等键每次生成新凭证",
              r2["credential_id"] != r1["credential_id"])

        # ---------------------------------------------------------- #
        # 2. 头格式校验：空值/非法字符/超长/重复提供 -> 400
        # ---------------------------------------------------------- #
        for label, key in [
            ("空值", ""),
            ("含空格", "bad key"),
            ("含感叹号", "bad!key"),
            ("含点号", "bad.key"),
            ("含斜杠", "bad/key"),
            ("非 ASCII", "café"),
            ("超长（65）", "a" * 65),
        ]:
            st, r = issue(simple_payload(), key=key)
            check(f"非法幂等键（{label}）-> 400",
                  st == 400 and isinstance(r.get("error"), str)
                  and r["error"])
        st, r = _http_dup_key(port, "/v1/credentials", simple_payload(),
                              ["dup-1", "dup-2"], tenant="idem-a")
        check("重复提供 Idempotency-Key -> 400", st == 400)
        # 边界长度与字符集合法
        for label, key in [("长度 1", "k"), ("长度 64", "K" * 64),
                           ("下划线连字符数字", "a_B-09")]:
            st, r = issue(simple_payload(), key=key)
            check(f"合法幂等键（{label}）-> 201", st == 201)
        # 键区分大小写：同内容不同大小写互不冲突
        st, r_low = issue(simple_payload(), key="casekey")
        check("小写键首签 -> 201", st == 201)
        st, r_up = issue(simple_payload(), key="CaseKey")
        check("大小写不同视为不同键 -> 201",
              st == 201 and r_up["credential_id"] != r_low["credential_id"])

        # ---------------------------------------------------------- #
        # 3. 首次 201 绑定；同内容重放 200 且结果逐字一致
        # ---------------------------------------------------------- #
        st, first = issue(simple_payload(), key="replay-1")
        check("首次使用键 -> 201", st == 201)
        cid = first["credential_id"]
        st, got = _http("GET", f"{base}/v1/credentials/{cid}", headers=TA)
        first_body = got["body"]
        n_audit = audit_count()
        for i in range(2):
            st, r = issue(simple_payload(), key="replay-1")
            check(f"同内容重放 #{i + 1} -> 200", st == 200)
            check("重放 credential_id 一致",
                  r["credential_id"] == first["credential_id"])
            check("重放 signature 一致",
                  r["signature"] == first["signature"])
            check("重放 issuer_key_version 一致",
                  r["issuer_key_version"] == first["issuer_key_version"])
        check("重放不新增审计事件", audit_count() == n_audit)
        st, got2 = _http("GET", f"{base}/v1/credentials/{cid}", headers=TA)
        check("重放不改变 issued_at",
              got2["body"]["issued_at"] == first_body["issued_at"])
        check("重放不产生新凭证（GET 仍为同一正文）",
              got2["body"] == first_body
              and got2["signature"] == got["signature"])
        persist["replay-1"] = first

        # ---------------------------------------------------------- #
        # 4. 内容比较规则
        # ---------------------------------------------------------- #
        # 4a. 忽略 JSON 空白与递归对象键顺序
        raw = (
            b'{ "claims": { "level": 1, "role": "admin" },'
            b'  "subject_did": "' + subject_a.encode() + b'",'
            b'\n\t"issuer_did": "' + issuer_a.encode() + b'" }'
        )
        st, r = issue(None, key="replay-1", raw=raw)
        check("键序/空白不同的同内容重放 -> 200",
              st == 200 and r["credential_id"] == first["credential_id"])
        # 4b. 1 与 1.0 视为相同数值
        st, r = issue(simple_payload(
            claims={"role": "admin", "level": 1.0}), key="replay-1")
        check("1 与 1.0 同值 -> 200 重放",
              st == 200 and r["credential_id"] == first["credential_id"])
        # 4c. 异内容统一 409 且 error 固定
        conflict_cases = [
            ("数组次序不同", {"claims": {"arr": [1, 2]}}),
            ("多一个字段", {"claims": {"role": "admin", "level": 1,
                                       "extra": 1}}),
            ("少一个字段", {"claims": {"role": "admin"}}),
            ("字符串替代数字", {"claims": {"role": "admin", "level": "1"}}),
            ("布尔替代数字", {"claims": {"role": "admin", "level": True}}),
            ("null 替代数字", {"claims": {"role": "admin", "level": None}}),
            ("数字不同", {"claims": {"role": "admin", "level": 2}}),
        ]
        for label, override in conflict_cases:
            st, r = issue(simple_payload(**override), key="replay-1")
            check(f"异内容（{label}）-> 409 固定原因",
                  st == 409 and r.get("error") == CONFLICT_MESSAGE)
        check("冲突不推进审计序号", audit_count() == n_audit)
        # 冲突不覆盖首次绑定：原内容仍重放 200
        st, r = issue(simple_payload(), key="replay-1")
        check("冲突后原内容仍重放 200（绑定未被覆盖）",
              st == 200 and r["credential_id"] == first["credential_id"])
        # 数组次序作为同内容的一部分：相同数组次序可绑定新键并重放
        st, arr_first = issue(
            simple_payload(claims={"arr": [1, 2]}), key="arr-key")
        check("含数组内容首签 -> 201", st == 201)
        st, r = issue(simple_payload(claims={"arr": [1, 2]}), key="arr-key")
        check("同数组次序重放 -> 200",
              st == 200 and r["credential_id"] == arr_first["credential_id"])
        st, r = issue(simple_payload(claims={"arr": [2, 1]}), key="arr-key")
        check("数组次序不同 -> 409",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)

        # ---------------------------------------------------------- #
        # 5. 租户隔离：同键跨租户独立绑定，互不泄露
        # ---------------------------------------------------------- #
        payload_b = {
            "issuer_did": issuer_b,
            "subject_did": subject_b,
            "claims": {"role": "admin", "level": 1},
        }
        st, first_b = issue(payload_b, headers=TB, key="replay-1")
        check("同键在他租户首签 -> 201", st == 201)
        check("他租户绑定独立（不同 credential_id）",
              first_b["credential_id"] != first["credential_id"])
        st, r = issue(payload_b, headers=TB, key="replay-1")
        check("他租户同内容重放 -> 200 本租户首次结果",
              st == 200 and r["credential_id"] == first_b["credential_id"])
        st, r = issue(simple_payload(), key="replay-1")
        check("本租户重放仍返回本租户首次结果",
              st == 200 and r["credential_id"] == first["credential_id"])
        # 缺省租户（default）与显式租户亦相互隔离
        st, r = issue({"issuer_did": issuer_d, "subject_did": issuer_d,
                       "claims": {"role": "admin", "level": 1}},
                      headers={}, key="replay-1")
        check("缺省租户同键首签 -> 201", st == 201)
        persist["replay-1-b"] = first_b

        # ---------------------------------------------------------- #
        # 6. 只有成功签发才占用键：失败后可同键修正重试
        # ---------------------------------------------------------- #
        # 6a. 400（未知 issuer_did）后同键修正 -> 201
        st, r = issue(simple_payload(issuer_did="did:example:nobody"),
                      key="retry-400")
        check("未绑定键签发失败 -> 400", st == 400)
        st, r = issue(simple_payload(), key="retry-400")
        check("400 后同键修正 -> 201", st == 201)
        # 6b. 404（模式不存在）后同键修正 -> 201
        st, r = issue(simple_payload(schema_id="nosuch", schema_version=1),
                      key="retry-404")
        check("未绑定键模式缺失 -> 404", st == 404)
        st, r = issue(simple_payload(), key="retry-404")
        check("404 后同键修正 -> 201", st == 201)
        # 6c. 409（显式引用已弃用模式版本）后同键修正 -> 201
        st, r = _http("POST", f"{base}/v1/credential-schemas", {
            "schema_id": "dep", "version": 1, "issuer_did": issuer_a,
            "claim_types": {"/role": "string"}, "required_claims": ["/role"],
        }, headers=TA)
        check("注册模式 -> 201", st == 201)
        st, r = _http("POST", f"{base}/v1/credential-schemas/dep/1/status",
                      {"issuer_did": issuer_a, "status": "deprecated"},
                      headers=TA)
        check("弃用模式 -> 201", st == 201)
        st, r = issue(simple_payload(schema_id="dep", schema_version=1),
                      key="retry-409")
        check("未绑定键引用弃用模式 -> 409", st == 409)
        st, r = issue(simple_payload(), key="retry-409")
        check("409 后同键修正 -> 201", st == 201)
        # 6d. 409（签发者已停用）后同键换用有效签发者 -> 201
        tmp_issuer = register_did(TA, "idem-tmp-issuer")
        st, r = _http("POST", f"{base}/v1/dids/{tmp_issuer}/deactivate",
                      {}, headers=TA)
        check("停用临时签发者 -> 200", st == 200)
        st, r = issue(simple_payload(issuer_did=tmp_issuer),
                      key="retry-deact")
        check("未绑定键签发者已停用 -> 409", st == 409)
        st, r = issue(simple_payload(), key="retry-deact")
        check("409（停用）后同键修正 -> 201", st == 201)
        # 6e. 请求体非 JSON 对象：带键时同样 400 且不占键
        st, r = issue(None, key="retry-json", raw=b"[1, 2]")
        check("带键请求体非 JSON 对象 -> 400", st == 400)
        st, r = issue(None, key="retry-json", raw=b"not-json")
        check("带键请求体非法 JSON -> 400", st == 400)
        st, r = issue(simple_payload(), key="retry-json")
        check("JSON 格式失败后同键修正 -> 201", st == 201)
        # 6f. 字段级校验失败（缺 claims）不占键
        st, r = issue({"issuer_did": issuer_a, "subject_did": subject_a},
                      key="retry-field")
        check("未绑定键缺字段 -> 400", st == 400)
        st, r = issue(simple_payload(), key="retry-field")
        check("字段校验失败后同键修正 -> 201", st == 201)

        # ---------------------------------------------------------- #
        # 7. 重放不受后续状态变化影响
        # ---------------------------------------------------------- #
        # 7a. 签发者密钥轮换后重放仍返回首次版本与签名
        st, rot_first = issue(simple_payload(), key="rotate-key")
        check("轮换前首签 -> 201", st == 201)
        st, r = _http("POST", f"{base}/v1/dids/{issuer_a}/keys/rotate",
                      {"key_handle": "rotated-1"}, headers=TA)
        check("轮换签发者密钥 -> 200", st == 200)
        st, r = issue(simple_payload(), key="rotate-key")
        check("轮换后重放 -> 200 首次结果",
              st == 200 and r == rot_first)
        check("重放不重新签名（issuer_key_version 保持首次值）",
              r["issuer_key_version"] == rot_first["issuer_key_version"])
        persist["rotate-key"] = rot_first
        # 7b. 凭证被吊销后重放仍返回首次结果，且不恢复凭证状态
        st, rev_first = issue(simple_payload(), key="revoke-key")
        check("吊销前首签 -> 201", st == 201)
        rev_cid = rev_first["credential_id"]
        st, r = _http("POST", f"{base}/v1/credentials/{rev_cid}/revoke",
                      {"reason": "违规"}, headers=TA)
        check("吊销凭证 -> 200", st == 200)
        st, r = issue(simple_payload(), key="revoke-key")
        check("吊销后重放 -> 200 首次结果", st == 200 and r == rev_first)
        st, got = _http("GET", f"{base}/v1/credentials/{rev_cid}",
                        headers=TA)
        st, r = _http("POST", f"{base}/v1/credentials/{rev_cid}/verify",
                      {"body": got["body"], "signature": got["signature"]},
                      headers=TA)
        check("重放不恢复凭证状态（验真仍为已吊销）",
              st == 200 and r.get("valid") is False
              and r.get("reason", "").startswith("凭证已吊销"))
        # 7c. 模式弃用后重放仍返回首次结果
        st, r = _http("POST", f"{base}/v1/credential-schemas", {
            "schema_id": "live", "version": 1, "issuer_did": issuer_a,
            "claim_types": {"/role": "string"}, "required_claims": ["/role"],
        }, headers=TA)
        check("注册新模式 -> 201", st == 201)
        st, sch_first = issue(
            simple_payload(claims={"role": "admin", "level": 1},
                           schema_id="live", schema_version=1),
            key="schema-key")
        check("模式绑定首签 -> 201", st == 201)
        st, r = _http("POST", f"{base}/v1/credential-schemas/live/1/status",
                      {"issuer_did": issuer_a, "status": "deprecated"},
                      headers=TA)
        check("弃用新模式 -> 201", st == 201)
        st, r = issue(
            simple_payload(claims={"role": "admin", "level": 1},
                           schema_id="live", schema_version=1),
            key="schema-key")
        check("模式弃用后重放 -> 200 首次结果", st == 200 and r == sch_first)
        persist["schema-key"] = sch_first
        # 7d. 签发者 DID 停用后重放仍返回首次结果
        st, deact_first = issue(simple_payload(), key="deact-key")
        check("停用前首签 -> 201", st == 201)
        st, r = _http("POST", f"{base}/v1/dids/{issuer_a}/deactivate",
                      {}, headers=TA)
        check("停用签发者 -> 200", st == 200)
        st, r = issue(simple_payload(), key="deact-key")
        check("签发者停用后重放 -> 200 首次结果",
              st == 200 and r == deact_first)
        persist["deact-key"] = deact_first

        # ---------------------------------------------------------- #
        # 8. 幂等键不泄露：正文、签名内容与公开查询响应均无键
        # ---------------------------------------------------------- #
        st, got = _http(
            "GET", f"{base}/v1/credentials/{deact_first['credential_id']}",
            headers=TA)
        check("凭证正文不含幂等键",
              all("deact-key" not in json.dumps(v, ensure_ascii=False)
                  for v in got["body"].values())
              and "idempotency_key" not in got["body"])
        check("签发/重放响应恰为三字段",
              set(deact_first) == {"credential_id", "signature",
                                   "issuer_key_version"})

    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 9. 跨重启：绑定保留，重放仍返回首次结果
    # -------------------------------------------------------------- #
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "服务重启超时"

        # 重启后同内容重放（内容需与首次一致，这里直接重放原负载）
        cases = [
            ("replay-1", TA, {
                "issuer_did": issuer_a, "subject_did": subject_a,
                "claims": {"role": "admin", "level": 1},
            }),
            ("rotate-key", TA, {
                "issuer_did": issuer_a, "subject_did": subject_a,
                "claims": {"role": "admin", "level": 1},
            }),
            ("deact-key", TA, {
                "issuer_did": issuer_a, "subject_did": subject_a,
                "claims": {"role": "admin", "level": 1},
            }),
            ("schema-key", TA, {
                "issuer_did": issuer_a, "subject_did": subject_a,
                "claims": {"role": "admin", "level": 1},
                "schema_id": "live", "schema_version": 1,
            }),
            ("replay-1", TB, {
                "issuer_did": issuer_b, "subject_did": subject_b,
                "claims": {"role": "admin", "level": 1},
            }),
        ]
        expect = {
            ("replay-1", "A"): persist["replay-1"],
            ("rotate-key", "A"): persist["rotate-key"],
            ("deact-key", "A"): persist["deact-key"],
            ("schema-key", "A"): persist["schema-key"],
            ("replay-1", "B"): persist["replay-1-b"],
        }
        for key, headers, payload in cases:
            tag = "A" if headers is TA else "B"
            h = dict(headers, **{"Idempotency-Key": key})
            st, r = _http("POST", f"{base}/v1/credentials", payload,
                          headers=h)
            first = expect[(key, tag)]
            check(f"重启后重放 {key}（租户 {tag}）-> 200 首次结果",
                  st == 200 and r == first)
        # 重启后异内容仍 409
        h = dict(TA, **{"Idempotency-Key": "replay-1"})
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": issuer_a, "subject_did": subject_a,
                       "claims": {"role": "root"}}, headers=h)
        check("重启后异内容 -> 409 固定原因",
              st == 409 and r.get("error") == CONFLICT_MESSAGE)
        # 重启后新键仍可首签
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": issuer_b, "subject_did": subject_b,
                       "claims": {"x": 1}}, headers=dict(
                          TB, **{"Idempotency-Key": "fresh-after-restart"}))
        check("重启后新键首签 -> 201", st == 201)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # -------------------------------------------------------------- #
    # 10. 旧状态文件不为历史凭证补造绑定
    # -------------------------------------------------------------- #
    legacy_store = tempfile.mktemp(suffix=".json")
    legacy_env = dict(os.environ, VCBACKEND_STORE=legacy_store)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=legacy_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "旧状态服务启动超时"
        st, r = _http("POST", f"{base}/v1/dids",
                      {"method": "example", "public_key": "legacy-i"},
                      headers=TA)
        legacy_issuer = r["did"]
        st, r = _http("POST", f"{base}/v1/credentials",
                      {"issuer_did": legacy_issuer,
                       "subject_did": legacy_issuer,
                       "claims": {"k": 1}}, headers=TA)
        check("旧状态无键签发 -> 201", st == 201)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    # 手工剥掉状态文件中的幂等键表，模拟旧版状态文件
    with open(legacy_store, encoding="utf-8") as fh:
        legacy_data = json.load(fh)
    for bucket in legacy_data.get("tenants", {}).values():
        bucket.pop("idempotency_keys", None)
    with open(legacy_store, "w", encoding="utf-8") as fh:
        json.dump(legacy_data, fh, ensure_ascii=False)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=legacy_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert wait_up(port), "旧状态服务重启超时"
        # 历史凭证没有绑定：任意键不会被误判为已绑定（同内容亦首签 201）
        h = dict(TA, **{"Idempotency-Key": "legacy-key"})
        st, r1 = _http("POST", f"{base}/v1/credentials",
                       {"issuer_did": legacy_issuer,
                        "subject_did": legacy_issuer,
                        "claims": {"k": 1}}, headers=h)
        check("旧状态加载后新键首签 -> 201", st == 201)
        st, r2 = _http("POST", f"{base}/v1/credentials",
                       {"issuer_did": legacy_issuer,
                        "subject_did": legacy_issuer,
                        "claims": {"k": 1}}, headers=h)
        check("旧状态加载后同键重放 -> 200",
              st == 200 and r2["credential_id"] == r1["credential_id"])
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
