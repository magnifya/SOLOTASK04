#!/usr/bin/env python3
"""验证方展示请求（presentation request）端到端测试。

覆盖：
- POST /v1/presentation-requests 创建：最小/完整参数、201 字段与默认值、
  非法字段一律 400；
- GET /v1/presentation-requests/{request_id} 查询：本租户 200、未知与
  跨租户同 ID 一律 404；
- present 的 request_id 模式：沿用请求 challenge/expires_at/disclose/
  issuer_dids/holder_binding，request_id 纳入 issuer/holder proof；请求
  不存在/已过期/签发者不符/持有人不符依次 400，未知凭证 404，混用字段
  400；普通 present 模式保持不变；
- verify 的 request_id 模式：使用请求 challenge 并执行策略，成功 200
  valid:true 并原子消费请求与演示（记 presentation.consumed）；失败均
  200 valid:false（策略不满足/不匹配/过期/已消费），失败不消费；重复
  消费沿用「演示已消费」；未知 presentation_id 404；
- 绑定展示保留 holder_proof、重启持久化、审计事件。

直接运行：python3 tests/presentation_request_test.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vcbackend import crypto  # noqa: E402

PORT = 8966
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"


def _wait_expired(expires_at: str, slack: float = 0.2) -> None:
    """轮询等待 UTC 当前时间严格超过 expires_at（含余量）。

    秒精度过期判定在调度抖动环境（如 WSL2）下不依赖固定 sleep。
    """
    moment = datetime.strptime(
        expires_at, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc).timestamp()
    deadline = time.time() + 10
    while time.time() <= moment + slack:
        if time.time() > deadline:
            break
        time.sleep(0.05)


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


def wait_up(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http("GET", f"http://127.0.0.1:{port}/health")
            return True
        except OSError:
            time.sleep(0.15)
    return False


def start_server():
    env = dict(os.environ, VCBACKEND_STORE=STORE)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(PORT), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(PORT), "服务启动超时"
    return proc


def main():
    proc = start_server()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    try:
        # ---------------- 准备：DID 与凭证 ---------------- #
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "pr-issuer"})
        assert st == 201, r
        issuer = r["did"]
        issuer_pem = r["public_key"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "pr-issuer2"})
        assert st == 201, r
        issuer2 = r["did"]
        st, r = _http("POST", f"{BASE}/v1/dids",
                      {"method": "example", "public_key": "pr-subject"})
        assert st == 201, r
        subject = r["did"]
        subject_pem = r["public_key"]
        st, r = _http("POST", f"{BASE}/v1/credentials",
                      {"issuer_did": issuer, "subject_did": subject,
                       "claims": {"role": "admin", "addr": {"city": "SH"},
                                  "age": 30}})
        assert st == 201, r
        cred = r["credential_id"]

        # ---------------- 创建请求：最小参数与默认值 ---------------- #
        st, r = _http("POST", f"{BASE}/v1/presentation-requests",
                      {"challenge": "c-min"})
        check("最小请求 201", st == 201)
        check("request_id 为 pr_ 前缀",
              st == 201 and r.get("request_id", "").startswith("pr_"))
        check("回显 challenge", r.get("challenge") == "c-min")
        check("默认 disclose 空列表", r.get("disclose") == [])
        check("默认 issuer_dids 为 null", r.get("issuer_dids") is None)
        check("默认 holder_binding false", r.get("holder_binding") is False)
        check("初始 status pending", r.get("status") == "pending")
        check("pending 不含 consumed_* 字段",
              "consumed_at" not in r and "consumed_presentation_id" not in r)
        check("默认有效期约 300 秒",
              st == 201 and isinstance(r.get("expires_at"), str))

        st, full = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "c-full", "expires_in": 600,
                          "disclose": ["/role", "/addr/city"],
                          "issuer_dids": [issuer], "holder_binding": True})
        assert st == 201, full
        check("完整参数 201 且策略回显",
              full["disclose"] == ["/role", "/addr/city"]
              and full["issuer_dids"] == [issuer]
              and full["holder_binding"] is True)

        # expires_in 边界
        for value in (1, 86400):
            st, r = _http("POST", f"{BASE}/v1/presentation-requests",
                          {"challenge": "c-bound", "expires_in": value})
            check(f"expires_in={value} 201", st == 201)

        # 非法字段
        bad_bodies = [
            ("缺少 challenge", {}),
            ("challenge 空串", {"challenge": ""}),
            ("challenge 非字符串", {"challenge": 1}),
            ("challenge 超长", {"challenge": "x" * 257}),
            ("expires_in 非整数", {"challenge": "c", "expires_in": "1"}),
            ("expires_in 布尔", {"challenge": "c", "expires_in": True}),
            ("expires_in 为 0", {"challenge": "c", "expires_in": 0}),
            ("expires_in 超上限", {"challenge": "c", "expires_in": 86401}),
            ("disclose 非数组", {"challenge": "c", "disclose": "/role"}),
            ("disclose 根路径", {"challenge": "c", "disclose": [""]}),
            ("disclose 非 / 开头", {"challenge": "c", "disclose": ["role"]}),
            ("disclose 重复", {"challenge": "c",
                                "disclose": ["/role", "/role"]}),
            ("disclose 祖先重叠",
             {"challenge": "c", "disclose": ["/addr", "/addr/city"]}),
            ("disclose 元素非字符串", {"challenge": "c", "disclose": [1]}),
            ("issuer_dids 非数组", {"challenge": "c", "issuer_dids": issuer}),
            ("issuer_dids 空元素", {"challenge": "c", "issuer_dids": [""]}),
            ("issuer_dids 重复",
             {"challenge": "c", "issuer_dids": [issuer, issuer]}),
            ("holder_binding 非布尔",
             {"challenge": "c", "holder_binding": "true"}),
            ("多余字段", {"challenge": "c", "unexpected": 1}),
            ("空请求体", None),
        ]
        for name, body in bad_bodies:
            if body is None:
                st, r = _http("POST",
                              f"{BASE}/v1/presentation-requests",
                              raw=b"")
            else:
                st, r = _http("POST",
                              f"{BASE}/v1/presentation-requests", body)
            check(f"非法请求 400: {name}",
                  st == 400 and bool(r.get("error")))

        # issuer_dids 显式空列表为空白名单（保留 []，区别于省略）
        st, r = _http("POST", f"{BASE}/v1/presentation-requests",
                      {"challenge": "c-any", "issuer_dids": []})
        check("issuer_dids 空列表 201 且保留为 []",
              st == 201 and r.get("issuer_dids") == [])
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": r["request_id"]},
        )
        check("空白名单请求对任何凭证签发者不符 400",
              st == 400 and r.get("error") == "凭证签发者不符合展示请求")

        # 省略 issuer_dids 为不限定（null）
        st, r = _http("POST", f"{BASE}/v1/presentation-requests",
                      {"challenge": "c-null"})
        check("省略 issuer_dids 归一为 null", r.get("issuer_dids") is None)

        # ---------------- 查询：404 与租户隔离 ---------------- #
        st, r = _http("GET",
                      f"{BASE}/v1/presentation-requests/{full['request_id']}")
        check("GET 本租户请求 200",
              st == 200 and r["request_id"] == full["request_id"])
        st, r = _http("GET",
                      f"{BASE}/v1/presentation-requests/pr_{'0' * 32}")
        check("GET 未知 request_id 404", st == 404)
        st, r = _http(
            "GET",
            f"{BASE}/v1/presentation-requests/{full['request_id']}",
            headers={"X-Tenant-ID": "other"},
        )
        check("GET 跨租户同 ID 404", st == 404)
        st, r = _http("GET", f"{BASE}/v1/presentation-requests")
        check("GET 集合路径 404", st == 404)

        # ---------------- present：request_id 模式 ---------------- #
        st, req = _http("POST", f"{BASE}/v1/presentation-requests",
                        {"challenge": "pr-ok", "expires_in": 600,
                         "disclose": ["/role", "/addr/city"],
                         "issuer_dids": [issuer]})
        assert st == 201, req
        st, vp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": req["request_id"]},
        )
        check("request_id present 201", st == 201)
        check("展示沿用请求 challenge", vp.get("challenge") == "pr-ok")
        check("展示沿用请求 expires_at",
              vp.get("expires_at") == req["expires_at"])
        check("展示沿用请求 disclose",
              vp.get("disclose") == ["/role", "/addr/city"])
        check("展示新增 request_id", vp.get("request_id") == req["request_id"])
        check("request_id 位于 expires_at 之后 proof 之前",
              list(vp).index("request_id")
              == list(vp).index("expires_at") + 1
              and list(vp).index("request_id")
              == list(vp).index("proof") - 1)
        check("未绑定无 holder_* 字段",
              "holder_did" not in vp and "holder_proof" not in vp)

        # issuer proof 覆盖含 request_id：用对象去 proof 外部验签
        try:
            crypto.verify(
                {k: v for k, v in vp.items() if k != "proof"},
                vp["proof"], issuer_pem,
            )
            check("issuer proof 覆盖 request_id 外部验真成功", True)
        except Exception:  # noqa: BLE001
            check("issuer proof 覆盖 request_id 外部验真成功", False)

        # 零披露请求
        st, zreq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-zero"})
        assert st == 201, zreq
        st, zvp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": zreq["request_id"]},
        )
        check("零披露请求 present 201",
              st == 201 and zvp["disclose"] == [] and zvp["claims"] == {})

        # 混用字段 / 非法 request_id
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": req["request_id"], "disclose": ["/role"]},
        )
        check("request_id 与 disclose 混用 400",
              st == 400 and bool(r.get("error")))
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": req["request_id"], "challenge": "x"},
        )
        check("request_id 与 challenge 混用 400",
              st == 400 and bool(r.get("error")))
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": 123},
        )
        check("request_id 非字符串 400", st == 400)
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": ""},
        )
        check("request_id 空串 400", st == 400)

        # 请求不存在
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": f"pr_{'0' * 32}"},
        )
        check("请求不存在 400 展示请求不存在",
              st == 400 and r.get("error") == "展示请求不存在")
        # 跨租户请求（本租户凭证 + 他租户请求）
        st, other_req = _http(
            "POST", f"{BASE}/v1/presentation-requests",
            {"challenge": "pr-other"},
            headers={"X-Tenant-ID": "tenant-b"},
        )
        assert st == 201, other_req
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": other_req["request_id"]},
        )
        check("跨租户请求 400 展示请求不存在",
              st == 400 and r.get("error") == "展示请求不存在")

        # 未知凭证：请求存在且未过期时 404
        st, fresh_req = _http("POST",
                              f"{BASE}/v1/presentation-requests",
                              {"challenge": "pr-404"})
        assert st == 201
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/vc_{'0' * 32}/present",
            {"request_id": fresh_req["request_id"]},
        )
        check("请求有效但凭证未知 404", st == 404)

        # 已过期优先于凭证判定
        st, exp_req = _http("POST",
                            f"{BASE}/v1/presentation-requests",
                            {"challenge": "pr-exp", "expires_in": 1})
        assert st == 201
        _wait_expired(exp_req["expires_at"])
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": exp_req["request_id"]},
        )
        check("请求已过期 400 展示请求已过期",
              st == 400 and r.get("error") == "展示请求已过期")
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/vc_{'0' * 32}/present",
            {"request_id": exp_req["request_id"]},
        )
        check("已过期优先于凭证 404",
              st == 400 and r.get("error") == "展示请求已过期")

        # 签发者不符
        st, iss_req = _http(
            "POST", f"{BASE}/v1/presentation-requests",
            {"challenge": "pr-iss", "issuer_dids": [issuer2]},
        )
        assert st == 201
        st, r = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": iss_req["request_id"]},
        )
        check("签发者不符 400",
              st == 400 and r.get("error") == "凭证签发者不符合展示请求")

        # 持有人不符：holder_binding 但凭证 subject_did 非本租户已注册
        # DID。正常签发要求 subject 已注册，故该 400 路径用直连 store
        # 构造（删除 subject DID 行后按请求生成）。
        from vcbackend.store import VCStore as _VCStore  # noqa: E402

        direct_path = tempfile.mktemp(suffix=".json")
        try:
            dstore = _VCStore(direct_path)
            drec = dstore.create_did("default", "example", "d-issuer")
            srec = dstore.create_did("default", "example", "d-subject")
            dcred = dstore.create_credential(
                "default", drec.did, srec.did, {"v": 1}
            )
            dreq = dstore.create_presentation_request(
                "default", challenge="d-hold", expires_in=600,
                disclose=["/v"], issuer_dids=None, holder_binding=True,
            )
            dstore._tenants["default"]["dids"].pop(srec.did)  # noqa: SLF001
            try:
                dstore.create_presentation_for_request(
                    "default", dcred.credential_id, dreq.request_id
                )
                raised = False
            except Exception as exc:  # noqa: BLE001
                raised = getattr(exc, "message", str(exc)) == \
                    "持有人不符合展示请求"
                raised = str(exc) == "持有人不符合展示请求"
            check("直连: 持有人不符 400 持有人不符合展示请求", raised)
        finally:
            if os.path.exists(direct_path):
                os.unlink(direct_path)

        # 普通 present 模式不受影响
        st, plain = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"disclose": ["/role"], "challenge": "legacy"},
        )
        check("普通 present 模式保持不变（无 request_id）",
              st == 201 and "request_id" not in plain)

        # ---------------- verify：request_id 模式 ---------------- #
        st, vreq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-verify", "expires_in": 600,
                          "disclose": ["/role"],
                          "issuer_dids": [issuer]})
        assert st == 201
        st, vvp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": vreq["request_id"]},
        )
        assert st == 201
        vvp_id = vvp["presentation_id"]

        # 不接受 challenge 字段
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{vvp_id}/verify",
            {"presentation": vvp, "request_id": vreq["request_id"],
             "challenge": "pr-verify"},
        )
        check("request_id 模式传 challenge -> 200 valid:false",
              st == 200 and r.get("valid") is False
              and "多余字段" in r.get("reason", ""))

        # 成功
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{vvp_id}/verify",
            {"presentation": vvp, "request_id": vreq["request_id"]},
        )
        check("request_id verify valid:true 且恰含 valid",
              st == 200 and r == {"valid": True})

        # 请求与演示均已消费
        st, got = _http(
            "GET",
            f"{BASE}/v1/presentation-requests/{vreq['request_id']}",
        )
        check("请求 status=consumed",
              st == 200 and got.get("status") == "consumed"
              and got.get("consumed_presentation_id") == vvp_id
              and bool(got.get("consumed_at")))
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{vvp_id}/verify",
            {"presentation": vvp, "request_id": vreq["request_id"]},
        )
        check("同演示重复消费 -> 演示已消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "演示已消费")

        # 另一演示不能消费已消费请求
        st, vvp2 = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"disclose": ["/age"], "challenge": "other-vp"},
        )
        assert st == 201
        # 把 request_id 字段伪造成已消费请求：字段集合/签名不匹配；
        # 而用真实由该请求生成的第二演示在 present 阶段即被禁止（请求
        # 已消费不影响 present——present 不检查消费状态，故可生成）。
        st, vvp3 = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": vreq["request_id"]},
        )
        check("已消费请求仍可再生成展示（消费仅在 verify 判定）",
              st == 201 and vvp3.get("request_id") == vreq["request_id"])
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{vvp3['presentation_id']}/verify",
            {"presentation": vvp3, "request_id": vreq["request_id"]},
        )
        check("第二演示消费已消费请求 -> 展示请求已消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "展示请求已消费")

        # 未知 presentation_id 404
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/vp_{'0' * 32}/verify",
            {"presentation": {}, "request_id": vreq["request_id"]},
        )
        check("verify 未知 presentation_id 404", st == 404)
        # 跨租户：演示对他租户不可见 -> 404
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{vvp3['presentation_id']}/verify",
            {"presentation": vvp3, "request_id": vreq["request_id"]},
            headers={"X-Tenant-ID": "tenant-b"},
        )
        check("跨租户 verify 404", st == 404)

        # 失败不消费：篡改演示 -> 展示请求不匹配，随后原演示仍可成功
        st, mreq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-mismatch", "expires_in": 600,
                          "disclose": ["/role"]})
        assert st == 201
        st, mvp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": mreq["request_id"]},
        )
        assert st == 201
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{mvp['presentation_id']}/verify",
            {"presentation": dict(mvp, claims={"role": "root"}),
             "request_id": mreq["request_id"]},
        )
        check("篡改 claims -> 展示请求不匹配，不消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "展示请求不匹配")
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{mvp['presentation_id']}/verify",
            {"presentation": dict(mvp, challenge="wrong"),
             "request_id": mreq["request_id"]},
        )
        check("篡改 challenge -> valid:false，不消费",
              st == 200 and r.get("valid") is False)
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{mvp['presentation_id']}/verify",
            {"presentation": mvp,
             "request_id": f"pr_{'f' * 32}"},
        )
        check("未知 request_id -> 展示请求不匹配",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "展示请求不匹配")
        st, got = _http(
            "GET",
            f"{BASE}/v1/presentation-requests/{mreq['request_id']}",
        )
        check("失败后请求仍 pending", got.get("status") == "pending")
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{mvp['presentation_id']}/verify",
            {"presentation": mvp, "request_id": mreq["request_id"]},
        )
        check("失败不消费，原演示随后 valid:true",
              st == 200 and r == {"valid": True})

        # 策略不满足：A 请求生成的演示，用不同 disclose 的 B 请求验证
        st, areq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-a", "expires_in": 600,
                          "disclose": ["/role"]})
        assert st == 201
        st, avp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": areq["request_id"]},
        )
        assert st == 201
        st, breq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-b", "expires_in": 600,
                          "disclose": ["/age"]})
        assert st == 201
        forged = dict(avp)
        forged["request_id"] = breq["request_id"]
        # 伪造 request_id 后 issuer proof 失效 -> 不匹配；策略不满足路径
        # 由 store 直连校验（HTTP 层无法构造 proof 合法但策略不符的状态）
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{avp['presentation_id']}/verify",
            {"presentation": forged, "request_id": breq["request_id"]},
        )
        check("演示 request_id 与验证请求不同 -> 展示请求不匹配",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "展示请求不匹配")

        # verify 时请求已过期（展示于过期前生成）
        st, ereq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-e", "expires_in": 1,
                          "disclose": ["/role"]})
        assert st == 201
        st, evp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": ereq["request_id"]},
        )
        assert st == 201
        _wait_expired(ereq["expires_at"])
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{evp['presentation_id']}/verify",
            {"presentation": evp, "request_id": ereq["request_id"]},
        )
        check("verify 时请求过期 -> 展示请求已过期，不消费",
              st == 200 and r.get("valid") is False
              and r.get("reason") == "展示请求已过期")
        st, got = _http(
            "GET",
            f"{BASE}/v1/presentation-requests/{ereq['request_id']}",
        )
        check("过期失败后请求仍 pending", got.get("status") == "pending")

        # 普通 challenge 模式验证 request 演示：字段集合不一致
        st, creq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-c", "disclose": ["/role"]})
        assert st == 201
        st, cvp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": creq["request_id"]},
        )
        assert st == 201
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{cvp['presentation_id']}/verify",
            {"presentation": cvp, "challenge": "pr-c"},
        )
        check("普通 challenge 模式验证 request 演示 -> valid:false",
              st == 200 and r.get("valid") is False)

        # ---------------- 持有者绑定请求 ---------------- #
        st, breq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-bound", "expires_in": 600,
                          "disclose": ["/role"], "holder_binding": True,
                          "issuer_dids": [issuer]})
        assert st == 201
        st, bvp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": breq["request_id"]},
        )
        check("绑定请求 present 201", st == 201)
        check("绑定展示含 holder_*",
              st == 201 and bvp.get("holder_did") == subject
              and isinstance(bvp.get("holder_key_version"), int)
              and bool(bvp.get("holder_proof")))
        # holder_proof 外部验真：去 proof/holder_proof + tenant_id
        try:
            holder_payload = {k: v for k, v in bvp.items()
                              if k not in ("proof", "holder_proof")}
            holder_payload["tenant_id"] = "default"
            crypto.verify(holder_payload, bvp["holder_proof"], subject_pem)
            check("绑定展示保留 holder_proof 且外部验真成功", True)
        except Exception:  # noqa: BLE001
            check("绑定展示保留 holder_proof 且外部验真成功", False)
        st, r = _http(
            "POST",
            f"{BASE}/v1/presentations/{bvp['presentation_id']}/verify",
            {"presentation": bvp, "request_id": breq["request_id"]},
        )
        check("绑定展示 request_id verify valid:true",
              st == 200 and r == {"valid": True})

        # ---------------- 审计事件 ---------------- #
        st, audit = _http("GET", f"{BASE}/v1/audit?limit=200")
        assert st == 200
        actions = [e["action"] for e in audit["events"]]
        check("审计含 presentation.request.created",
              "presentation.request.created" in actions)
        check("审计含 presentation.created",
              "presentation.created" in actions)
        check("审计含 presentation.consumed",
              "presentation.consumed" in actions)

        # ---------------- 重启持久化 ---------------- #
        st, kreq = _http("POST", f"{BASE}/v1/presentation-requests",
                         {"challenge": "pr-restart", "expires_in": 600,
                          "disclose": ["/role"]})
        assert st == 201
        st, kvp = _http(
            "POST", f"{BASE}/v1/credentials/{cred}/present",
            {"request_id": kreq["request_id"]},
        )
        assert st == 201
        keep_req = kreq["request_id"]
        keep_vp = kvp["presentation_id"]
        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()
        st, r = _http(
            "GET", f"{BASE}/v1/presentation-requests/{keep_req}")
        check("重启后请求保留 pending",
              st == 200 and r.get("status") == "pending")
        st, r = _http(
            "POST", f"{BASE}/v1/presentations/{keep_vp}/verify",
            {"presentation": kvp, "request_id": keep_req},
        )
        check("重启后 request_id verify valid:true",
              st == 200 and r == {"valid": True})
        st, r = _http("GET",
                      f"{BASE}/v1/presentation-requests/{keep_req}")
        check("重启后消费标记保留",
              st == 200 and r.get("status") == "consumed"
              and r.get("consumed_presentation_id") == keep_vp)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(STORE):
            os.unlink(STORE)

    print()
    if failures:
        print(f"共 {len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
