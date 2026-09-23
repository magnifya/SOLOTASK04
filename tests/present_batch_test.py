#!/usr/bin/env python3
"""POST /v1/credentials/{credential_id}/present-batch 端到端测试。

覆盖：
- 201 批量生成：1..50 项、与输入同序、项键序固定九字段，绑定项末加
  holder_did、holder_key_version、holder_proof；
- 缺省规则沿用 present：challenge 缺省 32 位小写 hex、expires_in 缺省
  300、holder_binding 缺省 false；显式值生效；[] 零披露；
- issuer/holder ES256 签名可外部验真，且生成的演示可经
  /v1/presentations/{id}/verify 验真；
- 请求级 400：缺/多字段、presentations 非数组、空数组、超 50 项、
  非法 JSON、非对象；项级 400：项非对象、缺 disclose、多余字段、
  challenge/expires_in/holder_binding 非法、RFC6901 根路径/数组索引/
  越界/重复/祖先重叠；
- 未知或他租户凭证 404；显式空 X-Tenant-ID 400；
- 原子性：任一项非法整批不写入演示、不记任何审计；成功批量为每项记
  一条 presentation.created，同一次原子提交；
- 重启后记录保留、仍可验签；
- 直连 store：subject 未注册的绑定项 400 且零写入。

直接运行：python3 tests/present_batch_test.py
"""

import json
import os
import re
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

PORT = 8956
STORE = tempfile.mktemp(suffix=".json")
BASE = f"http://127.0.0.1:{PORT}"

UNBOUND_KEYS = [
    "presentation_id", "credential_id", "issuer_did",
    "issuer_key_version", "disclose", "claims",
    "challenge", "expires_at", "proof",
]
BOUND_KEYS = UNBOUND_KEYS + [
    "holder_did", "holder_key_version", "holder_proof",
]
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
UTC_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


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


def _json(method, url, payload=None, headers=None, raw=None):
    status, text = _http(method, url, payload=payload, headers=headers, raw=raw)
    return status, (json.loads(text) if text else None), text


def _ordered_presentations(text):
    """解析批量响应并保留每个演示对象与顶层的键插入顺序。"""
    return json.loads(text, object_pairs_hook=lambda pairs: pairs)


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


def _audit_count():
    status, body, _ = _json("GET", f"{BASE}/v1/audit?limit=200")
    assert status == 200
    return len(body["events"])


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), "-", name)
        if not cond:
            failures.append(name)

    proc = start_server()
    try:
        # ---------------- 准备签发者/持有者与凭证 ---------------- #
        st, issuer, _ = _json(
            "POST", f"{BASE}/v1/dids",
            {"method": "example", "public_key": "batch-issuer-key"},
        )
        assert st == 201, (st, issuer)
        issuer_did = issuer["did"]
        issuer_pem = issuer["public_key"]

        st, holder, _ = _json(
            "POST", f"{BASE}/v1/dids",
            {"method": "example", "public_key": "batch-holder-key"},
        )
        assert st == 201
        holder_did = holder["did"]
        holder_pem = holder["public_key"]

        claims = {
            "role": "admin",
            "age": 30,
            "addr": {"city": "Beijing", "zip": "100000"},
            "tags": ["x", "y"],
            "a": {"b": 1},
        }
        st, cred, _ = _json(
            "POST", f"{BASE}/v1/credentials",
            {"issuer_did": issuer_did, "subject_did": holder_did,
             "claims": claims},
        )
        assert st == 201, (st, cred)
        credential_id = cred["credential_id"]
        cred_url = f"{BASE}/v1/credentials/{credential_id}"

        # ---------------- 201 混合批量 ---------------- #
        items = [
            {"disclose": []},
            {"disclose": ["/role"], "challenge": "ch-1"},
            {"disclose": ["/addr/city", "/age"],
             "challenge": "ch-2", "expires_in": 600},
            {"disclose": ["/tags"], "holder_binding": True,
             "challenge": "ch-bind"},
            {"disclose": ["/a/b"], "holder_binding": False},
        ]
        before_audit = _audit_count()
        st, body, text = _json(
            "POST", f"{cred_url}/present-batch", {"presentations": items}
        )
        check("混合批量返回 201", st == 201)
        check("错误响应不含 error 字段", isinstance(body, dict) and "error" not in body)

        ordered = _ordered_presentations(text)
        check("顶层键序恰为 presentations",
              [k for k, _ in ordered] == ["presentations"])
        vp_pairs = [pairs for pairs in dict(ordered)["presentations"]]
        vps = body["presentations"]
        ordered_vps = vps
        check("返回项数与输入一致且同序", len(vps) == 5)
        check("第 1 项零披露 claims 为空对象",
              vps[0]["claims"] == {} and vps[0]["disclose"] == [])
        check("第 2 项回显 challenge/disclose 与投影",
              vps[1]["challenge"] == "ch-1"
              and vps[1]["disclose"] == ["/role"]
              and vps[1]["claims"] == {"role": "admin"})
        check("第 3 项多路径嵌套投影与显式参数",
              vps[2]["claims"] == {"addr": {"city": "Beijing"}, "age": 30}
              and vps[2]["challenge"] == "ch-2")
        check("第 4 项绑定演示含 holder_* 且 holder_did 为 subject",
              vps[3]["holder_did"] == holder_did
              and vps[3]["holder_key_version"] == 1)
        check("第 5 项未绑定不含 holder_*",
              not any(k.startswith("holder_") for k in vps[4]))
        for idx, vp in enumerate(vps):
            check(f"项 {idx} 锚定 credential_id/issuer_did/版本",
                  vp["credential_id"] == credential_id
                  and vp["issuer_did"] == issuer_did
                  and vp["issuer_key_version"] == 1)

        check("未绑定项键序固定九字段",
              [[k for k, _ in pairs] for pairs in vp_pairs[:3]] ==
              [UNBOUND_KEYS, UNBOUND_KEYS, UNBOUND_KEYS]
              and [k for k, _ in vp_pairs[4]] == UNBOUND_KEYS)
        check("绑定项键序为九字段后接 holder 三字段",
              [k for k, _ in vp_pairs[3]] == BOUND_KEYS)

        # 缺省值校验
        check("缺省 challenge 为 32 位小写 hex",
              HEX32_RE.match(vps[0]["challenge"]) is not None
              and HEX32_RE.match(vps[4]["challenge"]) is not None
              and vps[0]["challenge"] != vps[4]["challenge"])
        now = datetime.now(timezone.utc)
        for idx, vp in enumerate(vps):
            check(f"项 {idx} expires_at 为 UTC 秒精度 Z",
                  UTC_Z_RE.match(vp["expires_at"]) is not None)
        exp0 = datetime.strptime(
            vps[0]["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        check("缺省 expires_in=300（秒精度容差）",
              290 <= (exp0 - now).total_seconds() <= 310)
        exp2 = datetime.strptime(
            vps[2]["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        check("显式 expires_in=600 生效",
              590 <= (exp2 - now).total_seconds() <= 610)

        # presentation_id 唯一且形如 vp_<32hex>
        ids = [vp["presentation_id"] for vp in vps]
        check("presentation_id 唯一且为 vp_ 加 32 位 hex",
              len(set(ids)) == 5
              and all(HEX32_RE.match(pid[3:]) for pid in ids))

        # 外部密码学验签：issuer proof 不含 holder_*；holder proof
        # 覆盖去 proof/holder_proof 后加 tenant_id=default。
        issuer_ok = True
        for vp in vps:
            issuer_payload = {
                k: v for k, v in vp.items()
                if k not in ("proof", "holder_did",
                             "holder_key_version", "holder_proof")
            }
            try:
                crypto.verify(issuer_payload, vp["proof"], issuer_pem)
            except Exception:  # noqa: BLE001
                issuer_ok = False
        check("全部 issuer proof 可用签发者公钥外部验真", issuer_ok)

        bound_vp = vps[3]
        holder_payload = {
            k: v for k, v in bound_vp.items()
            if k not in ("proof", "holder_proof")
        }
        holder_payload["tenant_id"] = "default"
        holder_ok = True
        try:
            crypto.verify(
                holder_payload, bound_vp["holder_proof"], holder_pem
            )
        except Exception:  # noqa: BLE001
            holder_ok = False
        check("holder_proof 可用持有者公钥外部验真（覆盖 tenant_id）",
              holder_ok)

        # 审计：成功批量为每项记一条 presentation.created
        after_audit = _audit_count()
        created = []
        st, audit_body, _ = _json("GET", f"{BASE}/v1/audit?limit=200")
        for event in audit_body["events"]:
            if event["action"] == "presentation.created":
                created.append(event)
        check("成功批量原子记录 5 条 presentation.created 审计",
              after_audit - before_audit == 5
              and {e["resource_id"] for e in created[-5:]} == set(ids))

        # 演示可经单项 verify 验真（未绑定与绑定各一）
        st, verify_body, _ = _json(
            "POST", f"{BASE}/v1/presentations/{vps[1]['presentation_id']}/verify",
            {"presentation": ordered_vps[1], "challenge": "ch-1"},
        )
        check("未绑定演示 verify 成功", st == 200 and verify_body == {"valid": True})
        st, verify_body, _ = _json(
            "POST", f"{BASE}/v1/presentations/{vps[1]['presentation_id']}/verify",
            {"presentation": ordered_vps[1], "challenge": "ch-1"},
        )
        check("重复 verify 返回已消费",
              verify_body.get("valid") is False and "已消费" in verify_body.get("reason", ""))
        st, verify_body, _ = _json(
            "POST", f"{BASE}/v1/presentations/{vps[3]['presentation_id']}/verify",
            {"presentation": ordered_vps[3], "challenge": "ch-bind"},
        )
        check("绑定演示双签名 verify 成功", st == 200 and verify_body == {"valid": True})

        # 50 项上限批量（全部零披露）
        st, body50, _ = _json(
            "POST", f"{cred_url}/present-batch",
            {"presentations": [{"disclose": []} for _ in range(50)]},
        )
        check("50 项批量成功 201",
              st == 201 and len(body50["presentations"]) == 50)

        # ---------------- 请求级 400 ---------------- #
        def expect_400(name, payload=None, raw=None):
            st, body, _ = _json(
                "POST", f"{cred_url}/present-batch",
                payload=payload, raw=raw,
            )
            ok = st == 400 and isinstance(body, dict) and bool(body.get("error"))
            check(name, ok)

        expect_400("缺少 presentations 字段 400", payload={})
        expect_400("多余字段 400",
                   payload={"presentations": [], "x": 1})
        expect_400("presentations 非数组 400",
                   payload={"presentations": {}})
        expect_400("空数组 400", payload={"presentations": []})
        expect_400("51 项超限 400",
                   payload={"presentations": [
                       {"disclose": []} for _ in range(51)]})
        expect_400("非法 JSON 400", raw=b"{not json")
        st, body, _ = _json(
            "POST", f"{cred_url}/present-batch", raw=b"[1,2]"
        )
        check("非对象请求体 400", st == 400 and bool(body.get("error")))

        # ---------------- 项级 400（且整批不写入） ---------------- #
        def expect_item_400(name, item):
            before = _audit_count()
            presentations_before = _count_presentations()
            st, body, _ = _json(
                "POST", f"{cred_url}/present-batch",
                {"presentations": [{"disclose": ["/role"]}, item]},
            )
            after = _audit_count()
            presentations_after = _count_presentations()
            check(
                name,
                st == 400 and bool(body.get("error")),
            )
            check(name + "：原子回滚，不记审计/不写演示",
                  before == after
                  and presentations_before == presentations_after)

        expect_item_400("项非对象 400", "nope")
        expect_item_400("项缺 disclose 400", {"challenge": "c"})
        expect_item_400("项含多余字段 400",
                        {"disclose": ["/role"], "holder": True, "x": 1})
        expect_item_400("challenge 空串 400",
                        {"disclose": ["/role"], "challenge": ""})
        expect_item_400("challenge 非字符串 400",
                        {"disclose": ["/role"], "challenge": 123})
        expect_item_400("challenge 超 256 码点 400",
                        {"disclose": ["/role"], "challenge": "超" * 257})
        expect_item_400("expires_in 为布尔 400",
                        {"disclose": ["/role"], "expires_in": True})
        expect_item_400("expires_in 为浮点 400",
                        {"disclose": ["/role"], "expires_in": 3.5})
        expect_item_400("expires_in 为 0 400",
                        {"disclose": ["/role"], "expires_in": 0})
        expect_item_400("expires_in 超 86400 400",
                        {"disclose": ["/role"], "expires_in": 86401})
        expect_item_400("expires_in 为字符串 400",
                        {"disclose": ["/role"], "expires_in": "300"})
        expect_item_400("holder_binding 非布尔 400",
                        {"disclose": ["/role"], "holder_binding": "true"})
        expect_item_400("disclose 非数组 400", {"disclose": "/role"})
        expect_item_400("根路径 400", {"disclose": [""]})
        expect_item_400("数组索引路径 400", {"disclose": ["/tags/0"]})
        expect_item_400("越界路径 400", {"disclose": ["/nope"]})
        expect_item_400("经过叶子路径 400", {"disclose": ["/role/x"]})
        expect_item_400("重复路径 400", {"disclose": ["/age", "/age"]})
        expect_item_400("祖先重叠路径 400",
                        {"disclose": ["/a", "/a/b"]})
        expect_item_400("后代重叠路径顺序反序 400",
                        {"disclose": ["/a/b", "/a"]})
        expect_item_400("非字符串路径 400", {"disclose": [1]})
        expect_item_400("非法转义路径 400", {"disclose": ["/a~2"]})

        # 错误原因必须为非空中文
        st, body, _ = _json(
            "POST", f"{cred_url}/present-batch",
            {"presentations": [{"disclose": ["/missing"]}]},
        )
        check("400 error 为非空中文原因",
              st == 400 and isinstance(body["error"], str)
              and any("一" <= ch <= "鿿" for ch in body["error"]))

        # ---------------- 404 / 租户规则 ---------------- #
        st, body, _ = _json(
            "POST", f"{BASE}/v1/credentials/vc_nonexistent/present-batch",
            {"presentations": [{"disclose": []}]},
        )
        check("未知凭证 404", st == 404 and bool(body.get("error")))

        st, body, _ = _json(
            "POST", f"{cred_url}/present-batch",
            {"presentations": [{"disclose": []}]},
            headers={"X-Tenant-ID": "other-tenant"},
        )
        check("他租户凭证 404", st == 404)

        st, body, _ = _json(
            "POST", f"{cred_url}/present-batch",
            {"presentations": [{"disclose": []}]},
            headers={"X-Tenant-ID": ""},
        )
        check("显式空 X-Tenant-ID 400", st == 400)

        # 未知凭证的批量失败同样零审计
        before = _audit_count()
        _json(
            "POST", f"{BASE}/v1/credentials/vc_nonexistent/present-batch",
            {"presentations": [{"disclose": []}, {"disclose": ["/role"]}]},
        )
        check("404 失败不记审计", _audit_count() == before)

        # ---------------- 重启持久化与验签 ---------------- #
        st, rb, _ = _json(
            "POST", f"{cred_url}/present-batch",
            {"presentations": [
                {"disclose": ["/role"], "challenge": "restart-u"},
                {"disclose": ["/age"], "challenge": "restart-b",
                 "holder_binding": True},
            ]},
        )
        assert st == 201
        restart_items = rb["presentations"]

        proc.terminate()
        proc.wait(timeout=10)
        proc = start_server()

        st, body, _ = _json(
            "POST",
            f"{BASE}/v1/presentations/{restart_items[0]['presentation_id']}/verify",
            {"presentation": restart_items[0], "challenge": "restart-u"},
        )
        check("重启后未绑定演示仍可验签", st == 200 and body == {"valid": True})
        st, body, _ = _json(
            "POST",
            f"{BASE}/v1/presentations/{restart_items[1]['presentation_id']}/verify",
            {"presentation": restart_items[1], "challenge": "restart-b"},
        )
        check("重启后绑定演示双签名仍可验签", st == 200 and body == {"valid": True})
        # 重启前已消费的演示重启后仍是已消费
        st, body, _ = _json(
            "POST", f"{BASE}/v1/presentations/{vps[1]['presentation_id']}/verify",
            {"presentation": ordered_vps[1], "challenge": "ch-1"},
        )
        check("消费标记跨重启保留",
              body.get("valid") is False and "已消费" in body.get("reason", ""))

        # ---------------- 直连 store：原子性防御路径 ---------------- #
        run_direct_store_checks(failures, check)
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


def _count_presentations():
    """通过状态文件统计当前租户演示总数（仅用于零写入断言）。"""
    if not os.path.exists(STORE):
        return 0
    with open(STORE, encoding="utf-8") as fh:
        data = json.load(fh)
    return len(data.get("tenants", {}).get("default", {}).get(
        "presentations", {}))


def run_direct_store_checks(failures, check):
    """直连 VCStore：非法批量整批不写入；绑定 subject 未注册 400。"""
    from vcbackend.store import VCStore, ValidationError

    direct_path = tempfile.mktemp(suffix=".json")
    try:
        dstore = VCStore(direct_path)
        issuer_rec = dstore.create_did("t1", "example", "d-issuer")
        subject_rec = dstore.create_did("t1", "example", "d-subject")
        cred = dstore.create_credential(
            "t1", issuer_rec.did, subject_rec.did, {"a": 1, "b": 2}
        )
        bucket = dstore._tenants["t1"]  # noqa: SLF001 测试直查内部状态
        audit_len = len(dstore._audit)  # noqa: SLF001

        # 第二项非法：第一项也不得写入
        raised = False
        try:
            dstore.create_presentations_batch(
                "t1", cred.credential_id,
                [
                    (["/a"], "ok-1", None, False),
                    (["/nope"], "ok-2", None, False),
                ],
            )
        except ValidationError:
            raised = True
        check("直连: 任一项非法整体抛 ValidationError", raised)
        check("直连: 非法批量零演示写入",
              len(bucket["presentations"]) == 0)
        check("直连: 非法批量零审计写入",
              len(dstore._audit) == audit_len)  # noqa: SLF001

        # 空 specs 拒绝
        raised = False
        try:
            dstore.create_presentations_batch("t1", cred.credential_id, [])
        except ValidationError:
            raised = True
        check("直连: 空 specs 抛 ValidationError", raised)

        # 绑定 subject 未注册 -> 400 且零写入
        saved = bucket["dids"].pop(subject_rec.did)
        raised = False
        try:
            dstore.create_presentations_batch(
                "t1", cred.credential_id,
                [(["/a"], "bind", None, True)],
            )
        except ValidationError:
            raised = True
        finally:
            bucket["dids"][subject_rec.did] = saved
        check("直连: subject 未注册的绑定项 400", raised)
        check("直连: 绑定失败零演示写入",
              len(bucket["presentations"]) == 0)

        # 全部合法时与输入同序、各自持久化并记审计
        records = dstore.create_presentations_batch(
            "t1", cred.credential_id,
            [
                (["/a"], "c1", None, False),
                (["/b"], "c2", 60, True),
                ([], "c3", None, False),
            ],
        )
        check("直连: 合法批量返回同序三项",
              [r.challenge for r in records] == ["c1", "c2", "c3"]
              and records[1].holder_did == subject_rec.did
              and len(bucket["presentations"]) == 3)
        created = [
            e for e in dstore._audit  # noqa: SLF001
            if e["action"] == "presentation.created"
        ]
        check("直连: 合法批量记 3 条审计", len(created) == 3)
        # 落盘文件中三项均存在（原子提交）
        with open(direct_path, encoding="utf-8") as fh:
            persisted = json.load(fh)
        check("直连: 三项与审计均已原子落盘",
              len(persisted["tenants"]["t1"]["presentations"]) == 3
              and sum(
                  1 for e in persisted["audit"]
                  if e["action"] == "presentation.created"
              ) == 3)
    finally:
        if os.path.exists(direct_path):
            os.unlink(direct_path)


if __name__ == "__main__":
    sys.exit(main())
