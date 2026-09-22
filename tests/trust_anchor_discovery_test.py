#!/usr/bin/env python3
"""GET /v1/trust/anchors 跨 DID 发现接口（只读）的端到端测试。

覆盖：
- 200 响应恰含 {anchors,next_after}，每项恰含
  {did,public_key,key_version,status,updated_at,cursor}；
- cursor 复用各版本注册/轮换历史的 active 事件 cursor，租户内跨 DID
  唯一、单调递增并持久化，吊销不改变；
- 先按 status 过滤，再按 cursor>after 升序取最多 limit；空结果
  next_after 等于 after；无锚点也返回 200 空数组；
- 查询参数仅允许 limit/after/status：limit 默认 50、1–200，after
  默认 0、非负 ASCII 十进制，status 省略或 active/revoked；重复、
  空值、空白、符号、Unicode 数字、越界及未知参数均 400；
- 显式空 X-Tenant-ID 400，租户不可越界；只读不记审计；
- 重启分页稳定；旧状态（锚点存在但无历史）加载补录后发现接口可用，
  无写重启 cursor 仍稳定；既有按 DID 路由不变。

直接运行：python3 tests/trust_anchor_discovery_test.py
"""

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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

PORT = 8986

PAGE_FIELDS = {"anchors", "next_after"}
ITEM_FIELDS = {
    "did", "public_key", "key_version", "status", "updated_at", "cursor",
}


def _http(method, url, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
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


def start_server(port, store_path):
    env = dict(os.environ, VCBACKEND_STORE=store_path)
    proc = subprocess.Popen(
        [sys.executable, "-m", "vcbackend.cli", "serve",
         "--port", str(port), "--host", "127.0.0.1"],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_up(port), "服务启动超时"
    return proc


def gen_pem():
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    H = {"X-Tenant-ID": "ta-disc-a"}
    H2 = {"X-Tenant-ID": "ta-disc-b"}
    P = gen_pem

    def register(did, version, pem, headers=None):
        return _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": did, "public_key": pem, "key_version": version},
            headers=headers or H,
        )

    def rotate(did, from_version, pem, headers=None):
        return _http(
            "POST", f"{base}/v1/trust/anchors/{did}/rotate",
            {"from_key_version": from_version, "public_key": pem},
            headers=headers or H,
        )

    def revoke(did, version, headers=None):
        return _http(
            "PUT",
            f"{base}/v1/trust/anchors/{did}/{version}/status",
            {"status": "revoked"}, headers=headers or H,
        )

    def discover(query=None, headers=None):
        url = f"{base}/v1/trust/anchors"
        if query is not None:
            url += f"?{query}"
        return _http("GET", url, headers=headers or H)

    def audit(headers=None):
        return _http(
            "GET", f"{base}/v1/audit?limit=200", headers=headers or H
        )[1]["events"]

    p1, p2, p3, p4 = P(), P(), P(), P()
    did_x = "did:web:disc-x"
    did_y = "did:web:disc-y"

    try:
        # ---- 1. 无锚点：200 空数组，next_after=0 ----
        st, h = discover()
        check(
            "无锚点返回 200 空数组",
            st == 200 and set(h) == PAGE_FIELDS
            and h == {"anchors": [], "next_after": 0},
        )

        # ---- 2. 跨 DID 按 active 事件 cursor 升序，字段恰为六项 ----
        # 操作顺序决定游标：x1 注册 c1、x2 轮换 c2、x4 注册 c3、
        # y1 注册 c4、x1 吊销 c5（吊销事件游标不进发现项）。
        st, _ = register(did_x, 1, p1)
        assert st == 201
        st, _ = rotate(did_x, 1, p2)
        assert st == 201
        st, _ = register(did_x, 4, p4)
        assert st == 201
        st, _ = register(did_y, 1, p3)
        assert st == 201
        st, rev_body = revoke(did_x, 1)
        assert st == 200

        st, h = discover("limit=200")
        items = h.get("anchors", [])
        expect = [
            # did, version, status, active-cursor
            (did_x, 1, "revoked", 1),
            (did_x, 2, "active", 2),
            (did_x, 4, "active", 3),
            (did_y, 1, "active", 4),
        ]
        got = [
            (it["did"], it["key_version"], it["status"], it["cursor"])
            for it in items
        ]
        check(
            "跨 DID 按 active 事件 cursor 升序，吊销不改变 cursor",
            st == 200 and set(h) == PAGE_FIELDS
            and got == expect
            and h["next_after"] == 4
            and all(set(it) == ITEM_FIELDS for it in items),
        )
        # 吊销项字段值取自锚点版本行
        rev_item = items[0]
        check(
            "吊销项 updated_at 为首次吊销时间、公钥为注册 PEM",
            rev_item["public_key"] == p1
            and rev_item["updated_at"] == rev_body["updated_at"]
            and rev_item["status"] == "revoked",
        )
        # active 项 updated_at 为 null
        check(
            "active 项 updated_at 为 null",
            all(it["updated_at"] is None for it in items if it["status"] == "active"),
        )
        cursors = [it["cursor"] for it in items]
        check(
            "cursor 租户内跨 DID 唯一且单调递增",
            len(set(cursors)) == len(cursors)
            and cursors == sorted(cursors),
        )

        # ---- 3. status 过滤 ----
        st, ha = discover("limit=200&status=active")
        check(
            "status=active 仅返回 active 版本，顺序仍按 cursor",
            st == 200
            and [(i["did"], i["key_version"]) for i in ha["anchors"]]
            == [(did_x, 2), (did_x, 4), (did_y, 1)]
            and ha["next_after"] == 4,
        )
        st, hr = discover("status=revoked")
        check(
            "status=revoked 仅返回吊销版本",
            st == 200 and len(hr["anchors"]) == 1
            and (hr["anchors"][0]["did"], hr["anchors"][0]["key_version"])
            == (did_x, 1)
            and hr["anchors"][0]["cursor"] == 1
            and hr["next_after"] == 1,
        )
        # status 过滤后无命中：空页 next_after 等于 after
        st, he = discover("status=revoked&after=1")
        check(
            "过滤后空页 next_after 等于 after",
            st == 200 and he["anchors"] == []
            and he["next_after"] == 1,
        )

        # ---- 4. 分页：默认 limit 50，after 排除 cursor ----
        st, hp = discover("limit=2&after=1")
        check(
            "after=1 排除 cursor=1，limit=2 取前两项",
            st == 200 and [i["cursor"] for i in hp["anchors"]] == [2, 3]
            and hp["next_after"] == 3,
        )
        st, hp = discover("after=3")
        check(
            "after=3 翻到末页",
            st == 200 and [i["cursor"] for i in hp["anchors"]] == [4]
            and hp["next_after"] == 4,
        )
        st, hp = discover("after=4")
        check(
            "末页之后空页且 next_after 等于 after",
            st == 200 and hp["anchors"] == []
            and hp["next_after"] == 4,
        )
        st, hp = discover("after=99999999999999999999")
        check(
            "超大非负 after 返回空页且保持 after",
            st == 200 and hp["anchors"] == []
            and hp["next_after"] == 99999999999999999999,
        )

        # ---- 5. 参数校验：仅 limit/after/status ----
        bad_queries = [
            "limit=0", "limit=201", "limit=-1", "limit=abc", "limit=1.5",
            "limit=true", "limit=%20", "limit=", "limit=1&limit=2",
            "after=-1", "after=abc", "after=1.0", "after=%20", "after=",
            "after=1&after=2", "after=%DB111",
            "status=", "status=%20", "status=ACTIVE", "status=revoked%20",
            "status=%20active",
            "status=unknown", "status=active&status=revoked",
            "foo=1", "limit=1&foo=1", "status=active&cursor=1",
        ]
        bad_results = [discover(q)[0] for q in bad_queries]
        check(
            "重复/空值/空白/符号/Unicode/越界/未知参数及非法 status 均 400",
            bad_results == [400] * len(bad_queries),
        )

        # ---- 6. 租户隔离与租户头 ----
        st, h2page = discover(headers=H2)
        check(
            "他租户看不到本租户锚点（空页 200）",
            st == 200 and h2page == {"anchors": [], "next_after": 0},
        )
        # 他租户注册自己的锚点，cursor 从 1 计起
        st, _ = register("did:web:disc-z", 1, P(), headers=H2)
        assert st == 201
        st, h2page = discover(headers=H2)
        check(
            "游标按租户隔离：他租户 cursor 从 1 计起",
            st == 200 and len(h2page["anchors"]) == 1
            and h2page["anchors"][0]["cursor"] == 1,
        )
        st, _ = discover(headers={"X-Tenant-ID": ""})
        check("显式空租户头 400", st == 400)

        # ---- 7. 只读不记审计 ----
        before = audit()
        discover("limit=1")
        discover("status=active")
        discover("status=revoked&after=9")
        discover("limit=200", headers=H2)
        check("发现查询不记审计", audit() == before)

        # ---- 8. 既有按 DID 路由不变 ----
        st, arr = _http(
            "GET", f"{base}/v1/trust/anchors/{did_x}", headers=H
        )
        check(
            "GET 按 DID 列表字段与顺序不变（无 cursor 字段）",
            st == 200 and [a["key_version"] for a in arr] == [1, 2, 4]
            and all(
                set(a) == {
                    "did", "public_key", "key_version", "status",
                    "updated_at",
                }
                for a in arr
            ),
        )
        st, hist = _http(
            "GET", f"{base}/v1/trust/anchors/{did_x}/history?limit=200",
            headers=H,
        )
        check(
            "按 DID 历史接口不变",
            st == 200 and set(hist) == {"did", "events", "next_after"},
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 跨重启：分页与 cursor 稳定 ----
    proc = start_server(PORT, store_path)
    try:
        st, h = discover("limit=200")
        got = [
            (it["did"], it["key_version"], it["status"], it["cursor"])
            for it in h["anchors"]
        ]
        check(
            "重启后跨 DID 顺序、状态与 cursor 稳定",
            st == 200 and got == [
                (did_x, 1, "revoked", 1),
                (did_x, 2, "active", 2),
                (did_x, 4, "active", 3),
                (did_y, 1, "active", 4),
            ]
            and h["next_after"] == 4,
        )
        # 重启后吊销仍不改变 cursor，分页可继续
        st, hp = discover("after=3&limit=1")
        check(
            "重启后 after 分页稳定",
            st == 200 and [i["cursor"] for i in hp["anchors"]] == [4]
            and hp["next_after"] == 4,
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 旧状态补录：删除历史命名空间与游标后重启 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    lt = {"X-Tenant-ID": "ta-disc-legacy"}
    lp = start_server(PORT, legacy_path)
    try:
        la, lb = P(), P()
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": "did:web:old-disc", "public_key": la, "key_version": 1},
            headers=lt,
        )
        assert st == 201
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors/did:web:old-disc/rotate",
            {"from_key_version": 1, "public_key": lb},
            headers=lt,
        )
        assert st == 201
        st, old_rev = _http(
            "PUT", f"{base}/v1/trust/anchors/did:web:old-disc/1/status",
            {"status": "revoked"}, headers=lt,
        )
        assert st == 200
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    raw = json.load(open(legacy_path, encoding="utf-8"))
    for bucket in raw["tenants"].values():
        bucket["trust_anchor_history"] = {}
    raw.pop("trust_anchor_history_cursors", None)
    with open(legacy_path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)

    lp = start_server(PORT, legacy_path)
    try:
        st, h = _http(
            "GET", f"{base}/v1/trust/anchors?limit=200", headers=lt
        )
        check(
            "旧状态加载补录 active 游标后发现接口可用（v1 吊销不影响其 active cursor）",
            st == 200 and [
                (i["key_version"], i["status"], i["cursor"])
                for i in h["anchors"]
            ] == [
                (1, "revoked", 1),
                (2, "active", 3),
            ]
            and h["anchors"][0]["updated_at"] == old_rev["updated_at"]
            and h["next_after"] == 3,
        )
        compat_cursors = [i["cursor"] for i in h["anchors"]]
        st, ha = _http(
            "GET", f"{base}/v1/trust/anchors?status=active", headers=lt
        )
        check(
            "补录后 status=active 过滤正确",
            st == 200 and [
                (i["key_version"], i["cursor"]) for i in ha["anchors"]
            ] == [(2, 3)] and ha["next_after"] == 3,
        )
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    # 无写直接重启：补录 cursor 重建为相同值
    lp = start_server(PORT, legacy_path)
    try:
        st, h = _http(
            "GET", f"{base}/v1/trust/anchors?limit=200", headers=lt
        )
        check(
            "补录 cursor 无写重启仍稳定",
            st == 200
            and [i["cursor"] for i in h["anchors"]] == compat_cursors,
        )
    finally:
        lp.terminate()
        lp.wait(timeout=10)

    for path in (store_path, legacy_path):
        if os.path.exists(path):
            os.remove(path)

    print()
    if failures:
        print(f"{len(failures)} 项失败:")
        for name in failures:
            print(" -", name)
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
