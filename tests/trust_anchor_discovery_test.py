#!/usr/bin/env python3
"""信任锚点跨 DID 只读发现接口（GET /v1/trust/anchors）端到端测试。

覆盖：
- 200 响应恰含 {anchors,next_after}，每项恰含
  {did,public_key,key_version,status,updated_at,cursor}；cursor 为 JSON
  正整数，租户内跨 DID 唯一、单调递增并持久化，复用对应注册/轮换历史
  的 active 事件游标，吊销不改变；
- status 过滤后按 cursor>after 升序取至多 limit；空结果 next_after 等于
  after；无锚点租户也返回 200 空数组；
- limit 默认 50、限 1–200，after 默认 0、须非负 ASCII 十进制，status
  仅可省略或为 active/revoked；重复、空值、空白、符号、小数、布尔词、
  Unicode 数字、越界与未知参数一律 400；
- 显式空 X-Tenant-ID 400，租户隔离；只读不记审计；重启分页稳定；
- 既有按 DID 路由（GET /v1/trust/anchors/{did} 等）不变；
- 加载迁移：按 did 字典序、key_version 升序为缺失 active 历史补游标，
  已有有效游标复用；GET 不触发落盘/重试，后续成功原子写再持久化；
  落盘失败不部分写入。

直接运行：python3 tests/trust_anchor_discovery_test.py
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

PORT = 8987

PAGE_FIELDS = {"anchors", "next_after"}
ITEM_FIELDS = {
    "did", "public_key", "key_version", "status", "updated_at", "cursor",
}


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


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL"), name)
        if not cond:
            failures.append(name)

    store_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, store_path)
    base = f"http://127.0.0.1:{PORT}"
    H = {"X-Tenant-ID": "disc-a"}
    H2 = {"X-Tenant-ID": "disc-b"}
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

    try:
        p1, p2, p3 = P(), P(), P()
        did_a = "did:web:disc-a"
        did_b = "did:web:disc-b"

        # ---- 1. 注册/轮换/吊销后的跨 DID 发现 ----
        st, _ = register(did_a, 1, p1)
        check("a v1 注册 201", st == 201)
        st, _ = rotate(did_a, 1, p2)
        check("a v2 轮换 201", st == 201)
        st, _ = register(did_b, 1, p3)
        check("b v1 注册 201", st == 201)
        st, rev_body = revoke(did_a, 1)
        check("a v1 吊销 200", st == 200)

        st, page = discover("limit=200")
        items = page.get("anchors", [])
        check(
            "响应恰含 anchors/next_after，每项恰含六字段",
            st == 200 and set(page) == PAGE_FIELDS
            and all(set(item) == ITEM_FIELDS for item in items),
        )
        check(
            "按 cursor 升序跨 DID 返回全部版本",
            [(i["did"], i["key_version"], i["status"], i["cursor"])
             for i in items]
            == [
                (did_a, 1, "revoked", 1),
                (did_a, 2, "active", 2),
                (did_b, 1, "active", 3),
            ]
            and page["next_after"] == 3,
        )
        a1 = items[0]
        check(
            "吊销不改变 cursor；字段取值与按 DID 接口一致",
            a1["cursor"] == 1
            and a1["public_key"] == p1
            and a1["updated_at"] == rev_body["updated_at"]
            and isinstance(a1["cursor"], int)
            and items[1]["updated_at"] is None,
        )

        # ---- 2. status 过滤 ----
        st, active_page = discover("status=active")
        check(
            "status=active 先过滤再按 cursor 升序",
            st == 200
            and [(i["did"], i["key_version"], i["cursor"])
                 for i in active_page["anchors"]]
            == [(did_a, 2, 2), (did_b, 1, 3)]
            and active_page["next_after"] == 3,
        )
        st, revoked_page = discover("status=revoked")
        check(
            "status=revoked 仅返吊销版本且 cursor 仍为 active 事件游标",
            st == 200
            and [(i["did"], i["key_version"], i["cursor"])
                 for i in revoked_page["anchors"]]
            == [(did_a, 1, 1)]
            and revoked_page["next_after"] == 1,
        )

        # ---- 3. 分页：先 status 过滤，再 cursor>after，取 limit ----
        st, pg = discover("status=active&after=2&limit=1")
        check(
            "过滤后 after 排除、limit 截断，next_after 取页末",
            st == 200 and [(i["cursor"]) for i in pg["anchors"]] == [3]
            and pg["next_after"] == 3,
        )
        st, empty = discover("after=3&limit=200")
        check(
            "非空空页 next_after 等于 after",
            st == 200 and empty["anchors"] == []
            and empty["next_after"] == 3,
        )
        st, empty = discover("status=revoked&after=1")
        check(
            "过滤后无匹配也返回空页且 next_after 等于 after",
            st == 200 and empty["anchors"] == []
            and empty["next_after"] == 1,
        )
        # 超大 after：空页保持 after（大整数不被转成浮点）
        st, empty = discover("after=99999999999999999999")
        check(
            "超大非负 after 返回空页且 next_after 精确保持 after",
            st == 200 and empty["anchors"] == []
            and empty["next_after"] == 99999999999999999999,
        )

        # ---- 4. limit 默认 50：注册 51 个跨 DID 版本 ----
        did_page = "did:web:disc-page"
        for version in range(1, 52):
            st, _ = register(did_page, version, P())
            assert st == 201, (version, st)
        st, pg = discover()
        check(
            "limit 默认 50",
            st == 200 and len(pg["anchors"]) == 50
            and pg["next_after"] == pg["anchors"][-1]["cursor"],
        )
        st, pg1 = discover("limit=1")
        check("limit=1 只返一项", st == 200 and len(pg1["anchors"]) == 1)
        st, pg200 = discover("limit=200")
        check("limit=200 合法", st == 200 and len(pg200["anchors"]) == 54)
        st, pg01 = discover("limit=01")
        check("前导零数字接受", st == 200 and len(pg01["anchors"]) == 1)

        # ---- 5. 参数校验：400 全覆盖 ----
        bad_queries = [
            "limit=0", "limit=201", "limit=-1", "limit=abc", "limit=1.5",
            "limit=1.0", "limit=true", "limit=false", "limit=%20",
            "limit=%201", "limit=%2B1", "limit=", "limit=1&limit=2",
            "after=-1", "after=abc", "after=1.0", "after=%20", "after=",
            "after=1&after=2", "after=%DB111", "after=true",
            "status=ACTIVE", "status=Revoked", "status=foo", "status=",
            "status=%20", "status=%20active", "status=1",
            "status=active&status=revoked",
            "foo=1", "did=x", "limit=50&foo=", "after=1&unknown=2",
        ]
        results = [discover(q)[0] for q in bad_queries]
        check(
            "重复/空值/空白/符号/小数/布尔词/Unicode/越界/未知参数均 400",
            results == [400] * len(bad_queries),
        )

        # ---- 6. 无锚点租户、租户隔离与租户头 ----
        st, fresh = discover(headers={"X-Tenant-ID": "disc-empty"})
        check(
            "无锚点租户返回 200 空数组",
            st == 200 and fresh == {"anchors": [], "next_after": 0},
        )
        st, other = discover(headers=H2)
        check(
            "租户不可越界：其他租户只见自己的锚点",
            st == 200 and other["anchors"] == []
            and other["next_after"] == 0,
        )
        st, _ = discover(headers={"X-Tenant-ID": ""})
        check("显式空 X-Tenant-ID 400", st == 400)

        # ---- 7. 只读不记审计 ----
        before = audit()
        discover("limit=200")
        discover("status=active&after=1")
        discover("limit=0")          # 400
        discover(headers=H2)        # 空租户
        discover(headers={"X-Tenant-ID": ""})  # 400
        after_audit = audit()
        check("发现接口（含 400/空租户）不记审计", before == after_audit)

        # ---- 8. 既有按 DID 路由不变 ----
        st, per_did = _http(
            "GET", f"{base}/v1/trust/anchors/{did_a}", headers=H
        )
        check(
            "按 DID GET 仍返回版本数组（六字段无 cursor）",
            st == 200 and [a["key_version"] for a in per_did] == [1, 2]
            and [set(a) == {
                "did", "public_key", "key_version", "status", "updated_at"
            } for a in per_did] == [True, True],
        )
        st, hist = _http(
            "GET", f"{base}/v1/trust/anchors/{did_b}/history", headers=H
        )
        check(
            "按 DID history 路由不变且 cursor 与发现接口一致",
            st == 200 and hist["events"][0]["cursor"]
            == discover("limit=200")[1]["anchors"][2]["cursor"],
        )
        st, _ = _http(
            "GET", f"{base}/v1/trust/anchors/did:web:no-such", headers=H
        )
        check("未知 DID 的按 DID 查询仍 404", st == 404)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 9. 重启后分页稳定，游标继续递增 ----
    proc = start_server(PORT, store_path)
    try:
        st, p_before = discover("status=active&limit=3&after=1")
        cursors_before = [i["cursor"] for i in p_before["anchors"]]
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    proc = start_server(PORT, store_path)
    try:
        st, p_after = discover("status=active&limit=3&after=1")
        cursors_after = [i["cursor"] for i in p_after["anchors"]]
        check("重启后分页结果稳定", cursors_before == cursors_after)
        st, _ = register("did:web:disc-c", 1, P())
        st, pg = discover("limit=200")
        cursors = [i["cursor"] for i in pg["anchors"]]
        check(
            "重启后新版本游标在租户内继续递增且跨 DID 唯一",
            st == 200 and len(cursors) == len(set(cursors))
            and cursors == sorted(cursors)
            and pg["anchors"][-1]["did"] == "did:web:disc-c"
            and pg["anchors"][-1]["cursor"] == cursors[-1]
            and cursors[-1] == max(cursors),
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 10. 旧状态迁移：缺 active 历史时按 did/版本稳定补游标 ----
    legacy_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, legacy_path)
    LH = {"X-Tenant-ID": "disc-legacy"}
    try:
        la1, la2, lb1 = P(), P(), P()
        # 字典序 m-a 在 m-b 之前；同 DID 内版本升序
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": "did:web:m-a", "public_key": la1, "key_version": 1},
            headers=LH,
        )
        assert st == 201
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors/did:web:m-a/rotate",
            {"from_key_version": 1, "public_key": la2}, headers=LH,
        )
        assert st == 201
        st, _ = _http(
            "POST", f"{base}/v1/trust/anchors",
            {"did": "did:web:m-b", "public_key": lb1, "key_version": 1},
            headers=LH,
        )
        assert st == 201
        st, _ = _http(
            "PUT", f"{base}/v1/trust/anchors/did:web:m-a/1/status",
            {"status": "revoked"}, headers=LH,
        )
        assert st == 200
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 删除全部锚点生命周期历史与游标，模拟旧状态文件
    raw = json.loads(Path(legacy_path).read_text(encoding="utf-8"))
    raw["tenants"]["disc-legacy"]["trust_anchor_history"] = {}
    raw.pop("trust_anchor_history_cursors", None)
    Path(legacy_path).write_text(json.dumps(raw), encoding="utf-8")

    proc = start_server(PORT, legacy_path)
    try:
        st, pg = discover("limit=200", headers=LH)
        # 全量重建时，同一版本的 active 与 revoked 补录事件按版本升序交错
        # 分配游标：m-a v1 active=1、revoked=2、m-a v2 active=3、
        # m-b v1 active=4。发现接口只取 active 游标（1/3/4），仍按
        # did 字典序、key_version 升序且唯一、单调递增。
        check(
            "迁移按 did 字典序、key_version 升序补 active 游标",
            st == 200
            and [(i["did"], i["key_version"], i["status"], i["cursor"])
                 for i in pg["anchors"]]
            == [
                ("did:web:m-a", 1, "revoked", 1),
                ("did:web:m-a", 2, "active", 3),
                ("did:web:m-b", 1, "active", 4),
            ]
            and pg["next_after"] == 4,
        )
        st, active_pg = discover("status=active", headers=LH)
        check(
            "迁移后 status=active 过滤仍按游标升序",
            [(i["did"], i["key_version"], i["cursor"])
             for i in active_pg["anchors"]]
            == [("did:web:m-a", 2, 3), ("did:web:m-b", 1, 4)]
            and active_pg["next_after"] == 4,
        )
        backfilled = [(i["did"], i["key_version"], i["cursor"])
                      for i in pg["anchors"]]

        # GET 不触发落盘/重试：文件内容不变
        digest_before = file_digest(legacy_path)
        discover("limit=200", headers=LH)
        discover("status=active", headers=LH)
        discover("status=revoked&after=0", headers=LH)
        digest_after = file_digest(legacy_path)
        check("GET 不触发落盘", digest_before == digest_after)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # 无写重启：补录游标重建为相同值
    proc = start_server(PORT, legacy_path)
    try:
        st, pg = discover("limit=200", headers=LH)
        check(
            "补录游标无写重启仍稳定",
            [(i["did"], i["key_version"], i["cursor"])
             for i in pg["anchors"]] == backfilled,
        )
        digest_before = file_digest(legacy_path)
        discover("limit=200", headers=LH)
        check("再次 GET 仍不落盘", file_digest(legacy_path) == digest_before)

        # 后续成功原子写（注册新版本）把迁移结果持久化
        st, _ = register("did:web:m-c", 1, P(), headers=LH)
        assert st == 201
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    persisted = json.loads(Path(legacy_path).read_text(encoding="utf-8"))
    persisted_hist = persisted["tenants"]["disc-legacy"]["trust_anchor_history"]
    persisted_cursors = persisted.get("trust_anchor_history_cursors", {})
    check(
        "成功原子写后补录历史与游标已持久化，新游标在其后递增",
        persisted_cursors.get("disc-legacy") == 5
        and persisted_hist["did:web:m-c"][0]["cursor"] == 5,
    )
    proc = start_server(PORT, legacy_path)
    try:
        st, pg = discover("limit=200", headers=LH)
        check(
            "持久化后重启补录游标保持不变",
            [(i["did"], i["key_version"], i["cursor"])
             for i in pg["anchors"]][:3]
            == [
                ("did:web:m-a", 1, 1),
                ("did:web:m-a", 2, 3),
                ("did:web:m-b", 1, 4),
            ],
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 11. 部分缺历史：已有有效游标复用，仅缺失项新分配 ----
    partial_path = tempfile.mktemp(suffix=".json")
    proc = start_server(PORT, partial_path)
    PH = {"X-Tenant-ID": "disc-partial"}
    try:
        pa, pb = P(), P()
        assert register("did:web:p-a", 1, pa, headers=PH)[0] == 201
        assert register("did:web:p-b", 1, pb, headers=PH)[0] == 201
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    raw = json.loads(Path(partial_path).read_text(encoding="utf-8"))
    # 仅删除 p-a 的历史；p-b 的 cursor=2 保留，游标计数器顶字段也删除
    raw["tenants"]["disc-partial"]["trust_anchor_history"]["did:web:p-a"] = []
    raw.pop("trust_anchor_history_cursors", None)
    Path(partial_path).write_text(json.dumps(raw), encoding="utf-8")
    proc = start_server(PORT, partial_path)
    try:
        st, pg = discover("limit=200", headers=PH)
        check(
            "已有有效游标复用（p-b=2），缺失项按字典序补分配（p-a=3）",
            st == 200
            and [(i["did"], i["cursor"]) for i in pg["anchors"]]
            == [("did:web:p-b", 2), ("did:web:p-a", 3)],
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    proc = start_server(PORT, partial_path)
    try:
        st, pg = discover("limit=200", headers=PH)
        check(
            "部分补录无写重启同样稳定",
            [(i["did"], i["cursor"]) for i in pg["anchors"]]
            == [("did:web:p-b", 2), ("did:web:p-a", 3)],
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # ---- 12. 直连 store：落盘失败不部分写入，发现结果回滚一致 ----
    from vcbackend.store import VCStore

    direct_path = tempfile.mktemp(suffix=".json")
    store = VCStore(direct_path)
    d1 = P()
    rec, created = store.register_trust_anchor("rt", "did:web:r-a", d1, 1)
    assert created
    entries0, na0 = store.list_trust_anchor_entries("rt", 0, 200)
    cursor0 = store._trust_anchor_history_cursors.get("rt", 0)  # noqa: SLF001

    def _boom():
        raise OSError("模拟落盘失败")

    store._save_locked = _boom  # type: ignore[assignment]
    raised = False
    try:
        store.register_trust_anchor("rt", "did:web:r-b", P(), 1)
    except OSError:
        raised = True
    entries1, na1 = store.list_trust_anchor_entries("rt", 0, 200)
    check(
        "注册落盘失败：发现结果、游标均不部分写入",
        raised
        and [(e.did, e.cursor) for e in entries1]
        == [(e.did, e.cursor) for e in entries0]
        and na1 == na0
        and store._trust_anchor_history_cursors.get("rt", 0) == cursor0,  # noqa: SLF001,E501
    )

    raised = False
    try:
        store.rotate_trust_anchor("rt", "did:web:r-a", 1, P())
    except OSError:
        raised = True
    entries2, _ = store.list_trust_anchor_entries("rt", 0, 200)
    check(
        "轮换落盘失败同样不产生新游标项",
        raised and len(entries2) == len(entries0)
        and store._trust_anchor_history_cursors.get("rt", 0) == cursor0,  # noqa: SLF001,E501
    )

    # 吊销落盘失败：cursor 与状态不变
    raised = False
    try:
        store.revoke_trust_anchor("rt", "did:web:r-a", 1)
    except OSError:
        raised = True
    entries3, _ = store.list_trust_anchor_entries("rt", 0, 200, "revoked")
    check(
        "吊销落盘失败：无 revoked 项、游标不前进",
        raised and entries3 == []
        and store._trust_anchor_history_cursors.get("rt", 0) == cursor0,  # noqa: SLF001,E501
    )

    del store._save_locked  # type: ignore[attr-defined]
    rec, created = store.register_trust_anchor("rt", "did:web:r-b", P(), 1)
    assert created
    entries4, na4 = store.list_trust_anchor_entries("rt", 0, 200)
    check(
        "恢复后成功写入，发现接口跨 DID 按游标返回",
        [(e.did, e.key_version, e.cursor) for e in entries4]
        == [("did:web:r-a", 1, cursor0), ("did:web:r-b", 1, cursor0 + 1)]
        and na4 == cursor0 + 1,
    )

    for path in (store_path, legacy_path, partial_path, direct_path):
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
