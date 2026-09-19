"""RFC6901 JSON Pointer 解析、路径校验与选择性披露投影。

选择性披露的路径规则（在凭证 claims 属性内）：
- 指针必须为字符串、非空且以 ``/`` 开头（根指针 ``""`` 表示零披露，
  由调用方以空 disclose 列表表达，不作为单条路径出现）；
- token 按 RFC6901 反转义（``~1`` -> ``/``、``~0`` -> ``~``），
  非法转义（``~`` 后非 0/1）拒绝；
- 路径必须命中 claims 中的属性：找不到键即越界；
- 禁止数组索引（claims 内不允许进入数组）；
- 同一语义路径不得重复，且任意两条路径不得构成祖先/后代重叠。
"""

from typing import Any, Dict, List, Tuple

__all__ = ["PointerError", "parse_pointer", "validate_paths", "project"]


class PointerError(ValueError):
    """披露路径不合法。"""


def _unescape_token(token: str) -> str:
    # RFC6901：先还原 ~1 再还原 ~0；~ 后必须紧跟 0 或 1。
    out: List[str] = []
    i = 0
    while i < len(token):
        ch = token[i]
        if ch == "~":
            if i + 1 >= len(token) or token[i + 1] not in "01":
                raise PointerError(f"JSON Pointer 含非法转义: {token!r}")
            out.append("/" if token[i + 1] == "1" else "~")
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def parse_pointer(pointer: Any) -> List[str]:
    """把 RFC6901 指针解析为 token 序列。

    根指针（""）与非字符串、非 "/" 开头的指针一律拒绝。
    """
    if not isinstance(pointer, str):
        raise PointerError("披露路径必须为字符串")
    if pointer == "":
        raise PointerError("禁止根路径：零披露请使用空数组 []")
    if not pointer.startswith("/"):
        raise PointerError(
            f"披露路径必须以 / 开头: {pointer!r}"
        )
    # "/a/b" -> ["", "a", "b"]；首段为空（根），其余为原始 token。
    raw_tokens = pointer.split("/")[1:]
    return [_unescape_token(tok) for tok in raw_tokens]


def _navigate(claims: Dict[str, Any], tokens: List[str]) -> Any:
    """沿 tokens 在 claims 内导航并返回叶子值，校验命中与无数组索引。"""
    node: Any = claims
    for depth, token in enumerate(tokens):
        if isinstance(node, list):
            # claims 内不允许进入数组：不支持数组索引。
            raise PointerError(
                f"披露路径不支持数组索引: {'/' + '/'.join(tokens[: depth + 1])}"
            )
        if not isinstance(node, dict):
            raise PointerError(
                f"披露路径无法继续解析（中间值不是对象）: {token!r}"
            )
        if token not in node:
            raise PointerError(
                f"披露路径越界，claims 中不存在: {token!r}"
            )
        node = node[token]
    return node


def validate_paths(
    paths: Any, claims: Dict[str, Any]
) -> Tuple[List[str], List[List[str]]]:
    """校验 disclose 列表，返回 (回显原文列表, 解析后的 token 列表)。

    校验：数组类型、逐条指针合法、命中 claims、无数组索引、无重复、
    无祖先重叠。空数组合法（零披露）。
    """
    if not isinstance(paths, list):
        raise PointerError("字段 disclose 必须为数组")

    originals: List[str] = []
    token_lists: List[List[str]] = []
    seen = set()
    for raw in paths:
        tokens = parse_pointer(raw)
        _navigate(claims, tokens)
        key = tuple(tokens)
        if key in seen:
            raise PointerError(f"disclose 含重复路径: {raw}")
        seen.add(key)
        originals.append(raw)
        token_lists.append(tokens)

    # 祖先重叠：任一条 token 序列是另一条的严格前缀。
    for i, ancestor in enumerate(token_lists):
        for j, descendant in enumerate(token_lists):
            if i == j or len(ancestor) >= len(descendant):
                continue
            if tuple(descendant[: len(ancestor)]) == tuple(ancestor):
                raise PointerError(
                    "disclose 含祖先重叠路径: "
                    f"{originals[i]} 与 {originals[j]}"
                )
    return originals, token_lists


def project(
    claims: Dict[str, Any], token_lists: List[List[str]]
) -> Dict[str, Any]:
    """按 token 序列在 claims 上构造仅含所选值的投影。

    空列表返回 {}（零披露）。调用方须先用 validate_paths 排除祖先重叠，
    因此中间对象不会与叶子标量冲突。
    """
    projected: Dict[str, Any] = {}
    for tokens in token_lists:
        value = _navigate(claims, tokens)
        node = projected
        for token in tokens[:-1]:
            existing = node.get(token)
            if not isinstance(existing, dict):
                existing = {}
                node[token] = existing
            node = existing
        node[tokens[-1]] = value
    return projected
