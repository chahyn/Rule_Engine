from __future__ import annotations

from typing import Any

_MISSING = object()


def escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def build(*tokens: Any) -> str:
    return "".join("/" + escape(str(t)) for t in tokens)


def resolve(doc: Any, pointer: str, default: Any = None) -> Any:
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        return default
    cur = doc
    for raw in pointer[1:].split("/"):
        token = unescape(raw)
        if isinstance(cur, dict):
            cur = cur.get(token, _MISSING)
        elif isinstance(cur, list) and token.isdigit() and int(token) < len(cur):
            cur = cur[int(token)]
        else:
            return default
        if cur is _MISSING:
            return default
    return cur
