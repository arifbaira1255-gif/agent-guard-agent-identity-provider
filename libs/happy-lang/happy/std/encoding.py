"""``std.encoding`` — text / binary encoding helpers for Happy."""

from __future__ import annotations

import base64
import binascii
import json as _json
import urllib.parse

from ..runtime.errors import HappyRuntimeError

__all__ = [
    "base64_encode",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "url_encode",
    "url_decode",
    "utf8_encode",
    "utf8_decode",
    "json_encode",
    "json_decode",
    "PUBLIC",
]

PUBLIC = [
    "base64_encode",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "url_encode",
    "url_decode",
    "utf8_encode",
    "utf8_decode",
    "json_encode",
    "json_decode",
]


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(data: str) -> str:
    try:
        return base64.b64decode(data.encode("ascii")).decode(
            "utf-8", errors="replace"
        )
    except (binascii.Error, ValueError) as exc:
        raise HappyRuntimeError(
            message=f"invalid base64: {exc}", code="R5050"
        ) from exc


def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


def hex_decode(data: str) -> str:
    try:
        return bytes.fromhex(data).decode("utf-8", errors="replace")
    except ValueError as exc:
        raise HappyRuntimeError(message=f"invalid hex: {exc}", code="R5051") from exc


def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def url_decode(text: str) -> str:
    return urllib.parse.unquote(text)


def utf8_encode(text: str) -> bytes:
    return text.encode("utf-8")


def utf8_decode(data: bytes) -> str:
    return bytes(data).decode("utf-8", errors="replace")


def json_encode(value) -> str:
    return _json.dumps(value, ensure_ascii=False, sort_keys=True)


def json_decode(text: str):
    return _json.loads(text)
