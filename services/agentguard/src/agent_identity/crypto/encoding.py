import base64
import binascii
import json
import re

_B64U = re.compile(r"^[A-Za-z0-9_\-]*$")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64U.fullmatch(s):
        raise ValueError("invalid base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise ValueError("invalid base64url") from e


def canonical_json(obj) -> bytes:
    """Deterministic JSON bytes used for everything that gets signed or hashed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
