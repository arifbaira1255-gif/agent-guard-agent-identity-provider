"""Minimal protobuf wire codec for the SPIFFE Workload API messages (workload.proto).

Only what the Workload API needs: varint + length-delimited fields. Strict: any truncated or
unsupported encoding raises SvidError (-> DENY). Encoders are used by the dev/test Workload API.
"""
from typing import Dict, List, Tuple

from .errors import R, SvidError

MAX_MESSAGE = 4 * 1024 * 1024


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field_bytes(num: int, value: bytes) -> bytes:
    return _varint((num << 3) | 2) + _varint(len(value)) + value


def field_str(num: int, value: str) -> bytes:
    return field_bytes(num, value.encode())


def parse_fields(buf: bytes) -> List[Tuple[int, bytes]]:
    """Return [(field_number, payload_bytes)] for length-delimited fields; skip varints."""
    if len(buf) > MAX_MESSAGE:
        raise SvidError("message too large", R.MALFORMED)
    out, i, n = [], 0, len(buf)

    def rd_varint(i):
        shift = val = 0
        while True:
            if i >= n or shift > 63:
                raise SvidError("truncated varint", R.MALFORMED)
            b = buf[i]
            i += 1
            val |= (b & 0x7F) << shift
            if not b & 0x80:
                return val, i
            shift += 7

    while i < n:
        key, i = rd_varint(i)
        num, wt = key >> 3, key & 7
        if num == 0:
            raise SvidError("bad field number", R.MALFORMED)
        if wt == 0:
            _, i = rd_varint(i)
        elif wt == 2:
            ln, i = rd_varint(i)
            if i + ln > n:
                raise SvidError("truncated field", R.MALFORMED)
            out.append((num, buf[i:i + ln]))
            i += ln
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        else:
            raise SvidError("unsupported wire type", R.MALFORMED)
        if i > n:
            raise SvidError("truncated field", R.MALFORMED)
    return out


def _str(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        raise SvidError("invalid utf-8", R.MALFORMED)


def _map(entries: List[bytes]) -> Dict[str, bytes]:
    out = {}
    for e in entries:
        k = v = None
        for num, p in parse_fields(e):
            if num == 1:
                k = _str(p)
            elif num == 2:
                v = p
        if k is None or v is None:
            raise SvidError("bad map entry", R.MALFORMED)
        out[k] = v
    return out


# ---- decoders -------------------------------------------------------------------------
def decode_x509_svid_response(buf: bytes) -> dict:
    svids, fed = [], []
    for num, p in parse_fields(buf):
        if num == 1:
            s = {"spiffe_id": "", "x509_svid": b"", "x509_svid_key": b"", "bundle": b"", "hint": ""}
            for n2, p2 in parse_fields(p):
                if n2 == 1:
                    s["spiffe_id"] = _str(p2)
                elif n2 == 2:
                    s["x509_svid"] = p2
                elif n2 == 3:
                    s["x509_svid_key"] = p2
                elif n2 == 4:
                    s["bundle"] = p2
                elif n2 == 5:
                    s["hint"] = _str(p2)
            svids.append(s)
        elif num == 3:
            fed.append(p)
    return {"svids": svids, "federated_bundles": _map(fed)}


def decode_jwt_svid_response(buf: bytes) -> List[dict]:
    out = []
    for num, p in parse_fields(buf):
        if num == 1:
            s = {"spiffe_id": "", "svid": "", "hint": ""}
            for n2, p2 in parse_fields(p):
                if n2 == 1:
                    s["spiffe_id"] = _str(p2)
                elif n2 == 2:
                    s["svid"] = _str(p2)
                elif n2 == 3:
                    s["hint"] = _str(p2)
            out.append(s)
    return out


def decode_jwt_bundles_response(buf: bytes) -> Dict[str, bytes]:
    return _map([p for num, p in parse_fields(buf) if num == 1])


# ---- encoders (dev / test Workload API) -----------------------------------------------
def encode_x509_svid_response(svids: List[dict], federated: Dict[str, bytes] = None) -> bytes:
    out = b""
    for s in svids:
        m = (field_str(1, s["spiffe_id"]) + field_bytes(2, s["x509_svid"]) +
             field_bytes(3, s["x509_svid_key"]) + field_bytes(4, s["bundle"]))
        if s.get("hint"):
            m += field_str(5, s["hint"])
        out += field_bytes(1, m)
    for k, v in (federated or {}).items():
        out += field_bytes(3, field_str(1, k) + field_bytes(2, v))
    return out


def encode_jwt_svid_response(svids: List[dict]) -> bytes:
    return b"".join(field_bytes(1, field_str(1, s["spiffe_id"]) + field_str(2, s["svid"]))
                    for s in svids)


def encode_jwt_bundles_response(bundles: Dict[str, bytes]) -> bytes:
    return b"".join(field_bytes(1, field_str(1, k) + field_bytes(2, v)) for k, v in bundles.items())


def encode_jwt_svid_request(audience: List[str], spiffe_id: str = "") -> bytes:
    out = b"".join(field_str(1, a) for a in audience)
    return out + (field_str(2, spiffe_id) if spiffe_id else b"")


def decode_jwt_svid_request(buf: bytes) -> Tuple[List[str], str]:
    aud, sid = [], ""
    for num, p in parse_fields(buf):
        if num == 1:
            aud.append(_str(p))
        elif num == 2:
            sid = _str(p)
    return aud, sid


def decode_x509_bundles_response(buf: bytes) -> Dict[str, bytes]:
    return _map([p for num, p in parse_fields(buf) if num == 2])


def encode_x509_bundles_response(bundles: Dict[str, bytes]) -> bytes:
    return b"".join(field_bytes(2, field_str(1, k) + field_bytes(2, v)) for k, v in bundles.items())
