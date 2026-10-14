"""Password hashing (stdlib ``hashlib.scrypt``) with a PHC-style, self-describing string format.

* No plaintext passwords are ever stored, logged, or returned.
* Salt is 16 random bytes per password; the parameters are embedded so they can be raised later and
  old hashes still verify (upgrade-on-login is possible via ``needs_rehash``).
* ``verify`` is constant-time (``hmac.compare_digest``) and never raises on malformed input.
* A memory-hard KDF (scrypt) is used; ``n`` is capped so a hostile stored hash cannot cause a
  denial-of-service via an enormous work factor (``maxmem`` is bounded).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# Tuned for the sandbox/tests but still memory-hard; production guidance in docs/STEP8_AUTH.md.
DEFAULT_N = 2 ** 14        # 16384
DEFAULT_R = 8
DEFAULT_P = 1
DKLEN = 32
SALT_BYTES = 16
_MAX_N = 2 ** 20           # refuse absurd stored parameters (DoS guard)
_MAX_MEM = 512 * 1024 * 1024

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 1024  # refuse unbounded input (KDF DoS guard)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password: str, *, n: int = DEFAULT_N, r: int = DEFAULT_R, p: int = DEFAULT_P) -> str:
    """Return a PHC-style string: ``$scrypt$n=..,r=..,p=..$<b64 salt>$<b64 hash>``."""
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
        raise ValueError("password length out of range")
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=DKLEN,
                        maxmem=_maxmem(n, r))
    return f"$scrypt$n={n},r={r},p={p}${_b64(salt)}${_b64(dk)}"


def _maxmem(n: int, r: int) -> int:
    # scrypt needs ~128*n*r bytes; give it head-room but keep it bounded.
    return min(_MAX_MEM, max(1024 * 1024, 128 * n * r * 2))


def _parse(encoded: str):
    if not isinstance(encoded, str) or not encoded.startswith("$scrypt$"):
        return None
    try:
        _, algo, params, salt_s, hash_s = encoded.split("$")
        kv = dict(x.split("=") for x in params.split(","))
        n, r, p = int(kv["n"]), int(kv["r"]), int(kv["p"])
        if not (1 < n <= _MAX_N) or not (0 < r <= 64) or not (0 < p <= 16):
            return None
        salt, expected = _unb64(salt_s), _unb64(hash_s)
        if len(salt) < 8 or len(expected) < 16:
            return None
        return n, r, p, salt, expected
    except Exception:
        return None


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification. Returns False on any malformed input (never raises)."""
    if not isinstance(password, str) or not password or len(password) > PASSWORD_MAX_LENGTH:
        return False
    parsed = _parse(encoded)
    if parsed is None:
        return False
    n, r, p, salt, expected = parsed
    try:
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected),
                            maxmem=_maxmem(n, r))
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(dk, expected)


def needs_rehash(encoded: str, *, n: int = DEFAULT_N, r: int = DEFAULT_R, p: int = DEFAULT_P) -> bool:
    parsed = _parse(encoded)
    if parsed is None:
        return True
    return (parsed[0], parsed[1], parsed[2]) != (n, r, p)


def password_policy_error(password: str) -> str | None:
    """Return a human-readable policy violation, or None if acceptable.

    Policy: >= 12 chars, at least three of {lower, upper, digit, symbol}, no whitespace-only,
    and not an obvious repeated/sequential pattern. Deliberately does NOT impose composition
    rules strong enough to push users toward predictable substitutions.
    """
    if not isinstance(password, str):
        return "password must be a string"
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"password must be at least {PASSWORD_MIN_LENGTH} characters"
    if len(password) > PASSWORD_MAX_LENGTH:
        return "password is too long"
    if password != password.strip():
        return "password must not begin or end with whitespace"
    classes = sum(bool(c) for c in (
        any(ch.islower() for ch in password),
        any(ch.isupper() for ch in password),
        any(ch.isdigit() for ch in password),
        any(not ch.isalnum() for ch in password),
    ))
    if classes < 3:
        return "password must include at least three of: lowercase, uppercase, digit, symbol"
    lowered = password.lower()
    for seq in ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"):
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in lowered:
                return "password must not contain long sequential runs"
    if len(set(password)) < 5:
        return "password is too repetitive"
    return None
