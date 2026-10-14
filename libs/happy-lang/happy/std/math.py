"""``std.math`` — mathematical functions for Happy."""

from __future__ import annotations

import math as _math

__all__ = [
    "pi",
    "e",
    "tau",
    "inf",
    "nan",
    "abs_val",
    "sqrt",
    "cbrt",
    "pow",
    "floor",
    "ceil",
    "round_val",
    "min_val",
    "max_val",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "atan2",
    "log",
    "log2",
    "log10",
    "exp",
    "hypot",
    "clamp",
    "sign",
    "gcd",
    "PUBLIC",
]

PUBLIC = [
    "pi",
    "e",
    "tau",
    "inf",
    "nan",
    "abs_val",
    "sqrt",
    "cbrt",
    "pow",
    "floor",
    "ceil",
    "round_val",
    "min_val",
    "max_val",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "atan2",
    "log",
    "log2",
    "log10",
    "exp",
    "hypot",
    "clamp",
    "sign",
    "gcd",
]

pi = _math.pi
e = _math.e
tau = _math.tau
inf = _math.inf
nan = _math.nan


def abs_val(x: float) -> float:
    return abs(x)


def sqrt(x: float) -> float:
    return _math.sqrt(x)


def cbrt(x: float) -> float:
    return _math.copysign(abs(x) ** (1.0 / 3.0), x)


def pow(base: float, exponent: float) -> float:
    return _math.pow(base, exponent)


def floor(x: float) -> int:
    return _math.floor(x)


def ceil(x: float) -> int:
    return _math.ceil(x)


def round_val(x: float, digits: int = 0) -> float:
    return round(x, digits)


def min_val(a, b):
    return a if a <= b else b


def max_val(a, b):
    return a if a >= b else b


def sin(x: float) -> float:
    return _math.sin(x)


def cos(x: float) -> float:
    return _math.cos(x)


def tan(x: float) -> float:
    return _math.tan(x)


def asin(x: float) -> float:
    return _math.asin(x)


def acos(x: float) -> float:
    return _math.acos(x)


def atan(x: float) -> float:
    return _math.atan(x)


def atan2(y: float, x: float) -> float:
    return _math.atan2(y, x)


def log(x: float, base: float = _math.e) -> float:
    return _math.log(x, base)


def log2(x: float) -> float:
    return _math.log2(x)


def log10(x: float) -> float:
    return _math.log10(x)


def exp(x: float) -> float:
    return _math.exp(x)


def hypot(x: float, y: float) -> float:
    return _math.hypot(x, y)


def clamp(x: float, low: float, high: float) -> float:
    if low > high:
        low, high = high, low
    return max(low, min(high, x))


def sign(x: float) -> int:
    return (x > 0) - (x < 0)


def gcd(a: int, b: int) -> int:
    return _math.gcd(int(a), int(b))
