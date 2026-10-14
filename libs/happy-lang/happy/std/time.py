"""``std.time`` — time and timing helpers for Happy."""

from __future__ import annotations

import datetime as _dt
import time as _time

__all__ = [
    "now",
    "timestamp",
    "timestamp_ms",
    "monotonic",
    "sleep_ms",
    "sleep_seconds",
    "format_time",
    "parse_time",
    "year",
    "month",
    "day",
    "PUBLIC",
]

PUBLIC = [
    "now",
    "timestamp",
    "timestamp_ms",
    "monotonic",
    "sleep_ms",
    "sleep_seconds",
    "format_time",
    "parse_time",
    "year",
    "month",
    "day",
]


def now() -> str:
    """The current local time as an ISO-8601 string."""
    return _dt.datetime.now().isoformat()


def timestamp() -> int:
    return int(_time.time())


def timestamp_ms() -> int:
    return int(_time.time() * 1000)


def monotonic() -> float:
    return _time.monotonic()


def sleep_ms(milliseconds: int) -> None:
    _time.sleep(max(0, int(milliseconds)) / 1000.0)


def sleep_seconds(seconds: float) -> None:
    _time.sleep(max(0.0, float(seconds)))


def format_time(value: str, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    parsed = _dt.datetime.fromisoformat(value)
    return parsed.strftime(fmt)


def parse_time(value: str) -> str:
    return _dt.datetime.fromisoformat(value).isoformat()


def year() -> int:
    return _dt.datetime.now().year


def month() -> int:
    return _dt.datetime.now().month


def day() -> int:
    return _dt.datetime.now().day
