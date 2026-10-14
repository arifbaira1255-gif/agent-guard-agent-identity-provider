"""``std.random`` — deterministic-by-default random helpers for Happy."""

from __future__ import annotations

import random as _random
from typing import List, Sequence, TypeVar

T = TypeVar("T")

__all__ = [
    "seed",
    "random_float",
    "random_int",
    "random_bool",
    "choice",
    "shuffle",
    "sample",
    "random_token",
    "PUBLIC",
]

PUBLIC = [
    "seed",
    "random_float",
    "random_int",
    "random_bool",
    "choice",
    "shuffle",
    "sample",
    "random_token",
]


def seed(value: int) -> None:
    _random.seed(int(value))


def random_float() -> float:
    return _random.random()


def random_int(low: int, high: int) -> int:
    """A uniform integer in ``[low, high]`` (inclusive)."""
    return _random.randint(int(low), int(high))


def random_bool() -> bool:
    return _random.random() < 0.5


def choice(items: Sequence[T]) -> T:
    return _random.choice(list(items))


def shuffle(items: List[T]) -> List[T]:
    out = list(items)
    _random.shuffle(out)
    return out


def sample(items: Sequence[T], k: int) -> List[T]:
    return _random.sample(list(items), int(k))


def random_token(length: int = 16) -> str:
    import secrets

    return secrets.token_hex(max(1, int(length) // 2))
