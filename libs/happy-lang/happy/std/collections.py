"""``std.collections`` — list / map / set helpers for Happy.

Happy's ``List<T>`` is a Python ``list``, ``Map<K, V>`` a ``dict`` and
``Set<T>`` a ``set``; this module provides the functional vocabulary that a
Happy program expects on top of them.  All functions are pure (no effects, no
capabilities) and secret-aware where they render values.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

__all__ = [
    "push",
    "pop",
    "append",
    "insert",
    "remove",
    "contains",
    "index_of",
    "slice",
    "concat",
    "reverse",
    "sort",
    "sorted_by",
    "map_list",
    "filter_list",
    "reduce_list",
    "sum_list",
    "enumerate_list",
    "keys",
    "values",
    "entries",
    "get",
    "put",
    "has_key",
    "PUBLIC",
]

PUBLIC = [
    "push",
    "pop",
    "insert",
    "remove",
    "contains",
    "index_of",
    "slice",
    "concat",
    "reverse",
    "sort",
    "map_list",
    "filter_list",
    "reduce_list",
    "sum_list",
    "enumerate_list",
    "keys",
    "values",
    "entries",
    "get",
    "put",
    "has_key",
]


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------
def push(xs: List[Any], value: Any, __ctx__: Any = None) -> List[Any]:
    """Append ``value`` to ``xs`` in place and return ``xs``."""
    xs.append(value)
    return xs


#: Alias matching ``list.push``.
append = push


def pop(xs: List[Any], index: int = -1, __ctx__: Any = None) -> Any:
    """Remove and return the element at ``index`` (default: last)."""
    return xs.pop(index)


def insert(xs: List[Any], index: int, value: Any, __ctx__: Any = None) -> List[Any]:
    xs.insert(index, value)
    return xs


def remove(xs: List[Any], value: Any, __ctx__: Any = None) -> bool:
    """Remove the first occurrence of ``value``; return whether it existed."""
    try:
        xs.remove(value)
        return True
    except ValueError:
        return False


def contains(container: Any, value: Any, __ctx__: Any = None) -> bool:
    return value in container


def index_of(xs: Sequence[Any], value: Any, __ctx__: Any = None) -> int:
    try:
        return list(xs).index(value)
    except ValueError:
        return -1


def slice(xs: Sequence[Any], start: int, end: Optional[int] = None, __ctx__: Any = None) -> List[Any]:
    return list(xs[start:end] if end is not None else xs[start:])


def concat(a: Sequence[Any], b: Sequence[Any], __ctx__: Any = None) -> List[Any]:
    return list(a) + list(b)


def reverse(xs: Sequence[Any], __ctx__: Any = None) -> List[Any]:
    return list(reversed(list(xs)))


def sort(xs: Sequence[Any], descending: bool = False, __ctx__: Any = None) -> List[Any]:
    return sorted(xs, reverse=descending)


def sorted_by(
    xs: Sequence[Any], key: Callable[[Any], Any], descending: bool = False,
    __ctx__: Any = None,
) -> List[Any]:
    return sorted(xs, key=key, reverse=descending)


def map_list(
    xs: Sequence[Any], fn: Callable[[Any], Any], __ctx__: Any = None
) -> List[Any]:
    return [fn(x) for x in xs]


def filter_list(
    xs: Sequence[Any], pred: Callable[[Any], bool], __ctx__: Any = None
) -> List[Any]:
    return [x for x in xs if pred(x)]


def reduce_list(
    xs: Sequence[Any], fn: Callable[[Any, Any], Any], initial: Any = None,
    __ctx__: Any = None,
) -> Any:
    items = list(xs)
    if initial is None and not items:
        return None
    acc = initial if initial is not None else items.pop(0)
    for x in items:
        acc = fn(acc, x)
    return acc


def sum_list(xs: Sequence[Any], __ctx__: Any = None) -> Any:
    total: Any = 0
    for x in xs:
        total = total + x
    return total


def enumerate_list(xs: Sequence[Any], __ctx__: Any = None) -> List[Any]:
    return [[i, x] for i, x in enumerate(xs)]


# ---------------------------------------------------------------------------
# Maps
# ---------------------------------------------------------------------------
def keys(m: Dict[Any, Any], __ctx__: Any = None) -> List[Any]:
    return list(m.keys())


def values(m: Dict[Any, Any], __ctx__: Any = None) -> List[Any]:
    return list(m.values())


def entries(m: Dict[Any, Any], __ctx__: Any = None) -> List[Any]:
    return [[k, v] for k, v in m.items()]


def get(m: Dict[Any, Any], key: Any, default: Any = None, __ctx__: Any = None) -> Any:
    return m.get(key, default)


def put(m: Dict[Any, Any], key: Any, value: Any, __ctx__: Any = None) -> Dict[Any, Any]:
    m[key] = value
    return m


def has_key(m: Dict[Any, Any], key: Any, __ctx__: Any = None) -> bool:
    return key in m
