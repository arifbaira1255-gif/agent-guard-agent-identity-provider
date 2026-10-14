import time


class Clock:
    """Injectable time source (epoch seconds)."""

    def now(self) -> float:
        return time.time()


class FixedClock(Clock):
    """Deterministic clock for tests."""

    def __init__(self, start: float = 1_800_000_000.0):
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds
