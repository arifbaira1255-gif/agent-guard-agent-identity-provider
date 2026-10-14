"""Async execution and concurrency primitives for the Happy runtime.

Happy's ``async function`` / ``await`` are backed by a small, deterministic
scheduler built on top of Python's :mod:`asyncio`:

* :class:`Task` — a running ``Future<T>``. ``await task`` suspends the current
  Happy task until the task completes and yields its result.
* :class:`Channel` — a typed, buffered communication channel between tasks
  (``channel.send(x)`` / ``await channel.recv()``).
* :func:`spawn` — start a coroutine concurrently, returning a :class:`Task`.
* :func:`gather` / :func:`await_all` — run a list of tasks to completion.
* :func:`sleep` — suspend the current task for N seconds.
* :class:`Scheduler` — owns the event loop; generated programs enter through
  :meth:`Scheduler.run`.

The layer is intentionally asyncio-compatible so generated code reads like
normal Python while still giving Happy programs structured concurrency.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterable, List, Optional, Sequence, Tuple

from .errors import AsyncRuntimeError

__all__ = [
    "Task",
    "Channel",
    "Scheduler",
    "spawn",
    "gather",
    "await_all",
    "sleep",
    "run",
    "select",
]


class Task:
    """A concurrently running computation (Happy's ``Future<T>``).

    ``Task`` wraps an :class:`asyncio.Task` when created through :func:`spawn`
    inside a running scheduler; otherwise it stores the coroutine and starts it
    lazily on first ``await``.
    """

    __slots__ = ("name", "_aio", "_coro", "_started")

    def __init__(self, coro: Optional[Awaitable[Any]] = None, name: str = "task") -> None:
        self.name = name
        self._coro: Optional[Awaitable[Any]] = coro
        self._aio: Optional["asyncio.Task"] = None
        self._started = False

    # -- lifecycle ------------------------------------------------------
    def _ensure_started(self) -> "asyncio.Task":
        if self._aio is None:
            if self._coro is None:
                raise AsyncRuntimeError(
                    message=f"task '{self.name}' has no body to run", code="R5002"
                )
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError as exc:  # pragma: no cover - defensive
                raise AsyncRuntimeError(
                    message=f"task '{self.name}' started outside a scheduler",
                    code="R5003",
                    cause=exc,
                )
            self._aio = loop.create_task(self._coro, name=self.name)
            self._started = True
        return self._aio

    def __await__(self):
        aio = self._ensure_started()

        async def _await() -> Any:
            return await aio

        return _await().__await__()

    # -- queries --------------------------------------------------------
    @property
    def done(self) -> bool:
        return self._aio is not None and self._aio.done()

    @property
    def cancelled(self) -> bool:
        return self._aio is not None and self._aio.cancelled()

    def result_nowait(self) -> Any:
        if self._aio is None or not self._aio.done():
            raise AsyncRuntimeError(
                message=f"task '{self.name}' has not completed", code="R5004"
            )
        exc = self._aio.exception()
        if exc is not None:
            raise exc
        return self._aio.result()

    def cancel(self) -> None:
        if self._aio is not None and not self._aio.done():
            self._aio.cancel()


def spawn(coro: Awaitable[Any], name: str = "task") -> Task:
    """Start ``coro`` concurrently, returning a :class:`Task`."""
    task = Task(coro, name=name)
    task._ensure_started()
    return task


async def gather(tasks: Sequence[Task]) -> List[Any]:
    """Await every task in ``tasks`` and return their results in order."""
    results: List[Any] = []
    for t in tasks:
        results.append(await t)
    return results


#: Alias matching the language-level ``await_all`` builtin.
await_all = gather


async def sleep(seconds: float) -> None:
    """Suspend the current task for ``seconds``."""
    await asyncio.sleep(seconds)


class Channel:
    """A buffered channel between tasks (Go-style send / recv)."""

    __slots__ = ("_queue", "name", "_closed")

    def __init__(self, capacity: int = 0, name: str = "channel") -> None:
        self.name = name
        self._queue: "asyncio.Queue" = asyncio.Queue(maxsize=max(capacity, 0))
        self._closed = False

    async def send(self, value: Any) -> None:
        if self._closed:
            raise AsyncRuntimeError(
                message=f"send on closed channel '{self.name}'", code="R5005"
            )
        await self._queue.put(value)

    async def recv(self) -> Any:
        if self._closed and self._queue.empty():
            raise AsyncRuntimeError(
                message=f"recv on closed channel '{self.name}'", code="R5006"
            )
        return await self._queue.get()

    def try_recv(self) -> Optional[Any]:
        """Return a buffered value immediately, or ``None`` when empty."""
        if self._queue.empty():
            return None
        return self._queue.get_nowait()

    def close(self) -> None:
        self._closed = True

    @property
    def empty(self) -> bool:
        return self._queue.empty()

    @property
    def closed(self) -> bool:
        return self._closed

    def __len__(self) -> int:
        return self._queue.qsize()


async def select(channels: Sequence[Channel]) -> Tuple[int, Any]:
    """Return ``(index, value)`` for the first channel that yields a value."""
    if not channels:
        raise AsyncRuntimeError(message="select() needs at least one channel", code="R5007")

    async def _one(idx: int, ch: Channel) -> Tuple[int, Any]:
        return idx, await ch.recv()

    done, pending = await asyncio.wait(
        [asyncio.ensure_future(_one(i, c)) for i, c in enumerate(channels)],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for p in pending:
        p.cancel()
    winner = next(iter(done))
    return winner.result()


class Scheduler:
    """Owns the event loop used to run a Happy program."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def run(self, coro: Awaitable[Any]) -> Any:
        """Run ``coro`` to completion on a fresh event loop and return it."""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if running is not None:
            # Already inside a loop (e.g. driven by a test harness): hand the
            # coroutine back through a helper task on that loop.
            return running.run_until_complete(coro)  # pragma: no cover

        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                loop.close()
                self._loop = None


def run(coro: Awaitable[Any]) -> Any:
    """Convenience: run ``coro`` on a managed :class:`Scheduler`."""
    return Scheduler().run(coro)
