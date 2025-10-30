"""Shared asyncio runner for executing provider coroutines in background."""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from typing import Awaitable, Optional, TypeVar

_T = TypeVar("_T")


class AsyncRunner:
    """Manage a background asyncio event loop on a dedicated thread."""

    def __init__(self, *, name: str = "ScoutAsyncRunner") -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name=name, daemon=True)
        self._started = threading.Event()
        self._shutdown_lock = threading.Lock()
        self._shutdown_future: Optional[concurrent.futures.Future[None]] = None
        self._closing = False
        self._thread.start()
        self._started.wait()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._started.set()
        try:
            self._loop.run_forever()
        finally:
            try:
                pending = asyncio.all_tasks(loop=self._loop)
            except RuntimeError:
                pending = set()
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.close()
            asyncio.set_event_loop(None)

    def submit(self, coro: Awaitable[_T]) -> concurrent.futures.Future[_T]:
        """Submit a coroutine to the background loop."""

        if self._closing:
            raise RuntimeError("Async runner is shutting down")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    def run(self, coro: Awaitable[_T]) -> _T:
        """Run a coroutine on the background loop and return its result."""

        return self.submit(coro).result()

    def shutdown(self, *, timeout: float | None = None) -> None:
        """Synchronously shut down the background loop."""

        future = self._initiate_shutdown()
        try:
            future.result(timeout=timeout)
        finally:
            self._thread.join(timeout)

    def _initiate_shutdown(self) -> concurrent.futures.Future[None]:
        with self._shutdown_lock:
            if self._shutdown_future is None:
                self._closing = True
                self._shutdown_future = asyncio.run_coroutine_threadsafe(
                    self._shutdown_coroutine(), self._loop
                )
        return self._shutdown_future

    async def _shutdown_coroutine(self) -> None:
        loop = asyncio.get_running_loop()
        tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        loop.stop()


_runner: Optional[AsyncRunner] = None
_runner_lock = threading.Lock()


def get_shared_async_runner() -> AsyncRunner:
    """Return the shared async runner instance, creating it on demand."""

    global _runner
    if _runner is None:
        with _runner_lock:
            if _runner is None:
                _runner = AsyncRunner()
    return _runner


def shutdown_shared_async_runner(*, timeout: float | None = None) -> None:
    """Shutdown the shared async runner if it exists."""

    global _runner
    runner = _runner
    if runner is None:
        return
    runner.shutdown(timeout=timeout)
    _runner = None

