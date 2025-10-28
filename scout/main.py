"""Main entry point for orchestrating Scout services."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from collections.abc import Sequence
from dataclasses import replace

from .backend_client import BackendClient
from .database_manager import DatabaseManager
from .featured_scout import FeaturedScout, _load_config_from_env
from .pro_scout import DEFAULT_DB_PATH, ProScout

LOGGER = logging.getLogger(__name__)


class ScoutApp:
    """Facade that wires ProScout and FeaturedScout around a shared database."""

    def __init__(
        self,
        *,
        database: DatabaseManager,
        pro_scout: ProScout,
        featured_scout: FeaturedScout,
        backend_client: BackendClient,
    ) -> None:
        self.database = database
        self.pro_scout = pro_scout
        self.featured_scout = featured_scout
        self.backend_client = backend_client
        self._running = False
        self._closed = False

    @classmethod
    def from_env(cls) -> "ScoutApp":
        """Construct the application from environment configuration."""

        db_path = os.environ.get("SCOUT_DB_PATH") or os.environ.get("DB_PATH") or DEFAULT_DB_PATH
        database = DatabaseManager(db_path)
        featured_config = _load_config_from_env()
        api_base_url = os.environ.get("API_BASE_URL") or featured_config.api_root
        admin_access_token = featured_config.admin_token
        backend_client = BackendClient(api_base_url, admin_access_token)
        pro_scout = ProScout.from_env(database=database, backend_client=backend_client)
        if featured_config.db_path != db_path:
            featured_config = replace(featured_config, db_path=db_path)
        featured_scout = FeaturedScout(featured_config, database=database, backend_client=backend_client)
        return cls(
            database=database,
            pro_scout=pro_scout,
            featured_scout=featured_scout,
            backend_client=backend_client,
        )

    def __enter__(self) -> "ScoutApp":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001, D401 - standard context manager signature
        self.shutdown()

    def start(self) -> None:
        """Start the background services."""

        if self._running:
            raise RuntimeError("ScoutApp already running")
        self.pro_scout.start()
        self.featured_scout.start()
        self._running = True

    def stop(self, timeout: float = 10.0) -> None:
        """Stop background services."""

        self.featured_scout.stop(timeout=timeout)
        self.pro_scout.stop(timeout=timeout)
        self._running = False

    def shutdown(self) -> None:
        """Stop services if needed and close the shared database."""

        if self._closed:
            return
        if self._running:
            self.stop()
        self.database.close()
        self.backend_client.close()
        self._closed = True

    def run(self) -> None:
        """Run both services until interrupted."""

        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            LOGGER.info("Shutdown requested via keyboard interrupt")
        finally:
            self.shutdown()

    def status(self) -> str:
        """Summarize the last processed block for each service."""

        pro_value = self.database.get_meta("pro_last_block")
        featured_value = self.database.get_meta("featured_last_block")

        def _format(value: str | None) -> str:
            if value is None:
                return "unknown"
            try:
                return str(int(value))
            except ValueError:
                return value

        return (
            f"ProScout last block: {_format(pro_value)}; "
            f"FeaturedScout last block: {_format(featured_value)}"
        )


def _install_signal_handlers(app: ScoutApp, stop_event: threading.Event) -> None:
    def _handler(signum: int, frame) -> None:  # noqa: ANN001
        LOGGER.info("Signal received", extra={"signal": signum})
        stop_event.set()
        app.stop()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point used by ``python -m scout``."""

    parser = argparse.ArgumentParser(description="Scout command line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Run the Scout services")
    subparsers.add_parser("status", help="Show the current Scout status")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    with ScoutApp.from_env() as app:
        if args.command == "run":
            stop_event = threading.Event()
            _install_signal_handlers(app, stop_event)
            app.start()
            try:
                while not stop_event.is_set():
                    time.sleep(1)
            finally:
                app.shutdown()
            return 0

        if args.command == "status":
            print(app.status())
            return 0

    return 1


if __name__ == "__main__":  # pragma: no cover - convenience for direct execution
    raise SystemExit(main())
