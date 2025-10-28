"""Utility helpers for loading environment variables from .env files."""

from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Iterable

LOGGER = logging.getLogger(__name__)


def _iter_candidate_paths(explicit: str | os.PathLike[str] | None) -> Iterable[Path]:
    if explicit:
        yield Path(explicit)
    env_override = os.environ.get("SCOUT_ENV_FILE")
    if env_override:
        yield Path(env_override)
    cwd = Path.cwd() / ".env"
    yield cwd
    package_root = Path(__file__).resolve().parent.parent
    repo_env = package_root / ".env"
    if repo_env != cwd:
        yield repo_env


def _parse_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {'"', "'"} and value[-1] == value[0]:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value[1:-1]
    return value


_ENV_LOADED = False


def load_env_file(explicit_path: str | os.PathLike[str] | None = None) -> None:
    """Load environment variables from a .env file if present."""

    global _ENV_LOADED
    if _ENV_LOADED:
        return

    for candidate in _iter_candidate_paths(explicit_path):
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError:
            LOGGER.warning("Failed to read .env file", extra={"path": str(candidate)})
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            key, raw_value = stripped.split("=", 1)
            key = key.strip()
            if not key or key.startswith("#"):
                continue
            value = _parse_value(raw_value)
            os.environ.setdefault(key, value)
        LOGGER.debug("Loaded environment variables from %s", candidate)
        break

    _ENV_LOADED = True
