"""Small structlog-compatible fallback used by offline test/install baselines."""

from __future__ import annotations

import logging
from typing import Any


class _BoundLogger:
    def __init__(self, name: str | None = None) -> None:
        self._logger = logging.getLogger(name or "secret_leak_sentinel")

    def _log(self, level: int, event: str, **kwargs: Any) -> None:
        if kwargs:
            self._logger.log(level, "%s %s", event, kwargs)
        else:
            self._logger.log(level, "%s", event)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._log(logging.INFO, event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, event, **kwargs)


def get_logger(name: str | None = None) -> _BoundLogger:
    return _BoundLogger(name)
