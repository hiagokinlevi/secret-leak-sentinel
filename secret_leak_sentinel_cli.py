"""Repository-unique console entrypoint for secret-leak-sentinel."""

from __future__ import annotations

import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).resolve().parent / "cli" / "main.py"
_SPEC = importlib.util.spec_from_file_location("secret_leak_sentinel_local_cli", _MODULE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Unable to load CLI module from {_MODULE_PATH}")

_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
cli = _MODULE.cli


def main() -> None:
    """Execute the repository-local Click CLI."""
    cli()


if __name__ == "__main__":
    main()
