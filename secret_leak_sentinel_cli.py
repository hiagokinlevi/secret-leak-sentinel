from __future__ import annotations

import re
from pathlib import Path

import click

try:
    from importlib.metadata import PackageNotFoundError, version as metadata_version
except Exception:  # pragma: no cover
    PackageNotFoundError = Exception  # type: ignore[assignment]
    metadata_version = None  # type: ignore[assignment]


SEMVER_FALLBACK = "0.0.0"


def _read_version_from_pyproject() -> str | None:
    pyproject_path = Path(__file__).resolve().parent / "pyproject.toml"
    if not pyproject_path.exists():
        return None
    content = pyproject_path.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']\s*$', content, flags=re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip()


def get_cli_version() -> str:
    if metadata_version is not None:
        for package_name in ("secret-leak-sentinel", "secret_leak_sentinel"):
            try:
                value = metadata_version(package_name)
                if value:
                    return value
            except PackageNotFoundError:
                continue
    return _read_version_from_pyproject() or SEMVER_FALLBACK


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=get_cli_version(), prog_name="secret-leak-sentinel")
def cli() -> None:
    """secret-leak-sentinel CLI."""


if __name__ == "__main__":
    cli()
