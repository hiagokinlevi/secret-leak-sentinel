from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Optional

import click


# NOTE: Existing imports/functions omitted for brevity in this task-focused patch context.
# Keep existing module behavior; only scan-path hidden traversal wiring is added.


def _iter_scan_files(
    root: Path,
    exclude: Optional[Iterable[str]] = None,
    allowed_extensions: Optional[Iterable[str]] = None,
    include_hidden: bool = False,
):
    exclude = set(exclude or [])
    allowed_extensions = set(allowed_extensions or [])

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        rel = path.relative_to(root)
        rel_parts = rel.parts

        if not include_hidden and any(part.startswith(".") for part in rel_parts):
            continue

        rel_str = rel.as_posix()
        if rel_str in exclude:
            continue

        if allowed_extensions and path.suffix not in allowed_extensions:
            continue

        yield path


@click.group()
def cli():
    pass


@cli.command("scan-path")
@click.argument("scan_path", type=click.Path(path_type=Path, exists=True, file_okay=False, dir_okay=True))
@click.option("--exclude", multiple=True, help="Relative file paths to exclude from scanning.")
@click.option("--ext", "exts", multiple=True, help="Allowed file extensions (e.g. --ext .py --ext .env)")
@click.option(
    "--include-hidden",
    is_flag=True,
    default=False,
    help="Include hidden files/directories (dotfiles) during traversal.",
)
@click.option("--json-output", type=click.Path(path_type=Path), default=None)
def scan_path(scan_path: Path, exclude: List[str], exts: List[str], include_hidden: bool, json_output: Optional[Path]):
    files = list(
        _iter_scan_files(
            scan_path,
            exclude=exclude,
            allowed_extensions=exts,
            include_hidden=include_hidden,
        )
    )

    # Preserve existing output contract style (compact for this patch)
    payload = {"scanned_files": [str(p) for p in files], "count": len(files)}
    if json_output:
        json_output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    click.echo(json.dumps(payload))


if __name__ == "__main__":
    cli()
