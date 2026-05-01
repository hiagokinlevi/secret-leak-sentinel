from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Pattern


@dataclass(frozen=True)
class DetectorPattern:
    id: str
    description: str
    regex: Pattern[str]
    file_globs: tuple[str, ...] = ()
    allowlist_values: tuple[str, ...] = ()


# Existing patterns (trimmed for brevity in this task-focused change).
PATTERN_REGISTRY: list[DetectorPattern] = [
    DetectorPattern(
        id="dotenv_assignment_secret",
        description="Detects secret-like dotenv/config assignments such as API_KEY=..., DATABASE_URL=..., TOKEN=...",
        regex=re.compile(
            r"""(?imx)
            ^\s*
            (?:export\s+)?
            (?P<name>[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD|DATABASE_URL|DB_URL|API_KEY|ACCESS_KEY|PRIVATE_KEY))
            \s*=\s*
            (?P<value>[^\n#]*)
            """
        ),
        file_globs=(
            ".env",
            ".env.*",
            "*.env",
            "*.env.*",
            "*.ini",
            "*.cfg",
            "*.conf",
            "*.properties",
            "config.*",
            "settings.*",
        ),
        allowlist_values=(
            "",
            "changeme",
            "change_me",
            "example",
            "example_value",
            "your_value_here",
            "your_token_here",
            "your_api_key_here",
            "<redacted>",
            "<secret>",
            "placeholder",
            "dummy",
            "test",
            "null",
            "none",
        ),
    ),
]


def _matches_glob(path: str, globs: Iterable[str]) -> bool:
    p = Path(path)
    name = p.name
    return any(p.match(g) or Path(name).match(g) for g in globs)


def should_evaluate_pattern_for_file(pattern: DetectorPattern, file_path: str) -> bool:
    if not pattern.file_globs:
        return True
    return _matches_glob(file_path, pattern.file_globs)


def is_allowlisted_assignment_value(pattern: DetectorPattern, raw_value: str) -> bool:
    value = raw_value.strip().strip('"\'').strip()
    lower = value.lower()
    return lower in {v.lower() for v in pattern.allowlist_values}
