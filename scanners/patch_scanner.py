"""
Scanner de patchs unificados.
================================
Converte um diff unificado em blocos por arquivo contendo apenas linhas
adicionadas e reaproveita os detectores já existentes do projeto.

Esse módulo existe para o caso de uso de `pre-push`: queremos inspecionar
somente o conteúdo novo que está prestes a sair do repositório local, sem
reativar falsos positivos em linhas removidas do patch.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from detectors.entropy_detector import EntropyFinding, scan_content_for_entropy
from detectors.regex_detector import Finding, scan_content


_HUNK_HEADER_RE = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@"
)


@dataclass
class PatchFileContent:
    """Representa o conteúdo adicionado de um único arquivo dentro do patch."""

    file_path: str
    content: str


@dataclass(frozen=True)
class PatchAddedLine:
    """Representa uma linha adicionada com a numeração final do arquivo."""

    file_path: str
    line_number: int
    content: str


def _normalize_patch_path(raw_path: str) -> str:
    """Normaliza o caminho vindo dos headers `+++` de um diff unificado."""
    candidate = raw_path.strip().split("\t", 1)[0]
    if candidate == "/dev/null":
        return ""
    if candidate.startswith(("a/", "b/")):
        return candidate[2:]
    return candidate


def extract_added_lines(patch_text: str) -> list[PatchAddedLine]:
    """Extrai linhas adicionadas com a posição final no arquivo de destino."""
    added_lines: list[PatchAddedLine] = []
    current_path = ""
    in_hunk = False
    current_new_line = 0

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            current_path = ""
            in_hunk = False
            continue

        if line.startswith("--- "):
            in_hunk = False
            continue

        if line.startswith("+++ "):
            current_path = _normalize_patch_path(line[4:])
            continue

        if line.startswith("@@"):
            match = _HUNK_HEADER_RE.match(line)
            in_hunk = match is not None and bool(current_path)
            if in_hunk and match is not None:
                current_new_line = int(match.group("start"))
            continue

        if not in_hunk or not current_path:
            continue

        if line.startswith("\\ No newline at end of file"):
            continue

        if line.startswith("+") and not line.startswith("+++ "):
            added_lines.append(
                PatchAddedLine(
                    file_path=current_path,
                    line_number=current_new_line,
                    content=line[1:],
                )
            )
            current_new_line += 1
            continue

        if line.startswith(" "):
            current_new_line += 1
            continue

        if line.startswith("-"):
            continue

    return added_lines


def extract_added_file_contents(patch_text: str) -> list[PatchFileContent]:
    """Extrai, por arquivo, apenas as linhas adicionadas de um patch unificado."""
    file_buffers: dict[str, list[str]] = {}
    for added_line in extract_added_lines(patch_text):
        file_buffers.setdefault(added_line.file_path, []).append(added_line.content)

    return [
        PatchFileContent(file_path=file_path, content="\n".join(lines))
        for file_path, lines in file_buffers.items()
        if lines
    ]


def scan_patch_content(
    patch_text: str,
    entropy_enabled: bool = True,
    entropy_threshold: float = 4.5,
) -> tuple[list[Finding], list[EntropyFinding]]:
    """Executa os detectores do projeto sobre o conteúdo adicionado do patch."""
    regex_findings: list[Finding] = []
    entropy_findings: list[EntropyFinding] = []

    for added_line in extract_added_lines(patch_text):
        line_regex_findings = scan_content(added_line.content, added_line.file_path)
        for finding in line_regex_findings:
            finding.line_number = added_line.line_number
        regex_findings.extend(line_regex_findings)

        if entropy_enabled:
            line_entropy_findings = scan_content_for_entropy(
                added_line.content,
                added_line.file_path,
                threshold=entropy_threshold,
            )
            for finding in line_entropy_findings:
                finding.line_number = added_line.line_number
            entropy_findings.extend(line_entropy_findings)

    return regex_findings, entropy_findings


def scan_patch_file(
    file_path: str | Path,
    entropy_enabled: bool = True,
    entropy_threshold: float = 4.5,
) -> tuple[list[Finding], list[EntropyFinding]]:
    """Lê um arquivo de patch do disco e o escaneia em modo added-lines-only."""
    patch_text = Path(file_path).read_text(encoding="utf-8", errors="replace")
    return scan_patch_content(
        patch_text,
        entropy_enabled=entropy_enabled,
        entropy_threshold=entropy_threshold,
    )
