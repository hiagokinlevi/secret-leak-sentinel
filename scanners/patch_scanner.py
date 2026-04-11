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

from detectors.entropy_detector import EntropyFinding, scan_content_for_entropy
from detectors.regex_detector import Finding, scan_content


@dataclass
class PatchFileContent:
    """Representa o conteúdo adicionado de um único arquivo dentro do patch."""

    file_path: str
    content: str


def _normalize_patch_path(raw_path: str) -> str:
    """Normaliza o caminho vindo dos headers `+++` de um diff unificado."""
    candidate = raw_path.strip().split("\t", 1)[0]
    if candidate == "/dev/null":
        return ""
    if candidate.startswith(("a/", "b/")):
        return candidate[2:]
    return candidate


def extract_added_file_contents(patch_text: str) -> list[PatchFileContent]:
    """Extrai, por arquivo, apenas as linhas adicionadas de um patch unificado."""
    file_buffers: dict[str, list[str]] = {}
    current_path = ""
    in_hunk = False

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            continue

        if line.startswith("--- "):
            in_hunk = False
            continue

        if line.startswith("+++ "):
            current_path = _normalize_patch_path(line[4:])
            if current_path:
                file_buffers.setdefault(current_path, [])
            continue

        if line.startswith("@@"):
            in_hunk = True
            continue

        if not in_hunk or not current_path:
            continue

        if line.startswith("+") and not line.startswith("+++ "):
            file_buffers[current_path].append(line[1:])

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

    for patch_file in extract_added_file_contents(patch_text):
        regex_findings.extend(scan_content(patch_file.content, patch_file.file_path))
        if entropy_enabled:
            entropy_findings.extend(
                scan_content_for_entropy(
                    patch_file.content,
                    patch_file.file_path,
                    threshold=entropy_threshold,
                )
            )

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
