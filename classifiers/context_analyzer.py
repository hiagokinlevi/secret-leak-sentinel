"""
Context Analyzer
================
Avalia o contexto de arquivo de um finding para ajustar confiança e severidade
sem depender apenas do padrão detectado. O objetivo é explicitar sinais como:

- arquivos de documentação e exemplos, que tendem a gerar falso positivo;
- diretórios de teste e fixtures, onde credenciais sintéticas são comuns;
- armazenamentos vivos de segredos, como `.env` e arquivos de chave;
- pipelines de CI/CD, onde o vazamento costuma ter alto impacto operacional.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


_SAMPLE_CONTEXT_PATTERNS = {
    "test",
    "tests",
    "spec",
    "specs",
    "fixtures",
    "sample",
    "samples",
    "example",
    "examples",
    "demo",
}

_DOCUMENTATION_CONTEXT_PATTERNS = {
    "docs",
    "documentation",
    "guides",
    "tutorial",
    "tutorials",
    "runbooks",
}

_HIGH_RISK_EXTENSIONS = {".env", ".pem", ".key", ".p12", ".pfx", ".secret"}
_LOW_RISK_EXTENSIONS = {".md", ".rst", ".txt", ".html", ".svg"}
_DOTENV_EXAMPLE_MARKERS = {"example", "examples", "sample", "samples", "template", "templates"}
_CI_PIPELINE_FILENAMES = {
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "jenkinsfile",
    "bitbucket-pipelines.yml",
    "bitbucket-pipelines.yaml",
    "buildkite.yml",
    "buildkite.yaml",
}


@dataclass(frozen=True)
class ContextAssessment:
    """Representa os sinais de contexto usados na classificação."""

    labels: tuple[str, ...]
    confidence_delta: float
    promote_high_to_critical: bool
    demote_critical_to_high: bool
    is_penalty: bool
    is_escalation: bool
    rationale_parts: tuple[str, ...]


def _path_parts_lower(file_path: str) -> set[str]:
    """Normaliza as partes do caminho para comparação sem case sensitivity."""
    return {part.lower() for part in Path(file_path).parts}


def _file_extension(file_path: str) -> str:
    """Retorna a extensão do arquivo em lowercase."""
    return Path(file_path).suffix.lower()


def _is_sample_context(file_path: str) -> bool:
    """Indica se o caminho parece pertencer a testes, fixtures ou exemplos."""
    return bool(_path_parts_lower(file_path).intersection(_SAMPLE_CONTEXT_PATTERNS))


def _is_documentation_context(file_path: str) -> bool:
    """Indica se o caminho parece pertencer a documentação ou tutoriais."""
    return bool(_path_parts_lower(file_path).intersection(_DOCUMENTATION_CONTEXT_PATTERNS))


def _is_dotenv_family_file(file_path: str) -> bool:
    """Retorna True para arquivos dotenv vivos, mas não para placeholders."""
    name = Path(file_path).name.lower()
    if not name:
        return False

    is_dotenv_name = (
        name == ".env"
        or name.startswith(".env.")
        or name.endswith(".env")
    )
    if not is_dotenv_name:
        return False

    parts = [part for part in name.split(".") if part]
    if any(part in _DOTENV_EXAMPLE_MARKERS for part in parts):
        return False
    return True


def _is_live_secret_store(file_path: str) -> bool:
    """Indica se o arquivo se parece com um armazenamento vivo de segredo."""
    return _file_extension(file_path) in _HIGH_RISK_EXTENSIONS or _is_dotenv_family_file(file_path)


def _is_ci_pipeline_context(file_path: str) -> bool:
    """Retorna True para caminhos clássicos de pipeline e automação."""
    path = Path(file_path)
    parts = tuple(part.lower() for part in path.parts)
    name = path.name.lower()

    if ".github" in parts and "workflows" in parts:
        return True
    if ".circleci" in parts:
        return True
    return name in _CI_PIPELINE_FILENAMES


def analyze_context(file_path: str) -> ContextAssessment:
    """Analisa o contexto do arquivo e retorna ajustes recomendados."""
    labels: list[str] = []
    rationale_parts: list[str] = []
    confidence_delta = 0.0
    promote_high_to_critical = False
    demote_critical_to_high = False
    is_penalty = False
    is_escalation = False

    if _is_live_secret_store(file_path):
        labels.append("live_secret_store")
        confidence_delta += 0.10
        promote_high_to_critical = True
        is_escalation = True
        rationale_parts.append(
            f"High-risk file context ({Path(file_path).name}) escalates confidence."
        )

    if _is_ci_pipeline_context(file_path):
        labels.append("ci_pipeline")
        confidence_delta += 0.05
        is_escalation = True
        rationale_parts.append(
            "CI pipeline context suggests the secret would impact automation paths quickly."
        )

    if _file_extension(file_path) in _LOW_RISK_EXTENSIONS:
        labels.append("documentation_extension")
        confidence_delta -= 0.15
        is_penalty = True
        rationale_parts.append(
            f"Low-risk file type ({_file_extension(file_path)}): likely documentation; confidence reduced."
        )

    if _is_documentation_context(file_path):
        labels.append("documentation_path")
        confidence_delta -= 0.10
        is_penalty = True
        rationale_parts.append(
            "Documentation-oriented path context suggests example-oriented content."
        )

    if _is_sample_context(file_path):
        labels.append("sample_or_test")
        confidence_delta -= 0.20
        demote_critical_to_high = True
        is_penalty = True
        rationale_parts.append(
            "File is in a test or sample directory; credential may be synthetic."
        )

    return ContextAssessment(
        labels=tuple(labels),
        confidence_delta=confidence_delta,
        promote_high_to_critical=promote_high_to_critical,
        demote_critical_to_high=demote_critical_to_high,
        is_penalty=is_penalty,
        is_escalation=is_escalation,
        rationale_parts=tuple(rationale_parts),
    )
