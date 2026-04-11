/**
 * Utilitários de payload para a extensão do VS Code.
 * Mantém a lógica de mensagem e normalização separada do runtime do editor
 * para facilitar testes locais simples com Node.
 */
"use strict";

function normalizeFindings(payload) {
  if (!payload || !Array.isArray(payload.findings)) {
    return [];
  }

  return payload.findings.filter((finding) => {
    return finding && typeof finding.file_path === "string" && Number.isInteger(finding.line_number);
  });
}

function formatFindingMessage(finding) {
  const severity = String(finding.severity || "unknown").toUpperCase();
  const detector = finding.detector_name || "unknown_detector";
  const rationale = finding.rationale || "No classifier rationale was provided.";
  return `[${severity}] ${detector}: ${rationale}`;
}

module.exports = {
  formatFindingMessage,
  normalizeFindings,
};
