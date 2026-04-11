"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  formatFindingMessage,
  normalizeFindings,
} = require("../src/scanPayload");

test("normalizeFindings ignores malformed entries", () => {
  const findings = normalizeFindings({
    findings: [
      { file_path: "/tmp/app.py", line_number: 12, detector_name: "aws_access_key_id" },
      { file_path: "/tmp/bad.py" },
      null,
    ],
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].file_path, "/tmp/app.py");
});

test("formatFindingMessage includes severity and detector context", () => {
  const message = formatFindingMessage({
    severity: "critical",
    detector_name: "aws_access_key_id",
    rationale: "Regex pattern matched in a production-looking file.",
  });

  assert.match(message, /\[CRITICAL\]/);
  assert.match(message, /aws_access_key_id/);
  assert.match(message, /production-looking file/);
});
