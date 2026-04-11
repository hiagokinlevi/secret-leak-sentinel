/**
 * Extensão mínima do VS Code para executar o secret-leak-sentinel
 * no arquivo ativo e publicar diagnostics inline.
 */
"use strict";

const { execFile } = require("node:child_process");
const vscode = require("vscode");

const { formatFindingMessage, normalizeFindings } = require("./scanPayload");

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection("secretLeakSentinel");
  const output = vscode.window.createOutputChannel("Secret Leak Sentinel");

  context.subscriptions.push(diagnostics, output);

  const scanCommand = vscode.commands.registerCommand(
    "secretLeakSentinel.scanCurrentFile",
    async () => {
      const document = vscode.window.activeTextEditor && vscode.window.activeTextEditor.document;
      if (!document) {
        vscode.window.showInformationMessage("Open a file before running Secret Leak Sentinel.");
        return;
      }

      await scanDocument(document, diagnostics, output);
    }
  );

  const clearCommand = vscode.commands.registerCommand(
    "secretLeakSentinel.clearFindings",
    () => {
      diagnostics.clear();
      output.appendLine("Cleared Secret Leak Sentinel diagnostics.");
    }
  );

  const closeSubscription = vscode.workspace.onDidCloseTextDocument((document) => {
    diagnostics.delete(document.uri);
  });

  const saveSubscription = vscode.workspace.onDidSaveTextDocument(async (document) => {
    const config = vscode.workspace.getConfiguration("secretLeakSentinel");
    if (!config.get("runOnSave", false)) {
      return;
    }

    await scanDocument(document, diagnostics, output);
  });

  context.subscriptions.push(scanCommand, clearCommand, closeSubscription, saveSubscription);
}

async function scanDocument(document, diagnostics, output) {
  if (document.uri.scheme !== "file") {
    vscode.window.showWarningMessage("Secret Leak Sentinel can only scan files on disk.");
    return;
  }

  const config = vscode.workspace.getConfiguration("secretLeakSentinel");
  const binaryPath = config.get("binaryPath", "secret-leak-sentinel");
  const extraArgs = config.get("extraArgs", []);
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
  const args = ["scan-file", "--json-output", ...extraArgs, document.fileName];

  output.appendLine(`Scanning ${document.fileName}`);

  try {
    const payload = await runCliScan(binaryPath, args, workspaceFolder && workspaceFolder.uri.fsPath);
    const findings = normalizeFindings(payload).filter(
      (finding) => finding.file_path === document.fileName
    );
    const documentDiagnostics = findings.map((finding) =>
      buildDiagnostic(document, finding)
    );

    diagnostics.set(document.uri, documentDiagnostics);
    output.appendLine(
      `Secret Leak Sentinel found ${documentDiagnostics.length} finding(s) in ${document.fileName}.`
    );
  } catch (error) {
    diagnostics.delete(document.uri);
    const message = error instanceof Error ? error.message : String(error);
    output.appendLine(`Secret Leak Sentinel failed: ${message}`);
    vscode.window.showErrorMessage(`Secret Leak Sentinel failed: ${message}`);
  }
}

function runCliScan(binaryPath, args, cwd) {
  return new Promise((resolve, reject) => {
    execFile(
      binaryPath,
      args,
      {
        cwd,
        maxBuffer: 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (error && error.code !== 1) {
          reject(new Error(stderr || error.message));
          return;
        }

        try {
          resolve(JSON.parse(stdout));
        } catch (parseError) {
          const message = stderr || stdout || String(parseError);
          reject(new Error(`Could not parse scan-file JSON output: ${message}`));
        }
      }
    );
  });
}

function buildDiagnostic(document, finding) {
  const lineIndex = Math.max((finding.line_number || 1) - 1, 0);
  const safeLineIndex = Math.min(lineIndex, Math.max(document.lineCount - 1, 0));
  const line = document.lineAt(safeLineIndex);
  const startCharacter = line.firstNonWhitespaceCharacterIndex;
  const endCharacter = Math.max(startCharacter + 1, line.text.length);
  const range = new vscode.Range(safeLineIndex, startCharacter, safeLineIndex, endCharacter);

  const diagnostic = new vscode.Diagnostic(
    range,
    formatFindingMessage(finding),
    mapSeverity(finding.severity)
  );
  diagnostic.source = "secret-leak-sentinel";
  diagnostic.code = finding.detector_name || "secret-leak-sentinel";
  return diagnostic;
}

function mapSeverity(severity) {
  switch (severity) {
    case "critical":
      return vscode.DiagnosticSeverity.Error;
    case "high":
      return vscode.DiagnosticSeverity.Warning;
    case "medium":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
