import * as vscode from 'vscode';
import axios from 'axios';

let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('vsh');
  context.subscriptions.push(diagnosticCollection);

  const analyzeFileCmd = vscode.commands.registerCommand('vsh.analyzeFile', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    const filePath = editor.document.uri.fsPath;
    await analyzeFile(filePath);
  });

  const analyzeWorkspaceCmd = vscode.commands.registerCommand('vsh.analyzeWorkspace', async () => {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) return;
    const projectPath = workspaceFolder.uri.fsPath;
    await analyzeProject(projectPath);
  });

  context.subscriptions.push(analyzeFileCmd, analyzeWorkspaceCmd);

  // Optional watch on save
  if (vscode.workspace.getConfiguration('vsh').get('watchOnSave')) {
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === 'python') {
        await analyzeFile(doc.uri.fsPath);
      }
    });
  }
}

async function analyzeFile(filePath: string) {
  const apiUrl = vscode.workspace.getConfiguration('vsh').get('apiUrl') as string;
  try {
    const res = await axios.post(`${apiUrl}/scan/file`, { path: filePath });
    updateDiagnostics(res.data.findings);
  } catch (e) {
    vscode.window.showErrorMessage('VSH scan failed');
  }
}

async function analyzeProject(projectPath: string) {
  const apiUrl = vscode.workspace.getConfiguration('vsh').get('apiUrl') as string;
  try {
    const res = await axios.post(`${apiUrl}/scan/project`, { path: projectPath });
    updateDiagnostics(res.data.findings);
  } catch (e) {
    vscode.window.showErrorMessage('VSH scan failed');
  }
}

function updateDiagnostics(findings: any[]) {
  diagnosticCollection.clear();
  const diagnostics: { [file: string]: vscode.Diagnostic[] } = {};

  for (const f of findings) {
    const uri = vscode.Uri.file(f.file);
    if (!diagnostics[f.file]) diagnostics[f.file] = [];
    const severity = f.severity === 'CRITICAL' ? vscode.DiagnosticSeverity.Error :
                     f.severity === 'HIGH' ? vscode.DiagnosticSeverity.Warning :
                     vscode.DiagnosticSeverity.Information;
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(f.line - 1, 0, f.end_line - 1, 100),
      f.message,
      severity
    );
    diagnostic.code = f.rule_id;
    diagnostics[f.file].push(diagnostic);
  }

  for (const file in diagnostics) {
    diagnosticCollection.set(vscode.Uri.file(file), diagnostics[file]);
  }
}

export function deactivate() {}