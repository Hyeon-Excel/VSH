import * as vscode from 'vscode';
import axios from 'axios';

let diagnosticCollection: vscode.DiagnosticCollection;
let currentPanel: vscode.WebviewPanel | undefined;

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

  const showDetailsCmd = vscode.commands.registerCommand('vsh.showDetails', async (finding: any) => {
    showWebviewPanel(finding);
  });

  context.subscriptions.push(analyzeFileCmd, analyzeWorkspaceCmd, showDetailsCmd);

  // Hover Provider
  const hoverProvider = vscode.languages.registerHoverProvider('python', {
    provideHover(document, position, token) {
      const diagnostics = diagnosticCollection.get(document.uri) || [];
      const lineDiagnostics = diagnostics.filter(d => d.range.start.line === position.line);
      if (lineDiagnostics.length > 0) {
        const diag = lineDiagnostics[0];
        const finding = diag.code as any; // Assume finding data
        return new vscode.Hover([
          `**Severity:** ${diag.severity === vscode.DiagnosticSeverity.Error ? 'CRITICAL' : 'HIGH'}`,
          `**Evidence:** ${diag.message}`,
          `**L2 Reasoning:** ${finding?.l2_reasoning?.reasoning || 'N/A'}`,
          `**Fix:** ${finding?.l2_reasoning?.fix_suggestion || 'N/A'}`
        ]);
      }
      return null;
    }
  });

  // Code Action Provider
  const codeActionProvider = vscode.languages.registerCodeActionsProvider('python', {
    provideCodeActions(document, range, context, token) {
      const actions: vscode.CodeAction[] = [];
      for (const diag of context.diagnostics) {
        if (diag.source === 'vsh') {
          const action = new vscode.CodeAction('Show VSH Details', vscode.CodeActionKind.QuickFix);
          action.command = {
            command: 'vsh.showDetails',
            title: 'Show Details',
            arguments: [diag.code] // finding data
          };
          actions.push(action);
        }
      }
      return actions;
    }
  });

  context.subscriptions.push(hoverProvider, codeActionProvider);

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
    diagnostic.source = 'vsh';
    diagnostic.code = f; // Store finding data
    diagnostics[f.file].push(diagnostic);
  }

  for (const file in diagnostics) {
    diagnosticCollection.set(vscode.Uri.file(file), diagnostics[file]);
  }
}

function showWebviewPanel(finding: any) {
  if (currentPanel) {
    currentPanel.reveal(vscode.ViewColumn.One);
  } else {
    currentPanel = vscode.window.createWebviewPanel(
      'vshDetails',
      'VSH Finding Details',
      vscode.ViewColumn.One,
      {}
    );

    currentPanel.webview.html = getWebviewContent(finding);

    currentPanel.onDidDispose(() => {
      currentPanel = undefined;
    }, null);
  }
}

function getWebviewContent(finding: any) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VSH Details</title>
    </head>
    <body>
        <h1>Finding Details</h1>
        <p><strong>File:</strong> ${finding.file}</p>
        <p><strong>Line:</strong> ${finding.line}</p>
        <p><strong>Severity:</strong> ${finding.severity}</p>
        <p><strong>Message:</strong> ${finding.message}</p>
        <h2>L2 Reasoning</h2>
        <p>${finding.l2_reasoning.reasoning}</p>
        <p><strong>Fix:</strong> ${finding.l2_reasoning.fix_suggestion}</p>
        <h2>L3 Validation</h2>
        <p>Validated: ${finding.l3_validation.validated}</p>
        <p>Exploit Possible: ${finding.l3_validation.exploit_possible}</p>
    </body>
    </html>
  `;
}

export function deactivate() {}