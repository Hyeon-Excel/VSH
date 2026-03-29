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

  const markReviewedCmd = vscode.commands.registerCommand('vsh.markReviewed', async (finding: any) => {
    // Remove the diagnostic for this finding
    const uri = vscode.Uri.file(finding.file);
    const currentDiagnostics = diagnosticCollection.get(uri) || [];
    const filteredDiagnostics = currentDiagnostics.filter(d => (d.code as any)?.id !== finding.id);
    diagnosticCollection.set(uri, filteredDiagnostics);
    vscode.window.showInformationMessage(`Finding marked as reviewed: ${finding.message}`);
  });

  context.subscriptions.push(analyzeFileCmd, analyzeWorkspaceCmd, showDetailsCmd, markReviewedCmd);

  // Hover Provider
  const hoverProvider = vscode.languages.registerHoverProvider('python', {
    provideHover(document, position, token) {
      const diagnostics = diagnosticCollection.get(document.uri) || [];
      const lineDiagnostics = diagnostics.filter(d => d.range.start.line === position.line);
      if (lineDiagnostics.length > 0) {
        const diag = lineDiagnostics[0];
        const finding = diag.code as any;
        const severityEmoji = diag.severity === vscode.DiagnosticSeverity.Error ? '🚨' : '⚠️';
        return new vscode.Hover([
          `${severityEmoji} **${diag.severity === vscode.DiagnosticSeverity.Error ? 'CRITICAL' : 'HIGH'}** - ${diag.message}`,
          '',
          `**Evidence:** ${finding?.evidence || 'N/A'}`,
          '',
          `**L2 Reasoning:** ${finding?.l2_reasoning?.reasoning || 'N/A'}`,
          `**Confidence:** ${finding?.l2_reasoning?.confidence ? Math.round(finding.l2_reasoning.confidence * 100) + '%' : 'N/A'}`,
          '',
          `**Attack Scenario:** ${finding?.l2_reasoning?.attack_scenario || 'N/A'}`,
          '',
          `**L3 Validation:** ${finding?.l3_validation?.validated ? '✅ Validated' : '❌ Not validated'}`,
          `**Exploit Possible:** ${finding?.l3_validation?.exploit_possible ? '🚨 YES' : '✅ NO'}`,
          '',
          `**Fix Suggestion:** ${finding?.l2_reasoning?.fix_suggestion || 'N/A'}`
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
          const finding = diag.code as any;
          
          // Show Details action
          const showDetailsAction = new vscode.CodeAction('🔍 Show VSH Details', vscode.CodeActionKind.QuickFix);
          showDetailsAction.command = {
            command: 'vsh.showDetails',
            title: 'Show Details',
            arguments: [finding]
          };
          actions.push(showDetailsAction);
          
          // Quick Fix action - insert as comment instead of replace
          if (finding?.l2_reasoning?.fix_suggestion) {
            const fixAction = new vscode.CodeAction('💡 Insert Fix Suggestion as Comment', vscode.CodeActionKind.QuickFix);
            const commentText = `# VSH Fix Suggestion:\n# ${finding.l2_reasoning.fix_suggestion.replace(/\n/g, '\n# ')}\n`;
            fixAction.edit = new vscode.WorkspaceEdit();
            fixAction.edit.insert(document.uri, new vscode.Position(diag.range.end.line + 1, 0), commentText);
            fixAction.diagnostics = [diag];
            actions.push(fixAction);
          }
          
          // Mark as reviewed action
          const markReviewedAction = new vscode.CodeAction('✅ Mark as Reviewed', vscode.CodeActionKind.QuickFix);
          markReviewedAction.command = {
            command: 'vsh.markReviewed',
            title: 'Mark as Reviewed',
            arguments: [finding]
          };
          actions.push(markReviewedAction);
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
                     f.severity === 'MEDIUM' ? vscode.DiagnosticSeverity.Warning :
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
    // Update content with new finding
    currentPanel.webview.html = getWebviewContent(finding);
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
  const severityColor = finding.severity === 'CRITICAL' ? '#ff4444' : '#ff8800';
  const vulnColor = finding.l2_reasoning.is_vulnerable ? '#ff4444' : '#44ff44';
  const exploitColor = finding.l3_validation.exploit_possible ? '#ff4444' : '#44ff44';
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VSH Finding Details</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
          .header { background-color: ${severityColor}; color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
          .section { background-color: white; padding: 15px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .l2-section { border-left: 4px solid #2196F3; }
          .l3-section { border-left: 4px solid #ff9800; }
          .vulnerable { color: ${vulnColor}; font-weight: bold; }
          .exploit { color: ${exploitColor}; font-weight: bold; }
          .code { background-color: #2d3748; color: #e2e8f0; padding: 10px; border-radius: 4px; font-family: Monaco, monospace; }
          .fix { background-color: #e8f5e8; padding: 10px; border-radius: 4px; border: 1px solid #44ff44; }
          .attack { background-color: #ffebee; padding: 10px; border-radius: 4px; border: 1px solid #ff4444; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 VSH Finding Details</h1>
            <h2>${finding.severity} - ${finding.rule_id}</h2>
        </div>
        
        <div class="section">
            <h3>📁 Basic Information</h3>
            <p><strong>File:</strong> ${finding.file}</p>
            <p><strong>Line:</strong> ${finding.line} - ${finding.end_line}</p>
            <p><strong>Message:</strong> ${finding.message}</p>
            <p><strong>Evidence:</strong> ${finding.evidence}</p>
            <p><strong>Reachability:</strong> ${finding.reachability_status} (${Math.round(finding.reachability_confidence * 100)}%)</p>
        </div>
        
        <div class="section l2-section">
            <h3>🧠 L2 Reasoning (AI Analysis)</h3>
            <p><strong>Vulnerable:</strong> <span class="vulnerable">${finding.l2_reasoning.is_vulnerable ? 'YES' : 'NO'}</span></p>
            <p><strong>Confidence:</strong> ${Math.round(finding.l2_reasoning.confidence * 100)}%</p>
            <p><strong>Reasoning:</strong></p>
            <div class="code">${finding.l2_reasoning.reasoning}</div>
            <p><strong>Attack Scenario:</strong></p>
            <div class="attack">${finding.l2_reasoning.attack_scenario}</div>
            <p><strong>Fix Suggestion:</strong></p>
            <div class="fix">${finding.l2_reasoning.fix_suggestion}</div>
        </div>
        
        <div class="section l3-section">
            <h3>🔬 L3 Validation (Deep Analysis)</h3>
            <p><strong>Validated:</strong> ${finding.l3_validation.validated ? 'YES' : 'NO'}</p>
            <p><strong>Exploit Possible:</strong> <span class="exploit">${finding.l3_validation.exploit_possible ? 'YES - EXPLOITABLE!' : 'NO'}</span></p>
            <p><strong>Confidence:</strong> ${Math.round(finding.l3_validation.confidence * 100)}%</p>
            <p><strong>Evidence:</strong></p>
            <div class="code">${finding.l3_validation.evidence}</div>
            <p><strong>Recommended Fix:</strong></p>
            <div class="fix">${finding.l3_validation.recommended_fix}</div>
        </div>
    </body>
    </html>
  `;
}

export function deactivate() {}