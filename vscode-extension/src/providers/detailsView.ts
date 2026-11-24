import * as vscode from 'vscode';
import * as path from 'path';
import { WorkspaceState } from '../state/workspace';
import { Finding } from '../types';

export class DetailsViewProvider implements vscode.WebviewViewProvider {
  private _view?: vscode.WebviewView;
  private state = WorkspaceState.getInstance();

  constructor(private readonly extensionUri: vscode.Uri) {
    this.state.onSelectedFindingChanged(finding => {
      this.updateView(finding);
    });

    this.state.onFindingsUpdated(() => {
      this.updateView(this.state.selectedFinding);
    });
  }

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this.extensionUri]
    };

    webviewView.webview.onDidReceiveMessage(async data => {
      if (data.command === 'openFile' && data.path) {
        const folders = vscode.workspace.workspaceFolders;
        if (folders && folders.length > 0) {
          const fullPath = path.resolve(folders[0].uri.fsPath, data.path.replace(/\\/g, '/').replace(/^\/+/, ''));
          const line = Math.max(0, (data.line || 1) - 1);
          const doc = await vscode.workspace.openTextDocument(fullPath);
          await vscode.window.showTextDocument(doc, {
            selection: new vscode.Range(line, 0, line, 100),
            preview: false
          });
        }
      } else if (data.command === 'runAudit') {
        vscode.commands.executeCommand('uncflow.runLastScenario');
      } else if (data.command === 'applyFix' && data.remediation) {
        vscode.window.showInformationMessage(`Рекомендация: ${data.remediation}`);
      }
    });

    this.updateView(this.state.selectedFinding);
  }

  private updateView(finding?: Finding) {
    if (!this._view) return;
    this._view.webview.html = this.getHtmlContent(finding);
  }

  private getHtmlContent(finding?: Finding): string {
    const summary = this.state.summary;

    if (!finding) {
      return `<!DOCTYPE html>
      <html lang="ru">
      <head>
        <meta charset="UTF-8">
        <style>
          body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            padding: 16px;
            margin: 0;
            background: transparent;
          }
          .card {
            border: 1px solid var(--vscode-widget-border, #333);
            background: var(--vscode-editor-background);
            border-radius: 8px;
            padding: 14px;
            text-align: center;
          }
          .title { font-size: 14px; font-weight: 600; margin-bottom: 8px; color: #38bdf8; }
          .desc { font-size: 12px; color: var(--vscode-descriptionForeground); margin-bottom: 14px; line-height: 1.4; }
          .btn {
            background: #0284c7;
            color: white;
            border: none;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
          }
          .btn:hover { background: #0369a1; }
          .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
            margin-top: 14px;
          }
          .stat-box {
            background: rgba(255, 255, 255, 0.04);
            border-radius: 6px;
            padding: 8px;
            text-align: center;
          }
          .stat-num { font-size: 18px; font-weight: bold; }
          .stat-lbl { font-size: 10px; opacity: 0.8; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="title">🛡️ uncflow Security Platform</div>
          <div class="desc">
            ${summary.total > 0 
              ? 'Выберите уязвимость в списке выше для просмотра рекомендаций AI.' 
              : 'Проект готов к проверке на утечки секретов, уязвимые зависимости и дефекты кода.'}
          </div>
          <button class="btn" onclick="vscode.postMessage({ command: 'runAudit' })">
            ▶ Запустить аудит проекта
          </button>
          ${summary.total > 0 ? `
            <div class="stat-grid">
              <div class="stat-box" style="border-left: 3px solid #ef4444;">
                <div class="stat-num" style="color: #ef4444;">${summary.critical}</div>
                <div class="stat-lbl">CRITICAL</div>
              </div>
              <div class="stat-box" style="border-left: 3px solid #f97316;">
                <div class="stat-num" style="color: #f97316;">${summary.high}</div>
                <div class="stat-lbl">HIGH</div>
              </div>
              <div class="stat-box" style="border-left: 3px solid #eab308;">
                <div class="stat-num" style="color: #eab308;">${summary.medium}</div>
                <div class="stat-lbl">MEDIUM</div>
              </div>
              <div class="stat-box" style="border-left: 3px solid #3b82f6;">
                <div class="stat-num" style="color: #3b82f6;">${summary.low}</div>
                <div class="stat-lbl">LOW</div>
              </div>
            </div>
          ` : ''}
        </div>
        <script>const vscode = acquireVsCodeApi();</script>
      </body>
      </html>`;
    }

    const severityColor =
      finding.severity === 'CRITICAL' ? '#ef4444' :
      finding.severity === 'HIGH' ? '#f97316' :
      finding.severity === 'MEDIUM' ? '#eab308' : '#3b82f6';

    const title = finding.class || finding.advisoryId || (finding.group && finding.artifact ? `${finding.artifact}:${finding.version}` : finding.category);

    return `<!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="UTF-8">
      <style>
        body {
          font-family: var(--vscode-font-family);
          color: var(--vscode-foreground);
          padding: 12px;
          margin: 0;
          line-height: 1.45;
          font-size: 12px;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 10px;
        }
        .badge {
          background: ${severityColor};
          color: white;
          font-size: 10px;
          font-weight: bold;
          padding: 2px 6px;
          border-radius: 4px;
          letter-spacing: 0.5px;
        }
        .cat-badge {
          background: rgba(255,255,255,0.1);
          color: var(--vscode-descriptionForeground);
          font-size: 10px;
          padding: 2px 6px;
          border-radius: 4px;
        }
        .vuln-title {
          font-size: 14px;
          font-weight: 600;
          color: var(--vscode-editor-foreground);
          margin-bottom: 8px;
        }
        .location {
          font-family: var(--vscode-editor-font-family, monospace);
          font-size: 11px;
          background: rgba(0,0,0,0.25);
          padding: 6px 8px;
          border-radius: 4px;
          border-left: 2px solid ${severityColor};
          cursor: pointer;
          margin-bottom: 12px;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .location:hover {
          background: rgba(255,255,255,0.06);
        }
        .section-lbl {
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          color: var(--vscode-descriptionForeground);
          font-weight: 600;
          margin-top: 12px;
          margin-bottom: 4px;
        }
        .desc-box {
          background: var(--vscode-editor-background);
          border: 1px solid var(--vscode-widget-border, #333);
          border-radius: 6px;
          padding: 10px;
          margin-bottom: 12px;
        }
        .ai-card {
          background: linear-gradient(135deg, rgba(56,189,248,0.08) 0%, rgba(139,92,246,0.08) 100%);
          border: 1px solid rgba(56,189,248,0.25);
          border-radius: 6px;
          padding: 10px;
          margin-top: 8px;
        }
        .ai-header {
          display: flex;
          align-items: center;
          gap: 6px;
          color: #38bdf8;
          font-weight: 600;
          font-size: 11px;
          margin-bottom: 6px;
        }
        .btn-link {
          color: #38bdf8;
          background: transparent;
          border: none;
          cursor: pointer;
          font-size: 11px;
          padding: 0;
          text-decoration: underline;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <span class="badge">${finding.severity}</span>
        <span class="cat-badge">${finding.category}</span>
      </div>

      <div class="vuln-title">${escapeHtml(title)}</div>

      <div class="location" onclick="vscode.postMessage({ command: 'openFile', path: '${escapeHtml(finding.path || '')}', line: ${finding.line || 1} })" title="Кликните, чтобы открыть в редакторе">
        <span>📄 ${escapeHtml(finding.path || '')}${finding.line ? `:${finding.line}` : ''}</span>
        <span style="font-size: 10px; opacity: 0.7;">Перейти ↗</span>
      </div>

      ${finding.description ? `
        <div class="section-lbl">Описание проблемы</div>
        <div class="desc-box">${escapeHtml(finding.description)}</div>
      ` : ''}

      ${finding.remediation ? `
        <div class="ai-card">
          <div class="ai-header">🤖 Рекомендация uncflow AI (GigaChat)</div>
          <div>${escapeHtml(finding.remediation)}</div>
        </div>
      ` : ''}

      <script>
        const vscode = acquireVsCodeApi();
      </script>
    </body>
    </html>`;
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
