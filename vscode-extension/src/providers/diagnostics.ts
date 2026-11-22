import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { Finding } from '../types';

export class DiagnosticsManager {
  private _collection: vscode.DiagnosticCollection;

  constructor() {
    this._collection = vscode.languages.createDiagnosticCollection('uncflow');
  }

  public get collection(): vscode.DiagnosticCollection {
    return this._collection;
  }

  public clear() {
    this._collection.clear();
  }

  public applyFindings(findings: Finding[], workspaceRoot: string) {
    this._collection.clear();

    const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
      if (!finding.path) continue;

      const normalizedRelPath = finding.path.replace(/\\/g, '/').replace(/^\/+/, '');
      const fullPath = path.resolve(workspaceRoot, normalizedRelPath);

      const uri = vscode.Uri.file(fullPath);
      const uriKey = uri.toString();

      const lineNum = Math.max(0, (finding.line ? Math.floor(finding.line) : 1) - 1);
      const endLineNum = finding.endLine ? Math.max(lineNum, Math.floor(finding.endLine) - 1) : lineNum;

      const range = new vscode.Range(lineNum, 0, endLineNum, 200);

      let severity = vscode.DiagnosticSeverity.Warning;
      if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
        severity = vscode.DiagnosticSeverity.Error;
      } else if (finding.severity === 'LOW' || finding.severity === 'INFO') {
        severity = vscode.DiagnosticSeverity.Information;
      }

      const problemTitle = finding.class || finding.advisoryId || finding.category;
      let msg = `uncflow [${finding.severity}] ${problemTitle}`;
      if (finding.description) {
        msg += `\n${finding.description}`;
      }
      if (finding.remediation) {
        msg += `\n💡 Рекомендация: ${finding.remediation}`;
      }

      const diagnostic = new vscode.Diagnostic(range, msg, severity);
      diagnostic.source = 'uncflow';
      diagnostic.code = problemTitle;

      // Store finding in diagnostic for QuickFix provider
      (diagnostic as any).finding = finding;

      const list = diagnosticsByFile.get(uriKey) || [];
      list.push(diagnostic);
      diagnosticsByFile.set(uriKey, list);
    }

    for (const [uriKey, diags] of diagnosticsByFile.entries()) {
      this._collection.set(vscode.Uri.parse(uriKey), diags);
    }
  }

  public dispose() {
    this._collection.dispose();
  }
}
