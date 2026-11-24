import * as vscode from 'vscode';
import { Finding } from '../types';

export class UncflowQuickFixProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'uncflow') continue;

      const finding: Finding | undefined = (diagnostic as any).finding;
      if (!finding) continue;

      // 1. Specific Remediation CodeAction with WorkspaceEdit
      if (finding.remediation) {
        let fixEdit: vscode.WorkspaceEdit | undefined;
        let fixTitle = `🛡️ uncflow: Исправить (${finding.class || finding.category})`;

        const fixAction = new vscode.CodeAction(
          fixTitle,
          vscode.CodeActionKind.QuickFix
        );
        fixAction.diagnostics = [diagnostic];

        const edit = new vscode.WorkspaceEdit();
        const lineText = document.lineAt(diagnostic.range.start.line).text;

        if (finding.category === 'SECRET') {
          // Hardcoded secret replacement suggestion
          if (lineText.includes('=')) {
            const parts = lineText.split('=');
            const varName = parts[0].trim().replace(/[^a-zA-Z0-9_]/g, '');
            const envVarName = varName.toUpperCase();
            let replacement = `System.getenv("${envVarName}")`;
            if (document.languageId === 'kotlin') {
              replacement = `System.getenv("${envVarName}") ?: ""`;
            } else if (document.languageId === 'python') {
              replacement = `os.getenv("${envVarName}")`;
            }
            const newLine = `${parts[0]}= ${replacement}`;
            edit.replace(
              document.uri,
              new vscode.Range(diagnostic.range.start.line, 0, diagnostic.range.start.line, lineText.length),
              newLine
            );
            fixEdit = edit;
            fixTitle = '🛡️ uncflow: Вынести секрет в переменную окружения';
          }
        } else if (finding.category === 'SCA' && finding.artifact && finding.version) {
          const fixedVersion = finding.fixedVersions?.find(version => version !== finding.version);
          if (fixedVersion && lineText.includes(finding.version)) {
            const newLine = lineText.replace(finding.version, fixedVersion);
            edit.replace(
              document.uri,
              new vscode.Range(diagnostic.range.start.line, 0, diagnostic.range.start.line, lineText.length),
              newLine
            );
            fixEdit = edit;
            fixTitle = `🛡️ uncflow: Обновить ${finding.artifact} до ${fixedVersion}`;
          }
        } else if (finding.class === 'credentialed-cors' || lineText.includes('allowCredentials(true)')) {
          if (lineText.includes('allowCredentials(true)')) {
            const newLine = lineText.replace('allowCredentials(true)', 'allowCredentials(false)');
            edit.replace(
              document.uri,
              new vscode.Range(diagnostic.range.start.line, 0, diagnostic.range.start.line, lineText.length),
              newLine
            );
            fixEdit = edit;
            fixTitle = '🛡️ uncflow: Отключить небезопасный allowCredentials(true)';
          }
        }

        if (fixEdit) {
          fixAction.edit = fixEdit;
          fixAction.title = fixTitle;
          fixAction.isPreferred = true;
          actions.push(fixAction);
        }
      }

      // 2. Info Action: View details in Details panel
      const detailsAction = new vscode.CodeAction(
        `ℹ️ uncflow: Показать детальный AI-анализ уязвимости`,
        vscode.CodeActionKind.Empty
      );
      detailsAction.command = {
        command: 'uncflow.showFindingDetails',
        title: 'Детали уязвимости',
        arguments: [finding]
      };
      actions.push(detailsAction);
    }

    return actions;
  }
}
