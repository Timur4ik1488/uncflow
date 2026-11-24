"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.UncflowQuickFixProvider = void 0;
const vscode = __importStar(require("vscode"));
class UncflowQuickFixProvider {
    static providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];
    provideCodeActions(document, range, context, _token) {
        const actions = [];
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'uncflow')
                continue;
            const finding = diagnostic.finding;
            if (!finding)
                continue;
            // 1. Specific Remediation CodeAction with WorkspaceEdit
            if (finding.remediation) {
                let fixEdit;
                let fixTitle = `🛡️ uncflow: Исправить (${finding.class || finding.category})`;
                const fixAction = new vscode.CodeAction(fixTitle, vscode.CodeActionKind.QuickFix);
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
                        }
                        else if (document.languageId === 'python') {
                            replacement = `os.getenv("${envVarName}")`;
                        }
                        const newLine = `${parts[0]}= ${replacement}`;
                        edit.replace(document.uri, new vscode.Range(diagnostic.range.start.line, 0, diagnostic.range.start.line, lineText.length), newLine);
                        fixEdit = edit;
                        fixTitle = '🛡️ uncflow: Вынести секрет в переменную окружения';
                    }
                }
                else if (finding.category === 'SCA' && finding.artifact && finding.version) {
                    const fixedVersion = finding.fixedVersions?.find(version => version !== finding.version);
                    if (fixedVersion && lineText.includes(finding.version)) {
                        const newLine = lineText.replace(finding.version, fixedVersion);
                        edit.replace(document.uri, new vscode.Range(diagnostic.range.start.line, 0, diagnostic.range.start.line, lineText.length), newLine);
                        fixEdit = edit;
                        fixTitle = `🛡️ uncflow: Обновить ${finding.artifact} до ${fixedVersion}`;
                    }
                }
                else if (finding.class === 'credentialed-cors' || lineText.includes('allowCredentials(true)')) {
                    if (lineText.includes('allowCredentials(true)')) {
                        const newLine = lineText.replace('allowCredentials(true)', 'allowCredentials(false)');
                        edit.replace(document.uri, new vscode.Range(diagnostic.range.start.line, 0, diagnostic.range.start.line, lineText.length), newLine);
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
            const detailsAction = new vscode.CodeAction(`ℹ️ uncflow: Показать детальный AI-анализ уязвимости`, vscode.CodeActionKind.Empty);
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
exports.UncflowQuickFixProvider = UncflowQuickFixProvider;
//# sourceMappingURL=quickFix.js.map