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
exports.DiagnosticsManager = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
class DiagnosticsManager {
    _collection;
    constructor() {
        this._collection = vscode.languages.createDiagnosticCollection('uncflow');
    }
    get collection() {
        return this._collection;
    }
    clear() {
        this._collection.clear();
    }
    applyFindings(findings, workspaceRoot) {
        this._collection.clear();
        const diagnosticsByFile = new Map();
        for (const finding of findings) {
            if (!finding.path)
                continue;
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
            }
            else if (finding.severity === 'LOW' || finding.severity === 'INFO') {
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
            diagnostic.finding = finding;
            const list = diagnosticsByFile.get(uriKey) || [];
            list.push(diagnostic);
            diagnosticsByFile.set(uriKey, list);
        }
        for (const [uriKey, diags] of diagnosticsByFile.entries()) {
            this._collection.set(vscode.Uri.parse(uriKey), diags);
        }
    }
    dispose() {
        this._collection.dispose();
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
//# sourceMappingURL=diagnostics.js.map