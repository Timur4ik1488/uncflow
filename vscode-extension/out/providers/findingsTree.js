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
exports.FindingsTreeProvider = exports.FindingTreeItem = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const workspace_1 = require("../state/workspace");
class FindingTreeItem extends vscode.TreeItem {
    label;
    itemType;
    collapsibleState;
    finding;
    category;
    constructor(label, itemType, collapsibleState, finding, category) {
        super(label, collapsibleState);
        this.label = label;
        this.itemType = itemType;
        this.collapsibleState = collapsibleState;
        this.finding = finding;
        this.category = category;
        if (itemType === 'category') {
            this.contextValue = 'category';
            if (category === 'SECRET') {
                this.iconPath = new vscode.ThemeIcon('key', new vscode.ThemeColor('errorForeground'));
            }
            else if (category === 'SCA') {
                this.iconPath = new vscode.ThemeIcon('package', new vscode.ThemeColor('charts.orange'));
            }
            else {
                this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.red'));
            }
        }
        else if (finding) {
            this.contextValue = 'finding';
            this.description = finding.severity;
            this.tooltip = new vscode.MarkdownString(`### uncflow: ${finding.class || finding.advisoryId || finding.category}\n` +
                `**Уровень:** \`${finding.severity}\`\n\n` +
                `**Файл:** \`${finding.path}:${finding.line || 1}\`\n\n` +
                `${finding.description || ''}\n\n` +
                (finding.remediation ? `💡 **Рекомендация:** ${finding.remediation}` : ''));
            // Set icons based on severity
            if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
                this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            }
            else if (finding.severity === 'MEDIUM') {
                this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            }
            else {
                this.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            }
            // Command to open file on click
            const folders = vscode.workspace.workspaceFolders;
            if (folders && folders.length > 0 && finding.path) {
                const fullPath = path.resolve(folders[0].uri.fsPath, finding.path.replace(/\\/g, '/').replace(/^\/+/, ''));
                const line = Math.max(0, (finding.line ? Math.floor(finding.line) : 1) - 1);
                const endLine = finding.endLine ? Math.max(line, Math.floor(finding.endLine) - 1) : line;
                this.command = {
                    command: 'vscode.open',
                    title: 'Открыть файл с уязвимостью',
                    arguments: [
                        vscode.Uri.file(fullPath),
                        {
                            selection: new vscode.Range(line, 0, endLine, 100),
                            preview: true
                        }
                    ]
                };
            }
        }
    }
}
exports.FindingTreeItem = FindingTreeItem;
class FindingsTreeProvider {
    _onDidChangeTreeData = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChangeTreeData.event;
    state = workspace_1.WorkspaceState.getInstance();
    constructor() {
        this.state.onFindingsUpdated(() => {
            this.refresh();
        });
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        const findings = this.state.findings;
        if (!findings || findings.length === 0) {
            return Promise.resolve([]);
        }
        if (!element) {
            // Root level: return categories that have findings
            const categories = [
                { cat: 'SECRET', title: '🔑 Утечки секретов (Secrets)' },
                { cat: 'SCA', title: '📦 Уязвимости зависимостей (SCA)' },
                { cat: 'SAST', title: '🛡️ Уязвимости в исходном коде (SAST)' }
            ];
            const items = [];
            for (const c of categories) {
                const count = findings.filter(f => f.category === c.cat).length;
                if (count > 0) {
                    const item = new FindingTreeItem(`${c.title} (${count})`, 'category', vscode.TreeItemCollapsibleState.Expanded, undefined, c.cat);
                    items.push(item);
                }
            }
            return Promise.resolve(items);
        }
        if (element.itemType === 'category' && element.category) {
            const catFindings = findings.filter(f => f.category === element.category);
            const items = catFindings.map(f => {
                const fileBase = path.basename(f.path || 'unknown');
                const lineStr = f.line ? `:${f.line}` : '';
                const title = f.class || f.advisoryId || (f.group && f.artifact ? `${f.artifact}:${f.version}` : f.category);
                const label = `${title} (${fileBase}${lineStr})`;
                return new FindingTreeItem(label, 'finding', vscode.TreeItemCollapsibleState.None, f);
            });
            return Promise.resolve(items);
        }
        return Promise.resolve([]);
    }
}
exports.FindingsTreeProvider = FindingsTreeProvider;
//# sourceMappingURL=findingsTree.js.map