import * as vscode from 'vscode';
import * as path from 'path';
import { Finding, FindingCategory } from '../types';
import { WorkspaceState } from '../state/workspace';

type TreeItemType = 'category' | 'finding';

export class FindingTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly itemType: TreeItemType,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly finding?: Finding,
    public readonly category?: FindingCategory
  ) {
    super(label, collapsibleState);

    if (itemType === 'category') {
      this.contextValue = 'category';
      if (category === 'SECRET') {
        this.iconPath = new vscode.ThemeIcon('key', new vscode.ThemeColor('errorForeground'));
      } else if (category === 'SCA') {
        this.iconPath = new vscode.ThemeIcon('package', new vscode.ThemeColor('charts.orange'));
      } else {
        this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.red'));
      }
    } else if (finding) {
      this.contextValue = 'finding';
      this.description = finding.severity;
      this.tooltip = new vscode.MarkdownString(
        `### uncflow: ${finding.class || finding.advisoryId || finding.category}\n` +
        `**Уровень:** \`${finding.severity}\`\n\n` +
        `**Файл:** \`${finding.path}:${finding.line || 1}\`\n\n` +
        `${finding.description || ''}\n\n` +
        (finding.remediation ? `💡 **Рекомендация:** ${finding.remediation}` : '')
      );

      // Set icons based on severity
      if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
        this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      } else if (finding.severity === 'MEDIUM') {
        this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
      } else {
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

export class FindingsTreeProvider implements vscode.TreeDataProvider<FindingTreeItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<FindingTreeItem | undefined | null | void> =
    new vscode.EventEmitter<FindingTreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<FindingTreeItem | undefined | null | void> =
    this._onDidChangeTreeData.event;

  private state = WorkspaceState.getInstance();

  constructor() {
    this.state.onFindingsUpdated(() => {
      this.refresh();
    });
  }

  public refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingTreeItem): Thenable<FindingTreeItem[]> {
    const findings = this.state.findings;
    if (!findings || findings.length === 0) {
      return Promise.resolve([]);
    }

    if (!element) {
      // Root level: return categories that have findings
      const categories: { cat: FindingCategory; title: string }[] = [
        { cat: 'SECRET', title: '🔑 Утечки секретов (Secrets)' },
        { cat: 'SCA', title: '📦 Уязвимости зависимостей (SCA)' },
        { cat: 'SAST', title: '🛡️ Уязвимости в исходном коде (SAST)' }
      ];

      const items: FindingTreeItem[] = [];
      for (const c of categories) {
        const count = findings.filter(f => f.category === c.cat).length;
        if (count > 0) {
          const item = new FindingTreeItem(
            `${c.title} (${count})`,
            'category',
            vscode.TreeItemCollapsibleState.Expanded,
            undefined,
            c.cat
          );
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
