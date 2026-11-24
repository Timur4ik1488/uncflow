import * as vscode from 'vscode';
import { Finding, AuditSummary, ScenarioTemplate } from '../types';

export class WorkspaceState {
  private static _instance: WorkspaceState;
  private _context?: vscode.ExtensionContext;
  private _findings: Finding[] = [];
  private _summary: AuditSummary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  private _selectedFinding?: Finding;
  private _lastScenarioId: string = 'template-full-audit';
  private _lastScenarioTitle: string = 'Комплексный аудит безопасности';
  private _templates: ScenarioTemplate[] = [];

  private _onFindingsUpdated = new vscode.EventEmitter<Finding[]>();
  public readonly onFindingsUpdated = this._onFindingsUpdated.event;

  private _onSelectedFindingChanged = new vscode.EventEmitter<Finding | undefined>();
  public readonly onSelectedFindingChanged = this._onSelectedFindingChanged.event;

  public static getInstance(): WorkspaceState {
    if (!WorkspaceState._instance) {
      WorkspaceState._instance = new WorkspaceState();
    }
    return WorkspaceState._instance;
  }

  public init(context: vscode.ExtensionContext) {
    this._context = context;
    this._lastScenarioId = context.workspaceState.get<string>('uncflow.lastScenarioId', 'template-full-audit');
    this._lastScenarioTitle = context.workspaceState.get<string>('uncflow.lastScenarioTitle', 'Комплексный аудит безопасности');
  }

  public get lastScenarioId(): string {
    return this._lastScenarioId;
  }

  public get lastScenarioTitle(): string {
    return this._lastScenarioTitle;
  }

  public async setLastScenario(id: string, title?: string) {
    this._lastScenarioId = id;
    if (title) this._lastScenarioTitle = title;
    if (this._context) {
      await this._context.workspaceState.update('uncflow.lastScenarioId', id);
      if (title) {
        await this._context.workspaceState.update('uncflow.lastScenarioTitle', title);
      }
    }
  }

  public get findings(): Finding[] {
    return this._findings;
  }

  public get summary(): AuditSummary {
    return this._summary;
  }

  public setFindings(findings: Finding[], summary?: AuditSummary) {
    this._findings = findings;
    if (summary) {
      this._summary = summary;
    } else {
      const crit = findings.filter(f => f.severity === 'CRITICAL').length;
      const high = findings.filter(f => f.severity === 'HIGH').length;
      const med = findings.filter(f => f.severity === 'MEDIUM').length;
      const low = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length;
      this._summary = {
        critical: crit,
        high: high,
        medium: med,
        low: low,
        total: findings.length
      };
    }
    this._selectedFinding = findings.length > 0 ? findings[0] : undefined;
    this._onFindingsUpdated.fire(this._findings);
    this._onSelectedFindingChanged.fire(this._selectedFinding);
  }

  public clearFindings() {
    this._findings = [];
    this._summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    this._selectedFinding = undefined;
    this._onFindingsUpdated.fire([]);
    this._onSelectedFindingChanged.fire(undefined);
  }

  public get selectedFinding(): Finding | undefined {
    return this._selectedFinding;
  }

  public setSelectedFinding(finding: Finding | undefined) {
    this._selectedFinding = finding;
    this._onSelectedFindingChanged.fire(finding);
  }

  public get templates(): ScenarioTemplate[] {
    return this._templates;
  }

  public setTemplates(templates: ScenarioTemplate[]) {
    this._templates = templates;
  }
}
