import * as vscode from 'vscode';
import { Finding, AuditResult, ScenarioTemplate } from '../types';

export class UncflowClient {
  private authToken: string = '';

  constructor(private readonly context?: vscode.ExtensionContext) {}

  public async loadAuthToken(): Promise<void> {
    this.authToken = (await this.context?.secrets.get('uncflow.authToken')) || '';
  }

  public async setAuthToken(token: string): Promise<void> {
    this.authToken = token;
    if (this.context) {
      if (token) {
        await this.context.secrets.store('uncflow.authToken', token);
      } else {
        await this.context.secrets.delete('uncflow.authToken');
      }
    }
  }

  private getServerUrl(): string {
    const config = vscode.workspace.getConfiguration('uncflow');
    const rawUrl = config.get<string>('serverUrl', 'https://uncflow.duckdns.org');
    return rawUrl.trim().replace(/\/+$/, '');
  }

  private getAuthHeaders(): Record<string, string> {
    const config = vscode.workspace.getConfiguration('uncflow');
    const token = (this.authToken || config.get<string>('apiToken', '')).trim();
    const headers: Record<string, string> = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      headers['X-CI-Token'] = token;
    }
    return headers;
  }

  public isLocalHost(): boolean {
    const url = this.getServerUrl().toLowerCase();
    return (
      url.includes('localhost') ||
      url.includes('127.0.0.1') ||
      url.includes('0.0.0.0')
    );
  }

  public async getTemplates(): Promise<ScenarioTemplate[]> {
    const serverUrl = this.getServerUrl();
    const url = `${serverUrl}/api/templates`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        ...this.getAuthHeaders()
      }
    });

    if (!res.ok) {
      throw new Error(`Не удалось загрузить шаблоны сценариев (${res.status} ${res.statusText})`);
    }

    const data = await res.json() as any[];
    return data.map(item => ({
      id: item.id,
      title: item.title || item.name || item.id,
      category: item.category || 'Security',
      description: item.description || '',
      graph: item.graph
    }));
  }

  public async uploadArchive(zipBuffer: Buffer, filename: string = 'project.zip'): Promise<{ path: string; fileCount: number }> {
    const serverUrl = this.getServerUrl();
    const url = `${serverUrl}/api/sources/local-archive`;

    const blob = new Blob([zipBuffer], { type: 'application/zip' });
    const formData = new FormData();
    formData.append('archive', blob, filename);

    const headers = { ...this.getAuthHeaders() };

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!res.ok) {
      const errText = await res.text();
      let msg = errText;
      try {
        const parsed = JSON.parse(errText);
        if (parsed.error) msg = parsed.error;
      } catch {
        // use raw text
      }
      throw new Error(`Ошибка загрузки архива проекта на ${serverUrl}: ${msg}`);
    }

    const data = await res.json() as { path: string; fileCount: number };
    return data;
  }

  public async runAudit(
    scenarioId: string,
    params: { codePath?: string; repository?: string; branch?: string }
  ): Promise<AuditResult> {
    const serverUrl = this.getServerUrl();
    if (params.repository) {
      const templates = await this.getTemplates();
      const template = templates.find(item => item.id === scenarioId) ||
        templates.find(item => item.id === 'template-full-audit');
      if (!template?.graph) {
        throw new Error('Не удалось получить сценарий для Git-аудита');
      }

      const graph = JSON.parse(JSON.stringify(template.graph));
      for (const node of graph.nodes || []) {
        if (node.type === 'source.local' || node.type === 'source.archive') {
          node.type = 'source.git';
          node.settings = {
            ...(node.settings || {}),
            repoUrl: params.repository,
            branch: params.branch || 'main',
            subDir: '',
            depth: 1
          };
        }
      }

      const res = await fetch(`${serverUrl}/api/workflow/run`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...this.getAuthHeaders()
        },
        body: JSON.stringify({ graph, initialData: {} })
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Ошибка запуска Git-аудита (${res.status}): ${text}`);
      }

      const run = await res.json() as any;
      let findings: Finding[] = [];
      if (run.runId) {
        try {
          const historyUrl = `${serverUrl}/api/history/${encodeURIComponent(run.runId)}`;
          const historyRes = await fetch(historyUrl, {
            headers: { Accept: 'application/json', ...this.getAuthHeaders() }
          });
          if (historyRes.ok) {
            const history = await historyRes.json() as any;
            findings = Array.from(history.findings || []) as Finding[];
          }
        } catch {}
      }

      if (findings.length === 0) {
        try {
          const latestRes = await fetch(`${serverUrl}/api/reports/latest`, {
            headers: { Accept: 'application/json', ...this.getAuthHeaders() }
          });
          if (latestRes.ok) {
            const latest = await latestRes.json() as any;
            findings = Array.isArray(latest.findings) ? latest.findings : [];
          }
        } catch {}
      }

      const summary = {
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length,
        total: findings.length
      };

      return {
        status: run.success ? 'passed' : 'failed',
        exitCode: run.success ? 0 : 1,
        summary,
        reportUrl: `${serverUrl}/api/reports/latest`,
        findings,
        totalFindings: findings.length
      };
    }

    const url = `${serverUrl}/api/ci/run`;

    const bodyPayload: Record<string, any> = {
      workflowId: scenarioId,
      failOnCritical: false
    };

    if (params.codePath) {
      bodyPayload.codePath = params.codePath;
      bodyPayload.repository = params.codePath;
    } else if (params.repository) {
      bodyPayload.repository = params.repository;
    }

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...this.getAuthHeaders()
      },
      body: JSON.stringify(bodyPayload)
    });

    if (!res.ok) {
      const errText = await res.text();
      let msg = errText;
      try {
        const parsed = JSON.parse(errText);
        if (parsed.error) msg = parsed.error;
      } catch {
        // use raw
      }
      throw new Error(`Ошибка выполнения аудита на ${serverUrl}: ${msg}`);
    }

    const data = await res.json() as any;

    const rawFindings: Finding[] = (
      data.findings ||
      data.jsonReport?.findings ||
      []
    );

    const summary = data.summary || {
      critical: data.criticalCount || 0,
      high: data.highCount || 0,
      medium: data.mediumCount || 0,
      low: data.lowCount || 0,
      total: data.totalFindings || rawFindings.length
    };

    return {
      status: data.status || 'passed',
      exitCode: data.exitCode || 0,
      summary,
      reportUrl: data.reportUrl,
      findings: rawFindings,
      totalFindings: summary.total
    };
  }
}
