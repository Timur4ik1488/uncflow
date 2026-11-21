import type { WorkflowEngine } from './workflow-engine.ts';
import type { TemplateCatalog, WorkflowTemplate } from '../templates/catalog.ts';
import type { DatabaseService } from '../storage/db.ts';
import type { WorkflowExecutionEvent } from './types.ts';

export interface ScheduledJobInfo {
  workflowId: string;
  workflowName: string;
  nodeId: string;
  cron: string;
  intervalMinutes: number;
  description: string;
  enabled: boolean;
  nextRun: string | null;
  lastRun: string | null;
  lastStatus: 'idle' | 'running' | 'completed' | 'failed';
  lastFindingsCount?: number;
}

/**
 * Robust zero-dependency Cron Parser & Matcher
 * Supports:
 * - Standard 5 fields: minute (0-59), hour (0-23), day of month (1-31), month (1-12), day of week (0-7, 0 and 7 = Sun)
 * - Wildcards (*), steps (* / n, 0-30/10), lists (1,2,5), ranges (1-5)
 * - Named aliases: @hourly, @daily, @midnight, @weekly, @monthly
 * - Simple intervals: "every Xm", "every Xh"
 */
export class CronParser {
  public static normalizeCron(expr: string): string {
    const trimmed = (expr || '').trim().toLowerCase();
    if (trimmed === '@hourly') return '0 * * * *';
    if (trimmed === '@daily' || trimmed === '@midnight') return '0 0 * * *';
    if (trimmed === '@weekly') return '0 0 * * 0';
    if (trimmed === '@monthly') return '0 0 1 * *';

    const everyMatch = trimmed.match(/^every\s+(\d+)\s*(m|min|minutes?|h|hours?)$/i);
    if (everyMatch) {
      const num = parseInt(everyMatch[1], 10);
      const unit = everyMatch[2].toLowerCase();
      if (unit.startsWith('m')) {
        return `*/${Math.max(1, Math.min(59, num))} * * * *`;
      } else {
        return `0 */${Math.max(1, Math.min(23, num))} * * *`;
      }
    }

    return trimmed || '0 14 * * *';
  }

  private static parseField(field: string, min: number, max: number, current: number): boolean {
    if (field === '*' || field === '?') return true;

    // Handle lists: e.g. "1,2,5"
    if (field.includes(',')) {
      const parts = field.split(',');
      return parts.some(p => CronParser.parseField(p.trim(), min, max, current));
    }

    // Handle step: e.g. "*/15" or "10-30/5"
    if (field.includes('/')) {
      const [rangePart, stepPart] = field.split('/');
      const step = parseInt(stepPart, 10);
      if (isNaN(step) || step <= 0) return false;

      let start = min;
      let end = max;
      if (rangePart && rangePart !== '*') {
        if (rangePart.includes('-')) {
          const [rStart, rEnd] = rangePart.split('-').map(x => parseInt(x, 10));
          start = isNaN(rStart) ? min : rStart;
          end = isNaN(rEnd) ? max : rEnd;
        } else {
          start = parseInt(rangePart, 10);
          if (isNaN(start)) start = min;
        }
      }

      if (current < start || current > end) return false;
      return (current - start) % step === 0;
    }

    // Handle ranges: e.g. "1-5"
    if (field.includes('-')) {
      const [rStart, rEnd] = field.split('-').map(x => parseInt(x, 10));
      if (isNaN(rStart) || isNaN(rEnd)) return false;
      return current >= rStart && current <= rEnd;
    }

    // Exact number
    const exact = parseInt(field, 10);
    if (isNaN(exact)) return false;
    // For day of week, 7 is also Sunday (0)
    if (min === 0 && max === 7) {
      if (exact === 7 && current === 0) return true;
      if (exact === 0 && current === 7) return true;
    }
    return exact === current;
  }

  public static matches(expr: string, date: Date = new Date()): boolean {
    const normalized = CronParser.normalizeCron(expr);
    const parts = normalized.split(/\s+/);
    if (parts.length !== 5) return false;

    const [minPart, hourPart, dayPart, monthPart, dowPart] = parts;

    const minute = date.getMinutes();
    const hour = date.getHours();
    const day = date.getDate();
    const month = date.getMonth() + 1; // 1-12
    const dow = date.getDay(); // 0-6 (0 is Sunday)

    if (!CronParser.parseField(minPart, 0, 59, minute)) return false;
    if (!CronParser.parseField(hourPart, 0, 23, hour)) return false;
    if (!CronParser.parseField(dayPart, 1, 31, day)) return false;
    if (!CronParser.parseField(monthPart, 1, 12, month)) return false;
    if (!CronParser.parseField(dowPart, 0, 7, dow)) return false;

    return true;
  }

  public static getNextRunDate(expr: string, fromDate: Date = new Date()): Date {
    const normalized = CronParser.normalizeCron(expr);
    const testDate = new Date(fromDate.getTime());
    // Start from the next minute boundary
    testDate.setSeconds(0, 0);
    testDate.setMinutes(testDate.getMinutes() + 1);

    // Look ahead up to 365 days (max 525,600 minutes)
    for (let i = 0; i < 525600; i++) {
      if (CronParser.matches(normalized, testDate)) {
        return new Date(testDate.getTime());
      }
      testDate.setMinutes(testDate.getMinutes() + 1);
    }

    return new Date(fromDate.getTime() + 24 * 60 * 60 * 1000);
  }

  public static describe(expr: string): string {
    const normalized = CronParser.normalizeCron(expr);
    const parts = normalized.split(/\s+/);
    if (parts.length !== 5) return `Пользовательское расписание (${expr})`;

    const [m, h, dom, mon, dow] = parts;

    if (m.startsWith('*/') && h === '*' && dom === '*' && mon === '*' && dow === '*') {
      const step = m.replace('*/', '');
      return `Каждые ${step} минут`;
    }
    if (m === '0' && h.startsWith('*/') && dom === '*' && mon === '*' && dow === '*') {
      const step = h.replace('*/', '');
      return `Каждые ${step} часа(ов)`;
    }
    if (m === '0' && h === '*' && dom === '*' && mon === '*' && dow === '*') {
      return 'Каждый час в 00 минут';
    }
    if (dom === '*' && mon === '*' && dow === '*') {
      const pad = (n: string) => n.padStart(2, '0');
      return `Каждый день в ${pad(h)}:${pad(m)}`;
    }
    if (dow !== '*' && dom === '*' && mon === '*') {
      const days = ['воскресеньям', 'понедельникам', 'вторникам', 'средам', 'четвергам', 'пятницам', 'субботам'];
      const dayName = days[parseInt(dow, 10)] || `день ${dow}`;
      return `Каждую неделю по ${dayName} в ${h}:${m.padStart(2, '0')}`;
    }

    return `Расписание: ${normalized}`;
  }
}

/**
 * Background In-Process Workflow Scheduler
 */
export class WorkflowScheduler {
  private engine: WorkflowEngine;
  private templates: TemplateCatalog;
  private db: DatabaseService;
  private broadcastEvent: (event: WorkflowExecutionEvent) => void;
  private timer: NodeJS.Timeout | null = null;
  private lastTriggeredMinutes: Map<string, string> = new Map();
  private jobStates: Map<string, { lastRun: string | null; lastStatus: 'idle' | 'running' | 'completed' | 'failed'; findingsCount?: number }> = new Map();

  constructor(
    engine: WorkflowEngine,
    templates: TemplateCatalog,
    db: DatabaseService,
    broadcastEvent: (event: WorkflowExecutionEvent) => void
  ) {
    this.engine = engine;
    this.templates = templates;
    this.db = db;
    this.broadcastEvent = broadcastEvent;
  }

  public start(intervalMs: number = 30000): void {
    if (this.timer) clearInterval(this.timer);
    console.log('⏰ [WorkflowScheduler]: Background cron engine initialized.');
    this.timer = setInterval(async () => {
      try {
        await this.tick();
      } catch (err: any) {
        console.error('⏰ [WorkflowScheduler Error in tick]:', err.message);
      }
    }, intervalMs);

    // Initial check
    setTimeout(() => this.tick(), 2000);
  }

  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public async tick(): Promise<void> {
    const now = new Date();
    const minuteKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()} ${now.getHours()}:${now.getMinutes()}`;

    const jobs = await this.discoverScheduledWorkflows();

    for (const job of jobs) {
      if (!job.enabled) continue;

      const scheduleKey = `${job.workflowId}_${job.nodeId}`;
      const lastTriggered = this.lastTriggeredMinutes.get(scheduleKey);

      // Check if intervalMinutes is set
      let isDue = false;
      if (job.intervalMinutes > 0) {
        const lastRunTime = this.jobStates.get(job.workflowId)?.lastRun;
        if (!lastRunTime) {
          isDue = true;
        } else {
          const diffMinutes = (now.getTime() - new Date(lastRunTime).getTime()) / (1000 * 60);
          isDue = diffMinutes >= job.intervalMinutes;
        }
      } else {
        // Cron match (and haven't triggered in this exact minute)
        if (lastTriggered !== minuteKey && CronParser.matches(job.cron, now)) {
          isDue = true;
        }
      }

      if (isDue) {
        this.lastTriggeredMinutes.set(scheduleKey, minuteKey);
        console.log(`⏰ [WorkflowScheduler]: Executing scheduled workflow "${job.workflowName}" (${job.cron})`);
        this.executeScheduledJob(job).catch(err => {
          console.error(`⏰ [WorkflowScheduler]: Failed to run ${job.workflowName}:`, err);
        });
      }
    }
  }

  public async discoverScheduledWorkflows(): Promise<ScheduledJobInfo[]> {
    const list: ScheduledJobInfo[] = [];

    // 1. Gather all templates from Catalog and Database
    const allTemplates = await this.templates.getAllAsync();

    for (const tpl of allTemplates) {
      if (!tpl.graph || !tpl.graph.nodes) continue;

      for (const node of tpl.graph.nodes) {
        if (node.type === 'trigger.schedule' || node.type === 'trigger.cron') {
          const s = node.settings || {};
          let cron = s.cron || '0 14 * * *';
          if (s.frequency === 'every_hour') cron = '0 * * * *';
          else if (s.frequency === 'every_15_min') cron = '*/15 * * * *';
          else if (s.frequency === 'every_30_min') cron = '*/30 * * * *';
          else if (s.frequency === 'every_week') {
            const parts = (s.timeOfDay || '14:00').split(':');
            cron = `${Number(parts[1]) || 0} ${Number(parts[0]) || 14} * * 1`;
          } else if (s.frequency === 'every_day' && s.timeOfDay) {
            const parts = (s.timeOfDay || '14:00').split(':');
            cron = `${Number(parts[1]) || 0} ${Number(parts[0]) || 14} * * *`;
          }
          const intervalMinutes = Number(s.intervalMinutes) || 0;
          const enabled = s.enabled !== false;

          const state = this.jobStates.get(tpl.id) || { lastRun: null, lastStatus: 'idle' };
          const nextRunDate = enabled ? CronParser.getNextRunDate(cron) : null;

          list.push({
            workflowId: tpl.id,
            workflowName: tpl.title || tpl.graph.name || 'Сценарий аудита',
            nodeId: node.id,
            cron,
            intervalMinutes,
            description: CronParser.describe(cron),
            enabled,
            nextRun: nextRunDate ? nextRunDate.toISOString() : null,
            lastRun: state.lastRun,
            lastStatus: state.lastStatus,
            lastFindingsCount: state.findingsCount
          });
        }
      }
    }

    return list;
  }

  public async runJobNow(workflowId: string): Promise<any> {
    const allTemplates = await this.templates.getAllAsync();
    const tpl = allTemplates.find(t => t.id === workflowId);
    if (!tpl || !tpl.graph) {
      throw new Error(`Сценарий с ID '${workflowId}' не найден для запуска`);
    }

    const cronNode = tpl.graph.nodes.find(n => n.type === 'trigger.schedule' || n.type === 'trigger.cron');
    const jobInfo: ScheduledJobInfo = {
      workflowId: tpl.id,
      workflowName: tpl.title || tpl.graph.name || 'Сценарий аудита',
      nodeId: cronNode?.id || 'node-cron',
      cron: cronNode?.settings?.cron || '0 14 * * *',
      intervalMinutes: 0,
      description: 'Ручной запуск',
      enabled: true,
      nextRun: null,
      lastRun: null,
      lastStatus: 'running'
    };

    return await this.executeScheduledJob(jobInfo);
  }

  private async executeScheduledJob(job: ScheduledJobInfo): Promise<any> {
    const allTemplates = await this.templates.getAllAsync();
    const tpl = allTemplates.find(t => t.id === job.workflowId);
    if (!tpl || !tpl.graph) return null;

    this.jobStates.set(job.workflowId, {
      lastRun: new Date().toISOString(),
      lastStatus: 'running'
    });

    try {
      const result = await this.engine.executeWorkflow(tpl.graph, {
        scheduleTriggeredAt: new Date().toISOString(),
        cron: job.cron
      }, (event) => {
        this.broadcastEvent(event);
      });

      const reportOutput = result.nodeOutputs['node-report'] || result.nodeOutputs['node-agg'] || {};
      const findings = reportOutput.allFindings || reportOutput.findings || [];
      const criticalCount = findings.filter((f: any) => f.severity === 'CRITICAL').length;
      const highCount = findings.filter((f: any) => f.severity === 'HIGH').length;

      this.jobStates.set(job.workflowId, {
        lastRun: new Date().toISOString(),
        lastStatus: result.success ? 'completed' : 'failed',
        findingsCount: findings.length
      });

      // Persist to PostgreSQL
      await this.db.saveWorkflowRun({
        id: result.runId,
        workflowId: tpl.id,
        workflowName: `${tpl.title} (Cron Schedule)`,
        success: result.success,
        durationMs: result.durationMs,
        startTime: result.startTime,
        endTime: result.endTime,
        findingsCount: findings.length,
        criticalCount,
        highCount,
        mediumCount: findings.filter((f: any) => f.severity === 'MEDIUM').length,
        lowCount: findings.filter((f: any) => f.severity === 'LOW').length,
        result
      });

      this.broadcastEvent({
        type: 'workflow-completed',
        runId: result.runId,
        data: {
          scheduled: true,
          workflowId: tpl.id,
          findingsCount: findings.length,
          result
        },
        timestamp: new Date().toISOString()
      });

      return result;
    } catch (err: any) {
      this.jobStates.set(job.workflowId, {
        lastRun: new Date().toISOString(),
        lastStatus: 'failed'
      });
      throw err;
    }
  }
}
