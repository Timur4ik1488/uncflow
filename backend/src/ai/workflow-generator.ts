import type { WorkflowGraph, WorkflowNodeInstance, WorkflowEdgeInstance } from '../engine/types.ts';

export class AiWorkflowGenerator {
  /**
   * Translates natural language description into a connected, positioned React Flow graph
   * Example prompt: "Каждый день в 14:00 проверяй код из репозитория на наличие секретов и отправляй отчет в телеграм"
   */
  public static generateFromPrompt(userPrompt: string): WorkflowGraph {
    const text = userPrompt.toLowerCase();

    // 1. Determine Trigger
    let triggerType = 'trigger.manual';
    let cronValue = '0 14 * * *';
    let triggerName = 'Кнопка запуска';

    if (text.includes('каждый день') || text.includes('расписани') || text.includes('часов') || text.includes(':00') || text.includes('cron')) {
      triggerType = 'trigger.schedule';
      triggerName = 'Запуск по расписанию';
      if (text.includes('14:00')) cronValue = '0 14 * * *';
      else if (text.includes('02:00') || text.includes('ноч')) cronValue = '0 2 * * *';
    } else if (text.includes('коммит') || text.includes('pr') || text.includes('ci') || text.includes('webhook')) {
      triggerType = 'trigger.webhook';
      triggerName = 'CI/CD Webhook';
    }

    // 2. Determine Scanners
    const wantSecrets = text.includes('секрет') || text.includes('парол') || text.includes('ключ') || (!text.includes('зависимост') && !text.includes('sast'));
    const wantSca = text.includes('зависимост') || text.includes('библиотек') || text.includes('sca') || text.includes('cve') || text.includes('пакет');
    const wantSast = text.includes('sast') || text.includes('код') || text.includes('инъекц') || text.includes('уязвимост') || text.includes('ошибк');

    // 3. Determine Notifications & Storage
    const wantTelegram = text.includes('телег') || text.includes('tg') || text.includes('бот');
    const wantWebhook = text.includes('webhook') || text.includes('slack') || text.includes('вебхук');
    const wantPostgres = text.includes('postgres') || text.includes('бд') || text.includes('баз') || text.includes('сохран');

    // 4. Build Nodes & Edges
    const nodes: WorkflowNodeInstance[] = [];
    const edges: WorkflowEdgeInstance[] = [];

    // Trigger Node
    nodes.push({
      id: 'node-trigger',
      type: triggerType,
      name: triggerName,
      position: { x: 50, y: 220 },
      settings: triggerType === 'trigger.schedule' ? { cron: cronValue } : {}
    });

    // Source Node
    nodes.push({
      id: 'node-source',
      type: 'source.local',
      name: 'Кодовая база',
      position: { x: 260, y: 220 },
      settings: { path: '.' }
    });

    edges.push({ id: 'e-trig-src', source: 'node-trigger', target: 'node-source' });

    // Scanners
    const scannerIds: string[] = [];
    let scannerY = 100;

    if (wantSecrets) {
      nodes.push({
        id: 'node-sec',
        type: 'scanner.secrets',
        name: 'Поиск секретов',
        position: { x: 500, y: scannerY },
        settings: { entropyThreshold: 3.3 }
      });
      edges.push({ id: 'e-src-sec', source: 'node-source', target: 'node-sec' });
      scannerIds.push('node-sec');
      scannerY += 140;
    }

    if (wantSca) {
      nodes.push({
        id: 'node-sca',
        type: 'scanner.sca',
        name: 'SCA Зависимости',
        position: { x: 500, y: scannerY },
        settings: {}
      });
      edges.push({ id: 'e-src-sca', source: 'node-source', target: 'node-sca' });
      scannerIds.push('node-sca');
      scannerY += 140;
    }

    if (wantSast) {
      nodes.push({
        id: 'node-sast',
        type: 'scanner.sast',
        name: 'SAST Анализ',
        position: { x: 500, y: scannerY },
        settings: {}
      });
      edges.push({ id: 'e-src-sast', source: 'node-source', target: 'node-sast' });
      scannerIds.push('node-sast');
    }

    // Aggregator
    nodes.push({
      id: 'node-agg',
      type: 'scanner.aggregator',
      name: 'Агрегатор находок',
      position: { x: 750, y: 220 },
      settings: {}
    });

    scannerIds.forEach((scId, idx) => {
      edges.push({
        id: `e-${scId}-agg`,
        source: scId,
        target: 'node-agg',
        sourceHandle: 'findings',
        targetHandle: `findings${idx + 1}`
      });
    });

    // Condition
    nodes.push({
      id: 'node-cond',
      type: 'logic.condition',
      name: 'Есть критические?',
      position: { x: 980, y: 220 },
      settings: { rule: 'has_critical' }
    });
    edges.push({ id: 'e-agg-cond', source: 'node-agg', target: 'node-cond' });

    // AI Explainer
    nodes.push({
      id: 'node-ai',
      type: 'ai.explainer',
      name: 'AI Объяснение и Рекомендации',
      position: { x: 1220, y: 180 },
      settings: { provider: 'offline-smart' }
    });
    edges.push({ id: 'e-cond-ai', source: 'node-cond', target: 'node-ai', sourceHandle: 'true' });

    // Dual Report
    nodes.push({
      id: 'node-report',
      type: 'report.dual',
      name: 'Экспорт отчётов',
      position: { x: 1460, y: 180 },
      settings: { outputDir: 'reports' }
    });
    edges.push({ id: 'e-ai-rep', source: 'node-ai', target: 'node-report' });

    // Notification
    if (wantTelegram || (!wantWebhook)) {
      nodes.push({
        id: 'node-tg',
        type: 'notify.telegram',
        name: 'Telegram Оповещение',
        position: { x: 1700, y: 180 },
        settings: { chatId: '@security_audit' }
      });
      edges.push({ id: 'e-rep-tg', source: 'node-report', target: 'node-tg' });
    }

    if (wantWebhook) {
      nodes.push({
        id: 'node-wh',
        type: 'notify.webhook',
        name: 'Webhook Оповещение',
        position: { x: 1700, y: 320 },
        settings: { url: 'https://webhook.site/audit' }
      });
      edges.push({ id: 'e-rep-wh', source: 'node-report', target: 'node-wh' });
    }

    if (wantPostgres) {
      nodes.push({
        id: 'node-pg',
        type: 'storage.postgres',
        name: 'Сохранение в PostgreSQL',
        position: { x: 1700, y: wantWebhook ? 440 : (wantTelegram ? 320 : 180) },
        settings: { tableName: 'findings', saveReport: true }
      });
      edges.push({ id: 'e-rep-pg', source: 'node-report', target: 'node-pg' });
    }

    return {
      id: 'wf-generated-' + Date.now(),
      name: 'Сгенерированный AI-сценарий',
      description: userPrompt,
      nodes,
      edges
    };
  }
}
