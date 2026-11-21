import type { WorkflowGraph } from '../engine/types.ts';
import { db } from '../storage/db.ts';

export interface WorkflowTemplate {
  id: string;
  title: string;
  description: string;
  category: 'Full Audit' | 'Secrets' | 'Dependencies' | 'CI/CD' | 'AI Audit' | string;
  tags: string[];
  author: string;
  userId?: string;       // Owner ID (for future multi-tenant auth / user profiles)
  isPublic?: boolean;    // Whether accessible to everyone or private to user
  isBuiltin?: boolean;   // System built-in default template
  createdAt?: string;
  updatedAt?: string;
  graph: WorkflowGraph;
}

export class TemplateCatalog {
  private templates: Map<string, WorkflowTemplate> = new Map();

  constructor() {
    this.registerDefaults();
  }

  public getAll(): WorkflowTemplate[] {
    return Array.from(this.templates.values());
  }

  public async getAllAsync(userId?: string): Promise<WorkflowTemplate[]> {
    // 1. Ensure all built-in templates are persistently saved into PostgreSQL
    for (const t of this.templates.values()) {
      if (t.isBuiltin) {
        db.saveTemplate(t, true, 'system', true).catch(() => {});
      }
    }

    // 2. Fetch templates from PostgreSQL
    const fromDb = await db.getTemplates(userId);

    // 3. Merge: Guarantee all built-in default templates are ALWAYS available
    const resultMap = new Map<string, WorkflowTemplate>();

    // Start with all in-memory built-in templates
    for (const t of this.templates.values()) {
      if (t.isBuiltin) {
        resultMap.set(t.id, t);
      }
    }

    // Overlay / append records from database
    if (fromDb.length > 0) {
      for (const t of fromDb) {
        resultMap.set(t.id, t);
      }
    }

    let all = Array.from(resultMap.values());
    if (userId) {
      all = all.filter(t => t.isBuiltin || t.isPublic || t.userId === userId || t.userId === 'default_user');
    }

    // Sort: Built-in default templates first, then user templates
    all.sort((a, b) => {
      if (a.isBuiltin && !b.isBuiltin) return -1;
      if (!a.isBuiltin && b.isBuiltin) return 1;
      return 0;
    });

    return all;
  }

  public getById(id: string): WorkflowTemplate | undefined {
    return this.templates.get(id);
  }

  public publish(template: WorkflowTemplate, isBuiltin = false) {
    template.isBuiltin = isBuiltin;
    template.userId = template.userId || (isBuiltin ? 'system' : 'default_user');
    template.isPublic = template.isPublic !== undefined ? template.isPublic : isBuiltin;
    this.templates.set(template.id, template);
    db.saveTemplate(template, isBuiltin, template.userId, template.isPublic).catch(() => {});
  }

  public async syncFromDb(): Promise<void> {
    try {
      // 1. Seed built-in default templates to PostgreSQL
      for (const t of this.templates.values()) {
        if (t.isBuiltin) {
          await db.saveTemplate(t, true, 'system', true);
        }
      }

      // 2. Load all templates from PostgreSQL
      const list = await db.getTemplates();
      for (const t of list) {
        this.templates.set(t.id, t);
      }
      console.log(`📦 [Templates Catalog]: Synchronized ${list.length} templates (including built-ins).`);
    } catch (err: any) {
      console.warn('⚠️ [Templates Catalog Sync]:', err.message);
    }
  }

  private registerDefaults() {
    // Template 1: Full Security Audit
    this.publish({
      id: 'template-full-audit',
      title: 'Комплексный аудит безопасности (Secrets + SCA + SAST + AI + Telegram)',
      description: 'Полный сценарий глубокой проверки: параллельный запуск всех анализаторов, логическое ветвление при критических уязвимостях, генерация рекомендаций AI и оповещение в Telegram.',
      category: 'Full Audit',
      tags: ['Kotlin', 'Spring Boot', 'Gradle', 'AI', 'Telegram', 'Полный аудит'],
      author: 'Cyber Garden Security Team',
      graph: {
        id: 'wf-full-audit',
        name: 'Комплексный аудит безопасности',
        description: 'Полный сценарий проверки проекта',
        nodes: [
          { id: 'node-trigger', type: 'trigger.manual', position: { x: 60, y: 270 }, settings: { label: 'Старт аудита' } },
          { id: 'node-source', type: 'source.local', position: { x: 440, y: 270 }, settings: { path: 'test-dataset/training-project' } },
          { id: 'node-sec', type: 'scanner.secrets', position: { x: 820, y: 80 }, settings: { entropyThreshold: 3.3 } },
          { id: 'node-sca', type: 'scanner.sca', position: { x: 820, y: 270 }, settings: { dbPath: 'test-dataset/vulnerability-database/vulnerabilities.json' } },
          { id: 'node-sast', type: 'scanner.sast', position: { x: 820, y: 460 }, settings: {} },
          { id: 'node-agg', type: 'scanner.aggregator', position: { x: 1200, y: 270 }, settings: {} },
          { id: 'node-cond', type: 'logic.condition', position: { x: 1580, y: 270 }, settings: { rule: 'has_critical' } },
          { id: 'node-ai', type: 'ai.explainer', position: { x: 1960, y: 220 }, settings: { provider: 'gigachat' } },
          { id: 'node-report', type: 'report.dual', position: { x: 2340, y: 220 }, settings: { outputDir: 'reports' } },
          { id: 'node-tg', type: 'notify.channel', position: { x: 2720, y: 220 }, settings: { enableTelegram: true, telegramChatId: '@security_audit' } }
        ],
        edges: [
          { id: 'e1', source: 'node-trigger', target: 'node-source' },
          { id: 'e2', source: 'node-source', target: 'node-sec' },
          { id: 'e3', source: 'node-source', target: 'node-sca' },
          { id: 'e4', source: 'node-source', target: 'node-sast' },
          { id: 'e5', source: 'node-sec', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings1' },
          { id: 'e6', source: 'node-sca', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings2' },
          { id: 'e7', source: 'node-sast', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings3' },
          { id: 'e8', source: 'node-agg', target: 'node-cond' },
          { id: 'e9', source: 'node-cond', target: 'node-ai', sourceHandle: 'true' },
          { id: 'e10', source: 'node-ai', target: 'node-report' },
          { id: 'e11', source: 'node-report', target: 'node-tg' }
        ]
      }
    }, true);

    // Template 1B: GigaChat AppSec Deep Audit
    this.publish({
      id: 'template-gigachat-deep',
      title: 'Интеллектуальный аудит со Сбер GigaChat-Pro (CWE + OWASP + Эксплойт-анализ)',
      description: 'Глубокий анализ исходного кода и зависимостей с использованием LLM GigaChat-Pro для категоризации по стандартам CWE и OWASP Top 10, генерации эксплойт-сценариев и патчей (по методологии ai_categorizer.py).',
      category: 'AI Audit',
      tags: ['GigaChat', 'LLM', 'CWE', 'OWASP', 'CISO', 'Cyber Garden'],
      author: 'AppSec AI Team',
      graph: {
        id: 'wf-gigachat-deep',
        name: 'GigaChat AppSec Экспертиза',
        description: 'Сценарий аудита с интеграцией Сбер GigaChat-Pro',
        nodes: [
          { id: 'node-trigger', type: 'trigger.manual', position: { x: 60, y: 270 }, settings: { label: 'Старт AI аудита' } },
          { id: 'node-source', type: 'source.local', position: { x: 440, y: 270 }, settings: { path: 'test-dataset/training-project' } },
          { id: 'node-sec', type: 'scanner.secrets', position: { x: 820, y: 80 }, settings: {} },
          { id: 'node-sca', type: 'scanner.sca', position: { x: 820, y: 270 }, settings: {} },
          { id: 'node-sast', type: 'scanner.sast', position: { x: 820, y: 460 }, settings: {} },
          { id: 'node-agg', type: 'scanner.aggregator', position: { x: 1200, y: 270 }, settings: {} },
          { id: 'node-gigachat', type: 'ai.explainer', position: { x: 1600, y: 270 }, settings: { provider: 'gigachat', model: 'GigaChat-Pro' } },
          { id: 'node-report', type: 'report.dual', position: { x: 2000, y: 270 }, settings: { outputDir: 'reports' } },
          { id: 'node-tg', type: 'notify.channel', position: { x: 2400, y: 270 }, settings: { enableTelegram: true, telegramChatId: '@security_audit' } }
        ],
        edges: [
          { id: 'e1', source: 'node-trigger', target: 'node-source' },
          { id: 'e2', source: 'node-source', target: 'node-sec' },
          { id: 'e3', source: 'node-source', target: 'node-sca' },
          { id: 'e4', source: 'node-source', target: 'node-sast' },
          { id: 'e5', source: 'node-sec', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings1' },
          { id: 'e6', source: 'node-sca', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings2' },
          { id: 'e7', source: 'node-sast', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings3' },
          { id: 'e8', source: 'node-agg', target: 'node-gigachat' },
          { id: 'e9', source: 'node-gigachat', target: 'node-report' },
          { id: 'e10', source: 'node-report', target: 'node-tg' }
        ]
      }
    }, true);

    // Template 2: Secrets Quick Check
    this.publish({
      id: 'template-secrets-quick',
      title: 'Быстрый аудит утечек секретов и токенов',
      description: 'Экспресс-сканирование исходного кода и конфигурационных файлов (application.yml) на предмет хардкода паролей, API-ключей и скрытых токенов.',
      category: 'Secrets',
      tags: ['Secrets', 'Fast', 'Passwords', 'API-Keys'],
      author: 'AppSec Lead',
      graph: {
        id: 'wf-secrets-quick',
        name: 'Быстрый аудит секретов',
        nodes: [
          { id: 'node-trigger', type: 'trigger.manual', position: { x: 60, y: 200 }, settings: {} },
          { id: 'node-source', type: 'source.local', position: { x: 440, y: 200 }, settings: { path: 'test-dataset/training-project' } },
          { id: 'node-sec', type: 'scanner.secrets', position: { x: 820, y: 200 }, settings: { entropyThreshold: 3.3 } },
          { id: 'node-report', type: 'report.dual', position: { x: 1200, y: 200 }, settings: { outputDir: 'reports' } }
        ],
        edges: [
          { id: 'e1', source: 'node-trigger', target: 'node-source' },
          { id: 'e2', source: 'node-source', target: 'node-sec' },
          { id: 'e3', source: 'node-sec', target: 'node-report' }
        ]
      }
    }, true);

    // Template 3: SCA Dependency Monitor
    this.publish({
      id: 'template-sca-monitor',
      title: 'SCA & Мониторинг уязвимых зависимостей Gradle',
      description: 'Анализ build.gradle.kts, gradle.lockfile и переменных окружения, сопоставление версий библиотек с локальной базой CVE/GHSA.',
      category: 'Dependencies',
      tags: ['SCA', 'Gradle', 'CVE', 'Dependencies'],
      author: 'Security Architect',
      graph: {
        id: 'wf-sca-monitor',
        name: 'SCA Мониторинг зависимостей',
        nodes: [
          { id: 'node-trigger', type: 'trigger.schedule', position: { x: 60, y: 200 }, settings: { cron: '0 0 * * *' } },
          { id: 'node-source', type: 'source.local', position: { x: 440, y: 200 }, settings: { path: 'test-dataset/training-project' } },
          { id: 'node-sca', type: 'scanner.sca', position: { x: 820, y: 200 }, settings: {} },
          { id: 'node-report', type: 'report.dual', position: { x: 1200, y: 200 }, settings: { outputDir: 'reports' } }
        ],
        edges: [
          { id: 'e1', source: 'node-trigger', target: 'node-source' },
          { id: 'e2', source: 'node-source', target: 'node-sca' },
          { id: 'e3', source: 'node-sca', target: 'node-report' }
        ]
      }
    }, true);

    // Template 4: CI/CD Gatekeeper
    this.publish({
      id: 'template-cicd-gatekeeper',
      title: 'CI/CD Gatekeeper: Блокировка сборки при критических уязвимостях',
      description: 'Сценарий для автоматического запуска на каждый коммит/PR с падением сборки и отправкой уведомлений.',
      category: 'CI/CD',
      tags: ['CI/CD', 'GitHub Actions', 'GitLab CI', 'Fail-on-Critical'],
      author: 'DevSecOps Team',
      graph: {
        id: 'wf-cicd-gatekeeper',
        name: 'CI/CD Gatekeeper',
        nodes: [
          { id: 'node-trigger', type: 'trigger.webhook', position: { x: 60, y: 220 }, settings: {} },
          { id: 'node-source', type: 'source.local', position: { x: 440, y: 220 }, settings: { path: 'test-dataset/training-project' } },
          { id: 'node-sec', type: 'scanner.secrets', position: { x: 820, y: 120 }, settings: {} },
          { id: 'node-sast', type: 'scanner.sast', position: { x: 820, y: 320 }, settings: {} },
          { id: 'node-agg', type: 'scanner.aggregator', position: { x: 1200, y: 220 }, settings: {} },
          { id: 'node-cond', type: 'logic.condition', position: { x: 1580, y: 220 }, settings: { rule: 'has_critical' } },
          { id: 'node-report', type: 'report.dual', position: { x: 1960, y: 160 }, settings: {} },
          { id: 'node-tg', type: 'notify.channel', position: { x: 2340, y: 160 }, settings: {} }
        ],
        edges: [
          { id: 'e1', source: 'node-trigger', target: 'node-source' },
          { id: 'e2', source: 'node-source', target: 'node-sec' },
          { id: 'e3', source: 'node-source', target: 'node-sast' },
          { id: 'e4', source: 'node-sec', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings1' },
          { id: 'e5', source: 'node-sast', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings2' },
          { id: 'e6', source: 'node-agg', target: 'node-cond' },
          { id: 'e7', source: 'node-cond', target: 'node-report', sourceHandle: 'true' },
          { id: 'e8', source: 'node-report', target: 'node-tg' }
        ]
      }
    }, true);
  }
}
