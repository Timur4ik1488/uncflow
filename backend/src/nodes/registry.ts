import * as fs from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import type { NodeDefinition, ExecutionContext } from '../engine/types.ts';
import { SecretAnalyzer } from '../analyzers/secrets/index.ts';
import { ScaAnalyzer } from '../analyzers/sca/index.ts';
import { SastAnalyzer } from '../analyzers/sast/index.ts';
import type { Finding } from '../types/findings.ts';
import { SmartSecurityCategorizer, GigaChatClient } from '../ai/security-categorizer.ts';
import { db } from '../storage/db.ts';
import { sendYandexMail, formatSecurityEmailHtml } from '../notifications/mailer.ts';

const execFileAsync = promisify(execFile);

/**
 * Clones or updates a remote Git repository into a local cache directory.
 * Supports public/private repositories, branches, subdirectories, and hackathon local datasets.
 */
async function cloneOrUpdateRepo(
  repoUrl: string,
  branch: string = 'main',
  subDir?: string,
  token?: string,
  depth: number = 1
): Promise<string> {
  if (fs.existsSync(repoUrl) && fs.statSync(repoUrl).isDirectory()) {
    return path.resolve(repoUrl);
  }

  const localTraining = path.resolve(process.cwd(), 'test-dataset/training-project');
  // Hackathon training dataset fast-path:
  if (repoUrl.includes('TBagirov/training') && fs.existsSync(localTraining) && (!subDir || subDir === 'training-project')) {
    return localTraining;
  }

  const cacheBase = path.resolve(process.cwd(), '.cache/repos');
  if (!fs.existsSync(cacheBase)) {
    fs.mkdirSync(cacheBase, { recursive: true });
  }

  // Safe slug for directory naming
  const slug = repoUrl
    .replace(/^https?:\/\//, '')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .substring(0, 50);

  const targetDir = path.join(cacheBase, slug);

  // Authenticated URL injection
  let authUrl = repoUrl;
  if (token && token.trim()) {
    authUrl = repoUrl.replace('https://', `https://${encodeURIComponent(token.trim())}@`);
  }

  if (fs.existsSync(path.join(targetDir, '.git'))) {
    // Repository already exists: attempt checkout and pull
    try {
      await execFileAsync('git', ['checkout', branch], { cwd: targetDir });
      await execFileAsync('git', ['pull', '--depth', String(depth || 1)], { cwd: targetDir });
    } catch {
      // Offline fallback: keep existing working tree
    }
  } else {
    // Fresh clone
    if (fs.existsSync(targetDir)) {
      fs.rmSync(targetDir, { recursive: true, force: true });
    }
    try {
      await execFileAsync('git', ['clone', '--depth', String(depth || 1), '-b', branch, authUrl, targetDir]);
    } catch (err: any) {
      // Retry without -b if branch name differs from remote default (e.g. master vs main)
      try {
        await execFileAsync('git', ['clone', '--depth', String(depth || 1), authUrl, targetDir]);
      } catch (cloneErr: any) {
        throw new Error(`Не удалось клонировать Git-репозиторий: ${cloneErr.message || err.message}. Проверьте URL репозитория, доступ в интернет и PAT-токен.`);
      }
    }
  }

  let finalPath = targetDir;
  if (subDir && subDir.trim()) {
    const candidate = path.join(targetDir, subDir.trim());
    if (fs.existsSync(candidate)) {
      finalPath = candidate;
    } else {
      console.warn(`[source.git] Указанная поддиректория '${subDir}' не найдена в репозитории, используется корень: ${targetDir}`);
    }
  }

  return finalPath;
}

export class NodeRegistry {
  private nodes: Map<string, NodeDefinition> = new Map();

  constructor() {
    this.registerDefaults();
  }

  public register(node: NodeDefinition) {
    this.nodes.set(node.type, node);
  }

  public getNode(type: string): NodeDefinition | undefined {
    return this.nodes.get(type);
  }

  public getAllNodes(): NodeDefinition[] {
    return Array.from(this.nodes.values()).filter(n => !(n as any).hidden);
  }

  private registerDefaults() {
    // -------------------------------------------------------------------------
    // 1. TRIGGERS
    // -------------------------------------------------------------------------

    this.register({
      type: 'trigger.manual',
      title: 'Ручной запуск (Кнопка)',
      category: 'Triggers',
      icon: 'PlayCircle',
      color: '#3B82F6', // Blue
      description: 'Запуск сценария по клику в интерфейсе или по вызову API',
      inputs: [],
      outputs: [{ id: 'start', label: 'Старт', type: 'any' }],
      settings: [
        { name: 'label', label: 'Название запуска', type: 'string', default: 'Ручной аудит' }
      ],
      run: async (inputs, settings) => {
        return { start: true, triggeredAt: new Date().toISOString() };
      }
    });

    const scheduleTriggerDef: NodeDefinition = {
      type: 'trigger.schedule',
      title: 'Запуск по расписанию',
      category: 'Triggers',
      icon: 'Clock',
      color: '#8B5CF6', // Purple
      description: 'Периодический запуск проверки проекта по расписанию',
      inputs: [],
      outputs: [
        { id: 'start', label: 'Старт', type: 'any' },
        { id: 'trigger', label: 'Триггер', type: 'any' },
        { id: 'codePath', label: 'Путь к коду', type: 'codePath' }
      ],
      settings: [
        {
          name: 'frequency',
          label: 'Частота запуска',
          type: 'select',
          default: 'every_day',
          options: [
            { label: 'Каждый день', value: 'every_day' },
            { label: 'Каждый час', value: 'every_hour' },
            { label: 'Каждые 15 минут', value: 'every_15_min' },
            { label: 'Каждые 30 минут', value: 'every_30_min' },
            { label: 'Раз в неделю', value: 'every_week' },
            { label: 'Пользовательское время', value: 'custom' }
          ]
        },
        { name: 'timeOfDay', label: 'Время запуска (ЧЧ:ММ)', type: 'string', default: '14:00' },
        { name: 'cron', label: 'Выражение расписания', type: 'string', default: '0 14 * * *' },
        { name: 'enabled', label: 'Активировать расписание', type: 'boolean', default: true }
      ],
      run: async (inputs, settings) => {
        let cronExpr = settings.cron || '0 14 * * *';
        if (settings.frequency === 'every_hour') cronExpr = '0 * * * *';
        else if (settings.frequency === 'every_15_min') cronExpr = '*/15 * * * *';
        else if (settings.frequency === 'every_30_min') cronExpr = '*/30 * * * *';
        else if (settings.frequency === 'every_week') {
          const parts = (settings.timeOfDay || '14:00').split(':');
          cronExpr = `${Number(parts[1]) || 0} ${Number(parts[0]) || 14} * * 1`;
        } else if (settings.frequency === 'every_day' && settings.timeOfDay) {
          const parts = (settings.timeOfDay || '14:00').split(':');
          cronExpr = `${Number(parts[1]) || 0} ${Number(parts[0]) || 14} * * *`;
        }

        return {
          start: true,
          trigger: true,
          scheduleTriggeredAt: new Date().toISOString(),
          cron: cronExpr,
          enabled: settings.enabled !== false,
          codePath: inputs.codePath || './test-dataset/training-project'
        };
      }
    };

    this.register(scheduleTriggerDef);
    // Also register alias 'trigger.cron' for seamless compatibility (hidden from palette)
    this.register({
      ...scheduleTriggerDef,
      type: 'trigger.cron',
      title: 'Запуск по расписанию',
      hidden: true
    } as any);

    this.register({
      type: 'trigger.webhook',
      title: 'CI/CD Webhook Триггер',
      category: 'Triggers',
      icon: 'GitPullRequest',
      color: '#EC4899', // Pink
      description: 'Автоматический приём Webhook из GitHub, GitLab, GitVerse на коммит или Pull Request',
      inputs: [],
      outputs: [
        { id: 'start', label: 'Старт', type: 'any' },
        { id: 'trigger', label: 'Триггер', type: 'any' },
        { id: 'codePath', label: 'Путь к коду', type: 'codePath' },
        { id: 'repoUrl', label: 'URL Репозитория', type: 'string' },
        { id: 'branch', label: 'Ветка', type: 'string' },
        { id: 'payload', label: 'Webhook Данные', type: 'any' }
      ],
      settings: [
        { name: 'endpoint', label: 'Endpoint Path', type: 'string', default: '/api/webhook/trigger', description: 'Путь приёма Webhook на сервере uncflow' },
        { name: 'secretToken', label: 'Secret Token', type: 'password', description: 'Секретный токен для верификации заголовка X-Webhook-Secret / X-Gitlab-Token' },
        { name: 'defaultRepoUrl', label: 'Резервный URL репозитория', type: 'string', default: '', description: 'Используется, если репозиторий не передан в webhook' },
        { name: 'defaultBranch', label: 'Резервная ветка', type: 'string', default: 'main', description: 'Используется по умолчанию (напр. main)' }
      ],
      run: async (inputs, settings) => {
        const payload = inputs.payload || inputs;
        const repoUrl = inputs.repoUrl || payload.repository?.clone_url || payload.repository?.html_url || payload.project?.git_http_url || settings.defaultRepoUrl || '';
        const rawBranch = inputs.branch || (payload.ref ? String(payload.ref).replace(/^refs\/heads\//, '') : '') || payload.pull_request?.head?.ref || settings.defaultBranch || 'main';
        const branch = String(rawBranch).trim();
        const commitSha = inputs.commitSha || payload.after || payload.pull_request?.head?.sha || payload.head_commit?.id || 'HEAD';
        const author = inputs.author || payload.pusher?.name || payload.sender?.login || payload.user_name || payload.head_commit?.author?.name || 'Webhook CI';
        const codePath = inputs.codePath || payload.codePath || './test-dataset/training-project';

        return {
          start: true,
          trigger: true,
          repoUrl,
          branch,
          commitSha,
          author,
          codePath,
          webhookTriggeredAt: new Date().toISOString(),
          payload
        };
      }
    });

    // -------------------------------------------------------------------------
    // 2. SOURCES
    // -------------------------------------------------------------------------

    this.register({
      type: 'source.local',
      title: 'Локальная папка проекта',
      category: 'Sources',
      icon: 'Folder',
      color: '#10B981', // Emerald
      description: 'Использовать локальный каталог с исходным кодом приложения',
      inputs: [{ id: 'trigger', label: 'Вход', type: 'any' }],
      outputs: [
        { id: 'codePath', label: 'Путь к коду', type: 'codePath' },
        { id: 'repoUrl', label: 'Путь к проекту', type: 'string' }
      ],
      settings: [
        { name: 'path', label: 'Путь к проекту', type: 'string', default: 'test-dataset/training-project', required: true }
      ],
      run: async (inputs, settings) => {
        let targetPath = inputs.codePath || inputs.path || settings.path || 'test-dataset/training-project';
        if (!path.isAbsolute(targetPath)) {
          targetPath = path.resolve(process.cwd(), targetPath);
        }
        if (!fs.existsSync(targetPath)) {
          throw new Error(`Указанный локальный каталог не найден: ${targetPath}. Проверьте правильность пути в настройках блока.`);
        }
        return { codePath: targetPath, repoUrl: targetPath, exists: true };
      }
    });

    this.register({
      type: 'source.git',
      title: 'Git Репозиторий',
      category: 'Sources',
      icon: 'GitBranch',
      color: '#059669', // Green
      description: 'Клонирование Git-репозитория по HTTPS ссылке с поддержкой веток и токенов',
      inputs: [{ id: 'trigger', label: 'Вход', type: 'any' }],
      outputs: [
        { id: 'codePath', label: 'Путь к коду', type: 'codePath' },
        { id: 'repoUrl', label: 'URL Репозитория', type: 'string' }
      ],
      settings: [
        { name: 'repoUrl', label: 'URL Репозитория (HTTPS)', type: 'string', default: 'https://github.com/TBagirov/training', required: true },
        { name: 'branch', label: 'Ветка (Branch)', type: 'string', default: 'main' },
        { name: 'subDir', label: 'Поддиректория проекта', type: 'string', default: '' },
        { name: 'token', label: 'Токен доступа (PAT)', type: 'password' },
        { name: 'depth', label: 'Глубина клонирования (depth)', type: 'number', default: 1 }
      ],
      run: async (inputs, settings, context) => {
        const repoUrl = (inputs.repoUrl || settings.repoUrl || '').trim();
        if (!repoUrl) {
          throw new Error('URL репозитория не указан в блоке Git Репозиторий.');
        }

        const branch = (inputs.branch || settings.branch || 'main').trim();
        const subDir = (inputs.subDir || settings.subDir || '').trim();
        let token = (inputs.token || settings.token || '').trim();
        if (!token) {
          if (repoUrl.includes('gitverse.ru')) {
            token = (process.env.GITVERSE_TOKEN || '').trim();
          } else if (repoUrl.includes('github.com')) {
            token = (process.env.GITHUB_TOKEN || '').trim();
          }
        }
        const depth = Number(settings.depth) || 1;

        const resolvedCodePath = await cloneOrUpdateRepo(repoUrl, branch, subDir, token, depth);
        if (context) {
          (context as any).repoUrl = repoUrl;
          (context as any).branch = branch;
        }
        return {
          codePath: resolvedCodePath,
          repoUrl,
          branch,
          clonedAt: new Date().toISOString()
        };
      }
    });

    // -------------------------------------------------------------------------
    // 3. SCANNERS
    // -------------------------------------------------------------------------

    this.register({
      type: 'scanner.secrets',
      title: 'Поиск Секретов (Secrets)',
      category: 'Scanners',
      icon: 'KeyRound',
      color: '#EF4444', // Red
      description: 'Поиск захардкоженных паролей, API-ключей, токенов, конкатенаций и fallback-ов',
      inputs: [{ id: 'codePath', label: 'Путь к коду', type: 'codePath' }],
      outputs: [{ id: 'findings', label: 'Находки (Secrets)', type: 'findings' }],
      settings: [
        { name: 'entropyThreshold', label: 'Порог энтропии Шеннона', type: 'number', default: 3.3, description: 'Порог для анализа случайности строк' },
        {
          name: 'minSeverity',
          label: 'Минимальная критичность',
          type: 'select',
          default: 'ALL',
          options: [
            { label: 'Все находки (ALL)', value: 'ALL' },
            { label: 'Только CRITICAL / HIGH', value: 'HIGH' },
            { label: 'Только CRITICAL', value: 'CRITICAL' }
          ]
        }
      ],
      run: async (inputs, settings) => {
        const codePath = inputs.codePath || (settings.path ? path.resolve(process.cwd(), settings.path) : path.resolve(process.cwd(), 'test-dataset/training-project'));
        if (!fs.existsSync(codePath)) {
          throw new Error(`Каталог для сканирования не существует: ${codePath}`);
        }
        const analyzer = new SecretAnalyzer({ entropyThreshold: Number(settings.entropyThreshold) || 3.3 });
        let findings = analyzer.scanProject(codePath);
        if (settings.minSeverity === 'HIGH') {
          findings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        } else if (settings.minSeverity === 'CRITICAL') {
          findings = findings.filter(f => f.severity === 'CRITICAL');
        }
        return { findings, count: findings.length, codePath };
      }
    });

    this.register({
      type: 'scanner.sca',
      title: 'Анализ Зависимостей (SCA)',
      category: 'Scanners',
      icon: 'PackageSearch',
      color: '#F97316', // Orange
      description: 'Проверка build.gradle.kts и версий зависимостей по базе уязвимостей',
      inputs: [{ id: 'codePath', label: 'Путь к коду', type: 'codePath' }],
      outputs: [{ id: 'findings', label: 'Находки (SCA)', type: 'findings' }],
      settings: [
        { name: 'dbPath', label: 'Путь к vulnerabilities.json', type: 'string', default: 'test-dataset/vulnerability-database/vulnerabilities.json' },
        {
          name: 'minSeverity',
          label: 'Минимальная критичность',
          type: 'select',
          default: 'ALL',
          options: [
            { label: 'Все находки (ALL)', value: 'ALL' },
            { label: 'Только CRITICAL / HIGH', value: 'HIGH' },
            { label: 'Только CRITICAL', value: 'CRITICAL' }
          ]
        }
      ],
      run: async (inputs, settings) => {
        const codePath = inputs.codePath || (settings.path ? path.resolve(process.cwd(), settings.path) : path.resolve(process.cwd(), 'test-dataset/training-project'));
        if (!fs.existsSync(codePath)) {
          throw new Error(`Каталог для сканирования не существует: ${codePath}`);
        }
        const dbPath = path.resolve(process.cwd(), settings.dbPath || 'test-dataset/vulnerability-database/vulnerabilities.json');
        const analyzer = new ScaAnalyzer(dbPath);
        let findings = analyzer.scanProject(codePath);
        if (settings.minSeverity === 'HIGH') {
          findings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        } else if (settings.minSeverity === 'CRITICAL') {
          findings = findings.filter(f => f.severity === 'CRITICAL');
        }
        return { findings, count: findings.length, codePath };
      }
    });

    this.register({
      type: 'scanner.sast',
      title: 'Статический Анализ (SAST)',
      category: 'Scanners',
      icon: 'ShieldAlert',
      color: '#DC2626', // Dark Red
      description: 'AST-анализ Kotlin/Spring Boot: SQL-инъекции, TLS, CORS, права маршрутов и IDOR',
      inputs: [{ id: 'codePath', label: 'Путь к коду', type: 'codePath' }],
      outputs: [{ id: 'findings', label: 'Находки (SAST)', type: 'findings' }],
      settings: [
        {
          name: 'minSeverity',
          label: 'Минимальная критичность',
          type: 'select',
          default: 'ALL',
          options: [
            { label: 'Все находки (ALL)', value: 'ALL' },
            { label: 'Только CRITICAL / HIGH', value: 'HIGH' },
            { label: 'Только CRITICAL', value: 'CRITICAL' }
          ]
        }
      ],
      run: async (inputs, settings) => {
        const codePath = inputs.codePath || (settings.path ? path.resolve(process.cwd(), settings.path) : path.resolve(process.cwd(), 'test-dataset/training-project'));
        if (!fs.existsSync(codePath)) {
          throw new Error(`Каталог для сканирования не существует: ${codePath}`);
        }
        const analyzer = new SastAnalyzer();
        let findings = analyzer.scanProject(codePath);
        if (settings.minSeverity === 'HIGH') {
          findings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        } else if (settings.minSeverity === 'CRITICAL') {
          findings = findings.filter(f => f.severity === 'CRITICAL');
        }
        return { findings, count: findings.length, codePath };
      }
    });

    this.register({
      type: 'scanner.aggregator',
      title: 'Агрегатор Находок',
      category: 'Scanners',
      icon: 'Layers',
      color: '#6366F1', // Indigo
      description: 'Объединение находок от всех сканеров и подсчёт статистики',
      inputs: [
        { id: 'findings1', label: 'Находки 1', type: 'findings' },
        { id: 'findings2', label: 'Находки 2', type: 'findings' },
        { id: 'findings3', label: 'Находки 3', type: 'findings' },
        { id: 'findings4', label: 'Находки 4', type: 'findings' },
        { id: 'findings5', label: 'Находки 5', type: 'findings' }
      ],
      outputs: [{ id: 'allFindings', label: 'Все находки', type: 'findings' }],
      settings: [
        { name: 'deduplicate', label: 'Удалять дубликаты находок', type: 'boolean', default: true }
      ],
      run: async (inputs, settings) => {
        const combined: Finding[] = [];
        for (const key of Object.keys(inputs)) {
          if (Array.isArray(inputs[key])) {
            combined.push(...inputs[key]);
          }
        }

        const counts = {
          total: combined.length,
          critical: combined.filter(f => f.severity === 'CRITICAL').length,
          high: combined.filter(f => f.severity === 'HIGH').length,
          medium: combined.filter(f => f.severity === 'MEDIUM').length,
          low: combined.filter(f => f.severity === 'LOW').length,
          hasCritical: combined.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
        };

        return {
          allFindings: combined,
          findings: combined,
          counts,
          hasCritical: counts.hasCritical,
          totalCount: counts.total
        };
      }
    });

    // -------------------------------------------------------------------------
    // 4. LOGIC
    // -------------------------------------------------------------------------

    this.register({
      type: 'logic.condition',
      title: 'Условие (If / Else)',
      category: 'Logic',
      icon: 'GitFork',
      color: '#EAB308', // Yellow
      description: 'Ветвление сценария в зависимости от условия (наличие критичных уязвимостей)',
      inputs: [{ id: 'input', label: 'Входные данные', type: 'any' }],
      outputs: [
        { id: 'true', label: 'Да (True)', type: 'any' },
        { id: 'false', label: 'Нет (False)', type: 'any' }
      ],
      settings: [
        {
          name: 'rule',
          label: 'Условие проверки',
          type: 'select',
          default: 'has_critical',
          options: [
            { label: 'Есть критичные/высокие уязвимости (CRITICAL/HIGH)', value: 'has_critical' },
            { label: 'Найдены любые проблемы (Всего > 0)', value: 'has_any' },
            { label: 'Проект чист (Всего == 0)', value: 'is_clean' },
            { label: 'Количество уязвимостей превышает порог', value: 'threshold_count' }
          ]
        },
        { name: 'threshold', label: 'Порог количества (для правила Порог)', type: 'number', default: 1 }
      ],
      run: async (inputs, settings) => {
        const findings: Finding[] = inputs.allFindings || inputs.findings || [];
        const rule = settings.rule || 'has_critical';
        const threshold = Number(settings.threshold) || 1;

        let result = false;
        if (rule === 'has_critical') {
          result = findings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
        } else if (rule === 'has_any') {
          result = findings.length > 0;
        } else if (rule === 'is_clean') {
          result = findings.length === 0;
        } else if (rule === 'threshold_count') {
          result = findings.length >= threshold;
        }

        return {
          result,
          allFindings: findings,
          findings: findings,
          true: result ? inputs : null,
          false: !result ? inputs : null
        };
      }
    });

    // -------------------------------------------------------------------------
    // 5. AI EXPLAINER (CONSOLIDATED AI ANALYSIS)
    // -------------------------------------------------------------------------

    this.register({
      type: 'ai.explainer',
      title: 'AI Анализ',
      category: 'AI',
      icon: 'Sparkles',
      color: '#A855F7', // Violet
      description: 'Анализ рисков, объяснение уязвимостей и рекомендации по исправлению',
      inputs: [
        { id: 'findings', label: 'Находки', type: 'findings' },
        { id: 'codePath', label: 'Путь к коду', type: 'codePath' }
      ],
      outputs: [
        { id: 'aiReport', label: 'AI Отчёт', type: 'aiReport' },
        { id: 'cisoSummary', label: 'Резюме CISO', type: 'any' }
      ],
      settings: [
        {
          name: 'provider',
          label: 'Провайдер AI',
          type: 'select',
          default: 'gigachat',
          options: [
            { label: 'Сбер GigaChat (GigaChat-Pro)', value: 'gigachat' },
            { label: 'Автономный умный анализ (локальный)', value: 'offline-smart' },
            { label: 'Ollama (Локальная модель в контуре)', value: 'ollama' }
          ]
        },
        { name: 'model', label: 'Модель', type: 'string', default: 'GigaChat-Pro' },
        { name: 'credentials', label: 'GigaChat Ключ (Base64)', type: 'password', description: 'Оставьте пустым для ключа из .env (GIGACHAT_CREDENTIALS)' },
        {
          name: 'scope',
          label: 'Область (Scope)',
          type: 'select',
          default: 'GIGACHAT_API_PERS',
          options: [
            { label: 'GIGACHAT_API_PERS (Физические лица)', value: 'GIGACHAT_API_PERS' },
            { label: 'GIGACHAT_API_CORP (Корпоративные клиенты)', value: 'GIGACHAT_API_CORP' }
          ]
        }
      ],
      run: async (inputs, settings) => {
        const findings: Finding[] = inputs.allFindings || inputs.findings || [];
        const useGigaChat = settings.provider === 'gigachat';

        if (useGigaChat) {
          const creds = (settings.credentials || process.env.GIGACHAT_CREDENTIALS || '').trim();
          if (!creds) {
            throw new Error('Не указаны авторизационные данные Сбер GigaChat! Войдите под test/test или привяжите ключ в профиле пользователя.');
          }
          GigaChatClient.getInstance().reloadConfig(creds, settings.scope || process.env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS');
          const token = await GigaChatClient.getInstance().getToken();
          if (!token) {
            throw new Error('Не удалось авторизоваться в Сбер GigaChat! Проверьте правильность GIGACHAT_CREDENTIALS в профиле пользователя.');
          }
        }

        const analyses = await Promise.all(
          findings.map(f => SmartSecurityCategorizer.analyzeFinding(f, useGigaChat))
        );

        const executive = await SmartSecurityCategorizer.generateExecutiveSummary(findings);

        const explanations = analyses.map((a, idx) => {
          const f = findings[idx] as any;
          return {
            category: a.category,
            path: f.path,
            line: f.line,
            class: f.class,
            advisoryId: f.advisoryId,
            severity: f.severity,
            summary: f.description,
            cwe: a.cwe,
            owasp: a.owasp,
            cvssScore: a.cvssScore,
            attackVector: a.attackVector,
            businessImpact: a.businessImpact,
            explanation: `${a.cwe} (${a.owasp}). ${a.attackVector}`,
            remediationPatch: a.remediationPatch,
            verificationStep: a.verificationStep,
            source: a.source
          };
        });

        return {
          aiReport: {
            overallSummary: executive.cisoSummary,
            riskLevel: executive.riskLevel,
            topRecommendations: executive.topRecommendations,
            analyzedWith: executive.analyzedWith,
            explanations,
            generatedAt: executive.generatedAt
          },
          cisoSummary: executive,
          allFindings: findings,
          findings: findings
        };
      }
    });

    // Alias 'ai.gigachat' (hidden from palette, seamlessly delegates to ai.explainer)
    this.register({
      type: 'ai.gigachat',
      title: 'AI Анализ',
      category: 'AI',
      icon: 'Sparkles',
      color: '#A855F7',
      hidden: true,
      description: 'Анализ рисков, объяснение уязвимостей и рекомендации по исправлению',
      inputs: [
        { id: 'findings', label: 'Находки', type: 'findings' },
        { id: 'codePath', label: 'Путь к коду', type: 'codePath' }
      ],
      outputs: [
        { id: 'aiReport', label: 'AI Отчёт', type: 'aiReport' },
        { id: 'cisoSummary', label: 'Резюме CISO', type: 'any' }
      ],
      settings: [
        { name: 'model', label: 'Модель GigaChat', type: 'string', default: 'GigaChat-Pro' },
        { name: 'credentials', label: 'GigaChat Credentials', type: 'password' },
        { name: 'scope', label: 'Scope', type: 'string', default: 'GIGACHAT_API_PERS' }
      ],
      run: async (inputs, settings, context) => {
        const explainer = this.getNode('ai.explainer');
        if (explainer) {
          return explainer.run(inputs, { ...settings, provider: 'gigachat' }, context);
        }
        return { allFindings: inputs.allFindings || inputs.findings || [] };
      }
    } as any);

    // -------------------------------------------------------------------------
    // 6. DUAL REPORT GENERATOR (MANDATORY REQUIREMENT)
    // -------------------------------------------------------------------------

    this.register({
      type: 'report.dual',
      title: 'Экспорт Двойного Отчёта',
      category: 'Reports',
      icon: 'FileText',
      color: '#06B6D4', // Cyan
      description: 'Формирование JSON по строгой спецификации конкурса и читаемого Markdown/HTML отчёта',
      inputs: [
        { id: 'findings', label: 'Находки', type: 'findings' },
        { id: 'aiReport', label: 'AI Отчёт', type: 'aiReport' }
      ],
      outputs: [{ id: 'reportFiles', label: 'Файлы отчётов', type: 'reportFiles' }],
      settings: [
        { name: 'outputDir', label: 'Директория сохранения', type: 'string', default: 'reports' }
      ],
      run: async (inputs, settings, context) => {
        const findings: Finding[] = inputs.allFindings || inputs.findings || [];
        const aiReport = inputs.aiReport;

        // 1. Generate Strict Submission JSON according to submission-format.md
        const cleanFindings = findings.map(f => {
          const item: any = {
            category: f.category,
            path: f.path.replace(/\\/g, '/')
          };

          if (f.category === 'SECRET' || f.category === 'SAST') {
            const sf = f as any;
            item.class = sf.class;
            item.line = sf.line;
            if (sf.endLine && sf.endLine !== sf.line) {
              item.endLine = sf.endLine;
            }
          } else if (f.category === 'SCA') {
            const sca = f as any;
            item.group = sca.group;
            item.artifact = sca.artifact;
            item.version = sca.version;
            item.advisoryId = sca.advisoryId;
          }

          if (f.severity) item.severity = f.severity;
          if (f.description) item.description = f.description;
          if (f.remediation) item.remediation = f.remediation;

          return item;
        });

        const submissionJson = JSON.stringify({ findings: cleanFindings }, null, 2);

        // 2. Generate Human-Readable Markdown Report
        let repoUrl = inputs.repoUrl || (context as any)?.repoUrl || '';
        let branch = inputs.branch || (context as any)?.branch || 'main';
        if (!repoUrl && context && (context as any).nodeOutputs) {
          for (const out of (context as any).nodeOutputs.values()) {
            if (out && out.repoUrl) {
              repoUrl = out.repoUrl;
              if (out.branch) branch = out.branch;
              break;
            }
          }
        }

        let md = `# Отчёт безопасности uncflow\n\n`;
        if (repoUrl) {
          md += `**Репозиторий:** [${repoUrl}](${repoUrl})\n`;
          if (branch && branch !== 'HEAD') {
            md += `**Ветка:** \`${branch}\`\n`;
          }
        }
        md += `**Дата проверки:** ${new Date().toLocaleString('ru-RU')}\n`;
        md += `**Всего проблем обнаружено:** ${findings.length}\n\n`;

        const criticalList = findings.filter(f => f.severity === 'CRITICAL');
        const highList = findings.filter(f => f.severity === 'HIGH');
        const mediumList = findings.filter(f => f.severity === 'MEDIUM');
        const lowList = findings.filter(f => f.severity === 'LOW');

        md += `### Сводка рисков\n`;
        md += `| Уровень | Количество |\n`;
        md += `| :--- | :--- |\n`;
        md += `| 🔴 Критический (CRITICAL) | **${criticalList.length}** |\n`;
        md += `| 🟠 Высокий (HIGH) | **${highList.length}** |\n`;
        md += `| 🟡 Средний (MEDIUM) | **${mediumList.length}** |\n`;
        md += `| 🔵 Низкий (LOW) | **${lowList.length}** |\n\n`;

        if (criticalList.length > 0 || highList.length > 0) {
          md += `> 🚨 **Внимание!** Обнаружены критические уязвимости. Релиз заблокирован до устранения проблем.\n\n`;
        } else if (findings.length > 0) {
          md += `> ⚠️ Обнаружены замечания средней или низкой критичности. Требуется плановое устранение.\n\n`;
        } else {
          md += `> ✅ **Проект безопасен!** Уязвимостей не обнаружено. Сборка разрешена.\n\n`;
        }

        if (aiReport?.overallSummary) {
          md += `## 🛡️ Заключение по безопасности\n\n`;
          md += `${aiReport.overallSummary}\n\n`;
        }

        if (aiReport?.topRecommendations && aiReport.topRecommendations.length > 0) {
          md += `### Рекомендуемые действия:\n`;
          for (let i = 0; i < aiReport.topRecommendations.length; i++) {
            md += `${i + 1}. ${aiReport.topRecommendations[i]}\n`;
          }
          md += `\n`;
        }

        md += `## 📋 Список находок\n\n`;
        md += `| Категория | Идентификатор | Файл и строка | Критичность | Описание |\n`;
        md += `| :--- | :--- | :--- | :--- | :--- |\n`;

        const isRemoteRepo = repoUrl && (repoUrl.includes('github.com') || repoUrl.includes('gitverse.ru'));
        for (const f of cleanFindings) {
          const loc = f.category === 'SCA' ? f.path : `${f.path}:${f.line}${f.endLine ? '-' + f.endLine : ''}`;
          const id = f.category === 'SCA' ? `${f.artifact} (${f.advisoryId})` : f.class;
          const locCell = isRemoteRepo
            ? `[${loc}](${repoUrl.replace(/\.git$/, '')}/blob/${branch}/${f.path}${f.line ? '#L' + f.line : ''})`
            : `\`${loc}\``;
          md += `| **${f.category}** | \`${id}\` | ${locCell} | **${f.severity || 'MEDIUM'}** | ${f.description || ''} |\n`;
        }

        if (aiReport?.explanations && aiReport.explanations.length > 0) {
          md += `\n## 💡 Рекомендации по исправлению\n\n`;
          for (const exp of aiReport.explanations) {
            const id = exp.advisoryId || exp.class || exp.category;
            md += `### ${id} (${exp.severity || 'MEDIUM'})\n`;
            if (exp.cwe) md += `* **Стандарт:** \`${exp.cwe}\`${exp.owasp ? ` (${exp.owasp})` : ''}\n`;
            if (exp.attackVector) md += `* **Суть проблемы:** ${exp.attackVector}\n`;
            if (exp.remediationPatch) {
              md += `* **Пример исправления:**\n\`\`\`kotlin\n${exp.remediationPatch}\n\`\`\`\n`;
            }
            if (exp.verificationStep) md += `* **Как проверить:** \`${exp.verificationStep}\`\n\n`;
          }
        }

        // Save files
        const outDir = path.resolve(process.cwd(), settings.outputDir || 'reports');
        if (!fs.existsSync(outDir)) {
          fs.mkdirSync(outDir, { recursive: true });
        }

        const jsonPath = path.join(outDir, 'submission-report.json');
        const mdPath = path.join(outDir, 'audit-report.md');

        fs.writeFileSync(jsonPath, submissionJson, 'utf-8');
        fs.writeFileSync(mdPath, md, 'utf-8');

        return {
          reportFiles: {
            jsonPath,
            mdPath,
            jsonContent: submissionJson,
            mdContent: md
          },
          submissionJson,
          findingsCount: cleanFindings.length,
          allFindings: findings,
          findings: findings,
          repoUrl,
          branch
        };
      }
    });

    // -------------------------------------------------------------------------
    // 7. NOTIFICATIONS (CONSOLIDATED COMMUNICATION CHANNELS)
    // -------------------------------------------------------------------------

    this.register({
      type: 'notify.channel',
      title: 'Каналы связи',
      category: 'Notifications',
      icon: 'Send',
      color: '#0284C7', // Sky Blue
      description: 'Отправка отчётов и алертов в Telegram, Яндекс Почту и Webhook',
      inputs: [
        { id: 'input', label: 'Отчёт / Данные', type: 'any' },
        { id: 'findings', label: 'Находки', type: 'findings' }
      ],
      outputs: [
        { id: 'sent', label: 'Статус отправки', type: 'boolean' },
        { id: 'channels', label: 'Каналы', type: 'any' }
      ],
      settings: [
        {
          name: 'channel',
          label: 'Канал связи',
          type: 'select',
          default: 'telegram',
          options: [
            { label: 'Telegram (Бот / Чат)', value: 'telegram' },
            { label: 'Яндекс Почта (Email)', value: 'yandex' },
            { label: 'Webhook (HTTP POST)', value: 'webhook' }
          ]
        },
        // Telegram
        { name: 'telegramBotToken', label: 'Telegram Bot Token', type: 'password' },
        { name: 'telegramChatId', label: 'Telegram Chat ID', type: 'string' },
        // Yandex Mail
        { name: 'yandexUser', label: 'Почта Яндекса', type: 'string' },
        { name: 'yandexPassword', label: 'Пароль приложения', type: 'password' },
        { name: 'yandexTo', label: 'Получатель отчёта (Email)', type: 'string' },
        // Webhook
        { name: 'webhookUrl', label: 'Webhook URL', type: 'string' },
        { name: 'webhookSecret', label: 'Секрет (X-Security-Token)', type: 'password' },
        // Filtering
        { name: 'onlyOnCritical', label: 'Только при критических уязвимостях', type: 'boolean', default: false }
      ],
      run: async (inputs, settings, context) => {
        let findings: Finding[] = inputs.allFindings || inputs.findings || inputs.input?.findings || inputs.payload?.findings || [];
        if (findings.length === 0 && context && (context as any).nodeOutputs) {
          for (const out of (context as any).nodeOutputs.values()) {
            if (out && (out.allFindings || out.findings)) {
              findings = out.allFindings || out.findings;
              break;
            }
          }
        }

        const count = findings.length;
        const criticalList = findings.filter(f => f.severity === 'CRITICAL');
        const highList = findings.filter(f => f.severity === 'HIGH');
        const mediumList = findings.filter(f => f.severity === 'MEDIUM');
        const lowList = findings.filter(f => f.severity === 'LOW');
        const criticalCount = criticalList.length + highList.length;

        if (settings.onlyOnCritical && criticalCount === 0) {
          return {
            sent: false,
            skipped: true,
            reason: 'Отправка пропущена: критических проблем не обнаружено (onlyOnCritical: true)',
            findingsCount: count
          };
        }

        let repoUrl = inputs.repoUrl || (context as any)?.repoUrl || '';
        let branch = inputs.branch || (context as any)?.branch || 'main';
        if (!repoUrl && context && (context as any).nodeOutputs) {
          for (const out of (context as any).nodeOutputs.values()) {
            if (out && out.repoUrl) {
              repoUrl = out.repoUrl;
              if (out.branch) branch = out.branch;
              break;
            }
          }
        }

        const channelResults: Record<string, any> = {};
        let anySent = false;
        const selectedChannel = settings.channel || (settings.enableYandex ? 'yandex' : (settings.enableWebhook ? 'webhook' : 'telegram'));

        // 1. Telegram
        if (selectedChannel === 'telegram') {
          const tgBotToken = (settings.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN || '').trim();
          const tgChatId = (settings.telegramChatId || process.env.TELEGRAM_CHAT_ID || '@security_audit').trim();

          let tgMessage = `🛡️ *uncflow — Отчёт проверки безопасности*\n\n`;
          if (repoUrl) {
            tgMessage += `🔗 *Репозиторий:* [${repoUrl}](${repoUrl})\n`;
            if (branch && branch !== 'HEAD') {
              tgMessage += `🌿 *Ветка:* \`${branch}\`\n`;
            }
          }
          tgMessage += `📅 *Дата проверки:* ${new Date().toLocaleString('ru-RU')}\n`;
          tgMessage += `📊 *Всего находок:* *${count}*\n`;
          tgMessage += `• 🔴 CRITICAL: *${criticalList.length}*\n`;
          tgMessage += `• 🟠 HIGH: *${highList.length}*\n`;
          tgMessage += `• 🟡 MEDIUM: *${mediumList.length}*\n`;
          tgMessage += `• 🔵 LOW: *${lowList.length}*\n\n`;

          if (criticalCount > 0) {
            tgMessage += `🚨 *ВНИМАНИЕ! Обнаружены критические риски безопасности! Релиз заблокирован.*\n\n`;
          } else if (count > 0) {
            tgMessage += `⚠️ *Замечания средней/низкой важности. Проект требует планового исправления.*\n\n`;
          } else {
            tgMessage += `✅ *Критических рисков не выявлено. Проект безопасен.*\n\n`;
          }

          if (count > 0) {
            tgMessage += `📋 *Ключевые находки:*\n`;
            const topFindings = [...criticalList, ...highList, ...mediumList, ...lowList].slice(0, 5);
            const isRemote = repoUrl && (repoUrl.includes('github.com') || repoUrl.includes('gitverse.ru'));
            const cleanRepo = repoUrl.replace(/\.git$/, '');

            for (let i = 0; i < topFindings.length; i++) {
              const f = topFindings[i] as any;
              const icon = f.severity === 'CRITICAL' ? '🔴' : (f.severity === 'HIGH' ? '🟠' : (f.severity === 'MEDIUM' ? '🟡' : '🔵'));
              const id = f.class || f.advisoryId || f.category;
              const fullLoc = f.path ? `${f.path}${f.line ? ':' + f.line : ''}` : '';

              tgMessage += `${icon} *[${f.category}]* \`${id}\`\n`;
              if (fullLoc) {
                if (isRemote) {
                  const link = `${cleanRepo}/blob/${branch}/${f.path}${f.line ? '#L' + f.line : ''}`;
                  tgMessage += `   📁 [${fullLoc}](${link})\n`;
                } else {
                  tgMessage += `   📁 \`${fullLoc}\`\n`;
                }
              }
              if (f.description) {
                const shortDesc = f.description.length > 80 ? f.description.substring(0, 77) + '...' : f.description;
                tgMessage += `   _${shortDesc.replace(/[*_`]/g, '')}_\n`;
              }
            }
          }

          if (!tgBotToken || !tgChatId || tgChatId === '@security_audit') {
            throw new Error('Не указан Telegram Bot Token или Chat ID! Укажите параметры в профиле (или войдите под test / test).');
          }

          try {
            const resp = await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                chat_id: tgChatId,
                text: tgMessage,
                parse_mode: 'Markdown'
              }),
              signal: AbortSignal.timeout(8000)
            });
            const resJson = await resp.json();
            const ok = resp.ok && resJson.ok;
            if (!ok) {
              throw new Error(`Telegram API: ${resJson.description || resp.statusText || 'Проверьте токен бота и ID чата'}`);
            }
            anySent = true;
            channelResults.telegram = {
              sent: true,
              chatId: tgChatId,
              messageId: resJson.result?.message_id
            };
          } catch (err: any) {
            throw new Error(`Не удалось доставить сообщение в Telegram: ${err.message}`);
          }
        }

        // 2. Yandex Mail
        if (selectedChannel === 'yandex') {
          const yUser = (settings.yandexUser || '').trim();
          const yPass = (settings.yandexPassword || '').trim();
          const yTo = (settings.yandexTo || yUser || '').trim();

          if (!yUser || !yPass || !yTo) {
            throw new Error('Не указаны реквизиты Яндекс Почты (логин, пароль приложения или получатель)! Заполните их в профиле пользователя.');
          }

          const emailSubject = `uncflow: Отчёт безопасности ${repoUrl ? `(${path.basename(repoUrl)})` : ''} — ${criticalCount > 0 ? '🚨 КРИТИЧЕСКИЕ РИСКИ' : '✅ ДОПУЩЕН'}`;
          const emailHtml = formatSecurityEmailHtml({
            repoUrl,
            branch,
            findings
          });

          const mailRes = await sendYandexMail({
            user: yUser,
            password: yPass,
            to: yTo,
            subject: emailSubject,
            html: emailHtml
          });

          if (!mailRes.sent) {
            throw new Error(`Не удалось отправить отчёт по Яндекс Почте: ${mailRes.error || 'Ошибка SMTP соединения'}`);
          }
          anySent = true;
          channelResults.yandexMail = mailRes;
        }

        // 3. Webhook
        if (selectedChannel === 'webhook') {
          const whUrl = (settings.webhookUrl || '').trim();
          const whSecret = (settings.webhookSecret || '').trim();

          if (!whUrl) {
            throw new Error('Не указан Webhook URL! Укажите адрес приёмника в профиле пользователя или параметрах блока.');
          }

          const isRemote = repoUrl && (repoUrl.includes('github.com') || repoUrl.includes('gitverse.ru'));
          const cleanRepo = repoUrl.replace(/\.git$/, '');

          const payload = {
            event: 'security_audit_completed',
            text: `🛡️ uncflow: Аудит безопасности завершён для ${repoUrl || 'проекта'}. Найдено ${count} уязвимостей (${criticalList.length} CRIT, ${highList.length} HIGH).`,
            timestamp: new Date().toISOString(),
            repoUrl,
            branch,
            summary: {
              totalFindings: count,
              criticalCount: criticalList.length,
              highCount: highList.length,
              mediumCount: mediumList.length,
              lowCount: lowList.length
            },
            findings: findings.map((f: any) => ({
              category: f.category,
              class: f.class || f.advisoryId || f.category,
              severity: f.severity,
              filePath: f.path,
              line: f.line,
              endLine: f.endLine,
              description: f.description,
              remediation: f.remediation,
              sourceUrl: (isRemote && f.path) ? `${cleanRepo}/blob/${branch}/${f.path}${f.line ? '#L' + f.line : ''}` : null
            }))
          };

          try {
            const headers: Record<string, string> = { 'Content-Type': 'application/json' };
            if (whSecret) headers['X-Security-Token'] = whSecret;

            const resp = await fetch(whUrl, {
              method: 'POST',
              headers,
              body: JSON.stringify(payload),
              signal: AbortSignal.timeout(8000)
            });
            if (!resp.ok) {
              throw new Error(`Приёмник Webhook вернул HTTP ${resp.status} ${resp.statusText}`);
            }
            anySent = true;
            channelResults.webhook = {
              sent: true,
              status: resp.status,
              targetUrl: whUrl
            };
          } catch (err: any) {
            throw new Error(`Не удалось доставить Webhook на ${whUrl}: ${err.message}`);
          }
        }

        return {
          sent: anySent,
          channels: channelResults,
          findingsCount: count,
          repoUrl,
          branch,
          deliveredAt: new Date().toISOString()
        };
      }
    });

    // Hidden backward compatibility aliases for templates & existing workflows
    this.register({
      type: 'notify.telegram',
      title: 'Каналы связи (Telegram)',
      category: 'Notifications',
      icon: 'Send',
      color: '#0284C7',
      hidden: true,
      description: 'Отправка отчёта в Telegram',
      inputs: [{ id: 'input', label: 'Отчёт / Данные', type: 'any' }],
      outputs: [{ id: 'sent', label: 'Статус', type: 'boolean' }],
      settings: [
        { name: 'botToken', label: 'Telegram Bot Token', type: 'password' },
        { name: 'chatId', label: 'Chat ID / Канал', type: 'string', default: '@security_audit' },
        { name: 'onlyOnCritical', label: 'Только при критических', type: 'boolean', default: false }
      ],
      run: async (inputs, settings, context) => {
        const channelNode = this.getNode('notify.channel');
        if (channelNode) {
          return channelNode.run(inputs, {
            ...settings,
            channel: 'telegram',
            telegramBotToken: settings.botToken || settings.telegramBotToken,
            telegramChatId: settings.chatId || settings.telegramChatId,
            onlyOnCritical: settings.onlyOnCritical
          }, context);
        }
        throw new Error('Блок notify.channel не найден в системе.');
      }
    } as any);

    this.register({
      type: 'notify.webhook',
      title: 'Каналы связи (Webhook)',
      category: 'Notifications',
      icon: 'Globe',
      color: '#4B5563',
      hidden: true,
      description: 'Отправка результатов на внешний Webhook',
      inputs: [{ id: 'payload', label: 'Данные', type: 'any' }, { id: 'findings', label: 'Находки', type: 'findings' }],
      outputs: [{ id: 'sent', label: 'Статус', type: 'boolean' }],
      settings: [
        { name: 'url', label: 'Webhook URL', type: 'string', default: '' },
        { name: 'secretHeader', label: 'Секретный токен', type: 'password' },
        { name: 'onlyOnCritical', label: 'Только при Critical/High', type: 'boolean', default: false }
      ],
      run: async (inputs, settings, context) => {
        const channelNode = this.getNode('notify.channel');
        if (channelNode) {
          return channelNode.run(inputs, {
            ...settings,
            channel: 'webhook',
            webhookUrl: settings.url || settings.webhookUrl,
            webhookSecret: settings.secretHeader || settings.webhookSecret,
            onlyOnCritical: settings.onlyOnCritical
          }, context);
        }
        throw new Error('Блок notify.channel не найден в системе.');
      }
    } as any);

    // -------------------------------------------------------------------------
    // 8. STORAGE (POSTGRESQL)
    // -------------------------------------------------------------------------

    this.register({
      type: 'storage.postgres',
      title: 'Экспорт в PostgreSQL',
      category: 'Storage',
      icon: 'Database',
      color: '#336791', // PostgreSQL Blue
      description: 'Сохранение находок уязвимостей, отчётов и статистики в PostgreSQL базу данных',
      inputs: [
        { id: 'input', label: 'Находки / Отчёт', type: 'any' }
      ],
      outputs: [
        { id: 'saved', label: 'Сохранено', type: 'boolean' },
        { id: 'count', label: 'Количество записей', type: 'number' }
      ],
      settings: [
        { name: 'tableName', label: 'Таблица назначения', type: 'string', default: 'findings' },
        { name: 'saveReport', label: 'Также сохранять Dual Report', type: 'boolean', default: true }
      ],
      run: async (inputs, settings, context) => {
        const findings: Finding[] = inputs.allFindings || inputs.findings || inputs.input?.findings || [];
        const runId = context?.runId || `run_${Date.now()}`;

        if (findings.length > 0) {
          await db.saveFindings(runId, findings);
        }

        if (settings.saveReport && inputs.reportFiles) {
          const critical = findings.filter(f => f.severity === 'CRITICAL').length;
          const high = findings.filter(f => f.severity === 'HIGH').length;
          const medium = findings.filter(f => f.severity === 'MEDIUM').length;
          const low = findings.filter(f => f.severity === 'LOW').length;

          await db.saveReport({
            runId,
            totalVulnerabilities: findings.length,
            summary: { critical, high, medium, low },
            jsonContent: inputs.submissionJson || { findings },
            markdownContent: inputs.reportFiles.mdContent || ''
          });
        }

        return {
          saved: true,
          count: findings.length,
          runId,
          target: 'postgresql'
        };
      }
    });
  }
}
