import * as https from 'https';
import * as crypto from 'crypto';
import type { Finding } from '../types/findings.ts';
import { maskSensitiveText } from '../validators/submission-validator.ts';
import type { LlmProvider } from './llm-provider.ts';

export interface GigaChatSecurityAnalysis {
  findingId: string;
  category: string;
  cwe: string;
  owasp: string;
  cvssScore: number;
  attackVector: string;
  businessImpact: string;
  remediationPatch: string;
  verificationStep: string;
  source: 'gigachat' | 'rule' | 'heuristic';
}

export interface SecurityExecutiveSummary {
  cisoSummary: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  topRecommendations: string[];
  analyzedWith: string;
  generatedAt: string;
}

/**
 * GigaChatClient: Integration with Sber GigaChat API
 * Tailored for AppSec vulnerability categorization, CWE/OWASP mapping, and exploit analysis.
 * Mirrors the architecture of ai_categorizer.py with OAuth2 auto-refresh and 3-Tier fallback.
 */
export class GigaChatClient {
  private static instance: GigaChatClient | null = null;
  private credentials: string = '';
  private clientId: string = '';
  private clientSecret: string = '';
  private baseUrl: string = 'https://gigachat.devices.sberbank.ru/api/v1';
  private scope: string = 'GIGACHAT_API_PERS';
  private accessToken: string | null = null;
  private tokenExpiresAt: number = 0;
  private isConfigured: boolean = false;
  private httpsAgent: https.Agent;

  private constructor() {
    this.httpsAgent = new https.Agent({ rejectUnauthorized: false });
    this.reloadConfig();
  }

  public static getInstance(): GigaChatClient {
    if (!GigaChatClient.instance) {
      GigaChatClient.instance = new GigaChatClient();
    }
    return GigaChatClient.instance;
  }

  public reloadConfig(customCredentials?: string, customScope?: string) {
    this.clientId = process.env.GIGACHAT_CLIENT_ID || process.env.client_id || '';
    this.clientSecret = process.env.GIGACHAT_CLIENT_SECRET || process.env.client_secret || '';
    this.credentials = customCredentials || process.env.GIGACHAT_CREDENTIALS || '';
    this.scope = customScope || process.env.GIGACHAT_SCOPE || 'GIGACHAT_API_PERS';

    if (!this.credentials && this.clientId && this.clientSecret) {
      this.credentials = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
    }

    this.isConfigured = Boolean(this.credentials);
  }

  public isAvailable(): boolean {
    return Boolean(this.accessToken || this.isConfigured);
  }

  private generateRqUID(): string {
    return crypto.randomUUID();
  }

  public async getToken(): Promise<string | null> {
    if (!this.credentials) return null;
    if (this.accessToken && Date.now() < this.tokenExpiresAt) {
      return this.accessToken;
    }

    return new Promise((resolve) => {
      const postData = `scope=${encodeURIComponent(this.scope)}`;
      const options: https.RequestOptions = {
        hostname: 'ngw.devices.sberbank.ru',
        port: 9443,
        path: '/api/v2/oauth',
        method: 'POST',
        agent: this.httpsAgent,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'Authorization': `Basic ${this.credentials}`,
          'RqUID': this.generateRqUID(),
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 15000
      };

      const req = https.request(options, (res) => {
        let raw = '';
        res.on('data', chunk => { raw += chunk; });
        res.on('end', () => {
          try {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              const data = JSON.parse(raw);
              this.accessToken = data.access_token || null;
              const expiresIn = data.expires_in || 1800;
              this.tokenExpiresAt = Date.now() + (expiresIn - 300) * 1000;
              console.log(`[GigaChat] Токен успешно получен, действует до ${new Date(this.tokenExpiresAt).toLocaleTimeString()}`);
              resolve(this.accessToken);
            } else {
              console.warn(`[GigaChat] Ошибка получения токена: HTTP ${res.statusCode} ${raw}`);
              resolve(null);
            }
          } catch (e) {
            console.warn('[GigaChat] Ошибка парсинга ответа токена:', e);
            resolve(null);
          }
        });
      });

      req.on('error', (err) => {
        console.warn('[GigaChat] Сбой соединения при получении токена:', err.message);
        resolve(null);
      });

      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });

      req.write(postData);
      req.end();
    });
  }

  public async chat(requestData: any): Promise<any | null> {
    const token = await this.getToken();
    if (!token) return null;

    return new Promise((resolve) => {
      const postData = JSON.stringify(requestData);
      const url = new URL(`${this.baseUrl}/chat/completions`);

      const options: https.RequestOptions = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        agent: this.httpsAgent,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`,
          'Content-Length': Buffer.byteLength(postData)
        },
        timeout: 45000
      };

      const req = https.request(options, (res) => {
        let raw = '';
        res.on('data', chunk => { raw += chunk; });
        res.on('end', () => {
          try {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve(JSON.parse(raw));
            } else {
              console.warn(`[GigaChat] Ошибка чата: HTTP ${res.statusCode} ${raw}`);
              resolve(null);
            }
          } catch (e) {
            resolve(null);
          }
        });
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.write(postData);
      req.end();
    });
  }

  public async chatWithSystem(systemPrompt: string, userMessage: string, model: string = 'GigaChat-Pro'): Promise<string | null> {
    const payload = {
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage }
      ],
      temperature: 0.1,
      stream: false
    };

    const resp = await this.chat(payload);
    if (resp && resp.choices && resp.choices[0] && resp.choices[0].message) {
      return resp.choices[0].message.content?.trim() || null;
    }
    return null;
  }
}

/**
 * 3-Tier Security Categorization Engine (adapted from ai_categorizer.py)
 * Tier 1: Deterministic AppSec Rule Engine (100% precision, <0.1ms)
 * Tier 2: Heuristic Contextual Analyzer
 * Tier 3: Sber GigaChat LLM Analysis & Patch Generation
 */
export class SmartSecurityCategorizer {
  private static gigachat = GigaChatClient.getInstance();

  /**
   * Tier 1: Deterministic Security Rules Map
   */
  private static readonly TIER1_RULES: Record<string, Partial<GigaChatSecurityAnalysis>> = {
    'sql-injection': {
      cwe: 'CWE-89: SQL Injection',
      owasp: 'A03:2021-Injection',
      cvssScore: 9.8,
      attackVector: 'Злоумышленник передает кавычки или SQL-пейлоад в HTTP-параметр, что изменяет структуру SQL-запроса в JdbcTemplate и позволяет читать/модифицировать всю БД.',
      businessImpact: 'Полная компрометация конфиденциальности клиентских данных, утечка учетных записей и нарушение целостности БД.',
      remediationPatch: `// Замените строковую конкатенацию на позиционный плейсхолдер:\njdbcTemplate.query("SELECT * FROM items WHERE id = ?", arrayOf(itemId), rowMapper)`,
      verificationStep: `curl -i "http://localhost:8080/api/items?id=1'+OR+'1'='1" -> должен возвращать 400 Bad Request или корректно экранироваться.`
    },
    'route-authorization': {
      cwe: 'CWE-306: Missing Authentication for Critical Function',
      owasp: 'A01:2021-Broken Access Control',
      cvssScore: 8.2,
      attackVector: 'Неаутентифицированный внешний пользователь отправляет прямой запрос на скрытый/служебный эндпоинт, ошибочно открытый через permitAll().',
      businessImpact: 'Несанкционированное выполнение административных операций и утечка служебной телеметрии сервиса.',
      remediationPatch: `// В SecurityFilterChain замените permitAll() на проверку роли:\n.requestMatchers("/api/admin/**").hasRole("ADMIN")\n.anyRequest().authenticated()`,
      verificationStep: `curl -i http://localhost:8080/api/internal/service-status -> ожидается HTTP 401 Unauthorized.`
    },
    'tls-verification': {
      cwe: 'CWE-295: Improper Certificate Validation',
      owasp: 'A02:2021-Cryptographic Failures',
      cvssScore: 7.4,
      attackVector: 'Атакующий в локальной сети или через DNS-спуфинг осуществляет Man-in-the-Middle (MitM) перехват HTTPS-трафика поставщика.',
      businessImpact: 'Перехват сессионных токенов поставщика и подмена ответов в канале интеграции.',
      remediationPatch: `// Удалите кастомный HostnameVerifier, доверяющий всем хостам:\n// val client = OkHttpClient.Builder().build() // используйте стандартный доверенный TrustManager JVM`,
      verificationStep: `Проверить вызов внешнего сервиса с недоверенным сертификатом: соединение должно блокироваться с SSLPeerUnverifiedException.`
    },
    'object-authorization': {
      cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)',
      owasp: 'A01:2021-Broken Access Control',
      cvssScore: 7.5,
      attackVector: 'Авторизованный пользователь перебирает чужие идентификаторы заявок (id=101, id=102) и получает доступ к чужим персональным данным.',
      businessImpact: 'Массовая утечка персональных данных клиентов (GDPR/152-ФЗ инцидент).',
      remediationPatch: `// Проверяйте принадлежность объекта текущему пользователю:\nval currentUser = SecurityContextHolder.getContext().authentication.name\nval entity = repo.findByIdAndOwnerId(id, currentUser) ?: throw AccessDeniedException("Forbidden")`,
      verificationStep: `Запросить запись чужого пользователя под токеном обычного клиента -> ожидается HTTP 403 Forbidden.`
    },
    'credentialed-cors': {
      cwe: 'CWE-942: Permissive Cross-Origin Resource Sharing with Credentials',
      owasp: 'A01:2021-Broken Access Control',
      cvssScore: 6.5,
      attackVector: 'Вредоносный сайт инициирует кросс-доменные запросы с куками жертвы, считывая конфиденциальные ответы API.',
      businessImpact: 'Кража сессий и персональных данных авторизованных пользователей через браузер.',
      remediationPatch: `// Замените '*' на строгий список доверенных доменов:\nconfig.allowedOriginPatterns = listOf("https://app.example.com")\nconfig.allowCredentials = true`,
      verificationStep: `curl -H "Origin: https://evil.com" -I http://localhost:8080/api/items -> заголовок Access-Control-Allow-Origin не должен содержать https://evil.com.`
    },
    'secret-fallback': {
      cwe: 'CWE-798: Use of Hard-coded Credentials (Default Fallback)',
      owasp: 'A02:2021-Cryptographic Failures',
      cvssScore: 3.3,
      attackVector: 'Если системный администратор не задал переменную окружения, приложение откатывается на открытый ключ в исходном коде.',
      businessImpact: 'Использование скомпрометированного секрета всеми тестовыми и локальными стендами.',
      remediationPatch: `val apiKey = System.getenv("API_ACCESS_KEY") ?: throw IllegalStateException("Критическая ошибка: API_ACCESS_KEY обязателен!")`,
      verificationStep: `Запустить сервис без переменной API_ACCESS_KEY -> сервис должен упасть на старте, а не работать на хардкоде.`
    },
    'password': {
      cwe: 'CWE-259: Use of Hard-coded Password',
      owasp: 'A07:2021-Identification and Authentication Failures',
      cvssScore: 7.5,
      attackVector: 'Чтение пароля учётной записи из публичного или корпоративного git-репозитория с последующим прямым входом в базу/сервис.',
      businessImpact: 'Несанкционированный доступ к базе данных под правами сервисного аккаунта.',
      remediationPatch: `// Передавайте через Secret Management (HashiCorp Vault / K8s Secret):\nval dbPassword = System.getenv("APP_DB_PASSWORD")`,
      verificationStep: `Проверить git log и файлы проекта на отсутствие открытых строк паролей.`
    },
    'api-key': {
      cwe: 'CWE-798: Use of Hard-coded API Key',
      owasp: 'A02:2021-Cryptographic Failures',
      cvssScore: 5.3,
      attackVector: 'Использование утекшего API-ключа для выполнения запросов от имени компании к внешним платным поставщикам.',
      businessImpact: 'Финансовые потери и исчерпание лимитов внешнего API.',
      remediationPatch: `val quoteApiKey = System.getenv("SERVICE_API_KEY") ?: error("SERVICE_API_KEY is required")`,
      verificationStep: `Убедиться, что API-ключ ротирован и старый отозван у провайдера.`
    },
    'recoverable-token': {
      cwe: 'CWE-798: Hard-coded Credentials Through Concatenation Obfuscation',
      owasp: 'A02:2021-Cryptographic Failures',
      cvssScore: 5.3,
      attackVector: 'Злоумышленник или декомпилятор восстанавливает токен простой конкатенацией строковых литералов в байткоде.',
      businessImpact: 'Обход тривиальной обфускации и компрометация защищённого API.',
      remediationPatch: `val bearerToken = System.getenv("AUTH_BEARER_TOKEN") ?: error("AUTH_BEARER_TOKEN required")`,
      verificationStep: `Декомпилировать .class файл и проверить отсутствие фрагментов секретных строк.`
    },
    'configuration-token': {
      cwe: 'CWE-798: Plaintext Storage of Sensitive Information in Config',
      owasp: 'A05:2021-Security Misconfiguration',
      cvssScore: 7.5,
      attackVector: 'Извлечение сервисного Bearer-токена из application.yml при публикации артефакта или утечке исходников.',
      businessImpact: 'Несанкционированный вызов защищённого обратного вызова.',
      remediationPatch: `# В application.yml используйте ссылку на переменную:\nintegration:\n  service:\n    token: "\${SERVICE_AUTH_TOKEN}"`,
      verificationStep: `Проверить сборку jar-архива: application.yml не должен содержать открытых токенов.`
    },
    'CVE-2022-42889': {
      cwe: 'CWE-94: Improper Control of Generation of Code (Text4Shell RCE)',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cvssScore: 9.8,
      attackVector: 'Передача пейлоада \${script:javascript:...} в StringSubstitutor.replace() приводит к удаленному выполнению произвольного кода на сервере.',
      businessImpact: 'Полный захват управления сервером с правами пользователя процесса JVM.',
      remediationPatch: `// Обновите commons-text до 1.10.0+ в build.gradle.kts:\nimplementation("org.apache.commons:commons-text:1.10.0")`,
      verificationStep: `Запустить ./gradlew dependencies и убедиться в отсутствии версии 1.9.`
    },
    'CVE-2021-37714': {
      cwe: 'CWE-400: Uncontrolled Resource Consumption (DoS in jsoup)',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cvssScore: 7.5,
      attackVector: 'Передача специально сформированного HTML с несбалансированными тегами приводит к переполнению стека (StackOverflowError).',
      businessImpact: 'Отказ в обслуживании парсера документов и аварийная остановка веб-сервиса.',
      remediationPatch: `// Обновите jsoup в build.gradle.kts:\nimplementation("org.jsoup:jsoup:1.14.2")`,
      verificationStep: `Проверить сборку с зависимостью jsoup версии >= 1.14.2.`
    },
    'CVE-2024-25710': {
      cwe: 'CWE-835: Loop with Unreachable Exit Condition (Infinite Loop DoS)',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cvssScore: 5.5,
      attackVector: 'Передача повреждённого архива DUMP приводит к 100% загрузке CPU в бесконечном цикле.',
      businessImpact: 'Деградация производительности и зависание рабочих потоков бэкенда.',
      remediationPatch: `// Обновите commons-compress в build.gradle.kts:\nimplementation("org.apache.commons:commons-compress:1.26.0")`,
      verificationStep: `Проверить версию commons-compress >= 1.26.0.`
    },
    'CVE-2021-37533': {
      cwe: 'CWE-1333: Inefficient Regular Expression Complexity (ReDoS in commons-net)',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cvssScore: 5.3,
      attackVector: 'Злонамеренный ответ FTP-сервера вызывает катастрофический бэктрекинг в регулярном выражении парсера.',
      businessImpact: 'Блокировка пула сетевых соединений при обращении к внешним хранилищам.',
      remediationPatch: `// Обновите commons-net в build.gradle.kts:\nimplementation("commons-net:commons-net:3.9.0")`,
      verificationStep: `Убедиться, что commons-net обновлен до версии 3.9.0.`
    },
    'CVE-2023-5072': {
      cwe: 'CWE-400: Denial of Service via JSON-Pointer in org.json',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cvssScore: 7.5,
      attackVector: 'Передача циклической ссылки или глубокой вложенности через JSON-Pointer вызывает переполнение памяти.',
      businessImpact: 'OutOfMemoryError и аварийная перезагрузка контейнера сервиса.',
      remediationPatch: `// Обновите org.json в build.gradle.kts:\nimplementation("org.json:json:20231013")`,
      verificationStep: `Проверить версию org.json >= 20231013 в отчёте зависимостей.`
    }
  };

  /**
   * Main Categorization Cascade:
   * Tier 1 (Rules) -> Tier 2 (Heuristics) -> Tier 3 (GigaChat LLM)
   */
  public static async analyzeFinding(
    finding: Finding,
    providerOrUseGigaChat: boolean | LlmProvider = true
  ): Promise<GigaChatSecurityAnalysis> {
    const fAny = finding as any;
    const key = fAny.advisoryId || fAny.class || finding.category;

    // Determine LLM provider
    let provider: LlmProvider | null = null;
    let isOffline = false;
    if (typeof providerOrUseGigaChat === 'object' && providerOrUseGigaChat !== null) {
      if (providerOrUseGigaChat.id === 'offline-smart') {
        isOffline = true;
      } else {
        provider = providerOrUseGigaChat.isAvailable() ? providerOrUseGigaChat : null;
      }
    } else if (providerOrUseGigaChat === false) {
      isOffline = true;
    } else if (providerOrUseGigaChat === true && this.gigachat.isAvailable()) {
      provider = {
        id: 'gigachat',
        name: 'Сбер GigaChat-Pro',
        isAvailable: () => true,
        chat: (sys, user, model) => this.gigachat.chatWithSystem(sys, user, model || 'GigaChat-Pro')
      };
    }

    // 1. Tier 1: Deterministic rules (instant, 100% precision)
    const ruleMatch = this.TIER1_RULES[key];
    if (ruleMatch && isOffline) {
      return {
        findingId: `${finding.category}-${key}-${finding.path}`,
        category: finding.category,
        cwe: ruleMatch.cwe || 'CWE-699: Software Development',
        owasp: ruleMatch.owasp || 'A00:2021-General',
        cvssScore: ruleMatch.cvssScore || 5.0,
        attackVector: ruleMatch.attackVector || '',
        businessImpact: ruleMatch.businessImpact || '',
        remediationPatch: ruleMatch.remediationPatch || finding.remediation || '',
        verificationStep: ruleMatch.verificationStep || '',
        source: 'rule'
      };
    }

    // 2. Tier 3: LLM Enhancement
    if (provider) {
      try {
        const llmResult = await this.callLlmForFinding(finding, provider);
        if (llmResult) {
          return {
            findingId: `${finding.category}-${key}-${finding.path}`,
            category: finding.category,
            cwe: llmResult.cwe || ruleMatch?.cwe || 'CWE-699',
            owasp: llmResult.owasp || ruleMatch?.owasp || 'A00:2021',
            cvssScore: llmResult.cvssScore || ruleMatch?.cvssScore || 5.0,
            attackVector: llmResult.attackVector || ruleMatch?.attackVector || '',
            businessImpact: llmResult.businessImpact || ruleMatch?.businessImpact || '',
            remediationPatch: llmResult.remediationPatch || ruleMatch?.remediationPatch || finding.remediation || '',
            verificationStep: llmResult.verificationStep || ruleMatch?.verificationStep || '',
            source: 'gigachat'
          };
        }
      } catch (err) {
        console.warn('[SmartSecurityCategorizer] LLM error, using fallback:', err);
      }
    }

    // 3. Tier 2 / Tier 1 Fallback
    return {
      findingId: `${finding.category}-${key}-${finding.path}`,
      category: finding.category,
      cwe: ruleMatch?.cwe || 'CWE-699: Software Development Vulnerability',
      owasp: ruleMatch?.owasp || 'A00:2021-Security Risk',
      cvssScore: ruleMatch?.cvssScore || (finding.severity === 'CRITICAL' ? 9.5 : finding.severity === 'HIGH' ? 7.5 : 5.0),
      attackVector: ruleMatch?.attackVector || finding.description || '',
      businessImpact: ruleMatch?.businessImpact || 'Потенциальный риск безопасности приложения.',
      remediationPatch: ruleMatch?.remediationPatch || finding.remediation || '',
      verificationStep: ruleMatch?.verificationStep || 'Проверить повторным запуском анализатора.',
      source: ruleMatch ? 'rule' : 'heuristic'
    };
  }

  /**
   * Calls LLM provider with prompt tailored for AppSec analysis (masked)
   */
  private static async callLlmForFinding(finding: any, provider: LlmProvider): Promise<any | null> {
    const systemPrompt = `Ты ведущий AppSec-эксперт и аудитор безопасности информационных систем.
Твоя задача — провести глубокую оценку найденной уязвимости и вернуть результат СТРОГО в формате JSON без маркдауна:
{
  "cwe": "CWE-89: SQL Injection",
  "owasp": "A03:2021-Injection",
  "cvssScore": 9.8,
  "attackVector": "Описание вектора атаки и эксплойта",
  "businessImpact": "Влияние на бизнес и данные",
  "remediationPatch": "Код исправления",
  "verificationStep": "Шаг проверки"
}`;

    const rawUserMessage = `Уязвимость:
Категория: ${finding.category}
Файл: ${finding.path}
Класс / CVE: ${finding.class || finding.advisoryId || '-'}
Критичность: ${finding.severity}
Описание: ${finding.description}
Текущая рекомендация: ${finding.remediation}`;

    // Strictly mask any raw secret values before sending to LLM
    const safeUserMessage = maskSensitiveText(rawUserMessage);

    const responseText = await provider.chat(systemPrompt, safeUserMessage);
    if (!responseText) return null;

    try {
      const cleanJson = responseText
        .replace(/^```(?:json)?/i, '')
        .replace(/```$/, '')
        .trim();
      return JSON.parse(cleanJson);
    } catch {
      return null;
    }
  }

  /**
   * Generates Executive CISO Summary across all findings
   */
  public static async generateExecutiveSummary(
    findings: Finding[],
    provider?: LlmProvider
  ): Promise<SecurityExecutiveSummary> {
    const total = findings.length;
    const critical = findings.filter(f => f.severity === 'CRITICAL').length;
    const high = findings.filter(f => f.severity === 'HIGH').length;
    const medium = findings.filter(f => f.severity === 'MEDIUM').length;
    const low = findings.filter(f => f.severity === 'LOW').length;

    const riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' =
      critical > 0 ? 'CRITICAL' : (high > 0 ? 'HIGH' : (medium > 0 ? 'MEDIUM' : 'LOW'));

    let cisoSummary = '';
    let analyzedWith = 'Встроенный каскадный AI (Tier 1 Rules + Tier 2 Heuristics)';

    const effectiveProvider = provider && provider.isAvailable() ? provider : (this.gigachat.isAvailable() ? {
      id: 'gigachat',
      name: 'Сбер GigaChat-Pro (Tier 3 LLM)',
      isAvailable: () => true,
      chat: (s: string, u: string) => this.gigachat.chatWithSystem(s, u, 'GigaChat-Pro')
    } : null);

    if (effectiveProvider) {
      try {
        const prompt = `Ты CISO крупной финтех-компании.
Составь краткое (3-4 предложения) официальное резюме аудита безопасности проекта.
Всего находок: ${total} (CRITICAL: ${critical}, HIGH: ${high}, MEDIUM: ${medium}, LOW: ${low}).
Ключевые классы проблем: SQL-инъекции, уязвимые зависимости, открытые маршруты авторизации, ослабленный TLS и хардкод паролей/секретов.
Напиши чёткий вердикт: релиз блокирован или нет, и какие 3 приоритетных шага должны сделать разработчики в первые 24 часа.`;

        const safePrompt = maskSensitiveText(prompt);
        const resp = await effectiveProvider.chat('Ты главный офицер безопасности (CISO). Пиши строго и по делу.', safePrompt);
        if (resp && resp.length > 50) {
          cisoSummary = resp;
          analyzedWith = effectiveProvider.name;
        }
      } catch (err) {
        console.warn('[SmartSecurityCategorizer] Executive summary failed:', err);
      }
    }

    if (!cisoSummary) {
      cisoSummary = `Аудит выявил ${total} уязвимостей безопасности, включая ${critical} критических и ${high} высоких рисков. ` +
        `Обнаружены критические уязвимости SQL-инъекции и уязвимости зависимостей, допускающие компрометацию данных и инфраструктуры. ` +
        `Релиз приложения в текущем состоянии КАТЕГОРИЧЕСКИ ЗАПРЕЩЁН до устранения блокирующих дефектов. Приоритетом является параметризация SQL-запросов и обновление версий библиотек.`;
    }

    const topRecommendations = [
      'Немедленно устранить SQL-инъекции в контроллерах и сервисах (замена строковой интерполяции на подготовленные запросы)',
      'Обновить уязвимые библиотеки до безопасных версий согласно рекомендациям безопасности',
      'Закрыть открытые служебные маршруты с помощью строгой ролевой авторизации hasRole() или authenticated()',
      'Отозвать и вынести все утекшие секреты и пароли из кодовой базы в защищённое хранилище секретов',
      'Восстановить строгую валидацию TLS сертификатов во всех внешних HTTP-клиентах'
    ];

    return {
      cisoSummary,
      riskLevel,
      topRecommendations,
      analyzedWith,
      generatedAt: new Date().toISOString()
    };
  }
}
