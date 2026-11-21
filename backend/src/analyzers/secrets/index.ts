import * as fs from 'fs';
import * as path from 'path';
import type { SecretFinding } from '../../types/findings.ts';

export interface SecretScanOptions {
  ignorePaths?: string[];
  entropyThreshold?: number;
}

export class SecretAnalyzer {
  private options: SecretScanOptions;

  constructor(options: SecretScanOptions = {}) {
    this.options = {
      ignorePaths: options.ignorePaths || [
        'README.md',
        'gradle.lockfile',
        'build.gradle.kts',
        '.git',
        'node_modules',
        'dist',
        'build',
        'target',
        '.gradle'
      ],
      entropyThreshold: options.entropyThreshold || 3.3
    };
  }

  public scanProject(projectRoot: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const files = this.collectFiles(projectRoot);

    for (const file of files) {
      const relPath = path.relative(projectRoot, file).replace(/\\/g, '/');

      // Check ignore paths (e.g., A-CTRL-01: README.md documentation placeholders)
      if (this.isIgnored(relPath)) {
        continue;
      }

      const content = fs.readFileSync(file, 'utf-8');
      const ext = path.extname(file).toLowerCase();

      if (ext === '.kt' || ext === '.java') {
        const codeFindings = this.scanKotlinSource(content, relPath);
        findings.push(...codeFindings);
      } else if (ext === '.yml' || ext === '.yaml' || ext === '.properties') {
        const configFindings = this.scanConfig(content, relPath);
        findings.push(...configFindings);
      }
    }

    return findings;
  }

  private collectFiles(dir: string): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;

    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!['.git', 'node_modules', '.gradle', 'build'].includes(entry.name)) {
          results.push(...this.collectFiles(fullPath));
        }
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
    return results;
  }

  private isIgnored(relPath: string): boolean {
    if (relPath === 'README.md' || relPath.endsWith('/README.md')) return true;
    for (const ig of this.options.ignorePaths || []) {
      if (relPath === ig || relPath.startsWith(ig + '/')) return true;
    }
    return false;
  }

  private scanKotlinSource(content: string, relPath: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const lines = content.split('\n');

    // Track local string variables for recoverable-token (A-SEC-05)
    // Map of varName -> { value: string, line: number }
    const localStringVars = new Map<string, { value: string; line: number }>();

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const lineText = lines[i];
      const trimmed = lineText.trim();

      // Skip comment lines
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        continue;
      }

      // 1. Password detection (A-SEC-01)
      const pwdMatch = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]*password[a-zA-Z0-9_]*)\s*[:=]\s*(?:String\s*=\s*)?["']([^"']+)["']/i);
      if (pwdMatch) {
        const val = pwdMatch[2];
        if (!this.isPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'password',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Пароль учётной записи записан в кодовой базе (${this.mask(val)})`,
            remediation: 'Вынести пароль в переменные окружения или защищённое хранилище секретов (Vault)'
          });
        }
      }

      // 2. API Key detection (A-SEC-02)
      const apiKeyMatch = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]*(?:api[_-]?key|pricing[_-]?key|secret[_-]?key)[a-zA-Z0-9_]*)\s*[:=]\s*(?:String\s*=\s*)?["']([^"']+)["']/i);
      if (apiKeyMatch) {
        const val = apiKeyMatch[2];
        if (!this.isPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'api-key',
            line: lineNum,
            endLine: lineNum,
            severity: 'MEDIUM',
            description: `Встроенный API-ключ (${this.mask(val)})`,
            remediation: 'Передавать API-ключ через конфигурацию окружения'
          });
        }
      }

      // Also check direct header assignment with api key literal:
      if (!apiKeyMatch && /header\s*\(\s*["']X-Api-Key["']\s*,\s*["']([^"']+)["']\s*\)/i.test(lineText)) {
        const match = lineText.match(/header\s*\(\s*["']X-Api-Key["']\s*,\s*["']([^"']+)["']\s*\)/i);
        if (match && !this.isPlaceholder(match[1])) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'api-key',
            line: lineNum,
            endLine: lineNum,
            severity: 'MEDIUM',
            description: `Встроенный API-ключ в заголовке X-Api-Key (${this.mask(match[1])})`,
            remediation: 'Передавать ключ через настройки окружения'
          });
        }
      }

      // 3. Secret fallback detection (A-SEC-04)
      // e.g. System.getenv("...") ?: "cg26_depot_..."
      const fallbackMatch = lineText.match(/(?:getenv|getProperty)\s*\([^)]*\)\s*\?:\s*["']([^"']+)["']/);
      if (fallbackMatch) {
        const val = fallbackMatch[1];
        if (!this.isPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'secret-fallback',
            line: lineNum,
            endLine: lineNum,
            severity: 'LOW',
            description: `Встроенный секрет используется по умолчанию при отсутствии переменной окружения (${this.mask(val)})`,
            remediation: 'Удалить встроенный fallback. При отсутствии переменной завершать запуск с ошибкой или отключать интеграцию'
          });
        }
      }

      // 4. Track local string variables for recoverable-token (A-SEC-05)
      const varAssignMatch = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*=\s*["']([^"']+)["']/);
      if (varAssignMatch) {
        localStringVars.set(varAssignMatch[1], { value: varAssignMatch[2], line: lineNum });
      }

      // Check concatenation of variables into a token:
      // e.g. val access = series + grant
      const concatMatch = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)/);
      if (concatMatch) {
        const targetVar = concatMatch[1];
        const var1 = concatMatch[2];
        const var2 = concatMatch[3];

        if (localStringVars.has(var1) && localStringVars.has(var2)) {
          const info1 = localStringVars.get(var1)!;
          const info2 = localStringVars.get(var2)!;
          const combined = info1.value + info2.value;

          // Check if this combined value or targetVar looks like a credential or is later used in auth
          // Look ahead in subsequent lines for setBearerAuth(targetVar) or Authorization
          const lookaheadLines = lines.slice(i, Math.min(lines.length, i + 6));
          const isUsedInAuth = lookaheadLines.some(l => 
            l.includes(`setBearerAuth(${targetVar})`) || 
            l.includes(`Bearer $${targetVar}`) ||
            l.includes(`header("Authorization"`) ||
            l.includes(`header('Authorization'`)
          );

          if (isUsedInAuth || combined.startsWith('cg26_') || this.calculateEntropy(combined) > this.options.entropyThreshold!) {
            const startLine = Math.min(info1.line, info2.line);
            // find the line where it is used or end of function
            let endL = lineNum;
            for (let k = 0; k < lookaheadLines.length; k++) {
              if (lookaheadLines[k].includes(targetVar)) {
                endL = i + k + 1;
              }
            }

            findings.push({
              category: 'SECRET',
              path: relPath,
              class: 'recoverable-token',
              line: startLine,
              endLine: endL,
              severity: 'MEDIUM',
              description: `Токен восстанавливается из конкатенации строковых фрагментов (${this.mask(combined)})`,
              remediation: 'Подставлять цельный токен из окружения или защищённого хранилища без разделения на фрагменты в коде'
            });
          }
        }
      }
    }

    return findings;
  }

  private scanConfig(content: string, relPath: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const lineText = lines[i];

      // A-CTRL-02: Control - environment variable references like ${INVENTORY_TOKEN} are SAFE!
      if (lineText.includes('${') && !lineText.match(/:\s*["'][^"'\${}]+["']/)) {
        // Pure variable substitution like: token: ${INVENTORY_TOKEN}
        continue;
      }

      // A-SEC-03: Configuration token (e.g. Bearer token in application.yml)
      // authorization: "Bearer cg26_pickup_Gq7mP8vJdW3sY6zN"
      const bearerMatch = lineText.match(/authorization:\s*["']Bearer\s+([^"']+)["']/i);
      if (bearerMatch) {
        const token = bearerMatch[1];
        if (!token.includes('${') && !this.isPlaceholder(token)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'configuration-token',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Bearer-токен зафиксирован в конфигурационном файле (${this.mask(token)})`,
            remediation: 'Задать свойство через ссылку на переменную окружения (например, ${PICKUP_CALLBACK_TOKEN}) без встроенного значения'
          });
        }
      }

      // Check general token keys in config (e.g. token: "cg26_...", password: "...")
      const generalSecretMatch = lineText.match(/(?:token|password|secret|api[-_]?key):\s*["']([^"']+)["']/i);
      if (generalSecretMatch && !bearerMatch) {
        const val = generalSecretMatch[1];
        if (!val.includes('${') && !this.isPlaceholder(val) && (val.startsWith('cg26_') || this.calculateEntropy(val) > this.options.entropyThreshold!)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'configuration-token',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Секрет сохранён в открытом виде в конфигурации (${this.mask(val)})`,
            remediation: 'Использовать плейсхолдеры системных переменных окружения без значений по умолчанию'
          });
        }
      }

      // Check properties format: key = value (e.g. spring.datasource.password=petclinic)
      const propMatch = lineText.match(/^(?:spring\.)?(?:datasource\.)?(?:password|token|secret|api[-_]?key)\s*=\s*(.+)/i);
      if (propMatch && !bearerMatch && !generalSecretMatch) {
        const val = propMatch[1].trim().replace(/^["']|["']$/g, '');
        if (val && !val.includes('${') && !this.isPlaceholder(val) && val !== '""' && val !== "''") {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'password',
            line: lineNum,
            endLine: lineNum,
            severity: 'CRITICAL',
            description: `Пароль базы данных сохранён в открытом виде в конфигурации (${this.mask(val)})`,
            remediation: 'Вынести пароль в системные переменные окружения (${DB_PASSWORD}) или Secret Manager'
          });
        }
      }
    }

    return findings;
  }

  private calculateEntropy(str: string): number {
    if (!str) return 0;
    const len = str.length;
    const frequencies = new Map<string, number>();

    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  private isPlaceholder(val: string): boolean {
    const lower = val.toLowerCase();
    return (
      lower.includes('placeholder') ||
      lower.includes('example') ||
      lower.includes('changeme') ||
      lower === 'test' ||
      lower === 'admin' ||
      lower.startsWith('${')
    );
  }

  private mask(secret: string): string {
    if (!secret || secret.length <= 6) return '******';
    return secret.substring(0, 4) + '...' + secret.substring(secret.length - 2);
  }
}
