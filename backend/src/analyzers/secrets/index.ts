import * as fs from 'fs';
import * as path from 'path';
import { parseDocument, LineCounter, isMap, isPair, isScalar } from 'yaml';
import type { SecretFinding } from '../../types/findings.ts';
import { stripCommentsPreservingLines } from '../utils/source-utils.ts';

export interface SecretScanOptions {
  ignorePaths?: string[];
  entropyThreshold?: number;
}

export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freqs = new Map<string, number>();
  for (const ch of str) {
    freqs.set(ch, (freqs.get(ch) || 0) + 1);
  }
  let ent = 0;
  for (const count of freqs.values()) {
    const p = count / str.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function isSafeOrPlaceholder(val: string): boolean {
  if (!val) return true;
  const trimmed = val.trim();
  if (trimmed.length === 0) return true;

  // Pure environment variable references like ${VAR} or ${VAR:}
  if (/^\$\{[A-Za-z0-9_.-]+(:)?\}$/.test(trimmed)) return true;

  const lower = trimmed.toLowerCase();
  const safeWords = new Set([
    'null', 'none', 'true', 'false', 'undefined', 'default', 'dummy',
    'test', 'testing', 'dev', 'development', 'prod', 'production',
    'localhost', '127.0.0.1', '0.0.0.0', 'example', 'sample', 'changeme',
    'change-me', 'change_me', 'todo', 'fixme', 'placeholder', 'secret',
    'password', 'token', 'apikey', 'api-key', 'api_key', 'admin', 'user', 'guest',
    'h2', 'postgres', 'postgresql', 'mysql', 'oracle', 'sqlite', 'redis', 'mem',
    'always', 'never', 'off', 'on', 'true', 'false', 'enabled', 'disabled'
  ]);
  if (safeWords.has(lower)) return true;

  // Identical character runs like "xxx", "***", "----"
  if (/^(.)\1{2,}$/.test(trimmed)) return true;

  // Numeric literals or simple port numbers
  if (/^\d+$/.test(trimmed)) return true;

  // Local/simple URLs without embedded credentials
  if (/^https?:\/\/[a-zA-Z0-9_.-]+(?::\d+)?\/?$/.test(trimmed)) return true;

  return false;
}

export function maskSecret(secret: string): string {
  if (!secret) return '******';
  const s = secret.trim();
  if (s.length <= 6) return '******';
  return s.substring(0, 4) + '...' + s.substring(s.length - 2);
}

export class SecretAnalyzer {
  private options: SecretScanOptions;

  constructor(options: SecretScanOptions = {}) {
    this.options = {
      ignorePaths: options.ignorePaths || [
        'README.md',
        'README',
        'gradle.lockfile',
        'build.gradle.kts',
        '.git',
        'node_modules',
        'dist',
        'build',
        'target',
        '.gradle'
      ],
      entropyThreshold: options.entropyThreshold ?? 3.2
    };
  }

  public scanProject(projectRoot: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const files = this.collectFiles(projectRoot);

    for (const file of files) {
      const relPath = path.relative(projectRoot, file).replace(/\\/g, '/');

      if (this.isIgnored(relPath)) {
        continue;
      }

      const content = fs.readFileSync(file, 'utf-8');
      const ext = path.extname(file).toLowerCase();

      if (ext === '.kt' || ext === '.java') {
        const codeFindings = this.scanCodeSource(content, relPath);
        findings.push(...codeFindings);
      } else if (ext === '.yml' || ext === '.yaml') {
        const yamlFindings = this.scanYamlConfig(content, relPath);
        findings.push(...yamlFindings);
      } else if (ext === '.properties' || ext === '.env') {
        const propFindings = this.scanPropertiesConfig(content, relPath);
        findings.push(...propFindings);
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
        if (!['.git', 'node_modules', '.gradle', 'build', 'dist', 'target'].includes(entry.name)) {
          results.push(...this.collectFiles(fullPath));
        }
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
    return results;
  }

  private isIgnored(relPath: string): boolean {
    const lower = relPath.toLowerCase();
    const base = path.basename(lower);

    // Markdown / Documentation / Controls
    if (base.startsWith('readme') || base.endsWith('.md') || base.endsWith('.adoc') || base.endsWith('.txt')) {
      return true;
    }

    // Test directory paths
    if (lower.startsWith('test/') || lower.includes('/test/') || lower.includes('test-fixtures/')) {
      return true;
    }

    for (const ig of this.options.ignorePaths || []) {
      const igLower = ig.toLowerCase();
      if (lower === igLower || lower.startsWith(igLower + '/')) return true;
    }
    return false;
  }

  private scanCodeSource(rawContent: string, relPath: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const cleanContent = stripCommentsPreservingLines(rawContent);
    const lines = cleanContent.split('\n');

    // Multi-pass variable tracking for recoverable tokens
    interface VarInfo {
      name: string;
      value: string;
      line: number;
    }
    const stringVars = new Map<string, VarInfo>();

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const lineText = lines[i];
      const trimmed = lineText.trim();
      if (!trimmed) continue;

      // 1. Password detection (A-SEC-01)
      const pwdMatch = lineText.match(
        /(?:val|var)\s+([a-zA-Z0-9_]*(?:password|passwd|pwd)[a-zA-Z0-9_]*)\s*[:=]\s*(?:String\s*=\s*)?["']([^"']+)["']/i
      );
      if (pwdMatch) {
        const val = pwdMatch[2];
        if (!isSafeOrPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'password',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Пароль учётной записи записан в кодовой базе (${maskSecret(val)})`,
            remediation: 'Вынести пароль в переменные окружения или защищённое хранилище секретов (Vault)'
          });
        }
      }

      // 2. API Key detection (A-SEC-02)
      const apiKeyMatch = lineText.match(
        /(?:val|var)\s+([a-zA-Z0-9_]*(?:api[_-]?key|secret[_-]?key|access[_-]?key|pricing[_-]?key)[a-zA-Z0-9_]*)\s*[:=]\s*(?:String\s*=\s*)?["']([^"']+)["']/i
      );
      if (apiKeyMatch) {
        const val = apiKeyMatch[2];
        if (!isSafeOrPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'api-key',
            line: lineNum,
            endLine: lineNum,
            severity: 'MEDIUM',
            description: `Встроенный API-ключ (${maskSecret(val)})`,
            remediation: 'Передавать API-ключ через конфигурацию окружения'
          });
        }
      }

      // Direct header assignment with API key literal: .header("X-Api-Key", "...")
      if (!apiKeyMatch && /header\s*\(\s*["'](?:X-Api-Key|api-key|apiKey)["']\s*,\s*["']([^"']+)["']\s*\)/i.test(lineText)) {
        const match = lineText.match(/header\s*\(\s*["'](?:X-Api-Key|api-key|apiKey)["']\s*,\s*["']([^"']+)["']\s*\)/i);
        if (match && !isSafeOrPlaceholder(match[1])) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'api-key',
            line: lineNum,
            endLine: lineNum,
            severity: 'MEDIUM',
            description: `Встроенный API-ключ в заголовке авторизации (${maskSecret(match[1])})`,
            remediation: 'Передавать ключ через настройки окружения'
          });
        }
      }

      // 3. Secret fallback detection (A-SEC-04)
      // e.g. System.getenv("...") ?: "fallback_value" or System.getProperty("...", "fallback_value")
      const envFallbackMatch = lineText.match(/(?:getenv|getProperty)\s*\([^)]*\)\s*\?:\s*["']([^"']+)["']/);
      const propFallbackMatch = lineText.match(/getProperty\s*\(\s*["'][^"']+["']\s*,\s*["']([^"']+)["']\s*\)/);
      const fallbackVal = envFallbackMatch ? envFallbackMatch[1] : (propFallbackMatch ? propFallbackMatch[1] : null);

      if (fallbackVal && !isSafeOrPlaceholder(fallbackVal)) {
        findings.push({
          category: 'SECRET',
          path: relPath,
          class: 'secret-fallback',
          line: lineNum,
          endLine: lineNum,
          severity: 'LOW',
          description: `Встроенный секрет используется по умолчанию при отсутствии переменной окружения (${maskSecret(fallbackVal)})`,
          remediation: 'Удалить встроенный fallback. При отсутствии переменной завершать запуск с ошибкой или отключать интеграцию'
        });
      }

      // Spring @Value with fallback: @Value("${key:fallback}")
      const springValueMatch = lineText.match(/@Value\s*\(\s*["']\$\{[^:}]+:([^"'}]+)\}["']\s*\)/);
      if (springValueMatch) {
        const val = springValueMatch[1].trim();
        if (!isSafeOrPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'secret-fallback',
            line: lineNum,
            endLine: lineNum,
            severity: 'LOW',
            description: `Встроенный секрет в аннотации @Value (${maskSecret(val)})`,
            remediation: 'Удалить значение по умолчанию из аннотации @Value'
          });
        }
      }

      // 4. Track local string variables for recoverable-token (A-SEC-05)
      const varAssign = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*(?::\s*String)?\s*=\s*["']([^"']+)["']/);
      if (varAssign) {
        stringVars.set(varAssign[1], {
          name: varAssign[1],
          value: varAssign[2],
          line: lineNum
        });
      }

      // Concatenation: val token = a + b
      const concatMatch = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)\s*\+\s*([a-zA-Z0-9_]+)/);
      // Interpolation: val token = "$a$b"
      const templateMatch = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*=\s*["']\$([a-zA-Z0-9_]+)\$([a-zA-Z0-9_]+)["']/);

      const targetVar = concatMatch ? concatMatch[1] : (templateMatch ? templateMatch[1] : null);
      const var1 = concatMatch ? concatMatch[2] : (templateMatch ? templateMatch[2] : null);
      const var2 = concatMatch ? concatMatch[3] : (templateMatch ? templateMatch[3] : null);

      if (targetVar && var1 && var2 && stringVars.has(var1) && stringVars.has(var2)) {
        const info1 = stringVars.get(var1)!;
        const info2 = stringVars.get(var2)!;
        const combined = info1.value + info2.value;

        // Register reconstructed variable
        stringVars.set(targetVar, {
          name: targetVar,
          value: combined,
          line: lineNum
        });

        // Check if combined value or targetVar is used in authentication within next lines
        const lookaheadLines = lines.slice(i, Math.min(lines.length, i + 8));
        const isUsedInAuth = lookaheadLines.some(l =>
          l.includes(`setBearerAuth(${targetVar})`) ||
          l.includes(`Bearer $${targetVar}`) ||
          l.includes(`header("Authorization"`) ||
          l.includes(`header('Authorization'`) ||
          l.includes(`header("X-Api-Key"`) ||
          l.includes(`HttpHeaders`)
        );

        const entropy = calculateEntropy(combined);
        if ((isUsedInAuth || entropy >= (this.options.entropyThreshold ?? 3.2)) && combined.length >= 10) {
          const startLine = Math.min(info1.line, info2.line);
          let endLine = lineNum;
          for (let k = 0; k < lookaheadLines.length; k++) {
            if (lookaheadLines[k].includes(targetVar)) {
              endLine = i + k + 1;
            }
          }

          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'recoverable-token',
            line: startLine,
            endLine: Math.min(endLine, startLine + 14),
            severity: 'MEDIUM',
            description: `Токен восстанавливается из конкатенации строковых фрагментов (${maskSecret(combined)})`,
            remediation: 'Подставлять цельный токен из окружения или защищённого хранилища без разделения на фрагменты в коде'
          });
        }
      }
    }

    return findings;
  }

  private scanYamlConfig(content: string, relPath: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const lines = content.split('\n');

    try {
      const lineCounter = new LineCounter();
      const doc = parseDocument(content, { lineCounter });

      const checkPair = (keyStr: string, valNode: any, keyPath: string[]) => {
        if (!isScalar(valNode)) return;
        const valStr = String(valNode.value ?? '').trim();
        if (!valStr) return;

        const pos = lineCounter.linePos(valNode.range ? valNode.range[0] : 0);
        const lineNum = pos ? pos.line : 1;

        // 1. Check Bearer token in YAML: e.g. authorization: "Bearer token_..."
        const bearerMatch = valStr.match(/^Bearer\s+([^"'\s]+)$/i);
        if (bearerMatch) {
          const token = bearerMatch[1];
          if (!isSafeOrPlaceholder(token)) {
            findings.push({
              category: 'SECRET',
              path: relPath,
              class: 'configuration-token',
              line: lineNum,
              endLine: lineNum,
              severity: 'HIGH',
              description: `Bearer-токен зафиксирован в конфигурационном файле (${maskSecret(token)})`,
              remediation: 'Задать свойство через ссылку на переменную окружения без встроенного значения'
            });
            return;
          }
        }

        // 2. Check fallback in YAML: ${ENV_VAR:fallback}
        const fallbackMatch = valStr.match(/^\$\{([^:}]+):([^"'}]+)\}$/);
        if (fallbackMatch) {
          const fallbackVal = fallbackMatch[2].trim();
          if (!isSafeOrPlaceholder(fallbackVal)) {
            const isPwd = /password|passwd|pwd/i.test(keyStr);
            findings.push({
              category: 'SECRET',
              path: relPath,
              class: isPwd ? 'password' : 'configuration-token',
              line: lineNum,
              endLine: lineNum,
              severity: 'HIGH',
              description: `Секрет с резервным значением сохранён в конфигурации (${maskSecret(fallbackVal)})`,
              remediation: 'Удалить встроенное значение по умолчанию, передавать секрет исключительно через окружение'
            });
            return;
          }
        }

        // 3. Skip pure environment variable references: ${VAR} or ${VAR:}
        if (/^\$\{[^}]+\}$/.test(valStr)) {
          return;
        }

        // 4. Password in YAML
        if (/(?:^|[._-])(?:password|passwd|pwd)$/i.test(keyStr)) {
          if (!isSafeOrPlaceholder(valStr)) {
            findings.push({
              category: 'SECRET',
              path: relPath,
              class: 'password',
              line: lineNum,
              endLine: lineNum,
              severity: 'HIGH',
              description: `Пароль сохранён в открытом виде в конфигурации (${maskSecret(valStr)})`,
              remediation: 'Вынести пароль в системные переменные окружения или Secret Manager'
            });
            return;
          }
        }

        // 5. Secret / Token / API Key in YAML
        if (/(?:token|secret|api[_-]?key|auth|credential)/i.test(keyStr)) {
          if (!isSafeOrPlaceholder(valStr)) {
            const entropy = calculateEntropy(valStr);
            if (valStr.length >= 12 || entropy >= (this.options.entropyThreshold ?? 3.2)) {
              findings.push({
                category: 'SECRET',
                path: relPath,
                class: 'configuration-token',
                line: lineNum,
                endLine: lineNum,
                severity: 'HIGH',
                description: `Секретный токен сохранён в конфигурации (${maskSecret(valStr)})`,
                remediation: 'Задать свойство через ссылку на переменную окружения'
              });
              return;
            }
          }
        }
      };

      const traverse = (node: any, currentPath: string[] = []) => {
        if (!node) return;
        if (isMap(node)) {
          for (const item of node.items) {
            if (isPair(item)) {
              const k = isScalar(item.key) ? String(item.key.value) : '';
              const nextPath = [...currentPath, k];
              if (isScalar(item.value)) {
                checkPair(k, item.value, nextPath);
              } else {
                traverse(item.value, nextPath);
              }
            }
          }
        }
      };

      traverse(doc.contents);
    } catch {
      // Fallback line-by-line parsing if YAML parser fails
      for (let i = 0; i < lines.length; i++) {
        const lineNum = i + 1;
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const m = line.match(/^([a-zA-Z0-9_.-]+)\s*:\s*["']?([^"']+)["']?$/);
        if (m) {
          const k = m[1];
          const v = m[2];
          if (v.startsWith('${') && !v.includes(':')) continue;
          if (/authorization/i.test(k) && /Bearer\s+/i.test(v)) {
            const token = v.replace(/^Bearer\s+/i, '').trim();
            if (!isSafeOrPlaceholder(token)) {
              findings.push({
                category: 'SECRET',
                path: relPath,
                class: 'configuration-token',
                line: lineNum,
                endLine: lineNum,
                severity: 'HIGH',
                description: `Bearer-токен зафиксирован в конфигурационном файле (${maskSecret(token)})`,
                remediation: 'Задать свойство через ссылку на переменную окружения без встроенного значения'
              });
            }
          }
        }
      }
    }

    return findings;
  }

  private scanPropertiesConfig(content: string, relPath: string): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i].trim();
      if (!line || line.startsWith('#') || line.startsWith('!')) continue;

      const eqIdx = line.indexOf('=');
      const colonIdx = line.indexOf(':');
      let sepIdx = -1;
      if (eqIdx !== -1 && colonIdx !== -1) {
        sepIdx = Math.min(eqIdx, colonIdx);
      } else {
        sepIdx = eqIdx !== -1 ? eqIdx : colonIdx;
      }
      if (sepIdx === -1) continue;

      const key = line.substring(0, sepIdx).trim();
      let val = line.substring(sepIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1).trim();
      }

      // Check pure env reference: ${VAR}
      if (/^\$\{[^:}]+\}$/.test(val)) continue;

      // Check fallback: ${VAR:fallback}
      const fallbackMatch = val.match(/^\$\{([^:}]+):([^"'}]+)\}$/);
      if (fallbackMatch) {
        const fb = fallbackMatch[2].trim();
        if (!isSafeOrPlaceholder(fb)) {
          const isPwd = /password|passwd|pwd/i.test(key);
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: isPwd ? 'password' : 'configuration-token',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Секрет с резервным значением в свойствах (${maskSecret(fb)})`,
            remediation: 'Удалить встроенное значение по умолчанию'
          });
          continue;
        }
      }

      if (/password|passwd|pwd/i.test(key)) {
        if (!isSafeOrPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'password',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Пароль сохранён в открытом виде в файле свойств (${maskSecret(val)})`,
            remediation: 'Вынести пароль в системные переменные окружения'
          });
        }
      } else if (/token|secret|api[_-]?key/i.test(key)) {
        if (!isSafeOrPlaceholder(val)) {
          findings.push({
            category: 'SECRET',
            path: relPath,
            class: 'configuration-token',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: `Токен сохранён в файле свойств (${maskSecret(val)})`,
            remediation: 'Задать свойство через ссылку на переменную окружения'
          });
        }
      }
    }

    return findings;
  }
}
