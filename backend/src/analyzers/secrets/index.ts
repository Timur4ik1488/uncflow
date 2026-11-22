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

  // Pure environment variable references like ${VAR} or \${VAR} or ${VAR:}
  if (/^\\?\$\{[A-Za-z0-9_.-]+(:)?\}$/.test(trimmed)) return true;

  const lower = trimmed.toLowerCase();

  // Explicit placeholder keywords and patterns
  const placeholderPatterns = [
    'your_api_key', 'your-api-key', 'yourapikey',
    'your_password', 'your-password', 'yourpassword',
    'your_token', 'your-token', 'yourtoken',
    'your_secret', 'your-secret', 'yoursecret',
    'change_me', 'change-me', 'changeme',
    'replace_me', 'replace-me', 'replaceme',
    'dummy', 'sample', 'example', 'placeholder'
  ];
  if (placeholderPatterns.includes(lower)) return true;

  if (/^(?:your[-_]?(?:api[-_]?key|password|token|secret)|change[-_]?me|replace[-_]?me|dummy|sample)(?:[_-]|$)/i.test(lower)) {
    return true;
  }

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

export const isPlaceholder = isSafeOrPlaceholder;

function splitConcatExpr(expr: string): string[] {
  const terms: string[] = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';

  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i];
    if ((ch === '"' || ch === "'") && (i === 0 || expr[i - 1] !== '\\')) {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = ch;
      } else if (ch === quoteChar) {
        inQuotes = false;
      }
      current += ch;
    } else if (ch === '+' && !inQuotes) {
      if (current.trim()) {
        terms.push(current.trim());
      }
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) {
    terms.push(current.trim());
  }
  return terms;
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
      componentLines: number[];
    }
    const stringVars = new Map<string, VarInfo>();
    const reportedRecoverableLines = new Set<number>();

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

      // Direct header assignment with API key / auth token literal across all auth headers (A-SEC-02 / Defect 1)
      const headerAuthPattern = /(?:\.header|header|\.headers|headers|\.set|set|\.add|add)\s*\(\s*(?:["'](?:X-Api-Key|Api-Key|X-Auth-Token|X-Access-Token|X-Secret-Key|X-Token|Authorization|api-key|apiKey|auth-token|authToken|access-token|accessToken|secret-key|secretKey|x-token|xToken)["']|HttpHeaders\.(?:AUTHORIZATION|[A-Z0-9_]+))\s*,\s*["']([^"']+)["']\s*\)/i;
      const bearerAuthPattern = /(?:setBearerAuth|\.setBearerAuth)\s*\(\s*["']([^"']+)["']\s*\)/i;

      const headerLiteralMatch = lineText.match(headerAuthPattern) || lineText.match(bearerAuthPattern);
      if (!apiKeyMatch && headerLiteralMatch) {
        const rawVal = headerLiteralMatch[1];
        if (rawVal && !/\$[a-zA-Z0-9_]+|\$\{[^}]+\}/.test(rawVal)) {
          const cleanToken = rawVal.replace(/^Bearer\s+/i, '').trim();
          if (!isSafeOrPlaceholder(cleanToken)) {
            findings.push({
              category: 'SECRET',
              path: relPath,
              class: 'api-key',
              line: lineNum,
              endLine: lineNum,
              severity: 'MEDIUM',
              description: `Встроенный секрет/токен в заголовке авторизации (${maskSecret(cleanToken)})`,
              remediation: 'Передавать ключ через настройки окружения'
            });
          }
        }
      }

      // 3. Secret fallback detection (A-SEC-04)
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

      // 4. Track local string variables and multi-variable assembly for recoverable-token (A-SEC-05 / Defect 2)
      const literalAssign = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*(?::\s*String)?\s*=\s*["']([^"']+)["']/);
      if (literalAssign && !/\$[a-zA-Z0-9_]+|\$\{[^}]+\}/.test(literalAssign[2])) {
        stringVars.set(literalAssign[1], {
          name: literalAssign[1],
          value: literalAssign[2],
          line: lineNum,
          componentLines: [lineNum]
        });
      }

      // Variable assignment combining variables via +, string templates, or mixed (e.g. val joined = x1 + x2 + "$x3$x4")
      const varAssignHeader = lineText.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*(?::\s*String)?\s*=\s*(.+)/);
      if (varAssignHeader && !stringVars.has(varAssignHeader[1])) {
        const targetVar = varAssignHeader[1];
        const expr = varAssignHeader[2].trim();
        const terms = splitConcatExpr(expr);

        if (terms.length > 1 || (terms.length === 1 && terms[0].includes('$'))) {
          const resolvedTerms: string[] = [];
          const allCompLines: number[] = [];
          let valid = true;
          let varRefsCount = 0;

          for (const term of terms) {
            if (/^[a-zA-Z0-9_]+$/.test(term)) {
              if (stringVars.has(term)) {
                const varInfo = stringVars.get(term)!;
                resolvedTerms.push(varInfo.value);
                allCompLines.push(...varInfo.componentLines);
                varRefsCount++;
              } else {
                valid = false;
                break;
              }
            } else if ((term.startsWith('"') && term.endsWith('"')) || (term.startsWith("'") && term.endsWith("'"))) {
              const strContent = term.slice(1, -1);
              const templateVarMatches = Array.from(strContent.matchAll(/\$([a-zA-Z0-9_]+)|\$\{([a-zA-Z0-9_]+)\}/g));
              if (templateVarMatches.length > 0) {
                let subContent = strContent;
                for (const m of templateVarMatches) {
                  const vn = m[1] || m[2];
                  if (stringVars.has(vn)) {
                    const varInfo = stringVars.get(vn)!;
                    subContent = subContent.replace(m[0], varInfo.value);
                    allCompLines.push(...varInfo.componentLines);
                    varRefsCount++;
                  } else {
                    valid = false;
                    break;
                  }
                }
                if (!valid) break;
                resolvedTerms.push(subContent);
              } else {
                resolvedTerms.push(strContent);
              }
            } else {
              valid = false;
              break;
            }
          }

          if (valid && varRefsCount >= 2) {
            const reconstructed = resolvedTerms.join('');
            const uniqueLines = Array.from(new Set(allCompLines)).sort((a, b) => a - b);
            stringVars.set(targetVar, {
              name: targetVar,
              value: reconstructed,
              line: lineNum,
              componentLines: uniqueLines
            });
          }
        }
      }

      // Check for usage of assembled token variables in auth headers / setBearerAuth calls
      for (const [varName, varInfo] of stringVars.entries()) {
        if (varInfo.componentLines.length >= 2) {
          const varInterpolation = `(?:\\$${varName}\\b|\\$\\{${varName}\\})`;
          const isUsedInAuthOnLine =
            lineText.includes(`setBearerAuth(${varName})`) ||
            lineText.includes(`.setBearerAuth(${varName})`) ||
            new RegExp(`(?:\\.header|header|\\.set|set|\\.add|add)\\s*\\(\\s*["'](?:Authorization|X-Api-Key|Api-Key|X-Auth-Token|X-Access-Token|X-Secret-Key|X-Token)["']\\s*,\\s*(?:["'][^"']*${varInterpolation}[^"']*["']|\\b${varName}\\b)`, 'i').test(lineText) ||
            new RegExp(`(?:\\.header|header|\\.set|set|\\.add|add)\\s*\\(\\s*HttpHeaders\\.(?:AUTHORIZATION|[A-Z0-9_]+)\\s*,\\s*(?:["'][^"']*${varInterpolation}[^"']*["']|\\b${varName}\\b)`, 'i').test(lineText);

          if (isUsedInAuthOnLine) {
            const startLine = Math.min(...varInfo.componentLines);
            if (!reportedRecoverableLines.has(startLine)) {
              reportedRecoverableLines.add(startLine);
              findings.push({
                category: 'SECRET',
                path: relPath,
                class: 'recoverable-token',
                line: startLine,
                endLine: lineNum,
                severity: 'MEDIUM',
                description: `Токен восстанавливается из конкатенации строковых фрагментов (${maskSecret(varInfo.value)})`,
                remediation: 'Подставлять цельный токен из окружения или защищённого хранилища без разделения на фрагменты в коде'
              });
            }
          }
        }
      }

      // Direct template assembly inside auth call: .header("Authorization", "Bearer $a$b$c") or setBearerAuth("${a}${b}${c}")
      const isAuthCallLine =
        /(?:\.header|header|\.set|set|\.add|add)\s*\(\s*(?:["'](?:Authorization|X-Api-Key|Api-Key|X-Auth-Token|X-Access-Token|X-Secret-Key|X-Token)["']|HttpHeaders\.(?:AUTHORIZATION|[A-Z0-9_]+))/i.test(lineText) ||
        /(?:setBearerAuth|\.setBearerAuth)\s*\(/i.test(lineText);

      if (isAuthCallLine) {
        const inlineTemplateVars = Array.from(lineText.matchAll(/\$([a-zA-Z0-9_]+)|\$\{([a-zA-Z0-9_]+)\}/g));
        if (inlineTemplateVars.length >= 2) {
          const matchedNames = inlineTemplateVars.map(m => m[1] || m[2]);
          if (matchedNames.every(vn => stringVars.has(vn))) {
            const compInfos = matchedNames.map(vn => stringVars.get(vn)!);
            const compLines = Array.from(new Set(compInfos.flatMap(info => info.componentLines)));
            const startLine = Math.min(...compLines);
            const combinedVal = compInfos.map(info => info.value).join('');
            if (!reportedRecoverableLines.has(startLine)) {
              reportedRecoverableLines.add(startLine);
              findings.push({
                category: 'SECRET',
                path: relPath,
                class: 'recoverable-token',
                line: startLine,
                endLine: lineNum,
                severity: 'MEDIUM',
                description: `Токен восстанавливается из конкатенации строковых фрагментов (${maskSecret(combinedVal)})`,
                remediation: 'Подставлять цельный токен из окружения или защищённого хранилища без разделения на фрагменты в коде'
              });
            }
          }
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
              class: isPwd ? 'password' : 'secret-fallback',
              line: lineNum,
              endLine: lineNum,
              severity: isPwd ? 'HIGH' : 'LOW',
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
            class: isPwd ? 'password' : 'secret-fallback',
            line: lineNum,
            endLine: lineNum,
            severity: isPwd ? 'HIGH' : 'LOW',
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
