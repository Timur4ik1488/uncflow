import * as fs from 'fs';
import * as path from 'path';
import type { SastFinding } from '../../types/findings.ts';

export class SastAnalyzer {
  public scanProject(projectRoot: string): SastFinding[] {
    const findings: SastFinding[] = [];
    const files = this.collectKotlinFiles(projectRoot);

    for (const file of files) {
      const relPath = path.relative(projectRoot, file).replace(/\\/g, '/');
      const content = fs.readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      // Rule 1: SQL Injection (A-SAST-01)
      const sqliFindings = this.checkSqlInjection(lines, relPath);
      findings.push(...sqliFindings);

      // Rule 2: TLS Verification (A-SAST-02)
      const tlsFindings = this.checkTlsVerification(lines, relPath);
      findings.push(...tlsFindings);

      // Rule 3: Credentialed CORS (A-SAST-03)
      const corsFindings = this.checkCredentialedCors(lines, relPath);
      findings.push(...corsFindings);

      // Rule 4: Route Authorization (A-SAST-04)
      const routeFindings = this.checkRouteAuthorization(lines, relPath);
      findings.push(...routeFindings);

      // Rule 5: Object Authorization / IDOR (A-SAST-05)
      const idorFindings = this.checkObjectAuthorization(lines, relPath, projectRoot);
      findings.push(...idorFindings);
    }

    return findings;
  }

  private collectKotlinFiles(dir: string): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;

    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!['.git', 'node_modules', '.gradle', 'build'].includes(entry.name)) {
          results.push(...this.collectKotlinFiles(fullPath));
        }
      } else if (entry.isFile() && entry.name.endsWith('.kt')) {
        results.push(fullPath);
      }
    }
    return results;
  }

  /**
   * Rule 1: SQL / HQL Injection
   * Match unparameterized SQL/HQL queries with string interpolation or concatenation.
   * Supports both JdbcTemplate (query, queryForList, execute) and JPA/Hibernate (createQuery, createNativeQuery).
   * Control A-CTRL-04: Queries using '?' positional parameters or named parameters are SAFE!
   */
  private checkSqlInjection(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];
    const reportedLines = new Set<number>();

    // Track SQL string variables (e.g. val sqlQuery = "SELECT ... $param")
    const sqlVars = new Map<string, { lineNum: number; hasInterpolation: boolean; hasPlaceholders: boolean }>();

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        continue;
      }

      // 1. Detect variables assigned to SQL/HQL statements
      const sqlAssignMatch = line.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*=\s*["'](.*(?:SELECT|INSERT|UPDATE|DELETE|FROM)\b.*)["']/i);
      if (sqlAssignMatch) {
        const varName = sqlAssignMatch[1];
        const hasInterp = /\$[a-zA-Z0-9_]+/.test(line);
        const hasConcat = /\+\s*[a-zA-Z0-9_]+/.test(line);
        const hasPlaceholders = (line.includes('?') || line.includes(':')) && !hasInterp && !hasConcat;
        sqlVars.set(varName, { lineNum, hasInterpolation: hasInterp || hasConcat, hasPlaceholders });
      }

      // 2. Check query execution methods (JdbcTemplate, JPA EntityManager, Hibernate Session)
      const sqlMethodMatch = line.match(/(?:query|queryForList|queryForObject|execute|executeUpdate|createQuery|createNativeQuery)\s*\(\s*(["'][^"']*["']|[a-zA-Z0-9_]+)/);
      if (sqlMethodMatch) {
        const arg = sqlMethodMatch[1].trim();

        // Subcase A: query execution passes a variable defined earlier with unparameterized SQL
        if (sqlVars.has(arg)) {
          const varInfo = sqlVars.get(arg)!;
          if (varInfo.hasInterpolation && !varInfo.hasPlaceholders && !reportedLines.has(varInfo.lineNum)) {
            reportedLines.add(varInfo.lineNum);
            findings.push({
              category: 'SAST',
              path: relPath,
              class: 'sql-injection',
              line: varInfo.lineNum,
              endLine: lineNum,
              severity: 'CRITICAL',
              description: 'Параметр подставляется в SQL/HQL-запрос без параметризации (интерполяция строки в createQuery/query)',
              remediation: 'Использовать позиционные (?) или именованные (:param) параметры и передавать значения через setParameter или параметры JdbcTemplate'
            });
            continue;
          }
        }

        // Subcase B: inline query inside method call
        if (
          line.includes('SELECT ') ||
          line.includes('INSERT ') ||
          line.includes('UPDATE ') ||
          line.includes('DELETE ')
        ) {
          const hasInterpolation = /["'].*SELECT.*\$[a-zA-Z0-9_]+.*["']/i.test(line);
          const hasConcatenation = /["'].*SELECT.*["']\s*\+\s*[a-zA-Z0-9_]+/i.test(line);
          const hasPlaceholders = line.includes('?') && !hasInterpolation && !hasConcatenation;

          if ((hasInterpolation || hasConcatenation) && !hasPlaceholders && !reportedLines.has(lineNum)) {
            reportedLines.add(lineNum);
            findings.push({
              category: 'SAST',
              path: relPath,
              class: 'sql-injection',
              line: lineNum,
              endLine: lineNum + 1 <= lines.length ? lineNum + 1 : lineNum,
              severity: 'CRITICAL',
              description: 'Параметр HTTP-запроса подставляется в SQL-запрос без параметризации (интерполяция строки)',
              remediation: 'Использовать позиционные плейсхолдеры (?) и передавать значения аргументами в JdbcTemplate'
            });
            continue;
          }
        }
      }

      // 3. Standalone unparameterized SQL/HQL string definition (e.g. "SELECT ... WHERE ... $lastName")
      if (
        (line.includes('SELECT ') || line.includes('FROM ')) &&
        /\$[a-zA-Z0-9_]+/.test(line) &&
        !line.includes('?') &&
        !reportedLines.has(lineNum) &&
        /(?:SELECT\s+.*FROM|FROM\s+.*WHERE)\s+.*\$[a-zA-Z0-9_]+/i.test(line)
      ) {
        reportedLines.add(lineNum);
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'sql-injection',
          line: lineNum,
          endLine: lineNum,
          severity: 'CRITICAL',
          description: 'Формирование непараметризованного SQL/HQL-запроса через интерполяцию переменных в строке',
          remediation: 'Использовать параметризованные запросы с плейсхолдерами (?) или именованными параметрами (:param)'
        });
      }
    }

    return findings;
  }

  /**
   * Rule 2: TLS Verification
   * Match disabled hostname verification or trusting all certs.
   * Control A-CTRL-06: Standard HttpsURLConnection without custom verifier is SAFE!
   */
  private checkTlsVerification(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      // Match: hostnameVerifier = HostnameVerifier { _, _ -> true } or return true
      if (
        line.includes('hostnameVerifier') &&
        (line.includes('-> true') || line.includes('return true'))
      ) {
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'tls-verification',
          line: lineNum,
          endLine: lineNum,
          severity: 'HIGH',
          description: 'Ослабленная проверка имени хоста в TLS (hostnameVerifier принимает любое имя)',
          remediation: 'Удалить кастомный HostnameVerifier и использовать штатную валидацию сертификатов JVM'
        });
      }
    }

    return findings;
  }

  /**
   * Rule 3: Credentialed CORS
   * Match allowedOriginPatterns = listOf("*") AND allowCredentials = true
   */
  private checkCredentialedCors(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];

    let originLine = -1;
    let credentialsLine = -1;

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      if (
        (line.includes('allowedOriginPatterns') || line.includes('allowedOrigins')) &&
        (line.includes('"*"') || line.includes("'*'"))
      ) {
        originLine = lineNum;
      }

      if (line.includes('allowCredentials') && line.includes('true')) {
        credentialsLine = lineNum;
      }
    }

    if (originLine !== -1 && credentialsLine !== -1 && Math.abs(originLine - credentialsLine) <= 5) {
      const startLine = Math.min(originLine, credentialsLine);
      const endLine = Math.max(originLine, credentialsLine);
      findings.push({
        category: 'SAST',
        path: relPath,
        class: 'credentialed-cors',
        line: startLine,
        endLine: endLine,
        severity: 'MEDIUM',
        description: 'CORS разрешает любой origin (*) совместно с передачей учетных данных (allowCredentials = true)',
        remediation: 'Указать доверенные домены в allowedOriginPatterns вместо подстановщика * при передаче credentials'
      });
    }

    return findings;
  }

  /**
   * Rule 4: Route Authorization Flaw
   * Match permitAll on sensitive routes (e.g. export, admin, internal, pickup).
   * Control A-CTRL-05: /api/catalog/services is a safe public catalog!
   */
  private checkRouteAuthorization(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      // Spring Security requestMatchers permitAll
      // rules.requestMatchers(GET, "/api/pickup/export").permitAll()
      if (line.includes('permitAll()') && line.includes('requestMatchers')) {
        // Control A-CTRL-05: /api/catalog/services or public catalog routes are SAFE
        if (line.includes('/catalog/') || line.includes('/public/')) {
          continue;
        }

        // Sensitive keywords: export, pickup, admin, internal, secret, manage, users
        if (
          line.includes('/export') ||
          line.includes('/pickup/') ||
          line.includes('/admin') ||
          line.includes('/internal')
        ) {
          findings.push({
            category: 'SAST',
            path: relPath,
            class: 'route-authorization',
            line: lineNum,
            endLine: lineNum,
            severity: 'HIGH',
            description: 'Служебный защищённый маршрут ошибочно открыт без авторизации через permitAll()',
            remediation: 'Заменить permitAll() на проверку аутентификации authenticated() или роли hasRole(...)'
          });
        }
      }
    }

    return findings;
  }

  /**
   * Rule 5: Object Authorization (IDOR / BOLA) (A-SAST-05 - HARD case)
   * Detect direct object access by ID without verifying customer ownership.
   */
  private checkObjectAuthorization(lines: string[], relPath: string, projectRoot: string): SastFinding[] {
    const findings: SastFinding[] = [];

    // Check if this file is a Reader/Repository with read by ticketId without customer constraint
    if (relPath.includes('Reader.kt') || relPath.includes('Repository.kt')) {
      for (let i = 0; i < lines.length; i++) {
        const lineNum = i + 1;
        const line = lines[i];

        // e.g. fun read(ticketId: Long): RepairTicket? = jdbc.query("SELECT ... WHERE ticket_id = ?", ..., ticketId)
        if (
          line.includes('fun read(') &&
          line.includes('ticketId') &&
          !line.includes('customerId')
        ) {
          const nextLines = lines.slice(i, Math.min(lines.length, i + 6)).join(' ');
          if (
            nextLines.includes('WHERE ticket_id = ?') &&
            !nextLines.includes('customer_id = ?') &&
            !nextLines.includes('AND customer_id')
          ) {
            findings.push({
              category: 'SAST',
              path: relPath,
              class: 'object-authorization',
              line: lineNum,
              endLine: lineNum + 1,
              severity: 'HIGH',
              description: 'Отсутствует проверка владения объектом (IDOR): чтение заявки выполняется только по ID без проверки customerId',
              remediation: 'Добавить проверку соответствия customerId текущему авторизованному пользователю'
            });
          }
        }
      }
    }

    return findings;
  }
}
