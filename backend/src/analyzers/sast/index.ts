import * as fs from 'fs';
import * as path from 'path';
import type { SastFinding } from '../../types/findings.ts';
import { stripCommentsPreservingLines, extractBraceBlocks } from '../utils/source-utils.ts';
import { normalizeFindingRange } from '../../validators/submission-validator.ts';

interface ControllerEndpoint {
  filePath: string;
  methodName: string;
  startLine: number;
  endLine: number;
  idParamNames: string[];
  hasPrincipal: boolean;
  hasSecurityAnnotation: boolean;
  calledMethods: string[];
}

interface ServiceMethod {
  filePath: string;
  methodName: string;
  startLine: number;
  endLine: number;
  hasPrincipal: boolean;
  hasSecurityAnnotation: boolean;
  calledMethods: string[];
}

interface RepoMethod {
  filePath: string;
  methodName: string;
  startLine: number;
  endLine: number;
  queryLine: number;
  queryText: string;
  hasOwnerCheckInQuery: boolean;
  hasOwnerColumnInContext: boolean;
}

export class SastAnalyzer {
  public scanProject(projectRoot: string): SastFinding[] {
    const findings: SastFinding[] = [];
    const files = this.collectSourceFiles(projectRoot);

    // Multi-file index for inter-procedural IDOR analysis
    const controllers: ControllerEndpoint[] = [];
    const serviceMethods: ServiceMethod[] = [];
    const repoMethods: RepoMethod[] = [];

    for (const file of files) {
      const relPath = path.relative(projectRoot, file).replace(/\\/g, '/');
      const rawContent = fs.readFileSync(file, 'utf-8');
      const cleanContent = stripCommentsPreservingLines(rawContent);
      const lines = cleanContent.split('\n');

      // Rule 1: SQL Injection (A-SAST-01)
      findings.push(...this.checkSqlInjection(lines, relPath));

      // Rule 2: TLS Verification (A-SAST-02)
      findings.push(...this.checkTlsVerification(lines, relPath));

      // Rule 3: Credentialed CORS (A-SAST-03)
      findings.push(...this.checkCredentialedCors(lines, relPath));

      // Rule 4: Route Authorization Flaw (A-SAST-04)
      findings.push(...this.checkRouteAuthorization(lines, relPath));

      // Indexing for Rule 5: Object Authorization (IDOR)
      this.indexForObjectAuthorization(lines, relPath, controllers, serviceMethods, repoMethods);
    }

    // Rule 5: Inter-procedural Object Authorization / IDOR (A-SAST-05)
    findings.push(...this.resolveObjectAuthorization(controllers, serviceMethods, repoMethods));

    return findings;
  }

  private collectSourceFiles(dir: string): string[] {
    const results: string[] = [];
    if (!fs.existsSync(dir)) return results;

    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!['.git', 'node_modules', '.gradle', 'build', 'dist', 'target'].includes(entry.name)) {
          results.push(...this.collectSourceFiles(fullPath));
        }
      } else if (entry.isFile() && (entry.name.endsWith('.kt') || entry.name.endsWith('.java'))) {
        results.push(fullPath);
      }
    }
    return results;
  }

  // =========================================================================
  // RULE 1: SQL / HQL / JPQL Injection (A-SAST-01)
  // =========================================================================

  private checkSqlInjection(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];
    const reportedLines = new Set<number>();

    // Intermediate variables tracking: varName -> { defLine, isDynamic, sqlText }
    const dynamicSqlVars = new Map<string, { defLine: number; sqlText: string }>();

    const sqlVerbs = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO|FROM)\b/i;
    const executionSinks = /\b(query|queryForList|queryForObject|queryForMap|update|batchUpdate|execute|executeUpdate|createQuery|createNativeQuery|prepareStatement)\s*\(/;

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      // 1. Detect dynamic SQL assigned to variables
      const assignMatch = line.match(/(?:val|var)\s+([a-zA-Z0-9_]+)\s*=\s*([\s\S]+)/);
      if (assignMatch) {
        const varName = assignMatch[1];
        const expr = assignMatch[2];

        if (sqlVerbs.test(expr)) {
          const hasInterpolation = /\$[a-zA-Z0-9_]+|\$\{[^}]+\}/.test(expr);
          const hasConcat = /["']\s*\+\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*\+\s*["']/.test(expr);
          const hasFormatting = /\.format\s*\(|String\.format\s*\(/.test(expr);

          if (hasInterpolation || hasConcat || hasFormatting) {
            dynamicSqlVars.set(varName, { defLine: lineNum, sqlText: expr });
          }
        }
      }

      // 2. Check execution sink calls
      if (executionSinks.test(line)) {
        // Subcase A: Sink executes an intermediate variable that was dynamically constructed
        for (const [varName, varInfo] of dynamicSqlVars.entries()) {
          const callWithVar = new RegExp(`\\b${varName}\\b`);
          if (callWithVar.test(line)) {
            if (!reportedLines.has(varInfo.defLine)) {
              reportedLines.add(varInfo.defLine);
              const range = normalizeFindingRange({ line: varInfo.defLine, endLine: lineNum }, lines);
              findings.push({
                category: 'SAST',
                path: relPath,
                class: 'sql-injection',
                line: range.line,
                endLine: range.endLine,
                severity: 'CRITICAL',
                description: 'Параметр подставляется в SQL/HQL-запрос без параметризации (конкатенация или интерполяция строки в sink-вызове)',
                remediation: 'Использовать позиционные (?) или именованные (:param) параметры с передачей значений через аргументы JdbcTemplate или setParameter'
              });
            }
          }
        }

        // Subcase B: Sink executes an inline SQL string with interpolation or concatenation
        if (sqlVerbs.test(line)) {
          const hasInterpolation = /\$[a-zA-Z0-9_]+|\$\{[^}]+\}/.test(line);
          const hasConcat = /["']\s*\+\s*[a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*\+\s*["']/.test(line);

          // Control check: does the call use positional placeholders ? with parameters safely?
          // If line has '?' AND doesn't interpolate or concatenate, it is SAFE (A-CTRL-04)
          const isSafelyParameterized = line.includes('?') && !hasInterpolation && !hasConcat;

          if ((hasInterpolation || hasConcat) && !isSafelyParameterized && !reportedLines.has(lineNum)) {
            reportedLines.add(lineNum);
            let endLine = lineNum;
            if (!line.includes(')')) {
              for (let k = i + 1; k < Math.min(lines.length, i + 10); k++) {
                if (lines[k].includes(')')) {
                  endLine = k + 1;
                  break;
                }
              }
            }
            const range = normalizeFindingRange({ line: lineNum, endLine }, lines);
            findings.push({
              category: 'SAST',
              path: relPath,
              class: 'sql-injection',
              line: range.line,
              endLine: range.endLine,
              severity: 'CRITICAL',
              description: 'Прямая подстановка непроверенных параметров в SQL-запрос через интерполяцию/конкатенацию строки',
              remediation: 'Заменить интерполяцию строки на позиционные плейсхолдеры (?) и передавать аргументы параметрами'
            });
          }
        }
      }
    }

    return findings;
  }

  // =========================================================================
  // RULE 2: Insecure TLS / Hostname Verification (A-SAST-02)
  // =========================================================================

  private checkTlsVerification(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];
    const coveredLines = new Set<number>();

    // Clean lines without imports and packages for block extraction
    const cleanLines = lines.map(l => {
      const trimmed = l.trim();
      return (trimmed.startsWith('import ') || trimmed.startsWith('package ')) ? '' : l;
    });

    // Aggregate empty checkClientTrusted / checkServerTrusted inside each X509TrustManager block (Defect 3)
    const trustManagerBlocks = extractBraceBlocks(cleanLines, /\bX509TrustManager\b/);
    for (const block of trustManagerBlocks) {
      const hasEmptyCheck = /(?:checkClientTrusted|checkServerTrusted)\s*\([^)]*\)\s*(?::\s*[A-Za-z0-9_?<>]+)?\s*\{\s*(?:return;?)?\s*\}/.test(
        block.content
      );
      if (hasEmptyCheck) {
        const range = normalizeFindingRange({ line: block.startLine, endLine: block.endLine }, lines);
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'tls-verification',
          line: range.line,
          endLine: range.endLine,
          severity: 'HIGH',
          description: 'Пустой метод валидации сертификатов X509TrustManager (отсутствует проверка цепочки сертификатов)',
          remediation: 'Выполнять полную проверку цепочки сертификатов X509Certificate или использовать дефолтный TrustManager'
        });
        for (let ln = block.startLine; ln <= block.endLine; ln++) {
          coveredLines.add(ln);
        }
      }
    }

    // HostnameVerifier blocks (anonymous object : HostnameVerifier or class : HostnameVerifier)
    const hostnameVerifierBlocks = extractBraceBlocks(cleanLines, /\bHostnameVerifier\b/);
    for (const block of hostnameVerifierBlocks) {
      const hasUnconditionalTrue =
        /override\s+fun\s+verify\s*\([^)]*\)[^{=]*=\s*true\b/.test(block.content) ||
        /override\s+fun\s+verify\s*\([^)]*\)\s*(?::\s*[A-Za-z0-9_?<>]+)?\s*\{\s*return\s+true;?\s*\}/.test(block.content) ||
        (/override\s+fun\s+verify\b/.test(block.content) && /\breturn\s+true\b/.test(block.content));

      if (hasUnconditionalTrue) {
        const range = normalizeFindingRange({ line: block.startLine, endLine: block.endLine }, lines);
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'tls-verification',
          line: range.line,
          endLine: range.endLine,
          severity: 'HIGH',
          description: 'Отключена проверка имени хоста в TLS (HostnameVerifier безусловно возвращает true)',
          remediation: 'Использовать штатную валидацию сертификатов и доменных имен JVM без переопределения HostnameVerifier'
        });
        for (let ln = block.startLine; ln <= block.endLine; ln++) {
          coveredLines.add(ln);
        }
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      if (coveredLines.has(lineNum)) continue;

      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('import ') || trimmed.startsWith('package ')) {
        continue;
      }

      const isHostnameVerifier =
        line.includes('hostnameVerifier') ||
        line.includes('HostnameVerifier') ||
        line.includes('setHostnameVerifier');

      const returnsTrue =
        /->\s*true\b/.test(line) ||
        /\breturn\s+true\b/.test(line) ||
        /verify\s*\([^)]*\)\s*[:=]\s*true\b/.test(line);

      if (isHostnameVerifier && returnsTrue) {
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'tls-verification',
          line: lineNum,
          endLine: lineNum,
          severity: 'HIGH',
          description: 'Отключена проверка имени хоста в TLS (HostnameVerifier безусловно возвращает true)',
          remediation: 'Использовать штатную валидацию сертификатов и доменных имен JVM без переопределения HostnameVerifier'
        });
        continue;
      }

      if (
        line.includes('NoopHostnameVerifier') ||
        line.includes('TrustAllStrategy') ||
        line.includes('InsecureTrustManagerFactory') ||
        /loadTrustMaterial\s*\(\s*null\s*\)\s*\{\s*_,?\s*_?\s*->\s*true/.test(line)
      ) {
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'tls-verification',
          line: lineNum,
          endLine: lineNum,
          severity: 'HIGH',
          description: 'Использование небезопасной стратегии доверия сертификатам (TrustAll / NoopHostnameVerifier)',
          remediation: 'Использовать доверенные системные сертификаты X.509 и строгую проверку цепочки доверия'
        });
        continue;
      }

      if (!coveredLines.has(lineNum) && (line.includes('checkServerTrusted') || line.includes('checkClientTrusted'))) {
        const nextLines = lines.slice(i, Math.min(lines.length, i + 4)).join(' ');
        if (/\{\s*\}/.test(nextLines) || /\{\s*return;?\s*\}/.test(nextLines)) {
          findings.push({
            category: 'SAST',
            path: relPath,
            class: 'tls-verification',
            line: lineNum,
            endLine: Math.min(lines.length, lineNum + 2),
            severity: 'HIGH',
            description: 'Пустой метод валидации сертификатов X509TrustManager (отсутствует проверка цепочки сертификатов)',
            remediation: 'Выполнять полную проверку цепочки сертификатов X509Certificate или использовать дефолтный TrustManager'
          });
          for (let ln = lineNum; ln <= Math.min(lines.length, lineNum + 10); ln++) {
            coveredLines.add(ln);
          }
        }
      }
    }

    return findings;
  }

  // =========================================================================
  // RULE 3: Credentialed CORS (A-SAST-03) - Scope-Isolated Block Analysis
  // =========================================================================

  private checkCredentialedCors(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];

    // Extract brace-balanced blocks (from innermost to outermost) to strictly isolate each CORS configuration block (Defect 4)
    const blocks = extractBraceBlocks(
      lines,
      /CorsConfiguration\b|addCorsMappings\b|addMapping\b|CorsFilter\b|corsConfigurationSource\b|\.apply\s*\{|\bfun\s+/
    ).sort((a, b) => (a.endLine - a.startLine) - (b.endLine - b.startLine));

    const claimedLines = new Set<number>();

    for (const block of blocks) {
      const blockLines = block.content.split('\n');
      let wildcardOriginLine = -1;
      let credentialsLine = -1;

      for (let j = 0; j < blockLines.length; j++) {
        const currentLineNum = block.startLine + j;
        if (claimedLines.has(currentLineNum)) continue;

        const bLine = blockLines[j];

        const hasWildcardOrigin =
          /\b(allowedOrigins|allowedOriginPatterns|addAllowedOrigin|addAllowedOriginPattern)\b/.test(bLine) &&
          (/["']\*["']/.test(bLine) || /listOf\s*\(\s*["']\*["']\s*\)/.test(bLine));

        if (hasWildcardOrigin && wildcardOriginLine === -1) {
          wildcardOriginLine = currentLineNum;
        }

        const hasCredentials =
          /\b(allowCredentials|setAllowCredentials)\b/.test(bLine) &&
          (/\btrue\b/.test(bLine) || /\(\s*true\s*\)/.test(bLine));

        if (hasCredentials && credentialsLine === -1) {
          credentialsLine = currentLineNum;
        }
      }

      if (wildcardOriginLine !== -1 && credentialsLine !== -1) {
        const start = Math.max(block.startLine, Math.min(wildcardOriginLine, credentialsLine));
        const end = Math.min(block.endLine, Math.max(wildcardOriginLine, credentialsLine));
        const range = normalizeFindingRange({ line: start, endLine: end }, lines);

        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'credentialed-cors',
          line: range.line,
          endLine: range.endLine !== undefined ? Math.min(range.endLine, block.endLine) : undefined,
          severity: 'MEDIUM',
          description: 'Небезопасная конфигурация CORS: разрешены любые источники (*) одновременно с передачей учетных данных (allowCredentials = true)',
          remediation: 'Заменить подстановочный символ * в allowedOriginPatterns на явный список доверенных доменов'
        });

        for (let ln = block.startLine; ln <= block.endLine; ln++) {
          claimedLines.add(ln);
        }
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      if (line.includes('@CrossOrigin') && (line.includes('"*"') || line.includes("'*'")) && line.includes('allowCredentials = "true"')) {
        findings.push({
          category: 'SAST',
          path: relPath,
          class: 'credentialed-cors',
          line: lineNum,
          endLine: lineNum,
          severity: 'MEDIUM',
          description: 'Аннотация @CrossOrigin разрешает любой origin (*) совместно с allowCredentials = true',
          remediation: 'Указать конкретные домены в origins вместо *'
        });
      }
    }

    return findings;
  }

  // =========================================================================
  // RULE 4: Route Authorization Flaw / Prefix Shadowing (A-SAST-04)
  // =========================================================================

  private checkRouteAuthorization(lines: string[], relPath: string): SastFinding[] {
    const findings: SastFinding[] = [];

    const techExemptions = [
      '/login', '/logout', '/error', '/health', '/actuator/health',
      '/actuator/info', '/api/auth', '/swagger-ui', '/v3/api-docs',
      '/static', '/public', '/catalog'
    ];

    const sensitiveSegments = [
      'admin', 'internal', 'manage', 'debug', 'export',
      'dump', 'backup', 'audit', 'secret', 'private', 'staff', 'operator'
    ];

    interface SecurityRule {
      line: number;
      pattern: string;
      access: 'permitAll' | 'authenticated' | 'hasRole' | 'denyAll';
      role?: string;
    }

    const rules: SecurityRule[] = [];

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      if (line.includes('requestMatchers') || line.includes('antMatchers')) {
        const pathMatch = line.match(/["'](\/[^"']*)["']/);
        if (pathMatch) {
          const pattern = pathMatch[1];
          let access: 'permitAll' | 'authenticated' | 'hasRole' | 'denyAll' = 'permitAll';
          let role: string | undefined;

          if (line.includes('permitAll()')) {
            access = 'permitAll';
          } else if (line.includes('authenticated()')) {
            access = 'authenticated';
          } else if (line.includes('hasRole') || line.includes('hasAuthority')) {
            access = 'hasRole';
            const roleMatch = line.match(/(?:hasRole|hasAuthority)\s*\(\s*["']([^"']+)["']/);
            if (roleMatch) role = roleMatch[1];
          } else if (line.includes('denyAll()')) {
            access = 'denyAll';
          }

          rules.push({ line: lineNum, pattern, access, role });
        }
      }
    }

    // Prefix Shadowing analysis
    for (let i = 0; i < rules.length; i++) {
      const current = rules[i];
      if (current.access === 'permitAll') {
        const isExempt = techExemptions.some(ex => current.pattern.startsWith(ex) || current.pattern.includes(ex));
        if (isExempt) continue;

        for (let j = i + 1; j < rules.length; j++) {
          const subsequent = rules[j];
          if (subsequent.access === 'hasRole' || subsequent.access === 'authenticated') {
            const prefix = subsequent.pattern.replace(/\/\*\*$/, '').replace(/\/\*$/, '');

            if (current.pattern.startsWith(prefix) && current.pattern !== prefix) {
              const isCritical = (subsequent.role && subsequent.role.toUpperCase().includes('ADMIN')) ||
                current.pattern.includes('admin') || current.pattern.includes('audit');

              findings.push({
                category: 'SAST',
                path: relPath,
                class: 'route-authorization',
                line: current.line,
                endLine: current.line,
                severity: isCritical ? 'CRITICAL' : 'HIGH',
                description: `Нарушение порядка правил авторизации (Prefix Shadowing): маршрут "${current.pattern}" открыт через permitAll() перед защищённым правилом "${subsequent.pattern}" (${subsequent.role || 'authenticated'})`,
                remediation: `Поместить защищённое правило "${subsequent.pattern}" выше permitAll() или закрыть маршрут соответствующей ролью`
              });
              break;
            }
          }
        }

        const containsSensitive = sensitiveSegments.some(seg => current.pattern.includes(seg));
        if (containsSensitive && !findings.some(f => f.line === current.line)) {
          findings.push({
            category: 'SAST',
            path: relPath,
            class: 'route-authorization',
            line: current.line,
            endLine: current.line,
            severity: current.pattern.includes('admin') ? 'CRITICAL' : 'HIGH',
            description: `Чувствительный маршрут "${current.pattern}" открыт без аутентификации через permitAll()`,
            remediation: 'Заменить permitAll() на authenticated() или hasRole(...)'
          });
        }
      }
    }

    return findings;
  }

  // =========================================================================
  // RULE 5: Object Authorization (IDOR / BOLA) - Inter-procedural Analysis
  // =========================================================================

  private indexForObjectAuthorization(
    lines: string[],
    relPath: string,
    controllers: ControllerEndpoint[],
    serviceMethods: ServiceMethod[],
    repoMethods: RepoMethod[]
  ): void {
    const fullText = lines.join('\n');
    const isController =
      fullText.includes('@RestController') ||
      fullText.includes('@Controller') ||
      relPath.includes('Controller');

    const isService =
      fullText.includes('@Service') ||
      fullText.includes('@Component') ||
      relPath.includes('Service');

    const hasDataAnnotation =
      /@(?:Repository|Component|Service)\b/.test(fullText);

    const hasJdbcCalls =
      /\b(?:jdbc|jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*(?:query|queryForObject|queryForList|queryForMap)\b/i.test(fullText);

    const isDataAccess = hasDataAnnotation || hasJdbcCalls;

    if (isController) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funMatch = line.match(/fun\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)/);
        if (funMatch) {
          const methodName = funMatch[1];
          const paramStr = funMatch[2];
          const methodLines = lines.slice(i, Math.min(lines.length, i + 25)).join(' ');

          const idParamMatch = paramStr.match(/(?:@PathVariable|@RequestParam)?\s*([a-zA-Z0-9_]*[iI]d|[a-zA-Z0-9_]*[cC]ode|[a-zA-Z0-9_]*[nN]umber)\s*:\s*(?:Long|Int|String|UUID)/g);

          const hasPrincipal =
            /Principal|Authentication|@AuthenticationPrincipal|SecurityContextHolder/i.test(paramStr) ||
            /SecurityContextHolder\.getContext\(\)/.test(methodLines);

          const hasSecurityAnnotation =
            /@PreAuthorize|@PostAuthorize|@Secured/.test(methodLines);

          const calledMethods: string[] = [];
          const callMatches = methodLines.matchAll(/\b([a-zA-Z0-9_]+)\s*\.\s*([a-zA-Z0-9_]+)\s*\(/g);
          for (const m of callMatches) {
            calledMethods.push(m[2]);
          }

          if (idParamMatch && idParamMatch.length > 0) {
            controllers.push({
              filePath: relPath,
              methodName,
              startLine: i + 1,
              endLine: Math.min(lines.length, i + 15),
              idParamNames: idParamMatch,
              hasPrincipal,
              hasSecurityAnnotation,
              calledMethods
            });
          }
        }
      }
    }

    if (isService) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funMatch = line.match(/fun\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)/);
        if (funMatch) {
          const methodName = funMatch[1];
          const paramStr = funMatch[2];
          const methodLines = lines.slice(i, Math.min(lines.length, i + 25)).join(' ');

          const hasPrincipal =
            /Principal|Authentication|@AuthenticationPrincipal|SecurityContextHolder/i.test(paramStr) ||
            /SecurityContextHolder\.getContext\(\)/.test(methodLines);

          const hasSecurityAnnotation =
            /@PreAuthorize|@PostAuthorize|@Secured/.test(methodLines);

          const calledMethods: string[] = [];
          const callMatches = methodLines.matchAll(/\b([a-zA-Z0-9_]+)\s*\.\s*([a-zA-Z0-9_]+)\s*\(/g);
          for (const m of callMatches) {
            calledMethods.push(m[2]);
          }

          serviceMethods.push({
            filePath: relPath,
            methodName,
            startLine: i + 1,
            endLine: Math.min(lines.length, i + 25),
            hasPrincipal,
            hasSecurityAnnotation,
            calledMethods
          });
        }
      }
    }

    if (isDataAccess) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funMatch = line.match(/fun\s+([a-zA-Z0-9_]+)\s*\(/);
        if (funMatch) {
          const methodName = funMatch[1];
          const methodStartLine = i + 1;
          const methodSlice = lines.slice(i, Math.min(lines.length, i + 15));
          const methodText = methodSlice.join(' ');

          const queryMatch = methodText.match(/(?:"""|["'])([\s\S]*?(?:SELECT|DELETE|UPDATE)\b[\s\S]*?)(?:"""|["'])/i);
          if (queryMatch) {
            const queryText = queryMatch[1];
            let queryLine = methodStartLine;
            for (let k = 0; k < methodSlice.length; k++) {
              if (methodSlice[k].includes(queryText.substring(0, Math.min(queryText.length, 20)))) {
                queryLine = methodStartLine + k;
                break;
              }
            }

            const filtersById = /WHERE\s+[a-zA-Z0-9_]*id\s*=\s*(?:\?|:[a-zA-Z0-9_]+)/i.test(queryText);

            const ownerRoots = [
              'customer', 'owner', 'user', 'account', 'client', 'holder',
              'beneficiary', 'author', 'member', 'driver', 'tenant', 'profile', 'subscriber'
            ];
            const rootsGroup = ownerRoots.join('|');

            const ownerQueryRegex = new RegExp(
              `\\b(?:${rootsGroup})[-_]?(?:id|account|uuid|no|code|ref|key|name)?\\s*=\\s*(?:\\?|:[a-zA-Z0-9_]+)`,
              'i'
            );
            const hasOwnerCheckInQuery = ownerQueryRegex.test(queryText);

            const ownerContextRegex = new RegExp(
              `\\b(?:${rootsGroup})[-_]?(?:id|account|uuid|no|code|ref|key|name)?\\b|\\b(?:${rootsGroup})(?:Id|Account|Uuid|No|Code|Ref|Key|Name)?\\b`,
              'i'
            );
            const hasOwnerColumnInContext = ownerContextRegex.test(fullText);

            if (filtersById) {
              repoMethods.push({
                filePath: relPath,
                methodName,
                startLine: methodStartLine,
                endLine: methodStartLine + methodSlice.length,
                queryLine,
                queryText,
                hasOwnerCheckInQuery,
                hasOwnerColumnInContext
              });
            }
          }
        }
      }
    }
  }

  private resolveObjectAuthorization(
    controllers: ControllerEndpoint[],
    serviceMethods: ServiceMethod[],
    repoMethods: RepoMethod[]
  ): SastFinding[] {
    const findings: SastFinding[] = [];
    const reportedRepoMethods = new Set<string>();

    for (const ctrl of controllers) {
      if (!ctrl.hasPrincipal && !ctrl.hasSecurityAnnotation) {
        for (const repo of repoMethods) {
          const isDirectlyCalled =
            ctrl.calledMethods.includes(repo.methodName) ||
            ctrl.methodName.toLowerCase().includes(repo.methodName.toLowerCase()) ||
            repo.methodName.toLowerCase().includes(ctrl.methodName.toLowerCase());

          let isTwoHopCalled = false;
          if (!isDirectlyCalled) {
            for (const svc of serviceMethods) {
              if (!svc.hasPrincipal && !svc.hasSecurityAnnotation) {
                const ctrlCallsSvc =
                  ctrl.calledMethods.includes(svc.methodName) ||
                  ctrl.methodName.toLowerCase().includes(svc.methodName.toLowerCase());
                if (ctrlCallsSvc) {
                  const svcCallsRepo =
                    svc.calledMethods.includes(repo.methodName) ||
                    svc.methodName.toLowerCase().includes(repo.methodName.toLowerCase());
                  if (svcCallsRepo) {
                    isTwoHopCalled = true;
                    break;
                  }
                }
              }
            }
          }

          if ((isDirectlyCalled || isTwoHopCalled) && !repo.hasOwnerCheckInQuery && repo.hasOwnerColumnInContext) {
            const repoKey = `${repo.filePath}:${repo.startLine}`;
            if (!reportedRepoMethods.has(repoKey)) {
              reportedRepoMethods.add(repoKey);
              const range = normalizeFindingRange({ line: repo.startLine, endLine: repo.queryLine });

              findings.push({
                category: 'SAST',
                path: repo.filePath,
                class: 'object-authorization',
                line: range.line,
                endLine: range.endLine,
                severity: 'HIGH',
                description: 'Отсутствует проверка владения объектом (IDOR/BOLA): доступ к записи выполняется только по идентификатору без верификации владельца в запросе',
                remediation: 'Добавить в SQL/HQL-запрос условие фильтрации по текущему авторизованному пользователю или проверку соответствия владельца в сервисном слое'
              });
            }
          }
        }
      }
    }

    return findings;
  }
}
