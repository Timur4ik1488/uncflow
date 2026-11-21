import * as fs from 'fs';
import * as path from 'path';
import type { Finding, FindingCategory } from '../types/findings.ts';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Normalizes line and endLine ranges for SECRET and SAST findings.
 * Requirements:
 * - 1 <= line
 * - line <= endLine <= line + 14
 * - If fileLines are provided, trim leading/trailing empty lines
 */
export function normalizeFindingRange(
  finding: { line: number; endLine?: number },
  fileLines?: string[]
): { line: number; endLine?: number } {
  let line = Math.max(1, Math.floor(finding.line || 1));
  let endLine = finding.endLine !== undefined ? Math.floor(finding.endLine) : line;

  if (fileLines && fileLines.length > 0) {
    const maxLine = fileLines.length;
    line = Math.min(line, maxLine);
    endLine = Math.min(Math.max(line, endLine), maxLine);

    // Trim leading blank lines
    while (line < endLine && !fileLines[line - 1]?.trim()) {
      line++;
    }
    // Trim trailing blank lines
    while (endLine > line && !fileLines[endLine - 1]?.trim()) {
      endLine--;
    }
  }

  if (endLine < line) {
    endLine = line;
  }

  // Maximum span is 14 lines: line <= endLine <= line + 14
  if (endLine > line + 14) {
    endLine = line + 14;
  }

  return {
    line,
    endLine: endLine > line ? endLine : undefined
  };
}

/**
 * Masks raw secret values in descriptions or remediation text
 */
export function maskSensitiveText(text?: string): string {
  if (!text) return '';
  return text
    .replace(/(Bearer\s+)[A-Za-z0-9_\-\.]{8,}/gi, '$1***')
    .replace(/(Basic\s+)[A-Za-z0-9+/=]{8,}/gi, '$1***')
    .replace(/([A-Fa-f0-9]{32,64})/g, (match) => match.substring(0, 4) + '***' + match.substring(match.length - 4))
    .replace(/(ghp_[A-Za-z0-9]{30,})/gi, 'ghp_***')
    .replace(/([a-zA-Z0-9_-]{4,8}_[A-Za-z0-9_]{10,})/gi, (m) => m.substring(0, 4) + '***');
}

/**
 * Strips internal diagnostic fields and produces a strict competition-compliant finding object
 */
export function sanitizeFindingForExport(f: any): any {
  const item: any = {
    category: f.category,
    path: (f.path || '').replace(/\\/g, '/').replace(/^\/+/, '')
  };

  if (f.category === 'SECRET' || f.category === 'SAST') {
    item.class = String(f.class || '').trim();
    item.line = Math.max(1, Math.floor(f.line || 1));
    if (f.endLine && f.endLine > item.line) {
      item.endLine = Math.min(f.endLine, item.line + 14);
    }
  } else if (f.category === 'SCA') {
    item.group = String(f.group || '').trim();
    item.artifact = String(f.artifact || '').trim();
    item.version = String(f.version || '').trim();
    item.advisoryId = String(f.advisoryId || '').trim();
    // Guarantee that class, line, endLine are NEVER exported for SCA
    delete item.class;
    delete item.line;
    delete item.endLine;
  }

  if (f.severity) item.severity = f.severity;
  if (f.description) item.description = maskSensitiveText(f.description);
  if (f.remediation) item.remediation = maskSensitiveText(f.remediation);

  return item;
}

/**
 * Independent submission report validator.
 * Validates strictly according to the hackathon competition format contract.
 */
export function validateSubmissionReport(report: any, repoRoot?: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!report || typeof report !== 'object') {
    return { valid: false, errors: ['Отчёт должен быть объектом JSON'], warnings };
  }

  if (!Array.isArray(report.findings)) {
    return { valid: false, errors: ['Отчёт должен содержать массив "findings"'], warnings };
  }

  // Deduplication check maps:
  // For SCA: track advisoryId + alias collisions
  const scaAdvisories = new Set<string>();
  const seenFindings = new Set<string>();

  for (let i = 0; i < report.findings.length; i++) {
    const f = report.findings[i];
    const prefix = `findings[${i}]`;

    if (!f || typeof f !== 'object') {
      errors.push(`${prefix}: находка должна быть объектом`);
      continue;
    }

    // 1. Category check
    const validCategories: FindingCategory[] = ['SECRET', 'SAST', 'SCA'];
    if (!validCategories.includes(f.category)) {
      errors.push(`${prefix}: недопустимая категория "${f.category}". Разрешены: SECRET, SAST, SCA`);
    }

    // 2. Path check
    if (!f.path || typeof f.path !== 'string') {
      errors.push(`${prefix}: поле "path" обязательно и должно быть строкой`);
    } else {
      const p = f.path;
      if (p.startsWith('/') || /^[a-zA-Z]:/.test(p) || p.startsWith('\\')) {
        errors.push(`${prefix}: путь "${p}" не должен быть абсолютным`);
      }
      if (p.includes('..')) {
        errors.push(`${prefix}: путь "${p}" содержит ".."`);
      }
      if (repoRoot && fs.existsSync(repoRoot)) {
        const fullPath = path.resolve(repoRoot, p);
        if (!fs.existsSync(fullPath)) {
          warnings.push(`${prefix}: файл "${p}" не найден в корне проекта ${repoRoot}`);
        }
      }
    }

    // 3. Category-specific checks
    if (f.category === 'SECRET' || f.category === 'SAST') {
      if (!f.class || typeof f.class !== 'string' || !f.class.trim()) {
        errors.push(`${prefix}: обязательное поле "class" отсутствует или пусто`);
      }
      if (typeof f.line !== 'number' || f.line < 1 || !Number.isInteger(f.line)) {
        errors.push(`${prefix}: обязательное поле "line" должно быть целым положительным числом, получено: ${f.line}`);
      }
      if (f.endLine !== undefined) {
        if (typeof f.endLine !== 'number' || !Number.isInteger(f.endLine)) {
          errors.push(`${prefix}: поле "endLine" должно быть целым числом`);
        } else if (f.endLine < f.line) {
          errors.push(`${prefix}: endLine (${f.endLine}) не может быть меньше line (${f.line})`);
        } else if (f.endLine > f.line + 14) {
          errors.push(`${prefix}: диапазон endLine (${f.endLine}) превышает line + 14 (${f.line + 14})`);
        }
      }

      // Check uniqueness
      const dedupKey = `${f.category}|${f.path}|${f.line}|${f.class}`;
      if (seenFindings.has(dedupKey)) {
        warnings.push(`${prefix}: дубликат находки (${dedupKey})`);
      }
      seenFindings.add(dedupKey);
    } else if (f.category === 'SCA') {
      if (f.class !== undefined) {
        errors.push(`${prefix}: поле "class" ЗАПРЕЩЕНО для SCA-находок`);
      }
      if (f.line !== undefined || f.endLine !== undefined) {
        errors.push(`${prefix}: поля "line" и "endLine" ЗАПРЕЩЕНЫ для SCA-находок`);
      }
      if (!f.group || typeof f.group !== 'string') {
        errors.push(`${prefix}: обязательное поле "group" отсутствует`);
      }
      if (!f.artifact || typeof f.artifact !== 'string') {
        errors.push(`${prefix}: обязательное поле "artifact" отсутствует`);
      }
      if (!f.version || typeof f.version !== 'string') {
        errors.push(`${prefix}: обязательное поле "version" отсутствует`);
      }
      if (!f.advisoryId || typeof f.advisoryId !== 'string') {
        errors.push(`${prefix}: обязательное поле "advisoryId" отсутствует`);
      }

      const scaKey = `${f.group}:${f.artifact}:${f.version}:${f.advisoryId}`;
      if (scaAdvisories.has(scaKey)) {
        errors.push(`${prefix}: дубликат SCA-находки для ${scaKey}`);
      }
      scaAdvisories.add(scaKey);
    }

    // 4. Raw secret leak check
    const textToCheck = `${f.description || ''} ${f.remediation || ''}`;
    if (/(?:[a-zA-Z0-9_-]{4,8}_[a-zA-Z0-9]{12,}|ghp_[a-zA-Z0-9]{20,})/.test(textToCheck)) {
      errors.push(`${prefix}: обнаружена утечка не замаскированного секрета в описании/рекомендации`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}
