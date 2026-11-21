import * as fs from 'fs';
import * as path from 'path';
import { GigaChatClient } from './security-categorizer.ts';
import { maskSensitiveText } from '../validators/submission-validator.ts';

export interface LlmProvider {
  id: string;
  name: string;
  isAvailable(): boolean;
  chat(systemPrompt: string, userMessage: string, model?: string): Promise<string | null>;
}

/**
 * Sber GigaChat Provider
 */
export class GigaChatProvider implements LlmProvider {
  public id = 'gigachat';
  public name = 'Сбер GigaChat API';
  private client = GigaChatClient.getInstance();

  public isAvailable(): boolean {
    return this.client.isAvailable();
  }

  public async chat(systemPrompt: string, userMessage: string, model: string = 'GigaChat-Pro'): Promise<string | null> {
    // Mask any credentials in prompt before sending to external LLM
    const safePrompt = maskSensitiveText(userMessage);
    return this.client.chatWithSystem(systemPrompt, safePrompt, model);
  }
}

/**
 * Ollama Local Provider (e.g. Qwen2.5-Coder, DeepSeek-Coder, Llama-3)
 */
export class OllamaProvider implements LlmProvider {
  public id = 'ollama';
  public name = 'Ollama Local LLM';
  private baseUrl: string;
  private defaultModel: string;

  constructor(baseUrl?: string, defaultModel?: string) {
    this.baseUrl = baseUrl || process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
    this.defaultModel = defaultModel || process.env.OLLAMA_MODEL || 'qwen2.5-coder';
  }

  public isAvailable(): boolean {
    return Boolean(process.env.OLLAMA_ENABLED === 'true' || process.env.OLLAMA_BASE_URL);
  }

  public async chat(systemPrompt: string, userMessage: string, model?: string): Promise<string | null> {
    const selectedModel = model || this.defaultModel;
    const safeUserMessage = maskSensitiveText(userMessage);
    const endpoint = `${this.baseUrl.replace(/\/+$/, '')}/api/chat`;

    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: selectedModel,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: safeUserMessage }
          ],
          stream: false,
          options: {
            temperature: 0.1
          }
        }),
        signal: AbortSignal.timeout(60000)
      });

      if (!resp.ok) {
        console.warn(`[OllamaProvider] Error HTTP ${resp.status}`);
        return null;
      }

      const data = await resp.json();
      return data?.message?.content?.trim() || null;
    } catch (err: any) {
      console.warn(`[OllamaProvider] Request failed: ${err?.message}`);
      return null;
    }
  }
}

/**
 * Deterministic Offline AppSec Provider (Zero network dependency, 100% reliable)
 */
export class OfflineSmartProvider implements LlmProvider {
  public id = 'offline-smart';
  public name = 'Offline Smart Engine (CWE/OWASP Rules)';

  public isAvailable(): boolean {
    return true;
  }

  public async chat(systemPrompt: string, userMessage: string): Promise<string | null> {
    return null; // Signals the engine to use Tier 1 deterministic rules
  }
}

/**
 * Factory for selecting LLM provider
 */
export class LlmProviderFactory {
  public static getProvider(preference?: string): LlmProvider {
    const pref = preference || process.env.LLM_PROVIDER || 'auto';

    if (pref === 'gigachat') {
      const g = new GigaChatProvider();
      if (g.isAvailable()) return g;
    } else if (pref === 'ollama') {
      const o = new OllamaProvider();
      return o;
    } else if (pref === 'offline-smart') {
      return new OfflineSmartProvider();
    }

    // Auto mode: check GigaChat -> Ollama -> Offline
    const g = new GigaChatProvider();
    if (g.isAvailable()) return g;

    const o = new OllamaProvider();
    if (o.isAvailable()) return o;

    return new OfflineSmartProvider();
  }
}

/**
 * Hallucination Guard: Validates that findings generated or supplemented by AI
 * correspond to real physical files, valid line numbers, and existing vulnerability records.
 */
export class HallucinationGuard {
  public static validateFinding(
    finding: any,
    repoRoot: string,
    vulnDbRecords?: Set<string>
  ): { valid: boolean; reason?: string } {
    if (!finding || typeof finding !== 'object') {
      return { valid: false, reason: 'Finding is null or not an object' };
    }

    // 1. Path existence check
    const relPath = String(finding.path || '').replace(/\\/g, '/');
    const fullPath = path.resolve(repoRoot, relPath);
    if (!fs.existsSync(fullPath)) {
      return {
        valid: false,
        reason: `Галлюцинация пути: файл ${relPath} не существует в репозитории`
      };
    }

    // 2. Line number check
    if (finding.line !== undefined && finding.line !== null) {
      const lineNum = Number(finding.line);
      if (isNaN(lineNum) || lineNum < 1) {
        return {
          valid: false,
          reason: `Недопустимый номер строки: ${finding.line}`
        };
      }

      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        const totalLines = content.split('\n').length;
        if (lineNum > totalLines) {
          return {
            valid: false,
            reason: `Галлюцинация строки: строка ${lineNum} превышает размер файла (${totalLines} строк)`
          };
        }
      } catch {
        // ignore read error
      }
    }

    // 3. For SCA: advisory database existence check
    if (finding.category === 'SCA' && vulnDbRecords && vulnDbRecords.size > 0) {
      const advisory = String(finding.advisoryId || '');
      const coord = `${finding.group}:${finding.artifact}`;
      if (!vulnDbRecords.has(advisory) && !vulnDbRecords.has(coord)) {
        return {
          valid: false,
          reason: `Галлюцинация уязвимости: advisory ${advisory} для ${coord} отсутствует в базе уязвимостей`
        };
      }
    }

    return { valid: true };
  }
}
