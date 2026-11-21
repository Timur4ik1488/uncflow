import * as fs from 'fs';
import * as path from 'path';

export function loadEnvFiles(): void {
  const candidates = [
    path.resolve(process.cwd(), '.env'),
    path.resolve(process.cwd(), 'backend', '.env'),
    path.resolve(process.cwd(), '..', '.env')
  ];

  for (const envPath of candidates) {
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf-8');
        for (const line of content.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const eqIdx = trimmed.indexOf('=');
          if (eqIdx > 0) {
            const key = trimmed.slice(0, eqIdx).trim();
            let val = trimmed.slice(eqIdx + 1).trim();
            if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
              val = val.slice(1, -1);
            }
            // Do NOT overwrite already set environment variables
            if (process.env[key] === undefined || process.env[key] === '') {
              process.env[key] = val;
            }
          }
        }
      } catch {
        // Ignore read errors
      }
    }
  }
}

// Execute immediately upon module import
loadEnvFiles();
