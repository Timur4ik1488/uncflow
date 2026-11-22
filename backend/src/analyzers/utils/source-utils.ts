/**
 * Source code processing utilities for SAST and Secret analyzers.
 */

/**
 * Strips line comments (// ...) and block comments (/* ... *\/, including nested in Kotlin)
 * while strictly preserving all newline characters (\n) and character line counts.
 * String literals ("..." and """...""") are preserved verbatim without stripping.
 */
export function stripCommentsPreservingLines(source: string): string {
  const len = source.length;
  let result = '';
  let i = 0;

  let inString = false;
  let inRawString = false;
  let blockCommentDepth = 0;
  let inLineComment = false;

  while (i < len) {
    const ch = source[i];
    const next = i + 1 < len ? source[i + 1] : '';
    const next2 = i + 2 < len ? source[i + 2] : '';

    // Handle line comment end
    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
        result += '\n';
      } else {
        result += ' ';
      }
      i++;
      continue;
    }

    // Handle block comment
    if (blockCommentDepth > 0) {
      if (ch === '/' && next === '*') {
        blockCommentDepth++;
        result += '  ';
        i += 2;
        continue;
      }
      if (ch === '*' && next === '/') {
        blockCommentDepth--;
        result += '  ';
        i += 2;
        continue;
      }
      if (ch === '\n') {
        result += '\n';
      } else {
        result += ' ';
      }
      i++;
      continue;
    }

    // Handle raw string literals (""")
    if (inRawString) {
      if (ch === '"' && next === '"' && next2 === '"') {
        inRawString = false;
        result += '"""';
        i += 3;
        continue;
      }
      result += ch;
      i++;
      continue;
    }

    // Handle standard string literals ("...")
    if (inString) {
      if (ch === '\\' && i + 1 < len) {
        result += ch + next;
        i += 2;
        continue;
      }
      if (ch === '"') {
        inString = false;
        result += '"';
        i++;
        continue;
      }
      result += ch;
      i++;
      continue;
    }

    // Start of raw string
    if (ch === '"' && next === '"' && next2 === '"') {
      inRawString = true;
      result += '"""';
      i += 3;
      continue;
    }

    // Start of regular string
    if (ch === '"') {
      inString = true;
      result += '"';
      i++;
      continue;
    }

    // Start of line comment
    if (ch === '/' && next === '/') {
      inLineComment = true;
      result += '  ';
      i += 2;
      continue;
    }

    // Start of block comment
    if (ch === '/' && next === '*') {
      blockCommentDepth = 1;
      result += '  ';
      i += 2;
      continue;
    }

    // Normal character
    result += ch;
    i++;
  }

  return result;
}

/**
 * Extracts balanced blocks starting with a pattern (e.g. `CorsConfiguration().apply {`)
 */
export interface CodeBlock {
  startLine: number;
  endLine: number;
  content: string;
}

export function extractBraceBlocks(
  lines: string[],
  startPattern: RegExp
): CodeBlock[] {
  const blocks: CodeBlock[] = [];

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('import ') || trimmed.startsWith('package ')) {
      continue;
    }
    if (startPattern.test(lines[i])) {
      const startLine = i + 1;
      let braceCount = 0;
      let foundOpen = false;
      const blockLines: string[] = [];

      for (let j = i; j < lines.length; j++) {
        const cur = lines[j];
        blockLines.push(cur);

        let abortBlock = false;
        for (const char of cur) {
          if (char === '{') {
            braceCount++;
            foundOpen = true;
          } else if (char === '}') {
            if (!foundOpen) {
              // Encountered closing brace before opening brace: abort this candidate block
              abortBlock = true;
              break;
            }
            braceCount--;
          }
        }

        if (abortBlock) {
          break;
        }

        if (!foundOpen && j > i + 3) {
          // No opening brace found within 3 lines: abort this candidate block
          break;
        }

        if (foundOpen && braceCount === 0) {
          blocks.push({
            startLine,
            endLine: j + 1,
            content: blockLines.join('\n')
          });
          break;
        }
      }
    }
  }

  return blocks;
}
