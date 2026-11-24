import * as fs from 'fs';
import * as path from 'path';
import archiver from 'archiver';

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'build',
  '.gradle',
  '.idea',
  'dist',
  '.cache',
  'out',
  '.vscode',
  '__pycache__'
]);

const IGNORED_EXTS = new Set([
  '.zip',
  '.tar',
  '.gz',
  '.jar',
  '.class',
  '.pyc',
  '.exe',
  '.bin'
]);

export async function createProjectZipBuffer(projectRoot: string): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const archive = archiver('zip', {
      zlib: { level: 6 }
    });

    const buffers: Buffer[] = [];
    archive.on('data', chunk => buffers.push(chunk));
    archive.on('end', () => resolve(Buffer.concat(buffers)));
    archive.on('error', err => reject(err));

    function addDirRecursive(currentDir: string, relativePrefix: string = '') {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });

      for (const entry of entries) {
        const name = entry.name;
        if (entry.isDirectory()) {
          if (IGNORED_DIRS.has(name) || name.startsWith('.git')) {
            continue;
          }
          const subRel = relativePrefix ? `${relativePrefix}/${name}` : name;
          addDirRecursive(path.join(currentDir, name), subRel);
        } else if (entry.isFile()) {
          const ext = path.extname(name).toLowerCase();
          if (IGNORED_EXTS.has(ext)) {
            continue;
          }
          const fileRel = relativePrefix ? `${relativePrefix}/${name}` : name;
          const fullPath = path.join(currentDir, name);
          archive.file(fullPath, { name: fileRel });
        }
      }
    }

    try {
      addDirRecursive(projectRoot);
      archive.finalize();
    } catch (err) {
      reject(err);
    }
  });
}
