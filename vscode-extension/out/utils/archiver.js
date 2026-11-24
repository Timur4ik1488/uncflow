"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createProjectZipBuffer = createProjectZipBuffer;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const archiver_1 = __importDefault(require("archiver"));
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
async function createProjectZipBuffer(projectRoot) {
    return new Promise((resolve, reject) => {
        const archive = (0, archiver_1.default)('zip', {
            zlib: { level: 6 }
        });
        const buffers = [];
        archive.on('data', chunk => buffers.push(chunk));
        archive.on('end', () => resolve(Buffer.concat(buffers)));
        archive.on('error', err => reject(err));
        function addDirRecursive(currentDir, relativePrefix = '') {
            const entries = fs.readdirSync(currentDir, { withFileTypes: true });
            for (const entry of entries) {
                const name = entry.name;
                if (entry.isDirectory()) {
                    if (IGNORED_DIRS.has(name) || name.startsWith('.git')) {
                        continue;
                    }
                    const subRel = relativePrefix ? `${relativePrefix}/${name}` : name;
                    addDirRecursive(path.join(currentDir, name), subRel);
                }
                else if (entry.isFile()) {
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
        }
        catch (err) {
            reject(err);
        }
    });
}
//# sourceMappingURL=archiver.js.map