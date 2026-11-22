import * as fs from 'fs';
import * as path from 'path';
import type { ScaFinding } from '../../types/findings.ts';
import { VersionComparator } from './version-comparator.ts';
import { stripCommentsPreservingLines } from '../utils/source-utils.ts';

export interface VulnRange {
  lower: string | null;
  lowerInclusive: boolean;
  upper: string | null;
  upperInclusive: boolean;
}

export interface VulnerabilityRecord {
  id: string;
  aliases?: string[];
  group: string;
  artifact: string;
  ranges: VulnRange[];
  fixedVersions?: string[];
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface VulnDatabase {
  formatVersion?: number;
  ecosystem?: string;
  vulnerabilities: VulnerabilityRecord[];
}

export interface DeclaredDependency {
  group: string;
  artifact: string;
  version: string;
  rawLine: string;
  lineNum: number;
  filePath: string;
}

export class ScaAnalyzer {
  private vulnDb: VulnerabilityRecord[] = [];

  constructor(vulnDbPathOrRecords?: string | VulnerabilityRecord[]) {
    if (typeof vulnDbPathOrRecords === 'string') {
      this.loadDatabase(vulnDbPathOrRecords);
    } else if (Array.isArray(vulnDbPathOrRecords)) {
      this.vulnDb = vulnDbPathOrRecords;
    }
  }

  public loadDatabase(dbPath: string): void {
    if (!fs.existsSync(dbPath)) {
      throw new Error(`Vulnerability database not found at ${dbPath}`);
    }
    const raw = fs.readFileSync(dbPath, 'utf-8');
    const parsed: VulnDatabase = JSON.parse(raw);
    this.vulnDb = parsed.vulnerabilities || [];
  }

  public scanProject(projectRoot: string, customDbPath?: string): ScaFinding[] {
    if (customDbPath) {
      this.loadDatabase(customDbPath);
    } else if (this.vulnDb.length === 0) {
      const candidates = [
        path.join(projectRoot, '..', 'vulnerability-database', 'vulnerabilities.json'),
        path.join(projectRoot, 'vulnerability-database', 'vulnerabilities.json'),
        path.join(process.cwd(), 'test-dataset', 'vulnerability-database', 'vulnerabilities.json')
      ];
      for (const c of candidates) {
        if (fs.existsSync(c)) {
          this.loadDatabase(c);
          break;
        }
      }
    }

    const findings: ScaFinding[] = [];

    // Find build files: build.gradle.kts, build.gradle
    const candidateBuildFiles = [
      path.join(projectRoot, 'build.gradle.kts'),
      path.join(projectRoot, 'build.gradle')
    ].filter(p => fs.existsSync(p));

    if (candidateBuildFiles.length === 0) {
      return findings;
    }

    // 1. Read gradle.properties if exists
    const gradleProps = this.loadGradleProperties(projectRoot);

    // 2. Read gradle.lockfile if exists
    const lockfileDeps = this.loadLockfile(projectRoot);

    // 3. Extract dependencies from all build files
    const dependencies: DeclaredDependency[] = [];
    for (const buildFile of candidateBuildFiles) {
      const relPath = path.relative(projectRoot, buildFile).replace(/\\/g, '/');
      const deps = this.extractDependencies(buildFile, relPath, gradleProps, lockfileDeps);
      dependencies.push(...deps);
    }

    // 4. Match against vulnerability database
    for (const dep of dependencies) {
      const matchedVulns = this.checkVulnerability(dep);
      for (const vuln of matchedVulns) {
        // Preferred advisoryId: CVE alias if present, else id (GHSA-...)
        let advisoryId = vuln.id;
        if (!advisoryId.startsWith('CVE-') && vuln.aliases && vuln.aliases.length > 0) {
          const cveAlias = vuln.aliases.find(a => a.startsWith('CVE-'));
          if (cveAlias) {
            advisoryId = cveAlias;
          } else {
            advisoryId = vuln.aliases[0];
          }
        }

        // Select minimum fixedVersion strictly greater than dep.version
        let targetFixedVersion: string | undefined;
        if (vuln.fixedVersions && vuln.fixedVersions.length > 0) {
          const upgradeCandidates = vuln.fixedVersions.filter(
            fv => VersionComparator.compare(fv, dep.version) > 0
          );
          if (upgradeCandidates.length > 0) {
            targetFixedVersion = upgradeCandidates.reduce((minVer, curVer) =>
              VersionComparator.compare(curVer, minVer) < 0 ? curVer : minVer
            );
          } else {
            targetFixedVersion = vuln.fixedVersions[0];
          }
        }

        findings.push({
          category: 'SCA',
          path: dep.filePath,
          group: dep.group,
          artifact: dep.artifact,
          version: dep.version,
          advisoryId: advisoryId,
          severity: vuln.severity || 'HIGH',
          description: `Уязвимая версия библиотеки ${dep.group}:${dep.artifact}:${dep.version} (${advisoryId})`,
          remediation: targetFixedVersion
            ? `Обновить ${dep.group}:${dep.artifact} до версии ${targetFixedVersion} или выше`
            : `Обновить зависимость ${dep.group}:${dep.artifact} до безопасной версии`
        });
      }
    }

    return findings;
  }

  private loadGradleProperties(projectRoot: string): Map<string, string> {
    const props = new Map<string, string>();
    const propPath = path.join(projectRoot, 'gradle.properties');
    if (fs.existsSync(propPath)) {
      const content = fs.readFileSync(propPath, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;
        const [k, ...vParts] = trimmed.split('=');
        props.set(k.trim(), vParts.join('=').trim());
      }
    }
    return props;
  }

  private loadLockfile(projectRoot: string): Map<string, string> {
    const lock = new Map<string, string>();
    const lockPath = path.join(projectRoot, 'gradle.lockfile');
    if (fs.existsSync(lockPath)) {
      const content = fs.readFileSync(lockPath, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || !trimmed.includes('=')) continue;
        const [coords] = trimmed.split('=');
        const parts = coords.trim().split(':');
        if (parts.length >= 3) {
          const group = parts[0];
          const artifact = parts[1];
          const version = parts[2];
          lock.set(`${group}:${artifact}`, version);
        }
      }
    }
    return lock;
  }

  private extractDependencies(
    buildFilePath: string,
    relPath: string,
    gradleProps: Map<string, string>,
    lockfile: Map<string, string>
  ): DeclaredDependency[] {
    const deps: DeclaredDependency[] = [];
    const rawContent = fs.readFileSync(buildFilePath, 'utf-8');
    const cleanContent = stripCommentsPreservingLines(rawContent);
    const lines = cleanContent.split('\n');

    const localVals = new Map<string, string>();

    // Pass 1: collect literal values and Gradle property references.
    for (const line of lines) {
      const valMatch = line.match(/(?:val|var|def)\s+([a-zA-Z0-9_]+)\s*=\s*["']([^"']*)["']/);
      if (valMatch) {
        localVals.set(valMatch[1], valMatch[2]);
      }
      const propGetMatch = line.match(/(?:val|var|def)\s+([a-zA-Z0-9_]+)\s*=\s*providers\.gradleProperty\(["']([^"']+)["']\)\.get\(\)/);
      if (propGetMatch) {
        const varName = propGetMatch[1];
        const propName = propGetMatch[2];
        if (gradleProps.has(propName)) {
          localVals.set(varName, gradleProps.get(propName)!);
        }
      }
    }

    const resolveInterpolations = (raw: string): string => raw.replace(/\$\{?([a-zA-Z_]\w*)\}?/g, (match, name: string) =>
      localVals.get(name) ?? gradleProps.get(name) ?? match
    );
    const findClosing = (text: string, openAt: number, open: string, close: string): number => {
      let depth = 0;
      let quote = '';
      for (let i = openAt; i < text.length; i++) {
        const char = text[i];
        if (quote) {
          if (char === '\\') i++;
          else if (char === quote) quote = '';
          continue;
        }
        if (char === '"' || char === "'") {
          quote = char;
        } else if (char === open) {
          depth++;
        } else if (char === close && --depth === 0) {
          return i;
        }
      }
      return -1;
    };
    const resolveCoordinate = (raw: string): string => {
      const trimmed = raw.trim().replace(/^["']|["']$/g, '');
      return resolveInterpolations(localVals.get(trimmed) ?? trimmed);
    };
    const readVersionConstraint = (suffix: string): string => {
      const trimmedSuffix = suffix.trimStart();
      if (!trimmedSuffix.startsWith('{')) return '';
      const closeAt = findClosing(trimmedSuffix, 0, '{', '}');
      if (closeAt < 0) return '';
      const constraint = trimmedSuffix.slice(1, closeAt).match(/\b(?:strictly|require)\s*\(\s*(["'][^"']+["']|[a-zA-Z_]\w*)\s*\)/);
      return constraint ? resolveCoordinate(constraint[1]) : '';
    };

    // Parse complete balanced calls so named arguments and declarations may span lines.
    const callPattern = /\b(implementation|api|runtimeOnly|compileOnly|add)\s*\(/g;
    for (const call of cleanContent.matchAll(callPattern)) {
      const callName = call[1];
      const openAt = call.index! + call[0].lastIndexOf('(');
      const closeAt = findClosing(cleanContent, openAt, '(', ')');
      if (closeAt < 0) continue;

      const args = cleanContent.slice(openAt + 1, closeAt);
      if (callName === 'add' && !/["'](?:implementation|api|runtimeOnly|compileOnly)["']/.test(args)) continue;
      const linePrefix = cleanContent.slice(0, call.index!);
      const lineNum = linePrefix.split('\n').length;
      const rawLine = cleanContent.slice(call.index!, closeAt + 1).replace(/\s+/g, ' ').trim();

      let group = '';
      let artifact = '';
      let version = '';
      const namedGroup = args.match(/\bgroup\s*=\s*(["'][^"']+["']|[a-zA-Z_]\w*)/);
      const namedArtifact = args.match(/\bname\s*=\s*(["'][^"']+["']|[a-zA-Z_]\w*)/);
      const namedVersion = args.match(/\bversion\s*=\s*(["'][^"']+["']|[a-zA-Z_]\w*)/);

      if (namedGroup && namedArtifact) {
        group = resolveCoordinate(namedGroup[1]);
        artifact = resolveCoordinate(namedArtifact[1]);
        version = namedVersion ? resolveCoordinate(namedVersion[1]) : '';
      } else {
        const coordinateLiteral = Array.from(args.matchAll(/["']([^"']+)["']/g))
          .map(match => match[1])
          .find(value => value.includes(':') && !/^(?:implementation|api|runtimeOnly|compileOnly)$/.test(value));
        const coordinateVariable = args.trim().match(/^([a-zA-Z_]\w*)\s*,?$/);
        const coordinate = coordinateLiteral
          ? resolveInterpolations(coordinateLiteral)
          : coordinateVariable
            ? resolveCoordinate(coordinateVariable[1])
            : '';
        const parts = coordinate.split(':');
        if (parts.length >= 2) {
          group = parts[0];
          artifact = parts[1];
          version = parts.slice(2).join(':');
        }
      }

      if (!group || !artifact) continue;

      const suffix = cleanContent.slice(closeAt + 1, Math.min(cleanContent.length, closeAt + 500));
      const constrainedVersion = readVersionConstraint(suffix);
      version = constrainedVersion || version;
      version = this.resolveVersion(version, localVals, gradleProps, lockfile, group, artifact);
      deps.push({ group, artifact, version, rawLine, lineNum, filePath: relPath });
    }

    return deps;
  }

  private resolveVersion(
    versionRaw: string,
    localVals: Map<string, string>,
    gradleProps: Map<string, string>,
    lockfile: Map<string, string>,
    group: string,
    artifact: string
  ): string {
    let version = versionRaw.trim();

    // Variable interpolation: $archiveFormatVersion or ${archiveFormatVersion}
    if (version.startsWith('$')) {
      const varName = version.substring(1).replace(/[{}]/g, '');
      if (localVals.has(varName)) {
        return localVals.get(varName)!;
      }
      if (gradleProps.has(varName)) {
        return gradleProps.get(varName)!;
      }
    }

    // Lockfile fallback if version is empty or still variable
    const lockKey = `${group}:${artifact}`;
    if (lockfile.has(lockKey) && (!version || version.includes('$'))) {
      return lockfile.get(lockKey)!;
    }

    return version;
  }

  private checkVulnerability(dep: DeclaredDependency): VulnerabilityRecord[] {
    const matched: VulnerabilityRecord[] = [];

    for (const vuln of this.vulnDb) {
      if (vuln.group === dep.group && vuln.artifact === dep.artifact) {
        let isVulnerable = false;

        for (const range of vuln.ranges) {
          if (
            VersionComparator.isInRange(
              dep.version,
              range.lower,
              range.lowerInclusive,
              range.upper,
              range.upperInclusive
            )
          ) {
            isVulnerable = true;
            break;
          }
        }

        if (isVulnerable) {
          matched.push(vuln);
        }
      }
    }

    return matched;
  }
}
