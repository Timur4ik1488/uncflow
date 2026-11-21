import * as fs from 'fs';
import * as path from 'path';
import type { ScaFinding } from '../../types/findings.ts';
import { VersionComparator } from './version-comparator.ts';

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

        findings.push({
          category: 'SCA',
          path: dep.filePath,
          group: dep.group,
          artifact: dep.artifact,
          version: dep.version,
          advisoryId: advisoryId,
          severity: vuln.severity || 'HIGH',
          description: `Уязвимая версия библиотеки ${dep.group}:${dep.artifact}:${dep.version} (${advisoryId})`,
          remediation: vuln.fixedVersions && vuln.fixedVersions.length > 0
            ? `Обновить ${dep.group}:${dep.artifact} до версии ${vuln.fixedVersions[0]} или выше`
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
    const content = fs.readFileSync(buildFilePath, 'utf-8');
    const lines = content.split('\n');

    const localVals = new Map<string, string>();

    // Pass 1: collect local variables (val archiveVersion = "1.0", def myVer = "...")
    for (const line of lines) {
      const valMatch = line.match(/(?:val|var|def)\s+([a-zA-Z0-9_]+)\s*=\s*["']([^"']+)["']/);
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

    // Pass 2: find dependency declarations
    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      const trimmed = line.trim();

      // Skip test configurations to avoid test dependencies FP
      if (
        trimmed.startsWith('testImplementation') ||
        trimmed.startsWith('testCompileOnly') ||
        trimmed.startsWith('testRuntimeOnly')
      ) {
        continue;
      }

      // Check standard configurations: implementation, api, runtimeOnly, compileOnly, etc.
      // 1. Direct coordinate string: implementation("group:artifact:version") or implementation "group:artifact:version"
      const stdMatch = line.match(/(?:implementation|api|runtimeOnly|compileOnly)\s*\(?\s*["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"']+)["']\s*\)?/);
      if (stdMatch) {
        const group = stdMatch[1];
        const artifact = stdMatch[2];
        let version = stdMatch[3];
        version = this.resolveVersion(version, localVals, gradleProps, lockfile, group, artifact);
        deps.push({ group, artifact, version, rawLine: line, lineNum, filePath: relPath });
        continue;
      }

      // 2. Named parameters: implementation(group = "...", name = "...", version = "...")
      const mapMatch = line.match(/group\s*=\s*["']([A-Za-z0-9_.-]+)["']\s*,\s*name\s*=\s*["']([A-Za-z0-9_.-]+)["'](?:\s*,\s*version\s*=\s*["']([^"']+)["'])?/);
      if (mapMatch) {
        const group = mapMatch[1];
        const artifact = mapMatch[2];
        let version = mapMatch[3] || '';
        version = this.resolveVersion(version, localVals, gradleProps, lockfile, group, artifact);
        deps.push({ group, artifact, version, rawLine: line, lineNum, filePath: relPath });
        continue;
      }

      // 3. Multi-line or add syntax: add("implementation", "group:artifact:version")
      const coordMatch = line.match(/["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^"']+)["']/);
      if (coordMatch) {
        const prevOrCurrent = (lines[Math.max(0, i - 1)] + ' ' + line).toLowerCase();
        if (
          prevOrCurrent.includes('add') ||
          prevOrCurrent.includes('implementation') ||
          prevOrCurrent.includes('api') ||
          prevOrCurrent.includes('runtimeonly')
        ) {
          const group = coordMatch[1];
          const artifact = coordMatch[2];
          let version = coordMatch[3];
          version = this.resolveVersion(version, localVals, gradleProps, lockfile, group, artifact);
          deps.push({ group, artifact, version, rawLine: line, lineNum, filePath: relPath });
        }
      }
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
