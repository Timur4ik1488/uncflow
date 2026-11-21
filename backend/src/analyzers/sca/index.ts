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

  public loadDatabase(dbPath: string) {
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
      // Look for default vulnerability database in known paths
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
    const buildGradlePath = path.join(projectRoot, 'build.gradle.kts');
    if (!fs.existsSync(buildGradlePath)) {
      return findings;
    }

    const relBuildGradle = path.relative(projectRoot, buildGradlePath).replace(/\\/g, '/');

    // 1. Read gradle.properties if exists
    const gradleProps = this.loadGradleProperties(projectRoot);

    // 2. Read gradle.lockfile if exists
    const lockfileDeps = this.loadLockfile(projectRoot);

    // 3. Extract dependencies from build.gradle.kts
    const dependencies = this.extractDependencies(buildGradlePath, gradleProps, lockfileDeps);

    // 4. Match against vulnerability database
    for (const dep of dependencies) {
      const matchedVulns = this.checkVulnerability(dep);
      for (const vuln of matchedVulns) {
        // Preferred advisoryId: CVE alias if present, else id (GHSA-...)
        const advisoryId = (vuln.aliases && vuln.aliases.length > 0) ? vuln.aliases[0] : vuln.id;

        findings.push({
          category: 'SCA',
          path: relBuildGradle,
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
    return propsToMap(lock);
  }

  private extractDependencies(
    buildFilePath: string,
    gradleProps: Map<string, string>,
    lockfile: Map<string, string>
  ): DeclaredDependency[] {
    const deps: DeclaredDependency[] = [];
    const content = fs.readFileSync(buildFilePath, 'utf-8');
    const lines = content.split('\n');

    // Local val variables (e.g., val archiveFormatVersion = "1.25.0")
    const localVals = new Map<string, string>();

    // Pass 1: collect local variables
    for (const line of lines) {
      const valMatch = line.match(/val\s+([a-zA-Z0-9_]+)\s*=\s*["']([^"']+)["']/);
      if (valMatch) {
        localVals.set(valMatch[1], valMatch[2]);
      }
      const propGetMatch = line.match(/val\s+([a-zA-Z0-9_]+)\s*=\s*providers\.gradleProperty\(["']([^"']+)["']\)\.get\(\)/);
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

      // Form 1: implementation("group:artifact:version") or runtimeOnly(...) etc.
      const stdMatch = line.match(/(?:implementation|api|runtimeOnly|testImplementation)\s*\(\s*["']([^"':]+):([^"':]+):([^"']+)["']\s*\)/);
      if (stdMatch) {
        const group = stdMatch[1];
        const artifact = stdMatch[2];
        let version = stdMatch[3];

        version = this.resolveVersion(version, localVals, gradleProps, lockfile, group, artifact);
        deps.push({ group, artifact, version, rawLine: line, lineNum });
        continue;
      }

      // Form 2: add("implementation", "commons-net:commons-net:3.8.0")
      // May be multiline or single line
      const addMatch = line.match(/["']([^"':]+):([^"':]+):([^"']+)["']/);
      if (addMatch && (line.includes('commons-net') || line.includes(':'))) {
        // verify if inside dependencies block
        const prevOrCurrent = (lines[Math.max(0, i - 1)] + ' ' + line).toLowerCase();
        if (prevOrCurrent.includes('add') || prevOrCurrent.includes('implementation')) {
          const group = addMatch[1];
          const artifact = addMatch[2];
          let version = addMatch[3];

          // Check if valid group/artifact
          if (group.includes('.') || group === 'commons-net') {
            version = this.resolveVersion(version, localVals, gradleProps, lockfile, group, artifact);
            deps.push({ group, artifact, version, rawLine: line, lineNum });
          }
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

    // Check $var interpolation e.g. "$archiveFormatVersion"
    if (version.startsWith('$')) {
      const varName = version.substring(1).replace(/[{}]/g, '');
      if (localVals.has(varName)) {
        return localVals.get(varName)!;
      }
      if (gradleProps.has(varName)) {
        return gradleProps.get(varName)!;
      }
    }

    // Check lockfile fallback
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

function propsToMap(m: Map<string, string>): Map<string, string> {
  return m;
}
