import assert from 'node:assert';
import { exportToSarif } from '../src/exporters/sarif.ts';
import type { Finding } from '../src/types/findings.ts';

console.log('--- Testing SARIF Exporter (OASIS SARIF v2.1.0) ---');

const mockFindings: Finding[] = [
  {
    category: 'SECRET',
    path: 'src/main/resources/application.properties',
    line: 12,
    endLine: 12,
    severity: 'CRITICAL',
    description: 'Hardcoded password detected',
    remediation: 'Use environment variables',
    class: 'password'
  } as any,
  {
    category: 'SAST',
    path: 'src/main/kotlin/com/bank/service/PaymentService.kt',
    line: 45,
    endLine: 48,
    severity: 'HIGH',
    description: 'Potential SQL Injection via string concatenation in executeQuery',
    remediation: 'Use parameterized queries',
    class: 'sql-injection'
  } as any,
  {
    category: 'SCA',
    path: 'build.gradle.kts',
    severity: 'CRITICAL',
    description: 'Apache Commons Text RCE vulnerability',
    remediation: 'Upgrade to 1.10.0+',
    advisoryId: 'CVE-2022-42889',
    artifact: 'org.apache.commons:commons-text'
  } as any
];

const sarif = exportToSarif(mockFindings);

// 1. Schema and Version
assert.strictEqual(sarif.version, '2.1.0', 'SARIF version must be 2.1.0');
assert.ok(sarif.$schema.includes('sarif-schema-2.1.0.json'), 'SARIF must reference 2.1.0 schema');
assert.ok(Array.isArray(sarif.runs) && sarif.runs.length === 1, 'SARIF runs array must have 1 run');

const run = sarif.runs[0];
assert.strictEqual(run.tool.driver.name, 'uncflow', 'Driver name must be uncflow');
assert.ok(Array.isArray(run.tool.driver.rules), 'Driver rules must be an array');
assert.strictEqual(run.tool.driver.rules.length, 3, 'Must register 3 unique rules');

// 2. Results format
assert.strictEqual(run.results.length, 3, 'Must produce 3 results');

const res0 = run.results[0];
assert.strictEqual(res0.ruleId, 'password');
assert.strictEqual(res0.level, 'error');
assert.strictEqual(res0.locations[0].physicalLocation.artifactLocation.uri, 'src/main/resources/application.properties');
assert.strictEqual(res0.locations[0].physicalLocation.region.startLine, 12);

const res1 = run.results[1];
assert.strictEqual(res1.ruleId, 'sql-injection');
assert.strictEqual(res1.level, 'error');
assert.strictEqual(res1.locations[0].physicalLocation.region.startLine, 45);
assert.strictEqual(res1.locations[0].physicalLocation.region.endLine, 48);

const res2 = run.results[2];
assert.strictEqual(res2.ruleId, 'CVE-2022-42889');
assert.strictEqual(res2.level, 'error');

console.log('✅ SARIF Exporter tests passed successfully (4/4 assertions)!');
