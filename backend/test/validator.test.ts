import assert from 'assert';
import {
  validateSubmissionReport,
  normalizeFindingRange,
  sanitizeFindingForExport,
  maskSensitiveText
} from '../src/validators/submission-validator.ts';

console.log('===============================================================');
console.log('🧪 RUNNING SUBMISSION VALIDATOR TESTS (STAGE 2)');
console.log('===============================================================');

// Test 1: Empty report is valid
{
  const emptyReport = { findings: [] };
  const res = validateSubmissionReport(emptyReport);
  assert.strictEqual(res.valid, true, 'Empty report should be valid');
  assert.strictEqual(res.errors.length, 0);
  console.log('  ✅ [PASS] Empty findings report is valid');
}

// Test 2: Valid report with SECRET, SAST, SCA
{
  const validReport = {
    findings: [
      {
        category: 'SECRET',
        path: 'src/main/resources/application.yml',
        class: 'configuration-token',
        line: 10,
        endLine: 12,
        severity: 'HIGH',
        description: 'Hardcoded Bearer token',
        remediation: 'Use environment variable'
      },
      {
        category: 'SAST',
        path: 'src/main/kotlin/app/Controller.kt',
        class: 'sql-injection',
        line: 25,
        severity: 'CRITICAL',
        description: 'SQL injection via interpolation'
      },
      {
        category: 'SCA',
        path: 'build.gradle.kts',
        group: 'org.apache.commons',
        artifact: 'commons-text',
        version: '1.9',
        advisoryId: 'CVE-2022-42889',
        severity: 'CRITICAL'
      }
    ]
  };
  const res = validateSubmissionReport(validReport);
  assert.strictEqual(res.valid, true, `Report should be valid: ${res.errors.join(', ')}`);
  console.log('  ✅ [PASS] Valid mixed report conforms to contract');
}

// Test 3: Rejection of absolute paths and traversal
{
  const badPaths = {
    findings: [
      { category: 'SECRET', path: '/etc/passwd', class: 'password', line: 1 },
      { category: 'SAST', path: '../secret.kt', class: 'sql-injection', line: 5 },
      { category: 'SAST', path: 'C:\\projects\\app.kt', class: 'sql-injection', line: 1 }
    ]
  };
  const res = validateSubmissionReport(badPaths);
  assert.strictEqual(res.valid, false, 'Absolute/traversal paths must be invalid');
  assert.strictEqual(res.errors.length, 3);
  console.log('  ✅ [PASS] Absolute and traversal paths rejected');
}

// Test 4: SCA must NOT contain class, line, or endLine
{
  const badSca = {
    findings: [
      {
        category: 'SCA',
        path: 'build.gradle.kts',
        class: 'vulnerable-dependency', // FORBIDDEN FOR SCA
        line: 15, // FORBIDDEN FOR SCA
        group: 'org.example',
        artifact: 'lib',
        version: '1.0',
        advisoryId: 'CVE-2023-1234'
      }
    ]
  };
  const res = validateSubmissionReport(badSca);
  assert.strictEqual(res.valid, false, 'SCA with class and line must be invalid');
  assert.ok(res.errors.some(e => e.includes('ЗАПРЕЩЕНО для SCA')));
  console.log('  ✅ [PASS] SCA with class/line/endLine strictly rejected');
}

// Test 5: EndLine constraints (line <= endLine <= line + 14)
{
  const badRange1 = {
    findings: [{ category: 'SECRET', path: 'test.kt', class: 'password', line: 20, endLine: 10 }]
  };
  assert.strictEqual(validateSubmissionReport(badRange1).valid, false);

  const badRange2 = {
    findings: [{ category: 'SECRET', path: 'test.kt', class: 'password', line: 10, endLine: 35 }] // > 14 lines span
  };
  assert.strictEqual(validateSubmissionReport(badRange2).valid, false);
  console.log('  ✅ [PASS] Invalid endLine ranges (< line or > line + 14) rejected');
}

// Test 6: normalizeFindingRange guarantees
{
  const norm1 = normalizeFindingRange({ line: 10, endLine: 5 });
  assert.strictEqual(norm1.line, 10);
  assert.strictEqual(norm1.endLine, undefined);

  const norm2 = normalizeFindingRange({ line: 10, endLine: 35 });
  assert.strictEqual(norm2.line, 10);
  assert.strictEqual(norm2.endLine, 24); // max line + 14

  const fakeFile = ['', '', 'val x = 1', 'val y = 2', '', ''];
  const norm3 = normalizeFindingRange({ line: 1, endLine: 6 }, fakeFile);
  assert.strictEqual(norm3.line, 3); // trimmed leading blanks
  assert.strictEqual(norm3.endLine, 4); // trimmed trailing blanks
  console.log('  ✅ [PASS] normalizeFindingRange trims blanks and caps at line + 14');
}

// Test 7: sanitizeFindingForExport strips internal fields and forbidden fields
{
  const rawSca = {
    category: 'SCA',
    path: 'build.gradle.kts',
    class: 'dependency',
    line: 5,
    endLine: 10,
    group: 'org.apache',
    artifact: 'commons',
    version: '1.0',
    advisoryId: 'CVE-2024-9999',
    rawSecret: 'secret_leak',
    internalScore: 99
  };
  const sanitized = sanitizeFindingForExport(rawSca);
  assert.strictEqual(sanitized.class, undefined);
  assert.strictEqual(sanitized.line, undefined);
  assert.strictEqual(sanitized.endLine, undefined);
  assert.strictEqual(sanitized.rawSecret, undefined);
  assert.strictEqual(sanitized.group, 'org.apache');
  console.log('  ✅ [PASS] sanitizeFindingForExport produces clean compliant objects');
}

// Test 8: maskSensitiveText
{
  const text = 'Bearer cg26_pickup_Gq7mP8vJdW3sY6zN and token 0123456789abcdef0123456789abcdef';
  const masked = maskSensitiveText(text);
  assert.ok(!masked.includes('Gq7mP8vJdW3sY6zN'));
  assert.ok(masked.includes('***'));
  console.log('  ✅ [PASS] maskSensitiveText eliminates raw tokens');
}

console.log('\n🎉 ALL 8 VALIDATOR TESTS PASSED!\n');
