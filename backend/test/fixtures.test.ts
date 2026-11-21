import * as path from 'path';
import { SecretAnalyzer } from '../src/analyzers/secrets/index.ts';
import { SastAnalyzer } from '../src/analyzers/sast/index.ts';

function runFixtureTests() {
  console.log('===============================================================');
  console.log('  TESTING SYNTHETIC FIXTURES (10 VULNERABILITY CLASSES + SAFE)');
  console.log('===============================================================\n');

  const rootDir = process.cwd();
  const vulnerableDir = path.join(rootDir, 'backend', 'test', 'fixtures', 'vulnerable');
  const safeDir = path.join(rootDir, 'backend', 'test', 'fixtures', 'safe');

  // 1. Run analyzers on vulnerable fixtures
  const secretAnalyzer = new SecretAnalyzer({ ignorePaths: [] });
  const sastAnalyzer = new SastAnalyzer();

  const secretFindings = secretAnalyzer.scanProject(vulnerableDir);
  const sastFindings = sastAnalyzer.scanProject(vulnerableDir);

  const expectedSecretClasses = [
    'password',
    'api-key',
    'configuration-token',
    'secret-fallback',
    'recoverable-token'
  ];

  const expectedSastClasses = [
    'sql-injection',
    'tls-verification',
    'credentialed-cors',
    'route-authorization',
    'object-authorization'
  ];

  console.log('1. Checking Vulnerable Fixtures Detection (Recall):');
  let detectedCount = 0;

  for (const cls of expectedSecretClasses) {
    const found = secretFindings.some(f => f.class === cls);
    if (found) {
      detectedCount++;
      console.log(`  ✅ [SECRET] ${cls} detected`);
    } else {
      console.error(`  ❌ [SECRET] ${cls} MISSED!`);
    }
  }

  for (const cls of expectedSastClasses) {
    const found = sastFindings.some(f => f.class === cls);
    if (found) {
      detectedCount++;
      console.log(`  ✅ [SAST] ${cls} detected`);
    } else {
      console.error(`  ❌ [SAST] ${cls} MISSED!`);
    }
  }

  if (detectedCount !== 10) {
    throw new Error(`Expected 10/10 classes detected, got ${detectedCount}`);
  }

  // 2. Run analyzers on safe fixtures (Anti-FP check)
  console.log('\n2. Checking Safe Fixtures (Precision / Zero FP):');
  const safeSecretFindings = secretAnalyzer.scanProject(safeDir);
  const safeSastFindings = sastAnalyzer.scanProject(safeDir);

  if (safeSecretFindings.length > 0) {
    console.error('  ❌ False positive secrets detected in safe fixtures:', safeSecretFindings);
    throw new Error(`Expected 0 secret findings in safe fixtures, got ${safeSecretFindings.length}`);
  } else {
    console.log('  ✅ [SECRET] 0 false positives in safe fixtures');
  }

  if (safeSastFindings.length > 0) {
    console.error('  ❌ False positive SAST detected in safe fixtures:', safeSastFindings);
    throw new Error(`Expected 0 SAST findings in safe fixtures, got ${safeSastFindings.length}`);
  } else {
    console.log('  ✅ [SAST] 0 false positives in safe fixtures');
  }

  console.log('\n🎉 All fixture tests passed: 100% Recall, 0% False Positives!\n');
}

runFixtureTests();
