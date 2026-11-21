import * as fs from 'fs';
import * as path from 'path';
import { SecretAnalyzer } from '../src/analyzers/secrets/index.ts';
import { ScaAnalyzer } from '../src/analyzers/sca/index.ts';
import { SastAnalyzer } from '../src/analyzers/sast/index.ts';
import type { Finding, SecretFinding, SastFinding, ScaFinding } from '../src/types/findings.ts';

interface GroundTruthFinding {
  id: string;
  category: 'SECRET' | 'SAST' | 'SCA';
  class: string;
  path: string;
  line: number;
  endLine?: number;
  group?: string;
  artifact?: string;
  version?: string;
  advisoryIds?: string[];
  difficulty: string;
  description: string;
}

interface GroundTruthControl {
  id: string;
  category: string;
  path: string;
  line?: number;
  endLine?: number;
  group?: string;
  artifact?: string;
  reason: string;
}

interface GroundTruthFile {
  dataset: string;
  findings: GroundTruthFinding[];
  controls: GroundTruthControl[];
}

function runVerification() {
  console.log('===============================================================');
  console.log('  CYBER GARDEN 2026: VERIFYING CUSTOM ANALYZERS ACCURACY');
  console.log('===============================================================\n');

  const rootDir = process.cwd();
  const testDatasetDir = path.join(rootDir, 'test-dataset');
  const projectRoot = path.join(testDatasetDir, 'training-project');
  const groundTruthPath = path.join(testDatasetDir, 'ground-truth', 'training-findings.json');
  const vulnDbPath = path.join(testDatasetDir, 'vulnerability-database', 'vulnerabilities.json');

  if (!fs.existsSync(groundTruthPath)) {
    console.error(`Ground truth file not found at ${groundTruthPath}`);
    process.exit(1);
  }

  const groundTruth: GroundTruthFile = JSON.parse(fs.readFileSync(groundTruthPath, 'utf-8'));

  // 1. Run Analyzers
  console.log('🔍 Running SecretAnalyzer...');
  const secretAnalyzer = new SecretAnalyzer();
  const secretFindings = secretAnalyzer.scanProject(projectRoot);
  console.log(`   Found ${secretFindings.length} secret candidates.\n`);

  console.log('🔍 Running ScaAnalyzer...');
  const scaAnalyzer = new ScaAnalyzer(vulnDbPath);
  const scaFindings = scaAnalyzer.scanProject(projectRoot);
  console.log(`   Found ${scaFindings.length} SCA dependency vulnerabilities.\n`);

  console.log('🔍 Running SastAnalyzer...');
  const sastAnalyzer = new SastAnalyzer();
  const sastFindings = sastAnalyzer.scanProject(projectRoot);
  console.log(`   Found ${sastFindings.length} SAST code vulnerabilities.\n`);

  const allDetectedFindings: Finding[] = [
    ...secretFindings,
    ...scaFindings,
    ...sastFindings
  ];

  // 2. Check Match with Expected Findings
  console.log('---------------------------------------------------------------');
  console.log('  CHECKING 15 EXPECTED GROUND-TRUTH FINDINGS');
  console.log('---------------------------------------------------------------');

  let passedExpected = 0;
  for (const expected of groundTruth.findings) {
    let matched = false;

    if (expected.category === 'SECRET') {
      matched = secretFindings.some(f => 
        f.category === 'SECRET' &&
        f.path.includes(path.basename(expected.path)) &&
        f.class === expected.class
      );
    } else if (expected.category === 'SCA') {
      matched = scaFindings.some(f => 
        f.category === 'SCA' &&
        f.group === expected.group &&
        f.artifact === expected.artifact &&
        (expected.advisoryIds ? expected.advisoryIds.includes(f.advisoryId) : true)
      );
    } else if (expected.category === 'SAST') {
      matched = sastFindings.some(f => 
        f.category === 'SAST' &&
        f.path.includes(path.basename(expected.path)) &&
        f.class === expected.class
      );
    }

    if (matched) {
      passedExpected++;
      console.log(`  ✅ [${expected.id}] [${expected.category}] [${expected.difficulty}] ${expected.class || expected.artifact} -> DETECTED`);
    } else {
      console.log(`  ❌ [${expected.id}] [${expected.category}] [${expected.difficulty}] ${expected.class || expected.artifact} -> MISSED`);
    }
  }

  // 3. Check False Positives on Controls
  console.log('\n---------------------------------------------------------------');
  console.log('  CHECKING 6 CONTROLS (FALSE POSITIVE CHECKS)');
  console.log('---------------------------------------------------------------');

  let passedControls = 0;
  for (const ctrl of groundTruth.controls) {
    let falseAlarm = false;

    if (ctrl.category === 'SECRET') {
      falseAlarm = secretFindings.some(f => 
        f.path.includes(path.basename(ctrl.path)) && (ctrl.line ? f.line === ctrl.line : false)
      );
    } else if (ctrl.category === 'SCA') {
      falseAlarm = scaFindings.some(f => 
        f.group === ctrl.group && f.artifact === ctrl.artifact
      );
    } else if (ctrl.category === 'SAST') {
      falseAlarm = sastFindings.some(f => 
        f.path.includes(path.basename(ctrl.path)) && (ctrl.line ? f.line === ctrl.line : false)
      );
    }

    if (!falseAlarm) {
      passedControls++;
      console.log(`  ✅ [${ctrl.id}] [${ctrl.category}] Correctly IGNORED (no false positive)`);
    } else {
      console.log(`  ❌ [${ctrl.id}] [${ctrl.category}] FALSE POSITIVE detected on control!`);
    }
  }

  console.log('\n===============================================================');
  console.log(`  RESULTS: Expected: ${passedExpected}/${groundTruth.findings.length} | Controls: ${passedControls}/${groundTruth.controls.length}`);
  console.log('===============================================================\n');

  if (passedExpected === groundTruth.findings.length && passedControls === groundTruth.controls.length) {
    console.log('🎉 100% PERFECT SCORE! All vulnerabilities detected with 0 false positives!\n');
  } else {
    console.log('⚠️ Some checks failed. Review rules.\n');
    process.exit(1);
  }
}

runVerification();
