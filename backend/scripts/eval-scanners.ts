import * as fs from 'fs';
import * as path from 'path';
import { SecretAnalyzer } from '../src/analyzers/secrets/index.ts';
import { ScaAnalyzer } from '../src/analyzers/sca/index.ts';
import { SastAnalyzer } from '../src/analyzers/sast/index.ts';
import type { Finding } from '../src/types/findings.ts';
import { sanitizeFindingForExport } from '../src/validators/submission-validator.ts';

interface CliArgs {
  target: string;
  groundTruth?: string;
  vulnDb?: string;
  format: 'text' | 'json';
}

function parseArgs(): CliArgs {
  const args = process.argv.slice(2);
  let target = '';
  let groundTruth: string | undefined;
  let vulnDb: string | undefined;
  let format: 'text' | 'json' = 'text';

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--target' && i + 1 < args.length) {
      target = args[++i];
    } else if (a === '--ground-truth' && i + 1 < args.length) {
      groundTruth = args[++i];
    } else if (a === '--vuln-db' && i + 1 < args.length) {
      vulnDb = args[++i];
    } else if (a === '--format' && i + 1 < args.length) {
      format = args[++i] === 'json' ? 'json' : 'text';
    }
  }

  const rootDir = fs.existsSync(path.join(process.cwd(), 'test-dataset'))
    ? process.cwd()
    : path.resolve(process.cwd(), '..');

  if (!target) {
    const defaultTarget = path.join(rootDir, 'test-dataset', 'training-project');
    if (fs.existsSync(defaultTarget)) {
      target = defaultTarget;
    } else {
      console.error('Error: --target <path> argument is required');
      process.exit(1);
    }
  }

  if (!groundTruth) {
    const defaultGt = path.join(rootDir, 'test-dataset', 'ground-truth', 'training-findings.json');
    if (fs.existsSync(defaultGt)) {
      groundTruth = defaultGt;
    }
  }

  if (!vulnDb) {
    const defaultDb = path.join(rootDir, 'test-dataset', 'vulnerability-database', 'vulnerabilities.json');
    if (fs.existsSync(defaultDb)) {
      vulnDb = defaultDb;
    }
  }

  return { target, groundTruth, vulnDb, format };
}

function runEval() {
  const { target, groundTruth, vulnDb, format } = parseArgs();

  const targetPath = path.resolve(process.cwd(), target);
  if (!fs.existsSync(targetPath)) {
    console.error(`Error: Target directory does not exist: ${targetPath}`);
    process.exit(1);
  }

  // 1. Run scanners
  const secretAnalyzer = new SecretAnalyzer();
  const secretFindings = secretAnalyzer.scanProject(targetPath);

  const scaAnalyzer = new ScaAnalyzer(vulnDb);
  const scaFindings = scaAnalyzer.scanProject(targetPath);

  const sastAnalyzer = new SastAnalyzer();
  const sastFindings = sastAnalyzer.scanProject(targetPath);

  const allFindings: Finding[] = [
    ...secretFindings,
    ...scaFindings,
    ...sastFindings
  ];

  // 2. Mode without ground truth: output findings
  if (!groundTruth) {
    if (format === 'json') {
      const sanitized = allFindings.map(sanitizeFindingForExport);
      console.log(JSON.stringify(sanitized, null, 2));
    } else {
      console.log('===============================================================');
      console.log(`  SECURITY SCAN RESULTS FOR: ${target}`);
      console.log('===============================================================\n');
      console.log(`Total Findings: ${allFindings.length}`);
      console.log(`- SECRET: ${secretFindings.length}`);
      console.log(`- SCA:    ${scaFindings.length}`);
      console.log(`- SAST:   ${sastFindings.length}\n`);

      for (const f of allFindings) {
        console.log(`[${f.category}] [${(f as any).class || (f as any).advisoryId || 'vuln'}] ${f.path}${f.line ? `:${f.line}` : ''}`);
        console.log(`   ${f.description}`);
      }
    }
    process.exit(0);
  }

  // 3. Mode with ground truth: evaluate metrics
  const gtPath = path.resolve(process.cwd(), groundTruth);
  if (!fs.existsSync(gtPath)) {
    console.error(`Error: Ground truth file not found: ${gtPath}`);
    process.exit(1);
  }

  const gtData = JSON.parse(fs.readFileSync(gtPath, 'utf-8'));
  const expectedFindings: any[] = gtData.findings || [];
  const controls: any[] = gtData.controls || [];

  let tp = 0;
  let fn = 0;
  let fp = 0;

  const missedList: any[] = [];
  const fpList: any[] = [];

  // Check True Positives / False Negatives against Ground Truth findings
  for (const exp of expectedFindings) {
    let matched = false;
    if (exp.category === 'SECRET') {
      matched = secretFindings.some(f =>
        f.category === 'SECRET' &&
        f.path.includes(path.basename(exp.path)) &&
        f.class === exp.class
      );
    } else if (exp.category === 'SCA') {
      matched = scaFindings.some(f =>
        f.category === 'SCA' &&
        f.group === exp.group &&
        f.artifact === exp.artifact &&
        (!exp.advisoryIds || exp.advisoryIds.includes(f.advisoryId))
      );
    } else if (exp.category === 'SAST') {
      matched = sastFindings.some(f =>
        f.category === 'SAST' &&
        f.path.includes(path.basename(exp.path)) &&
        f.class === exp.class
      );
    }

    if (matched) {
      tp++;
    } else {
      fn++;
      missedList.push(exp);
    }
  }

  // Check False Positives against Control rules
  for (const ctrl of controls) {
    let matched = false;
    if (ctrl.category === 'SECRET') {
      matched = secretFindings.some(f =>
        f.path.includes(path.basename(ctrl.path)) &&
        (ctrl.line ? f.line === ctrl.line : false)
      );
    } else if (ctrl.category === 'SCA') {
      matched = scaFindings.some(f =>
        f.group === ctrl.group && f.artifact === ctrl.artifact
      );
    } else if (ctrl.category === 'SAST') {
      matched = sastFindings.some(f =>
        f.path.includes(path.basename(ctrl.path)) &&
        (ctrl.line ? f.line === ctrl.line : false)
      );
    }

    if (matched) {
      fp++;
      fpList.push(ctrl);
    }
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0.0;

  if (format === 'json') {
    console.log(JSON.stringify({
      metrics: {
        precision,
        recall,
        f1,
        tp,
        fp,
        fn
      },
      missed: missedList,
      falsePositives: fpList
    }, null, 2));
  } else {
    console.log('===============================================================');
    console.log('  EVALUATION RESULTS (BENCHMARK METRICS)');
    console.log('===============================================================\n');
    console.log(`Target:       ${target}`);
    console.log(`Ground Truth: ${groundTruth}\n`);
    console.log('---------------------------------------------------------------');
    console.log(`  TP (True Positives):  ${tp} / ${expectedFindings.length}`);
    console.log(`  FP (False Positives): ${fp} / ${controls.length} controls`);
    console.log(`  FN (False Negatives): ${fn}`);
    console.log('---------------------------------------------------------------');
    console.log(`  Precision:  ${(precision * 100).toFixed(1)}%`);
    console.log(`  Recall:     ${(recall * 100).toFixed(1)}%`);
    console.log(`  F1-Score:   ${(f1 * 100).toFixed(1)}%`);
    console.log('---------------------------------------------------------------\n');

    if (missedList.length > 0) {
      console.log('❌ MISSED FINDINGS:');
      for (const m of missedList) {
        console.log(`   - [${m.category}] [${m.class || m.artifact}] in ${m.path}`);
      }
      console.log('');
    }

    if (fpList.length > 0) {
      console.log('❌ FALSE POSITIVES ON CONTROLS:');
      for (const f of fpList) {
        console.log(`   - [${f.category}] in ${f.path}`);
      }
      console.log('');
    }

    if (recall === 1.0 && fp === 0) {
      console.log('🎉 PERFECT EVALUATION SCORE: 100% Precision, 100% Recall, 100% F1!\n');
    }
  }

  process.exit(recall === 1.0 && fp === 0 ? 0 : 1);
}

runEval();
