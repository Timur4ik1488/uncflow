import * as path from 'path';
import { HallucinationGuard, LlmProviderFactory, OfflineSmartProvider } from '../src/ai/llm-provider.ts';
import { SmartSecurityCategorizer } from '../src/ai/security-categorizer.ts';
import { maskSensitiveText } from '../src/validators/submission-validator.ts';

async function runAiLayerTests() {
  console.log('===============================================================');
  console.log('  TESTING AI LAYER: HALLUCINATION GUARD & MULTI-PROVIDER');
  console.log('===============================================================\n');

  const repoRoot = path.join(process.cwd(), 'test-dataset', 'training-project');

  // 1. Test Hallucination Guard
  console.log('1. Testing Hallucination Guard:');

  // Valid finding
  const validFinding = {
    category: 'SECRET',
    path: 'src/main/resources/application.yml',
    class: 'configuration-token',
    line: 13
  };
  const check1 = HallucinationGuard.validateFinding(validFinding, repoRoot);
  if (!check1.valid) throw new Error(`Expected valid finding to pass, got: ${check1.reason}`);
  console.log('  ✅ Real file and line successfully validated');

  // Fake non-existent path
  const fakePathFinding = {
    category: 'SAST',
    path: 'src/main/kotlin/lab/repairdesk/non_existent_file.kt',
    class: 'sql-injection',
    line: 10
  };
  const check2 = HallucinationGuard.validateFinding(fakePathFinding, repoRoot);
  if (check2.valid) throw new Error('Expected hallucinated path to be rejected');
  console.log('  ✅ Hallucinated path successfully caught:', check2.reason);

  // Exceeding line number
  const fakeLineFinding = {
    category: 'SECRET',
    path: 'src/main/resources/application.yml',
    class: 'password',
    line: 99999
  };
  const check3 = HallucinationGuard.validateFinding(fakeLineFinding, repoRoot);
  if (check3.valid) throw new Error('Expected hallucinated line to be rejected');
  console.log('  ✅ Hallucinated line number successfully caught:', check3.reason);

  // Fake SCA advisory
  const fakeScaFinding = {
    category: 'SCA',
    path: 'build.gradle.kts',
    group: 'org.unknown',
    artifact: 'fake-lib',
    version: '1.0.0',
    advisoryId: 'CVE-9999-99999'
  };
  const check4 = HallucinationGuard.validateFinding(fakeScaFinding, repoRoot, new Set(['CVE-2022-42889']));
  if (check4.valid) throw new Error('Expected hallucinated SCA advisory to be rejected');
  console.log('  ✅ Hallucinated SCA advisory successfully caught:', check4.reason);

  // 2. Test Secret Masking in Prompts
  console.log('\n2. Testing Secret Masking for AI Prompts:');
  const sensitivePrompt = 'User found secret Bearer secret_live_token_12345678 and basic password super_secret_pass';
  const maskedPrompt = maskSensitiveText(sensitivePrompt);
  if (maskedPrompt.includes('secret_live_token_12345678')) {
    throw new Error('Raw token leaked in prompt!');
  }
  console.log('  ✅ Sensitive token masked before LLM:', maskedPrompt);

  // 3. Test Offline Smart Provider
  console.log('\n3. Testing Offline Smart Categorization:');
  const provider = LlmProviderFactory.getProvider('offline-smart');
  const analysis = await SmartSecurityCategorizer.analyzeFinding({
    category: 'SAST',
    path: 'src/main/OrderController.kt',
    class: 'sql-injection',
    line: 15,
    severity: 'CRITICAL',
    description: 'SQL Injection via interpolation',
    remediation: 'Use parameterized query'
  }, provider);

  if (analysis.cwe !== 'CWE-89: SQL Injection' || analysis.cvssScore !== 9.8) {
    throw new Error(`Unexpected analysis output: ${JSON.stringify(analysis)}`);
  }
  console.log('  ✅ Offline Smart Categorizer mapped CWE-89, CVSS 9.8, and OWASP A03');

  const exec = await SmartSecurityCategorizer.generateExecutiveSummary([
    { category: 'SAST', path: 'test.kt', severity: 'CRITICAL', description: 'test' }
  ], provider);
  if (!exec.cisoSummary || exec.riskLevel !== 'CRITICAL') {
    throw new Error('Failed to generate offline CISO summary');
  }
  console.log('  ✅ Executive CISO Summary successfully generated offline with CRITICAL risk level');

  console.log('\n🎉 All AI layer and hallucination guard tests passed successfully!\n');
}

runAiLayerTests().catch(err => {
  console.error('AI layer test error:', err);
  process.exit(1);
});
