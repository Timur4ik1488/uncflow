import { db, DatabaseService } from '../src/storage/db.ts';
import type { Finding } from '../src/types/findings.ts';
import type { WorkflowTemplate } from '../src/templates/catalog.ts';

async function runPostgresStorageTests() {
  console.log('===============================================================');
  console.log('  TESTING POSTGRESQL STORAGE & DATABASE SERVICE');
  console.log('===============================================================\n');

  let passed = 0;
  let total = 0;

  function assert(condition: boolean, testName: string) {
    total++;
    if (condition) {
      console.log(`  ✅ [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${testName}`);
      process.exitCode = 1;
    }
  }

  // 1. Initialize DB Service
  console.log('1. Checking Database Initialization & Connection Mode...');
  const initResult = await db.init();
  const health = await db.getHealth();
  console.log(`   Connected: ${health.connected} | Driver: ${health.driver}`);
  assert(typeof health.driver === 'string', 'Database service initialized with active driver');

  // 2. Test Workflow Run Persistence
  console.log('\n2. Testing Workflow Run Persistence...');
  const testRunId = 'test_run_' + Date.now();
  await db.saveWorkflowRun({
    id: testRunId,
    workflowId: 'wf-test-audit',
    workflowName: 'Test Security Workflow',
    success: true,
    durationMs: 142,
    startTime: new Date().toISOString(),
    endTime: new Date().toISOString(),
    findingsCount: 3,
    criticalCount: 1,
    highCount: 1,
    mediumCount: 1,
    lowCount: 0,
    result: { status: 'completed' }
  });

  const runs = await db.getWorkflowRuns(10, 0);
  assert(runs.length > 0, 'Workflow runs retrieved from storage');
  const foundRun = await db.getWorkflowRunById(testRunId);
  assert(foundRun !== null && foundRun.id === testRunId, 'Specific workflow run retrieved by ID');
  assert(foundRun?.workflowName === 'Test Security Workflow', 'Run attributes correctly persisted');

  // 3. Test Findings Persistence & Querying
  console.log('\n3. Testing Findings Storage & Filtering...');
  const testFindings: Finding[] = [
    {
      category: 'SECRET',
      class: 'password',
      path: 'src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt',
      line: 4,
      severity: 'HIGH',
      description: 'Hardcoded legacy import password detected',
      remediation: 'Use environment variable instead'
    },
    {
      category: 'SCA',
      group: 'org.jsoup',
      artifact: 'jsoup',
      version: '1.14.1',
      advisoryId: 'CVE-2021-37714',
      path: 'build.gradle.kts',
      severity: 'CRITICAL',
      description: 'Cross-site scripting and unhandled exception in jsoup',
      remediation: 'Upgrade to jsoup 1.14.2+'
    },
    {
      category: 'SAST',
      class: 'sql-injection',
      path: 'src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt',
      line: 14,
      severity: 'CRITICAL',
      description: 'Unescaped SQL query interpolation in JdbcTemplate',
      remediation: 'Use parameterized queries with ?'
    }
  ];

  await db.saveFindings(testRunId, testFindings);

  const retrievedFindings = await db.getFindings({ runId: testRunId });
  assert(retrievedFindings.length === 3, 'All 3 findings persisted and retrieved by runId');

  const criticalFindings = await db.getFindings({ runId: testRunId, severity: 'CRITICAL' });
  assert(criticalFindings.length === 2, 'Filtered findings by severity CRITICAL (expected 2)');

  const scaFindings = await db.getFindings({ runId: testRunId, category: 'SCA' });
  assert(scaFindings.length === 1 && (scaFindings[0] as any).artifact === 'jsoup', 'Filtered findings by category SCA');

  // 4. Test Aggregated Statistics
  console.log('\n4. Testing Aggregated Statistics...');
  const stats = await db.getFindingsStats();
  assert(stats.total >= 3, `Stats total count >= 3 (got ${stats.total})`);
  assert(stats.critical >= 2, `Stats critical count >= 2 (got ${stats.critical})`);
  assert(stats.byCategory.SECRET >= 1, 'Stats byCategory SECRET >= 1');
  assert(stats.byCategory.SAST >= 1, 'Stats byCategory SAST >= 1');
  assert(stats.byCategory.SCA >= 1, 'Stats byCategory SCA >= 1');

  // 5. Test Dual Report Storage
  console.log('\n5. Testing Dual Report Storage & Latest Query...');
  const testReportId = await db.saveReport({
    runId: testRunId,
    totalVulnerabilities: 3,
    summary: { critical: 2, high: 1, medium: 0, low: 0 },
    jsonContent: { findings: testFindings },
    markdownContent: '# Audit Report\n\nFound 3 vulnerabilities.'
  });
  assert(testReportId > 0, 'Report saved with valid ID');

  const latestReport = await db.getLatestReport();
  assert(latestReport !== null, 'Latest report retrieved');
  assert(latestReport?.totalVulnerabilities === 3, 'Latest report contains correct vulnerability count');
  assert(latestReport?.markdownContent.includes('Audit Report') === true, 'Latest report contains Markdown body');

  // 6. Test Workflow Templates CRUD
  console.log('\n6. Testing Workflow Templates CRUD...');
  const customTemplate: WorkflowTemplate = {
    id: 'template-custom-test-' + Date.now(),
    title: 'Custom User Test Workflow',
    description: 'A test workflow scenario created by user',
    category: 'Full Audit',
    tags: ['Custom', 'Test'],
    author: 'Test Developer',
    graph: {
      id: 'wf-custom',
      name: 'Custom Flow',
      nodes: [],
      edges: []
    }
  };

  await db.saveTemplate(customTemplate, false);
  const templates = await db.getTemplates();
  assert(templates.some(t => t.id === customTemplate.id), 'Custom template saved and found in templates list');

  const fetchedTemplate = await db.getTemplateById(customTemplate.id);
  assert(fetchedTemplate?.title === customTemplate.title, 'Fetched specific template by ID');

  const deleted = await db.deleteTemplate(customTemplate.id);
  assert(deleted === true, 'Template deleted successfully');
  const postDelete = await db.getTemplateById(customTemplate.id);
  assert(postDelete === null, 'Template is no longer accessible after deletion');

  // 7. Test Secret Vault Storage
  console.log('\n7. Testing Secret Vault Encrypted Storage...');
  const secretKey = 'test_token_' + Date.now();
  await db.saveSecret(secretKey, 'encrypted-payload-sample-hex', 'Test description');
  const retrievedSecret = await db.getSecret(secretKey);
  assert(retrievedSecret === 'encrypted-payload-sample-hex', 'Secret retrieved from vault');

  // 8. Close DB Service Cleanly
  await db.close();

  console.log('\n===============================================================');
  console.log(`  POSTGRESQL STORAGE TESTS RESULT: ${passed}/${total} PASSED`);
  console.log('===============================================================');

  if (passed === total) {
    console.log('🎉 All PostgreSQL storage & database operations passed successfully!\n');
  } else {
    console.error('❌ Some PostgreSQL tests failed.\n');
    process.exit(1);
  }
}

runPostgresStorageTests().catch(err => {
  console.error('Test execution error:', err);
  process.exit(1);
});
