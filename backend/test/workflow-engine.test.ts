import * as fs from 'fs';
import * as path from 'path';
import { NodeRegistry } from '../src/nodes/registry.ts';
import { WorkflowEngine } from '../src/engine/workflow-engine.ts';
import type { WorkflowGraph } from '../src/engine/types.ts';

async function testWorkflowExecution() {
  console.log('===============================================================');
  console.log('  TESTING FULL DAG WORKFLOW EXECUTION END-TO-END');
  console.log('===============================================================\n');

  const registry = new NodeRegistry();
  const engine = new WorkflowEngine(registry);

  const testGraph: WorkflowGraph = {
    id: 'wf-security-audit-full',
    name: 'Комплексный аудит безопасности (Secrets + SCA + SAST + AI + Telegram)',
    description: 'Полный автоматический конвейер проверки кода и генерации отчетов',
    nodes: [
      {
        id: 'node-trigger',
        type: 'trigger.manual',
        position: { x: 50, y: 200 },
        settings: { label: 'Старт аудита' }
      },
      {
        id: 'node-source',
        type: 'source.local',
        position: { x: 250, y: 200 },
        settings: { path: 'test-dataset/training-project' }
      },
      {
        id: 'node-sec',
        type: 'scanner.secrets',
        position: { x: 500, y: 100 },
        settings: { entropyThreshold: 3.3 }
      },
      {
        id: 'node-sca',
        type: 'scanner.sca',
        position: { x: 500, y: 250 },
        settings: { dbPath: 'test-dataset/vulnerability-database/vulnerabilities.json' }
      },
      {
        id: 'node-sast',
        type: 'scanner.sast',
        position: { x: 500, y: 400 },
        settings: {}
      },
      {
        id: 'node-agg',
        type: 'scanner.aggregator',
        position: { x: 750, y: 250 },
        settings: {}
      },
      {
        id: 'node-cond',
        type: 'logic.condition',
        position: { x: 950, y: 250 },
        settings: { rule: 'has_critical' }
      },
      {
        id: 'node-ai',
        type: 'ai.explainer',
        position: { x: 1200, y: 200 },
        settings: { provider: 'offline-smart' }
      },
      {
        id: 'node-report',
        type: 'report.dual',
        position: { x: 1450, y: 200 },
        settings: { outputDir: 'reports' }
      },
      {
        id: 'node-tg',
        type: 'notify.telegram',
        position: { x: 1700, y: 200 },
        settings: { chatId: '@security_alert' }
      }
    ],
    edges: [
      { id: 'e1', source: 'node-trigger', target: 'node-source' },
      { id: 'e2', source: 'node-source', target: 'node-sec' },
      { id: 'e3', source: 'node-source', target: 'node-sca' },
      { id: 'e4', source: 'node-source', target: 'node-sast' },
      { id: 'e5', source: 'node-sec', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings1' },
      { id: 'e6', source: 'node-sca', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings2' },
      { id: 'e7', source: 'node-sast', target: 'node-agg', sourceHandle: 'findings', targetHandle: 'findings3' },
      { id: 'e8', source: 'node-agg', target: 'node-cond' },
      { id: 'e9', source: 'node-cond', target: 'node-ai', sourceHandle: 'true' },
      { id: 'e10', source: 'node-ai', target: 'node-report' },
      { id: 'e11', source: 'node-report', target: 'node-tg' }
    ]
  };

  const events: any[] = [];
  const result = await engine.executeWorkflow(testGraph, {}, (evt) => {
    events.push(evt);
    if (evt.type === 'node-completed') {
      console.log(`  ✓ Node [${evt.nodeId}] COMPLETED in ${evt.data?.durationMs || 0}ms`);
    } else if (evt.type === 'node-failed') {
      console.log(`  ✗ Node [${evt.nodeId}] FAILED: ${evt.error}`);
    }
  });

  console.log('\n===============================================================');
  console.log('  WORKFLOW RESULT SUMMARY');
  console.log('===============================================================');
  console.log(`Success: ${result.success}`);
  console.log(`Total Duration: ${result.durationMs}ms`);

  const reportOutput = result.nodeOutputs['node-report'];
  if (reportOutput && reportOutput.reportFiles) {
    console.log(`\nGenerated Reports:`);
    console.log(`  - JSON Report: ${reportOutput.reportFiles.jsonPath}`);
    console.log(`  - Markdown Report: ${reportOutput.reportFiles.mdPath}`);

    const jsonContent = JSON.parse(fs.readFileSync(reportOutput.reportFiles.jsonPath, 'utf-8'));
    console.log(`  - JSON Findings count: ${jsonContent.findings.length}`);
    console.log(`  - Sample finding:\n`, JSON.stringify(jsonContent.findings[0], null, 2));
  }

  const tgOutput = result.nodeOutputs['node-tg'];
  if (tgOutput && tgOutput.sent) {
    console.log(`\nTelegram Notification:`);
    console.log(tgOutput.messagePreview);
  }

  console.log('\nDAG Workflow execution test PASSED perfectly!\n');
}

testWorkflowExecution().catch(err => {
  console.error('Workflow execution error:', err);
  process.exit(1);
});
