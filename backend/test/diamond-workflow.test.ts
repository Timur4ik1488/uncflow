import { NodeRegistry } from '../src/nodes/registry.ts';
import { WorkflowEngine } from '../src/engine/workflow-engine.ts';
import { DagManager } from '../src/engine/dag.ts';
import type { WorkflowGraph } from '../src/engine/types.ts';

async function runDiamondAndLogicTests() {
  console.log('===============================================================');
  console.log('  TESTING WORKFLOW ENGINE: DIAMOND GRAPH, LOGIC & REGEX');
  console.log('===============================================================\n');

  const registry = new NodeRegistry();
  const engine = new WorkflowEngine(registry);

  // 1. Diamond Graph Test with logic.condition
  console.log('1. Testing Diamond Graph (If/Else with downstream merge node):');
  const diamondGraph: WorkflowGraph = {
    id: 'wf-diamond-test',
    name: 'Diamond Test Graph',
    nodes: [
      {
        id: 'start',
        type: 'trigger.manual',
        position: { x: 0, y: 0 },
        settings: {}
      },
      {
        id: 'cond',
        type: 'logic.condition',
        position: { x: 200, y: 0 },
        settings: {
          mode: 'compare',
          compareField: 'count',
          compareOperator: '>',
          compareValue: '5'
        }
      },
      {
        id: 'branch-true',
        type: 'logic.regex',
        position: { x: 400, y: -100 },
        settings: {
          pattern: 'important',
          mode: 'test'
        }
      },
      {
        id: 'branch-false',
        type: 'logic.regex',
        position: { x: 400, y: 100 },
        settings: {
          pattern: 'unimportant',
          mode: 'test'
        }
      },
      {
        id: 'merge-agg',
        type: 'scanner.aggregator',
        position: { x: 600, y: 0 },
        settings: { deduplicate: true }
      }
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'cond' },
      { id: 'e2', source: 'cond', target: 'branch-true', sourceHandle: 'true' },
      { id: 'e3', source: 'cond', target: 'branch-false', sourceHandle: 'false' },
      { id: 'e4', source: 'branch-true', target: 'merge-agg' },
      { id: 'e5', source: 'branch-false', target: 'merge-agg' }
    ]
  };

  // Run with count = 10 (triggers true branch)
  const resultTrue = await engine.executeWorkflow(diamondGraph, {
    count: 10,
    findings: [
      { category: 'SECRET', path: 'Config.kt', class: 'password', line: 10, severity: 'HIGH', description: 'test' },
      { category: 'SECRET', path: 'Config.kt', class: 'password', line: 10, severity: 'HIGH', description: 'test' } // duplicate!
    ]
  });

  if (resultTrue.nodeStatuses['branch-true'] !== 'completed') {
    throw new Error(`Expected branch-true to be completed, got ${resultTrue.nodeStatuses['branch-true']}`);
  }
  if (resultTrue.nodeStatuses['branch-false'] !== 'skipped') {
    throw new Error(`Expected branch-false to be skipped, got ${resultTrue.nodeStatuses['branch-false']}`);
  }
  if (resultTrue.nodeStatuses['merge-agg'] !== 'completed') {
    throw new Error(`Expected merge-agg to be completed (diamond merge!), got ${resultTrue.nodeStatuses['merge-agg']}`);
  }

  console.log('  ✅ Diamond execution: true branch completed, false branch skipped, merge node completed!');

  // Check deduplication in aggregator
  const aggOutput = resultTrue.nodeOutputs['merge-agg'];
  if (!aggOutput || aggOutput.totalCount !== 1) {
    throw new Error(`Expected deduplicated totalCount = 1, got ${aggOutput?.totalCount}`);
  }
  console.log('  ✅ Aggregator deduplication: 2 identical findings reduced to 1 unique finding!');

  // 2. Cycle detection test
  console.log('\n2. Testing Cycle Detection (DAG Validation):');
  const cyclicGraph: WorkflowGraph = {
    id: 'wf-cycle-test',
    name: 'Cyclic Graph',
    nodes: [
      { id: 'n1', type: 'trigger.manual', position: { x: 0, y: 0 } },
      { id: 'n2', type: 'trigger.manual', position: { x: 100, y: 0 } }
    ],
    edges: [
      { id: 'ce1', source: 'n1', target: 'n2' },
      { id: 'ce2', source: 'n2', target: 'n1' } // cycle!
    ]
  };

  const dagCheck = DagManager.validateDag(cyclicGraph);
  if (dagCheck.valid) {
    throw new Error('Expected cyclic graph to be detected as invalid');
  }
  console.log('  ✅ Cycle successfully detected:', dagCheck.error);

  console.log('\n🎉 All diamond workflow, logic condition, regex, and cycle tests passed!\n');
}

runDiamondAndLogicTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
