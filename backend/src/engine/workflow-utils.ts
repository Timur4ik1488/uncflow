import type { WorkflowGraph } from './types.ts';
import type { WorkflowRunResult } from './workflow-engine.ts';

/**
 * Extracts findings from a workflow execution result by node type semantics
 * rather than hardcoded node IDs.
 */
export function extractWorkflowFindings(graph: WorkflowGraph | undefined, result: WorkflowRunResult): any[] {
  if (!result || !result.nodeOutputs) {
    return [];
  }

  // 1. If graph is provided, check outputs by node types in order of priority:
  // Dual Report -> Aggregator -> Individual Scanners
  if (graph && graph.nodes) {
    // Check report nodes
    for (const node of graph.nodes) {
      if (node.type === 'report.dual' || node.type === 'report.json') {
        const out = result.nodeOutputs[node.id];
        if (out && Array.isArray(out.allFindings) && out.allFindings.length > 0) {
          return out.allFindings;
        }
        if (out && Array.isArray(out.findings) && out.findings.length > 0) {
          return out.findings;
        }
      }
    }

    // Check aggregator nodes
    for (const node of graph.nodes) {
      if (node.type === 'scanner.aggregator' || node.type === 'scan.aggregator') {
        const out = result.nodeOutputs[node.id];
        if (out && Array.isArray(out.allFindings) && out.allFindings.length > 0) {
          return out.allFindings;
        }
        if (out && Array.isArray(out.findings) && out.findings.length > 0) {
          return out.findings;
        }
      }
    }

    // Check individual scanner nodes
    const scannerFindings: any[] = [];
    for (const node of graph.nodes) {
      if (
        node.type === 'scanner.sast' || node.type === 'scan.sast' ||
        node.type === 'scanner.secrets' || node.type === 'scan.secret' ||
        node.type === 'scanner.sca' || node.type === 'scan.sca'
      ) {
        const out = result.nodeOutputs[node.id];
        if (out && Array.isArray(out.findings)) {
          scannerFindings.push(...out.findings);
        }
      }
    }
    if (scannerFindings.length > 0) {
      return scannerFindings;
    }
  }

  // 2. Fallback: inspect all node outputs dynamically
  for (const [nodeId, out] of Object.entries(result.nodeOutputs)) {
    if (out && Array.isArray(out.allFindings) && out.allFindings.length > 0) {
      return out.allFindings;
    }
  }
  for (const [nodeId, out] of Object.entries(result.nodeOutputs)) {
    if (out && Array.isArray(out.findings) && out.findings.length > 0) {
      return out.findings;
    }
  }

  return [];
}
