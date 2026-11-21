import { DagManager } from './dag.ts';
import type {
  WorkflowGraph,
  WorkflowNodeInstance,
  ExecutionContext,
  WorkflowExecutionEvent,
  NodeExecutionStatus
} from './types.ts';
import { NodeRegistry } from '../nodes/registry.ts';

export interface WorkflowRunResult {
  runId: string;
  workflowId: string;
  success: boolean;
  startTime: string;
  endTime: string;
  durationMs: number;
  nodeStatuses: Record<string, NodeExecutionStatus>;
  nodeInputs: Record<string, Record<string, any>>;
  nodeOutputs: Record<string, Record<string, any>>;
  errors: Record<string, string>;
}

export class WorkflowEngine {
  private registry: NodeRegistry;

  constructor(registry: NodeRegistry) {
    this.registry = registry;
  }

  public async executeWorkflow(
    graph: WorkflowGraph,
    initialData: Record<string, any> = {},
    eventListener?: (event: WorkflowExecutionEvent) => void
  ): Promise<WorkflowRunResult> {
    const runId = 'run_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
    const startTime = new Date().toISOString();
    const t0 = Date.now();

    const nodeOutputs = new Map<string, Record<string, any>>();
    const nodeInputs = new Map<string, Record<string, any>>();
    const nodeStatuses = new Map<string, NodeExecutionStatus>();
    const nodeErrors = new Map<string, string>();
    const skippedNodes = new Set<string>();

    for (const node of graph.nodes) {
      nodeStatuses.set(node.id, 'idle');
    }

    const emit = (event: WorkflowExecutionEvent) => {
      if (eventListener) {
        eventListener(event);
      }
    };

    emit({
      type: 'workflow-started',
      runId,
      data: { workflowName: graph.name, nodeCount: graph.nodes.length },
      timestamp: new Date().toISOString()
    });

    const context: ExecutionContext = {
      workflowId: graph.id,
      runId,
      nodeOutputs,
      nodeInputs,
      emitEvent: emit
    };

    try {
      const layers = DagManager.getExecutionLayers(graph);

      for (const layer of layers) {
        // Execute nodes in the same topological layer in parallel
        const promises = layer.nodeIds.map(async (nodeId) => {
          const nodeInstance = graph.nodes.find(n => n.id === nodeId);
          if (!nodeInstance) return;

          // If node was marked as skipped (e.g. from an inactive if/else branch)
          if (skippedNodes.has(nodeId)) {
            nodeStatuses.set(nodeId, 'skipped');
            emit({
              type: 'node-completed',
              runId,
              nodeId,
              status: 'skipped',
              timestamp: new Date().toISOString()
            });
            return;
          }

          // Gather inputs from incoming edges
          const incoming = DagManager.getIncomingEdges(graph, nodeId);
          const collectedInputs: Record<string, any> = { ...initialData };

          for (const edge of incoming) {
            const srcOutputs = nodeOutputs.get(edge.source) || {};
            // If edge connects specific handles
            if (edge.sourceHandle && edge.targetHandle) {
              collectedInputs[edge.targetHandle] = srcOutputs[edge.sourceHandle];
            } else if (edge.sourceHandle) {
              const val = srcOutputs[edge.sourceHandle];
              if (edge.sourceHandle === 'true' || edge.sourceHandle === 'false') {
                if (val && typeof val === 'object') {
                  Object.assign(collectedInputs, val);
                }
              } else {
                collectedInputs[edge.sourceHandle] = val;
              }
            } else {
              // Merge all outputs from source
              Object.assign(collectedInputs, srcOutputs);
            }
          }

          nodeInputs.set(nodeId, collectedInputs);
          nodeStatuses.set(nodeId, 'running');

          emit({
            type: 'node-started',
            runId,
            nodeId,
            status: 'running',
            data: { inputs: collectedInputs },
            timestamp: new Date().toISOString()
          });

          const nodeDef = this.registry.getNode(nodeInstance.type);
          if (!nodeDef) {
            throw new Error(`Node type '${nodeInstance.type}' is not registered in the system.`);
          }

          try {
            const tStartNode = Date.now();
            const output = await nodeDef.run(collectedInputs, nodeInstance.settings || {}, context);
            const durationMs = Date.now() - tStartNode;

            nodeOutputs.set(nodeId, output);
            nodeStatuses.set(nodeId, 'completed');

            emit({
              type: 'node-completed',
              runId,
              nodeId,
              status: 'completed',
              data: { output, durationMs },
              timestamp: new Date().toISOString()
            });

            // Special handle for conditional branch pruning (If/Else)
            if (nodeInstance.type === 'logic.condition' && output) {
              const conditionResult = output.result === true;
              const outgoing = DagManager.getOutgoingEdges(graph, nodeId);
              for (const edge of outgoing) {
                // If branch doesn't match condition result, mark downstream as skipped
                if (
                  (conditionResult && edge.sourceHandle === 'false') ||
                  (!conditionResult && edge.sourceHandle === 'true')
                ) {
                  this.propagateSkipped(graph, edge.target, skippedNodes);
                }
              }
            }
          } catch (err: any) {
            const errorMsg = err?.message || String(err);
            nodeErrors.set(nodeId, errorMsg);
            nodeStatuses.set(nodeId, 'failed');

            emit({
              type: 'node-failed',
              runId,
              nodeId,
              status: 'failed',
              error: errorMsg,
              timestamp: new Date().toISOString()
            });

            // Propagate skip to all downstream nodes of failed node
            const outgoing = DagManager.getOutgoingEdges(graph, nodeId);
            for (const edge of outgoing) {
              this.propagateSkipped(graph, edge.target, skippedNodes);
            }
          }
        });

        await Promise.all(promises);
      }

      const hasFailures = Array.from(nodeStatuses.values()).includes('failed');
      const endTime = new Date().toISOString();
      const totalDuration = Date.now() - t0;

      const result: WorkflowRunResult = {
        runId,
        workflowId: graph.id,
        success: !hasFailures,
        startTime,
        endTime,
        durationMs: totalDuration,
        nodeStatuses: Object.fromEntries(nodeStatuses),
        nodeInputs: Object.fromEntries(nodeInputs),
        nodeOutputs: Object.fromEntries(nodeOutputs),
        errors: Object.fromEntries(nodeErrors)
      };

      emit({
        type: hasFailures ? 'workflow-failed' : 'workflow-completed',
        runId,
        data: result,
        timestamp: endTime
      });

      return result;
    } catch (graphError: any) {
      const endTime = new Date().toISOString();
      emit({
        type: 'workflow-failed',
        runId,
        error: graphError?.message || String(graphError),
        timestamp: endTime
      });
      throw graphError;
    }
  }

  /**
   * Run a single node in isolation with custom/pinned inputs (n8n feature)
   */
  public async runSingleNode(
    nodeInstance: WorkflowNodeInstance,
    inputs: Record<string, any> = {}
  ): Promise<{ success: boolean; output?: any; error?: string; durationMs: number }> {
    const nodeDef = this.registry.getNode(nodeInstance.type);
    if (!nodeDef) {
      return { success: false, error: `Node type '${nodeInstance.type}' not found`, durationMs: 0 };
    }

    const t0 = Date.now();
    const context: ExecutionContext = {
      workflowId: 'test-single-node',
      runId: 'single_' + Date.now(),
      nodeOutputs: new Map(),
      nodeInputs: new Map(),
      emitEvent: () => {}
    };

    try {
      const output = await nodeDef.run(inputs, nodeInstance.settings || {}, context);
      return { success: true, output, durationMs: Date.now() - t0 };
    } catch (err: any) {
      return { success: false, error: err?.message || String(err), durationMs: Date.now() - t0 };
    }
  }

  private propagateSkipped(graph: WorkflowGraph, startNodeId: string, skippedSet: Set<string>) {
    skippedSet.add(startNodeId);
    const outgoing = DagManager.getOutgoingEdges(graph, startNodeId);
    for (const edge of outgoing) {
      if (!skippedSet.has(edge.target)) {
        this.propagateSkipped(graph, edge.target, skippedSet);
      }
    }
  }
}
