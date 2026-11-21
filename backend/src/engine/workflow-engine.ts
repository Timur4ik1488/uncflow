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

    const completedNodes = new Set<string>();
    const skippedNodes = new Set<string>();
    const failedNodes = new Set<string>();
    const prunedEdges = new Set<string>();

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

    // 1. DAG validation and cycle check
    const dagCheck = DagManager.validateDag(graph);
    if (!dagCheck.valid) {
      const err = new Error(dagCheck.error || 'Invalid workflow DAG: cycle detected');
      emit({
        type: 'workflow-failed',
        runId,
        error: err.message,
        timestamp: new Date().toISOString()
      });
      throw err;
    }

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

          const incoming = DagManager.getIncomingEdges(graph, nodeId);

          // Determine if node should be skipped
          let shouldSkip = false;
          if (skippedNodes.has(nodeId)) {
            shouldSkip = true;
          } else if (incoming.length > 0) {
            // Node has incoming dependencies: check if any are active
            const hasActiveIncoming = incoming.some(
              edge => !prunedEdges.has(edge.id) && completedNodes.has(edge.source)
            );
            if (!hasActiveIncoming) {
              shouldSkip = true;
            }
          }

          if (shouldSkip) {
            skippedNodes.add(nodeId);
            nodeStatuses.set(nodeId, 'skipped');
            // Prune all outgoing edges from skipped node
            for (const outEdge of DagManager.getOutgoingEdges(graph, nodeId)) {
              prunedEdges.add(outEdge.id);
            }
            emit({
              type: 'node-completed',
              runId,
              nodeId,
              status: 'skipped',
              timestamp: new Date().toISOString()
            });
            return;
          }

          // Gather inputs only from active completed incoming edges
          const collectedInputs: Record<string, any> = { ...initialData };

          for (const edge of incoming) {
            if (prunedEdges.has(edge.id) || !completedNodes.has(edge.source)) {
              continue;
            }
            const srcOutputs = nodeOutputs.get(edge.source) || {};
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
            completedNodes.add(nodeId);

            emit({
              type: 'node-completed',
              runId,
              nodeId,
              status: 'completed',
              data: { output, durationMs },
              timestamp: new Date().toISOString()
            });

            // Handle conditional branch pruning (If/Else)
            if (nodeInstance.type === 'logic.condition' && output) {
              const conditionResult = output.result === true;
              const outgoing = DagManager.getOutgoingEdges(graph, nodeId);
              for (const edge of outgoing) {
                if (
                  (conditionResult && edge.sourceHandle === 'false') ||
                  (!conditionResult && edge.sourceHandle === 'true')
                ) {
                  prunedEdges.add(edge.id);
                }
              }
            }
          } catch (err: any) {
            const errorMsg = err?.message || String(err);
            nodeErrors.set(nodeId, errorMsg);
            nodeStatuses.set(nodeId, 'failed');
            failedNodes.add(nodeId);

            // Prune outgoing edges of failed node
            for (const edge of DagManager.getOutgoingEdges(graph, nodeId)) {
              prunedEdges.add(edge.id);
            }

            emit({
              type: 'node-failed',
              runId,
              nodeId,
              status: 'failed',
              error: errorMsg,
              timestamp: new Date().toISOString()
            });
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
   * Run a single node in isolation with custom/pinned inputs
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
}
