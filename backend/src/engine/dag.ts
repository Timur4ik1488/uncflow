import type { WorkflowGraph, WorkflowNodeInstance, WorkflowEdgeInstance } from './types.ts';

export interface TopologicalLayer {
  level: number;
  nodeIds: string[];
}

export class DagManager {
  /**
   * Validates if graph is a valid DAG and does not contain cycles.
   */
  public static validateDag(graph: WorkflowGraph): { valid: boolean; error?: string } {
    try {
      this.getExecutionLayers(graph);
      return { valid: true };
    } catch (err: any) {
      return { valid: false, error: err?.message || 'Cycle detected in workflow graph' };
    }
  }

  /**
   * Validates if graph has cycles and returns execution layers
   */
  public static getExecutionLayers(graph: WorkflowGraph): TopologicalLayer[] {
    const nodeIds = new Set(graph.nodes.map(n => n.id));
    const inDegree = new Map<string, number>();
    const adjList = new Map<string, string[]>();

    for (const id of nodeIds) {
      inDegree.set(id, 0);
      adjList.set(id, []);
    }

    for (const edge of graph.edges) {
      if (nodeIds.has(edge.source) && nodeIds.has(edge.target)) {
        adjList.get(edge.source)!.push(edge.target);
        inDegree.set(edge.target, (inDegree.get(edge.target) || 0) + 1);
      }
    }

    const layers: TopologicalLayer[] = [];
    let currentLevel: string[] = [];

    // All nodes with in-degree 0 start in layer 0
    for (const [id, deg] of inDegree.entries()) {
      if (deg === 0) {
        currentLevel.push(id);
      }
    }

    let levelIdx = 0;
    let visitedCount = 0;

    while (currentLevel.length > 0) {
      layers.push({ level: levelIdx++, nodeIds: [...currentLevel] });
      visitedCount += currentLevel.length;

      const nextLevel: string[] = [];

      for (const nodeId of currentLevel) {
        const neighbors = adjList.get(nodeId) || [];
        for (const neighbor of neighbors) {
          const currentDeg = inDegree.get(neighbor)! - 1;
          inDegree.set(neighbor, currentDeg);
          if (currentDeg === 0) {
            nextLevel.push(neighbor);
          }
        }
      }

      currentLevel = nextLevel;
    }

    if (visitedCount < nodeIds.size) {
      const remainingNodes = Array.from(nodeIds).filter(id => (inDegree.get(id) || 0) > 0);
      throw new Error(`Cycle detected in workflow graph! Cyclic nodes: [${remainingNodes.join(', ')}]. Execution requires a Directed Acyclic Graph (DAG).`);
    }

    return layers;
  }

  /**
   * Get incoming edges for a given node
   */
  public static getIncomingEdges(graph: WorkflowGraph, nodeId: string): WorkflowEdgeInstance[] {
    return graph.edges.filter(e => e.target === nodeId);
  }

  /**
   * Get outgoing edges for a given node
   */
  public static getOutgoingEdges(graph: WorkflowGraph, nodeId: string): WorkflowEdgeInstance[] {
    return graph.edges.filter(e => e.source === nodeId);
  }
}
