import type { Finding } from '../types/findings.ts';

export type PortType = 'any' | 'codePath' | 'findings' | 'aiReport' | 'boolean' | 'string' | 'reportFiles';

export interface NodePort {
  id: string;
  label: string;
  type: PortType;
}

export interface NodeSettingSchema {
  name: string;
  label: string;
  type: 'string' | 'password' | 'number' | 'boolean' | 'select' | 'textarea';
  default?: any;
  options?: { label: string; value: string }[];
  description?: string;
  required?: boolean;
}

export interface ExecutionContext {
  workflowId: string;
  runId: string;
  projectRoot?: string;
  nodeOutputs: Map<string, Record<string, any>>;
  nodeInputs: Map<string, Record<string, any>>;
  emitEvent: (event: WorkflowExecutionEvent) => void;
  isCancelled?: boolean;
}

export interface NodeDefinition {
  type: string;
  title: string;
  category: 'Triggers' | 'Sources' | 'Scanners' | 'Logic' | 'AI' | 'Reports' | 'Notifications';
  icon?: string;
  color?: string;
  description: string;
  inputs: NodePort[];
  outputs: NodePort[];
  settings: NodeSettingSchema[];
  run: (inputs: Record<string, any>, settings: Record<string, any>, context: ExecutionContext) => Promise<Record<string, any>>;
}

export interface WorkflowNodeInstance {
  id: string;
  type: string;
  name?: string;
  position: { x: number; y: number };
  settings: Record<string, any>;
}

export interface WorkflowEdgeInstance {
  id: string;
  source: string;
  sourceHandle?: string;
  target: string;
  targetHandle?: string;
}

export interface WorkflowGraph {
  id: string;
  name: string;
  description?: string;
  nodes: WorkflowNodeInstance[];
  edges: WorkflowEdgeInstance[];
}

export type NodeExecutionStatus = 'idle' | 'running' | 'completed' | 'failed' | 'skipped';

export interface WorkflowExecutionEvent {
  type: 'workflow-started' | 'node-started' | 'node-progress' | 'node-completed' | 'node-failed' | 'workflow-completed' | 'workflow-failed';
  runId: string;
  nodeId?: string;
  status?: NodeExecutionStatus;
  progress?: number;
  data?: any;
  error?: string;
  timestamp: string;
}
