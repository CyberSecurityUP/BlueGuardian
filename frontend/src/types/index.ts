// TypeScript type definitions for BlueGuardian AI frontend

export interface Job {
  job_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  artifact_name: string;
  agent_type: string;
  created_at: string;
  completed_at?: string;
  error?: string;
}

export interface AnalysisResult {
  artifact_name: string;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  confidence: number;
  summary: string;
  iocs: IOC[];
  mitre_techniques: string[];
  raw_analysis: any;
  metadata: AnalysisMetadata;
}

export interface IOC {
  type: string;
  value: string;
  confidence: number;
  description?: string;
}

export interface AnalysisMetadata {
  agent_name: string;
  analysis_duration: number;
  ai_provider: string;
  ai_cost: number;
}

export interface SystemStatus {
  status: string;
  ai_providers: string[];
  agents_available: number;
  consensus_enabled: boolean;
}

export interface AgentInfo {
  name: string;
  description: string;
  supported_formats: string[];
}

export interface CostInfo {
  total_cost: number;
  costs_by_provider: Record<string, number>;
}
