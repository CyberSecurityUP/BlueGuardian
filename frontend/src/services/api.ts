import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
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
  iocs: string[];
  mitre_techniques: string[];
  raw_analysis: any;
  metadata: {
    agent_name: string;
    analysis_duration: number;
    ai_provider: string;
    ai_cost: number;
  };
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

// API Functions
export const apiService = {
  // Health & Status
  async getHealth() {
    const response = await api.get('/health');
    return response.data;
  },

  async getStatus(): Promise<SystemStatus> {
    const response = await api.get<SystemStatus>('/status');
    return response.data;
  },

  // Agents
  async getAgents(): Promise<AgentInfo[]> {
    const response = await api.get<AgentInfo[]>('/agents');
    return response.data;
  },

  // Analysis
  async analyzeFile(file: File, agentType?: string): Promise<Job> {
    const formData = new FormData();
    formData.append('file', file);
    if (agentType) {
      formData.append('agent_type', agentType);
    }

    const response = await api.post<Job>('/analyze/file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  async analyzeUrl(url: string, agentType?: string): Promise<Job> {
    const response = await api.post<Job>('/analyze/url', {
      url,
      agent_type: agentType,
    });
    return response.data;
  },

  // Jobs
  async getJobs(): Promise<Job[]> {
    const response = await api.get<Job[]>('/jobs');
    return response.data;
  },

  async getJob(jobId: string): Promise<Job> {
    const response = await api.get<Job>(`/jobs/${jobId}`);
    return response.data;
  },

  async getJobResult(jobId: string): Promise<AnalysisResult> {
    const response = await api.get<AnalysisResult>(`/jobs/${jobId}/result`);
    return response.data;
  },

  async deleteJob(jobId: string): Promise<void> {
    await api.delete(`/jobs/${jobId}`);
  },

  // Reports
  async downloadReport(jobId: string, format: 'json' | 'html' | 'markdown' | 'pdf'): Promise<Blob> {
    const response = await api.get(`/jobs/${jobId}/report/${format}`, {
      responseType: 'blob',
    });
    return response.data;
  },

  // Costs
  async getCosts(): Promise<CostInfo> {
    const response = await api.get<CostInfo>('/costs');
    return response.data;
  },
};

export default apiService;
