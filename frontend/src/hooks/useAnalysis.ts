// Custom hooks for BlueGuardian AI analysis operations
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../services/api';

/**
 * Hook to fetch all jobs
 */
export function useJobs() {
  return useQuery({
    queryKey: ['jobs'],
    queryFn: () => apiService.getJobs(),
    refetchInterval: 5000, // Refetch every 5 seconds
  });
}

/**
 * Hook to fetch a specific job
 */
export function useJob(jobId: string) {
  return useQuery({
    queryKey: ['job', jobId],
    queryFn: () => apiService.getJob(jobId),
    enabled: !!jobId,
  });
}

/**
 * Hook to fetch job results
 */
export function useJobResult(jobId: string) {
  return useQuery({
    queryKey: ['jobResult', jobId],
    queryFn: () => apiService.getJobResult(jobId),
    enabled: !!jobId,
  });
}

/**
 * Hook to analyze a file
 */
export function useFileAnalysis() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ file, agentType }: { file: File; agentType?: string }) =>
      apiService.analyzeFile(file, agentType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
  });
}

/**
 * Hook to analyze a URL
 */
export function useUrlAnalysis() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ url, agentType }: { url: string; agentType?: string }) =>
      apiService.analyzeUrl(url, agentType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
  });
}

/**
 * Hook to fetch system status
 */
export function useSystemStatus() {
  return useQuery({
    queryKey: ['status'],
    queryFn: () => apiService.getStatus(),
  });
}

/**
 * Hook to fetch available agents
 */
export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => apiService.getAgents(),
  });
}

/**
 * Hook to fetch API costs
 */
export function useCosts() {
  return useQuery({
    queryKey: ['costs'],
    queryFn: () => apiService.getCosts(),
  });
}
