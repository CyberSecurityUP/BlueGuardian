import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Download,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Shield,
  Target,
  Hash,
  DollarSign,
} from 'lucide-react';
import { apiService } from '../services/api';

export default function JobDetailsPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);

  const { data: job, isLoading: jobLoading } = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => apiService.getJob(jobId!),
    enabled: !!jobId,
  });

  const { data: result, isLoading: resultLoading } = useQuery({
    queryKey: ['jobResult', jobId],
    queryFn: () => apiService.getJobResult(jobId!),
    enabled: !!jobId && job?.status === 'completed',
  });

  const handleDownloadReport = async (format: 'json' | 'html' | 'markdown' | 'pdf') => {
    if (!jobId) return;

    try {
      setDownloadingFormat(format);
      const blob = await apiService.downloadReport(jobId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${jobId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Failed to download report:', error);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const getVerdictIcon = (verdict: string) => {
    switch (verdict) {
      case 'malicious':
        return <XCircle className="w-8 h-8 text-red-600" />;
      case 'suspicious':
        return <AlertTriangle className="w-8 h-8 text-yellow-600" />;
      case 'clean':
        return <CheckCircle className="w-8 h-8 text-green-600" />;
      default:
        return <Shield className="w-8 h-8 text-gray-600" />;
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'malicious':
        return 'bg-red-100 border-red-300 text-red-900';
      case 'suspicious':
        return 'bg-yellow-100 border-yellow-300 text-yellow-900';
      case 'clean':
        return 'bg-green-100 border-green-300 text-green-900';
      default:
        return 'bg-gray-100 border-gray-300 text-gray-900';
    }
  };

  if (jobLoading || resultLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Job not found</p>
        <Link to="/jobs" className="text-blue-600 hover:underline mt-4 inline-block">
          Back to Jobs
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            to="/jobs"
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-6 h-6" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-gray-900">{job.artifact_name}</h1>
            <p className="text-gray-600 mt-1">Job ID: {job.job_id}</p>
          </div>
        </div>

        {job.status === 'completed' && result && (
          <div className="flex gap-2">
            <button
              onClick={() => handleDownloadReport('html')}
              disabled={downloadingFormat === 'html'}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              {downloadingFormat === 'html' ? 'Downloading...' : 'HTML'}
            </button>
            <button
              onClick={() => handleDownloadReport('pdf')}
              disabled={downloadingFormat === 'pdf'}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              {downloadingFormat === 'pdf' ? 'Downloading...' : 'PDF'}
            </button>
            <button
              onClick={() => handleDownloadReport('json')}
              disabled={downloadingFormat === 'json'}
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 disabled:bg-gray-300 flex items-center gap-2"
            >
              <Download className="w-4 h-4" />
              {downloadingFormat === 'json' ? 'Downloading...' : 'JSON'}
            </button>
          </div>
        )}
      </div>

      {/* Job Status */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Job Status</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <p className="text-sm text-gray-600">Status</p>
            <p className="text-lg font-medium text-gray-900 mt-1 capitalize">{job.status}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Agent</p>
            <p className="text-lg font-medium text-gray-900 mt-1">{job.agent_type}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600">Created At</p>
            <p className="text-lg font-medium text-gray-900 mt-1">
              {new Date(job.created_at).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Running State */}
      {job.status === 'running' && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6 flex items-center gap-4">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-yellow-600"></div>
          <div>
            <p className="font-medium text-yellow-900">Analysis in Progress</p>
            <p className="text-sm text-yellow-700 mt-1">
              This analysis is currently running. Results will appear here when complete.
            </p>
          </div>
        </div>
      )}

      {/* Failed State */}
      {job.status === 'failed' && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-6">
          <div className="flex items-start gap-3">
            <XCircle className="w-6 h-6 text-red-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-red-900">Analysis Failed</p>
              {job.error && (
                <p className="text-sm text-red-700 mt-1">{job.error}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Analysis Results */}
      {job.status === 'completed' && result && (
        <>
          {/* Verdict */}
          <div
            className={`rounded-lg border-2 p-8 ${getVerdictColor(result.verdict)}`}
          >
            <div className="flex items-center gap-4 mb-4">
              {getVerdictIcon(result.verdict)}
              <div>
                <h2 className="text-2xl font-bold">
                  Verdict: {result.verdict.toUpperCase()}
                </h2>
                <p className="text-lg mt-1">
                  Confidence: {(result.confidence * 100).toFixed(1)}%
                </p>
              </div>
            </div>
            <div className="w-full bg-white bg-opacity-50 rounded-full h-3">
              <div
                className={`h-3 rounded-full ${
                  result.verdict === 'malicious'
                    ? 'bg-red-600'
                    : result.verdict === 'suspicious'
                    ? 'bg-yellow-600'
                    : 'bg-green-600'
                }`}
                style={{ width: `${result.confidence * 100}%` }}
              ></div>
            </div>
          </div>

          {/* Summary */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Summary</h2>
            <p className="text-gray-700 whitespace-pre-wrap">{result.summary}</p>
          </div>

          {/* Metadata */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Analysis Metadata</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div>
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <Shield className="w-5 h-5" />
                  <p className="text-sm">Agent</p>
                </div>
                <p className="font-medium text-gray-900">{result.metadata.agent_name}</p>
              </div>
              <div>
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <Clock className="w-5 h-5" />
                  <p className="text-sm">Duration</p>
                </div>
                <p className="font-medium text-gray-900">
                  {result.metadata.analysis_duration.toFixed(2)}s
                </p>
              </div>
              <div>
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <Hash className="w-5 h-5" />
                  <p className="text-sm">AI Provider</p>
                </div>
                <p className="font-medium text-gray-900">{result.metadata.ai_provider}</p>
              </div>
              <div>
                <div className="flex items-center gap-2 text-gray-600 mb-2">
                  <DollarSign className="w-5 h-5" />
                  <p className="text-sm">AI Cost</p>
                </div>
                <p className="font-medium text-gray-900">
                  ${result.metadata.ai_cost.toFixed(4)}
                </p>
              </div>
            </div>
          </div>

          {/* IOCs */}
          {result.iocs.length > 0 && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Indicators of Compromise (IOCs)
              </h2>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                        IOC
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {result.iocs.map((ioc, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                          {ioc}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* MITRE ATT&CK Techniques */}
          {result.mitre_techniques.length > 0 && (
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center gap-2 mb-4">
                <Target className="w-6 h-6 text-red-600" />
                <h2 className="text-xl font-semibold text-gray-900">
                  MITRE ATT&CK Techniques
                </h2>
              </div>
              <div className="flex flex-wrap gap-2">
                {result.mitre_techniques.map((technique, index) => (
                  <a
                    key={index}
                    href={`https://attack.mitre.org/techniques/${technique.replace('T', 'T')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 bg-red-100 text-red-800 rounded-lg hover:bg-red-200 transition-colors font-mono text-sm"
                  >
                    {technique}
                  </a>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
