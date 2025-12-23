import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Upload, FileUp, Link as LinkIcon, AlertCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';

export default function AnalysisPage() {
  const navigate = useNavigate();
  const [analysisType, setAnalysisType] = useState<'file' | 'url'>('file');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [dragActive, setDragActive] = useState(false);

  const { data: agents } = useQuery({
    queryKey: ['agents'],
    queryFn: () => apiService.getAgents(),
  });

  const fileAnalysisMutation = useMutation({
    mutationFn: (data: { file: File; agentType?: string }) =>
      apiService.analyzeFile(data.file, data.agentType),
    onSuccess: (job) => {
      navigate(`/jobs/${job.job_id}`);
    },
  });

  const urlAnalysisMutation = useMutation({
    mutationFn: (data: { url: string; agentType?: string }) =>
      apiService.analyzeUrl(data.url, data.agentType),
    onSuccess: (job) => {
      navigate(`/jobs/${job.job_id}`);
    },
  });

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (analysisType === 'file' && selectedFile) {
      fileAnalysisMutation.mutate({
        file: selectedFile,
        agentType: selectedAgent || undefined,
      });
    } else if (analysisType === 'url' && url) {
      urlAnalysisMutation.mutate({
        url,
        agentType: selectedAgent || undefined,
      });
    }
  };

  const isLoading = fileAnalysisMutation.isPending || urlAnalysisMutation.isPending;
  const error = fileAnalysisMutation.error || urlAnalysisMutation.error;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Analysis</h1>
        <p className="text-gray-600 mt-2">Upload files or analyze URLs for threats</p>
      </div>

      {/* Analysis Type Selector */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex gap-4 mb-6">
          <button
            onClick={() => setAnalysisType('file')}
            className={`flex-1 py-3 px-6 rounded-lg font-medium transition-colors ${
              analysisType === 'file'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            <FileUp className="inline-block w-5 h-5 mr-2" />
            File Upload
          </button>
          <button
            onClick={() => setAnalysisType('url')}
            className={`flex-1 py-3 px-6 rounded-lg font-medium transition-colors ${
              analysisType === 'url'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            <LinkIcon className="inline-block w-5 h-5 mr-2" />
            URL Analysis
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* File Upload */}
          {analysisType === 'file' && (
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
                dragActive
                  ? 'border-blue-600 bg-blue-50'
                  : 'border-gray-300 hover:border-gray-400'
              }`}
            >
              <Upload className="w-12 h-12 mx-auto text-gray-400 mb-4" />
              <p className="text-lg font-medium text-gray-900 mb-2">
                {selectedFile ? selectedFile.name : 'Drop your file here'}
              </p>
              <p className="text-sm text-gray-500 mb-4">
                or click to browse
              </p>
              <input
                type="file"
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
              />
              <label
                htmlFor="file-upload"
                className="inline-block px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 cursor-pointer"
              >
                Select File
              </label>
              {selectedFile && (
                <div className="mt-4 text-sm text-gray-600">
                  Size: {(selectedFile.size / 1024).toFixed(2)} KB
                </div>
              )}
            </div>
          )}

          {/* URL Input */}
          {analysisType === 'url' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                URL or IP Address
              </label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com or 192.168.1.1"
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-600 focus:border-transparent"
                required
              />
            </div>
          )}

          {/* Agent Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Analysis Agent (Optional)
            </label>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-600 focus:border-transparent"
            >
              <option value="">Auto-detect</option>
              {agents?.map((agent) => (
                <option key={agent.name} value={agent.name}>
                  {agent.name} - {agent.description}
                </option>
              ))}
            </select>
            <p className="text-xs text-gray-500 mt-2">
              Leave as "Auto-detect" to let the system choose the best agent for your file
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-900">Analysis Failed</p>
                <p className="text-sm text-red-700 mt-1">
                  {error instanceof Error ? error.message : 'An unexpected error occurred'}
                </p>
              </div>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={
              isLoading ||
              (analysisType === 'file' && !selectedFile) ||
              (analysisType === 'url' && !url)
            }
            className="w-full py-3 px-6 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
          >
            {isLoading ? (
              <>
                <div className="inline-block animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Analyzing...
              </>
            ) : (
              'Start Analysis'
            )}
          </button>
        </form>
      </div>

      {/* Supported Formats */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h3 className="font-semibold text-blue-900 mb-3">Supported File Types</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-blue-800">
          <div>
            <p className="font-medium mb-1">Executables</p>
            <p className="text-xs">PE, EXE, DLL, ELF</p>
          </div>
          <div>
            <p className="font-medium mb-1">Documents</p>
            <p className="text-xs">PDF, DOCX, XLSX</p>
          </div>
          <div>
            <p className="font-medium mb-1">Shortcuts</p>
            <p className="text-xs">LNK</p>
          </div>
          <div>
            <p className="font-medium mb-1">Email</p>
            <p className="text-xs">EML, MSG</p>
          </div>
          <div>
            <p className="font-medium mb-1">Memory</p>
            <p className="text-xs">RAW, DMP, VMEM</p>
          </div>
          <div>
            <p className="font-medium mb-1">Network</p>
            <p className="text-xs">IPs, URLs, Domains</p>
          </div>
          <div>
            <p className="font-medium mb-1">Scripts</p>
            <p className="text-xs">JS, VBS, PS1</p>
          </div>
          <div>
            <p className="font-medium mb-1">Logs</p>
            <p className="text-xs">JSON, CSV, TXT</p>
          </div>
        </div>
      </div>
    </div>
  );
}
