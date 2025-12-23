import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Search, Filter, ChevronRight, Clock, CheckCircle, XCircle, Loader } from 'lucide-react';
import { apiService } from '../services/api';

export default function JobsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const { data: jobs, isLoading, refetch } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => apiService.getJobs(),
    refetchInterval: 5000, // Refetch every 5 seconds to update running jobs
  });

  const filteredJobs = jobs?.filter((job) => {
    const matchesSearch = job.artifact_name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || job.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'running':
        return <Loader className="w-5 h-5 text-yellow-600 animate-spin" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-600" />;
      default:
        return <Clock className="w-5 h-5 text-blue-600" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const classes = {
      completed: 'bg-green-100 text-green-800',
      running: 'bg-yellow-100 text-yellow-800',
      pending: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
    };

    return (
      <span
        className={`px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
          classes[status as keyof typeof classes] || 'bg-gray-100 text-gray-800'
        }`}
      >
        {status}
      </span>
    );
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Analysis Jobs</h1>
        <p className="text-gray-600 mt-2">View and manage all security analyses</p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search by filename..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-600 focus:border-transparent"
            />
          </div>

          {/* Status Filter */}
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-600 focus:border-transparent appearance-none"
            >
              <option value="all">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="pending">Pending</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-600">Total Jobs</p>
          <p className="text-2xl font-bold text-gray-900">{jobs?.length || 0}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-600">Completed</p>
          <p className="text-2xl font-bold text-green-600">
            {jobs?.filter((j) => j.status === 'completed').length || 0}
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-600">Running</p>
          <p className="text-2xl font-bold text-yellow-600">
            {jobs?.filter((j) => j.status === 'running').length || 0}
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-600">Failed</p>
          <p className="text-2xl font-bold text-red-600">
            {jobs?.filter((j) => j.status === 'failed').length || 0}
          </p>
        </div>
      </div>

      {/* Jobs List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {filteredJobs && filteredJobs.length > 0 ? (
          <div className="divide-y divide-gray-200">
            {filteredJobs.map((job) => (
              <Link
                key={job.job_id}
                to={`/jobs/${job.job_id}`}
                className="block hover:bg-gray-50 transition-colors"
              >
                <div className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 flex-1">
                      {getStatusIcon(job.status)}
                      <div className="flex-1 min-w-0">
                        <p className="text-lg font-medium text-gray-900 truncate">
                          {job.artifact_name}
                        </p>
                        <div className="flex items-center gap-4 mt-1">
                          <p className="text-sm text-gray-500">
                            Agent: <span className="font-medium">{job.agent_type}</span>
                          </p>
                          <p className="text-sm text-gray-500">
                            Created: {new Date(job.created_at).toLocaleString()}
                          </p>
                          {job.completed_at && (
                            <p className="text-sm text-gray-500">
                              Completed: {new Date(job.completed_at).toLocaleString()}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {getStatusBadge(job.status)}
                      <ChevronRight className="w-5 h-5 text-gray-400" />
                    </div>
                  </div>
                  {job.error && (
                    <div className="mt-3 text-sm text-red-600 bg-red-50 rounded p-3">
                      Error: {job.error}
                    </div>
                  )}
                </div>
              </Link>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-gray-500">
              {searchTerm || statusFilter !== 'all'
                ? 'No jobs match your filters'
                : 'No analysis jobs yet. Start by uploading a file!'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
