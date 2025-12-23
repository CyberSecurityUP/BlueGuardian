import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { AlertTriangle, CheckCircle, XCircle, Clock, Shield, TrendingUp } from 'lucide-react';
import { api } from '../services/api';

const VERDICT_COLORS = {
  malicious: '#dc3545',
  suspicious: '#ffc107',
  clean: '#28a745',
  unknown: '#6c757d',
};

export default function Dashboard() {
  const { data: jobs, isLoading } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api.getJobs(),
  });

  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: () => api.getStatus(),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  // Calculate statistics
  const stats = {
    total: jobs?.length || 0,
    completed: jobs?.filter((j: any) => j.status === 'completed').length || 0,
    running: jobs?.filter((j: any) => j.status === 'running').length || 0,
    failed: jobs?.filter((j: any) => j.status === 'failed').length || 0,
  };

  // Verdict distribution for completed jobs
  const completedJobs = jobs?.filter((j: any) => j.status === 'completed') || [];
  const verdictData = [
    { name: 'Malicious', value: 0, color: VERDICT_COLORS.malicious },
    { name: 'Suspicious', value: 0, color: VERDICT_COLORS.suspicious },
    { name: 'Clean', value: 0, color: VERDICT_COLORS.clean },
    { name: 'Unknown', value: 0, color: VERDICT_COLORS.unknown },
  ];

  // Agent usage statistics
  const agentStats: any = {};
  jobs?.forEach((job: any) => {
    agentStats[job.agent_type] = (agentStats[job.agent_type] || 0) + 1;
  });

  const agentData = Object.entries(agentStats).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600 mt-2">Real-time security analysis overview</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Analyses"
          value={stats.total}
          icon={Shield}
          color="blue"
        />
        <StatCard
          title="Completed"
          value={stats.completed}
          icon={CheckCircle}
          color="green"
        />
        <StatCard
          title="Running"
          value={stats.running}
          icon={Clock}
          color="yellow"
        />
        <StatCard
          title="Failed"
          value={stats.failed}
          icon={XCircle}
          color="red"
        />
      </div>

      {/* System Status */}
      {status && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">System Status</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <p className="text-sm text-gray-600">AI Providers</p>
              <p className="text-2xl font-bold text-gray-900">{status.ai_providers?.length || 0}</p>
              <p className="text-xs text-gray-500 mt-1">
                {status.ai_providers?.join(', ')}
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Agents Available</p>
              <p className="text-2xl font-bold text-gray-900">{status.agents_available || 0}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Consensus Enabled</p>
              <p className="text-2xl font-bold text-gray-900">
                {status.consensus_enabled ? '✓' : '✗'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Agent Usage Chart */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Agent Usage</h2>
          {agentData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={agentData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              No data available
            </div>
          )}
        </div>

        {/* Verdict Distribution */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Verdict Distribution</h2>
          {verdictData.some((d) => d.value > 0) ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={verdictData.filter((d) => d.value > 0)}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label
                >
                  {verdictData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              No completed analyses yet
            </div>
          )}
        </div>
      </div>

      {/* Recent Jobs */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Analyses</h2>
        {jobs && jobs.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Artifact
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Agent
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Created
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {jobs.slice(0, 10).map((job: any) => (
                  <tr key={job.job_id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {job.artifact_name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {job.agent_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <StatusBadge status={job.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(job.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            No analyses yet. Start by uploading a file!
          </div>
        )}
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: number;
  icon: any;
  color: 'blue' | 'green' | 'yellow' | 'red';
}

function StatCard({ title, value, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    yellow: 'bg-yellow-100 text-yellow-600',
    red: 'bg-red-100 text-red-600',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colorClasses = {
    completed: 'bg-green-100 text-green-800',
    running: 'bg-yellow-100 text-yellow-800',
    pending: 'bg-blue-100 text-blue-800',
    failed: 'bg-red-100 text-red-800',
  };

  return (
    <span
      className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
        colorClasses[status as keyof typeof colorClasses] || 'bg-gray-100 text-gray-800'
      }`}
    >
      {status}
    </span>
  );
}
