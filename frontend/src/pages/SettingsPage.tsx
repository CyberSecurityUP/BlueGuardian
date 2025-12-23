import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Settings, DollarSign, Shield, Zap, Database } from 'lucide-react';
import { apiService } from '../services/api';

export default function SettingsPage() {
  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: () => apiService.getStatus(),
  });

  const { data: costs } = useQuery({
    queryKey: ['costs'],
    queryFn: () => apiService.getCosts(),
  });

  const { data: agents } = useQuery({
    queryKey: ['agents'],
    queryFn: () => apiService.getAgents(),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-600 mt-2">System configuration and status</p>
      </div>

      {/* System Status */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="w-6 h-6 text-blue-600" />
          <h2 className="text-xl font-semibold text-gray-900">System Status</h2>
        </div>

        {status ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-blue-50 rounded-lg p-4">
              <p className="text-sm text-blue-600 font-medium mb-2">Status</p>
              <p className="text-2xl font-bold text-blue-900 capitalize">{status.status}</p>
            </div>
            <div className="bg-green-50 rounded-lg p-4">
              <p className="text-sm text-green-600 font-medium mb-2">Agents Available</p>
              <p className="text-2xl font-bold text-green-900">{status.agents_available}</p>
            </div>
            <div className="bg-purple-50 rounded-lg p-4">
              <p className="text-sm text-purple-600 font-medium mb-2">Consensus Mode</p>
              <p className="text-2xl font-bold text-purple-900">
                {status.consensus_enabled ? 'Enabled' : 'Disabled'}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        )}
      </div>

      {/* AI Providers */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-6">
          <Zap className="w-6 h-6 text-yellow-600" />
          <h2 className="text-xl font-semibold text-gray-900">AI Providers</h2>
        </div>

        {status && status.ai_providers && status.ai_providers.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {status.ai_providers.map((provider, index) => (
              <div
                key={index}
                className="bg-gradient-to-br from-yellow-50 to-orange-50 rounded-lg p-4 border border-yellow-200"
              >
                <div className="flex items-center justify-between">
                  <p className="font-semibold text-gray-900">{provider}</p>
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                </div>
                <p className="text-xs text-gray-600 mt-2">Active</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500">No AI providers configured</p>
        )}

        {status?.consensus_enabled && (
          <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <p className="text-sm text-blue-900 font-medium">
              Multi-model consensus is enabled
            </p>
            <p className="text-xs text-blue-700 mt-1">
              Analyses use multiple AI models for improved accuracy and hallucination prevention
            </p>
          </div>
        )}
      </div>

      {/* Available Agents */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-6">
          <Database className="w-6 h-6 text-green-600" />
          <h2 className="text-xl font-semibold text-gray-900">Analysis Agents</h2>
        </div>

        {agents && agents.length > 0 ? (
          <div className="space-y-4">
            {agents.map((agent, index) => (
              <div
                key={index}
                className="bg-gray-50 rounded-lg p-4 border border-gray-200"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-semibold text-gray-900">{agent.name}</h3>
                    <p className="text-sm text-gray-600 mt-1">{agent.description}</p>
                    {agent.supported_formats && agent.supported_formats.length > 0 && (
                      <div className="flex flex-wrap gap-2 mt-3">
                        {agent.supported_formats.map((format, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs font-mono"
                          >
                            {format}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="w-2 h-2 bg-green-500 rounded-full flex-shrink-0 mt-1"></div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        )}
      </div>

      {/* Cost Tracking */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-3 mb-6">
          <DollarSign className="w-6 h-6 text-green-600" />
          <h2 className="text-xl font-semibold text-gray-900">API Cost Tracking</h2>
        </div>

        {costs ? (
          <>
            <div className="bg-green-50 rounded-lg p-6 mb-6">
              <p className="text-sm text-green-600 font-medium mb-2">Total API Cost</p>
              <p className="text-4xl font-bold text-green-900">
                ${costs.total_cost.toFixed(4)}
              </p>
            </div>

            {costs.costs_by_provider && Object.keys(costs.costs_by_provider).length > 0 && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Cost by Provider</h3>
                <div className="space-y-3">
                  {Object.entries(costs.costs_by_provider).map(([provider, cost]) => (
                    <div
                      key={provider}
                      className="flex items-center justify-between bg-gray-50 rounded-lg p-4"
                    >
                      <span className="font-medium text-gray-900">{provider}</span>
                      <span className="text-lg font-semibold text-gray-900">
                        ${cost.toFixed(4)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        )}
      </div>

      {/* Configuration Info */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <div className="flex items-center gap-3 mb-4">
          <Settings className="w-5 h-5 text-blue-600" />
          <h3 className="font-semibold text-blue-900">Configuration</h3>
        </div>
        <div className="space-y-2 text-sm text-blue-800">
          <p>
            <span className="font-medium">Environment:</span> Production
          </p>
          <p>
            <span className="font-medium">Version:</span> 1.0.0
          </p>
          <p>
            <span className="font-medium">API Endpoint:</span>{' '}
            {import.meta.env.VITE_API_URL || '/api/v1'}
          </p>
        </div>
      </div>

      {/* Features */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Features</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FeatureCard
            title="Multi-Model Analysis"
            description="Leverage multiple AI models for robust threat detection"
            enabled={status?.consensus_enabled || false}
          />
          <FeatureCard
            title="MITRE ATT&CK Mapping"
            description="Automatic mapping to MITRE ATT&CK framework"
            enabled={true}
          />
          <FeatureCard
            title="IOC Extraction"
            description="Automated extraction of indicators of compromise"
            enabled={true}
          />
          <FeatureCard
            title="Threat Intelligence"
            description="Integration with VirusTotal, OTX, and Hybrid Analysis"
            enabled={true}
          />
          <FeatureCard
            title="Memory Forensics"
            description="Volatility 3 integration for memory analysis"
            enabled={true}
          />
          <FeatureCard
            title="SIEM Integration"
            description="Splunk, ELK, Azure Sentinel, and Syslog support"
            enabled={true}
          />
        </div>
      </div>
    </div>
  );
}

interface FeatureCardProps {
  title: string;
  description: string;
  enabled: boolean;
}

function FeatureCard({ title, description, enabled }: FeatureCardProps) {
  return (
    <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="font-semibold text-gray-900">{title}</h3>
          <p className="text-sm text-gray-600 mt-1">{description}</p>
        </div>
        <div
          className={`w-3 h-3 rounded-full flex-shrink-0 mt-1 ${
            enabled ? 'bg-green-500' : 'bg-gray-300'
          }`}
        ></div>
      </div>
    </div>
  );
}
