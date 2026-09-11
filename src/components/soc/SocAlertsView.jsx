import React, { useState } from 'react';
import {
  ZapFocusIcon,
  FilterIcon,
  CloudIcon,
  MonitorIcon,
  UserIdentityIcon,
} from './SocIcons.jsx';

const INITIAL_ALERTS = [
  {
    id: 'alt-001',
    severity: 'critical',
    source: 'Cloud',
    sourceType: 'cloud',
    time: '0m ago',
    title: 'Unusual outbound traffic to known malicious domain',
    description: 'Large data transfer to suspicious external IP address',
    threat: 'Data Exfiltration',
    assignedTo: null,
  },
  {
    id: 'alt-002',
    severity: 'critical',
    source: 'Cloud',
    sourceType: 'cloud',
    time: '0m ago',
    title: 'Unusual outbound traffic to known malicious domain',
    description: 'Large data transfer to suspicious external IP address',
    threat: 'Data Exfiltration',
    assignedTo: null,
  },
  {
    id: 'alt-003',
    severity: 'medium',
    source: 'Cloud',
    sourceType: 'cloud',
    time: '2h ago',
    title: 'Privilege escalation attempt detected',
    description: 'User account attempting admin-level operations',
    threat: 'DDoS Attempt',
    assignedTo: null,
  },
  {
    id: 'alt-004',
    severity: 'low',
    source: 'Endpoint',
    sourceType: 'endpoint',
    time: '10m ago',
    title: 'Suspicious PowerShell execution detected',
    description: 'Encoded PowerShell script executed with bypass flag',
    threat: 'Data Exfiltration',
    assignedTo: null,
  },
  {
    id: 'alt-005',
    severity: 'low',
    source: 'Endpoint',
    sourceType: 'endpoint',
    time: '10m ago',
    title: 'Suspicious PowerShell execution detected',
    description: 'Encoded PowerShell script executed with bypass flag',
    threat: 'Data Exfiltration',
    assignedTo: null,
  },
  {
    id: 'alt-006',
    severity: 'medium',
    source: 'Cloud',
    sourceType: 'cloud',
    time: '2h ago',
    title: 'Privilege escalation attempt detected',
    description: 'User account attempting admin-level operations',
    threat: 'DDoS Attempt',
    assignedTo: null,
  },
  {
    id: 'alt-007',
    severity: 'critical',
    source: 'Identity',
    sourceType: 'identity',
    time: '1h ago',
    title: 'Unusual outbound traffic to known malicious domain',
    description: 'Large data transfer to suspicious external IP address',
    threat: 'Phishing',
    assignedTo: 'Sarah Chen',
  },
  {
    id: 'alt-008',
    severity: 'high',
    source: 'Endpoint',
    sourceType: 'endpoint',
    time: '1h ago',
    title: 'Anomalous network connection pattern',
    description: 'Connection to known C2 infrastructure detected',
    threat: 'Data Exfiltration',
    assignedTo: 'Sarah Chen',
  },
];

const SEVERITY_CONFIG = {
  critical: {
    border: 'border-[#EF4444] dark:border-[#EF4444]',
    badgeBg: 'bg-rose-500/10 dark:bg-rose-500/15',
    badgeText: 'text-rose-600 dark:text-rose-400',
    badgeBorder: 'border-rose-500/30',
    label: 'CRITICAL',
  },
  high: {
    border: 'border-[#F97316] dark:border-[#F97316]',
    badgeBg: 'bg-orange-500/10 dark:bg-orange-500/15',
    badgeText: 'text-orange-600 dark:text-orange-400',
    badgeBorder: 'border-orange-500/30',
    label: 'HIGH',
  },
  medium: {
    border: 'border-[#EAB308] dark:border-[#EAB308]',
    badgeBg: 'bg-amber-500/10 dark:bg-amber-500/15',
    badgeText: 'text-amber-600 dark:text-amber-400',
    badgeBorder: 'border-amber-500/30',
    label: 'MEDIUM',
  },
  low: {
    border: 'border-[#3B82F6] dark:border-[#3B82F6]',
    badgeBg: 'bg-blue-500/10 dark:bg-blue-500/15',
    badgeText: 'text-blue-600 dark:text-blue-400',
    badgeBorder: 'border-blue-500/30',
    label: 'LOW',
  },
};

const SocAlertsView = () => {
  const [focusMode, setFocusMode] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [selectedSource, setSelectedSource] = useState('All');
  const [openMenuId, setOpenMenuId] = useState(null);

  const filteredAlerts = INITIAL_ALERTS.filter((alt) => {
    if (focusMode && alt.severity !== 'critical' && alt.severity !== 'high') {
      return false;
    }
    if (selectedSeverity !== 'All' && alt.severity.toLowerCase() !== selectedSeverity.toLowerCase()) {
      return false;
    }
    if (selectedSource !== 'All' && alt.source.toLowerCase() !== selectedSource.toLowerCase()) {
      return false;
    }
    return true;
  });

  const getSourceIcon = (type) => {
    if (type === 'cloud') return <CloudIcon className="w-3.5 h-3.5" />;
    if (type === 'endpoint') return <MonitorIcon className="w-3.5 h-3.5" />;
    return <UserIdentityIcon className="w-3.5 h-3.5" />;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Focus Mode & Filter Dropdowns matching Figma */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs transition-colors">
        {/* Focus Mode Switch */}
        <div className="flex items-center space-x-4">
          <div className="w-9 h-9 rounded-xl bg-gray-100 dark:bg-[#23252A] flex items-center justify-center text-gray-700 dark:text-gray-200 shrink-0">
            <ZapFocusIcon className="w-5 h-5 text-amber-500" />
          </div>

          <div>
            <div className="flex items-center space-x-3">
              <span className="text-sm font-bold text-gray-900 dark:text-white">
                Focus Mode
              </span>
              {/* Toggle Switch */}
              <button
                onClick={() => setFocusMode(!focusMode)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors cursor-pointer ${
                  focusMode ? 'bg-blue-600' : 'bg-gray-300 dark:bg-[#2E3038]'
                }`}
                role="switch"
                aria-checked={focusMode}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    focusMode ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              Show only critical & high severity alerts
            </p>
          </div>
        </div>

        {/* Filters Dropdowns */}
        <div className="flex items-center space-x-3 self-end md:self-auto">
          <div className="flex items-center space-x-2 text-xs font-semibold text-gray-500 dark:text-gray-400">
            <FilterIcon className="w-3.5 h-3.5" />
            <span>Filters:</span>
          </div>

          {/* Severities filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="text-xs font-medium bg-gray-100 dark:bg-[#23252A] border border-gray-200 dark:border-[#2E3038] text-gray-800 dark:text-gray-200 rounded-xl px-3 py-2 outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="All">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Sources filter */}
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="text-xs font-medium bg-gray-100 dark:bg-[#23252A] border border-gray-200 dark:border-[#2E3038] text-gray-800 dark:text-gray-200 rounded-xl px-3 py-2 outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="All">All Sources</option>
            <option value="cloud">Cloud</option>
            <option value="endpoint">Endpoint</option>
            <option value="identity">Identity</option>
          </select>
        </div>
      </div>

      {/* Section Heading */}
      <div className="flex items-center justify-between">
        <div className="flex items-baseline space-x-2">
          <h2 className="text-xl font-extrabold text-gray-900 dark:text-white tracking-tight">
            Active Alerts
          </h2>
          <span className="text-xs font-semibold text-gray-500 dark:text-gray-400">
            {filteredAlerts.length} alerts
          </span>
        </div>
      </div>

      {/* Alert Cards Grid matching soc_alert_1.png */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {filteredAlerts.map((alert) => {
          const cfg = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.low;
          const isMenuOpen = openMenuId === alert.id;

          return (
            <div
              key={alert.id}
              className={`bg-white dark:bg-[#18191D] border ${cfg.border} rounded-2xl p-5 shadow-xs transition-all relative flex flex-col justify-between`}
            >
              <div>
                {/* Header row: Badge, Source, Time, 3-dots */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[11px] font-extrabold tracking-wider border ${cfg.badgeBg} ${cfg.badgeText} ${cfg.badgeBorder}`}
                    >
                      {cfg.label}
                    </span>

                    <div className="flex items-center space-x-1.5 text-xs text-gray-500 dark:text-gray-400 font-medium">
                      {getSourceIcon(alert.sourceType)}
                      <span>{alert.source}</span>
                    </div>

                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      {alert.time}
                    </span>
                  </div>

                  {/* 3-dots context menu trigger */}
                  <div className="relative">
                    <button
                      onClick={() => setOpenMenuId(isMenuOpen ? null : alert.id)}
                      className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-[#23252A] cursor-pointer"
                      aria-label="Alert actions"
                    >
                      <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" />
                      </svg>
                    </button>

                    {/* Popout menu matching Figma (Assign, Investigate, Update Status, Dismiss) */}
                    {isMenuOpen && (
                      <div className="absolute right-0 top-8 w-36 bg-white dark:bg-[#23252A] border border-gray-200 dark:border-[#323D4E] rounded-xl shadow-xl z-20 py-1.5 text-xs font-semibold text-gray-800 dark:text-gray-200">
                        <button
                          onClick={() => {
                            alert(`Assigning ${alert.id}`);
                            setOpenMenuId(null);
                          }}
                          className="w-full text-left px-3.5 py-2 hover:bg-gray-100 dark:hover:bg-[#2E3038] cursor-pointer"
                        >
                          Assign
                        </button>
                        <button
                          onClick={() => {
                            alert(`Opening investigation for ${alert.id}`);
                            setOpenMenuId(null);
                          }}
                          className="w-full text-left px-3.5 py-2 hover:bg-gray-100 dark:hover:bg-[#2E3038] cursor-pointer"
                        >
                          Investigate
                        </button>
                        <button
                          onClick={() => {
                            alert(`Updating status for ${alert.id}`);
                            setOpenMenuId(null);
                          }}
                          className="w-full text-left px-3.5 py-2 hover:bg-gray-100 dark:hover:bg-[#2E3038] cursor-pointer"
                        >
                          Update Status
                        </button>
                        <button
                          onClick={() => {
                            alert(`Dismissing ${alert.id}`);
                            setOpenMenuId(null);
                          }}
                          className="w-full text-left px-3.5 py-2 text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/20 cursor-pointer"
                        >
                          Dismiss
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* Alert Title & Description */}
                <div className="mt-3">
                  <h4 className="text-sm font-bold text-gray-900 dark:text-white leading-snug">
                    {alert.title}
                  </h4>
                  <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 leading-normal">
                    {alert.description}
                  </p>
                </div>
              </div>

              {/* Threat Tag & Assignee Footer */}
              <div className="mt-4 pt-3 border-t border-gray-100 dark:border-[#2A2C34] flex items-center justify-between text-xs">
                <div className="flex items-center space-x-1.5">
                  <span className="text-gray-400 dark:text-gray-500 font-medium">Threat:</span>
                  <span className="px-2 py-0.5 rounded-md bg-gray-100 dark:bg-[#23252A] text-gray-800 dark:text-gray-200 font-semibold text-[11px]">
                    {alert.threat}
                  </span>
                </div>

                {alert.assignedTo && (
                  <div className="flex items-center space-x-1.5 text-gray-500 dark:text-gray-400">
                    <span>Assigned to:</span>
                    <span className="font-semibold text-gray-800 dark:text-gray-200">
                      {alert.assignedTo}
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SocAlertsView;
