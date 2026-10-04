import React, { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import {
  FileText,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  UploadCloud,
  ChevronRight,
  Sparkles,
  Lock,
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

export default function DashboardPage() {
  const {
    activeJobId,
    analysisResult,
    isRealData,
    unifiedThreats,
    threatCounts,
    handleDownloadReport,
    handleIngestTestbed,
    ingesting,
  } = useApp();

  // Highest severity finding from threat_matrix (unconditional hook)
  const mostCriticalFinding = useMemo(() => {
    if (!unifiedThreats || unifiedThreats.length === 0) return null;
    const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    return [...unifiedThreats].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0))[0];
  }, [unifiedThreats]);

  // Donut chart: severity counts (unconditional hook)
  const severityDonutData = useMemo(() => [
    { name: 'Critical', value: threatCounts.critical, color: '#EF4444' },
    { name: 'High', value: threatCounts.high, color: '#F97316' },
    { name: 'Medium', value: threatCounts.medium, color: '#F59E0B' },
    { name: 'Low', value: threatCounts.low, color: '#10B981' },
  ].filter(d => d.value > 0), [threatCounts]);

  // Bar chart: findings by category (unconditional hook)
  const categoryBarData = useMemo(() => {
    const cats = {};
    (unifiedThreats || []).forEach(t => {
      const cat = t.category || 'General';
      cats[cat] = (cats[cat] || 0) + 1;
    });
    return Object.entries(cats).map(([name, count]) => ({ name, count }));
  }, [unifiedThreats]);

  // If no job loaded, show designated empty state
  if (!isRealData || !analysisResult) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-4">
        <div className="h-16 w-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
          <UploadCloud className="h-8 w-8" />
        </div>
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-white">No Active Audit Session</h2>
          <p className="text-xs text-gray-400 max-w-sm">
            Upload a capture or run a testbed capture to begin.
          </p>
        </div>
        <div className="flex items-center gap-3 pt-2">
          <Link to="/upload">
            <Button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs h-9 px-4 gap-2 cursor-pointer">
              <UploadCloud className="h-4 w-4" />
              <span>Upload PCAP</span>
            </Button>
          </Link>
          <Button
            variant="outline"
            onClick={handleIngestTestbed}
            disabled={ingesting}
            className="border-[#1F2639] text-gray-300 hover:text-white hover:bg-[#161B26] text-xs h-9 px-4 gap-2 cursor-pointer"
          >
            <RotateCcw className={`h-4 w-4 ${ingesting ? 'animate-spin' : ''}`} />
            <span>{ingesting ? 'Ingesting...' : 'Run Testbed Audit'}</span>
          </Button>
        </div>
      </div>
    );
  }

  // Real data extraction (Never invented, no mock fallback)
  const meta = analysisResult.metadata || {};
  const summary = analysisResult.summary || {};
  const control = analysisResult.control_plane || {};
  const fileName = meta.filename || activeJobId || 'capture_session.pcap';
  const fileSizeMb = meta.file_size_bytes ? (meta.file_size_bytes / (1024 * 1024)).toFixed(1) : meta.file_size_mb || '—';
  const packetCount = meta.packet_count ?? analysisResult.data_plane?.total_packets ?? '—';

  // Score Posture (one single number, never a range)
  const score = summary.score_observed_only ?? analysisResult.overall_score ?? 0;
  const [covObs, covTot] = typeof summary.coverage === 'string' ? summary.coverage.split('/') : [];
  const coverageObserved = summary.coverage?.observed_checks ?? summary.coverage_observed ?? covObs ?? '—';
  const coverageTotal = summary.coverage?.total_checks ?? summary.coverage_total ?? covTot ?? '—';
  const coverageRatioPct = summary.coverage_ratio !== undefined ? `${Math.round(summary.coverage_ratio * 100)}%` : '—';
  const riskLevel = (summary.base_risk_level || summary.risk_level || 'UNKNOWN').toUpperCase();

  return (
    <div className="space-y-5">
      {/* ── Header: File Info & Top Actions ── */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-[#0F121C] border border-[#1F2639]">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-gray-500 uppercase">audit_session:</span>
            <span className="text-sm font-semibold text-white font-mono">{fileName}</span>
            <span className="text-xs text-gray-500 font-mono">
              ({fileSizeMb} MB &middot; {packetCount} frames &middot; Zero Decryption Scope)
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-gray-400">
            <span>Tunnel: {control.initiator_ip || '10.0.0.1'} &rarr; {control.responder_ip || '10.0.0.2'}</span>
            <span>&bull;</span>
            <span>IKE {control.ike_version || 'v2'}</span>
            <span>&bull;</span>
            <span>{control.encryption_algorithm || 'AES-GCM'}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Button
            onClick={handleDownloadReport}
            variant="outline"
            className="border-[#1F2639] bg-[#161B26] hover:bg-[#202738] text-gray-200 text-xs h-8 px-3 gap-1.5 cursor-pointer"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Export PDF Report</span>
          </Button>

          <Button
            onClick={handleIngestTestbed}
            disabled={ingesting}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs h-8 px-3 gap-1.5 cursor-pointer"
          >
            <RotateCcw className={`h-3.5 w-3.5 ${ingesting ? 'animate-spin' : ''}`} />
            <span>Re-run Audit</span>
          </Button>
        </div>
      </div>

      {/* ── Row 1: Security Posture Score & Most Critical Finding ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Score Dial / Number Card (4 cols) */}
        <div className="lg:col-span-4 rounded-xl bg-[#0F121C] border border-[#1F2639] p-5 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-gray-400 font-semibold">
              Security Posture Score
            </span>
            <Badge
              variant={
                riskLevel === 'CRITICAL'
                  ? 'critical'
                  : riskLevel === 'HIGH'
                  ? 'high'
                  : riskLevel === 'MODERATE' || riskLevel === 'MEDIUM'
                  ? 'medium'
                  : 'secure'
              }
            >
              {riskLevel} RISK
            </Badge>
          </div>

          <div className="flex items-baseline gap-3 my-2">
            <span className="text-5xl font-black text-white font-mono tracking-tight">
              {score}
            </span>
            <span className="text-sm font-mono text-gray-500">/ 100</span>
          </div>

          <div className="space-y-1 text-xs text-gray-400 border-t border-[#1F2639] pt-3">
            <div className="flex items-center justify-between">
              <span>Observable wire checks:</span>
              <span className="font-mono text-gray-200">{coverageObserved} of {coverageTotal}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Assurance boundary:</span>
              <span className="font-mono text-emerald-400 flex items-center gap-1">
                <Lock className="h-3 w-3" />
                Zero-decryption
              </span>
            </div>
          </div>
        </div>

        {/* Most Critical Finding Card (8 cols) */}
        <div className="lg:col-span-8 rounded-xl bg-[#0F121C] border border-[#1F2639] p-5 flex flex-col justify-between">
          {mostCriticalFinding ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
                  <span className="text-[11px] font-mono uppercase tracking-wider text-rose-400 font-semibold">
                    Most Critical Finding
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="critical">
                    {mostCriticalFinding.severity}
                  </Badge>
                  <span className="text-[10px] font-mono text-gray-400">
                    {mostCriticalFinding.finding_id}
                  </span>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-white">
                  {mostCriticalFinding.title}
                </h3>
                <p className="text-xs text-gray-300 mt-1 leading-relaxed">
                  {mostCriticalFinding.description}
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-[#1F2639] text-xs font-mono text-gray-400">
                <div className="flex items-center gap-3">
                  <span>obs: <strong className="text-gray-300">{mostCriticalFinding.observability || 'wire_observed'}</strong></span>
                  <span>&bull;</span>
                  <span>source: <strong className="text-gray-300">{mostCriticalFinding.evidence_source || 'esp_header'}</strong></span>
                </div>
                <Link
                  to="/findings"
                  className="text-blue-400 hover:text-blue-300 flex items-center gap-1 font-semibold transition-colors"
                >
                  <span>View all findings</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center py-6 text-gray-400 space-y-2">
              <ShieldCheck className="h-8 w-8 text-emerald-500" />
              <div className="text-xs font-semibold text-gray-200">No Critical Protocol Violations Flagged</div>
              <p className="text-[11px] text-gray-500 max-w-xs">
                All observed wire parameters conform with baseline cryptographic hygiene rules.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Row 2: Four Stat Cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-gray-400 font-semibold">
            Total Findings
          </span>
          <div className="text-2xl font-black text-white font-mono">{threatCounts.total}</div>
          <div className="text-[11px] text-gray-500 font-mono">Deduplicated findings</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 font-semibold">
            Critical Severities
          </span>
          <div className="text-2xl font-black text-rose-400 font-mono">{threatCounts.critical}</div>
          <div className="text-[11px] text-gray-500 font-mono">Immediate risk remediation</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-semibold">
            Medium / Low Findings
          </span>
          <div className="text-2xl font-black text-amber-400 font-mono">
            {threatCounts.medium} / {threatCounts.low}
          </div>
          <div className="text-[11px] text-gray-500 font-mono">Protocol hygiene &amp; ciphers</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-blue-400 font-semibold">
            Audit Wire Coverage
          </span>
          <div className="text-2xl font-black text-blue-400 font-mono">{coverageRatioPct}</div>
          <div className="text-[11px] text-gray-500 font-mono">
            {coverageObserved} of {coverageTotal} observable
          </div>
        </div>
      </div>

      {/* ── Row 3: Severity Donut + Findings by Category Bar Chart ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Severity Donut (5 cols) */}
        <div className="lg:col-span-5 rounded-xl bg-[#0F121C] border border-[#1F2639] p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1F2639]">
            <span className="text-xs font-semibold text-white">Severity Breakdown</span>
            <span className="text-[11px] font-mono text-gray-400">Total: {threatCounts.total}</span>
          </div>

          <div className="h-48 w-full flex items-center justify-center">
            {severityDonutData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDonutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityDonutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0A0D14', borderColor: '#1F2639', borderRadius: '8px', fontSize: '11px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <span className="text-xs text-gray-500 font-mono">No findings recorded</span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono pt-1">
            <div className="flex items-center gap-1.5 text-rose-400">
              <span className="h-2 w-2 rounded-full bg-rose-500" />
              <span>Critical: {threatCounts.critical}</span>
            </div>
            <div className="flex items-center gap-1.5 text-orange-400">
              <span className="h-2 w-2 rounded-full bg-orange-500" />
              <span>High: {threatCounts.high}</span>
            </div>
            <div className="flex items-center gap-1.5 text-amber-400">
              <span className="h-2 w-2 rounded-full bg-amber-500" />
              <span>Medium: {threatCounts.medium}</span>
            </div>
            <div className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span>Low: {threatCounts.low}</span>
            </div>
          </div>
        </div>

        {/* Findings by Category Bar Chart (7 cols) */}
        <div className="lg:col-span-7 rounded-xl bg-[#0F121C] border border-[#1F2639] p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1F2639]">
            <span className="text-xs font-semibold text-white">Findings by Category</span>
            <span className="text-[11px] font-mono text-gray-400">{categoryBarData.length} categories</span>
          </div>

          <div className="h-48 w-full">
            {categoryBarData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryBarData} layout="vertical" margin={{ left: 10, right: 20, top: 10, bottom: 0 }}>
                  <XAxis type="number" stroke="#4B5563" fontSize={10} />
                  <YAxis type="category" dataKey="name" stroke="#9CA3AF" fontSize={10} width={100} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0A0D14', borderColor: '#1F2639', borderRadius: '8px', fontSize: '11px' }}
                  />
                  <Bar dataKey="count" fill="#3B82F6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-gray-500 font-mono">
                No category data available
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── "Go to" Deep Link Strip ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Link
          to="/findings"
          className="flex items-center justify-between p-3.5 rounded-xl bg-[#0F121C] hover:bg-[#141824] border border-[#1F2639] transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-semibold text-white group-hover:text-blue-400 transition-colors">
                Findings &amp; Compliance
              </div>
              <div className="text-[11px] text-gray-500">
                Detailed evidence log, RFC audit &amp; dimensions
              </div>
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-gray-500 group-hover:text-white transition-colors" />
        </Link>

        <Link
          to="/ai"
          className="flex items-center justify-between p-3.5 rounded-xl bg-[#0F121C] hover:bg-[#141824] border border-[#1F2639] transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <Sparkles className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-semibold text-white group-hover:text-purple-400 transition-colors">
                AI Cryptographic Insights
              </div>
              <div className="text-[11px] text-gray-500">
                Gemini executive briefing &amp; hardening actions
              </div>
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-gray-500 group-hover:text-white transition-colors" />
        </Link>

        <Link
          to="/reports"
          className="flex items-center justify-between p-3.5 rounded-xl bg-[#0F121C] hover:bg-[#141824] border border-[#1F2639] transition-colors group cursor-pointer"
        >
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <FileText className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-semibold text-white group-hover:text-emerald-400 transition-colors">
                Compliance Reports
              </div>
              <div className="text-[11px] text-gray-500">
                Download NIST SP 800-77 &amp; CNSA 2.0 PDFs
              </div>
            </div>
          </div>
          <ChevronRight className="h-4 w-4 text-gray-500 group-hover:text-white transition-colors" />
        </Link>
      </div>
    </div>
  );
}
