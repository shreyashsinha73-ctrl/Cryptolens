import React, { useState, useEffect } from 'react';
import { ThemeProvider } from './context/ThemeContext.jsx';
import SocSidebar from './components/soc/SocSidebar.jsx';
import SocHeader from './components/soc/SocHeader.jsx';
import SocMetricCards from './components/soc/SocMetricCards.jsx';
import SocAlertVolumeTrend from './components/soc/SocAlertVolumeTrend.jsx';
import SocSeverityDistribution from './components/soc/SocSeverityDistribution.jsx';
import SocAlertsView from './components/soc/SocAlertsView.jsx';
import SocDesignSystemView from './components/soc/SocDesignSystemView.jsx';
import PerTunnelBreakdown from './components/PerTunnelBreakdown.jsx';
import ScoreDial from './components/ScoreDial.jsx';
import AnalysisDimensions from './components/dashboard/AnalysisDimensions.jsx';
import ComplianceRadar from './components/dashboard/ComplianceRadar.jsx';
import TrafficDistribution from './components/dashboard/TrafficDistribution.jsx';
import AiTelemetryCard from './components/dashboard/AiTelemetryCard.jsx';
import LiveTelemetryPanel from './components/dashboard/LiveTelemetryPanel.jsx';
import ThreatHeatmap from './components/dashboard/ThreatHeatmap.jsx';
import RemediationModal from './components/dashboard/RemediationModal.jsx';

// ── Empty state shown before any PCAP is uploaded ──────────────────────────
const EmptyState = ({ onUploadPcap, uploading }) => {
  const fileRef = React.useRef(null);
  return (
    <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
      <div className="w-16 h-16 rounded-2xl bg-blue-500/10 dark:bg-blue-500/15 flex items-center justify-center mb-4">
        <svg className="w-8 h-8 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      </div>
      <h2 className="text-xl font-extrabold text-gray-900 dark:text-white mb-1.5">
        Upload Offline PCAP Capture
      </h2>
      <p className="text-xs text-gray-500 dark:text-gray-400 max-w-md mb-6 leading-relaxed">
        Upload an existing <code>.pcap</code> or <code>.pcapng</code> file to perform comprehensive control-plane AST validation, data-plane CNN inference, and NIST/CNSA compliance auditing.
      </p>
      <input
        type="file"
        ref={fileRef}
        accept=".pcap,.pcapng,.cap"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onUploadPcap(f);
        }}
      />
      <button
        onClick={() => fileRef.current?.click()}
        disabled={uploading}
        className={`inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-bold transition-all shadow-xs cursor-pointer ${uploading
            ? 'bg-blue-400/50 text-white animate-pulse'
            : 'bg-blue-600 hover:bg-blue-700 text-white'
          }`}
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
        </svg>
        {uploading ? 'Analyzing…' : 'Upload PCAP / PCAPNG'}
      </button>
    </div>
  );
};

// ── Analysing spinner ────────────────────────────────────────────────────────
const AnalysingState = ({ jobId }) => (
  <div className="flex flex-col items-center justify-center py-24 px-6 text-center">
    <div className="w-16 h-16 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mb-6" />
    <h2 className="text-xl font-extrabold text-gray-900 dark:text-white mb-2">Loading Capture Assessment…</h2>
    <p className="text-xs text-gray-500 dark:text-gray-400">
      Job <code className="font-mono font-bold">{jobId || 'Loading'}</code> is processing.
    </p>
  </div>
);

function MainSocApp() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [activeJobId, setActiveJobId] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [uploadError, setUploadError] = useState(null);
  const [ingesting, setIngesting] = useState(false);
  const [remediationOpen, setRemediationOpen] = useState(false);

  // Poll backend for job status
  useEffect(() => {
    if (!activeJobId) return;
    let subscribed = true;

    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/v1/results/${activeJobId}`);
        if (res.ok) {
          const payload = await res.json();
          if (payload.status === 'completed') {
            if (subscribed) { setAnalysisResult(payload); setUploading(false); }
            return true;
          } else if (payload.status === 'failed') {
            if (subscribed) { setUploadError(payload.error?.message || 'Analysis failed'); setUploading(false); }
            return true;
          }
        }
      } catch (e) { console.error('Poll error:', e); }
      return false;
    };

    fetchStatus().then(shouldStop => {
      if (!shouldStop && subscribed) {
        const interval = setInterval(async () => {
          const stop = await fetchStatus();
          if (stop) clearInterval(interval);
        }, 1500);
        return () => clearInterval(interval);
      }
    });

    return () => { subscribed = false; };
  }, [activeJobId]);

  const handleUploadPcap = async (file) => {
    setUploading(true);
    setUploadError(null);
    setAnalysisResult(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const res = await fetch('/api/v1/analyze', { method: 'POST', body: form });
      if (!res.ok) {
        let msg = 'Failed to submit PCAP for analysis';
        try { const e = await res.json(); msg = e.detail?.message || e.detail || e.message || msg; }
        catch {
          msg = res.status === 502 || res.status === 504
            ? 'Backend API unreachable (502). Run: .venv/bin/python -m uvicorn backend.main:app --port 8000'
            : `Server error ${res.status}`;
        }
        throw new Error(msg);
      }
      const { job_id } = await res.json();
      setActiveJobId(job_id);
    } catch (e) { setUploadError(e.message); setUploading(false); }
  };

  const handleIngestTestbed = async () => {
    setIngesting(true);
    setUploadError(null);
    setUploading(true);
    try {
      const res = await fetch('/api/v1/capture/ingest', { method: 'POST' });
      if (!res.ok) {
        let msg = 'Failed to ingest testbed captures';
        try { const e = await res.json(); msg = e.detail?.message || e.detail || e.message || msg; }
        catch { msg = `Server error ${res.status}`; }
        throw new Error(msg);
      }
      const payload = await res.json();
      const results = payload.results || [];
      const valid = results.filter(r => r.status === 'completed' || r.status === 'already_ingested');

      if (valid.length > 0) {
        let nextIdx = 0;
        if (activeJobId) {
          const curr = valid.findIndex(r => r.job_id === activeJobId);
          if (curr !== -1) {
            nextIdx = (curr + 1) % valid.length;
          }
        }
        const nextJobId = valid[nextIdx].job_id;
        setActiveJobId(nextJobId);

        const rRes = await fetch(`/api/v1/results/${nextJobId}`);
        if (rRes.ok) {
          const rPayload = await rRes.json();
          if (rPayload.status === 'completed') {
            setAnalysisResult(rPayload);
            setUploading(false);
          }
        }
      } else {
        throw new Error(payload.message || 'No captures available.');
      }
    } catch (e) {
      setUploadError(e.message);
      setUploading(false);
    } finally {
      setIngesting(false);
    }
  };

  const handleDownloadReport = () => {
    if (!activeJobId) return;
    window.open(`/api/v1/report/${activeJobId}/pdf?type=executive`, '_blank');
  };

  const isRealData = Boolean(analysisResult && analysisResult.status === 'completed');

  const data = isRealData ? {
    overall_score:
      analysisResult.summary?.overall_security_score === null
        ? null
        : Math.round(analysisResult.summary?.overall_security_score ?? 0),

    risk_level: analysisResult.summary?.risk_level || (
      analysisResult.threat_matrix?.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' :
        analysisResult.threat_matrix?.some(f => f.severity === 'HIGH') ? 'HIGH' :
          analysisResult.threat_matrix?.some(f => f.severity === 'MEDIUM') ? 'MODERATE' : 'LOW'
    ),
    nist_status:
      analysisResult.compliance?.standards?.NIST_SP_800_77_R1?.overall_status || 'NOT_ASSESSED',
    sub_scores: {
      cipher_strength: (analysisResult.score_breakdown?.encryption?.score ?? 0) / (analysisResult.score_breakdown?.encryption?.max_score || 25),
      key_exchange: (analysisResult.score_breakdown?.key_exchange?.score ?? 0) / (analysisResult.score_breakdown?.key_exchange?.max_score || 15),
      mode_pfs: (analysisResult.score_breakdown?.pfs?.score ?? 0) / (analysisResult.score_breakdown?.pfs?.max_score || 10),
      metadata_exposure: (analysisResult.score_breakdown?.ike_version?.score ?? 0) / (analysisResult.score_breakdown?.ike_version?.max_score || 10),
      pqc_readiness: analysisResult.control_plane?.dh_group === 19 ? 1.0 : (analysisResult.control_plane?.dh_group ? 0.0 : 0.0),
    },

    traffic_distribution:
      analysisResult.data_plane?.detected_traffic || [],

    tunnels: [{
      id: activeJobId,
      status: analysisResult.summary?.risk_level === 'HIGH' || analysisResult.summary?.risk_level === 'CRITICAL' ? 'critical' : 'active',
      encryption: analysisResult.control_plane?.encryption_algorithm || 'Unknown',
      dh_group: analysisResult.control_plane?.dh_group || 'N/A',
      pfs_enabled: analysisResult.control_plane?.pfs_enabled ?? false,
      inferred_mode: analysisResult.control_plane?.operating_mode || 'Tunnel',
      inner_traffic: analysisResult.data_plane?.detected_traffic?.[0]?.traffic_type || 'N/A',
    }],
    threat_matrix: analysisResult.threat_matrix || [],
    cnsa_status:
      analysisResult.compliance?.standards?.CNSA_2_0?.overall_status || 'NOT_ASSESSED',
    ai_metrics: {
      confidence_score: analysisResult.data_plane?.ai_confidence_score ?? 0.0,
      heuristic_agreement: analysisResult.data_plane?.agreement_flag ?? false,
      predicted_mode: analysisResult.data_plane?.llm_mode_prediction || analysisResult.data_plane?.heuristic_mode_prediction || 'unknown',
      replay_confirmed: analysisResult.control_plane?.replay_protection_enabled ?? true,
    },
  } : null;

  const totalAlerts = data?.threat_matrix?.length ?? 0;
  const criticalAlerts = data?.threat_matrix?.filter(f => f.severity === 'CRITICAL').length ?? 0;
  const mediumAlerts = data?.threat_matrix?.filter(f => f.severity === 'MEDIUM').length ?? 0;
  const lowAlerts = data?.threat_matrix?.filter(f => f.severity === 'LOW').length ?? 0;

  const showEmpty = !uploading && !isRealData;
  const showAnalysing = uploading && !isRealData;

  return (
    <div className="min-h-screen bg-[#F8F9FA] dark:bg-[#0F1012] text-gray-900 dark:text-white transition-colors flex font-['Nunito_Sans']">
      <SocSidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      <div className="flex-1 flex flex-col lg:pl-[220px] min-w-0">
        <div className="p-4 sm:p-6 lg:p-7 space-y-6 max-w-[1600px] w-full mx-auto">
          {/* Header */}
          <SocHeader
            onToggleSidebar={() => setSidebarOpen(p => !p)}
            onUploadPcap={handleUploadPcap}
            uploading={uploading}
            onIngestTestbed={handleIngestTestbed}
            ingesting={ingesting}
            activeJobId={activeJobId}
            onDownloadReport={handleDownloadReport}
            isRealData={isRealData}
            onOpenRemediation={() => setRemediationOpen(true)}
          />

          {/* Upload error banner */}
          {uploadError && (
            <div className="bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 px-4 py-3 rounded-xl text-xs font-semibold flex items-center justify-between">
              <span>⚠ {uploadError}</span>
              <button onClick={() => setUploadError(null)} className="underline cursor-pointer">Dismiss</button>
            </div>
          )}

          {/* Live job banner */}
          {isRealData && (
            <div className="bg-blue-500/10 border border-blue-500/30 text-blue-600 dark:text-blue-400 px-4 py-2.5 rounded-xl text-xs font-semibold flex items-center justify-between">
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                Live Analysis — Job: <code className="font-mono font-bold">{activeJobId}</code>
              </span>
              <button
                onClick={() => { setAnalysisResult(null); setActiveJobId(null); }}
                className="underline text-[11px] cursor-pointer hover:opacity-80"
              >
                Clear &amp; Upload New PCAP
              </button>
            </div>
          )}

          {/* Tab content */}
          {activeTab === 'alerts' ? (
            <SocAlertsView liveThreats={data?.threat_matrix} />
          ) : activeTab === 'settings' ? (
            <SocDesignSystemView />
          ) : activeTab === 'reports' ? (
            <div className="space-y-6">
              <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-gray-900 dark:text-white">Compliance &amp; Security Reports</h2>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    Export high-fidelity NIST SP 800-77 &amp; CNSA 2.0 audit reports
                  </p>
                </div>
                {isRealData ? (
                  <button
                    onClick={handleDownloadReport}
                    className="px-4 py-2 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-700 text-white cursor-pointer transition-colors shadow-xs"
                  >
                    Download Assessment PDF
                  </button>
                ) : (
                  <span className="text-xs text-gray-400">Upload a PCAP to generate a report</span>
                )}
              </div>
              {isRealData ? (
                <PerTunnelBreakdown tunnels={data.tunnels} />
              ) : (
                <EmptyState onUploadPcap={handleUploadPcap} uploading={uploading} />
              )}
            </div>
          ) : (
            /* ── Dashboard ── */
            showEmpty ? (
              <div className="space-y-6">
                <LiveTelemetryPanel jobId={null} isRealData={false} />
                <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl shadow-xs">
                  <EmptyState onUploadPcap={handleUploadPcap} uploading={uploading} />
                </div>
              </div>
            ) : showAnalysing ? (
              <AnalysingState jobId={activeJobId} />
            ) : (
              <div className="space-y-6">
                {/* Fallback Banner */}
                {isRealData && !analysisResult?.control_plane && (
                  <div className="bg-amber-500/10 border-2 border-amber-500/40 text-amber-700 dark:text-amber-300 px-5 py-3.5 rounded-2xl text-xs font-bold flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
                    <div className="flex items-center gap-3">
                      <span className="w-3 h-3 rounded-full bg-amber-500 animate-pulse shrink-0" />
                      <div>
                        <span className="font-black uppercase tracking-wider text-[11px] block">
                          ⚠ Control-Plane Handshake Unavailable (Mid-Session Capture)
                        </span>
                        <span className="font-medium text-amber-600 dark:text-amber-400 text-[11px]">
                          Deterministic IKE parser bypassed. Operating mode & inner traffic inferred from encrypted ESP data plane via local 1D CNN classifier.
                        </span>
                      </div>
                    </div>
                    <span className="bg-amber-500/20 text-amber-700 dark:text-amber-300 px-3 py-1 rounded-lg text-[10px] uppercase font-black tracking-wider shrink-0 self-start sm:self-center">
                      AI Inference Fallback Engaged
                    </span>
                  </div>
                )}

                {/* Tunnel Connection & Live Negotiated Parameters Bar */}
                {isRealData && (
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-4 shadow-xs flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <span className="flex h-3 w-3 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                      </span>
                      <div>
                        <div className="text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                          Live IPsec Tunnel Status
                        </div>
                        <div className="text-sm font-extrabold text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
                          TUNNEL ACTIVE &amp; AUDITED
                          <span className="text-[11px] font-mono text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-[#202228] px-2 py-0.5 rounded font-bold">
                            {activeJobId}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2.5 text-xs">
                      <div className="bg-gray-100 dark:bg-[#23252A] px-3 py-1.5 rounded-xl border border-gray-200 dark:border-[#2A2C34]">
                        <span className="text-gray-500 dark:text-gray-400 text-[10px] block uppercase font-bold">Cipher</span>
                        <span className="font-bold text-blue-600 dark:text-blue-400">{data.tunnels[0]?.encryption}</span>
                      </div>
                      <div className="bg-gray-100 dark:bg-[#23252A] px-3 py-1.5 rounded-xl border border-gray-200 dark:border-[#2A2C34]">
                        <span className="text-gray-500 dark:text-gray-400 text-[10px] block uppercase font-bold">Key Exchange</span>
                        <span className="font-bold text-purple-600 dark:text-purple-400">DH Group {data.tunnels[0]?.dh_group}</span>
                      </div>
                      <div className="bg-gray-100 dark:bg-[#23252A] px-3 py-1.5 rounded-xl border border-gray-200 dark:border-[#2A2C34]">
                        <span className="text-gray-500 dark:text-gray-400 text-[10px] block uppercase font-bold">Forward Secrecy</span>
                        <span className={`font-bold ${data.tunnels[0]?.pfs_enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>
                          {data.tunnels[0]?.pfs_enabled ? 'PFS ON' : 'PFS OFF'}
                        </span>
                      </div>
                      <div className="bg-gray-100 dark:bg-[#23252A] px-3 py-1.5 rounded-xl border border-gray-200 dark:border-[#2A2C34]">
                        <span className="text-gray-500 dark:text-gray-400 text-[10px] block uppercase font-bold">Mode</span>
                        <span className="font-bold text-amber-600 dark:text-amber-400">{data.tunnels[0]?.inferred_mode}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Row 1: Metric cards */}
                <SocMetricCards
                  totalAlerts={totalAlerts}
                  criticalAlerts={criticalAlerts}
                  mediumAlerts={mediumAlerts}
                  lowAlerts={lowAlerts}
                  threatMatrix={data.threat_matrix}
                  riskLevel={data.risk_level}
                />

                {/* Row 2: Score Dial, Analysis Dimensions, Compliance Radar, AI Telemetry */}
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs flex items-center justify-center">
                    <ScoreDial
                      overall_score={data.overall_score}
                      risk_level={data.risk_level}
                      nist_status={data.nist_status}
                      score_headline={data.score_headline}
                      coverage={data.coverage}
                      score_if_unobserved_fail={data.score_if_unobserved_fail}
                      score_if_unobserved_pass={data.score_if_unobserved_pass}
                    />
                  </div>
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs">
                    <AnalysisDimensions sub_scores={data.sub_scores} />
                  </div>
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs">
                    <ComplianceRadar sub_scores={data.sub_scores} />
                  </div>
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs">
                    <AiTelemetryCard ai_metrics={data.ai_metrics} />
                  </div>
                </div>

                {/* Row 3: Charts */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                  <div className="lg:col-span-8">
                    <SocAlertVolumeTrend threatMatrix={data.threat_matrix} />
                  </div>
                  <div className="lg:col-span-4">
                    <SocSeverityDistribution threatMatrix={data.threat_matrix} />
                  </div>
                </div>

                {/* Row 4: Live Telemetry & Sniffer Streaming */}
                <LiveTelemetryPanel jobId={activeJobId} isRealData={isRealData} />

                {/* Row 5: Explainable AI Threat Heatmap */}
                <ThreatHeatmap jobId={activeJobId} />

                {/* Row 6: Traffic Distribution */}
                <div className="w-full">
                  <TrafficDistribution traffic={data.traffic_distribution} />
                </div>

                {/* Row 7: Tunnel breakdown */}
                <div className="w-full">
                  <PerTunnelBreakdown tunnels={data.tunnels} />
                </div>
              </div>
            )
          )}
        </div>
      </div>

      {/* AI Hardening Remediation Modal */}
      <RemediationModal
        jobId={activeJobId}
        isOpen={remediationOpen}
        onClose={() => setRemediationOpen(false)}
      />
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <MainSocApp />
    </ThemeProvider>
  );
}

export default App;

