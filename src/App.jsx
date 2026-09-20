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

<<<<<<< HEAD
function App() {
  const [configType, setConfigType] = useState('critical');
  const [data, setData] = useState(null);
  const [uploadState, setUploadState] = useState({ status: 'idle', message: '' });

  useEffect(() => {
    setData(mockData[configType]);
  }, [configType]);

  if (!data) return <div className="text-white p-8 font-mono">Initializing Telemetry...</div>;

  const toggleConfig = () => {
    setConfigType(prev => prev === 'compliant' ? 'critical' : 'compliant');
    setUploadState({ status: 'idle', message: '' });
  };

  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || '/api/v1';

  const resultToDashboardData = (result) => {
    const control = result.control_plane || {};
    const dataPlane = result.data_plane || {};
    const summary = result.summary || {};
    const traffic = dataPlane.detected_traffic?.[0] || {};
    const scoreBreakdown = result.score_breakdown || {};
    const ratio = (name) => {
      const item = scoreBreakdown[name];
      return item?.max_score ? item.score / item.max_score : 0;
    };
    const riskLevel = (summary.risk_level || '').toLowerCase();

    return {
      // The API returns risk; the dial displays compliance/posture.
      overall_score: Math.max(0, Math.min(100, 100 - (summary.overall_risk_score ?? 100))),
      sub_scores: {
        cipher_strength: ratio('encryption'),
        key_exchange: ratio('key_exchange'),
        mode_pfs: (ratio('mode') + ratio('pfs')) / 2,
        metadata_exposure: ratio('replay_protection'),
        pqc_readiness: 0,
      },
      tunnels: [{
        id: result.job_id || 'uploaded-pcap',
        status: riskLevel === 'critical' ? 'critical' : riskLevel === 'high' || riskLevel === 'moderate' ? 'flagged' : 'active',
        encryption: control.encryption_algorithm ?? 'Not observed',
        dh_group: control.dh_group ?? 'Not observed',
        pfs_enabled: control.pfs_enabled === true,
        inferred_mode: dataPlane.llm_mode_prediction && dataPlane.llm_mode_prediction !== 'Unknown'
          ? dataPlane.llm_mode_prediction
          : (dataPlane.heuristic_mode_prediction ?? 'Unknown'),
        inner_traffic: traffic.traffic_type ?? 'Unknown',
      }],
      ai_metrics: {
        confidence_score: summary.ai_confidence_score ?? dataPlane.ai_confidence_score ?? 0,
        heuristic_agreement: summary.agreement_flag ?? dataPlane.agreement_flag ?? false,
      },
      replay_protection_enabled: control.replay_protection_enabled,
      processed_packets: summary.processed_packets ?? traffic.packet_count ?? 0,
    };
  };

  const uploadPcap = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploadState({ status: 'uploading', message: `Uploading ${file.name}…` });
    try {
      const formData = new FormData();
      formData.append('file', file);
      const uploadResponse = await fetch(`${apiBaseUrl}/analyze`, { method: 'POST', body: formData });
      const uploadBody = await uploadResponse.json();
      if (!uploadResponse.ok) throw new Error(uploadBody.detail?.message || uploadBody.message || 'Upload failed.');

      setUploadState({ status: 'processing', message: 'PCAP uploaded. Analyzing control and data planes…' });
      for (let attempt = 0; attempt < 60; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const resultResponse = await fetch(`${apiBaseUrl}/results/${uploadBody.job_id}`);
        if (resultResponse.status === 404) continue; // background job has not saved its result yet
        const result = await resultResponse.json();
        if (!resultResponse.ok || result.status === 'failed') {
          throw new Error(result.error?.message || result.detail?.message || 'Analysis failed.');
        }
        setData(resultToDashboardData(result));
        setUploadState({ status: 'complete', message: `Analysis complete: ${result.summary?.processed_packets ?? 0} ESP packets processed.` });
        return;
      }
      throw new Error('Analysis is still running. Please try the upload again shortly.');
    } catch (error) {
      setUploadState({ status: 'error', message: error.message || 'Unable to analyze this PCAP.' });
    } finally {
      event.target.value = '';
    }
  };

  const SubScoreBar = ({ label, value }) => (
    <div className="mb-4 last:mb-0">
      <div className="flex justify-between text-xs font-mono mb-2">
        <span className="text-slate-400 uppercase tracking-wide font-semibold">{label}</span>
        <span className="text-slate-300 font-bold">{(value * 10).toFixed(1)}<span className="text-slate-600 font-normal">/10</span></span>
      </div>
      <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
        <div 
          className="h-full rounded-full transition-all duration-700 ease-out shadow-[0_0_8px_currentColor]"
          style={{ 
            width: `${value * 100}%`, 
            backgroundColor: value >= 0.8 ? '#10b981' : value >= 0.5 ? '#f59e0b' : '#f43f5e' 
          }}
        />
=======
// ── Empty state shown before any PCAP is uploaded ──────────────────────────
const EmptyState = ({ onUploadPcap, uploading }) => {
  const fileRef = React.useRef(null);
  return (
    <div className="flex flex-col items-center justify-center py-24 px-6 text-center">
      <div className="w-20 h-20 rounded-2xl bg-blue-500/10 dark:bg-blue-500/15 flex items-center justify-center mb-6">
        <svg className="w-10 h-10 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1
      </div>
      <h2 className="text-2xl font-extrabold text-gray-900 dark:text-white mb-2">
        No Analysis Yet
      </h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 max-w-md mb-8 leading-relaxed">
        <strong></strong> <strong></strong> 
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
        className={`inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-bold transition-all shadow-xs cursor-pointer ${
          uploading
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
    <h2 className="text-xl font-extrabold text-gray-900 dark:text-white mb-2">Analysing PCAP…</h2>
    <p className="text-xs text-gray-500 dark:text-gray-400">
      Job <code className="font-mono font-bold">{jobId}</code> is running.
      This usually takes 10–30 seconds.
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

  // Poll backend for job status
  useEffect(() => {
    if (!activeJobId) return;
    let subscribed = true;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/v1/results/${activeJobId}`);
        if (res.ok) {
          const payload = await res.json();
          if (payload.status === 'completed') {
            if (subscribed) { setAnalysisResult(payload); setUploading(false); clearInterval(interval); }
          } else if (payload.status === 'failed') {
            if (subscribed) { setUploadError(payload.error?.message || 'Analysis failed'); setUploading(false); clearInterval(interval); }
          }
        }
      } catch (e) { console.error('Poll error:', e); }
    }, 1500);
    return () => { subscribed = false; clearInterval(interval); };
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
        catch { msg = res.status === 502 || res.status === 504
          ? 'Backend API unreachable (502). Run: .venv/bin/python -m uvicorn backend.main:app --port 8000'
          : `Server error ${res.status}`; }
        throw new Error(msg);
      }
      const { job_id } = await res.json();
      setActiveJobId(job_id);
    } catch (e) { setUploadError(e.message); setUploading(false); }
  };

  const handleDownloadReport = () => {
    if (!activeJobId) return;
    window.open(`/api/v1/report/${activeJobId}/pdf?type=executive`, '_blank');
  };

  const isRealData = Boolean(analysisResult && analysisResult.status === 'completed');

  // Derive everything strictly from live analysis — no fallbacks or dummy values
  const data = isRealData ? {
    overall_score: Math.round(
      analysisResult.summary?.overall_security_score ??
      (analysisResult.summary?.overall_risk_score !== undefined ? 100 - analysisResult.summary.overall_risk_score : 0)
    ),
    risk_level: analysisResult.summary?.risk_level || (
      analysisResult.threat_matrix?.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' :
      analysisResult.threat_matrix?.some(f => f.severity === 'HIGH') ? 'HIGH' :
      analysisResult.threat_matrix?.some(f => f.severity === 'MEDIUM') ? 'MODERATE' : 'LOW'
    ),
    sub_scores: {
      cipher_strength:    (analysisResult.score_breakdown?.encryption?.score ?? 0) / (analysisResult.score_breakdown?.encryption?.max_score || 25),
      key_exchange:       (analysisResult.score_breakdown?.key_exchange?.score ?? 0) / (analysisResult.score_breakdown?.key_exchange?.max_score || 15),
      mode_pfs:           (analysisResult.score_breakdown?.pfs?.score ?? 0) / (analysisResult.score_breakdown?.pfs?.max_score || 10),
      metadata_exposure:  (analysisResult.score_breakdown?.ike_version?.score ?? 0) / (analysisResult.score_breakdown?.ike_version?.max_score || 10),
      pqc_readiness:      analysisResult.control_plane?.dh_group === 19 ? 1.0 : (analysisResult.control_plane?.dh_group ? 0.0 : 0.0),
    },
    tunnels: [{
      id:             activeJobId,
      status:         analysisResult.summary?.risk_level === 'HIGH' || analysisResult.summary?.risk_level === 'CRITICAL' ? 'critical' : 'active',
      encryption:     analysisResult.control_plane?.encryption_algorithm || 'Unknown',
      dh_group:       analysisResult.control_plane?.dh_group || 'N/A',
      pfs_enabled:    analysisResult.control_plane?.pfs_enabled ?? false,
      inferred_mode:  analysisResult.control_plane?.operating_mode || 'Tunnel',
      inner_traffic:  analysisResult.data_plane?.detected_traffic?.[0]?.traffic_type || 'N/A',
    }],
    threat_matrix: analysisResult.threat_matrix || [],
  } : null;

  const totalAlerts    = data?.threat_matrix?.length ?? 0;
  const criticalAlerts = data?.threat_matrix?.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length ?? 0;
  const mediumAlerts   = data?.threat_matrix?.filter(f => f.severity === 'MEDIUM').length ?? 0;
  const lowAlerts      = data?.threat_matrix?.filter(f => f.severity === 'LOW').length ?? 0;

  const showEmpty     = !uploading && !isRealData;
  const showAnalysing = uploading && !isRealData;

  return (
<<<<<<< HEAD
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
      {/* Header */}
      <header className="mb-8 border-b border-slate-800 pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 bg-gradient-to-br from-blue-600 to-indigo-800 rounded flex items-center justify-center font-bold font-mono tracking-tighter text-white shadow-[0_0_15px_rgba(37,99,235,0.4)] border border-blue-400/20">
            CL
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">CryptoLens</h1>
          <span className="px-2.5 py-0.5 text-[10px] font-mono border border-slate-700/80 text-slate-400 rounded-full bg-slate-900">v2.4.1-rc</span>
        </div>
        
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2 bg-slate-900 px-3 py-1.5 rounded-full border border-slate-800">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse"></div>
            <span className="text-emerald-500/90 text-[10px] font-mono tracking-widest uppercase font-semibold">ENGINE ONLINE — DUAL TRACK ANALYZER</span>
          </div>
          
          <label className="px-4 py-2 bg-blue-700 hover:bg-blue-600 border border-blue-400/40 transition-all rounded text-[11px] font-mono text-white uppercase tracking-wider font-bold cursor-pointer">
            Upload PCAP
            <input className="hidden" type="file" accept=".pcap,.pcapng,.cap" onChange={uploadPcap} />
          </label>
          <button 
            onClick={toggleConfig}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-600 transition-all rounded text-[11px] font-mono text-slate-200 uppercase tracking-wider font-bold hover:shadow-lg focus:outline-none"
          >
            Demo: {configType === 'compliant' ? 'Compliant Config' : 'Critical Misconfig'}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto space-y-6">
        {uploadState.status !== 'idle' && (
          <div className={`rounded-lg border px-4 py-3 font-mono text-xs ${
            uploadState.status === 'error'
              ? 'border-rose-500/40 bg-rose-950/30 text-rose-300'
              : 'border-cyan-500/30 bg-cyan-950/20 text-cyan-200'
          }`}>
            {uploadState.message}
          </div>
        )}
        
        {/* Top Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Col 1: ScoreDial */}
          <div className="col-span-1 bg-slate-900/70 border border-slate-800/80 rounded-xl p-6 shadow-xl backdrop-blur flex flex-col">
            <h2 className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase mb-6">Posture Status</h2>
            <div className="flex-1 flex items-center justify-center">
              <ScoreDial overall_score={data.overall_score} />
            </div>
          </div>
=======
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
            activeJobId={activeJobId}
            onDownloadReport={handleDownloadReport}
            isRealData={isRealData}
          />
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1

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
<<<<<<< HEAD
            
            <div className="mt-8 space-y-4">
              <AgreementFlag heuristicAgreement={data.ai_metrics.heuristic_agreement} />
              
              <div className="w-full flex items-center justify-between py-3">
                <span className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase">Active Replay Protection</span>
                <span className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold border tracking-wider ${
                  data.replay_protection_enabled === true
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : data.replay_protection_enabled === false
                      ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                }`}>
                  {data.replay_protection_enabled === true ? 'VERIFIED' : data.replay_protection_enabled === false ? 'NOT VERIFIED' : 'NOT OBSERVED'}
                </span>
=======
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
>>>>>>> 09ed384854c6a471d409aeed5b20daf4a821a5d1
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
              <EmptyState onUploadPcap={handleUploadPcap} uploading={uploading} />
            ) : showAnalysing ? (
              <AnalysingState jobId={activeJobId} />
            ) : (
              <div className="space-y-6">
                {/* Row 1: Metric cards */}
                <SocMetricCards
                  totalAlerts={totalAlerts}
                  criticalAlerts={criticalAlerts}
                  mediumAlerts={mediumAlerts}
                  lowAlerts={lowAlerts}
                  threatMatrix={data.threat_matrix}
                  riskLevel={data.risk_level}
                />

                {/* Row 2: Score + Dimensions */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs flex items-center justify-center">
                    <ScoreDial overall_score={data.overall_score} risk_level={data.risk_level} />
                  </div>
                  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs">
                    <AnalysisDimensions sub_scores={data.sub_scores} />
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

                {/* Row 4: Tunnel breakdown */}
                <div className="w-full">
                  <PerTunnelBreakdown tunnels={data.tunnels} />
                </div>
              </div>
            )
          )}
        </div>
      </div>
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
