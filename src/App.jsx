import React, { useState, useEffect } from 'react';
import mockData from './mock/mockData.json';
import ScoreDial from './components/ScoreDial.jsx';
import ConfidenceBar from './components/ConfidenceBar.jsx';
import PerTunnelBreakdown from './components/PerTunnelBreakdown.jsx';
import AgreementFlag from './components/AgreementFlag.jsx';

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
      </div>
    </div>
  );

  return (
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

          {/* Col 2: Sub-score Breakdown */}
          <div className="col-span-1 bg-slate-900/70 border border-slate-800/80 rounded-xl p-6 shadow-xl backdrop-blur">
            <h2 className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase mb-6">Analysis Dimensions</h2>
            <div className="flex flex-col justify-center h-full pb-4">
              <SubScoreBar label="Cipher Strength" value={data.sub_scores.cipher_strength} />
              <SubScoreBar label="Key Exchange" value={data.sub_scores.key_exchange} />
              <SubScoreBar label="Mode & PFS" value={data.sub_scores.mode_pfs} />
              <SubScoreBar label="Metadata Exposure" value={data.sub_scores.metadata_exposure} />
              <SubScoreBar label="PQC Readiness" value={data.sub_scores.pqc_readiness} />
            </div>
          </div>

          {/* Col 3: AI Inference & Telemetry */}
          <div className="col-span-1 bg-slate-900/70 border border-slate-800/80 rounded-xl p-6 shadow-xl backdrop-blur flex flex-col justify-between">
            <div>
              <h2 className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase mb-5">AI Inference & Telemetry</h2>
              <ConfidenceBar confidenceScore={data.ai_metrics.confidence_score} />
            </div>
            
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
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Row: Tunnels Table */}
        <div className="w-full">
          <PerTunnelBreakdown tunnels={data.tunnels} />
        </div>
        
      </div>
    </div>
  );
}

export default App;
