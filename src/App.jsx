import React, { useState, useEffect } from 'react';
import mockData from './mock/mockData.json';
import ScoreDial from './components/ScoreDial.jsx';
import ConfidenceBar from './components/ConfidenceBar.jsx';
import PerTunnelBreakdown from './components/PerTunnelBreakdown.jsx';
import AgreementFlag from './components/AgreementFlag.jsx';

function App() {
  const [configType, setConfigType] = useState('critical');
  const [data, setData] = useState(null);

  useEffect(() => {
    setData(mockData[configType]);
  }, [configType]);

  if (!data) return <div className="text-white p-8 font-mono">Initializing Telemetry...</div>;

  const toggleConfig = () => {
    setConfigType(prev => prev === 'compliant' ? 'critical' : 'compliant');
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
                <span className="px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-[0_0_8px_rgba(16,185,129,0.15)] tracking-wider">VERIFIED</span>
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
