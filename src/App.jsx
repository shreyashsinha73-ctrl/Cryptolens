import React, { useState, useEffect } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
  Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis
} from 'recharts';
import { Shield, Activity, UploadCloud, User, Cpu, Clock, Database, Lock } from 'lucide-react';

function App() {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
        // Use AbortController for safe fallback handling
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2500);
        
        const response = await fetch(`${baseUrl}/api/v1/results/job_demo`, {
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        
        if (response.ok) {
          const json = await response.json();
          setData(json);
        }
      } catch (error) {
        console.error("Failed to fetch live data, using mock/offline handling", error);
      } finally {
        setIsLoading(false);
      }
    };
    fetchData();
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0e131f] flex items-center justify-center">
        <div className="animate-pulse flex flex-col items-center">
          <Shield className="w-12 h-12 text-[#00f2fe] mb-4" />
          <span className="text-slate-400 font-bold uppercase tracking-widest text-xs">Initializing Telemetry...</span>
        </div>
      </div>
    );
  }

  // Fallback structural safety
  const summary = data?.summary || {
    overall_risk_score: 0,
    risk_level: "UNKNOWN",
    ai_confidence_score: 0,
    processed_packets: 0
  };
  const controlPlane = data?.control_plane || {};
  const dataPlane = data?.data_plane || {};
  const threatMatrix = data?.threat_matrix || [];
  const detectedTraffic = dataPlane.detected_traffic || [];

  // Generate synthetic radar data from threat matrix deductions
  const generateRadarData = () => {
    let scores = { 'Encryption': 25, 'Key Exchange': 15, 'Integrity': 15, 'PFS': 10, 'Lifetime': 10 };
    threatMatrix.forEach(t => {
      const id = (t.id || t.finding_id || "").toUpperCase();
      if (id.includes('ENC') || id.includes('CIPHER')) scores['Encryption'] -= 10;
      if (id.includes('INT')) scores['Integrity'] -= 10;
      if (id.includes('KEX') || id.includes('DH')) scores['Key Exchange'] -= 10;
      if (id.includes('PFS')) scores['PFS'] = 0;
      if (id.includes('LIFE')) scores['Lifetime'] = 0;
    });

    return [
      { subject: 'Encryption', A: Math.max(0, scores['Encryption']), fullMark: 25 },
      { subject: 'Key Exchange', A: Math.max(0, scores['Key Exchange']), fullMark: 15 },
      { subject: 'Integrity', A: Math.max(0, scores['Integrity']), fullMark: 15 },
      { subject: 'PFS', A: Math.max(0, scores['PFS']), fullMark: 10 },
      { subject: 'Lifetime', A: Math.max(0, scores['Lifetime']), fullMark: 10 },
    ];
  };

  const radarData = generateRadarData();

  // Score Dial Calculation
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const scorePercent = summary.overall_risk_score / 100;
  const strokeDashoffset = circumference - (scorePercent * circumference);
  
  // Dynamic color for Risk Tier
  const getRiskColor = (tier) => {
    switch ((tier || '').toUpperCase()) {
      case 'LOW': return 'text-[#10b981]';
      case 'MODERATE': return 'text-[#f59e0b]';
      case 'HIGH': return 'text-[#f43f5e]';
      case 'CRITICAL': return 'text-red-600';
      default: return 'text-slate-400';
    }
  };
  
  const getRiskBg = (tier) => {
    switch ((tier || '').toUpperCase()) {
      case 'LOW': return 'bg-[#10b981]';
      case 'MODERATE': return 'bg-[#f59e0b]';
      case 'HIGH': return 'bg-[#f43f5e]';
      case 'CRITICAL': return 'bg-red-600';
      default: return 'bg-slate-600';
    }
  };

  const getSeverityBg = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500 text-white';
      case 'HIGH': return 'bg-[#f43f5e] text-white';
      case 'MEDIUM': return 'bg-[#f59e0b] text-white';
      case 'LOW': return 'bg-[#10b981] text-white';
      default: return 'bg-slate-600 text-white';
    }
  };

  // Severity counts for legend
  const sevCounts = threatMatrix.reduce((acc, t) => {
    const s = (t.severity || 'UNKNOWN').toUpperCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="min-h-screen bg-[#0e131f] text-slate-300 font-sans p-6 pb-20">
      
      {/* 1. Top Navigation Bar */}
      <nav className="flex items-center justify-between mb-8 bg-[#161d2d] border border-slate-800 rounded-2xl p-4 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00f2fe] to-[#4facfe] flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-tight">CRYPTOLENS</h1>
            <span className="text-[10px] font-bold tracking-widest text-[#00f2fe] uppercase">SOC V1.0</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-[#0e131f]">
            <div className="w-2 h-2 rounded-full bg-[#10b981] animate-pulse"></div>
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">System Health: Operational</span>
          </div>
          
          <div className={`hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-800 bg-[#0e131f]`}>
            <div className={`w-2 h-2 rounded-full ${getRiskBg(summary.risk_level)}`}></div>
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
              Threat Level: <span className={getRiskColor(summary.risk_level)}>{summary.risk_level}</span>
            </span>
          </div>

          <button className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold transition-colors">
            <UploadCloud className="w-4 h-4" />
            Upload PCAP
          </button>
          
          <div className="w-9 h-9 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700 cursor-pointer hover:bg-slate-700 transition-colors">
            <User className="w-4 h-4 text-slate-300" />
          </div>
        </div>
      </nav>

      {/* 2. Top 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        
        {/* Card 1: AI Confidence */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-5 shadow-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <Cpu className="w-6 h-6 text-[#00f2fe]" />
          </div>
          <div>
            <h4 className="text-xs font-semibold tracking-wide uppercase text-slate-400">AI Confidence</h4>
            <div className="text-2xl font-bold text-white mt-1">{(summary.ai_confidence_score * 100).toFixed(0)}%</div>
          </div>
        </div>

        {/* Card 2: Key Lifetime */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-5 shadow-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
            <Clock className="w-6 h-6 text-[#f59e0b]" />
          </div>
          <div>
            <h4 className="text-xs font-semibold tracking-wide uppercase text-slate-400">Key Lifetime</h4>
            <div className="text-2xl font-bold text-white mt-1">{controlPlane.key_lifetime_seconds || 'N/A'}s</div>
          </div>
        </div>

        {/* Card 3: Packets Processed */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-5 shadow-xl flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
            <Database className="w-6 h-6 text-[#10b981]" />
          </div>
          <div>
            <h4 className="text-xs font-semibold tracking-wide uppercase text-slate-400">Packets Processed</h4>
            <div className="text-2xl font-bold text-white mt-1">{summary.processed_packets ? summary.processed_packets.toLocaleString() : '0'}</div>
          </div>
        </div>

        {/* Card 4: Operating Mode / PFS */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-5 shadow-xl flex flex-col justify-center relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <Lock className="w-16 h-16 text-slate-500" />
          </div>
          <h4 className="text-xs font-semibold tracking-wide uppercase text-slate-400 relative z-10">Op Mode & PFS</h4>
          <div className="flex items-center gap-3 mt-1 relative z-10">
            <span className="text-xl font-bold text-white">{controlPlane.operating_mode || 'Unknown'}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${controlPlane.pfs_enabled ? 'bg-[#10b981]/20 text-[#10b981]' : 'bg-[#f43f5e]/20 text-[#f43f5e]'}`}>
              {controlPlane.pfs_enabled ? 'PFS ENABLED' : 'PFS DISABLED'}
            </span>
          </div>
        </div>
      </div>

      {/* 3. Main Visualizations (Row 2 - 3-Column Grid) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        
        {/* Left Card: Traffic Distribution */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col h-[380px]">
          <h3 className="text-xs font-semibold tracking-wide uppercase text-slate-400 mb-6">Traffic Distribution</h3>
          <div className="flex-1 w-full relative">
            {detectedTraffic.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={detectedTraffic} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="traffic_type" stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis stroke="#475569" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip 
                    cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }} 
                    contentStyle={{ backgroundColor: '#0e131f', border: '1px solid #1e293b', borderRadius: '8px', color: '#fff', fontSize: '12px' }} 
                    itemStyle={{ color: '#00f2fe' }} 
                  />
                  <Bar dataKey="percentage" radius={[4, 4, 0, 0]}>
                    {detectedTraffic.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={index % 2 === 0 ? '#00f2fe' : '#10b981'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 text-sm">No traffic data</div>
            )}
          </div>
        </div>

        {/* Middle Card: Cryptographic Compliance Radar */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col h-[380px]">
          <h3 className="text-xs font-semibold tracking-wide uppercase text-slate-400 mb-2">Compliance Radar</h3>
          <div className="flex-1 w-full relative -mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                <PolarGrid stroke="#1e293b" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <PolarRadiusAxis angle={30} domain={[0, 25]} tick={false} axisLine={false} />
                <Radar name="Awarded Score" dataKey="A" stroke="#8b5cf6" strokeWidth={2} fill="#8b5cf6" fillOpacity={0.3} />
                <Tooltip 
                    contentStyle={{ backgroundColor: '#0e131f', border: '1px solid #1e293b', borderRadius: '8px', color: '#fff', fontSize: '12px' }} 
                    itemStyle={{ color: '#8b5cf6' }} 
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right Card: Security Posture Dial */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col h-[380px] items-center">
          <h3 className="text-xs font-semibold tracking-wide uppercase text-slate-400 w-full text-left mb-6">Risk Assessment</h3>
          
          <div className="relative w-48 h-48 flex items-center justify-center mb-6">
            <svg className="w-full h-full transform -rotate-90 drop-shadow-lg" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="50" stroke="#1e293b" strokeWidth="12" fill="transparent" />
              <circle 
                cx="60" cy="60" r="50" 
                stroke="currentColor" 
                className={getRiskColor(summary.risk_level)}
                strokeWidth="12" 
                fill="transparent" 
                strokeDasharray="314.159" 
                strokeDashoffset={strokeDashoffset} 
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-5xl font-black text-white tracking-tighter">{summary.overall_risk_score}</span>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">POSTURE</span>
            </div>
          </div>

          <div className="w-full grid grid-cols-4 gap-2 pt-4 border-t border-slate-800">
             <div className="flex flex-col items-center"><span className="text-lg font-bold text-red-500">{sevCounts['CRITICAL'] || 0}</span><span className="text-[9px] text-slate-500 uppercase font-bold">Crit</span></div>
             <div className="flex flex-col items-center"><span className="text-lg font-bold text-[#f43f5e]">{sevCounts['HIGH'] || 0}</span><span className="text-[9px] text-slate-500 uppercase font-bold">High</span></div>
             <div className="flex flex-col items-center"><span className="text-lg font-bold text-[#f59e0b]">{sevCounts['MEDIUM'] || 0}</span><span className="text-[9px] text-slate-500 uppercase font-bold">Med</span></div>
             <div className="flex flex-col items-center"><span className="text-lg font-bold text-[#10b981]">{sevCounts['LOW'] || 0}</span><span className="text-[9px] text-slate-500 uppercase font-bold">Low</span></div>
          </div>
        </div>

      </div>

      {/* 4. Bottom Section: Threat Matrix & Control Plane */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Threat Matrix */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl shadow-xl flex flex-col min-h-[350px] overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-[#161d2d]">
            <h3 className="text-xs font-semibold tracking-wide uppercase text-slate-400">Threat Matrix</h3>
            <span className="text-[10px] bg-slate-800 px-2 py-1 rounded text-slate-300 font-bold uppercase">{threatMatrix.length} Found</span>
          </div>
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left border-collapse">
              <thead className="bg-[#0e131f] text-slate-500 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">ID</th>
                  <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Severity</th>
                  <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Title</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {threatMatrix.map((threat, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-6 py-4 text-[11px] font-bold text-slate-300 whitespace-nowrap">{threat.id || threat.finding_id || `VULN-${idx}`}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 rounded text-[9px] font-bold uppercase tracking-wider ${getSeverityBg(threat.severity)}`}>
                        {threat.severity || 'UNKNOWN'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400 font-medium">{threat.title || threat.description}</td>
                  </tr>
                ))}
                {threatMatrix.length === 0 && (
                  <tr>
                    <td colSpan="3" className="px-6 py-10 text-center text-xs text-slate-500 font-medium">No active threats detected.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Control Plane Parameters */}
        <div className="bg-[#161d2d] border border-slate-800 rounded-2xl shadow-xl flex flex-col min-h-[350px] overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-[#161d2d]">
            <h3 className="text-xs font-semibold tracking-wide uppercase text-slate-400">Control Plane Parameters</h3>
          </div>
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left border-collapse">
              <thead className="bg-[#0e131f] text-slate-500 border-b border-slate-800">
                <tr>
                  <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Parameter</th>
                  <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                <tr className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-4 text-xs font-bold text-slate-300">IKE Version</td>
                  <td className="px-6 py-4 text-xs text-cyan-400 font-medium">{controlPlane.ike_version || 'Unknown'}</td>
                </tr>
                <tr className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-4 text-xs font-bold text-slate-300">Encryption Cipher</td>
                  <td className="px-6 py-4 text-xs text-cyan-400 font-medium">{controlPlane.encryption_algorithm || 'Unknown'}</td>
                </tr>
                <tr className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-4 text-xs font-bold text-slate-300">Integrity Hash</td>
                  <td className="px-6 py-4 text-xs text-cyan-400 font-medium">{controlPlane.integrity_algorithm || 'Unknown'}</td>
                </tr>
                <tr className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-4 text-xs font-bold text-slate-300">DH Group</td>
                  <td className="px-6 py-4 text-xs text-cyan-400 font-medium">{controlPlane.dh_group || 'Unknown'}</td>
                </tr>
                <tr className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-4 text-xs font-bold text-slate-300">Perfect Forward Secrecy</td>
                  <td className="px-6 py-4 text-xs">
                    <span className={`px-2 py-1 rounded text-[9px] font-bold uppercase tracking-wider ${controlPlane.pfs_enabled ? 'bg-[#10b981]/20 text-[#10b981]' : 'bg-[#f43f5e]/20 text-[#f43f5e]'}`}>
                      {controlPlane.pfs_enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
