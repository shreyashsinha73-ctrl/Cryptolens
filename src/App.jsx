import React, { useState, useEffect } from 'react';
import mockData from './mock/mockData.json';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

function App() {
  const [data, setData] = useState(mockData.critical);
  const [isOffline, setIsOffline] = useState(true);
  const [selectedTraffic, setSelectedTraffic] = useState(null);
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const fetchData = async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);

      try {
        const response = await fetch(`${BASE_URL}/api/v1/results/job_demo`, { signal: controller.signal });
        clearTimeout(timeoutId);
        
        if (response.ok) {
          const result = await response.json();
          setData(result);
          setIsOffline(false);
        } else {
          setIsOffline(true);
        }
      } catch (err) {
        console.warn('Backend fetch failed, retaining fallback data.', err);
        setIsOffline(true);
      }
    };
    fetchData();
  }, []);

  const jobId = data?.job_id || 'job_demo';
  const controlPlane = Array.isArray(data?.control_plane) ? data.control_plane[0] : (data?.control_plane || {});
  const threatMatrix = Array.isArray(data?.threat_matrix) ? data.threat_matrix : [];
  
  // Safe extraction of detected_traffic array mapping
  const detectedTraffic = Array.isArray(data?.data_plane?.detected_traffic) 
    ? data.data_plane.detected_traffic 
    : [
        { traffic_type: 'VoIP', percentage: 40, packet_count: 5800, avg_packet_size_bytes: 140 },
        { traffic_type: 'Streaming', percentage: 35, packet_count: 5075, avg_packet_size_bytes: 1200 },
        { traffic_type: 'Messaging', percentage: 25, packet_count: 3627, avg_packet_size_bytes: 60 }
      ];

  useEffect(() => {
    if (detectedTraffic && detectedTraffic.length > 0) {
      setSelectedTraffic(detectedTraffic[0]);
    }
  }, [data]);
  
  // Summing packet_count safely
  const totalPackets = detectedTraffic.reduce((sum, item) => sum + (item.packet_count || 0), 0) || 14502;

  const targetScore = data?.summary?.overall_risk_score ?? 0;
  
  useEffect(() => {
    setAnimatedScore(0);
    const timeoutId = setTimeout(() => {
      setAnimatedScore(targetScore);
    }, 100);
    return () => clearTimeout(timeoutId);
  }, [targetScore]);

  const circumference = 2 * Math.PI * 50; // ~314.159
  const offset = circumference - (circumference * (animatedScore / 100));

  let scoreColor = '#22c55e'; // Green
  if (targetScore >= 80) scoreColor = '#ef4444'; // Red
  else if (targetScore >= 60) scoreColor = '#f97316'; // Orange

  return (
    <div className="min-h-screen bg-slate-50 font-sans relative">
      {/* Top Header Background (35vh vibrant blue gradient) */}
      <div className="w-full h-[35vh] bg-gradient-to-r from-cyan-400 to-blue-600 absolute top-0 left-0 z-0"></div>
      
      {/* Top Navigation */}
      <nav className="relative z-10 flex items-center justify-between px-6 py-6 max-w-7xl mx-auto text-white">
        <div className="flex items-center space-x-3">
          <span className="text-xl font-bold tracking-tight uppercase">CryptoLens</span>
        </div>
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${isOffline ? 'bg-amber-300' : 'bg-emerald-300'} animate-pulse`}></div>
            <span className="text-xs font-semibold tracking-wider uppercase opacity-90">
              {isOffline ? 'CACHE MODE' : 'LIVE API'}
            </span>
          </div>
          <button 
            onClick={() => window.open(`${BASE_URL}/api/v1/report/${jobId}/pdf`, '_blank')}
            className="px-4 py-2 bg-white/10 hover:bg-white/20 transition-colors border border-white/20 rounded-full text-xs font-bold shadow-sm"
          >
            Export PDF Report
          </button>
        </div>
      </nav>

      {/* Main Container */}
      <div className="relative z-10 max-w-7xl mx-auto pb-12 pt-8">
        
        {/* Top Row: 3 Stat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 px-6 -mt-16 lg:-mt-24">
          
          {/* Card 1: AI Confidence */}
          <div className="bg-white shadow-md p-5 flex items-center justify-between transition-transform hover:-translate-y-1 duration-300">
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">AI Confidence</p>
              <h3 className="text-xl font-bold text-slate-700">{((data?.summary?.ai_confidence_score || 0) * 100).toFixed(0)}%</h3>
            </div>
            <div className="w-12 h-12 rounded-full bg-cyan-500 text-white flex items-center justify-center shadow-md">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>
            </div>
          </div>

          {/* Card 3: Key Lifetime */}
          <div className="bg-white  shadow-md p-5 flex items-center justify-between transition-transform hover:-translate-y-1 duration-300">
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Key Lifetime</p>
              <h3 className="text-xl font-bold text-slate-700">{controlPlane?.key_lifetime_seconds ?? 'N/A'}s</h3>
            </div>
            <div className="w-12 h-12 rounded-full bg-orange-500 text-white flex items-center justify-center shadow-md">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
            </div>
          </div>

          {/* Card 4: Packets Processed */}
          <div className="bg-white  shadow-md p-5 flex items-center justify-between transition-transform hover:-translate-y-1 duration-300">
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Processed</p>
              <h3 className="text-xl font-bold text-slate-700">{totalPackets.toLocaleString()}</h3>
            </div>
            <div className="w-12 h-12 rounded-full bg-yellow-500 text-white flex items-center justify-center shadow-md">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path></svg>
            </div>
          </div>
        </div>

        {/* Middle Row: Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 px-6 mt-6">
          {/* Right Chart (span 1): Radial Score Dial */}
          <div className="lg:col-span-1 bg-white p-6 shadow-md flex flex-col h-[350px]">
            <h6 className="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Assessment</h6>
            <h2 className="text-slate-700 text-xl font-bold mb-6">Overall Security Posture</h2>
            
            <div className="flex-1 flex items-center justify-center relative w-full h-full">
              <svg className="w-full h-full max-h-[200px] transform -rotate-90 drop-shadow-md" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="50" stroke="#f1f5f9" strokeWidth="10" fill="transparent" />
                <circle 
                  cx="60" cy="60" r="50" 
                  stroke={scoreColor} 
                  strokeWidth="10" 
                  fill="transparent" 
                  strokeDasharray="314.159" 
                  strokeDashoffset={offset} 
                  strokeLinecap="square"
                  className="transition-all duration-1000 ease-out" 
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-5xl font-black text-slate-800 tracking-tighter">{targetScore}</span>
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">out of 100</span>
              </div>
            </div>
          </div>

          {/* Left Chart (span 2): Interactive Bar Chart */}
          <div className="lg:col-span-2 bg-white p-6 shadow-md flex flex-col h-[350px]">
            <div className="flex justify-between items-center mb-6">
              <div>
                <h6 className="text-[10px] uppercase text-slate-400 font-bold tracking-widest">Analytics</h6>
                <h2 className="text-slate-800 text-xl font-bold">Traffic Distribution</h2>
              </div>
            </div>
            <div className="flex-1 w-full relative">
              {detectedTraffic && detectedTraffic.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={detectedTraffic} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <XAxis dataKey="traffic_type" stroke="#333333" tick={{ fill: '#333333', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis stroke="#333333" tick={{ fill: '#333333', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip cursor={{ fill: 'rgba(0, 0, 0, 0.05)' }} contentStyle={{ backgroundColor: '#f8fafc', border: 'none', borderRadius: '0px', color: '#1e293b', fontSize: '12px' }} itemStyle={{ color: '#0f172a' }} />
                    <Bar 
                      dataKey="percentage" 
                       
                      onClick={(data) => setSelectedTraffic(data)} 
                      cursor="pointer"
                    >
                      {detectedTraffic.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={selectedTraffic?.traffic_type === entry.traffic_type ? '#2dce89' : '#11cdef'} 
                          className="transition-colors duration-300"
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-slate-400 text-sm">No traffic telemetry available.</div>
              )}
            </div>
          </div>
        </div>

        {/* Bottom Row: Tables */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 px-6 mt-6 mb-10">
          
          {/* Threat Matrix Table */}
          <div className="bg-white  shadow-md overflow-hidden flex flex-col min-h-[300px]">
            <div className="px-6 py-5 border-b border-slate-100 flex items-center justify-between bg-white">
              <h3 className="text-slate-700 font-bold text-sm">Threat Matrix</h3>
              <span className="text-[10px] bg-slate-100 px-2 py-1  text-slate-500 font-bold uppercase">{threatMatrix.length} Found</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead className="bg-slate-50 text-slate-400">
                  <tr>
                    <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">ID</th>
                    <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Severity</th>
                    <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Title</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {threatMatrix.map((threat, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="px-6 py-4 text-[11px] font-bold text-slate-700 whitespace-nowrap">{threat.id || threat.finding_id || `VULN-${idx}`}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2.5 py-1  text-[9px] font-bold uppercase tracking-wider shadow-sm ${
                          (threat.severity || '').toUpperCase() === 'CRITICAL' ? 'bg-red-500 text-white' : 
                          (threat.severity || '').toUpperCase() === 'HIGH' ? 'bg-orange-500 text-white' : 
                          'bg-yellow-500 text-white'
                        }`}>
                          {threat.severity || 'UNKNOWN'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-xs text-slate-500 font-medium">{threat.title || threat.description || 'Unknown Vulnerability'}</td>
                    </tr>
                  ))}
                  {threatMatrix.length === 0 && (
                    <tr>
                      <td colSpan="3" className="px-6 py-8 text-center text-xs text-slate-400 font-medium">No active threats detected.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Control Plane Table */}
          <div className="bg-white  shadow-md overflow-hidden flex flex-col min-h-[300px]">
            <div className="px-6 py-5 border-b border-slate-100 flex items-center justify-between bg-white">
              <h3 className="text-slate-700 font-bold text-sm">Control Plane Parameters</h3>
              <button className="text-[10px] text-blue-600 font-bold uppercase tracking-wider hover:text-blue-700">See All</button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead className="bg-slate-50 text-slate-400">
                  <tr>
                    <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Parameter</th>
                    <th className="px-6 py-3 text-[10px] font-semibold uppercase tracking-wider">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  <tr className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 text-xs font-bold text-slate-700">IKE Version</td>
                    <td className="px-6 py-4 text-xs text-slate-500 font-medium">{controlPlane.ike_version || 'Unknown'}</td>
                  </tr>
                  <tr className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 text-xs font-bold text-slate-700">Encryption Cipher</td>
                    <td className="px-6 py-4 text-xs text-slate-500 font-medium">{controlPlane.encryption_algorithm || controlPlane.encryption || 'Unknown'}</td>
                  </tr>
                  <tr className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 text-xs font-bold text-slate-700">Integrity Hash</td>
                    <td className="px-6 py-4 text-xs text-slate-500 font-medium">{controlPlane.integrity_algorithm || 'Unknown'}</td>
                  </tr>
                  <tr className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 text-xs font-bold text-slate-700">Perfect Forward Secrecy</td>
                    <td className="px-6 py-4 text-xs text-slate-500">
                      <span className={`px-2.5 py-1  text-[9px] font-bold uppercase tracking-wider shadow-sm ${controlPlane.pfs_enabled ? 'bg-emerald-500 text-white' : 'bg-red-500 text-white'}`}>
                        {controlPlane.pfs_enabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </td>
                  </tr>
                  <tr className="hover:bg-slate-50 transition-colors">
                    <td className="px-6 py-4 text-xs font-bold text-slate-700">Operating Mode</td>
                    <td className="px-6 py-4 text-xs text-slate-500 font-medium">{controlPlane.operating_mode || 'Unknown'}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          
        </div>
      </div>
    </div>
  );
}

export default App;
