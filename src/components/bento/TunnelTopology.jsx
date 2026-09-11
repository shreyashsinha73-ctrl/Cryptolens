import React from 'react';

const TunnelTopology = ({ controlPlane }) => {
  const data = Array.isArray(controlPlane) ? controlPlane[0] : controlPlane || {};
  const mode = data.operating_mode || 'Tunnel';
  const hMode = 'Tunnel'; // Using static mock logic for demonstration
  const lMode = 'Tunnel';

  return (
    <div className="bg-[#a7c2d1] rounded-3xl p-5 w-full flex flex-col shadow-inner">
      <div className="bg-white rounded-2xl p-6 shadow-sm flex-1 flex flex-col justify-between border border-slate-100">
        <div>
          <h3 className="text-sm font-semibold text-slate-800 tracking-wide uppercase mb-1">Tunnel Topology & Mode Verification</h3>
          <p className="text-xs text-slate-500 mb-6">Gateway connection and mode verification</p>
        </div>

        {/* Minimal Node map */}
        <div className="flex items-center justify-between w-full px-2 mb-8 relative">
          <div className="absolute left-8 right-8 h-1 bg-slate-100 top-1/2 -translate-y-1/2"></div>
          <div className="absolute left-1/2 right-8 h-1 bg-blue-500 top-1/2 -translate-y-1/2 -translate-x-1/2 w-1/3 animate-pulse"></div>
          
          <div className="z-10 bg-white p-2 rounded-xl shadow-sm border border-slate-50 flex flex-col items-center">
            <div className="w-8 h-8 rounded-full bg-slate-50 flex items-center justify-center text-slate-400 mb-1">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
            </div>
            <span className="text-[9px] font-bold text-slate-500 uppercase">Local GW</span>
          </div>

          <div className="z-10 bg-white p-2 rounded-xl shadow-sm border border-slate-50 flex flex-col items-center">
            <div className="w-8 h-8 rounded-full bg-blue-50 flex items-center justify-center text-blue-500 mb-1">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path></svg>
            </div>
            <span className="text-[9px] font-bold text-blue-600 uppercase">Remote GW</span>
          </div>
        </div>

        <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 flex flex-col">
          <span className="text-[10px] uppercase text-slate-400 font-bold mb-1">Operating Mode</span>
          <div className="flex items-center space-x-2">
            <span className="text-sm font-black text-slate-700">{mode}</span>
            <span className="px-2 py-0.5 rounded text-[8px] font-bold bg-blue-100 text-blue-600 uppercase">Heuristic: {hMode}</span>
            <span className="px-2 py-0.5 rounded text-[8px] font-bold bg-emerald-100 text-emerald-600 uppercase">LLM: {lMode}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
export default TunnelTopology;
