import React from 'react';

const PostureRiskIndex = ({ summary, threatMatrix }) => {
  const score = summary?.overall_risk_score ?? 78;
  const riskLevel = summary?.risk_level || 'HIGH RISK';
  const threats = Array.isArray(threatMatrix) && threatMatrix.length > 0 ? threatMatrix : [
    { id: 'VULN-001', category: 'Cryptography', severity: 'HIGH', description: 'Deprecated IKE transform (SHA1)' },
    { id: 'VULN-002', category: 'Configuration', severity: 'MEDIUM', description: 'No PFS configured in phase 2' }
  ];

  let colorCode = '#f43f5e'; // Rose
  if (score >= 85) colorCode = '#22c55e'; // Emerald
  else if (score >= 70) colorCode = '#f59e0b'; // Amber

  const radius = 35;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="bg-slate-200 rounded-3xl p-5 w-full flex flex-col shadow-inner">
      <div className="bg-white rounded-2xl p-6 shadow-sm flex-1 flex flex-col border border-slate-100 h-[280px]">
        <h3 className="text-sm font-semibold text-slate-800 tracking-wide uppercase mb-1">Security Posture & Threat Matrix</h3>
        <div className="flex items-center mb-4">
          <div className="relative w-24 h-24 flex items-center justify-center flex-shrink-0">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle className="stroke-slate-100" strokeWidth="8" fill="transparent" r={radius} cx="50" cy="50" />
              <circle stroke={colorCode} strokeWidth="8" strokeLinecap="round" fill="transparent" r={radius} cx="50" cy="50" strokeDasharray={circumference} strokeDashoffset={offset} className="transition-all duration-1000" />
            </svg>
            <div className="absolute flex flex-col items-center mt-1">
              <span className="text-2xl font-black text-slate-800 leading-none">{score}</span>
              <span className="text-[8px] text-slate-400 font-bold uppercase mt-0.5">{riskLevel}</span>
            </div>
          </div>
        </div>

        {/* Scrollable Threat Matrix */}
        <div className="flex-1 overflow-y-auto pr-2 space-y-2">
          {threats.map((threat, i) => (
            <div key={i} className="flex flex-col bg-slate-50 rounded-lg p-2.5 border border-slate-100">
              <div className="flex items-center justify-between mb-1">
                <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${threat.severity?.toUpperCase() === 'HIGH' ? 'bg-rose-100 text-rose-600' : 'bg-amber-100 text-amber-600'}`}>
                  {threat.severity?.toUpperCase() || 'MEDIUM'}
                </span>
                <span className="text-[9px] font-semibold text-slate-400">{threat.category || 'General'}</span>
              </div>
              <span className="text-[10px] text-slate-600 leading-snug font-medium">{threat.description || threat.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
export default PostureRiskIndex;
