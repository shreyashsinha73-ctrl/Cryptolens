import React from 'react';

const ConfidenceBar = ({ confidence }) => {
  const percentage = Math.round((confidence || 0) * 100);

  return (
    <div className="w-full">
      <div className="flex justify-between items-end mb-2">
        <div className="flex flex-col">
          <span className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase mb-1">
            AI Mode Inference
          </span>
          <span className="text-[10px] font-mono text-slate-500 tracking-tight">
            ESP SIZE & TIMING METADATA INFERENCE
          </span>
        </div>
        <span className="text-cyan-400 font-mono font-bold text-xl leading-none" style={{ textShadow: '0 0 10px rgba(34,211,238,0.5)' }}>{percentage}%</span>
      </div>
      
      <div className="h-2.5 w-full bg-slate-800 rounded-full overflow-hidden mt-4">
        <div 
          className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full transition-all duration-1000 ease-out shadow-[0_0_12px_rgba(34,211,238,0.6)]"
          style={{ width: `${percentage}%` }}
        />
      </div>
      <p className="text-slate-500 text-[10px] font-mono mt-3 text-right">Inferred from encrypted ESP packet timing & size distributions.</p>
    </div>
  );
};

export default ConfidenceBar;
