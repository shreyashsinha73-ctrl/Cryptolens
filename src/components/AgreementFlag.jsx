import React from 'react';

const AgreementFlag = ({ heuristicAgreement }) => {
  if (heuristicAgreement) {
    return (
      <div className="w-full flex items-center p-3.5 bg-emerald-950/30 border border-emerald-900/50 rounded-lg shadow-sm">
        <span className="flex-shrink-0 w-4 h-4 text-emerald-500 mr-3 shadow-[0_0_8px_rgba(16,185,129,0.5)] rounded-full">
          <svg fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 2a5 5 0 00-5 5v2a2 2 0 00-2 2v5a2 2 0 002 2h10a2 2 0 002-2v-5a2 2 0 00-2-2H7V7a3 3 0 015.905-.75 1 1 0 001.937-.5A5.002 5.002 0 0010 2zM9 13a1 1 0 112 0v2a1 1 0 11-2 0v-2z" clipRule="evenodd"></path></svg>
        </span>
        <span className="text-emerald-400 text-xs font-mono font-bold tracking-wide uppercase">
          ✓ Heuristic & AI Consensus: Verified
        </span>
      </div>
    );
  }

  return (
    <div className="w-full flex items-center p-3.5 bg-amber-950/40 border border-amber-500/30 rounded-lg shadow-[0_0_15px_rgba(245,158,11,0.15)] animate-pulse">
      <span className="flex-shrink-0 w-5 h-5 text-amber-500 mr-3">
        <svg fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
      </span>
      <span className="text-amber-400 text-[11px] font-mono font-bold tracking-wide uppercase leading-tight">
        ⚠ Discrepancy: AI Classifier differs from Rule Heuristic
      </span>
    </div>
  );
};

export default AgreementFlag;
