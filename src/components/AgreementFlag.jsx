import React from 'react';

const AgreementFlag = ({ heuristicAgreement }) => {
  if (heuristicAgreement) {
    return (
      <div className="w-full flex items-center p-3.5 bg-[#00B69B]/10 dark:bg-[#00B69B]/15 border border-[#00B69B]/30 rounded-[8px]">
        <div className="w-7 h-7 rounded-full bg-[#00B69B]/20 text-[#00B69B] flex items-center justify-center shrink-0 mr-3">
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
            <path
              fillRule="evenodd"
              d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
              clipRule="evenodd"
            />
          </svg>
        </div>
        <div>
          <div className="text-xs font-bold text-[#00B69B] tracking-wide uppercase font-['Nunito_Sans']">
            Consensus Verified
          </div>
          <div className="text-[11px] text-gray-500 dark:text-gray-400 font-medium">
            Heuristic rules & neural telemetry agree
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full flex items-center p-3.5 bg-[#FFA756]/10 dark:bg-[#FFA756]/15 border border-[#FFA756]/30 rounded-[8px]">
      <div className="w-7 h-7 rounded-full bg-[#FFA756]/20 text-[#FFA756] flex items-center justify-center shrink-0 mr-3">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      </div>
      <div>
        <div className="text-xs font-bold text-[#FFA756] tracking-wide uppercase font-['Nunito_Sans']">
          Telemetry Discrepancy
        </div>
        <div className="text-[11px] text-gray-500 dark:text-gray-400 font-medium">
          Rule engine differs from deep flow classifier
        </div>
      </div>
    </div>
  );
};

export default AgreementFlag;
