import React from 'react';

const ConfidenceBar = ({ confidenceScore }) => {
  const percentage = Math.round((confidenceScore || 0) * 100);

  return (
    <div className="w-full font-['Nunito_Sans']">
      <div className="flex justify-between items-end mb-2">
        <div>
          <span className="text-xs font-bold text-[#646464] dark:text-gray-400 uppercase tracking-wider block">
            AI Mode Inference
          </span>
          <span className="text-[11px] font-semibold text-gray-400 dark:text-gray-500">
            ESP Size & Timing Distribution
          </span>
        </div>
        <span className="text-xl font-extrabold text-[#4880FF] dark:text-[#5A8CFF]">
          {percentage}%
        </span>
      </div>

      <div className="h-3 w-full bg-[#F5F6FA] dark:bg-[#1B2431] rounded-full overflow-hidden p-0.5 border border-gray-100 dark:border-[#323D4E]">
        <div
          className="h-full bg-gradient-to-r from-[#4880FF] to-[#354DF0] rounded-full transition-all duration-1000 ease-out shadow-[0_2px_8px_rgba(72,128,255,0.4)]"
          style={{ width: `${percentage}%` }}
        />
      </div>

      <p className="text-gray-400 dark:text-gray-500 text-[11px] font-medium mt-2 text-right">
        Confidence rating based on neural heuristics & flow metadata.
      </p>
    </div>
  );
};

export default ConfidenceBar;
