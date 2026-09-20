import React from 'react';

const THREAT_LIST = [
  { name: 'Malware', count: 47, color: '#F97316' },
  { name: 'Phishing', count: 89, color: '#EAB308' },
  { name: 'DDoS', count: 23, color: '#EF4444' },
  { name: 'Ransomware', count: 12, color: '#06B6D4' },
  { name: 'SQL Injection', count: 34, color: '#F59E0B' },
  { name: 'XSS Attack', count: 42, color: '#F43F5E' },
];

const SocRecentThreats = () => {
  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between">
      <div>
        <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
          Recent Threats
        </h3>
        <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
          Signature classifications in current cycle
        </p>
      </div>

      <div className="divide-y divide-gray-100 dark:divide-[#2A2C34] mt-2">
        {THREAT_LIST.map((threat) => (
          <div
            key={threat.name}
            className="py-3 flex items-center justify-between transition-colors hover:bg-gray-50/70 dark:hover:bg-[#23252A]/50 px-1 rounded-lg"
          >
            <div className="flex items-center space-x-3">
              <span
                className="w-2.5 h-2.5 rounded-full shrink-0"
                style={{ backgroundColor: threat.color }}
              />
              <span className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                {threat.name}
              </span>
            </div>

            <span className="text-sm font-extrabold text-gray-900 dark:text-white font-mono">
              {threat.count}
            </span>
          </div>
        ))}
      </div>

      <div className="pt-3 border-t border-gray-100 dark:border-[#2A2C34] flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
        <span>Total Detected</span>
        <span className="font-bold text-gray-900 dark:text-white">247</span>
      </div>
    </div>
  );
};

export default SocRecentThreats;
