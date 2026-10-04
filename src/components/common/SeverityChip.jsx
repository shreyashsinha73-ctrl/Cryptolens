import React from 'react';

const STYLE = {
  CRITICAL: 'bg-red-500/15 text-red-600 dark:text-red-300',
  HIGH: 'bg-orange-500/15 text-orange-600 dark:text-orange-300',
  MEDIUM: 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
  LOW: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300',
};

export default function SeverityChip({ severity }) {
  const s = String(severity || '').toUpperCase();
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${STYLE[s] || 'bg-gray-500/15 text-gray-600'}`}>
      {s || 'INFO'}
    </span>
  );
}

export function Skeleton({ lines = 4 }) {
  return (
    <div className="space-y-3 animate-pulse py-4" aria-busy="true">
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-4 rounded bg-gray-200 dark:bg-[#2A2C34]" style={{ width: `${95 - i * 12}%` }} />
      ))}
    </div>
  );
}

