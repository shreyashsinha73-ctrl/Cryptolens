import React from 'react';
import { impactsFor } from '../../data/impacts.js';
import SeverityChip from '../common/SeverityChip.jsx';

export default function AttackerImpactCards({ findings }) {
  const cards = impactsFor(findings);
  if (cards.length === 0) return null;
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {cards.map((c) => (
        <div key={c.id} className="rounded-xl border border-gray-200 dark:border-[#2A2C34] bg-white dark:bg-[#18191D] p-4">
          <div className="flex items-center justify-between">
            <div className="text-[10px] font-bold uppercase text-gray-400">What an attacker could do</div>
            <SeverityChip severity={c.severity} />
          </div>
          <div className="text-sm font-bold text-gray-900 dark:text-white mt-1">{c.heading}</div>
          <p className="text-xs text-gray-700 dark:text-gray-300 mt-1">{c.impact}</p>
          <div className="text-[10px] text-gray-500 mt-2">
            Finding: {c.finding}{c.reference ? ` · ${c.reference}` : ''}
          </div>
        </div>
      ))}
    </div>
  );
}
