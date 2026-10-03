import React from 'react';
import demo from '../../data/demo_dataset.json';
import { computeGrade } from '../../lib/grade.js';

const LIGHT = { red: 'bg-red-500', amber: 'bg-amber-500', green: 'bg-emerald-500' };

export default function DemoGrid() {
  return (
    <div className="space-y-3">
      <div className="text-xs text-gray-500">
        6 real captures, scored by the live engine. From real run, {demo.generated_at}.
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {demo.captures.map((c) => {
          const g = computeGrade({
            score: c.score,
            worst: c.score_if_unobserved_fail,
            best: c.score_if_unobserved_pass,
            coverage: c.coverage,
            riskLevel: c.risk_level,
          });
          return (
            <div key={c.capture} className="rounded-xl border border-gray-200 dark:border-[#2A2C34] bg-white dark:bg-[#18191D] p-4">
              <div className="flex items-center gap-3">
                <span className={`w-3 h-3 rounded-full ${LIGHT[g.light]}`} />
                <span className="text-3xl font-black text-gray-900 dark:text-white">{g.label}</span>
              </div>
              <div className="text-xs font-mono text-gray-600 dark:text-gray-300 mt-2 truncate" title={c.capture}>{c.capture}</div>
              <div className="text-xs text-gray-500 mt-1">
                Range {c.score_headline} · {c.risk_level}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
