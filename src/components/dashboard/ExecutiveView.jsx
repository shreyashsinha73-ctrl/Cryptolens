import React from 'react';
import { computeGrade, buildVerdict, GLOSSARY } from '../../lib/grade.js';

const LIGHT = {
  red: { bg: 'bg-red-500', text: 'Action needed' },
  amber: { bg: 'bg-amber-500', text: 'Review recommended' },
  green: { bg: 'bg-emerald-500', text: 'Looks good' },
};

function Term({ k, children }) {
  return (
    <abbr title={GLOSSARY[k]} className="underline decoration-dotted cursor-help">
      {children || k}
    </abbr>
  );
}

export default function ExecutiveView({ data, findings, executiveSummary, engineUsed }) {
  const grade = computeGrade({
    score: data.overall_score,
    worst: data.score_if_unobserved_fail,
    best: data.score_if_unobserved_pass,
    coverage: data.coverage,
    riskLevel: data.risk_level,
  });
  const light = LIGHT[grade.light];
  const verdict = buildVerdict(findings, grade);

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs flex flex-col md:flex-row gap-6 items-start">
      <div className="flex items-center gap-4 shrink-0">
        <div className={`w-5 h-5 rounded-full ${light.bg}`} aria-label={light.text} />
        <div className="text-6xl font-black tracking-tight text-gray-900 dark:text-white">{grade.label}</div>
      </div>
      <div className="space-y-2 min-w-0">
        <div className="text-sm font-bold text-gray-900 dark:text-white">{light.text}</div>
        <p className="text-sm text-gray-700 dark:text-gray-300">{verdict}</p>
        <p className="text-xs text-gray-500">
          Score range {data.score_headline || 'n/a'} · <Term k="Coverage" /> {data.coverage || 'partial'}.
          Terms: <Term k="PFS" />, <Term k="ESP" />, <Term k="IKE" />, <Term k="DH group" />.
        </p>
        {executiveSummary && (
          <div className="text-xs text-gray-600 dark:text-gray-400 border-l-2 border-blue-500 pl-3">
            {executiveSummary}
            {engineUsed && <span className="ml-2 font-bold">[{engineUsed}]</span>}
          </div>
        )}
      </div>
    </div>
  );
}
