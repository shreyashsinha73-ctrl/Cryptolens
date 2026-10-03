import React from 'react';
import { computeGrade } from '../../lib/grade.js';

// Current (observed) vs hardened parameters, with a PROJECTED (not re-measured) grade.
export default function BeforeAfterDiff({ diff, projected, engineUsed }) {
  if (!Array.isArray(diff) || diff.length === 0) return null;

  const grade = projected
    ? computeGrade({
        score: projected.score,
        worst: projected.score_if_unobserved_fail,
        best: projected.score_if_unobserved_pass,
        coverage: projected.coverage,
        riskLevel: projected.risk_level,
      })
    : null;

  const asText = diff
    .map((r) => `- ${r.param}: ${r.current ?? 'not observable'}\n+ ${r.param}: ${r.hardened}`)
    .join('\n');

  const download = () => {
    const url = URL.createObjectURL(new Blob([asText], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cryptolens_config_diff.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="rounded-xl border border-gray-200 dark:border-[#2C384B] p-4 space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="text-xs font-bold text-gray-900 dark:text-white">
          Before / After
          {engineUsed && <span className="ml-2 text-gray-500">[{engineUsed}]</span>}
        </div>
        <div className="flex items-center gap-2">
          {grade && (
            <span className="text-xs font-bold px-2 py-1 rounded bg-blue-500/10 text-blue-600 dark:text-blue-300"
                  title={projected.note}>
              PROJECTED grade {grade.label} · not re-measured
            </span>
          )}
          <button type="button" className="text-xs font-bold underline"
                  onClick={() => navigator.clipboard.writeText(asText)}>Copy</button>
          <button type="button" className="text-xs font-bold underline" onClick={download}>Download</button>
        </div>
      </div>
      <pre className="font-mono text-xs leading-relaxed overflow-x-auto">
        {diff.map((r) => (
          <React.Fragment key={r.param}>
            <div className="bg-red-500/10 text-red-700 dark:text-red-300 px-2">
              - {r.param}: {r.current ?? 'not observable from capture'}
            </div>
            <div className="bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 px-2">
              + {r.param}: {r.hardened}
            </div>
          </React.Fragment>
        ))}
      </pre>
    </div>
  );
}
