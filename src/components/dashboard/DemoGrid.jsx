import React, { useState } from 'react';
import demo from '../../data/demo_dataset.json';
import { computeGrade } from '../../lib/grade.js';

const LIGHT = { red: 'bg-red-500', amber: 'bg-amber-500', green: 'bg-emerald-500' };

export default function DemoGrid() {
  const [mode, setMode] = useState('wire_only'); // 'wire_only' | 'with_sidecar'
  const isSidecar = mode === 'with_sidecar';

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-200 dark:border-[#2A2C34] pb-3">
        <div className="text-xs text-gray-500">
          6 real captures, scored by the live engine. From real run, {demo.generated_at}.
        </div>
        <div className="flex items-center gap-1 bg-gray-100 dark:bg-[#23252B] p-1 rounded-lg border border-gray-200 dark:border-[#2C384B] shrink-0">
          <button
            type="button"
            onClick={() => setMode('wire_only')}
            className={`px-3 py-1 text-xs font-bold rounded-md transition-colors ${
              !isSidecar
                ? 'bg-white dark:bg-[#18191D] text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Wire-only
          </button>
          <button
            type="button"
            onClick={() => setMode('with_sidecar')}
            className={`px-3 py-1 text-xs font-bold rounded-md transition-colors ${
              isSidecar
                ? 'bg-white dark:bg-[#18191D] text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            With testbed config (operator-attested)
          </button>
        </div>
      </div>

      {isSidecar && (
        <div className="text-xs font-medium px-3 py-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-700 dark:text-blue-300">
          Config supplied from our testbed ground truth. Unobserved fields verified via operator sidecar.
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {demo.captures.map((item) => {
          const evalData = isSidecar ? item.with_sidecar : item.wire_only;
          if (!evalData) return null;

          const g = computeGrade({
            score: evalData.score,
            worst: evalData.score_if_unobserved_fail,
            best: evalData.score_if_unobserved_pass,
            coverage: evalData.coverage,
            riskLevel: evalData.risk_level,
          });

          return (
            <div
              key={item.capture}
              className="rounded-xl border border-gray-200 dark:border-[#2A2C34] bg-white dark:bg-[#18191D] p-4 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className={`w-3 h-3 rounded-full shrink-0 ${LIGHT[g.light]}`} />
                    <span className="text-2xl font-black text-gray-900 dark:text-white">
                      {g.label}
                      {isSidecar && (
                        <span className="text-[11px] font-semibold text-blue-600 dark:text-blue-400 ml-1.5">
                          (operator-attested)
                        </span>
                      )}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-gray-100 dark:bg-[#23252B] text-gray-600 dark:text-gray-300">
                    {evalData.coverage}
                  </span>
                </div>
                <div
                  className="text-xs font-mono font-semibold text-gray-700 dark:text-gray-300 mt-2.5 truncate"
                  title={item.capture}
                >
                  {item.capture}
                </div>
              </div>
              <div className="text-[11px] text-gray-500 dark:text-gray-400 mt-2 border-t border-gray-100 dark:border-[#23252B] pt-2 flex items-center justify-between">
                <span>Range {evalData.score_headline}</span>
                <span className="font-bold">{evalData.risk_level}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
