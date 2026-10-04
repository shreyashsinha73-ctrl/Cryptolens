import React, { useState } from 'react';
import { computeGrade, buildVerdict, GLOSSARY } from '../../lib/grade.js';

const LIGHT = {
  red: { bg: 'bg-red-500', text: 'Action needed' },
  amber: { bg: 'bg-amber-500', text: 'Review recommended' },
  green: { bg: 'bg-emerald-500', text: 'Looks good' },
};

function Term({ k, children }) {
  return (
    <abbr title={GLOSSARY[k]} className="underline decoration-dotted cursor-help text-blue-600 dark:text-blue-400">
      {children || k}
    </abbr>
  );
}

export default function ExecutiveView({
  data,
  findings = [],
  executiveSummary = null,
  verboseReport = null,
  findingsExplanations = [],
  engineUsed = null,
  cachedBadge = null,
  isAiGenerated = false,
}) {
  const [showDetailedFindings, setShowDetailedFindings] = useState(true);

  const grade = computeGrade({
    score: data.overall_score,
    worst: data.score_if_unobserved_fail,
    best: data.score_if_unobserved_pass,
    coverage: data.coverage,
    riskLevel: data.risk_level,
  });
  const light = LIGHT[grade.light];
  const verdict = buildVerdict(findings, grade);

  const reportText = verboseReport || executiveSummary;
  const isGemini = engineUsed && engineUsed.toLowerCase().includes('gemini');

  return (
    <div className="space-y-4">
      {/* Primary Grade & High-Level Posture Card */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs flex flex-col md:flex-row gap-6 items-start">
        <div className="flex items-center gap-4 shrink-0">
          <div className={`w-5 h-5 rounded-full ${light.bg} shadow-xs animate-pulse`} aria-label={light.text} />
          <div className="text-6xl font-black tracking-tight text-gray-900 dark:text-white">{grade.label}</div>
        </div>
        <div className="space-y-2 min-w-0 flex-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-sm font-bold text-gray-900 dark:text-white uppercase tracking-wider">{light.text}</span>
            <div className="flex items-center gap-2">
              {engineUsed && (
                <span className={`text-[11px] font-mono px-2.5 py-0.5 rounded-full font-bold border ${
                  isGemini
                    ? 'bg-purple-500/10 text-purple-700 dark:text-purple-300 border-purple-500/30'
                    : 'bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/30'
                }`}>
                  {isGemini ? '✨ ' : ''}{engineUsed}
                </span>
              )}
              {cachedBadge && (
                <span className="text-[10px] font-mono text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-[#22242B] px-2 py-0.5 rounded border border-gray-200 dark:border-gray-800">
                  {cachedBadge}
                </span>
              )}
            </div>
          </div>
          <p className="text-sm font-medium text-gray-800 dark:text-gray-200 leading-relaxed">{verdict}</p>
          <div className="text-xs text-gray-500 flex flex-wrap items-center gap-x-2 gap-y-1 pt-1">
            <span>Score headline: <strong className="text-gray-700 dark:text-gray-300">{data.score_headline || 'n/a'}</strong></span>
            <span>·</span>
            <span><Term k="Coverage" />: <strong className="text-gray-700 dark:text-gray-300">{data.coverage || 'partial'}</strong></span>
            <span>·</span>
            <span>Audited terms: <Term k="PFS" />, <Term k="ESP" />, <Term k="IKE" />, <Term k="DH group" /></span>
          </div>
        </div>
      </div>

      {/* Gemini AI Verbose Executive Assessment */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-100 dark:border-[#2A2C34] pb-3">
          <div className="flex items-center gap-2">
            <span className="text-base font-extrabold text-gray-900 dark:text-white flex items-center gap-2">
              <svg className="w-4 h-4 text-purple-500" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1.323l3.954 1.582 1.599-.8a1 1 0 011.094 1.666l-1.09 1.454 1.455 1.09a1 1 0 01-1.2 1.6l-1.6-.8-1.582 3.954V17a1 1 0 11-2 0v-1.323l-3.954-1.582-1.599.8a1 1 0 01-1.094-1.666l1.09-1.454-1.455-1.09a1 1 0 011.2-1.6l1.6.8 1.582-3.954V3a1 1 0 011-1z" clipRule="evenodd" />
              </svg>
              Executive Security Briefing (Minimalist Jargon)
            </span>
          </div>
          <span className="text-xs font-semibold text-gray-500 dark:text-gray-400">
            Automated Executive Briefing for Non-Technical Stakeholders &amp; Leadership
          </span>
        </div>

        {reportText ? (
          <div className="space-y-3">
            <div className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed space-y-2 whitespace-pre-line bg-gray-50 dark:bg-[#1F2228] p-4 rounded-xl border border-gray-100 dark:border-[#2A2C34]">
              {reportText}
            </div>

            {findingsExplanations && findingsExplanations.length > 0 && (
              <div className="pt-2">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-gray-800 dark:text-gray-200 uppercase tracking-wider">
                    Plain-English Finding Breakdown ({findingsExplanations.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => setShowDetailedFindings((v) => !v)}
                    className="text-[11px] font-bold text-blue-600 hover:text-blue-700 dark:text-blue-400 cursor-pointer"
                  >
                    {showDetailedFindings ? 'Hide Details ▲' : 'Show Details ▼'}
                  </button>
                </div>

                {showDetailedFindings && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {findingsExplanations.map((f, idx) => (
                      <div
                        key={idx}
                        className="bg-white dark:bg-[#15171B] border border-gray-200 dark:border-[#2A2C34] rounded-xl p-3.5 space-y-2 text-xs"
                      >
                        <div>
                          <span className="text-[10px] font-black uppercase tracking-wider text-gray-400 block">Finding</span>
                          <span className="font-bold text-gray-900 dark:text-gray-100">{f.plain_summary}</span>
                        </div>
                        <div>
                          <span className="text-[10px] font-black uppercase tracking-wider text-amber-500 block">Why It Matters</span>
                          <span className="text-gray-600 dark:text-gray-300">{f.why_it_matters}</span>
                        </div>
                        <div>
                          <span className="text-[10px] font-black uppercase tracking-wider text-emerald-500 block">What Changed in Hardened Profile</span>
                          <span className="text-emerald-700 dark:text-emerald-400 font-medium">{f.what_changed}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="text-xs text-gray-500 italic p-3 bg-gray-50 dark:bg-[#1A1C21] rounded-xl border border-dashed border-gray-300 dark:border-gray-700">
            Generating verbose executive analysis from Gemini API...
          </div>
        )}
      </div>
    </div>
  );
}
