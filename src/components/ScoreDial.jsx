import React, { useState, useEffect } from 'react';
import { useTheme } from '../context/useTheme.js';
import Badge from './common/Badge.jsx';

const ScoreDial = ({
  overall_score,
  risk_level,
  base_risk_level,
  nist_status,
  cnsa_status,
  _score_headline,
  coverage,
  coverage_ratio,
  score_if_unobserved_fail,
  score_if_unobserved_pass,
  score_breakdown,
}) => {
  const { isDark } = useTheme();
  const [showTooltip, setShowTooltip] = useState(false);

  const isNotAssessed =
    overall_score === null || overall_score === undefined;

  const score = isNotAssessed
    ? 0
    : Math.min(Math.max(overall_score, 0), 100);

  const radius = 56;
  const circumference = 2 * Math.PI * radius;

  // Start with 0 progress
  const [currentScore, setCurrentScore] = useState(0);
  const [displayNumber, setDisplayNumber] = useState(0);

  useEffect(() => {
    setCurrentScore(score);
    setDisplayNumber(score);
  }, [score]);

  // Determine risk level and presentation strictly from backend or derived score
  const effectiveRisk = base_risk_level || risk_level || (
    score >= 90 ? 'LOW' :
    score >= 75 ? 'MODERATE' :
    score >= 50 ? 'HIGH' : 'CRITICAL'
  );

  const normalizedRisk = (isNotAssessed ? 'NOT_ASSESSED' : effectiveRisk).toUpperCase();

  let colorCode = '#EF3826'; // Red
  let badgeVariant = 'rejected';
  let statusText = 'CRITICAL RISK';
  if (normalizedRisk === 'NOT_ASSESSED') {
    colorCode = '#9CA3AF';
    badgeVariant = 'on_hold';
    statusText = 'NOT ASSESSED';
  } else if (normalizedRisk.includes('LOW') || normalizedRisk === 'COMPLIANT') {
    colorCode = '#00B69B'; // Green
    badgeVariant = 'completed';
    statusText = normalizedRisk.includes('OPERATOR') ? 'LOW RISK (OPERATOR-ATTESTED)' : 'COMPLIANT (LOW RISK)';
  } else if (normalizedRisk.includes('MODERATE') || normalizedRisk.includes('MEDIUM')) {
    colorCode = '#FFA756'; // Amber
    badgeVariant = 'on_hold';
    statusText = 'MEDIUM RISK';
  } else if (normalizedRisk.includes('HIGH')) {
    colorCode = '#F97316'; // Orange-Red
    badgeVariant = 'rejected';
    statusText = 'HIGH RISK';
  } else {
    colorCode = '#EF3826'; // Red
    badgeVariant = 'rejected';
    statusText = 'CRITICAL RISK';
  }

  const strokeDashoffset = circumference - (currentScore / 100) * circumference;

  // Unobserved categories calculation for tooltip
  const unobservedList = [];
  if (score_breakdown && typeof score_breakdown === 'object') {
    Object.entries(score_breakdown).forEach(([k, v]) => {
      if (v && v.observability && v.observability !== 'observed') {
        const catName = k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const obsLabel = v.observability === 'operator_supplied' ? 'operator_supplied' : (v.observability || 'not_observable');
        const evLabel = v.evidence_source || 'unobservable_on_wire';
        unobservedList.push({ name: catName, obs: obsLabel, ev: evLabel });
      }
    });
  }

  const rangeDiff = (score_if_unobserved_pass !== undefined && score_if_unobserved_fail !== undefined)
    ? Math.abs(score_if_unobserved_pass - score_if_unobserved_fail)
    : 0;

  const covPct = coverage_ratio !== undefined && coverage_ratio !== null
    ? Math.round(coverage_ratio * 100)
    : (coverage ? Math.round((parseInt(coverage.split('/')[0], 10) / (parseInt(coverage.split('/')[1], 10) || 8)) * 100) : 100);

  return (
    <div className="flex flex-col items-center justify-center w-full py-2">
      <div className="relative w-44 h-44 flex items-center justify-center">
        <svg
          className="absolute w-full h-full transform -rotate-90 overflow-visible"
          viewBox="0 0 140 140"
        >
          <defs>
            <filter id="dialGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Background track */}
          <circle
            stroke={isDark ? '#1B2431' : '#F1F2F6'}
            strokeWidth="11"
            fill="transparent"
            r={radius}
            cx="70"
            cy="70"
          />

          {/* Progress stroke with DashStack accent */}
          <circle
            stroke={colorCode}
            strokeWidth="11"
            strokeLinecap="round"
            fill="transparent"
            r={radius}
            cx="70"
            cy="70"
            filter="url(#dialGlow)"
            className="transition-all duration-[1400ms] ease-out"
            style={{
              strokeDasharray: circumference,
              strokeDashoffset: strokeDashoffset,
            }}
          />
        </svg>

        {/* Centered Score: ONE deterministic headline number */}
        <div className="relative flex flex-col items-center justify-center select-none text-center px-2">
          {isNotAssessed ? (
            <div className="text-2xl font-black font-['Nunito_Sans'] tracking-tight text-gray-400 dark:text-gray-500 text-center">
              N/A
            </div>
          ) : (
            <div className="flex flex-col items-center">
              <div className="flex items-baseline">
                <span
                  className="text-4xl sm:text-5xl font-black font-['Nunito_Sans'] tracking-tight"
                  style={{ color: colorCode }}
                >
                  {displayNumber}
                </span>
                <span className="text-sm font-bold text-[#646464] dark:text-gray-400 ml-1">
                  /100
                </span>
              </div>
              <span className="text-[10px] font-bold text-gray-500 dark:text-gray-400 mt-0.5 whitespace-nowrap">
                based on {covPct}% of checks observable
              </span>
            </div>
          )}
          <span className="text-[11px] font-bold uppercase tracking-wider text-gray-400 dark:text-gray-500 mt-1">
            Score
          </span>
        </div>
      </div>

      {/* Details & Range Tooltip trigger (shown when range > 5 or unobserved checks exist) */}
      {!isNotAssessed && (unobservedList.length > 0 || rangeDiff > 0) && (
        <div className="relative mt-2 flex flex-col items-center">
          {(
            <button
              type="button"
              onClick={() => setShowTooltip(v => !v)}
              onMouseEnter={() => setShowTooltip(true)}
              onMouseLeave={() => setShowTooltip(false)}
              className="text-[10px] text-indigo-500 hover:text-indigo-400 font-bold underline cursor-pointer flex items-center gap-1"
            >
              <span>Interval &amp; Observability details</span>
              <svg className="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </button>
          )}

          {showTooltip && unobservedList.length > 0 && (
            <div className="absolute bottom-6 z-50 w-64 p-3 bg-gray-900 text-white rounded-xl shadow-xl text-left border border-gray-700 text-xs">
              <div className="font-bold border-b border-gray-700 pb-1 mb-1.5 flex justify-between">
                <span>Best/Worst Case Interval</span>
                <span className="font-mono text-indigo-400">
                  {score_if_unobserved_fail ?? score}–{score_if_unobserved_pass ?? 100}
                </span>
              </div>
              <p className="text-[10px] text-gray-300 mb-1.5">
                Unobserved categories are neither assumed safe nor failing:
              </p>
              <ul className="space-y-1 text-[10px] max-h-36 overflow-y-auto">
                {unobservedList.map((item, idx) => (
                  <li key={idx} className="flex justify-between items-center gap-1">
                    <span className="font-medium text-gray-200">{item.name}:</span>
                    <span className="font-mono text-[9px] px-1 py-0.5 bg-gray-800 rounded text-amber-300">
                      {item.obs} ({item.ev})
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="mt-4 flex flex-col items-center space-y-1.5">
        <span className="text-[11px] font-bold text-[#646464] dark:text-gray-400 tracking-wider uppercase">
          Security Posture
        </span>
        <Badge variant={badgeVariant} label={statusText} size="md" />
        <div className="mt-3 text-center flex gap-4">
          <div>
            <span className="text-[10px] font-bold text-[#646464] dark:text-gray-400 tracking-wider uppercase">
              NIST SP 800-77
            </span>
            <div className="text-sm font-extrabold text-gray-900 dark:text-white mt-1">
              {nist_status || 'NOT_ASSESSED'}
            </div>
          </div>
          <div>
            <span className="text-[10px] font-bold text-[#646464] dark:text-gray-400 tracking-wider uppercase">
              NSA CNSA 2.0
            </span>
            <div className="text-sm font-extrabold text-gray-900 dark:text-white mt-1">
              {cnsa_status || 'NOT_ASSESSED'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScoreDial;
