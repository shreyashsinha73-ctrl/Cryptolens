import React, { useState, useEffect } from 'react';
import { useTheme } from '../context/useTheme.js';
import Badge from './common/Badge.jsx';

const ScoreDial = ({
  overall_score,
  risk_level,
  nist_status,
  score_headline,
  coverage,
  score_if_unobserved_fail,
  score_if_unobserved_pass,
}) => {
  const { isDark } = useTheme();
  const isNotAssessed =
  overall_score === null || overall_score === undefined;

const score = isNotAssessed
  ? 0
  : Math.min(Math.max(overall_score, 0), 100);

  const radius = 56;
  const circumference = 2 * Math.PI * radius;

  // Start with 0 progress (stroke offset = circumference -> empty circle)
  const [currentScore, setCurrentScore] = useState(0);
  const [displayNumber, setDisplayNumber] = useState(0);

  useEffect(() => {
    // Reset to 0 initially
    setCurrentScore(0);
    setDisplayNumber(0);

    let animFrameId = null;
    const timeout = setTimeout(() => {
      setCurrentScore(score);

      let startTimestamp = null;
      const duration = 1400; // ms

      const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        const easeOut = 1 - Math.pow(1 - progress, 3);

        setDisplayNumber(Math.floor(easeOut * score));

        if (progress < 1) {
          animFrameId = window.requestAnimationFrame(step);
        } else {
          setDisplayNumber(score);
        }
      };
      animFrameId = window.requestAnimationFrame(step);
    }, 80);

    return () => {
      clearTimeout(timeout);
      if (animFrameId) window.cancelAnimationFrame(animFrameId);
    };
  }, [score]);

  // Determine risk level and presentation strictly from backend or derived score
  const normalizedRisk = (
    isNotAssessed
      ? 'NOT_ASSESSED'
        : (
            risk_level || (
              score >= 90 ? 'LOW' :
              score >= 75 ? 'MODERATE' :
              score >= 50 ? 'HIGH' : 'CRITICAL'
            )
          )
  ).toUpperCase();

  let colorCode = '#EF3826'; // Red
  let badgeVariant = 'rejected';
  let statusText = 'CRITICAL RISK';
  if (normalizedRisk === 'NOT_ASSESSED') {
    colorCode = '#9CA3AF';
    badgeVariant = 'on_hold';
    statusText = 'NOT ASSESSED';
  } else if (normalizedRisk === 'UNVERIFIED') {
    colorCode = '#818CF8'; // Indigo
    badgeVariant = 'on_hold';
    statusText = 'UNVERIFIED (PARTIAL TELEMETRY)';
  } else if (normalizedRisk === 'LOW' || normalizedRisk === 'COMPLIANT') {
    colorCode = '#00B69B'; // Green
    badgeVariant = 'completed';
    statusText = 'COMPLIANT (LOW RISK)';
  } else if (normalizedRisk === 'MODERATE' || normalizedRisk === 'MEDIUM') {
    colorCode = '#FFA756'; // Amber
    badgeVariant = 'on_hold';
    statusText = 'MEDIUM RISK';
  } else if (normalizedRisk === 'HIGH') {
    colorCode = '#F97316'; // Orange-Red
    badgeVariant = 'rejected';
    statusText = 'HIGH RISK';
  } else {
    colorCode = '#EF3826'; // Red
    badgeVariant = 'rejected';
    statusText = 'CRITICAL RISK';
  }

  const strokeDashoffset = circumference - (currentScore / 100) * circumference;

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

        {/* Centered Score */}
        <div className="relative flex flex-col items-center justify-center select-none">
          {isNotAssessed ? (
            <div
              className="text-2xl font-black font-['Nunito_Sans'] tracking-tight text-gray-400 dark:text-gray-500 text-center"
            >
              N/A
            </div>
          ) : normalizedRisk === 'UNVERIFIED' ? (
            <div className="flex flex-col items-center">
              <span
                className="text-2xl font-black font-['Nunito_Sans'] tracking-tight"
                style={{ color: colorCode }}
              >
                {score_headline || `${score_if_unobserved_fail ?? score}–${score_if_unobserved_pass ?? 100}`}
              </span>
              <span className="text-[10px] font-extrabold uppercase text-indigo-400 mt-0.5">
                Cov: {coverage || 'Partial'}
              </span>
            </div>
          ) : (
            <div className="flex items-baseline">
              <span
                className="text-5xl font-black font-['Nunito_Sans'] tracking-tight"
                style={{ color: colorCode }}
              >
                {displayNumber}
              </span>
              <span className="text-sm font-bold text-[#646464] dark:text-gray-400 ml-1">
                /100
              </span>
            </div>
          )}
          <span className="text-[11px] font-bold uppercase tracking-wider text-gray-400 dark:text-gray-500 mt-1">
            Score
          </span>
        </div>
      </div>

      <div className="mt-6 flex flex-col items-center space-y-1.5">
        <span className="text-[11px] font-bold text-[#646464] dark:text-gray-400 tracking-wider uppercase">
          Security Posture
        </span>
        <Badge variant={badgeVariant} label={statusText} size="md" />
         <div className="mt-3 text-center">
          <span className="text-[10px] font-bold text-[#646464] dark:text-gray-400 tracking-wider uppercase">
            NIST SP 800-77
          </span>

          <div className="text-sm font-extrabold text-gray-900 dark:text-white mt-1">
            {nist_status || 'NOT_ASSESSED'}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScoreDial;
