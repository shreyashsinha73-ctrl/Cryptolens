import React, { useState, useEffect } from 'react';

const ScoreDial = ({ overall_score }) => {
  const score = Math.min(Math.max(overall_score || 0, 0), 100);
  
  const [currentScore, setCurrentScore] = useState(0);
  const [displayNumber, setDisplayNumber] = useState(0);

  useEffect(() => {
    // Reset state if score prop changes (e.g. from preset toggle)
    setCurrentScore(0);
    setDisplayNumber(0);
    
    const timeout = setTimeout(() => {
      setCurrentScore(score);
      
      // Start JS number animation alongside CSS stroke animation
      let startTimestamp = null;
      const duration = 1500; // ms
      
      const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        
        // ease-out cubic
        const easeOut = 1 - Math.pow(1 - progress, 3);
        
        setDisplayNumber(Math.floor(easeOut * score));
        
        if (progress < 1) {
          window.requestAnimationFrame(step);
        } else {
          setDisplayNumber(score);
        }
      };
      window.requestAnimationFrame(step);
      
    }, 100);

    return () => clearTimeout(timeout);
  }, [score]);

  let colorCode = '#f43f5e'; // Rose
  let verdictText = 'CRITICAL ACTION REQUIRED';
  let verdictBg = 'bg-rose-500/10 text-rose-400 border-rose-500/20 shadow-[0_0_8px_rgba(244,63,94,0.2)]';

  if (score >= 85) {
    colorCode = '#10b981'; // Emerald
    verdictText = 'LOW RISK';
    verdictBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 shadow-[0_0_8px_rgba(16,185,129,0.2)]';
  } else if (score >= 70) {
    colorCode = '#f59e0b'; // Amber
    verdictText = 'MEDIUM RISK';
    verdictBg = 'bg-amber-500/10 text-amber-400 border-amber-500/20 shadow-[0_0_8px_rgba(245,158,11,0.2)]';
  }

  const radius = 55;
  const circumference = 2 * Math.PI * radius; // Full circle
  const strokeDashoffset = circumference - (currentScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center w-full">
      <div className="relative w-40 h-40 flex items-center justify-center">
        <svg className="absolute w-full h-full transform -rotate-90 overflow-visible" viewBox="0 0 140 140">
          <defs>
            <filter id="neonGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur1" />
              <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur2" />
              <feMerge>
                <feMergeNode in="blur2" />
                <feMergeNode in="blur1" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          
          {/* Muted background track */}
          <circle
            className="stroke-slate-800"
            strokeWidth="10"
            fill="transparent"
            r={radius}
            cx="70"
            cy="70"
          />
          {/* Animated colored progress stroke with Neon Glow */}
          <circle
            stroke={colorCode}
            strokeWidth="10"
            strokeLinecap="round"
            fill="transparent"
            r={radius}
            cx="70"
            cy="70"
            filter="url(#neonGlow)"
            className="transition-all duration-[1500ms] ease-out"
            style={{
              strokeDasharray: circumference,
              strokeDashoffset: strokeDashoffset
            }}
          />
        </svg>
        {/* Centered Score */}
        <div className="relative flex items-baseline">
          <span className="text-5xl font-bold font-mono tracking-tighter" style={{ color: colorCode, textShadow: `0 0 15px ${colorCode}60` }}>
            {displayNumber}
          </span>
          <span className="text-sm font-mono text-slate-500 ml-1">/100</span>
        </div>
      </div>
      <div className="mt-8 flex flex-col items-center">
        <span className="text-[10px] font-mono text-slate-500 tracking-widest mb-2 uppercase font-semibold">NIST Compliance Status</span>
        <div className={`px-3 py-1.5 rounded-full text-[10px] font-mono font-bold tracking-widest border ${verdictBg}`}>
          {verdictText}
        </div>
      </div>
    </div>
  );
};

export default ScoreDial;
