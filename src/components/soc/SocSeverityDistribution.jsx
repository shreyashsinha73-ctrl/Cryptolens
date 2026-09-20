import React, { useState, useEffect, useMemo } from 'react';

const SIZE = 180;
const STROKE_WIDTH = 26;
const RADIUS = (SIZE - STROKE_WIDTH) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const COLORS = {
  CRITICAL: '#EF4444',
  HIGH:     '#F97316',
  MEDIUM:   '#EAB308',
  LOW:      '#06B6D4',
  INFO:     '#6B7280',
};

const SocSeverityDistribution = ({ threatMatrix = [] }) => {
  const [activeItem, setActiveItem] = useState(null);
  const [animProgress, setAnimProgress] = useState(0);

  // Derive severity counts from real data
  const severities = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    threatMatrix.forEach((f) => {
      const sev = (f.severity || 'INFO').toUpperCase();
      if (sev in counts) counts[sev]++;
      else counts.INFO++;
    });
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return null;

    let offset = 0;
    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((key) => {
      const pct = Math.round((counts[key] / total) * 100);
      const item = { id: key.toLowerCase(), name: key[0] + key.slice(1).toLowerCase(), value: pct, count: counts[key], color: COLORS[key], offset };
      offset += pct;
      return item;
    }).filter(s => s.count > 0);
  }, [threatMatrix]);

  useEffect(() => {
    setAnimProgress(0);
    if (!severities) return;
    let start = null;
    let animFrame = null;
    const duration = 1200;
    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      setAnimProgress(1 - Math.pow(1 - progress, 3));
      if (progress < 1) animFrame = requestAnimationFrame(step);
    };
    animFrame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animFrame);
  }, [severities]);

  if (!severities) {
    return (
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs flex flex-col items-center justify-center h-full min-h-[240px]">
        <p className="text-xs font-semibold text-gray-400 dark:text-gray-500 text-center">
          Severity distribution will appear after PCAP analysis.
        </p>
      </div>
    );
  }

  const total = threatMatrix.length;
  const active = activeItem ? severities.find(s => s.id === activeItem) : null;

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between h-full">
      <div>
        <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">Severity Distribution</h3>
        <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
          Breakdown by finding severity
        </p>
      </div>

      {/* Donut */}
      <div className="relative flex items-center justify-center my-auto py-2">
        <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} className="transform -rotate-90">
          {severities.map((sev) => {
            const isHighlighted = activeItem === sev.id;
            const val  = sev.value * animProgress;
            const off  = sev.offset * animProgress;
            return (
              <circle
                key={sev.id}
                cx={SIZE / 2} cy={SIZE / 2} r={RADIUS}
                fill="transparent"
                stroke={sev.color}
                strokeWidth={isHighlighted ? STROKE_WIDTH + 4 : STROKE_WIDTH}
                strokeDasharray={`${(val / 100) * CIRCUMFERENCE} ${CIRCUMFERENCE}`}
                strokeDashoffset={-((off / 100) * CIRCUMFERENCE)}
                strokeLinecap="round"
                className="cursor-pointer transition-all duration-200"
                onMouseEnter={() => setActiveItem(sev.id)}
                onMouseLeave={() => setActiveItem(null)}
              />
            );
          })}
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none">
          <span className="text-2xl font-black text-gray-900 dark:text-white leading-tight">
            {active ? `${active.value}%` : total}
          </span>
          <span className="text-[10px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
            {active ? active.name : 'Findings'}
          </span>
        </div>
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-y-2 gap-x-4 pt-3 border-t border-gray-100 dark:border-[#2A2C34] text-xs font-semibold">
        {severities.map((sev) => (
          <div
            key={sev.id}
            onMouseEnter={() => setActiveItem(sev.id)}
            onMouseLeave={() => setActiveItem(null)}
            className="flex items-center space-x-2 cursor-pointer transition-opacity hover:opacity-80"
          >
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: sev.color }} />
            <span className="text-gray-600 dark:text-gray-300">{sev.name}</span>
            <span className="text-gray-400 dark:text-gray-500 text-[11px] font-normal ml-auto">{sev.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SocSeverityDistribution;
