import React, { useState, useEffect, useMemo } from 'react';

/**
 * Derives bar/line data from the live threat_matrix.
 * Groups findings by category and counts all severities
 */
const deriveChartData = (threatMatrix) => {
  if (!threatMatrix || !threatMatrix.length) return null;

  // Group by category
  const categoryMap = {};
  threatMatrix.forEach((f) => {
    const cat = (f.category || f.threat_category || 'Other').slice(0, 18);
    if (!categoryMap[cat]) categoryMap[cat] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const sev = (f.severity || 'INFO').toUpperCase();
    if (sev === 'CRITICAL') categoryMap[cat].critical++;
    else if (sev === 'HIGH') categoryMap[cat].high++;
    else if (sev === 'MEDIUM') categoryMap[cat].medium++;
    else if (sev === 'LOW') categoryMap[cat].low++;
    else categoryMap[cat].info++;
  });

  const labels = Object.keys(categoryMap);
  const critical = labels.map(l => categoryMap[l].critical);
  const high     = labels.map(l => categoryMap[l].high);
  const medium   = labels.map(l => categoryMap[l].medium);
  const low      = labels.map(l => categoryMap[l].low);
  const info     = labels.map(l => categoryMap[l].info);

  return { labels, critical, high, medium, low , info};
};

const SocAlertVolumeTrend = ({ threatMatrix = [] }) => {
  const [animProgress, setAnimProgress] = useState(0);

  const chartData = useMemo(() => deriveChartData(threatMatrix), [threatMatrix]);

  useEffect(() => {
    setAnimProgress(0);
    if (!chartData) return;
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
  }, [chartData]);

  // ── empty state ──────────────────────────────────────────────────────────
  if (!chartData) {
    return (
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs flex flex-col items-center justify-center h-full min-h-[240px]">
        <p className="text-xs font-semibold text-gray-400 dark:text-gray-500">
          Alert Volume Trend will appear after PCAP analysis.
        </p>
      </div>
    );
  }

  const { labels, critical, high, medium, low, info } = chartData;
  const maxVal = Math.max(...critical, ...high, ...medium, ...low, ...info, 1);

  const svgW = 500;
  const svgH = 180;
  const padB = 30; // space for x-axis labels
  const padT = 16;
  const plotH = svgH - padB - padT;

  const xs = labels.map((_, i) => (i / Math.max(labels.length - 1, 1)) * svgW);

  const toY = (val) => padT + plotH - (val / maxVal) * plotH * animProgress;

  const toPath = (vals) => {
    if (!vals.length) return '';
    const pts = vals.map((v, i) => ({ x: xs[i], y: toY(v) }));
    let d = `M ${pts[0].x} ${pts[0].y}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const cx = (pts[i].x + pts[i + 1].x) / 2;
      d += ` C ${cx} ${pts[i].y}, ${cx} ${pts[i + 1].y}, ${pts[i + 1].x} ${pts[i + 1].y}`;
    }
    return d;
  };

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between h-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
            Alert Volume by Category
          </h3>
          <div className="flex items-center space-x-4 mt-2 text-xs font-semibold">
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
              <span className="text-gray-600 dark:text-gray-300">Critical</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#F97316]" />
              <span className="text-gray-600 dark:text-gray-300">High</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#EAB308]" />
              <span className="text-gray-600 dark:text-gray-300">Medium</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#22C55E]" />
              <span className="text-gray-600 dark:text-gray-300">Low</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#6B7280]" />
              <span className="text-gray-600 dark:text-gray-300">Info</span>
            </div>
          </div>
        </div>
        <span className="text-[11px] text-gray-400 dark:text-gray-500 font-medium self-start sm:self-auto">
          {threatMatrix.length} total findings
        </span>
      </div>

      {/* SVG chart */}
      <div className="relative w-full overflow-hidden">
        <div className="flex items-stretch">
          {/* Y-axis */}
          <div className="flex flex-col justify-between pr-2 text-[10px] font-semibold text-gray-400 dark:text-gray-500 pb-7 select-none" style={{ minWidth: 24 }}>
            <span>{maxVal}</span>
            <span>{Math.round(maxVal / 2)}</span>
            <span>0</span>
          </div>

          <div className="flex-1 relative">
            <svg viewBox={`0 0 ${svgW} ${svgH}`} className="w-full" style={{ height: svgH }} preserveAspectRatio="none">
              {/* Grid */}
              {[0, 0.5, 1].map((fraction) => {
                const y = padT + plotH * (1 - fraction);
                return (
                  <line key={fraction} x1={0} y1={y} x2={svgW} y2={y}
                    stroke="currentColor" strokeWidth="1" strokeDasharray="3 3"
                    className="text-gray-200 dark:text-gray-800" />
                );
              })}

              {/* Lines */}
              <path d={toPath(low)} fill="none" stroke="#22C55E" strokeWidth="2.2" strokeLinecap="round" />
              <path d={toPath(medium)} fill="none" stroke="#EAB308" strokeWidth="2.2" strokeLinecap="round" />
              <path d={toPath(high)}   fill="none" stroke="#F97316" strokeWidth="2.2" strokeLinecap="round" />
              <path d={toPath(critical)} fill="none" stroke="#EF4444" strokeWidth="2.2" strokeLinecap="round" />
              <path d={toPath(info)} fill="none" stroke="#6B7280" strokeWidth="2.2" strokeLinecap="round" />

              {/* Dots */}
              {info.map((v, i) => (
                <circle key={`info-${i}`} cx={xs[i]} cy={toY(v)} r={3} fill="#6B7280" />
              ))}
              {low.map((v, i) => (
                <circle key={`low-${i}`} cx={xs[i]} cy={toY(v)} r={3} fill="#22C55E" />
              ))}
              {medium.map((v, i) => (
                <circle key={`medium-${i}`} cx={xs[i]} cy={toY(v)} r={3} fill="#EAB308" />
              ))}
              {critical.map((v, i) => (
                <circle key={i} cx={xs[i]} cy={toY(v)} r={3} fill="#EF4444" />
              ))}
              {high.map((v, i) => (
                <circle key={i} cx={xs[i]} cy={toY(v)} r={3} fill="#F97316" />
              ))}
            </svg>

            {/* X-axis labels */}
            <div className="flex justify-between text-[9px] font-semibold text-gray-400 dark:text-gray-500 mt-1 select-none overflow-hidden">
              {labels.map((l) => (
                <span key={l} className="truncate max-w-[60px] text-center">{l}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SocAlertVolumeTrend;
