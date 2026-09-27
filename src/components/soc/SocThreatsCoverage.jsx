import React, { useState, useEffect } from 'react';

const AXES = [
  { name: 'Discovery', score: 0.85 },
  { name: 'Initial Access', score: 0.70 },
  { name: 'Exec', score: 0.80 },
  { name: 'Privilege Escalation', score: 0.75 },
  { name: 'Persistence', score: 0.90 },
  { name: 'Defense Evasion', score: 0.65 },
  { name: 'LM', score: 0.60 },
  { name: 'Exfiltration', score: 0.75 },
];

const SocThreatsCoverage = () => {
  const [animProgress, setAnimProgress] = useState(0);

  useEffect(() => {
    let start = null;
    const duration = 1200;
    let animFrame = null;

    const step = (timestamp) => {
      if (!start) start = timestamp;
      const progress = Math.min((timestamp - start) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      setAnimProgress(ease);

      if (progress < 1) {
        animFrame = requestAnimationFrame(step);
      }
    };

    animFrame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animFrame);
  }, []);

  const size = 260;
  const center = size / 2;
  const radius = 85;
  const numAxes = AXES.length;

  const getCoordinates = (index, value) => {
    // Start at top (-90 degrees)
    const angle = (Math.PI * 2 * index) / numAxes - Math.PI / 2;
    const r = radius * value;
    const x = center + r * Math.cos(angle);
    const y = center + r * Math.sin(angle);
    return { x, y };
  };

  // Concentric octagons (0.25, 0.5, 0.75, 1.0)
  const rings = [0.33, 0.66, 1.0];

  // Polygon path for threat coverage (scaled by animProgress)
  const coveragePoints = AXES.map((axis, i) => {
    const { x, y } = getCoordinates(i, axis.score * animProgress);
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between h-full">
      <div>
        <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
          Threats Coverage
        </h3>
        <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
          MITRE ATT&CK framework vectors
        </p>
      </div>

      {/* Radar SVG */}
      <div className="relative flex items-center justify-center my-auto py-2">
        <svg width={size} height={size} className="overflow-visible">
          {/* Concentric Octagon Rings */}
          {rings.map((ringVal) => {
            const ringPoints = AXES.map((_, i) => {
              const { x, y } = getCoordinates(i, ringVal);
              return `${x},${y}`;
            }).join(' ');

            return (
              <polygon
                key={ringVal}
                points={ringPoints}
                fill="none"
                stroke="currentColor"
                strokeWidth="1"
                strokeDasharray="2 2"
                className="text-gray-200 dark:text-gray-800"
              />
            );
          })}

          {/* Radial Spokes from center */}
          {AXES.map((_, i) => {
            const { x, y } = getCoordinates(i, 1.0);
            return (
              <line
                key={i}
                x1={center}
                y1={center}
                x2={x}
                y2={y}
                stroke="currentColor"
                strokeWidth="1"
                className="text-gray-200 dark:text-gray-800"
              />
            );
          })}

          {/* Active Coverage Polygon (Pink / Magenta #EC4899) */}
          <polygon
            points={coveragePoints}
            fill="#EC4899"
            fillOpacity="0.22"
            stroke="#EC4899"
            strokeWidth="2.2"
            strokeLinejoin="round"
          />

          {/* Axis Vertex Dots */}
          {AXES.map((axis, i) => {
            const { x, y } = getCoordinates(i, axis.score);
            return (
              <circle
                key={i}
                cx={x}
                cy={y}
                r="3.5"
                fill="#EC4899"
                className="stroke-white dark:stroke-[#18191D] stroke-1"
              />
            );
          })}

          {/* Axis Labels positioned around perimeter */}
          {AXES.map((axis, i) => {
            const labelCoord = getCoordinates(i, 1.28);
            let textAnchor = 'middle';
            if (labelCoord.x < center - 10) textAnchor = 'end';
            else if (labelCoord.x > center + 10) textAnchor = 'start';

            return (
              <text
                key={axis.name}
                x={labelCoord.x}
                y={labelCoord.y + 3}
                textAnchor={textAnchor}
                className="text-[10px] font-semibold fill-gray-600 dark:fill-gray-400 select-none"
              >
                {axis.name}
              </text>
            );
          })}
        </svg>
      </div>

      {/* Legend Footer */}
      <div className="flex items-center justify-center space-x-2 pt-1 border-t border-gray-100 dark:border-[#2A2C34]">
        <span className="w-2.5 h-2.5 rounded-full bg-[#EC4899]" />
        <span className="text-xs font-semibold text-gray-600 dark:text-gray-300">
          Threats coverage
        </span>
      </div>
    </div>
  );
};

export default SocThreatsCoverage;
