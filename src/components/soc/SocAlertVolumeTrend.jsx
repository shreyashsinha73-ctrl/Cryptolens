import React, { useState } from 'react';

const DATES = [
  '15 Oct', '16 Oct', '17 Oct', '18 Oct', '19 Oct', '20 Oct',
  '21 Oct', '22 Oct', '23 Oct', '24 Oct', '25 Oct', '26 Oct',
];

const SocAlertVolumeTrend = () => {
  const [activeTimeframe, setActiveTimeframe] = useState('2W');
  const [hoveredIdx, setHoveredIdx] = useState(4); // Default to 19 Oct peak from Figma

  // SVG dimensions
  const width = 500;
  const height = 180;
  const paddingBottom = 25;
  const paddingTop = 20;

  // 12 points for Critical, High, Low
  const criticalPoints = [10, 14, 13, 15, 17, 18, 14, 13, 16, 17, 17, 15];
  const highPoints = [12, 16, 15, 17, 16, 19, 13, 17, 15, 18, 20, 18];
  const lowPoints = [7, 13, 11, 14, 15, 17, 8, 15, 12, 19, 21, 19];

  // Helper to calculate SVG path with smooth cubic beziers
  const getCoordinates = (points) => {
    const stepX = width / (points.length - 1);
    const maxY = 24;
    return points.map((p, i) => {
      const x = i * stepX;
      const y = height - paddingBottom - (p / maxY) * (height - paddingTop - paddingBottom);
      return { x, y, val: p };
    });
  };

  const toSmoothPath = (coords) => {
    if (coords.length === 0) return '';
    let path = `M ${coords[0].x} ${coords[0].y}`;
    for (let i = 0; i < coords.length - 1; i++) {
      const current = coords[i];
      const next = coords[i + 1];
      const controlX = (current.x + next.x) / 2;
      path += ` C ${controlX} ${current.y}, ${controlX} ${next.y}, ${next.x} ${next.y}`;
    }
    return path;
  };

  const critCoords = getCoordinates(criticalPoints);
  const highCoords = getCoordinates(highPoints);
  const lowCoords = getCoordinates(lowPoints);

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between h-full">
      {/* Top Header & Timeframe Pills */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
            Alert Volume Trend
          </h3>

          {/* Legend dots matching Figma */}
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
              <span className="text-gray-600 dark:text-gray-300">Low</span>
            </div>
          </div>
        </div>

        {/* 1D / 1W / 2W / 1M filter pills */}
        <div className="flex items-center bg-gray-100 dark:bg-[#23252A] p-0.5 rounded-lg border border-gray-200 dark:border-[#2E3038] self-start sm:self-auto">
          {['1D', '1W', '2W', '1M'].map((tf) => (
            <button
              key={tf}
              onClick={() => setActiveTimeframe(tf)}
              className={`px-2.5 py-1 text-xs font-bold rounded-md transition-all cursor-pointer ${
                activeTimeframe === tf
                  ? 'bg-white dark:bg-[#18191D] text-gray-900 dark:text-white shadow-xs border border-gray-200/60 dark:border-[#2A2C34]'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200'
              }`}
            >
              {tf}
            </button>
          ))}
        </div>
      </div>

      {/* Interactive Chart Container */}
      <div className="relative w-full overflow-hidden pt-2">
        <div className="flex items-stretch">
          {/* Y-Axis Labels (24, 16, 12, 6, 0) */}
          <div className="flex flex-col justify-between pr-2 text-[11px] font-semibold text-gray-400 dark:text-gray-500 pb-6 select-none">
            <span>24</span>
            <span>16</span>
            <span>12</span>
            <span>6</span>
            <span>0</span>
          </div>

          {/* SVG Canvas with lines & hover detection */}
          <div className="flex-1 relative">
            <svg
              viewBox={`0 0 ${width} ${height}`}
              className="w-full h-[180px] overflow-visible"
              preserveAspectRatio="none"
            >
              {/* Dotted Grid lines */}
              {[0, 6, 12, 16, 24].map((gridVal) => {
                const y = height - paddingBottom - (gridVal / 24) * (height - paddingTop - paddingBottom);
                return (
                  <line
                    key={gridVal}
                    x1="0"
                    y1={y}
                    x2={width}
                    y2={y}
                    stroke="currentColor"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                    className="text-gray-200 dark:text-gray-800"
                  />
                );
              })}

              {/* Low wave (Yellow #EAB308) */}
              <path
                d={toSmoothPath(lowCoords)}
                fill="none"
                stroke="#EAB308"
                strokeWidth="2.2"
                strokeLinecap="round"
              />

              {/* High wave (Orange #F97316) */}
              <path
                d={toSmoothPath(highCoords)}
                fill="none"
                stroke="#F97316"
                strokeWidth="2.2"
                strokeLinecap="round"
              />

              {/* Critical wave (Red #EF4444) */}
              <path
                d={toSmoothPath(critCoords)}
                fill="none"
                stroke="#EF4444"
                strokeWidth="2.2"
                strokeLinecap="round"
              />

              {/* Active / Hovered vertical indicator */}
              {hoveredIdx !== null && (
                <line
                  x1={critCoords[hoveredIdx].x}
                  y1={0}
                  x2={critCoords[hoveredIdx].x}
                  y2={height - paddingBottom}
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeDasharray="2 2"
                  className="text-gray-400 dark:text-gray-600"
                />
              )}
            </svg>

            {/* Hover Tooltip Box matching Figma tooltip (5C, 2M, 7L / 19 Aug, 2025) */}
            {hoveredIdx !== null && (
              <div
                className="absolute -top-3 transform -translate-x-1/2 bg-gray-900 dark:bg-[#23252A] text-white px-2.5 py-1.5 rounded-lg text-[10px] font-bold shadow-lg border border-gray-700 dark:border-[#323D4E] pointer-events-none whitespace-nowrap z-10"
                style={{
                  left: `${(hoveredIdx / (DATES.length - 1)) * 100}%`,
                }}
              >
                <div className="text-gray-300">
                  {criticalPoints[hoveredIdx]}C, {highPoints[hoveredIdx]}H, {lowPoints[hoveredIdx]}L
                </div>
                <div className="text-gray-400 font-normal text-[9px]">
                  {DATES[hoveredIdx]}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* X-Axis Date Labels */}
        <div className="flex justify-between pl-6 text-[10px] font-semibold text-gray-500 dark:text-gray-400 mt-1 select-none">
          {DATES.map((date, idx) => (
            <span
              key={date}
              onClick={() => setHoveredIdx(idx)}
              className={`cursor-pointer transition-colors ${
                hoveredIdx === idx ? 'text-gray-900 dark:text-white font-bold' : ''
              }`}
            >
              {date}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};

export default SocAlertVolumeTrend;
