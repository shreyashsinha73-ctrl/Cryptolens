import React, { useState } from 'react';

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

// Simulated weekly threat activity pattern matching Figma heatmap matrix
const GENERATED_MATRIX = [
  // Mon
  [1, 2, 3, 2, 2, 1, 2, 3, 4, 3, 4, 4, 3, 2, 1, 2, 3, 2, 1, 2, 3, 2, 3, 2],
  // Tue
  [2, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 2, 1, 3, 2, 3, 3, 3, 2, 3, 4, 3, 3, 2],
  // Wed
  [2, 2, 3, 2, 1, 2, 1, 0, 4, 3, 3, 2, 1, 4, 4, 2, 2, 3, 1, 2, 3, 3, 4, 3],
  // Thu
  [3, 2, 3, 1, 1, 2, 2, 4, 3, 3, 4, 4, 2, 1, 3, 3, 3, 3, 1, 3, 3, 4, 3, 2],
  // Fri
  [1, 1, 2, 4, 3, 2, 1, 0, 4, 3, 1, 3, 2, 3, 4, 2, 3, 1, 2, 2, 3, 3, 2, 2],
  // Sat
  [2, 3, 4, 4, 3, 3, 3, 2, 3, 3, 2, 4, 2, 2, 3, 3, 4, 3, 4, 4, 3, 2, 3, 2],
  // Sun
  [2, 3, 4, 3, 3, 4, 2, 3, 3, 2, 3, 1, 3, 3, 3, 3, 4, 4, 1, 3, 2, 2, 3, 2],
];

const COLOR_LEVELS = [
  { level: 0, dark: 'bg-[#18191D] border-gray-800/40', light: 'bg-gray-100 border-gray-200' },
  { level: 1, dark: 'bg-[#1E3A8A]', light: 'bg-[#93C5FD]' },
  { level: 2, dark: 'bg-[#854D0E]', light: 'bg-[#FDE047]' },
  { level: 3, dark: 'bg-[#C2410C]', light: 'bg-[#FB923C]' },
  { level: 4, dark: 'bg-[#DC2626]', light: 'bg-[#F87171]' },
];

const SocWeeklyActivityPattern = () => {
  const [hoveredCell, setHoveredCell] = useState(null);

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
            Weekly Threat Activity Pattern
          </h3>
          <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
            24-hour heat matrix of security anomalies and ingress telemetry
          </p>
        </div>

        {hoveredCell && (
          <span className="text-xs font-bold text-gray-700 dark:text-gray-200 bg-gray-100 dark:bg-[#23252A] px-2.5 py-1 rounded-md border border-gray-200 dark:border-[#323D4E]">
            {hoveredCell.day}, {hoveredCell.hour}:00h • Level {hoveredCell.level}
          </span>
        )}
      </div>

      {/* Heatmap Grid */}
      <div className="overflow-x-auto pt-1">
        <div className="min-w-[560px]">
          {/* Hours Header (0h, 6h, 12h, 18h, 23h) */}
          <div className="flex pl-10 pr-1 justify-between text-[10px] font-bold text-gray-400 dark:text-gray-500 pb-2 select-none">
            <span>0h</span>
            <span>6h</span>
            <span>12h</span>
            <span>18h</span>
            <span>23h</span>
          </div>

          {/* Matrix Rows */}
          <div className="space-y-1.5">
            {DAYS.map((day, dIdx) => (
              <div key={day} className="flex items-center space-x-2">
                <span className="w-8 text-[11px] font-bold text-gray-500 dark:text-gray-400 text-left select-none">
                  {day}
                </span>

                <div className="flex-1 grid grid-cols-24 gap-1 sm:gap-1.5">
                  {HOURS.map((hour) => {
                    const level = GENERATED_MATRIX[dIdx][hour];
                    const colorDef = COLOR_LEVELS[level] || COLOR_LEVELS[0];

                    return (
                      <div
                        key={hour}
                        onMouseEnter={() => setHoveredCell({ day, hour, level })}
                        onMouseLeave={() => setHoveredCell(null)}
                        className={`h-4 sm:h-5 rounded-[4px] cursor-pointer transition-transform hover:scale-115 hover:z-10 ${colorDef.light} dark:${colorDef.dark}`}
                        title={`${day} at ${hour}:00 - Threat Intensity: ${level}`}
                      />
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Legend Scale matching Figma */}
      <div className="flex items-center space-x-2 pt-4 mt-2 border-t border-gray-100 dark:border-[#2A2C34] text-xs font-semibold text-gray-500 dark:text-gray-400">
        <span>Activity: Low</span>
        <div className="flex items-center space-x-1">
          <span className="w-3 h-3 rounded-[3px] bg-[#93C5FD] dark:bg-[#1E3A8A]" />
          <span className="w-3 h-3 rounded-[3px] bg-[#FDE047] dark:bg-[#854D0E]" />
          <span className="w-3 h-3 rounded-[3px] bg-[#FB923C] dark:bg-[#C2410C]" />
          <span className="w-3 h-3 rounded-[3px] bg-[#F87171] dark:bg-[#DC2626]" />
        </div>
        <span>High</span>
      </div>
    </div>
  );
};

export default SocWeeklyActivityPattern;
