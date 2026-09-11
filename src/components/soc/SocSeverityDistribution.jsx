import React, { useState } from 'react';

const SIZE = 180;
const STROKE_WIDTH = 26;
const RADIUS = (SIZE - STROKE_WIDTH) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const SEVERITIES = [
  { id: 'critical', name: 'Critical', value: 35, count: 16, color: '#EF4444', offset: 0 },
  { id: 'high', name: 'High', value: 25, count: 12, color: '#F97316', offset: 35 },
  { id: 'medium', name: 'Medium', value: 25, count: 12, color: '#EAB308', offset: 60 },
  { id: 'low', name: 'Low', value: 15, count: 7, color: '#06B6D4', offset: 85 },
];

const SocSeverityDistribution = () => {
  const [activeItem, setActiveItem] = useState(null);

  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between h-full">
      <div>
        <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
          Severity Distribution
        </h3>
        <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
          Breakdown by threat criticality
        </p>
      </div>

      {/* Center Donut SVG */}
      <div className="relative flex items-center justify-center my-auto py-2">
        <svg
          width={SIZE}
          height={SIZE}
          viewBox={`0 0 ${SIZE} ${SIZE}`}
          className="transform -rotate-90"
        >
          {SEVERITIES.map((sev) => {
            const isHighlighted = activeItem === sev.id;
            const strokeDasharray = `${(sev.value / 100) * CIRCUMFERENCE} ${CIRCUMFERENCE}`;
            const strokeDashoffset = -((sev.offset / 100) * CIRCUMFERENCE);

            return (
              <circle
                key={sev.id}
                cx={SIZE / 2}
                cy={SIZE / 2}
                r={RADIUS}
                fill="transparent"
                stroke={sev.color}
                strokeWidth={isHighlighted ? STROKE_WIDTH + 4 : STROKE_WIDTH}
                strokeDasharray={strokeDasharray}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                className="cursor-pointer transition-all duration-200 hover:opacity-90"
                onMouseEnter={() => setActiveItem(sev.id)}
                onMouseLeave={() => setActiveItem(null)}
              />
            );
          })}
        </svg>

        {/* Donut Center Counter */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none">
          <span className="text-2xl font-black text-gray-900 dark:text-white leading-tight">
            {activeItem ? SEVERITIES.find((s) => s.id === activeItem)?.value + '%' : '47'}
          </span>
          <span className="text-[10px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
            {activeItem ? SEVERITIES.find((s) => s.id === activeItem)?.name : 'Alerts'}
          </span>
        </div>
      </div>

      {/* Legend Footer */}
      <div className="grid grid-cols-2 gap-y-2 gap-x-4 pt-3 border-t border-gray-100 dark:border-[#2A2C34] text-xs font-semibold">
        {SEVERITIES.map((sev) => (
          <div
            key={sev.id}
            onMouseEnter={() => setActiveItem(sev.id)}
            onMouseLeave={() => setActiveItem(null)}
            className="flex items-center space-x-2 cursor-pointer transition-opacity hover:opacity-80"
          >
            <span
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: sev.color }}
            />
            <span className="text-gray-600 dark:text-gray-300">
              {sev.name}
            </span>
            <span className="text-gray-400 dark:text-gray-500 text-[11px] font-normal ml-auto">
              {sev.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SocSeverityDistribution;
