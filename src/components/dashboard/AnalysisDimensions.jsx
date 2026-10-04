import React, { useState, useEffect } from 'react';
import Card from '../common/Card.jsx';
import Badge from '../common/Badge.jsx';
import { selectDimensions } from '../../lib/dimensions.js';

const SubScoreRow = ({ label, value: rawValue }) => {
  const unobservable = rawValue === null || rawValue === undefined;
  const value = unobservable ? 0 : rawValue;
  const [animProgress, setAnimProgress] = useState(0);

  useEffect(() => {
    const timeout = setTimeout(() => {
      setAnimProgress(1);
    }, 60);
    return () => clearTimeout(timeout);
  }, [value]);

  const targetPercent = Math.round(value * 100);
  const percent = Math.round(targetPercent * animProgress);
  const scoreOutOfTen = (value * 10 * animProgress).toFixed(1);

  let barColor = 'bg-[#EF3826]';
  let badgeVariant = 'rejected';
  let statusText = 'Weak';

  if (value >= 0.8) {
    barColor = 'bg-[#00B69B]';
    badgeVariant = 'completed';
    statusText = 'Strong';
  } else if (value >= 0.5) {
    barColor = 'bg-[#FFA756]';
    badgeVariant = 'on_hold';
    statusText = 'Moderate';
  }

  if (unobservable) {
    return (
      <div className="space-y-1.5 font-['Nunito_Sans']">
        <div className="flex justify-between items-center text-xs">
          <span className="font-bold text-[#202224] dark:text-white">{label}</span>
          <span className="text-[11px] italic text-gray-400">not observable</span>
        </div>
        <div className="h-2.5 w-full rounded-full border border-dashed border-gray-300 dark:border-[#323D4E]" />
      </div>
    );
  }

  return (
    <div className="space-y-1.5 font-['Nunito_Sans']">
      <div className="flex justify-between items-center text-xs">
        <div className="flex items-center space-x-2">
          <span className="font-bold text-[#202224] dark:text-white">
            {label}
          </span>
          <Badge variant={badgeVariant} label={statusText} size="sm" />
        </div>
        <span className="font-extrabold text-[#202224] dark:text-white">
          {scoreOutOfTen}
          <span className="text-gray-400 font-normal text-[11px]">/10</span>
        </span>
      </div>

      <div className="h-2.5 w-full bg-[#F5F6FA] dark:bg-[#1B2431] rounded-full overflow-hidden border border-gray-100 dark:border-[#323D4E]">
        <div
          className={`h-full rounded-full transition-all duration-1000 ease-out ${barColor}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
};

const AnalysisDimensions = ({ score_breakdown = null, control_plane = null }) => {
  const dims = selectDimensions(score_breakdown, control_plane);
  return (
    <Card
      title="Analysis Dimensions"
      subtitle="Cryptographic sub-score breakdown"
      padding="p-6"
      className="h-full flex flex-col justify-between"
    >
      <div className="space-y-4 pt-2">
        {dims.map((d) => <SubScoreRow key={d.key} label={d.label} value={d.value} />)}
      </div>
    </Card>
  );
};

export default AnalysisDimensions;
