import React from 'react';
import Card from '../common/Card.jsx';
import Badge from '../common/Badge.jsx';

const SubScoreRow = ({ label, value }) => {
  const percent = Math.round(value * 100);
  const scoreOutOfTen = (value * 10).toFixed(1);

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
          className={`h-full rounded-full transition-all duration-700 ease-out ${barColor}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
};

const AnalysisDimensions = ({ sub_scores = {} }) => {
  return (
    <Card
      title="Analysis Dimensions"
      subtitle="Cryptographic sub-score breakdown"
      padding="p-6"
      className="h-full flex flex-col justify-between"
    >
      <div className="space-y-4 pt-2">
        <SubScoreRow label="Cipher Strength" value={sub_scores.cipher_strength ?? 0} />
        <SubScoreRow label="Key Exchange" value={sub_scores.key_exchange ?? 0} />
        <SubScoreRow label="Mode & PFS" value={sub_scores.mode_pfs ?? 0} />
        <SubScoreRow label="Metadata Exposure" value={sub_scores.metadata_exposure ?? 0} />
        <SubScoreRow label="PQC Readiness" value={sub_scores.pqc_readiness ?? 0} />
      </div>
    </Card>
  );
};

export default AnalysisDimensions;
