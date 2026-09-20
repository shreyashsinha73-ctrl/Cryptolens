import React from 'react';
import Card from '../common/Card.jsx';

const StatCard = ({
  title,
  value,
  subtitle,
  icon: Icon,
  iconBg = 'bg-[#4880FF]/15 text-[#4880FF]',
  trend,
  trendType = 'up', // 'up', 'down', 'neutral'
  trendLabel = 'from last audit',
}) => {
  return (
    <Card padding="p-5" className="relative overflow-hidden">
      <div className="flex items-start justify-between">
        <div>
          <span className="text-xs font-bold text-[#646464] dark:text-gray-400 uppercase tracking-wider block">
            {title}
          </span>
          <div className="text-2xl lg:text-3xl font-extrabold text-[#202224] dark:text-white mt-2 font-['Nunito_Sans'] tracking-tight">
            {value}
          </div>
        </div>

        {Icon && (
          <div className={`w-12 h-12 rounded-[14px] flex items-center justify-center ${iconBg}`}>
            <Icon className="w-6 h-6" />
          </div>
        )}
      </div>

      {(trend || subtitle) && (
        <div className="mt-4 flex items-center gap-1.5 text-xs font-semibold">
          {trend && (
            <span
              className={`inline-flex items-center gap-1 ${
                trendType === 'up'
                  ? 'text-[#00B69B]'
                  : trendType === 'down'
                  ? 'text-[#EF3826]'
                  : 'text-[#FFA756]'
              }`}
            >
              {trendType === 'up' ? '↗' : trendType === 'down' ? '↘' : '→'} {trend}
            </span>
          )}
          <span className="text-[#646464] dark:text-gray-400">{subtitle || trendLabel}</span>
        </div>
      )}
    </Card>
  );
};

export default StatCard;
