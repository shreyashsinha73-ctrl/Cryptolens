import React from 'react';
import {
  AlertTriangleIcon,
  ShieldAlertIcon,
  ClockIcon,
  TrendUpIcon,
} from './SocIcons.jsx';

const MetricCard = ({
  title,
  value,
  subtitle,
  subtitleColor = 'text-purple-600 dark:text-purple-400',
  icon: Icon,
  iconBg = 'bg-purple-500/10 text-purple-600 dark:bg-purple-500/15 dark:text-purple-400',
}) => {
  return (
    <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div>
          <span className="text-xs font-semibold text-gray-500 dark:text-gray-400">
            {title}
          </span>
          <div className="text-3xl font-extrabold text-gray-900 dark:text-white mt-2 tracking-tight">
            {value}
          </div>
        </div>

        <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      <div className="mt-4">
        <span className={`text-xs font-bold ${subtitleColor}`}>
          {subtitle}
        </span>
      </div>
    </div>
  );
};

const SocMetricCards = ({ totalAlerts = 47, criticalAlerts = 10 }) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      {/* 1. Total Active Alerts */}
      <MetricCard
        title="Total Active Alerts"
        value={totalAlerts}
        subtitle="+12% from yesterday"
        subtitleColor="text-purple-600 dark:text-purple-400"
        icon={AlertTriangleIcon}
        iconBg="bg-purple-500/10 text-purple-600 dark:bg-purple-500/15 dark:text-purple-400"
      />

      {/* 2. Critical Alerts */}
      <MetricCard
        title="Critical Alerts"
        value={criticalAlerts}
        subtitle="+3 in last hour"
        subtitleColor="text-rose-600 dark:text-rose-400"
        icon={ShieldAlertIcon}
        iconBg="bg-rose-500/10 text-rose-600 dark:bg-rose-500/15 dark:text-rose-400"
      />

      {/* 3. Avg Response Time */}
      <MetricCard
        title="Avg Response Time"
        value="8.2 min"
        subtitle="-15% improvement"
        subtitleColor="text-emerald-600 dark:text-emerald-400"
        icon={ClockIcon}
        iconBg="bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400"
      />

      {/* 4. Threat Trend */}
      <MetricCard
        title="Threat Trend"
        value="Increasing"
        subtitle="Monitor closely"
        subtitleColor="text-amber-600 dark:text-amber-400"
        icon={TrendUpIcon}
        iconBg="bg-amber-500/10 text-amber-600 dark:bg-amber-500/15 dark:text-amber-400"
      />
    </div>
  );
};

export default SocMetricCards;
