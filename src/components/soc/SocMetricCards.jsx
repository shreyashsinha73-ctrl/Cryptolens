import React, { useState, useEffect } from 'react';

const AnimatedCounter = ({ endValue }) => {
  const [display, setDisplay] = useState(0);
  const isNumber = typeof endValue === 'number';
  const num = isNumber ? endValue : parseFloat(endValue) || 0;

  useEffect(() => {
    let start = null;
    let animFrame = null;
    const duration = 900;

    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.floor(ease * num));
      if (progress < 1) animFrame = requestAnimationFrame(step);
      else setDisplay(num);
    };

    animFrame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animFrame);
  }, [num]);

  if (!isNumber && isNaN(parseFloat(endValue))) return <span>{endValue}</span>;
  return <span>{display}</span>;
};

const MetricCard = ({ title, value, subtitle, subtitleColor = 'text-gray-500 dark:text-gray-400' }) => (
  <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs transition-colors flex flex-col justify-between">
    <div>
      <span className="text-xs font-semibold text-gray-500 dark:text-gray-400">{title}</span>
      <div className="text-3xl font-extrabold text-gray-900 dark:text-white mt-2 tracking-tight">
        <AnimatedCounter endValue={value} />
      </div>
    </div>
    <div className="mt-4">
      <span className={`text-xs font-bold ${subtitleColor}`}>{subtitle}</span>
    </div>
  </div>
);

const SocMetricCards = ({
  totalAlerts = 0,
  criticalAlerts = 0,
  mediumAlerts = 0,
  lowAlerts = 0,
  threatMatrix = [],
  riskLevel: backendRiskLevel = null,
}) => {
  // Compute highest-severity category from live data
  const topCategory = (() => {
    if (!threatMatrix.length) return '—';
    const counts = {};
    threatMatrix.forEach(t => {
      const cat = t.category || t.threat_category || 'Other';
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—';
  })();

  const computedRisk = backendRiskLevel
    ? `${backendRiskLevel.toUpperCase()} RISK`
    : (criticalAlerts > 0 ? 'HIGH RISK' : totalAlerts > 0 ? 'MODERATE RISK' : 'LOW RISK');

  const riskColor = (computedRisk.includes('HIGH') || computedRisk.includes('CRITICAL'))
    ? 'text-rose-600 dark:text-rose-400'
    : computedRisk.includes('MODERATE')
    ? 'text-amber-600 dark:text-amber-400'
    : 'text-emerald-600 dark:text-emerald-400';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <MetricCard
        title="Total Findings"
        value={totalAlerts}
        subtitle={`${criticalAlerts} critical + ${mediumAlerts} medium + ${lowAlerts} low`}
        subtitleColor="text-gray-500 dark:text-gray-400"
      />
      <MetricCard
        title="Critical / High"
        value={criticalAlerts}
        subtitle={criticalAlerts > 0 ? 'Requires immediate attention' : 'No critical findings'}
        subtitleColor={criticalAlerts > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}
      />
      <MetricCard
        title="Medium / Low"
        value={mediumAlerts + lowAlerts}
        subtitle={`${mediumAlerts} medium · ${lowAlerts} low severity`}
        subtitleColor="text-amber-600 dark:text-amber-400"
      />
      <MetricCard
        title="Risk Level"
        value={computedRisk}
        subtitle={totalAlerts > 0 ? `Top issue: ${topCategory}` : 'No findings from analysis'}
        subtitleColor={riskColor}
      />
    </div>
  );
};

export default SocMetricCards;
