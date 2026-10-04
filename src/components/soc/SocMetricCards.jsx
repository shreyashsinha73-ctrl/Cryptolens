import React, { useState, useEffect } from 'react';

const AnimatedCounter = ({ endValue }) => {
  const [display, setDisplay] = useState(0);
  const isNumber = typeof endValue === 'number';
  const num = isNumber ? endValue : parseFloat(endValue) || 0;

  useEffect(() => {
    let start = null;
    let animFrame = null;
    const duration = 600;

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
      <div className="text-2xl sm:text-3xl font-extrabold text-gray-900 dark:text-white mt-2 tracking-tight">
        <AnimatedCounter endValue={value} />
      </div>
    </div>
    <div className="mt-3">
      <p className={`text-xs font-semibold leading-relaxed ${subtitleColor}`}>{subtitle}</p>
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
  baseRiskLevel = null,
  riskReview = null,
  coverage = null,
}) => {
  const highAlerts = (threatMatrix || []).filter(t => t.severity === 'HIGH').length;
  const infoAlerts = (threatMatrix || []).filter(t => t.severity === 'INFO').length;

  // Determine top failing category from threatMatrix
  const topCategory = (() => {
    if (!threatMatrix || !threatMatrix.length) return '—';
    const counts = {};
    threatMatrix.forEach(t => {
      const cat = t.category || t.threat_category || 'General';
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—';
  })();

  const rawLevel = baseRiskLevel || backendRiskLevel || (
    criticalAlerts > 0 ? 'CRITICAL' :
    highAlerts > 0 ? 'HIGH' :
    mediumAlerts > 0 ? 'MODERATE' : 'LOW'
  );

  let computedRisk = String(rawLevel).toUpperCase();
  if (computedRisk.startsWith('LOW')) computedRisk = 'LOW RISK';
  else if (computedRisk.startsWith('MODERATE') || computedRisk.startsWith('MEDIUM')) computedRisk = 'MODERATE RISK';
  else if (computedRisk.startsWith('HIGH')) computedRisk = 'HIGH RISK';
  else if (computedRisk.startsWith('CRITICAL')) computedRisk = 'CRITICAL RISK';
  else if (computedRisk === 'UNVERIFIED' || computedRisk.replace('_', ' ') === 'NOT ASSESSED') computedRisk = 'NOT ASSESSED';
  else if (!computedRisk.includes('RISK') && computedRisk !== 'NOT ASSESSED') computedRisk += ' RISK';

  const riskColor = (computedRisk.includes('HIGH') || computedRisk.includes('CRITICAL'))
    ? 'text-rose-600 dark:text-rose-400'
    : computedRisk.includes('MODERATE')
    ? 'text-amber-600 dark:text-amber-400'
    : computedRisk === 'NOT ASSESSED'
    ? 'text-indigo-600 dark:text-indigo-400'
    : 'text-emerald-600 dark:text-emerald-400';

  const covMatch = /^(\d+)\/(\d+)$/.exec(String(coverage || ''));
  const covText = covMatch ? ` · based on ${covMatch[1]} of ${covMatch[2]} checks observable` : '';
  const displaySubtitle = (riskReview ? riskReview + covText : null) || (
    totalAlerts > 0
      ? `Top issue: ${topCategory} (${threatMatrix.length} finding${threatMatrix.length === 1 ? '' : 's'} recorded)`
      : 'No verified vulnerabilities detected in capture'
  );

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <MetricCard
        title="Total Findings"
        value={totalAlerts}
        subtitle={`${criticalAlerts} critical · ${highAlerts} high · ${mediumAlerts} med · ${lowAlerts} low · ${infoAlerts} info`}
        subtitleColor="text-gray-500 dark:text-gray-400"
      />
      <MetricCard
        title="Critical Findings"
        value={criticalAlerts}
        subtitle={criticalAlerts > 0 ? 'Requires immediate remediation' : 'No critical CVE/RFC violations'}
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
        subtitle={displaySubtitle}
        subtitleColor={riskColor}
      />
    </div>
  );
};

export default SocMetricCards;
