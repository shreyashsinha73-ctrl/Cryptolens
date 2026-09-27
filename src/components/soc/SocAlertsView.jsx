import React, { useState, useMemo } from 'react';

// ── Severity config ───────────────────────────────────────────────────────────
const SEV_CFG = {
  critical: {
    label: 'CRITICAL',
    barColor: '#EF4444',
    badgeBg: 'bg-rose-50 dark:bg-rose-500/15',
    badgeText: 'text-rose-700 dark:text-rose-400',
    badgeBorder: 'border-rose-300 dark:border-rose-500/40',
    leftBar: 'bg-[#EF4444]',
  },
  high: {
    label: 'HIGH',
    barColor: '#F97316',
    badgeBg: 'bg-orange-50 dark:bg-orange-500/15',
    badgeText: 'text-orange-700 dark:text-orange-400',
    badgeBorder: 'border-orange-300 dark:border-orange-500/40',
    leftBar: 'bg-[#F97316]',
  },
  medium: {
    label: 'MEDIUM',
    barColor: '#EAB308',
    badgeBg: 'bg-amber-50 dark:bg-amber-500/15',
    badgeText: 'text-amber-700 dark:text-amber-400',
    badgeBorder: 'border-amber-300 dark:border-amber-500/40',
    leftBar: 'bg-[#EAB308]',
  },
  low: {
    label: 'LOW',
    barColor: '#06B6D4',
    badgeBg: 'bg-cyan-50 dark:bg-cyan-500/15',
    badgeText: 'text-cyan-700 dark:text-cyan-400',
    badgeBorder: 'border-cyan-300 dark:border-cyan-500/40',
    leftBar: 'bg-[#06B6D4]',
  },
  info: {
  label: 'INFO',
  barColor: '#6B7280',
  badgeBg: 'bg-gray-50 dark:bg-gray-500/15',
  badgeText: 'text-gray-700 dark:text-gray-400',
  badgeBorder: 'border-gray-300 dark:border-gray-500/40',
  leftBar: 'bg-gray-400',
},
};

const normalise = (sev) => {
  const s = (sev || 'info').toLowerCase();
  return s in SEV_CFG ? s : 'info';
};

// ── Single Finding Card ───────────────────────────────────────────────────────
const FindingCard = ({ finding, index }) => {
  const [expanded, setExpanded] = useState(false);
  const sev = normalise(finding.severity);
  const cfg = SEV_CFG[sev];

  // Human-readable field extraction
  const title       = finding.title || finding.finding || `Finding #${index + 1}`;
  const description = finding.description || finding.detail || '—';
  const category    = finding.category || finding.threat_category || '—';
  const observed    = finding.observed_value || finding.observed || null;
  const expected    = finding.expected_value || finding.expected || null;
  const recommendation = finding.recommendation || finding.remediation || finding.fix || null;
  const findingId   = finding.finding_id || finding.id || `F-${String(index + 1).padStart(3, '0')}`;

  return (
    <div className={`bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl shadow-xs overflow-hidden transition-all`}>
      {/* Colour accent bar at top */}
      <div className={`h-1 w-full ${cfg.leftBar}`} />

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            {/* Severity badge */}
            <span className={`shrink-0 mt-0.5 px-2.5 py-0.5 rounded-full text-[11px] font-extrabold tracking-wider border ${cfg.badgeBg} ${cfg.badgeText} ${cfg.badgeBorder}`}>
              {cfg.label}
            </span>
            {/* Title */}
            <div className="min-w-0">
              <p className="text-sm font-bold text-gray-900 dark:text-white leading-snug">{title}</p>
              <p className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5 font-mono">{findingId} · {category}</p>
            </div>
          </div>

          {/* Expand toggle */}
          <button
            onClick={() => setExpanded(v => !v)}
            className="shrink-0 p-1.5 rounded-lg text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-[#23252A] cursor-pointer transition-colors"
            aria-label={expanded ? 'Collapse' : 'Expand'}
          >
            <svg className={`w-4 h-4 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Description (always visible) */}
        <p className="text-xs text-gray-600 dark:text-gray-400 mt-3 leading-relaxed">{description}</p>

        {/* Observed vs Expected inline pills */}
        {(observed || expected) && (
          <div className="flex flex-wrap gap-2 mt-3">
            {observed && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-50 dark:bg-rose-500/10 border border-rose-200 dark:border-rose-500/25 text-[11px] font-semibold text-rose-700 dark:text-rose-400">
                <span className="font-bold">Found:</span> {String(observed)}
              </span>
            )}
            {expected && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/25 text-[11px] font-semibold text-emerald-700 dark:text-emerald-400">
                <span className="font-bold">Expected:</span> {String(expected)}
              </span>
            )}
          </div>
        )}

        {/* Expanded section: recommendation + all raw fields */}
        {expanded && (
          <div className="mt-4 pt-4 border-t border-gray-100 dark:border-[#2A2C34] space-y-3">
            {recommendation && (
              <div className="flex gap-2">
                <span className="shrink-0 mt-0.5">
                  <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                      d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </span>
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-0.5">Recommendation</p>
                  <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed">{recommendation}</p>
                </div>
              </div>
            )}

            {/* Raw extra fields as key/value table */}
            {(() => {
              const skip = new Set(['title','finding','description','detail','category','threat_category',
                'severity','observed_value','observed','expected_value','expected',
                'recommendation','remediation','fix','finding_id','id']);
              const extras = Object.entries(finding).filter(([k]) => !skip.has(k) && finding[k] !== null && finding[k] !== undefined && finding[k] !== '');
              if (!extras.length) return null;
              return (
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-1.5">Technical Details</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5">
                    {extras.map(([k, v]) => (
                      <div key={k} className="flex items-start gap-1.5">
                        <span className="text-[10px] font-bold text-gray-400 dark:text-gray-500 uppercase tracking-wide shrink-0 mt-0.5 w-28 truncate">{k.replace(/_/g, ' ')}</span>
                        <span className="text-[11px] text-gray-700 dark:text-gray-300 font-mono break-all">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        )}
      </div>
    </div>
  );
};

// ── Main View ─────────────────────────────────────────────────────────────────
const SocAlertsView = ({ liveThreats = null }) => {
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [focusMode, setFocusMode] = useState(false);

  const hasData = liveThreats && liveThreats.length > 0;

  const filtered = useMemo(() => {
    if (!hasData) return [];
    return liveThreats.filter((f) => {
      const sev = normalise(f.severity);
      if (focusMode && sev !== 'critical' && sev !== 'high') return false;
      if (selectedSeverity !== 'All' && sev !== selectedSeverity) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const haystack = [f.title, f.description, f.category, f.finding_id, f.observed_value, f.expected_value]
          .filter(Boolean).join(' ').toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [liveThreats, selectedSeverity, searchQuery, focusMode]);

  // Summary counts
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (liveThreats || []).forEach(f => { const s = normalise(f.severity); if (s in c) c[s]++; });
    return c;
  }, [liveThreats]);

  return (
    <div className="space-y-5">
      {/* ── Page title & summary ── */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-5 shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-extrabold text-gray-900 dark:text-white tracking-tight">
              Threat Findings
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              {hasData
                ? `${liveThreats.length} security findings identified from PCAP analysis — sorted by severity`
                : 'Upload a PCAP file to see security findings from the analysis engine'}
            </p>
          </div>

          {/* Summary pills */}
          {hasData && (
            <div className="flex flex-wrap gap-2 shrink-0">
              {[
                { key: 'critical', label: 'Critical', color: '#EF4444', bg: 'bg-rose-50 dark:bg-rose-500/10', text: 'text-rose-700 dark:text-rose-400', border: 'border-rose-200 dark:border-rose-500/30' },
                { key: 'high',     label: 'High',     color: '#F97316', bg: 'bg-orange-50 dark:bg-orange-500/10', text: 'text-orange-700 dark:text-orange-400', border: 'border-orange-200 dark:border-orange-500/30' },
                { key: 'medium',   label: 'Medium',   color: '#EAB308', bg: 'bg-amber-50 dark:bg-amber-500/10', text: 'text-amber-700 dark:text-amber-400', border: 'border-amber-200 dark:border-amber-500/30' },
                { key: 'low',      label: 'Low',      color: '#06B6D4', bg: 'bg-cyan-50 dark:bg-cyan-500/10', text: 'text-cyan-700 dark:text-cyan-400', border: 'border-cyan-200 dark:border-cyan-500/30' },
                { key: 'info',     label: 'Info',     color: '#6B7280', bg: 'bg-gray-50 dark:bg-gray-500/10', text: 'text-gray-700 dark:text-gray-400', border: 'border-gray-200 dark:border-gray-500/30' },
              ].filter(s => counts[s.key] > 0).map(s => (
                <button
                  key={s.key}
                  onClick={() => setSelectedSeverity(selectedSeverity === s.key ? 'All' : s.key)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border cursor-pointer transition-all ${s.bg} ${s.text} ${s.border} ${selectedSeverity === s.key ? 'ring-2 ring-offset-1 ring-current' : ''}`}
                >
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
                  {s.label} ({counts[s.key]})
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Filters row ── */}
      {hasData && (
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search */}
          <div className="relative flex-1">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              placeholder="Search findings…"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 text-xs bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-xl text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors"
            />
          </div>

          {/* Severity filter */}
          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="text-xs font-medium bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] text-gray-800 dark:text-gray-200 rounded-xl px-3 py-2 outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="All">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          {/* Focus mode toggle */}
          <button
            onClick={() => setFocusMode(v => !v)}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all cursor-pointer ${
              focusMode
                ? 'bg-amber-500 text-white border-amber-500'
                : 'bg-white dark:bg-[#18191D] text-gray-700 dark:text-gray-300 border-gray-200 dark:border-[#2A2C34] hover:border-amber-400'
            }`}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Focus: Critical &amp; High
          </button>
        </div>
      )}

      {/* ── Empty state ── */}
      {!hasData ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="w-16 h-16 rounded-2xl bg-gray-100 dark:bg-[#23252A] flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5"
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-sm font-bold text-gray-500 dark:text-gray-400">No findings yet</p>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">Upload a PCAP from the Dashboard to run analysis</p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-sm font-bold text-gray-500 dark:text-gray-400">No findings match your filters</p>
          <button onClick={() => { setSelectedSeverity('All'); setSearchQuery(''); setFocusMode(false); }}
            className="mt-3 text-xs text-blue-500 underline cursor-pointer">Clear filters</button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400">
            Showing {filtered.length} of {liveThreats.length} findings
          </p>
          {/* Sort: critical first */}
          {[...filtered]
            .sort((a, b) => {
              const order = { critical: 0, high: 1, medium: 2, low: 3 , info: 4};
              return (order[normalise(a.severity)] ?? 4) - (order[normalise(b.severity)] ?? 4);
            })
            .map((f, i) => (
              <FindingCard key={f.finding_id || i} finding={f} index={i} />
            ))}
        </div>
      )}
    </div>
  );
};

export default SocAlertsView;
