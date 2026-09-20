<<<<<<< Updated upstream
import React from 'react';

const SocDesignSystemView = () => {
  return (
    <div className="space-y-8">
      {/* Design System Header */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs transition-colors">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold text-lg">
            SO
          </div>
          <div>
            <h2 className="text-xl font-extrabold text-gray-900 dark:text-white tracking-tight">
              SecureOps Design System
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              v1.0.0 • Built for Security Operations Centers (SOC)
            </p>
          </div>
        </div>
      </div>

      {/* 1. Base Layers & Contrast Check */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-bold text-gray-900 dark:text-white">
          1. Base Layers (Elevation & Surfaces)
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Deep neutral foundation providing subtle surface elevation and depth hierarchy.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-gray-50 dark:bg-[#0F1012] border border-gray-200 dark:border-[#2A2C34]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 900</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Deepest background</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-900</code>
          </div>
          <div className="p-4 rounded-xl bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 800</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Primary background</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-800</code>
          </div>
          <div className="p-4 rounded-xl bg-gray-100 dark:bg-[#23252A] border border-gray-200 dark:border-[#2A2C34]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 700</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Elevated surface</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-700</code>
          </div>
          <div className="p-4 rounded-xl bg-gray-200 dark:bg-[#282A32] border border-gray-300 dark:border-[#2E3038]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 500</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Hover states</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-500</code>
          </div>
        </div>
      </div>

      {/* 2. Text Hierarchy & Non-Error Contrast Verification */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-bold text-gray-900 dark:text-white">
          2. Text Hierarchy (WCAG AA Contrast Ratios)
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Clear contrast ratios optimized for readability and quick scanning in data-dense SOC shifts.
        </p>

        <div className="space-y-3 pt-2">
          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#23252A] flex items-center justify-between">
            <div>
              <div className="text-sm font-bold text-gray-900 dark:text-white">
                The quick brown fox jumps over the lazy dog
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">Primary content</div>
            </div>
            <code className="text-xs font-mono text-blue-600 dark:text-blue-400">--soc-text-primary</code>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#23252A] flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-gray-600 dark:text-gray-300">
                The quick brown fox jumps over the lazy dog
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">Secondary content</div>
            </div>
            <code className="text-xs font-mono text-blue-600 dark:text-blue-400">--soc-text-secondary</code>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#23252A] flex items-center justify-between">
            <div>
              <div className="text-xs font-medium text-gray-500 dark:text-gray-400">
                The quick brown fox jumps over the lazy dog
              </div>
              <div className="text-[11px] text-gray-400 dark:text-gray-500">Metadata, labels</div>
            </div>
            <code className="text-xs font-mono text-blue-600 dark:text-blue-400">--soc-text-tertiary</code>
          </div>
        </div>
      </div>

      {/* 3. Severity System */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-bold text-gray-900 dark:text-white">
          3. Severity System
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Consistent visual hierarchy for threat levels with background, primary, hover, and muted variants.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          {/* Critical */}
          <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 dark:bg-rose-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500 text-white inline-block">
              CRITICAL
            </span>
            <div className="text-xs font-bold text-rose-700 dark:text-rose-400">
              Immediate threat mitigation
            </div>
            <div className="text-[11px] text-rose-600/80 dark:text-rose-300/80">
              Data exfiltration, root compromise
            </div>
          </div>

          {/* High */}
          <div className="p-4 rounded-xl border border-orange-500/40 bg-orange-500/10 dark:bg-orange-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-orange-500 text-white inline-block">
              HIGH
            </span>
            <div className="text-xs font-bold text-orange-700 dark:text-orange-400">
              Elevated investigation required
            </div>
            <div className="text-[11px] text-orange-600/80 dark:text-orange-300/80">
              C2 beacons, privilege escalations
            </div>
          </div>

          {/* Medium */}
          <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 dark:bg-amber-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500 text-white inline-block">
              MEDIUM
            </span>
            <div className="text-xs font-bold text-amber-700 dark:text-amber-400">
              Policy anomaly / suspicious action
            </div>
            <div className="text-[11px] text-amber-600/80 dark:text-amber-300/80">
              Multiple failed logins, unusual hours
            </div>
          </div>

          {/* Low */}
          <div className="p-4 rounded-xl border border-blue-500/40 bg-blue-500/10 dark:bg-blue-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-500 text-white inline-block">
              LOW
            </span>
            <div className="text-xs font-bold text-blue-700 dark:text-blue-400">
              Informational / routine telemetry
            </div>
            <div className="text-[11px] text-blue-600/80 dark:text-blue-300/80">
              Port scans, generic warnings
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SocDesignSystemView;
=======
import React from 'react';

const SocDesignSystemView = () => {
  return (
    <div className="space-y-8">
      {/* Design System Header */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs transition-colors">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold text-lg">
            CL
          </div>
          <div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              CryptoLens Design System
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Global component library and typography scale
            </p>
          </div>
        </div>
      </div>

      {/* 1. Base Layers & Contrast Check */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-bold text-gray-900 dark:text-white">
          1. Base Layers (Elevation & Surfaces)
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Deep neutral foundation providing subtle surface elevation and depth hierarchy.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-gray-50 dark:bg-[#0F1012] border border-gray-200 dark:border-[#2A2C34]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 900</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Deepest background</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-900</code>
          </div>
          <div className="p-4 rounded-xl bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 800</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Primary background</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-800</code>
          </div>
          <div className="p-4 rounded-xl bg-gray-100 dark:bg-[#23252A] border border-gray-200 dark:border-[#2A2C34]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 700</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Elevated surface</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-700</code>
          </div>
          <div className="p-4 rounded-xl bg-gray-200 dark:bg-[#282A32] border border-gray-300 dark:border-[#2E3038]">
            <span className="text-xs font-bold text-gray-900 dark:text-white block">Base 500</span>
            <span className="text-[11px] text-gray-500 dark:text-gray-400">Hover states</span>
            <code className="block text-[10px] text-blue-600 dark:text-blue-400 mt-2">--soc-base-500</code>
          </div>
        </div>
      </div>

      {/* 2. Text Hierarchy & Non-Error Contrast Verification */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-bold text-gray-900 dark:text-white">
          2. Text Hierarchy (WCAG AA Contrast Ratios)
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Clear contrast ratios optimized for readability and quick scanning in data-dense SOC shifts.
        </p>

        <div className="space-y-3 pt-2">
          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#23252A] flex items-center justify-between">
            <div>
              <div className="text-sm font-bold text-gray-900 dark:text-white">
                The quick brown fox jumps over the lazy dog
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">Primary content</div>
            </div>
            <code className="text-xs font-mono text-blue-600 dark:text-blue-400">--soc-text-primary</code>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#23252A] flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-gray-600 dark:text-gray-300">
                The quick brown fox jumps over the lazy dog
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">Secondary content</div>
            </div>
            <code className="text-xs font-mono text-blue-600 dark:text-blue-400">--soc-text-secondary</code>
          </div>

          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#23252A] flex items-center justify-between">
            <div>
              <div className="text-xs font-medium text-gray-500 dark:text-gray-400">
                The quick brown fox jumps over the lazy dog
              </div>
              <div className="text-[11px] text-gray-400 dark:text-gray-500">Metadata, labels</div>
            </div>
            <code className="text-xs font-mono text-blue-600 dark:text-blue-400">--soc-text-tertiary</code>
          </div>
        </div>
      </div>

      {/* 3. Severity System */}
      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-bold text-gray-900 dark:text-white">
          3. Severity System
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Consistent visual hierarchy for threat levels with background, primary, hover, and muted variants.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          {/* Critical */}
          <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 dark:bg-rose-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500 text-white inline-block">
              CRITICAL
            </span>
            <div className="text-xs font-bold text-rose-700 dark:text-rose-400">
              Immediate threat mitigation
            </div>
            <div className="text-[11px] text-rose-600/80 dark:text-rose-300/80">
              Data exfiltration, root compromise
            </div>
          </div>

          {/* High */}
          <div className="p-4 rounded-xl border border-orange-500/40 bg-orange-500/10 dark:bg-orange-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-orange-500 text-white inline-block">
              HIGH
            </span>
            <div className="text-xs font-bold text-orange-700 dark:text-orange-400">
              Elevated investigation required
            </div>
            <div className="text-[11px] text-orange-600/80 dark:text-orange-300/80">
              C2 beacons, privilege escalations
            </div>
          </div>

          {/* Medium */}
          <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 dark:bg-amber-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500 text-white inline-block">
              MEDIUM
            </span>
            <div className="text-xs font-bold text-amber-700 dark:text-amber-400">
              Policy anomaly / suspicious action
            </div>
            <div className="text-[11px] text-amber-600/80 dark:text-amber-300/80">
              Multiple failed logins, unusual hours
            </div>
          </div>

          {/* Low */}
          <div className="p-4 rounded-xl border border-blue-500/40 bg-blue-500/10 dark:bg-blue-500/15 space-y-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-500 text-white inline-block">
              LOW
            </span>
            <div className="text-xs font-bold text-blue-700 dark:text-blue-400">
              Informational / routine telemetry
            </div>
            <div className="text-[11px] text-blue-600/80 dark:text-blue-300/80">
              Port scans, generic warnings
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SocDesignSystemView;
>>>>>>> Stashed changes
