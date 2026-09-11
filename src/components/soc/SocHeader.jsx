import React from 'react';
import { ClockIcon, BellIcon } from './SocIcons.jsx';

const SocHeader = ({ configType, onToggleConfig, onToggleSidebar }) => {
  const isCompliant = configType === 'compliant';

  return (
    <header className="h-[72px] bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl px-4 lg:px-6 flex items-center justify-between shadow-xs transition-colors">
      {/* Left: Mobile hamburger & Status Pills */}
      <div className="flex items-center space-x-3 lg:space-x-6">
        {/* Mobile menu trigger */}
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-2 rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-[#23252A] cursor-pointer"
          aria-label="Toggle Menu"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        {/* System Health Badge */}
        <div className="flex items-center space-x-2">
          <svg className="w-4 h-4 text-emerald-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          <span className="hidden sm:inline text-xs font-semibold text-gray-500 dark:text-gray-400">
            System Health:
          </span>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            OPERATIONAL
          </span>
        </div>

        {/* Threat Level Badge */}
        <div className="flex items-center space-x-2">
          <svg className="w-4 h-4 text-rose-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <span className="hidden sm:inline text-xs font-semibold text-gray-500 dark:text-gray-400">
            Threat Level:
          </span>
          <span
            className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold transition-colors ${
              isCompliant
                ? 'bg-emerald-500/10 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                : 'bg-rose-500/10 dark:bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isCompliant ? 'bg-emerald-500' : 'bg-rose-500 animate-ping'
              }`}
            />
            {isCompliant ? 'LOW / COMPLIANT' : 'CRITICAL'}
          </span>
        </div>
      </div>

      {/* Right: Timefilter, Bell, Profile, Demo Config Toggle */}
      <div className="flex items-center space-x-3 sm:space-x-5">
        {/* Demo Config Switcher */}
        <button
          onClick={onToggleConfig}
          className={`hidden md:inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-bold border transition-colors cursor-pointer ${
            isCompliant
              ? 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
              : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-600 dark:text-rose-400 border-rose-500/30'
          }`}
          title="Switch telemetry scenario"
        >
          Demo: {isCompliant ? 'Compliant' : 'Critical'}
        </button>

        {/* Timeframe Dropdown (from Figma: Clock + All Time + Chevron) */}
        <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-100 dark:bg-[#23252A] border border-gray-200 dark:border-[#2E3038] text-gray-700 dark:text-gray-200 text-xs font-medium cursor-pointer">
          <ClockIcon className="w-3.5 h-3.5 text-gray-500 dark:text-gray-400" />
          <span>All Time</span>
          <svg className="w-3.5 h-3.5 text-gray-400 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* Notification Bell with Badge 9+ */}
        <div className="relative">
          <button
            className="p-2 rounded-xl text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-[#23252A] transition-colors cursor-pointer"
            aria-label="View notifications"
          >
            <BellIcon className="w-5 h-5" />
          </button>
          <span className="absolute top-1 right-1 px-1.5 py-0.2 bg-rose-500 text-white text-[10px] font-extrabold rounded-full flex items-center justify-center leading-none">
            9+
          </span>
        </div>

        {/* Vertical Divider */}
        <div className="h-7 w-[1px] bg-gray-200 dark:bg-[#2A2C34]" />

        {/* User Profile (from Figma: Shreya - System Engineer) */}
        <div className="flex items-center space-x-3">
          <div className="hidden lg:flex flex-col text-right">
            <span className="text-xs font-bold text-gray-900 dark:text-white leading-tight">
              Shreya
            </span>
            <span className="text-[11px] font-medium text-gray-500 dark:text-gray-400">
              System Engineer
            </span>
          </div>

          <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-purple-600 to-indigo-500 text-white flex items-center justify-center text-sm font-bold shadow-xs">
            S
          </div>
        </div>
      </div>
    </header>
  );
};

export default SocHeader;
