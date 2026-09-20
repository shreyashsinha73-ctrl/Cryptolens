import React from 'react';
import {
  SearchIcon,
  BellIcon,
  SunIcon,
  MoonIcon,
} from '../icons/DashIcons.jsx';
import { useTheme } from '../../context/useTheme.js';

const TopBar = ({ configType, onToggleConfig, onToggleSidebar }) => {
  const { isDark, toggleTheme } = useTheme();

  return (
    <header
      className={`h-[70px] sticky top-0 z-30 flex items-center justify-between px-4 lg:px-8 transition-colors duration-200 ${
        isDark
          ? 'bg-[#273142] border-b border-[#323D4E]'
          : 'bg-white border-b border-[#E0E0E0]'
      }`}
    >
      {/* Left: Mobile hamburger & Search input */}
      <div className="flex items-center space-x-3 lg:space-x-6 flex-1 max-w-lg">
        {/* Mobile menu button */}
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-2 rounded-lg text-gray-500 hover:bg-gray-100 dark:hover:bg-slate-700 cursor-pointer"
          aria-label="Toggle Navigation"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>

        {/* DashStack Rounded Search Input (Figma: 388x38px, radius 19px) */}
        <div className="relative w-full max-w-[388px]">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-gray-400">
            <SearchIcon className="w-4 h-4" />
          </div>
          <input
            type="text"
            placeholder="Search..."
            className={`w-full h-[38px] pl-10 pr-4 rounded-full text-sm font-['Nunito_Sans'] transition-all focus:outline-none focus:ring-2 focus:ring-[#4880FF]/40 ${
              isDark
                ? 'bg-[#1B2431] border border-[#323D4E] text-white placeholder-gray-400'
                : 'bg-[#F5F6FA] border border-[#D5D5D5] text-[#202224] placeholder-[#888888]'
            }`}
          />
        </div>
      </div>

      {/* Right Controls: Notifications, Demo Toggle, Theme Toggle, Profile */}
      <div className="flex items-center space-x-2 sm:space-x-4">
        {/* Config Switcher (Compliant / Critical) */}
        <button
          onClick={onToggleConfig}
          className={`hidden sm:inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold transition-all border cursor-pointer ${
            configType === 'compliant'
              ? 'bg-[#00B69B]/15 text-[#00B69B] border-[#00B69B]/30 hover:bg-[#00B69B]/25'
              : 'bg-[#EF3826]/15 text-[#EF3826] border-[#EF3826]/30 hover:bg-[#EF3826]/25'
          }`}
          title="Toggle between Compliant and Critical sample configs"
        >
          <span
            className={`w-2 h-2 rounded-full ${
              configType === 'compliant' ? 'bg-[#00B69B]' : 'bg-[#EF3826] animate-ping'
            }`}
          />
          <span className="font-semibold">
            {configType === 'compliant' ? 'Config: Compliant' : 'Config: Critical'}
          </span>
        </button>

        {/* Theme Switcher (Dark / Light) */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-slate-700 transition-colors cursor-pointer"
          title={isDark ? 'Switch to Light mode' : 'Switch to Dark mode'}
          aria-label="Toggle theme"
        >
          {isDark ? <SunIcon className="w-5 h-5 text-amber-400" /> : <MoonIcon className="w-5 h-5 text-gray-600" />}
        </button>

        {/* Notification Bell with Badge */}
        <div className="relative">
          <button className="p-2 rounded-full text-gray-500 hover:bg-gray-100 dark:hover:bg-slate-700 transition-colors cursor-pointer">
            <BellIcon className="w-5 h-5" />
          </button>
          <span className="absolute top-1 right-1 w-4 h-4 bg-[#EF3826] text-white text-[10px] font-bold rounded-full flex items-center justify-center">
            6
          </span>
        </div>

        {/* Language selector matching Figma */}
        <div className="hidden md:flex items-center space-x-2 px-2 py-1 cursor-pointer">
          <span className="text-lg">🇬🇧</span>
          <span className="text-xs font-bold text-[#646464] dark:text-gray-300">English</span>
          <svg className="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* User Profile matching Figma Profile component */}
        <div className="flex items-center space-x-3 pl-2 sm:pl-3 border-l border-gray-200 dark:border-[#323D4E]">
          <div className="w-10 h-10 rounded-full bg-[#4880FF]/15 border-2 border-[#4880FF] flex items-center justify-center font-bold text-[#4880FF] text-sm overflow-hidden shrink-0">
            JA
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-sm font-bold text-[#404040] dark:text-white leading-tight">
              Jone Aly
            </div>
            <div className="text-[11px] font-semibold text-[#565656] dark:text-gray-400">
              Admin
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

export default TopBar;
