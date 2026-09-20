<<<<<<< Updated upstream
import React from 'react';
import {
  SocShieldLogo,
  DashboardIcon,
  AlertTriangleIcon,
  ReportDocIcon,
  SettingsIcon,
} from './SocIcons.jsx';
import { useTheme } from '../../context/useTheme.js';

const NAV_LINKS = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { id: 'alerts', label: 'Threat Alerts', icon: AlertTriangleIcon, badge: null },
  { id: 'reports', label: 'Audit Reports', icon: ReportDocIcon },
];

const SocSidebar = ({ activeTab, onSelectTab, isOpen, onClose }) => {
  const { toggleTheme, isDark } = useTheme();

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-xs"
        />
      )}

      {/* Sidebar Navigation */}
      <aside
        className={`fixed top-0 left-0 h-screen w-[220px] z-50 transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        } bg-white dark:bg-[#18191D] border-r border-gray-200 dark:border-[#2A2C34] flex flex-col justify-between p-4 select-none`}
      >
        <div className="space-y-6">
          {/* Logo Brand Header */}
          <div className="flex items-center space-x-3 px-2 pt-2">
            <SocShieldLogo className="w-8 h-8 shrink-0" />
            <div className="flex flex-col">
              <span className="font-extrabold text-lg tracking-tight text-gray-900 dark:text-white leading-tight">
                SecureOps
              </span>
              <span className="text-[10px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                SOC v1.0
              </span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1.5 pt-2">
            {NAV_LINKS.map((item) => {
              const isActive = activeTab === item.id;
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  onClick={() => {
                    onSelectTab(item.id);
                    if (onClose) onClose();
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-semibold transition-all duration-150 cursor-pointer ${
                    isActive
                      ? 'bg-blue-600/10 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 font-bold shadow-xs'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100/80 dark:hover:bg-[#23252A]'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </div>

                  {item.badge && (
                    <span className="px-2 py-0.5 text-[11px] font-bold rounded-full bg-rose-500/15 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 border border-rose-500/30">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Area: Settings & Theme Toggle Pill */}
        <div className="pt-4 border-t border-gray-200 dark:border-[#2A2C34] space-y-4">
          <button
            onClick={() => onSelectTab('settings')}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-xl text-sm font-medium transition-colors cursor-pointer ${
              activeTab === 'settings'
                ? 'bg-blue-600/10 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 font-bold'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-[#23252A]'
            }`}
          >
            <SettingsIcon className="w-4 h-4" />
            <span>Settings</span>
          </button>

          {/* Figma Custom Theme Toggle Switch (Pill with Sun and Moon) */}
          <div className="px-1">
            <button
              onClick={toggleTheme}
              className="w-full relative flex items-center justify-between p-1 bg-gray-200 dark:bg-[#23252A] border border-gray-300/80 dark:border-[#2E3038] rounded-full cursor-pointer h-9 transition-colors shadow-inner"
              title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
              aria-label="Toggle dark/light theme"
            >
              {/* Sun Icon */}
              <span className="w-1/2 flex items-center justify-center text-xs z-10 font-bold text-gray-700 dark:text-gray-400">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="5" strokeWidth="2" />
                  <path strokeWidth="2" strokeLinecap="round" d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
                </svg>
              </span>

              {/* Moon Icon */}
              <span className="w-1/2 flex items-center justify-center text-xs z-10 font-bold text-gray-500 dark:text-gray-200">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
                </svg>
              </span>

              {/* Sliding Indicator */}
              <div
                className={`absolute top-1 bottom-1 w-[calc(50%-4px)] bg-white dark:bg-[#0F1012] rounded-full shadow-md transition-transform duration-200 ease-out flex items-center justify-center ${
                  isDark ? 'translate-x-[calc(100%+2px)]' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};

export default SocSidebar;
=======
import React from 'react';
import {
  SocShieldLogo,
  DashboardIcon,
  AlertTriangleIcon,
  ReportDocIcon,
  SettingsIcon,
} from './SocIcons.jsx';
import { useTheme } from '../../context/useTheme.js';

const NAV_LINKS = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { id: 'alerts', label: 'Threat Alerts', icon: AlertTriangleIcon, badge: null },
  { id: 'reports', label: 'Audit Reports', icon: ReportDocIcon },
];

const SocSidebar = ({ activeTab, onSelectTab, isOpen, onClose }) => {
  const { toggleTheme, isDark } = useTheme();

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-xs"
        />
      )}

      {/* Sidebar Navigation */}
      <aside
        className={`fixed top-0 left-0 h-screen w-[220px] z-50 transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        } bg-white dark:bg-[#18191D] border-r border-gray-200 dark:border-[#2A2C34] flex flex-col justify-between p-4 select-none`}
      >
        <div className="space-y-6">
          {/* Logo Brand Header */}
          <div className="flex items-center space-x-3 px-2 pt-2">
            <SocShieldLogo className="w-8 h-8 shrink-0" />
            <div className="flex flex-col">
              <span className="font-extrabold text-lg tracking-tight text-gray-900 dark:text-white leading-tight">
                CryptoLens
              </span>
              <span className="text-[10px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                IPsec Security Engine
              </span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1.5 pt-2">
            {NAV_LINKS.map((item) => {
              const isActive = activeTab === item.id;
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  onClick={() => {
                    onSelectTab(item.id);
                    if (onClose) onClose();
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-semibold transition-all duration-150 cursor-pointer ${
                    isActive
                      ? 'bg-blue-600/10 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 font-bold shadow-xs'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100/80 dark:hover:bg-[#23252A]'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </div>

                  {item.badge && (
                    <span className="px-2 py-0.5 text-[11px] font-bold rounded-full bg-rose-500/15 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 border border-rose-500/30">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Area: Settings & Theme Toggle Pill */}
        <div className="pt-4 border-t border-gray-200 dark:border-[#2A2C34] space-y-4">
          <button
            onClick={() => onSelectTab('settings')}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-xl text-sm font-medium transition-colors cursor-pointer ${
              activeTab === 'settings'
                ? 'bg-blue-600/10 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 font-bold'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-[#23252A]'
            }`}
          >
            <SettingsIcon className="w-4 h-4" />
            <span>Settings</span>
          </button>

          {/* Figma Custom Theme Toggle Switch (Pill with Sun and Moon) */}
          <div className="px-1">
            <button
              onClick={toggleTheme}
              className="w-full relative flex items-center justify-between p-1 bg-gray-200 dark:bg-[#23252A] border border-gray-300/80 dark:border-[#2E3038] rounded-full cursor-pointer h-9 transition-colors shadow-inner"
              title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
              aria-label="Toggle dark/light theme"
            >
              {/* Sun Icon */}
              <span className="w-1/2 flex items-center justify-center text-xs z-10 font-bold text-gray-700 dark:text-gray-400">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="5" strokeWidth="2" />
                  <path strokeWidth="2" strokeLinecap="round" d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
                </svg>
              </span>

              {/* Moon Icon */}
              <span className="w-1/2 flex items-center justify-center text-xs z-10 font-bold text-gray-500 dark:text-gray-200">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
                </svg>
              </span>

              {/* Sliding Indicator */}
              <div
                className={`absolute top-1 bottom-1 w-[calc(50%-4px)] bg-white dark:bg-[#0F1012] rounded-full shadow-md transition-transform duration-200 ease-out flex items-center justify-center ${
                  isDark ? 'translate-x-[calc(100%+2px)]' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};

export default SocSidebar;
>>>>>>> Stashed changes
