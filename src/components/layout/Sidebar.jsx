import React from 'react';
import {
  DashboardIcon,
  ProductsIcon,
  FavoritesIcon,
  ChatIcon,
  OrderListIcon,
  StockIcon,
  PricingIcon,
  CalendarIcon,
  ToDoIcon,
  ContactIcon,
  InvoiceIcon,
  UIElementIcon,
  TeamIcon,
  SettingsIcon,
} from '../icons/DashIcons.jsx';
import { useTheme } from '../../context/useTheme.js';

const MENU_ITEMS_MAIN = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon },
  { id: 'tunnels', label: 'Products / SAs', icon: ProductsIcon },
  { id: 'favorites', label: 'Favorites', icon: FavoritesIcon },
  { id: 'inbox', label: 'Inbox', icon: ChatIcon, badge: '6' },
  { id: 'orders', label: 'Order Lists', icon: OrderListIcon },
  { id: 'stock', label: 'Product Stock', icon: StockIcon },
];

const MENU_ITEMS_PAGES = [
  { id: 'pricing', label: 'Pricing', icon: PricingIcon },
  { id: 'calendar', label: 'Calendar', icon: CalendarIcon },
  { id: 'todo', label: 'To-Do', icon: ToDoIcon },
  { id: 'contact', label: 'Contact', icon: ContactIcon },
  { id: 'invoice', label: 'Invoice', icon: InvoiceIcon },
  { id: 'ui-elements', label: 'UI Elements', icon: UIElementIcon },
  { id: 'team', label: 'Team', icon: TeamIcon },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
];

const Sidebar = ({ activeTab, onSelectTab, isOpen, onClose }) => {
  const { isDark } = useTheme();

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-black/40 z-40 lg:hidden backdrop-blur-xs"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 left-0 h-screen w-[240px] z-50 transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        } ${
          isDark
            ? 'bg-[#273142] border-r border-[#323D4E] text-gray-200'
            : 'bg-white border-r border-[#E0E0E0] text-[#202224]'
        } flex flex-col`}
      >
        {/* Logo Section matching Figma Logo (Light/Dark) */}
        <div className="h-[70px] flex items-center px-6 border-b border-gray-100 dark:border-[#323D4E] shrink-0">
          <div className="flex items-center space-x-2">
            <span className="font-extrabold text-[22px] tracking-tight text-[#4880FF] font-['Nunito_Sans']">
              Dash
            </span>
            <span
              className={`font-extrabold text-[22px] tracking-tight font-['Nunito_Sans'] ${
                isDark ? 'text-white' : 'text-[#202224]'
              }`}
            >
              Stack
            </span>
            <span className="ml-1 text-[9px] font-bold px-1.5 py-0.5 rounded bg-[#4880FF]/10 text-[#4880FF] uppercase tracking-wider">
              Lens
            </span>
          </div>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 overflow-y-auto py-4 px-3 space-y-1 select-none scrollbar-thin">
          {MENU_ITEMS_MAIN.map((item) => {
            const isActive = activeTab === item.id;
            const Icon = item.icon;

            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectTab(item.id);
                  if (onClose) onClose();
                }}
                className={`w-full flex items-center justify-between px-4 py-3 rounded-[6px] text-sm font-semibold transition-all duration-150 cursor-pointer ${
                  isActive
                    ? 'bg-[#4880FF] text-white shadow-[0_4px_12px_rgba(72,128,255,0.3)]'
                    : isDark
                    ? 'text-gray-300 hover:bg-[#1f2735] hover:text-white'
                    : 'text-[#202224] hover:bg-[#F5F6FA] hover:text-[#4880FF]'
                }`}
              >
                <div className="flex items-center space-x-3.5">
                  <Icon
                    className="w-5 h-5"
                    color={isActive ? '#FFFFFF' : isDark ? '#A6B0CF' : '#202224'}
                  />
                  <span className="tracking-tight">{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${
                      isActive
                        ? 'bg-white text-[#4880FF]'
                        : 'bg-[#EF3826] text-white'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}

          {/* Section Heading: PAGES */}
          <div className="pt-5 pb-2 px-4">
            <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#979797] dark:text-[#646464]">
              Pages
            </span>
          </div>

          {MENU_ITEMS_PAGES.map((item) => {
            const isActive = activeTab === item.id;
            const Icon = item.icon;

            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectTab(item.id);
                  if (onClose) onClose();
                }}
                className={`w-full flex items-center justify-between px-4 py-3 rounded-[6px] text-sm font-semibold transition-all duration-150 cursor-pointer ${
                  isActive
                    ? 'bg-[#4880FF] text-white shadow-[0_4px_12px_rgba(72,128,255,0.3)]'
                    : isDark
                    ? 'text-gray-300 hover:bg-[#1f2735] hover:text-white'
                    : 'text-[#202224] hover:bg-[#F5F6FA] hover:text-[#4880FF]'
                }`}
              >
                <div className="flex items-center space-x-3.5">
                  <Icon
                    className="w-5 h-5"
                    color={isActive ? '#FFFFFF' : isDark ? '#A6B0CF' : '#202224'}
                  />
                  <span className="tracking-tight">{item.label}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Footer info in sidebar */}
        <div className="p-4 border-t border-gray-100 dark:border-[#323D4E] shrink-0 text-center">
          <p className="text-[11px] text-gray-400 font-medium">DashStack v1.2 • CryptoLens</p>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
