import React from 'react';

/**
 * DashStack Status Badges and Tags
 * From Figma node 0:40222:
 * - Label / Completed (#00B69B)
 * - Label / Processing (#6226EF)
 * - Label / Rejected (#EF3826)
 * - Label / On Hold (#FFA756)
 * - Label / In Transit (#BA29FF)
 * - Category Labels: Primary, Work, Friends, Social
 */
const VARIANTS = {
  // Status Labels
  completed: {
    bg: 'bg-[#00B69B]/15 dark:bg-[#00B69B]/20',
    text: 'text-[#00B69B]',
    border: 'border-[#00B69B]/20',
    defaultLabel: 'Completed',
  },
  processing: {
    bg: 'bg-[#6226EF]/15 dark:bg-[#6226EF]/20',
    text: 'text-[#6226EF]',
    border: 'border-[#6226EF]/20',
    defaultLabel: 'Processing',
  },
  rejected: {
    bg: 'bg-[#EF3826]/15 dark:bg-[#EF3826]/20',
    text: 'text-[#EF3826]',
    border: 'border-[#EF3826]/20',
    defaultLabel: 'Rejected',
  },
  on_hold: {
    bg: 'bg-[#FFA756]/15 dark:bg-[#FFA756]/20',
    text: 'text-[#FFA756]',
    border: 'border-[#FFA756]/20',
    defaultLabel: 'On Hold',
  },
  in_transit: {
    bg: 'bg-[#BA29FF]/15 dark:bg-[#BA29FF]/20',
    text: 'text-[#BA29FF]',
    border: 'border-[#BA29FF]/20',
    defaultLabel: 'In Transit',
  },
  // Category Labels
  primary: {
    bg: 'bg-[#4880FF]/15 dark:bg-[#4880FF]/20',
    text: 'text-[#4880FF]',
    border: 'border-[#4880FF]/20',
    defaultLabel: 'Primary',
  },
  work: {
    bg: 'bg-[#FD9A56]/15 dark:bg-[#FD9A56]/20',
    text: 'text-[#FD9A56]',
    border: 'border-[#FD9A56]/20',
    defaultLabel: 'Work',
  },
  friends: {
    bg: 'bg-[#D456FD]/15 dark:bg-[#D456FD]/20',
    text: 'text-[#D456FD]',
    border: 'border-[#D456FD]/20',
    defaultLabel: 'Friends',
  },
  social: {
    bg: 'bg-[#5A8CFF]/15 dark:bg-[#5A8CFF]/20',
    text: 'text-[#5A8CFF]',
    border: 'border-[#5A8CFF]/20',
    defaultLabel: 'Social',
  },
  // Telemetry Aliases
  active: {
    bg: 'bg-[#00B69B]/15 dark:bg-[#00B69B]/20',
    text: 'text-[#00B69B]',
    border: 'border-[#00B69B]/20',
    defaultLabel: 'Active',
  },
  flagged: {
    bg: 'bg-[#FFA756]/15 dark:bg-[#FFA756]/20',
    text: 'text-[#FFA756]',
    border: 'border-[#FFA756]/20',
    defaultLabel: 'Flagged',
  },
  critical: {
    bg: 'bg-[#EF3826]/15 dark:bg-[#EF3826]/20',
    text: 'text-[#EF3826]',
    border: 'border-[#EF3826]/20',
    defaultLabel: 'Critical',
  },
};

const Badge = ({ variant = 'completed', label, size = 'md', className = '' }) => {
  const config = VARIANTS[variant.toLowerCase()] || VARIANTS.primary;
  const content = label || config.defaultLabel;

  const sizeClasses = size === 'sm'
    ? 'px-2 py-0.5 text-[11px] font-semibold rounded-[4px]'
    : 'px-3 py-1 text-[12px] font-bold rounded-[5px] min-w-[70px] inline-flex items-center justify-center';

  return (
    <span
      className={`font-['Nunito_Sans'] transition-colors border ${config.bg} ${config.text} ${config.border} ${sizeClasses} ${className}`}
    >
      {content}
    </span>
  );
};

export default Badge;
