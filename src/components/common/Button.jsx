import React from 'react';

/**
 * DashStack Buttons
 * From Figma node 0:40222:
 * - Button / Compose message (Primary, 238x43px, radius 8px, #4880FF, text #FFF)
 * - Button / Apply Now (Compact CTA, 129x36px, radius 6px, #4880FF, text #FFF)
 */
const Button = ({
  children,
  variant = 'primary', // 'primary', 'compact', 'outline', 'ghost', 'dark'
  size = 'md', // 'sm', 'md', 'lg'
  icon: Icon,
  className = '',
  onClick,
  ...props
}) => {
  let variantStyles = '';

  switch (variant) {
    case 'primary':
      variantStyles =
        'bg-[#4880FF] hover:bg-[#354DF0] text-white shadow-[0_4px_14px_rgba(72,128,255,0.35)] active:translate-y-[1px]';
      break;
    case 'compact':
      variantStyles =
        'bg-[#4880FF] hover:bg-[#354DF0] text-white text-xs font-bold rounded-[6px] shadow-[0_4px_12px_rgba(72,128,255,0.25)]';
      break;
    case 'outline':
      variantStyles =
        'bg-transparent border border-[#D5D5D5] dark:border-[#323D4E] text-[#202224] dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-slate-800';
      break;
    case 'ghost':
      variantStyles =
        'bg-transparent text-[#646464] dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-800';
      break;
    case 'dark':
      variantStyles =
        'bg-[#273142] hover:bg-[#1f2735] text-white border border-[#323D4E]';
      break;
    default:
      variantStyles = 'bg-[#4880FF] hover:bg-[#354DF0] text-white';
  }

  let sizeStyles = 'px-5 py-2.5 text-sm font-bold rounded-[8px]';
  if (size === 'sm' || variant === 'compact') {
    sizeStyles = 'px-3.5 py-2 text-xs font-bold rounded-[6px]';
  } else if (size === 'lg') {
    sizeStyles = 'px-6 py-3 text-base font-bold rounded-[10px]';
  }

  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center justify-center gap-2 font-['Nunito_Sans'] transition-all duration-200 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${sizeStyles} ${variantStyles} ${className}`}
      {...props}
    >
      {Icon && <Icon className="w-4 h-4" />}
      {children}
    </button>
  );
};

export default Button;
