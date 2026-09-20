import React from 'react';

/**
 * DashStack Card Container
 * From Figma node 0:40222 (Product Card / Container):
 * - backgroundColor: #FFFFFF (Light) / #273142 (Dark)
 * - borderRadius: 14px
 * - boxShadow: 6px 6px 54px 0px rgba(0, 0, 0, 0.05)
 */
const Card = ({
  children,
  className = '',
  title,
  subtitle,
  action,
  headerBorder = false,
  padding = 'p-6',
}) => {
  return (
    <div
      className={`bg-white dark:bg-[#273142] rounded-[14px] border border-gray-100 dark:border-[#323D4E] shadow-[6px_6px_54px_0px_rgba(0,0,0,0.05)] dark:shadow-[0_4px_24px_0px_rgba(0,0,0,0.25)] transition-colors duration-200 ${className}`}
    >
      {(title || action) && (
        <div
          className={`flex items-center justify-between px-6 pt-5 pb-4 ${
            headerBorder ? 'border-b border-gray-100 dark:border-[#323D4E]' : ''
          }`}
        >
          <div>
            {title && (
              <h3 className="text-base md:text-lg font-bold text-[#202224] dark:text-white tracking-tight">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-xs text-[#646464] dark:text-gray-400 mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className={title || action ? padding.replace('p-6', 'px-6 pb-6 pt-2') : padding}>
        {children}
      </div>
    </div>
  );
};

export default Card;
