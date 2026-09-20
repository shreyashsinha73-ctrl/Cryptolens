import React, { useState } from 'react';
import { FavoritesIcon } from '../icons/DashIcons.jsx';
import Button from './Button.jsx';

/**
 * DashStack Product Card / Favourite Product Card
 * From Figma node 0:40458 & 0:40490:
 * - 361x497px (responsive)
 * - borderRadius: 14px
 * - boxShadow: 6px 6px 54px 0px rgba(0, 0, 0, 0.05)
 * - Heart toggle, image slot, title, rating stars, price, action button
 */
const ProductCard = ({
  _id,
  title = 'Hardware Security Module (HSM)',
  category = 'Cryptographic Device',
  price = '$849.00',
  rating = 4.8,
  reviewsCount = 128,
  initialFavorited = false,
  imageUrl,
  onInspect,
}) => {
  const [isFavorited, setIsFavorited] = useState(initialFavorited);

  return (
    <div className="w-full max-w-[361px] bg-white dark:bg-[#273142] rounded-[14px] border border-gray-100 dark:border-[#323D4E] shadow-[6px_6px_54px_0px_rgba(0,0,0,0.05)] dark:shadow-[0_4px_24px_0px_rgba(0,0,0,0.25)] overflow-hidden transition-all duration-200 hover:-translate-y-1 font-['Nunito_Sans'] flex flex-col justify-between">
      {/* Top Image & Favorite Button */}
      <div className="relative w-full h-[220px] bg-[#F5F6FA] dark:bg-[#1B2431] flex items-center justify-center p-4">
        {imageUrl ? (
          <img src={imageUrl} alt={title} className="max-h-full object-contain" />
        ) : (
          <div className="flex flex-col items-center justify-center text-gray-400">
            <svg className="w-16 h-16 text-[#4880FF]/40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
            </svg>
            <span className="text-[11px] font-bold text-gray-400 mt-2 uppercase tracking-wider">
              {category}
            </span>
          </div>
        )}

        {/* Favorite Heart Toggle */}
        <button
          onClick={() => setIsFavorited(!isFavorited)}
          className={`absolute top-3.5 right-3.5 w-9 h-9 rounded-full flex items-center justify-center transition-all cursor-pointer shadow-sm ${
            isFavorited
              ? 'bg-[#EF3826]/10 text-[#EF3826]'
              : 'bg-white/80 dark:bg-[#273142]/80 text-gray-400 hover:text-[#EF3826]'
          }`}
          title={isFavorited ? 'Remove from favorites' : 'Add to favorites'}
        >
          <FavoritesIcon
            className="w-4 h-4"
            filled={isFavorited}
            color={isFavorited ? '#EF3826' : 'currentColor'}
          />
        </button>
      </div>

      {/* Card Body */}
      <div className="p-5 flex flex-col flex-1 justify-between">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#646464] dark:text-gray-400">
              {category}
            </span>
            {/* Star Rating */}
            <div className="flex items-center space-x-1 text-amber-400 text-xs font-bold">
              <span>★</span>
              <span className="text-[#202224] dark:text-white font-bold">{rating}</span>
              <span className="text-gray-400">({reviewsCount})</span>
            </div>
          </div>

          <h4 className="text-base font-bold text-[#202224] dark:text-white mt-1.5 leading-snug line-clamp-2">
            {title}
          </h4>
        </div>

        <div className="mt-5 pt-4 border-t border-gray-100 dark:border-[#323D4E] flex items-center justify-between">
          <div>
            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
              Unit Cost
            </span>
            <span className="text-lg font-extrabold text-[#4880FF] tracking-tight">
              {price}
            </span>
          </div>

          <Button
            variant="compact"
            size="sm"
            onClick={onInspect || (() => alert(`Viewing details for ${title}`))}
          >
            Apply Now
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ProductCard;
