import React from 'react';
import Card from '../common/Card.jsx';
import Badge from '../common/Badge.jsx';
import Button from '../common/Button.jsx';
import ProductCard from '../common/ProductCard.jsx';
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

const ComponentShowcase = () => {
  const handleAction = (msg) => {
    alert(msg);
  };

  return (
    <div className="space-y-8 font-['Nunito_Sans']">
      {/* Intro Header */}
      <div>
        <h2 className="text-2xl font-extrabold text-[#202224] dark:text-white tracking-tight">
          💎 DashStack UI Kit Component Library
        </h2>
        <p className="text-sm text-[#646464] dark:text-gray-400 mt-1">
          Direct implementation of design tokens and components from Figma canvas{' '}
          <span className="font-mono font-bold text-[#4880FF]">0:40222</span>
        </p>
      </div>

      {/* Badges Section */}
      <Card
        title="1. Status Badges & Category Labels"
        subtitle="Pixel-perfect radius (5px status, 3px category) and hex colors from Figma"
        headerBorder={true}
      >
        <div className="space-y-6">
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-[#646464] dark:text-gray-400 mb-3">
              Status Labels (Figma: Label / Completed, Processing, Rejected, On Hold, In Transit)
            </h4>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex flex-col items-center gap-1.5">
                <Badge variant="completed" label="Completed" />
                <span className="text-[10px] text-gray-400 font-mono">#00B69B</span>
              </div>
              <div className="flex flex-col items-center gap-1.5">
                <Badge variant="processing" label="Processing" />
                <span className="text-[10px] text-gray-400 font-mono">#6226EF</span>
              </div>
              <div className="flex flex-col items-center gap-1.5">
                <Badge variant="rejected" label="Rejected" />
                <span className="text-[10px] text-gray-400 font-mono">#EF3826</span>
              </div>
              <div className="flex flex-col items-center gap-1.5">
                <Badge variant="on_hold" label="On Hold" />
                <span className="text-[10px] text-gray-400 font-mono">#FFA756</span>
              </div>
              <div className="flex flex-col items-center gap-1.5">
                <Badge variant="in_transit" label="In Transit" />
                <span className="text-[10px] text-gray-400 font-mono">#BA29FF</span>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-gray-100 dark:border-[#323D4E]">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[#646464] dark:text-gray-400 mb-3">
              Category Tags (Figma: Label / Primary, Work, Friends, Social)
            </h4>
            <div className="flex flex-wrap items-center gap-3">
              <Badge variant="primary" label="Primary" size="sm" />
              <Badge variant="work" label="Work" size="sm" />
              <Badge variant="friends" label="Friends" size="sm" />
              <Badge variant="social" label="Social" size="sm" />
            </div>
          </div>
        </div>
      </Card>

      {/* Buttons Section */}
      <Card
        title="2. Buttons & Actions"
        subtitle="From Figma Button / Compose message (238x43px) & Button / Apply Now (129x36px)"
        headerBorder={true}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
          <div className="space-y-3">
            <span className="text-xs font-bold uppercase tracking-wider text-[#646464] dark:text-gray-400 block">
              Button / Compose message (Primary CTA)
            </span>
            <Button
              variant="primary"
              className="w-full max-w-[238px] h-[43px]"
              onClick={() => handleAction('Compose Action triggered!')}
            >
              + Compose
            </Button>
            <p className="text-[11px] text-gray-400">
              Width: 238px • Height: 43px • Radius: 8px • Background: #4880FF
            </p>
          </div>

          <div className="space-y-3">
            <span className="text-xs font-bold uppercase tracking-wider text-[#646464] dark:text-gray-400 block">
              Button / Apply Now (Secondary CTA)
            </span>
            <div className="flex items-center gap-3">
              <Button
                variant="compact"
                className="w-[129px] h-[36px]"
                onClick={() => handleAction('Apply Now triggered!')}
              >
                Apply Now
              </Button>
              <Button variant="outline" size="sm" onClick={() => handleAction('Outline Button')}>
                Outline
              </Button>
            </div>
            <p className="text-[11px] text-gray-400">
              Width: 129px • Height: 36px • Radius: 6px • Font: Nunito Sans 700
            </p>
          </div>
        </div>
      </Card>

      {/* Product Cards Section */}
      <Card
        title="3. Product Card & Favourite Product Card"
        subtitle="From Figma nodes 0:40458 & 0:40490 (361x497px card container with 14px radius)"
        headerBorder={true}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <ProductCard
            title="IPsec Hardware Cryptographic Accelerator"
            category="Gateway Device"
            price="$1,249.00"
            rating={4.9}
            reviewsCount={84}
            initialFavorited={false}
          />
          <ProductCard
            title="Post-Quantum Cryptography (PQC) Module"
            category="Security Co-Processor"
            price="$2,190.00"
            rating={5.0}
            reviewsCount={42}
            initialFavorited={true}
          />
          <ProductCard
            title="Network Flow Telemetry Probe v2"
            category="Monitoring Sensor"
            price="$620.00"
            rating={4.7}
            reviewsCount={116}
            initialFavorited={false}
          />
        </div>
      </Card>

      {/* Icon System Section */}
      <Card
        title="4. Element / Icon System"
        subtitle="14 UI Kit icons extracted from Figma node 0:40222"
        headerBorder={true}
      >
        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-4">
          {[
            { name: 'dashboard', Icon: DashboardIcon },
            { name: 'product', Icon: ProductsIcon },
            { name: 'Favourites', Icon: FavoritesIcon },
            { name: 'chat', Icon: ChatIcon },
            { name: 'orderlist', Icon: OrderListIcon },
            { name: 'stock', Icon: StockIcon },
            { name: 'pricing', Icon: PricingIcon },
            { name: 'calendar', Icon: CalendarIcon },
            { name: 'to do', Icon: ToDoIcon },
            { name: 'contact', Icon: ContactIcon },
            { name: 'invoice', Icon: InvoiceIcon },
            { name: 'UI element', Icon: UIElementIcon },
            { name: 'team', Icon: TeamIcon },
            { name: 'settings', Icon: SettingsIcon },
          ].map((item) => {
            const Icon = item.Icon;
            return (
              <div
                key={item.name}
                className="flex flex-col items-center justify-center p-3 rounded-[10px] bg-[#F5F6FA] dark:bg-[#1B2431] border border-gray-200/60 dark:border-[#323D4E] hover:border-[#4880FF] transition-all group"
              >
                <div className="w-9 h-9 rounded-lg bg-white dark:bg-[#273142] shadow-xs flex items-center justify-center text-[#4880FF] group-hover:scale-110 transition-transform">
                  <Icon className="w-5 h-5" />
                </div>
                <span className="text-[11px] font-bold text-[#202224] dark:text-gray-300 mt-2 truncate max-w-full">
                  {item.name}
                </span>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
};

export default ComponentShowcase;
