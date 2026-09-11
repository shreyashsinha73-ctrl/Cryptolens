import React, { useState } from 'react';
import mockData from './mock/mockData.json';
import { ThemeProvider } from './context/ThemeContext.jsx';
import SocSidebar from './components/soc/SocSidebar.jsx';
import SocHeader from './components/soc/SocHeader.jsx';
import SocMetricCards from './components/soc/SocMetricCards.jsx';
import SocAlertVolumeTrend from './components/soc/SocAlertVolumeTrend.jsx';
import SocThreatsCoverage from './components/soc/SocThreatsCoverage.jsx';
import SocSeverityDistribution from './components/soc/SocSeverityDistribution.jsx';
import SocWeeklyActivityPattern from './components/soc/SocWeeklyActivityPattern.jsx';
import SocRecentThreats from './components/soc/SocRecentThreats.jsx';
import SocAlertsView from './components/soc/SocAlertsView.jsx';
import SocDesignSystemView from './components/soc/SocDesignSystemView.jsx';
import PerTunnelBreakdown from './components/PerTunnelBreakdown.jsx';
import ScoreDial from './components/ScoreDial.jsx';
import AnalysisDimensions from './components/dashboard/AnalysisDimensions.jsx';

function MainSocApp() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [configType, setConfigType] = useState('critical');
  const [showTelemetryDrawer, setShowTelemetryDrawer] = useState(false);

  const data = mockData[configType];

  const toggleConfig = () => {
    setConfigType((prev) => (prev === 'compliant' ? 'critical' : 'compliant'));
  };

  const totalAlertsCount = configType === 'critical' ? 47 : 12;
  const criticalAlertsCount = configType === 'critical' ? 10 : 0;

  return (
    <div className="min-h-screen bg-[#F1F3F6] dark:bg-[#0F1012] text-gray-900 dark:text-white transition-colors flex font-['Nunito_Sans']">
      {/* Sidebar Navigation */}
      <SocSidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col lg:pl-[220px] min-w-0">
        <div className="p-4 sm:p-6 lg:p-7 space-y-6 max-w-[1600px] w-full mx-auto">
          {/* Header Bar */}
          <SocHeader
            configType={configType}
            onToggleConfig={toggleConfig}
            onToggleSidebar={() => setSidebarOpen((prev) => !prev)}
          />

          {/* Tab Navigation Content */}
          {activeTab === 'alerts' ? (
            <SocAlertsView />
          ) : activeTab === 'settings' ? (
            <SocDesignSystemView />
          ) : activeTab === 'investigations' || activeTab === 'trends' || activeTab === 'reports' ? (
            <div className="space-y-6">
              <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs transition-colors">
                <h2 className="text-xl font-bold text-gray-900 dark:text-white capitalize">
                  {activeTab} Management
                </h2>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Active deep packet inspection & flow analysis telemetry
                </p>
              </div>
              <PerTunnelBreakdown tunnels={data.tunnels} />
            </div>
          ) : (
            /* Main Overview Dashboard matching soc_overview_1.png */
            <div className="space-y-6">
              {/* Row 1: 4 Metric Cards */}
              <SocMetricCards
                totalAlerts={totalAlertsCount}
                criticalAlerts={criticalAlertsCount}
              />

              {/* Row 2: Charts (Alert Volume Trend + Threats Coverage + Severity Distribution) */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                {/* 1. Alert Volume Trend (5 cols on wide screens) */}
                <div className="lg:col-span-6 xl:col-span-5">
                  <SocAlertVolumeTrend />
                </div>

                {/* 2. Threats Coverage Radar (3.5 cols on wide screens) */}
                <div className="lg:col-span-6 xl:col-span-4">
                  <SocThreatsCoverage />
                </div>

                {/* 3. Severity Distribution Donut (3.5 cols on wide screens) */}
                <div className="lg:col-span-12 xl:col-span-3">
                  <SocSeverityDistribution />
                </div>
              </div>

              {/* Row 3: Heatmap & Recent Threats */}
              <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
                {/* Weekly Threat Activity Pattern (8 cols) */}
                <div className="xl:col-span-8">
                  <SocWeeklyActivityPattern />
                </div>

                {/* Recent Threats (4 cols) */}
                <div className="xl:col-span-4">
                  <SocRecentThreats />
                </div>
              </div>

              {/* Cryptographic IPsec SAs Telemetry Section (Expandable/Toggleable) */}
              <div className="pt-2">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-base font-bold text-gray-900 dark:text-white">
                      Cryptographic Posture & Monitored IPsec SAs
                    </h3>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Telemetry integration with Dual-Track CryptoLens Analyzer
                    </p>
                  </div>

                  <button
                    onClick={() => setShowTelemetryDrawer(!showTelemetryDrawer)}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-bold border border-gray-200 dark:border-[#2A2C34] bg-white dark:bg-[#18191D] hover:bg-gray-50 dark:hover:bg-[#23252A] text-gray-800 dark:text-gray-200 transition-colors cursor-pointer shadow-xs"
                  >
                    {showTelemetryDrawer ? 'Hide Deep Telemetry ▲' : 'Show Deep Telemetry ▼'}
                  </button>
                </div>

                {showTelemetryDrawer && (
                  <div className="space-y-6 pt-2 transition-all">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs flex items-center justify-center">
                        <ScoreDial overall_score={data.overall_score} />
                      </div>
                      <div className="bg-white dark:bg-[#18191D] border border-gray-200 dark:border-[#2A2C34] rounded-2xl p-6 shadow-xs">
                        <AnalysisDimensions sub_scores={data.sub_scores} />
                      </div>
                    </div>

                    <PerTunnelBreakdown tunnels={data.tunnels} />
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <MainSocApp />
    </ThemeProvider>
  );
}

export default App;
