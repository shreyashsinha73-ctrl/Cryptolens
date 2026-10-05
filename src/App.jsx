import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AppProvider, useApp } from './context/AppContext';
import StitchSidebar from './components/soc/StitchSidebar';
import StitchHeader from './components/soc/StitchHeader';

// Pages
import DashboardPage from './pages/DashboardPage';
import LiveMonitorPage from './pages/LiveMonitorPage';
import PlaceholderPage from './pages/PlaceholderPage';
import FindingsPage from './pages/FindingsPage';
import AiInsightsPage from './pages/AiInsightsPage';
import ReportsPage from './pages/ReportsPage';
import UploadPage from './pages/UploadPage';
import TestbedPage from './pages/TestbedPage';

function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { uploadError, setUploadError, setActiveJobId } = useApp();

  return (
    <div className="min-h-screen bg-[#090A0F] text-[#F3F4F6] flex font-sans antialiased">
      {/* Sidebar Navigation */}
      <StitchSidebar
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col md:pl-60 min-w-0">
        <StitchHeader
          onToggleSidebar={() => setSidebarOpen((p) => !p)}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-7 space-y-6 max-w-[1600px] w-full mx-auto">
          {/* Global Upload Error Toast / Banner */}
          {uploadError && (
            <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 px-4 py-3 rounded-lg text-xs font-semibold flex items-center justify-between">
              <span>⚠ {uploadError}</span>
              <button
                onClick={() => {
                  setUploadError(null);
                  if (setActiveJobId) setActiveJobId(null);
                  localStorage.removeItem('cryptolens_active_job');
                }}
                className="underline hover:text-white cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Routed Views */}
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/live" element={<LiveMonitorPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/testbed" element={<TestbedPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/ai" element={<AiInsightsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/help" element={<PlaceholderPage title="Help & Terminology" description="Zero-decryption cryptographic terminology and guide." />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppProvider>
        <BrowserRouter>
          <AppLayout />
        </BrowserRouter>
      </AppProvider>
    </ThemeProvider>
  );
}
