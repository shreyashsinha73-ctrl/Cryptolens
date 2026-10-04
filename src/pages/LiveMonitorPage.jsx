import React from 'react';
import LiveTelemetryPanel from '../components/dashboard/LiveTelemetryPanel';
import { useApp } from '../context/AppContext';

export default function LiveMonitorPage() {
  const { activeJobId, isRealData, unifiedThreats } = useApp();

  return (
    <div className="space-y-4">
      <LiveTelemetryPanel
        jobId={activeJobId}
        _isRealData={isRealData}
        _unifiedThreats={unifiedThreats}
      />
    </div>
  );
}
