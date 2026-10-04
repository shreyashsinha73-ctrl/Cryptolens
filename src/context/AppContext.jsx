import React, { createContext, useContext, useState, useEffect, useMemo, useCallback } from 'react';
import { useLiveTelemetry } from '../hooks/useLiveTelemetry';
import { mergeThreatsAndAnomalies, getThreatCounts } from '../lib/threatMatrixHelper';

const AppContext = createContext(null);

export function AppProvider({ children }) {
  // Live Telemetry Hook (singleton across entire app)
  const telemetry = useLiveTelemetry();

  // Audit / Job state
  const [activeJobId, setActiveJobId] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [ingesting, setIngesting] = useState(false);
  const [briefingPending, setBriefingPending] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Poll for executive briefing if missing on completed job
  useEffect(() => {
    if (!briefingPending || !activeJobId) return;
    let tries = 0;
    const t = setInterval(async () => {
      tries += 1;
      try {
        const r = await fetch(`/api/v1/results/${activeJobId}`);
        if (r.ok) {
          const p = await r.json();
          if (p.remediation) {
            setAnalysisResult(prev => (prev ? { ...prev, remediation: p.remediation } : prev));
            setBriefingPending(false);
          }
        }
      } catch { /* retry */ }
      if (tries >= 15) setBriefingPending(false);
    }, 2000);
    return () => clearInterval(t);
  }, [briefingPending, activeJobId]);

  // Poll for job completion
  useEffect(() => {
    if (!activeJobId) return;
    let subscribed = true;
    let notFoundCount = 0;

    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/v1/results/${activeJobId}`);
        if (res.status === 404) {
          notFoundCount += 1;
          if (notFoundCount > 5) {
            if (subscribed) {
              setUploadError('Job not found after 5 retries');
              setUploading(false);
            }
            return true;
          }
          return false;
        }
        if (res.ok) {
          const payload = await res.json();
          if (payload.status === 'completed') {
            if (subscribed) {
              setAnalysisResult(payload);
              setUploading(false);
              if (!payload.remediation) setBriefingPending(true);
            }
            return true;
          } else if (payload.status === 'failed') {
            if (subscribed) {
              setUploadError(payload.error?.message || 'Analysis failed');
              setUploading(false);
            }
            return true;
          }
        }
      } catch (e) {
        console.error('Poll error:', e);
      }
      return false;
    };

    let interval = null;
    fetchStatus().then(shouldStop => {
      if (!shouldStop && subscribed) {
        interval = setInterval(async () => {
          const stop = await fetchStatus();
          if (stop) {
            clearInterval(interval);
            interval = null;
          }
        }, 1000);
      }
    });

    return () => {
      subscribed = false;
      if (interval) clearInterval(interval);
    };
  }, [activeJobId]);

  const handleUploadPcap = useCallback(async (file) => {
    setUploading(true);
    setUploadError(null);
    setAnalysisResult(null);
    if (telemetry.clearWire) telemetry.clearWire();

    try {
      const form = new FormData();
      form.append('file', file);
      const res = await fetch('/api/v1/analyze', {
        method: 'POST',
        body: form,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Upload failed with status ${res.status}`);
      }

      const info = await res.json();
      setActiveJobId(info.job_id);
    } catch (err) {
      setUploadError(err.message || 'PCAP upload failed');
      setUploading(false);
    }
  }, [telemetry]);

  const handleIngestTestbed = useCallback(async () => {
    setIngesting(true);
    setUploadError(null);
    try {
      const res = await fetch('/api/v1/capture/ingest?force=true', {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`Testbed ingestion failed: ${res.status}`);
      const info = await res.json();
      
      // Look for the first completed job_id in results or info.job_id
      const firstJobId = info.job_id || info.results?.find(r => r.status === 'completed')?.job_id;
      if (firstJobId) {
        setActiveJobId(firstJobId);
        setUploading(true);
      }
    } catch (err) {
      setUploadError(err.message || 'Testbed ingest failed');
    } finally {
      setIngesting(false);
    }
  }, []);

  const handleDownloadReport = useCallback(async () => {
    if (!activeJobId) return;
    try {
      const res = await fetch(`/api/v1/report/${activeJobId}/pdf`);
      if (!res.ok) throw new Error('Failed to fetch report PDF');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `CryptoLens_Report_${activeJobId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download report error:', err);
    }
  }, [activeJobId]);

  // Unified threat matrix
  const unifiedThreats = useMemo(() => {
    return mergeThreatsAndAnomalies(
      analysisResult?.threat_matrix || [],
      telemetry.anomalyAlerts || []
    );
  }, [analysisResult?.threat_matrix, telemetry.anomalyAlerts]);

  const threatCounts = useMemo(() => getThreatCounts(unifiedThreats), [unifiedThreats]);

  const isRealData = Boolean(analysisResult && analysisResult.status === 'completed');

  const value = {
    telemetry,
    activeJobId,
    setActiveJobId,
    analysisResult,
    setAnalysisResult,
    isRealData,
    uploading,
    setUploading,
    uploadError,
    setUploadError,
    ingesting,
    unifiedThreats,
    threatCounts,
    sidebarOpen,
    setSidebarOpen,
    handleUploadPcap,
    handleIngestTestbed,
    handleDownloadReport,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) throw new Error('useApp must be used within an AppProvider');
  return context;
}
