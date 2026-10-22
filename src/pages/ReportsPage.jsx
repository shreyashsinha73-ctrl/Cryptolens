import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, Download, AlertTriangle } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';


export default function ReportsPage() {
  const { activeJobId, analysisResult: activeResult, loadingResult, uploading } = useApp();
  const [downloading, setDownloading] = useState(null);
  const [error, setError] = useState(null);

  const handleDownload = async (type) => {
    if (!activeJobId) return;
    setDownloading(type);
    setError(null);
    try {
      const res = await fetch(`/api/v1/report/${activeJobId}/pdf?type=${type}`);
      if (!res.ok) {
        if (res.status === 404) {
          throw new Error('Analysis session expired on server. Please upload a new PCAP to generate reports.');
        }
        throw new Error(`HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `CryptoLens_Report_${type}_${activeJobId.slice(0,8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      setError(e.message);
    } finally {
      setDownloading(null);
    }

  };


  if ((loadingResult || uploading) && !activeResult) {
    return (
      <div className="flex-1 space-y-6 p-8 overflow-y-auto bg-[#090A0F]">
        <div className="flex items-center gap-3 text-emerald-400 font-mono text-sm">
          <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span>Restoring reports for session {activeJobId}...</span>
        </div>
        <div className="space-y-4">
          <div className="h-10 w-64 bg-[#1F2639] rounded animate-pulse" />
          <div className="h-64 w-full bg-[#0F121C] border border-[#1F2639] rounded-xl animate-pulse" />
        </div>
      </div>
    );
  }

  if (!activeJobId || !activeResult) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 min-h-[600px]">
        <AlertTriangle className="h-12 w-12 mb-4 opacity-50" />
        <h2 className="text-xl font-semibold text-zinc-300">No active analysis</h2>
        <p className="mt-2 text-sm text-center max-w-md">
          Upload a PCAP or run a testbed capture to generate reports.
        </p>
      </div>
    );
  }


  return (
    <div className="flex-1 space-y-6 p-8 overflow-y-auto bg-[#090A0F]">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-zinc-100 tracking-tight flex items-center gap-2">
          <FileText className="h-6 w-6 text-emerald-400" /> Compliance Reports
        </h1>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-[#0F121C] border-[#1F2639]">
          <CardHeader>
            <CardTitle className="text-lg text-zinc-100">Executive Assessment</CardTitle>
            <CardDescription className="text-zinc-400">High-level summary of cryptographic posture, compliance status, and top-priority remediation items for leadership.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              onClick={() => handleDownload('executive')}
              disabled={downloading !== null}
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white"
            >
              <Download className="mr-2 h-4 w-4" />
              {downloading === 'executive' ? 'Generating PDF...' : 'Download Executive PDF'}
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-[#0F121C] border-[#1F2639]">
          <CardHeader>
            <CardTitle className="text-lg text-zinc-100">Technical Audit</CardTitle>
            <CardDescription className="text-zinc-400">Detailed evidence log including full wire metadata, exact findings, XAI attribution maps, and vendor-specific configuration templates.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              onClick={() => handleDownload('technical')}
              disabled={downloading !== null}
              className="w-full bg-[#1F2639] hover:bg-[#2A3143] text-zinc-100"
            >
              <Download className="mr-2 h-4 w-4" />
              {downloading === 'technical' ? 'Generating PDF...' : 'Download Technical PDF'}
            </Button>
          </CardContent>
        </Card>
      </div>

      {error && (
        <div className="p-4 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 shrink-0" />
            <p>{error}</p>
          </div>
          <Link
            to="/upload"
            className="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded text-xs font-semibold cursor-pointer shrink-0"
          >
            Upload PCAP
          </Link>
        </div>
      )}

    </div>
  );
}
