import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import {
  UploadCloud,
  FileCheck2,
  AlertTriangle,
  ArrowRight,
  Shield,
  RotateCcw,
  CheckCircle2,
  FileText,
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';

export default function UploadPage() {
  const navigate = useNavigate();
  const {
    handleUploadPcap,
    uploading,
    uploadError,
    activeJobId,
    analysisResult,
    isRealData,
  } = useApp();

  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      setSelectedFile(files[0]);
    }
  };

  const onDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };

  const onDragLeave = () => {
    setDragOver(false);
  };

  const handleStartAnalysis = () => {
    if (selectedFile) {
      handleUploadPcap(selectedFile);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Title */}
      <div className="space-y-1">
        <h1 className="text-xl font-bold text-white tracking-tight">Upload &amp; Analyze Captures</h1>
        {/* <p className="text-xs text-gray-400">
          Upload offline <code className="font-mono text-gray-300">.pcap</code>, <code className="font-mono text-gray-300">.pcapng</code>, or <code className="font-mono text-gray-300">.cap</code> captures for zero-decryption cryptographic analysis.
        </p> */}
      </div>

      {/* Upload Zone */}
      <div
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => fileInputRef.current?.click()}
        className={`relative flex flex-col items-center justify-center p-10 rounded-2xl border-2 border-dashed transition-all cursor-pointer text-center ${
          dragOver
            ? 'border-blue-500 bg-blue-500/10'
            : 'border-[#1F2639] bg-[#0F121C] hover:border-gray-600 hover:bg-[#121624]'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) setSelectedFile(f);
          }}
          accept=".pcap,.pcapng,.cap"
          className="hidden"
        />

        <div className="h-16 w-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-4">
          <UploadCloud className="h-8 w-8" />
        </div>

        {selectedFile ? (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-white font-mono text-sm font-semibold">
              <FileCheck2 className="h-4 w-4 text-emerald-400" />
              <span>{selectedFile.name}</span>
            </div>
            <p className="text-xs text-gray-400 font-mono">
              {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB &middot; Ready for cryptographic evaluation
            </p>
          </div>
        ) : (
          <div className="space-y-1">
            <div className="text-sm font-semibold text-white">
              Drag and drop your network capture here, or <span className="text-blue-400 underline">browse</span>
            </div>
            <p className="text-xs text-gray-500">
              Supports libpcap, pcapng, and tcpdump formats up to 250MB
            </p>
          </div>
        )}
      </div>

      {/* Action Strip if File Selected */}
      {selectedFile && !uploading && !isRealData && (
        <div className="flex items-center justify-between p-4 rounded-xl bg-[#0F121C] border border-[#1F2639]">
          <div className="flex items-center gap-2 text-xs font-mono text-gray-300">
            <Shield className="h-4 w-4 text-blue-400" />
            <span>Scope: Zero Decryption (metadata-only AST inspection)</span>
          </div>
          <Button
            onClick={(e) => {
              e.stopPropagation();
              handleStartAnalysis();
            }}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs h-9 px-4 gap-2 cursor-pointer"
          >
            <span>Start Cryptographic Audit</span>
            <ArrowRight className="h-4 w-4" />
          </Button>
        </div>
      )}

      {/* Uploading / Processing Stepper State */}
      {uploading && (
        <div className="p-6 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-blue-500 animate-ping" />
              <span className="text-sm font-semibold text-white font-mono">
                Processing {selectedFile?.name || activeJobId || 'capture'}...
              </span>
            </div>
            {/* <Badge variant="outline" className="border-blue-500/30 text-blue-400 font-mono text-[10px]">
              Engine Active
            </Badge> */}
          </div>

          <div className="space-y-2 text-xs font-mono text-gray-400">
            <div className="flex items-center gap-2 text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>1. Upload and packet framing complete</span>
            </div>
            <div className="flex items-center gap-2 text-blue-400">
              <RotateCcw className="h-3.5 w-3.5 animate-spin" />
              <span>2. Parsing IKE handshakes &amp; RFC 4303 ESP security associations...</span>
            </div>
            <div className="flex items-center gap-2 text-gray-500">
              <span className="h-3.5 w-3.5 rounded-full border border-gray-600" />
              <span>3. Deterministic scoring &amp; NIST / CNSA compliance auditing</span>
            </div>
          </div>
        </div>
      )}

      {/* Error State */}
      {uploadError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>Upload or analysis failed: {uploadError}</span>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleStartAnalysis}
            className="border-rose-500/40 text-rose-400 hover:bg-rose-500/20 text-xs"
          >
            Retry
          </Button>
        </div>
      )}

      {/* Completed State */}
      {isRealData && !uploading && (
        <div className="p-6 rounded-xl bg-[#0F121C] border border-emerald-500/30 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {/* <CheckCircle2 className="h-5 w-5 text-emerald-400" /> */}
              <div>
                <h3 className="text-sm font-semibold text-white">Cryptographic Audit Completed</h3>
                {/* <p className="text-xs text-gray-400 font-mono">Job ID: {activeJobId}</p> */}
              </div>
            </div>
            <Button
              onClick={() => navigate('/dashboard')}
              className="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs h-9 px-4 gap-2 cursor-pointer"
            >
              <span>View Dashboard</span>
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>

          {/* <div className="p-3 rounded-lg bg-[#0A0D14] border border-[#1F2639] flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-gray-400">
            <div>
               Overall Score: <strong className="text-white text-sm">{analysisResult.overall_score}/100</strong> 
            </div>
            <div>
              Risk: <strong className="text-rose-400">{analysisResult.summary?.risk_level || 'EVALUATED'}</strong>
            </div>
            <div>
              Findings: <strong className="text-amber-400">{analysisResult.threat_matrix?.length || 0}</strong>
            </div>
          </div> */}
        </div>
      )}
    </div>
  );
}
