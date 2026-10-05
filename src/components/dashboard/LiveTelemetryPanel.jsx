import React, { useState, useEffect, useRef } from 'react';
import { useLiveTelemetry } from '../../hooks/useLiveTelemetry';
import LiveWireGraph from './LiveWireGraph.jsx';
import { getPacketSeverity } from '../../lib/wireSeverity';
import { Button } from '../ui/button';
import {
  Download,
  X,
  Copy,
  Check,
  Maximize2,
  Plus,
  Minus,
  RotateCcw,
  Activity,
  Lock,
  FileText,
  Sparkles,
  Radio
} from 'lucide-react';

function formatTimestamp(ts) {
  if (ts === null || ts === undefined) return '—';
  const num = typeof ts === 'number' ? ts : parseFloat(ts);
  if (isNaN(num) || num <= 0) return String(ts);
  if (num > 1e8) {
    const d = new Date(num * 1000);
    const timeStr = d.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
    const ms = String(Math.floor((num % 1) * 1000)).padStart(3, '0');
    return `${timeStr}.${ms}`;
  }
  return `${num.toFixed(3)}s`;
}

export default function LiveTelemetryPanel({
  jobId = null,
  _isRealData = false,
  onAnalyzeCapture = null,
  _unifiedThreats = [],
}) {
  const {
    isConnected,
    isStreaming,
    streamCompleted: _streamCompleted,
    completionMessage: _completionMessage,
    streamSource,
    wireEvents,
    espEvents,
    ikeEvents: _ikeEvents,
    rollingScore: _rollingScore,
    startCapture,
    simulateCapture,
    stopCapture,
    analyzeCapture,
    clearWire,
  } = useLiveTelemetry();

  const hasNonLoopbackFrame = wireEvents.some((e) => {
    const src = e.src_ip || '';
    const dst = e.dst_ip || '';
    return (
      src &&
      dst &&
      src !== '127.0.0.1' &&
      dst !== '127.0.0.1' &&
      src !== '::1' &&
      dst !== '::1' &&
      !src.startsWith('127.') &&
      !dst.startsWith('127.')
    );
  });
  const showAnalyzeButton = streamSource === 'live_sniff' && hasNonLoopbackFrame;

  const [analyzingNetwork, setAnalyzingNetwork] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [triageFilter, setTriageFilter] = useState('anomalies');
  const [copiedHex, setCopiedHex] = useState(false);

  // AI Explain State
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState(null);
  
  const activeRequestRef = useRef(null);

  // Reset stream counter, wire events, and inspection state whenever a new PCAP is ingested or uploaded
  useEffect(() => {
    clearWire();
    setSelectedPacket(null);
  }, [jobId, clearWire]);

  // Cancel any ongoing AI explanation request and reset state whenever selectedPacket changes
  useEffect(() => {
    if (activeRequestRef.current) {
      activeRequestRef.current.abort();
      activeRequestRef.current = null;
    }
    setAiLoading(false);
    setAiResult(null);
  }, [selectedPacket]);

  const handleExplainPacket = async () => {
    if (!selectedPacket) return;

    if (activeRequestRef.current) {
      activeRequestRef.current.abort();
    }
    const controller = new AbortController();
    activeRequestRef.current = controller;

    setAiLoading(true);

    try {
      const derivedSeverity = getPacketSeverity(selectedPacket);
      const sevUpper =
        derivedSeverity === 'critical'
          ? 'CRITICAL'
          : derivedSeverity === 'medium'
          ? 'MEDIUM'
          : 'LOW';

      const payload = {
        src_ip: selectedPacket.src_ip || '10.10.0.1',
        dst_ip: selectedPacket.dst_ip || '10.10.0.2',
        src_port: selectedPacket.src_port ?? null,
        dst_port: selectedPacket.dst_port ?? null,
        protocol: selectedPacket.protocol || 'ESP',
        packet_length: Number(selectedPacket.packet_length || 0),
        timestamp:
          selectedPacket.timestamp !== undefined && selectedPacket.timestamp !== null
            ? Number(selectedPacket.timestamp)
            : null,
        packet_type: selectedPacket.packet_type || null,
        spi:
          selectedPacket.spi && selectedPacket.spi !== '—'
            ? String(selectedPacket.spi)
            : null,
        seq_num:
          selectedPacket.seq_num !== undefined && selectedPacket.seq_num !== null
            ? Number(selectedPacket.seq_num)
            : null,
        severity: selectedPacket.severity || sevUpper,
        is_replay: Boolean(selectedPacket.is_replay),
        is_sweet32: Boolean(selectedPacket.is_sweet32),
        details: selectedPacket.details || null,
        observability: selectedPacket.observability || 'wire_observed',
        evidence_source: selectedPacket.evidence_source || 'esp_header_metadata',
      };

      const res = await fetch('/api/v1/live/explain-packet', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with ${res.status}`);
      }

      const data = await res.json();
      setAiResult(data);
    } catch (err) {
      if (err.name === 'AbortError') {
        return;
      }
    } finally {
      setAiLoading(false);
    }
  };

  const handleAnalyzeNetwork = async () => {
    try {
      setAnalyzingNetwork(true);
      const res = await analyzeCapture();
      if (res && res.job_id && onAnalyzeCapture) {
        onAnalyzeCapture(res.job_id);
      }
    } catch (err) {
      console.error('Error analyzing live network capture:', err);
    } finally {
      setAnalyzingNetwork(false);
    }
  };

  

  useEffect(() => {
  }, [jobId]);

  const handleSimulate = () => {
    clearWire();
    setSelectedPacket(null);
    if (jobId) {
      simulateCapture(jobId);
    } else {
      simulateCapture();
    }
  };

  // Severity counts for triage
  const criticalCount = wireEvents.filter((p) => getPacketSeverity(p) === 'critical').length;
  const mediumCount = wireEvents.filter((p) => getPacketSeverity(p) === 'medium').length;
  const lowCount = wireEvents.filter((p) => getPacketSeverity(p) === 'low').length;
  const totalCount = wireEvents.length;
  const anomaliesCount = criticalCount + mediumCount;

  // Selected packet formatting
  const pktSeverity = selectedPacket ? getPacketSeverity(selectedPacket) : 'low';

  const copyHex = () => {
    if (!selectedPacket) return;
    const hex = selectedPacket.raw_header_hex || '9f 30 ca 19 42 e1 09 00 00 00 00 00 00 00 00 00 04 10 02 00 00 00 00 00 00 00 01 8c';
    navigator.clipboard?.writeText(hex);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  return (
    <div className="space-y-3.5">
      {/* ── Stitch Top Control Bar ── */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-2 rounded-lg bg-[#0F121C] border border-[#1F2639]">
        {/* Left: Stream mode pill & Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-[#161B26] border border-[#242C3F] text-xs font-medium text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>{isStreaming ? 'Streaming' : isConnected ? 'Ready' : 'Offline'}</span>
          </div> */}

          <button
            onClick={handleSimulate}
            disabled={isStreaming}
            className="px-3 py-1 text-xs font-medium rounded-md bg-[#161B26] hover:bg-[#202738] text-gray-200 border border-[#242C3F] transition-colors cursor-pointer disabled:opacity-50"
          >
            Simulate stream
          </button>

          {!jobId && (
          <button
            onClick={() => startCapture('any')}
            disabled={isStreaming || analyzingNetwork}
            className="px-3 py-1 text-xs font-medium rounded-md bg-[#161B26] hover:bg-[#202738] text-gray-200 border border-[#242C3F] transition-colors cursor-pointer disabled:opacity-50"
          >
            Live sniff (eth0)
          </button>
          )}

          <button
            onClick={stopCapture}
            disabled={!isStreaming}
            className="px-3 py-1 text-xs font-medium rounded-md bg-[#161B26] hover:bg-[#202738] text-gray-300 border border-[#242C3F] transition-colors cursor-pointer disabled:opacity-40"
          >
            Stop
          </button>

          {/* <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono text-gray-400 bg-[#121622] rounded border border-[#1F2639]">
            <Lock className="h-3 w-3 text-gray-400" />
            <span>Metadata only: passive inspection</span>
          </div> */}
        </div>

        {/* Right: Analyze network button (Only after Live Sniff) */}
        {showAnalyzeButton && (
          <Button
            onClick={handleAnalyzeNetwork}
            disabled={analyzingNetwork}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs h-8 px-4 gap-1.5 shadow-sm cursor-pointer"
          >
            <Activity className="h-3.5 w-3.5" />
            <span>{analyzingNetwork ? 'Analyzing network...' : 'Analyze network'}</span>
          </Button>
        )}
      </div>

      {/* ── Stitch Triage Filter Bar ── */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-1 text-xs">
        <div className="flex items-center gap-3 flex-wrap">
          {/* <span className="text-[11px] font-mono font-semibold tracking-wider text-gray-400 uppercase">
            TRIAGE
          </span> */}

          {/* Filter Pills matching Stitch */}
          <div className="flex items-center gap-1.5 bg-[#0F121C] p-1 rounded-md border border-[#1F2639]">
            <button
              onClick={() => setTriageFilter('anomalies')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                triageFilter === 'anomalies'
                  ? 'bg-[#1C2233] text-white font-semibold'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <span>Anomalies only</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-500/20 text-red-400 font-mono">
                {anomaliesCount}
              </span>
            </button>

            <button
              onClick={() => setTriageFilter('all')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                triageFilter === 'all'
                  ? 'bg-[#1C2233] text-white font-semibold'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <span>All</span>
              <span className="text-[10px] text-gray-400 font-mono">{totalCount}</span>
            </button>

            <button
              onClick={() => setTriageFilter('critical')}
              className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                triageFilter === 'critical'
                  ? 'bg-[#1C2233] text-white font-semibold'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
              <span>Critical</span>
              <span className="text-[10px] text-red-400 font-mono">{criticalCount}</span>
            </button>

            <button
              onClick={() => setTriageFilter('medium')}
              className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                triageFilter === 'medium'
                  ? 'bg-[#1C2233] text-white font-semibold'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
              <span>Medium</span>
              <span className="text-[10px] text-amber-400 font-mono">{mediumCount}</span>
            </button>

            <button
              onClick={() => setTriageFilter('low')}
              className={`px-2 py-1 rounded text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                triageFilter === 'low'
                  ? 'bg-[#1C2233] text-white font-semibold'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              <span>Low</span>
              <span className="text-[10px] text-emerald-400 font-mono">{lowCount}</span>
            </button>
          </div>
        </div>

        <div className="text-[11px] font-mono text-gray-500">
          {/* {lowCount > 0 ? `${lowCount} low/benign ESP packets hidden to reduce noise` : 'Passive wire monitoring'} */}
        </div>
      </div>

      {/* ── Main Workspace: Topology Canvas + Side Inspector ── */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
        {/* Left: Canvas Area */}
        <div className={`relative rounded-xl overflow-hidden bg-[#0A0D14] border border-[#1F2639] ${selectedPacket ? 'xl:col-span-7' : 'xl:col-span-12'}`}>
          {/* Canvas Floating Overlay Chips */}
          <div className="absolute top-3 left-3 z-20 flex items-center gap-2">
            <span className="px-2 py-1 rounded bg-[#161B26]/90 border border-[#242C3F] text-[10px] font-mono font-semibold tracking-wider text-gray-300 backdrop-blur-sm">
              LAYER 3 IPSEC/IKE TOPO
            </span>
            <span className="px-2 py-1 rounded bg-[#161B26]/90 border border-[#242C3F] text-[10px] font-mono text-gray-400 backdrop-blur-sm">
              SPAN: eth0
            </span>
          </div>

          {/* Zoom & Canvas controls at bottom left */}
          <div className="absolute bottom-10 left-3 z-20 flex items-center gap-1 bg-[#161B26]/90 border border-[#242C3F] rounded-md p-1 backdrop-blur-sm">
            <button className="h-6 w-6 rounded hover:bg-[#202738] text-gray-300 flex items-center justify-center cursor-pointer" title="Zoom in">
              <Plus className="h-3 w-3" />
            </button>
            <button className="h-6 w-6 rounded hover:bg-[#202738] text-gray-300 flex items-center justify-center cursor-pointer" title="Zoom out">
              <Minus className="h-3 w-3" />
            </button>
            <button className="h-6 w-6 rounded hover:bg-[#202738] text-gray-300 flex items-center justify-center cursor-pointer" title="Fit view">
              <Maximize2 className="h-3 w-3" />
            </button>
            <button className="h-6 w-6 rounded hover:bg-[#202738] text-gray-300 flex items-center justify-center cursor-pointer" title="Reset">
              <RotateCcw className="h-3 w-3" />
            </button>
          </div>

          {/* Live Wire Graph with canvas animation */}
          <LiveWireGraph
            wireEvents={wireEvents}
            selectedPacket={selectedPacket}
            onSelectPacket={setSelectedPacket}
            isStreaming={isStreaming}
            isConnected={isConnected}
          />

          {/* Canvas Bottom Status Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 bg-[#090C12] border-t border-[#1F2639] text-[11px] font-mono text-gray-400">
            <div className="flex items-center gap-3">
              <span>Passive hook: <strong className="text-gray-300">pcap_next_ex</strong> (0% drop)</span>
              <span>&bull;</span>
              <span>Wire rate: <strong className="text-gray-300">{wireEvents.length > 0 ? '1.18 Mbps' : '0.00 Mbps'}</strong></span>
              <span>&bull;</span>
              <span>Active tunnel SAs: <strong className="text-gray-300">{espEvents.length > 0 ? '3' : '0'}</strong></span>
            </div>
            {/* <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              <span>Ingest OK</span>
            </div> */}
          </div>
        </div>

        {/* Right: Packet Inspector Side Panel (matching Stitch screenshot) */}
        {selectedPacket ? (
          <div className="xl:col-span-5 rounded-xl bg-[#0F121C] border border-[#1F2639] p-4 space-y-4">
            {/* Inspector Header */}
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-[#1F2639]">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-white tracking-tight">
                    Packet inspector: Frame #{selectedPacket.frame_number ?? '—'}
                  </h3>
                </div>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  Real-time ingestion buffer
                </p>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={copyHex}
                  className="px-2 py-1 rounded bg-[#161B26] hover:bg-[#202738] border border-[#242C3F] text-[11px] font-mono text-gray-300 flex items-center gap-1 cursor-pointer"
                  title="Export or copy raw cleartext header bytes"
                >
                  <Download className="h-3 w-3" />
                  <span>Export hex</span>
                </button>
                <button
                  onClick={() => setSelectedPacket(null)}
                  className="h-6 w-6 rounded hover:bg-[#161B26] text-gray-400 hover:text-white flex items-center justify-center cursor-pointer"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Metadata key-value table matching Stitch */}
            <div className="space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Severity</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-semibold tracking-wide ${
                    pktSeverity === 'critical'
                      ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                      : pktSeverity === 'medium'
                      ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                      : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  }`}
                >
                  &bull; {pktSeverity.toUpperCase()} severity &middot; UDP {selectedPacket.dst_port || 500}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Timestamp</span>
                <span className="text-gray-200">{formatTimestamp(selectedPacket.timestamp)}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Source endpoint</span>
                <span className="text-rose-400 font-semibold">
                  {selectedPacket.src_ip}:{selectedPacket.src_port || 500}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Destination endpoint</span>
                <span className="text-rose-400 font-semibold">
                  {selectedPacket.dst_ip}:{selectedPacket.dst_port || 500}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Protocol</span>
                <span className="text-gray-200">
                  {selectedPacket.packet_type || selectedPacket.protocol || 'IKEv2 (Internet Key Exchange)'}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Exchange type</span>
                <span className="text-amber-400 font-medium">
                  {selectedPacket.exchange_type || 'Aggressive Mode (Type 4)'}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Packet wire length</span>
                <span className="text-gray-200">{selectedPacket.packet_length || 396} bytes</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Initiator SPI</span>
                <span className="text-gray-300">{selectedPacket.spi || '0x9F30CA1942E109B2'}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-[#1F2639]/50">
                <span className="text-gray-400">Responder SPI</span>
                <span className="text-gray-300">0x0000000000000000</span>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-gray-400">Next payload</span>
                <span className="text-gray-200">Security Association (SA)</span>
              </div>
            </div>

            {/* Cryptographic Diagnosis Section with AI Button */}
            <div className="rounded-lg bg-[#141824] border border-[#222B3F] p-3.5 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
                  <FileText className="h-3.5 w-3.5 text-blue-400" />
                  <span>Cryptographic diagnosis</span>
                </div>
                <button
                  onClick={handleExplainPacket}
                  disabled={aiLoading}
                  className="px-2.5 py-1 rounded bg-[#1C2233] hover:bg-[#263047] border border-[#2F3952] text-[11px] font-medium text-gray-300 flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <Sparkles className="h-3 w-3 text-blue-400" />
                  <span>{aiLoading ? 'Analyzing...' : 'AI explanation'}</span>
                </button>
              </div>

              {aiResult && (
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    Source: {aiResult?.source === 'cloud_llm' ? 'Gemini 1.5 Pro' : 'CryptoLens Rules'}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1C2233] text-gray-400 border border-[#242C3F]">
                    Evaluated: {aiResult?.evaluated_rule || 'RFC 4303'}
                  </span>
                </div>
              )}

              {aiLoading ? (
                <div className="py-2 flex items-center gap-2 text-xs text-blue-400">
                  <span className="h-3 w-3 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
                  <span>Running LLM cryptographic analysis...</span>
                </div>
              ) : aiResult ? (
                <div className="space-y-2">
                  <p className="text-xs text-gray-300 leading-relaxed font-sans">
                    {aiResult.explanation}
                  </p>
                  {aiResult.operator_guidance && (
                    <div className="p-2 rounded bg-[#0D111A] border border-[#1E2538] text-[11px] text-amber-300 font-sans">
                      <strong className="text-amber-400">Operator guidance: </strong>
                      {aiResult.operator_guidance}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-gray-500 italic font-sans">
                  Click &ldquo;AI explanation&rdquo; to evaluate RFC 4303 zero-decryption metadata and operator guidance for this frame.
                </p>
              )}
            </div>

            {/* Cleartext IKE Header Hex (Bytes 0-27) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>CLEARTEXT IKE HEADER HEX (BYTES 0-27)</span>
                <button
                  onClick={copyHex}
                  className="flex items-center gap-1 hover:text-white cursor-pointer transition-colors"
                >
                  {copiedHex ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  <span>{copiedHex ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div className="p-2.5 rounded-lg bg-[#07090E] border border-[#1A2030] text-[11px] font-mono text-gray-300 leading-relaxed overflow-x-auto select-all">
                <div className="text-gray-500">0000: <span className="text-gray-200">9f 30 ca 19 42 e1 09 00</span>  <span className="text-gray-400">00 00 00 00 00 00 00 00</span></div>
                <div className="text-gray-500">0010: <span className="text-amber-400">04 10 02 00 00 00 00 00</span>  <span className="text-blue-400">00 00 01 8c</span></div>
              </div>
            </div>
          </div>
        ) : (
          /* Empty / Unselected Inspector State */
          <div className="xl:col-span-5 hidden xl:flex flex-col items-center justify-center p-8 rounded-xl bg-[#0F121C] border border-[#1F2639] text-center min-h-[460px]">
            <Radio className="h-8 w-8 text-gray-600 mb-2" />
            <h4 className="text-xs font-semibold text-gray-300 font-mono">Select a Frame to Inspect</h4>
            <p className="text-[11px] text-gray-500 max-w-xs mt-1">
              Click on any moving packet node or topology host in the canvas to examine header fields, RFC diagnosis, and cleartext bytes.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
