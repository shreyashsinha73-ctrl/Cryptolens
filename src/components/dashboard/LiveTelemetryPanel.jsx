import React, { useState, useEffect, useRef } from 'react';
import Card from '../common/Card.jsx';
import { useLiveTelemetry } from '../../hooks/useLiveTelemetry';

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

export default function LiveTelemetryPanel({ jobId = null, isRealData = false }) {
  const {
    isConnected,
    isStreaming,
    streamCompleted,
    completionMessage,
    wireEvents,
    espEvents,
    ikeEvents,
    rollingScore,
    anomalyAlerts,
    startCapture,
    simulateCapture,
    stopCapture,
    clearWire,
  } = useLiveTelemetry();

  const [wireFilter, setWireFilter] = useState('all');
  const [sortOrder, setSortOrder] = useState('desc'); // 'desc' (newest first) or 'asc' (oldest first)
  const [selectedPacket, setSelectedPacket] = useState(null);
  const scrollRef = useRef(null);

  // Reset stream counter, wire events, and inspection state whenever a new PCAP is ingested or uploaded
  useEffect(() => {
    clearWire();
    setSelectedPacket(null);
  }, [jobId, clearWire]);

  const handleSimulate = () => {
    clearWire();
    setSelectedPacket(null);
    if (jobId) {
      simulateCapture(jobId);
    } else {
      simulateCapture();
    }
  };

  const scrollToTop = () => {
    if (scrollRef.current) scrollRef.current.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const scrollToBottom = () => {
    if (scrollRef.current) scrollRef.current.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  };

  const filteredWire = wireEvents.filter((pkt) => {
    if (wireFilter === 'esp') return pkt.protocol === 'ESP' || pkt.packet_type?.includes('ESP');
    if (wireFilter === 'ike') return pkt.protocol === 'IKE' || pkt.packet_type?.includes('IKE');
    if (wireFilter === 'anomaly') return pkt.severity === 'CRITICAL' || pkt.severity === 'WARNING' || pkt.severity === 'MEDIUM' || pkt.is_replay;
    return true;
  });

  const displayedWire = sortOrder === 'desc' ? [...filteredWire].reverse() : filteredWire;

  return (
    <Card
      title="Live Stream Ingestion & Telemetry"
      subtitle="Real-time multi-protocol wire sniffing, authentic packet injection & rolling AI inference"
      padding="p-6"
      className="space-y-5"
    >
      {/* Stream Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-gray-50 dark:bg-[#1A222F] border border-gray-100 dark:border-[#2C384B]">
        <div className="flex items-center gap-3">
          <span className="relative flex h-3.5 w-3.5">
            {isStreaming && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            )}
            <span
              className={`relative inline-flex rounded-full h-3.5 w-3.5 ${
                isStreaming ? 'bg-emerald-500' : isConnected ? 'bg-amber-400' : 'bg-red-500'
              }`}
            ></span>
          </span>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-gray-800 dark:text-gray-200 flex items-center gap-2">
              <span>{isStreaming ? 'Live Stream Active' : isConnected ? 'WebSocket Connected' : 'Disconnected'}</span>
              {isStreaming && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  STREAMING
                </span>
              )}
              {streamCompleted && !isStreaming && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                  PCAP COMPLETED
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
              {isStreaming
                ? `${wireEvents.length} frames ingested (${espEvents.length} ESP | ${ikeEvents.length} IKE)`
                : streamCompleted
                ? completionMessage || `All ${wireEvents.length} packets streamed successfully.`
                : jobId
                ? `Uploaded PCAP ready for replay: ${jobId}`
                : 'Live sniffer ready'}
            </div>
          </div>
        </div>

        {/* Action Controls - NO DROPDOWN MENU */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Simulate Stream appears ONLY when a PCAP is uploaded/ingested (jobId is present) */}
          {(jobId || isRealData) && (
            <button
              onClick={handleSimulate}
              disabled={isStreaming}
              className="text-xs px-3.5 py-2 font-bold rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white transition shadow-xs flex items-center gap-1.5 cursor-pointer"
              title={`Simulate uploaded PCAP: ${jobId}`}
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Simulate Stream
            </button>
          )}

          {/* Live Sniff (Always available) */}
          <button
            onClick={() => startCapture('any')}
            disabled={isStreaming}
            className="text-xs px-3.5 py-2 font-bold rounded-lg bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white transition shadow-xs flex items-center gap-1.5 cursor-pointer"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Live Sniff
          </button>

          {isStreaming && (
            <button
              onClick={stopCapture}
              className="text-xs px-3.5 py-2 font-bold rounded-lg bg-red-600 hover:bg-red-700 text-white transition shadow-xs flex items-center gap-1.5 cursor-pointer"
            >
              Stop
            </button>
          )}

          {wireEvents.length > 0 && !isStreaming && (
            <button
              onClick={clearWire}
              className="text-xs px-2.5 py-2 font-medium text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Stream Completion Banner */}
      {streamCompleted && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300 px-4 py-3 rounded-xl text-xs font-semibold flex items-center justify-between">
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            ✓ {completionMessage || `PCAP Stream finished: all ${wireEvents.length} frames streamed.`}
          </span>
          <span className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400">Natural End of File</span>
        </div>
      )}

      {/* Rolling Metrics */}
      {rollingScore && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <MetricTile
            label="Mode Prediction"
            value={rollingScore.ai_mode}
            sub={`Agreement: ${rollingScore.mode_agreement ? 'MATCH' : 'DISAGREE'}`}
          />
          <MetricTile
            label="Inner Traffic"
            value={rollingScore.ai_traffic}
            sub={`Confidence: ${Math.round((rollingScore.confidence || 0) * 100)}%`}
          />
          <MetricTile
            label="Throughput"
            value={`${rollingScore.esp_count || 0} pkts`}
            sub={`${rollingScore.ike_count || 0} IKE handshakes`}
          />
          <MetricTile
            label="Rolling Score"
            value={rollingScore.security_score !== undefined ? `${rollingScore.security_score}/100` : '...'}
            sub={
              <span
                className={`font-black uppercase tracking-wider ${
                  rollingScore.risk_level === 'LOW'
                    ? 'text-emerald-500'
                    : rollingScore.risk_level === 'CRITICAL'
                    ? 'text-red-500'
                    : 'text-amber-500'
                }`}
              >
                {rollingScore.risk_level || 'ANALYZING'}
              </span>
            }
          />
          <MetricTile
            label="Replay Guard"
            value={rollingScore.risk_level === 'CRITICAL' ? 'VIOLATION' : 'Active Window'}
            sub={
              rollingScore.risk_level === 'CRITICAL' ? (
                <span className="text-red-500 font-bold">Duplicate Seq Detected</span>
              ) : (
                <span className="text-emerald-500">Strictly Monotonic</span>
              )
            }
          />
        </div>
      )}

      {/* Selected Packet Metadata Modal / Inspector */}
      {selectedPacket && (
        <div className="rounded-xl border border-blue-500/40 bg-blue-500/5 dark:bg-blue-500/10 p-4 transition-all">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-blue-500/20">
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400">
                Frame #{selectedPacket.frame_number} Metadata Inspector
              </span>
              <span
                className={`text-[10px] font-black uppercase tracking-wider px-2 py-0.5 rounded ${
                  selectedPacket.severity === 'CRITICAL' || selectedPacket.is_replay
                    ? 'bg-red-500 text-white'
                    : selectedPacket.severity === 'WARNING' || selectedPacket.severity === 'MEDIUM'
                    ? 'bg-amber-500 text-gray-950 font-bold'
                    : 'bg-emerald-500 text-white'
                }`}
              >
                {selectedPacket.severity === 'CRITICAL' || selectedPacket.is_replay
                  ? 'CRITICAL THREAT'
                  : selectedPacket.severity === 'WARNING' || selectedPacket.severity === 'MEDIUM'
                  ? 'MEDIUM RISK'
                  : 'LOW RISK / SECURE'}
              </span>
            </div>
            <button
              onClick={() => setSelectedPacket(null)}
              className="text-xs font-bold text-gray-500 hover:text-gray-800 dark:hover:text-gray-200 cursor-pointer"
            >
              ✕ Close
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2.5 text-xs font-mono">
            {/* Packet Type */}
            <div className="bg-white dark:bg-[#1E2530] p-2.5 rounded-lg border border-gray-200 dark:border-[#2C384B] col-span-1">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Packet Type</span>
              <span className="font-bold text-purple-600 dark:text-purple-400 block text-[11px] leading-tight">
                {selectedPacket.packet_type}
              </span>
            </div>

            {/* Wire Flow - 2 columns so no truncation occurs */}
            <div className="bg-white dark:bg-[#1E2530] p-2.5 rounded-lg border border-gray-200 dark:border-[#2C384B] col-span-2 sm:col-span-2 lg:col-span-2">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Wire Flow</span>
              <span className="font-semibold text-gray-800 dark:text-gray-200 block text-[11px] font-mono leading-tight whitespace-nowrap overflow-x-auto">
                {selectedPacket.src_ip}{selectedPacket.src_port ? `:${selectedPacket.src_port}` : ''}
                {' '}&rarr;{' '}
                {selectedPacket.dst_ip}{selectedPacket.dst_port ? `:${selectedPacket.dst_port}` : ''}
              </span>
            </div>

            {/* SPI (Hex) */}
            <div className="bg-white dark:bg-[#1E2530] p-2.5 rounded-lg border border-gray-200 dark:border-[#2C384B] col-span-1">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">SPI (Hex)</span>
              <span className="font-bold text-amber-600 dark:text-amber-400 block text-[11px] font-mono whitespace-nowrap">
                {selectedPacket.spi || '—'}
              </span>
            </div>

            {/* Sequence # */}
            <div className="bg-white dark:bg-[#1E2530] p-2.5 rounded-lg border border-gray-200 dark:border-[#2C384B] col-span-1">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Sequence #</span>
              <span className={`font-bold block text-[11px] ${selectedPacket.is_replay ? 'text-red-500 underline font-black' : 'text-gray-800 dark:text-gray-200'}`}>
                {selectedPacket.seq_num !== null && selectedPacket.seq_num !== undefined ? selectedPacket.seq_num : '—'}
                {selectedPacket.is_replay && ' [REPLAY]'}
              </span>
            </div>

            {/* Wire Length */}
            <div className="bg-white dark:bg-[#1E2530] p-2.5 rounded-lg border border-gray-200 dark:border-[#2C384B] col-span-1">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Wire Length</span>
              <span className="font-bold text-emerald-600 dark:text-emerald-400 block text-[11px] whitespace-nowrap">
                {selectedPacket.packet_length} Bytes
              </span>
            </div>

            {/* Timestamp */}
            <div className="bg-white dark:bg-[#1E2530] p-2.5 rounded-lg border border-gray-200 dark:border-[#2C384B] col-span-1">
              <span className="text-[10px] uppercase font-bold text-gray-400 block mb-1">Timestamp</span>
              <span className="font-semibold text-gray-700 dark:text-gray-300 block text-[11px] whitespace-nowrap" title={`Epoch: ${selectedPacket.timestamp}`}>
                {formatTimestamp(selectedPacket.timestamp)}
              </span>
              <span className="text-[9px] text-gray-400 block truncate font-mono">
                {selectedPacket.timestamp ? Number(selectedPacket.timestamp).toFixed(1) : ''}
              </span>
            </div>
          </div>

          <div className="mt-3 p-3 rounded-lg bg-white dark:bg-[#1E2530] text-[11px] font-mono text-gray-800 dark:text-gray-200 border border-gray-200 dark:border-[#2C384B] flex items-start gap-2.5">
            <span className="font-bold text-blue-600 dark:text-blue-400 shrink-0 uppercase tracking-wider text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20">Analysis</span>
            <span className="leading-relaxed">{selectedPacket.details || 'Standard wire frame verified.'}</span>
          </div>
        </div>
      )}

      {/* Multi-Protocol Live Wire Ingest Feed */}
      <div className="rounded-xl bg-gray-950 text-gray-200 p-4 border border-gray-800">
        <div className="flex flex-wrap items-center justify-between pb-3 mb-2 border-b border-gray-800 gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-gray-300 uppercase tracking-wider font-bold">
              Multi-Protocol Live Wire Feed
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">
              {displayedWire.length} / {wireEvents.length} frames visible
            </span>
            <span className="text-[10px] text-gray-500 hidden lg:inline">
              (Click any packet to inspect full metadata)
            </span>
          </div>

          {/* Filter Pills, Order Toggle & Jump Buttons */}
          <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
            {/* Filter Pills */}
            <div className="flex items-center gap-1 bg-gray-900 p-0.5 rounded-lg border border-gray-800">
              <button
                onClick={() => setWireFilter('all')}
                className={`px-2 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                  wireFilter === 'all'
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                All ({wireEvents.length})
              </button>
              <button
                onClick={() => setWireFilter('esp')}
                className={`px-2 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                  wireFilter === 'esp'
                    ? 'bg-emerald-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                ESP ({espEvents.length})
              </button>
              <button
                onClick={() => setWireFilter('ike')}
                className={`px-2 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                  wireFilter === 'ike'
                    ? 'bg-purple-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                IKE ({ikeEvents.length})
              </button>
              <button
                onClick={() => setWireFilter('anomaly')}
                className={`px-2 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                  wireFilter === 'anomaly'
                    ? 'bg-rose-600 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Anomalies ({wireEvents.filter(p => p.severity === 'CRITICAL' || p.severity === 'WARNING' || p.severity === 'MEDIUM' || p.is_replay).length})
              </button>
            </div>

            {/* Sort Order Toggle */}
            <button
              onClick={() => setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'))}
              className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-gray-900 border border-gray-800 text-gray-300 hover:text-white hover:border-gray-700 transition cursor-pointer flex items-center gap-1"
              title="Toggle packet ordering"
            >
              <span>{sortOrder === 'desc' ? '▼ Newest First' : '▲ Frame #1 First'}</span>
            </button>

            {/* Scroll Navigation Buttons */}
            {displayedWire.length > 10 && (
              <div className="flex items-center gap-1">
                <button
                  onClick={scrollToTop}
                  className="px-2 py-1 rounded-md text-[10px] font-bold bg-gray-900 border border-gray-800 text-gray-400 hover:text-white transition cursor-pointer"
                  title="Scroll to top"
                >
                  ↑ Top
                </button>
                <button
                  onClick={scrollToBottom}
                  className="px-2 py-1 rounded-md text-[10px] font-bold bg-gray-900 border border-gray-800 text-gray-400 hover:text-white transition cursor-pointer"
                  title="Scroll to bottom"
                >
                  ↓ Bottom
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Color-Coded Wire Packets Table (Red=Critical, Orange=Medium, Green=Secure/Low) */}
        <div
          ref={scrollRef}
          className="font-mono text-xs space-y-1.5 min-h-[380px] max-h-[600px] overflow-y-auto pr-1 scroll-smooth"
        >
          {displayedWire.length === 0 ? (
            <div className="text-gray-500 italic py-16 text-center">
              No wire traffic captured. Click &quot;Simulate Stream&quot; or &quot;Live Sniff&quot; to begin.
            </div>
          ) : (
            displayedWire.map((pkt, idx) => {
              const isCrit = pkt.severity === 'CRITICAL' || pkt.is_replay;
              const isWarn = pkt.severity === 'WARNING' || pkt.severity === 'MEDIUM';
              const isLow = !isCrit && !isWarn;
              const isSelected = selectedPacket?.frame_number === pkt.frame_number;

              return (
                <div
                  key={pkt.frame_number !== undefined ? `${pkt.frame_number}-${idx}` : idx}
                  onClick={() => setSelectedPacket(pkt)}
                  className={`flex items-center justify-between py-1.5 px-3 rounded-lg transition cursor-pointer ${
                    isSelected
                      ? 'ring-2 ring-blue-500'
                      : ''
                  } ${
                    isCrit
                      ? 'bg-red-500/15 border border-red-500/40 text-red-300 hover:bg-red-500/25'
                      : isWarn
                      ? 'bg-amber-500/15 border border-amber-500/40 text-amber-300 hover:bg-amber-500/25'
                      : 'bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 hover:bg-emerald-500/20'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-gray-400 text-[11px] font-bold w-10 shrink-0 font-mono">
                      #{pkt.frame_number !== undefined ? pkt.frame_number : idx + 1}
                    </span>

                    {/* Status / Severity Tag */}
                    <span
                      className={`text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded shrink-0 ${
                        isCrit
                          ? 'bg-red-500 text-white'
                          : isWarn
                          ? 'bg-amber-500 text-gray-950 font-extrabold'
                          : 'bg-emerald-500/30 text-emerald-300'
                      }`}
                    >
                      {isCrit ? 'CRITICAL' : isWarn ? 'MEDIUM' : 'SECURE'}
                    </span>

                    {/* Type Badge */}
                    <span className="text-[10px] font-bold uppercase tracking-wider text-gray-300 shrink-0">
                      {pkt.packet_type || pkt.protocol || 'ESP'}
                    </span>

                    {/* Source -> Destination */}
                    <span className="text-gray-200 font-medium truncate">
                      {pkt.src_ip}
                      {pkt.src_port ? `:${pkt.src_port}` : ''} &rarr; {pkt.dst_ip}
                      {pkt.dst_port ? `:${pkt.dst_port}` : ''}
                    </span>

                    {/* SPI */}
                    {pkt.spi && pkt.spi !== '—' && (
                      <span className="text-purple-400 text-[11px] shrink-0">
                        SPI:{pkt.spi}
                      </span>
                    )}

                    {/* Sequence # */}
                    {pkt.seq_num !== null && pkt.seq_num !== undefined && (
                      <span
                        className={`text-[11px] shrink-0 font-bold ${
                          pkt.is_replay ? 'text-red-400 underline animate-pulse' : 'text-gray-400'
                        }`}
                      >
                        Seq:{pkt.seq_num}
                        {pkt.is_replay && ' [REPLAY]'}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-amber-400 font-semibold">{pkt.packet_length}B</span>
                    <span className="text-[10px] text-gray-500 hover:text-gray-300">&rarr;</span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </Card>
  );
}

function MetricTile({ label, value, sub }) {
  return (
    <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#1E2530] border border-gray-100 dark:border-[#2C384B]">
      <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400">
        {label}
      </div>
      <div className="text-sm font-extrabold text-gray-900 dark:text-white capitalize mt-0.5">
        {value}
      </div>
      <div className="text-[10px] text-gray-500 dark:text-gray-400 mt-0.5">{sub}</div>
    </div>
  );
}
