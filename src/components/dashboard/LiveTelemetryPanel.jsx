import React, { useState } from 'react';
import Card from '../common/Card.jsx';
import { useLiveTelemetry } from '../../hooks/useLiveTelemetry';

export default function LiveTelemetryPanel() {
  const {
    isConnected,
    isStreaming,
    espEvents,
    ikeEvents,
    rollingScore,
    anomalyAlerts,
    startCapture,
    simulateCapture,
    stopCapture,
  } = useLiveTelemetry();

  const [simConfig, setSimConfig] = useState('config_01_tunnel_aes256gcm_dh19_pfson');

  return (
    <Card
      title="Live Stream Ingestion & Telemetry"
      subtitle="Real-time ESP/IKE wire sniffing & rolling AI inference"
      padding="p-6"
      className="space-y-5"
    >
      {/* Stream Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-gray-50 dark:bg-[#1A222F] border border-gray-100 dark:border-[#2C384B]">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-3 w-3">
            {isStreaming && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            )}
            <span className={`relative inline-flex rounded-full h-3 w-3 ${
              isStreaming ? 'bg-emerald-500' : isConnected ? 'bg-amber-400' : 'bg-red-500'
            }`}></span>
          </span>
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-gray-800 dark:text-gray-200">
              {isStreaming ? 'Streaming Active' : isConnected ? 'WebSocket Ready' : 'Disconnected'}
            </div>
            <div className="text-[11px] text-gray-400">
              {isStreaming
                ? `${espEvents.length} ESP frames | ${ikeEvents.length} IKE handshakes`
                : 'Select capture mode to begin'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={simConfig}
            onChange={(e) => setSimConfig(e.target.value)}
            disabled={isStreaming}
            className="text-xs px-2.5 py-1.5 rounded-lg border border-gray-200 dark:border-[#38465B] bg-white dark:bg-[#232D3F] text-gray-700 dark:text-gray-200 outline-none"
          >
            <option value="config_01_tunnel_aes256gcm_dh19_pfson">Config 01: Hardened (100/LOW)</option>
            <option value="config_06_tunnel_3des_sha1_dh2_pfsoff">Config 06: Insecure (45/CRITICAL)</option>
            <option value="config_05_transport_3des_sha1_dh2_pfsoff">Config 05: Transport 3DES</option>
          </select>
          <button onClick={() => simulateCapture(simConfig)} disabled={isStreaming}
            className="text-xs px-3.5 py-1.5 font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white transition shadow-sm">
            Simulate Stream
          </button>
          <button onClick={() => startCapture('any')} disabled={isStreaming}
            className="text-xs px-3.5 py-1.5 font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white transition shadow-sm">
            Live Sniff
          </button>
          {isStreaming && (
            <button onClick={stopCapture}
              className="text-xs px-3.5 py-1.5 font-semibold rounded-lg bg-red-600 hover:bg-red-700 text-white transition shadow-sm">
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Rolling Metrics */}
      {rollingScore && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <MetricTile label="Mode Prediction" value={rollingScore.ai_mode}
            sub={`Agreement: ${rollingScore.mode_agreement ? 'MATCH' : 'DISAGREE'}`} />
          <MetricTile label="Inner Traffic" value={rollingScore.ai_traffic}
            sub={`Confidence: ${Math.round((rollingScore.confidence || 0) * 100)}%`} />
          <MetricTile label="ESP Throughput" value={`${rollingScore.esp_count} pkts`}
            sub={`IKE Count: ${rollingScore.ike_count}`} />
          <MetricTile label="Rolling Score"
            value={rollingScore.security_score !== undefined ? `${rollingScore.security_score}/100` : '...'}
            sub={<span className={rollingScore.risk_level === 'LOW' ? 'text-emerald-500' : 'text-red-500'}>
              {rollingScore.risk_level || 'ANALYZING'}</span>} />
          <MetricTile label="Replay Guard" value="Active Window" sub="Sequence monotonic" />
        </div>
      )}

      {/* Anomaly Alerts */}
      {anomalyAlerts.length > 0 && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30">
          <div className="text-xs font-bold uppercase tracking-wider text-red-600 dark:text-red-400 flex items-center gap-1.5 mb-2">
            <span className="inline-block w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
            PyOD Anomaly Alerts ({anomalyAlerts.length})
          </div>
          {anomalyAlerts.slice(-3).reverse().map((a, i) => (
            <div key={i} className="text-xs p-2 rounded-lg bg-red-500/15 text-red-700 dark:text-red-300 font-mono mt-1">
              <span className="font-bold uppercase mr-2">[{a.anomaly_label}]</span>{a.description}
            </div>
          ))}
        </div>
      )}

      {/* ESP Wire Console */}
      <div className="rounded-xl bg-gray-900 text-gray-300 p-4 border border-gray-800">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-gray-800 text-xs">
          <span className="font-mono text-gray-400 uppercase tracking-wider">ESP Wire Ingest</span>
          <span className="text-gray-500 text-[11px]">{espEvents.length} captured</span>
        </div>
        <div className="font-mono text-xs space-y-1 max-h-40 overflow-y-auto">
          {espEvents.length === 0 ? (
            <div className="text-gray-500 italic py-2 text-center">No traffic. Click Simulate or Live Sniff.</div>
          ) : (
            espEvents.slice(-8).reverse().map((pkt, idx) => (
              <div key={idx} className="flex items-center justify-between py-0.5 hover:bg-gray-800/60 px-1 rounded transition">
                <div className="flex items-center gap-2">
                  <span className="text-blue-400 font-semibold">#{pkt.frame_number || idx + 1}</span>
                  <span className="text-gray-400">{pkt.src_ip} &rarr; {pkt.dst_ip}</span>
                  <span className="text-purple-400 text-[11px]">SPI:{pkt.spi || '—'}</span>
                </div>
                <span className="text-amber-400">{pkt.packet_length}B</span>
              </div>
            ))
          )}
        </div>
      </div>
    </Card>
  );
}

function MetricTile({ label, value, sub }) {
  return (
    <div className="p-3 rounded-lg bg-gray-50 dark:bg-[#1E2530] border border-gray-100 dark:border-[#2C384B]">
      <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400">{label}</div>
      <div className="text-sm font-bold text-gray-800 dark:text-white capitalize mt-0.5">{value}</div>
      <div className="text-[10px] text-gray-400 mt-0.5">{sub}</div>
    </div>
  );
}

