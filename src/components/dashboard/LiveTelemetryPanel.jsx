import React, { useState } from 'react';
import Card from '../common/Card.jsx';
import { useLiveTelemetry } from '../../hooks/useLiveTelemetry';

export default function LiveTelemetryPanel({ jobId = null, isRealData = false }) {
  const {
    isConnected,
    isStreaming,
    wireEvents,
    espEvents,
    ikeEvents,
    rollingScore,
    anomalyAlerts,
    startCapture,
    simulateCapture,
    injectTraffic,
    stopCapture,
    clearWire,
  } = useLiveTelemetry();

  const [simConfig, setSimConfig] = useState(jobId ? 'current_job' : 'config_01_tunnel_aes256gcm_dh19_pfson');
  const [wireFilter, setWireFilter] = useState('all');
  const [expandedAlert, setExpandedAlert] = useState(null);

  const handleSimulate = () => {
    if (simConfig === 'current_job') {
      simulateCapture('config_01_tunnel_aes256gcm_dh19_pfson', jobId);
    } else {
      simulateCapture(simConfig, null);
    }
  };

  const filteredWire = wireEvents.filter((pkt) => {
    if (wireFilter === 'esp') return pkt.protocol === 'ESP' || pkt.packet_type?.includes('ESP');
    if (wireFilter === 'ike') return pkt.protocol === 'IKE' || pkt.packet_type?.includes('IKE');
    return true;
  });

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
                  REAL-TIME
                </span>
              )}
            </div>
            <div className="text-[11px] text-gray-500 dark:text-gray-400 mt-0.5">
              {isStreaming
                ? `${wireEvents.length} total packets (${espEvents.length} ESP | ${ikeEvents.length} IKE)`
                : 'Select simulation or traffic injection to start telemetry'}
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={simConfig}
            onChange={(e) => setSimConfig(e.target.value)}
            disabled={isStreaming}
            className="text-xs px-3 py-2 rounded-lg border border-gray-200 dark:border-[#38465B] bg-white dark:bg-[#232D3F] text-gray-700 dark:text-gray-200 font-medium outline-none focus:ring-1 focus:ring-blue-500"
          >
            {jobId && (
              <option value="current_job">Current PCAP ({jobId})</option>
            )}
            <option value="config_01_tunnel_aes256gcm_dh19_pfson">Config 01: Hardened (AES-256-GCM / DH19)</option>
            <option value="config_06_tunnel_3des_sha1_dh2_pfsoff">Config 06: Vulnerable (3DES / Replay Attack)</option>
            <option value="config_05_transport_3des_sha1_dh2_pfsoff">Config 05: Transport 3DES (Metadata Leak)</option>
          </select>

          {/* Simulate Stream */}
          <button
            onClick={handleSimulate}
            disabled={isStreaming}
            className="text-xs px-3.5 py-2 font-bold rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white transition shadow-xs flex items-center gap-1.5 cursor-pointer"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Simulate Stream
          </button>

          {/* Live Sniff */}
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

          {/* Traffic Injector 1: Hardened */}
          <button
            onClick={() => injectTraffic('hardened')}
            className="text-xs px-3 py-2 font-bold rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white transition shadow-xs flex items-center gap-1.5 cursor-pointer"
            title="Inject authentic NIST/CNSA compliant AES-256-GCM + DH19 traffic"
          >
            <span>🛡️</span>
            <span>Inject Hardened</span>
          </button>

          {/* Traffic Injector 2: Attack/Vulnerable */}
          <button
            onClick={() => injectTraffic('vulnerable')}
            className="text-xs px-3 py-2 font-bold rounded-lg bg-rose-600 hover:bg-rose-700 text-white transition shadow-xs flex items-center gap-1.5 cursor-pointer"
            title="Inject Sweet32 3DES packets and Replay Attack duplicate sequence numbers"
          >
            <span>⚠️</span>
            <span>Inject Attack</span>
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
            value={rollingScore.risk_level === 'CRITICAL' ? 'VIOLATION DETECTED' : 'Active Window'}
            sub={
              rollingScore.risk_level === 'CRITICAL' ? (
                <span className="text-red-500 font-bold">Duplicate Seq # Injected</span>
              ) : (
                <span className="text-emerald-500">Strictly Monotonic</span>
              )
            }
          />
        </div>
      )}

      {/* Anomaly Alerts Section with Full Packet Metadata Localization */}
      {anomalyAlerts.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-xs font-bold uppercase tracking-wider text-red-600 dark:text-red-400 flex items-center gap-2">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
              </span>
              Security &amp; Protocol Anomaly Detections ({anomalyAlerts.length})
            </div>
            <span className="text-[11px] font-mono text-gray-500 dark:text-gray-400">
              PyOD Isolation Forest &amp; Wire Validation
            </span>
          </div>

          <div className="space-y-2.5">
            {anomalyAlerts.slice(-3).reverse().map((a, i) => {
              const culprit = a.culprit_packet;
              const isExpanded = expandedAlert === i;

              return (
                <div
                  key={i}
                  className="rounded-xl border border-red-500/30 bg-red-500/5 dark:bg-red-500/10 p-4 transition-all"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-red-500/20">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[11px] font-black uppercase tracking-wider bg-red-500 text-white shadow-xs">
                        {a.anomaly_label}
                      </span>
                      <span className="text-xs font-semibold text-red-700 dark:text-red-300">
                        {a.description}
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs font-mono font-bold text-red-600 dark:text-red-400">
                        Score: {typeof a.anomaly_score === 'number' ? a.anomaly_score.toFixed(3) : a.anomaly_score}
                      </span>
                      <button
                        onClick={() => setExpandedAlert(isExpanded ? null : i)}
                        className="text-[11px] font-bold text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 underline cursor-pointer"
                      >
                        {isExpanded ? 'Hide Raw Details' : 'Full Packet Metadata'}
                      </button>
                    </div>
                  </div>

                  {/* Culprit Packet Metadata Table */}
                  {culprit && (
                    <div className="mt-3 pt-1">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-gray-500 dark:text-gray-400 mb-2">
                        Triggering Culprit Packet Attribution:
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2 text-xs font-mono">
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">Frame #</span>
                          <span className="font-bold text-blue-600 dark:text-blue-400">#{culprit.frame_number}</span>
                        </div>
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">Type</span>
                          <span className="font-bold text-purple-600 dark:text-purple-400">{culprit.packet_type}</span>
                        </div>
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">Src &rarr; Dst</span>
                          <span className="font-semibold text-gray-700 dark:text-gray-200 truncate block">
                            {culprit.src_ip} &rarr; {culprit.dst_ip}
                          </span>
                        </div>
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">SPI</span>
                          <span className="font-bold text-amber-600 dark:text-amber-400">{culprit.spi || '—'}</span>
                        </div>
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">Seq #</span>
                          <span className={`font-bold ${a.anomaly_label === 'REPLAY_ATTACK' ? 'text-red-500 underline font-black' : 'text-gray-700 dark:text-gray-200'}`}>
                            {culprit.seq_num || '—'} {a.anomaly_label === 'REPLAY_ATTACK' && '⚠ REPLAY'}
                          </span>
                        </div>
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">Length</span>
                          <span className="font-bold text-emerald-600 dark:text-emerald-400">{culprit.packet_length}B</span>
                        </div>
                        <div className="bg-white/80 dark:bg-[#1E2530] p-2 rounded-lg border border-red-500/20 col-span-2 sm:col-span-4 md:col-span-1">
                          <span className="text-[9px] uppercase font-bold text-gray-400 block">Trigger Cause</span>
                          <span className="text-[11px] font-semibold text-red-600 dark:text-red-400 truncate block" title={culprit.anomaly_reason}>
                            {culprit.anomaly_reason || 'Outlier distribution'}
                          </span>
                        </div>
                      </div>

                      {/* Top Feature Contributions */}
                      {a.top_features && Object.keys(a.top_features).length > 0 && (
                        <div className="flex flex-wrap items-center gap-2 mt-2 pt-1">
                          <span className="text-[10px] text-gray-500 dark:text-gray-400 font-bold uppercase">Deviations:</span>
                          {Object.entries(a.top_features).map(([feat, val]) => (
                            <span
                              key={feat}
                              className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-600 dark:text-red-300 border border-red-500/20"
                            >
                              <code>{feat}</code>: <b>{val}</b>
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Raw JSON expander */}
                      {isExpanded && (
                        <pre className="mt-3 p-3 rounded-lg bg-gray-950 text-gray-300 text-[11px] font-mono overflow-x-auto max-h-48 border border-gray-800">
                          {JSON.stringify(culprit, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Multi-Protocol Live Wire Ingest Feed */}
      <div className="rounded-xl bg-gray-950 text-gray-200 p-4 border border-gray-800">
        <div className="flex flex-wrap items-center justify-between pb-3 mb-2 border-b border-gray-800 gap-2">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-gray-300 uppercase tracking-wider font-bold">
              Multi-Protocol Live Wire Stream
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">
              {wireEvents.length} frames ingested
            </span>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <button
              onClick={() => setWireFilter('all')}
              className={`px-2.5 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                wireFilter === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              All ({wireEvents.length})
            </button>
            <button
              onClick={() => setWireFilter('esp')}
              className={`px-2.5 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                wireFilter === 'esp'
                  ? 'bg-emerald-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              ESP ({espEvents.length})
            </button>
            <button
              onClick={() => setWireFilter('ike')}
              className={`px-2.5 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                wireFilter === 'ike'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              IKE ({ikeEvents.length})
            </button>
          </div>
        </div>

        {/* Wire Packets Table */}
        <div className="font-mono text-xs space-y-1.5 max-h-56 overflow-y-auto pr-1">
          {filteredWire.length === 0 ? (
            <div className="text-gray-500 italic py-6 text-center">
              No wire traffic captured. Click &quot;Simulate Stream&quot;, &quot;Live Sniff&quot;, or &quot;Inject Hardened/Attack&quot; to begin.
            </div>
          ) : (
            filteredWire
              .slice(-25)
              .reverse()
              .map((pkt, idx) => {
                const isIke = pkt.protocol === 'IKE' || pkt.packet_type?.includes('IKE');
                const isSweet32 = pkt.is_sweet32 || pkt.packet_type?.includes('3DES');
                const isReplay = pkt.is_replay;

                return (
                  <div
                    key={idx}
                    className={`flex items-center justify-between py-1 px-2.5 rounded transition ${
                      isReplay
                        ? 'bg-red-500/20 border border-red-500/40 text-red-300'
                        : isSweet32
                        ? 'bg-amber-500/10 border border-amber-500/20 text-amber-200'
                        : isIke
                        ? 'bg-purple-500/10 border border-purple-500/20 hover:bg-purple-500/20'
                        : 'bg-gray-900 hover:bg-gray-800/80 border border-gray-800/60'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-gray-500 text-[11px] font-bold w-10 shrink-0">
                        #{pkt.frame_number || idx + 1}
                      </span>

                      {/* Type Badge */}
                      <span
                        className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded shrink-0 ${
                          isReplay
                            ? 'bg-red-500 text-white'
                            : isSweet32
                            ? 'bg-amber-500/30 text-amber-300'
                            : isIke
                            ? 'bg-purple-500/30 text-purple-300'
                            : 'bg-emerald-500/20 text-emerald-400'
                        }`}
                      >
                        {pkt.packet_type || (isIke ? 'IKEv2' : 'ESP')}
                      </span>

                      {/* Source -> Destination */}
                      <span className="text-gray-300 font-medium truncate">
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
                            isReplay ? 'text-red-400 underline animate-pulse' : 'text-gray-400'
                          }`}
                        >
                          Seq:{pkt.seq_num}
                          {isReplay && ' [REPLAY]'}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-amber-400 font-semibold">{pkt.packet_length}B</span>
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
