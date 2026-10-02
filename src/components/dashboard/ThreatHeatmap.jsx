import React, { useState, useEffect } from 'react';
import Card from '../common/Card.jsx';

export default function ThreatHeatmap({ jobId }) {
  const [xaiData, setXaiData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [method, setMethod] = useState('grad_cam');
  const [targetHead, setTargetHead] = useState('mode');
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    setLoading(true);
    setError(null);
    fetch(`/api/v1/xai/${jobId}?method=${method}&target_head=${targetHead}`)
      .then((r) => { if (!r.ok) throw new Error('XAI not available'); return r.json(); })
      .then((d) => { if (alive) { setXaiData(d.xai); setLoading(false); } })
      .catch((e) => { if (alive) { setError(e.message); setLoading(false); } });
    return () => { alive = false; };
  }, [jobId, method, targetHead]);

  if (!jobId) return null;

  const totalFrames = xaiData?.xai_heatmap?.length || xaiData?.sequence_length || 0;
  const midFrame = Math.round(totalFrames / 2);

  return (
    <Card
      title="Explainable AI (XAI) Threat Localizer"
      subtitle="Grad-CAM 1D neural activation & per-packet risk attribution"
      padding="p-6"
      className="space-y-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
          <span>Model:</span>
          <span className="font-semibold text-gray-700 dark:text-gray-200">1D-CNN (DataPlaneCNN)</span>
          {xaiData?.predicted_class && (
            <span className="ml-1 px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 font-mono text-[11px] font-bold">
              Class: {xaiData.predicted_class.toUpperCase()}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Target Head Selector */}
          <div className="flex bg-gray-100 dark:bg-[#1E2530] p-0.5 rounded-lg border border-gray-200/50 dark:border-gray-800">
            <button
              onClick={() => setTargetHead('mode')}
              className={`text-[11px] px-2.5 py-1 rounded-md font-medium transition ${
                targetHead === 'mode'
                  ? 'bg-white dark:bg-[#2A3444] text-blue-600 dark:text-blue-400 shadow-sm'
                  : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
              }`}
            >
              Mode Head (Tunnel/Transport)
            </button>
            <button
              onClick={() => setTargetHead('traffic')}
              className={`text-[11px] px-2.5 py-1 rounded-md font-medium transition ${
                targetHead === 'traffic'
                  ? 'bg-white dark:bg-[#2A3444] text-blue-600 dark:text-blue-400 shadow-sm'
                  : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
              }`}
            >
              Traffic Head (HTTPS/VoIP/ICMP)
            </button>
          </div>

          {/* XAI Attribution Method */}
          <div className="flex bg-gray-100 dark:bg-[#1E2530] p-0.5 rounded-lg border border-gray-200/50 dark:border-gray-800">
            {['grad_cam', 'integrated_gradients'].map((m) => (
              <button
                key={m}
                onClick={() => setMethod(m)}
                className={`text-[11px] px-2.5 py-1 rounded-md font-medium transition ${
                  method === m
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-gray-500 hover:text-gray-700 dark:text-gray-400'
                }`}
              >
                {m === 'grad_cam' ? 'Grad-CAM 1D' : 'Integrated Gradients'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs text-gray-400">Computing neural gradients across wire sequence...</div>
      ) : error ? (
        <div className="p-3 text-xs text-amber-500 bg-amber-500/10 rounded-lg">{error}</div>
      ) : xaiData ? (
        <div className="space-y-5">
          {xaiData.summary && (
            <div className="text-xs text-gray-600 dark:text-gray-300 bg-gray-50 dark:bg-[#1A222F] p-3 rounded-lg border border-gray-100 dark:border-[#2C384B]">
              <span className="font-bold text-blue-500 mr-1.5">Attribution:</span>
              {xaiData.summary}
            </div>
          )}

          {/* Saliency bar */}
          <div>
            <div className="flex justify-between text-xs mb-2">
              <span className="font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300">
                Sequence Activation ({totalFrames} Frames)
              </span>
              <span className="text-gray-400 text-[11px]">Red = High Attention (Neural Saliency)</span>
            </div>
            <div className="flex gap-1 h-12 items-end p-2 bg-gray-900 rounded-lg overflow-x-auto">
              {xaiData.xai_heatmap?.map((val, idx) => {
                const n = Math.min(1, Math.max(0.05, val));
                return (
                  <div
                    key={idx}
                    className="flex-1 min-w-[6px] rounded-t-sm transition-all hover:scale-110 cursor-pointer"
                    style={{
                      height: `${Math.max(n * 100, 10)}%`,
                      backgroundColor: `rgb(${Math.round(n * 230 + 25)},${Math.round((1 - n) * 180 + 30)},40)`,
                    }}
                    title={`Frame ${idx + 1}: Saliency ${val.toFixed(3)}`}
                  />
                );
              })}
            </div>
            <div className="flex justify-between text-[10px] text-gray-400 mt-1 font-mono">
              <span>Frame 1</span>
              {midFrame > 1 && <span>Frame {midFrame}</span>}
              <span>Frame {totalFrames}</span>
            </div>
          </div>

          {/* Replay alerts */}
          {xaiData.replay_attacks?.length > 0 && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
              <div className="text-xs font-bold text-red-500 uppercase">
                Anti-Replay Violation ({xaiData.replay_attacks.length})
              </div>
              <div className="text-xs text-red-400 mt-1">{xaiData.replay_attacks[0].description}</div>
            </div>
          )}

          {/* Threat packets table */}
          {xaiData.threat_packets?.length > 0 && (
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300 mb-2">
                Top Attributed Packets
              </div>
              <div className="overflow-x-auto rounded-lg border border-gray-100 dark:border-[#2C384B]">
                <table className="w-full text-xs text-left">
                  <thead className="bg-gray-50 dark:bg-[#1E2530] text-gray-500 dark:text-gray-400 font-semibold border-b border-gray-100 dark:border-[#2C384B]">
                    <tr>
                      <th className="py-2 px-3">Rank</th>
                      <th className="py-2 px-3">Frame</th>
                      <th className="py-2 px-3">Protocol / Type</th>
                      <th className="py-2 px-3">Length</th>
                      <th className="py-2 px-3">SPI / Port</th>
                      <th className="py-2 px-3">Saliency</th>
                      <th className="py-2 px-3">Attribution</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-[#2C384B]">
                    {xaiData.threat_packets.slice(0, 10).map((p, i) => {
                      const proto = (p.protocol || 'ESP').toUpperCase();
                      const badgeColor =
                        proto === 'ESP'
                          ? 'bg-blue-500/10 text-blue-500 border-blue-500/20'
                          : proto === 'ICMP'
                          ? 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                          : proto === 'IKE'
                          ? 'bg-cyan-500/10 text-cyan-500 border-cyan-500/20'
                          : proto === 'VOIP'
                          ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                          : 'bg-purple-500/10 text-purple-400 border-purple-500/20';

                      return (
                        <tr key={i} className="hover:bg-gray-50/50 dark:hover:bg-[#1E2530]/50">
                          <td className="py-2 px-3 font-bold">#{p.attribution_rank}</td>
                          <td className="py-2 px-3 font-mono text-blue-500">#{p.frame_number}</td>
                          <td className="py-2 px-3">
                            <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold border ${badgeColor}`}>
                              {p.packet_type || p.protocol || 'ESP'}
                            </span>
                          </td>
                          <td className="py-2 px-3 font-mono">{p.packet_length}B</td>
                          <td className="py-2 px-3 font-mono text-[11px] text-purple-400">
                            {p.spi ? p.spi.slice(0, 12) : '—'}
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={`font-mono font-bold ${
                                p.saliency_score > 0.6
                                  ? 'text-red-500'
                                  : p.saliency_score > 0.3
                                  ? 'text-amber-500'
                                  : 'text-gray-400'
                              }`}
                            >
                              {p.saliency_score.toFixed(3)}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-gray-600 dark:text-gray-300">
                            {p.threat_description}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </Card>
  );
}

