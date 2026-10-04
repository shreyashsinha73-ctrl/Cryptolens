import React, { useState, useEffect } from 'react';
import Card from '../common/Card.jsx';

export default function ThreatHeatmap({ jobId }) {
  const [xaiData, setXaiData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [method, setMethod] = useState('grad_cam');
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    setLoading(true);
    setError(null);
    fetch(`/api/v1/xai/${jobId}?method=${method}`)
      .then(async (r) => {
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          if (r.status === 404 && err.detail?.includes('No packet data')) {
            throw new Error('No ESP data to explain');
          }
          throw new Error('XAI not available');
        }
        return r.json();
      })
      .then((d) => {
        if (alive) {
          setXaiData(d.xai);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (alive) {
          setError(e.message);
          setLoading(false);
        }
      });
    return () => { alive = false; };
  }, [jobId, method]);

  if (!jobId) return null;

  const isNoEspData =
    error === 'No ESP data to explain' ||
    (xaiData && (xaiData.has_esp === false || xaiData.summary === 'No ESP data to explain' || !xaiData.xai_heatmap?.length));

  return (
    <Card
      title="Traffic Classifier Explanation (XAI)"
      subtitle="Neural gradients explain the 1D-CNN traffic classifier only (operating mode & inner-traffic heuristic), not cryptographic weaknesses"
      padding="p-6"
      className="space-y-5"
    >
      <div className="flex items-center justify-between">
        <div className="text-xs text-gray-500 dark:text-gray-400">
          Model: <span className="font-semibold text-gray-700 dark:text-gray-200">1D-CNN (DataPlaneCNN)</span>
          <span className="ml-2 text-[10px] text-amber-500 font-mono">[Classifier Explainability]</span>
        </div>
        <div className="flex gap-2">
          {['grad_cam', 'integrated_gradients'].map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMethod(m)}
              className={`text-xs px-3 py-1.5 rounded-lg font-medium transition cursor-pointer ${
                method === m
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'bg-gray-100 dark:bg-[#1E2530] text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-[#283241]'
              }`}
            >
              {m === 'grad_cam' ? 'Grad-CAM 1D' : 'Integrated Gradients'}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="py-12 text-center text-xs text-gray-400 flex flex-col items-center justify-center">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-2" />
          <span>Computing neural gradients...</span>
        </div>
      ) : isNoEspData ? (
        <div className="py-10 flex flex-col items-center justify-center text-center px-4 bg-gray-50/50 dark:bg-[#15181E] rounded-xl border border-gray-100 dark:border-[#2A2C34]">
          <div className="w-10 h-10 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-500 mb-2">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h4 className="text-sm font-bold text-gray-800 dark:text-gray-200">No ESP data to explain</h4>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 max-w-md">
            This capture contains no encrypted ESP data frames. Grad-CAM and Integrated Gradients explain the 1D-CNN traffic classifier only (operating mode and inner-traffic heuristics), not cryptographic weaknesses.
          </p>
        </div>
      ) : error ? (
        <div className="p-3 text-xs text-amber-500 bg-amber-500/10 rounded-lg">{error}</div>
      ) : xaiData ? (
        <div className="space-y-5">
          {xaiData.summary && (
            <div className="text-xs text-gray-600 dark:text-gray-300 bg-gray-50 dark:bg-[#1A222F] p-3 rounded-lg border border-gray-100 dark:border-[#2C384B]">
              <span className="font-bold text-blue-500 mr-1.5">Attribution:</span>{xaiData.summary}
            </div>
          )}

          {/* Saliency bar */}
          <div>
            <div className="flex justify-between text-xs mb-2">
              <span className="font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300">
                Sequence Activation ({xaiData.xai_heatmap?.length || 30} Frames)
              </span>
              <span className="text-gray-400 text-[11px]">Red = High Attention</span>
            </div>
            <div className="flex gap-1 h-10 items-end p-2 bg-gray-900 rounded-lg">
              {xaiData.xai_heatmap?.map((val, idx) => {
                const n = Math.min(1, Math.max(0.05, val));
                const wireFrame = xaiData.frame_mapping?.[idx] ?? (idx + 1);
                return (
                  <div
                    key={idx}
                    className="flex-1 rounded-t-sm transition-all hover:scale-110 cursor-pointer"
                    style={{
                      height: `${Math.max(n * 100, 10)}%`,
                      backgroundColor: `rgb(${Math.round(n * 230 + 25)},${Math.round((1 - n) * 180 + 30)},40)`,
                    }}
                    title={`Wire Frame #${wireFrame} (Sequence #${idx + 1}): Relative Saliency ${val.toFixed(3)}`}
                  />
                );
              })}
            </div>
            <div className="flex justify-between text-[10px] text-gray-400 mt-1 font-mono">
              <span>{xaiData.frame_mapping?.[0] ? `Wire #${xaiData.frame_mapping[0]}` : 'Frame 1'}</span>
              <span>{xaiData.frame_mapping?.[Math.floor((xaiData.frame_mapping.length || 30) / 2)] ? `Wire #${xaiData.frame_mapping[Math.floor((xaiData.frame_mapping.length || 30) / 2)]}` : 'Frame 15'}</span>
              <span>{xaiData.frame_mapping?.[xaiData.frame_mapping.length - 1] ? `Wire #${xaiData.frame_mapping[xaiData.frame_mapping.length - 1]}` : `Frame ${xaiData.xai_heatmap?.length || 30}`}</span>
            </div>
          </div>

          {/* Replay alerts */}
          {xaiData.replay_attacks?.length > 0 && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
              <div className="text-xs font-bold text-red-500 uppercase">Anti-Replay Violation ({xaiData.replay_attacks.length})</div>
              <div className="text-xs text-red-400 mt-1">{xaiData.replay_attacks[0].description}</div>
            </div>
          )}

          {/* Threat packets table */}
          {xaiData.threat_packets?.length > 0 && (
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300 mb-2">
                Top Attributed Packets (Traffic Classifier Attribution)
              </div>
              <div className="overflow-x-auto rounded-lg border border-gray-100 dark:border-[#2C384B]">
                <table className="w-full text-xs text-left">
                  <thead className="bg-gray-50 dark:bg-[#1E2530] text-gray-500 dark:text-gray-400 font-semibold border-b border-gray-100 dark:border-[#2C384B]">
                    <tr>
                      <th className="py-2 px-3">Rank</th>
                      <th className="py-2 px-3">Frame</th>
                      <th className="py-2 px-3">Length</th>
                      <th className="py-2 px-3">SPI</th>
                      <th className="py-2 px-3">Saliency</th>
                      <th className="py-2 px-3">Attribution</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-[#2C384B]">
                    {xaiData.threat_packets.slice(0, 8).map((p, i) => (
                      <tr key={i} className="hover:bg-gray-50/50 dark:hover:bg-[#1E2530]/50">
                        <td className="py-2 px-3 font-bold">#{p.attribution_rank}</td>
                        <td className="py-2 px-3 font-mono text-blue-500">#{p.frame_number}</td>
                        <td className="py-2 px-3 font-mono">{p.packet_length}B</td>
                        <td className="py-2 px-3 font-mono text-[11px] text-purple-400">{p.spi?.slice(0, 8)}</td>
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
                            {typeof p.saliency_score === 'number' ? p.saliency_score.toFixed(3) : p.saliency_score}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-gray-600 dark:text-gray-300">{p.threat_description}</td>
                      </tr>
                    ))}
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
