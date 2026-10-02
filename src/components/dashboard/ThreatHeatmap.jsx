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
      .then((r) => { if (!r.ok) throw new Error('XAI not available'); return r.json(); })
      .then((d) => { if (alive) { setXaiData(d.xai); setLoading(false); } })
      .catch((e) => { if (alive) { setError(e.message); setLoading(false); } });
    return () => { alive = false; };
  }, [jobId, method]);

  if (!jobId) return null;

  return (
    <Card title="Explainable AI (XAI) Threat Localizer"
      subtitle="Grad-CAM 1D neural activation & per-packet risk attribution" padding="p-6" className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="text-xs text-gray-500 dark:text-gray-400">
          Model: <span className="font-semibold text-gray-700 dark:text-gray-200">1D-CNN (DataPlaneCNN)</span>
        </div>
        <div className="flex gap-2">
          {['grad_cam', 'integrated_gradients'].map((m) => (
            <button key={m} onClick={() => setMethod(m)}
              className={`text-xs px-3 py-1.5 rounded-lg font-medium transition ${
                method === m ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-[#1E2530] text-gray-600 dark:text-gray-300'
              }`}>
              {m === 'grad_cam' ? 'Grad-CAM 1D' : 'Integrated Gradients'}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="py-8 text-center text-xs text-gray-400">Computing neural gradients...</div>
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
              <span className="font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300">Sequence Activation (30 Frames)</span>
              <span className="text-gray-400 text-[11px]">Red = High Attention</span>
            </div>
            <div className="flex gap-1 h-10 items-end p-2 bg-gray-900 rounded-lg">
              {xaiData.xai_heatmap?.map((val, idx) => {
                const n = Math.min(1, Math.max(0.05, val));
                return (
                  <div key={idx} className="flex-1 rounded-t-sm transition-all hover:scale-110 cursor-pointer"
                    style={{ height: `${Math.max(n * 100, 10)}%`, backgroundColor: `rgb(${Math.round(n*230+25)},${Math.round((1-n)*180+30)},40)` }}
                    title={`Frame ${idx+1}: ${val.toFixed(3)}`} />
                );
              })}
            </div>
            <div className="flex justify-between text-[10px] text-gray-400 mt-1 font-mono">
              <span>Frame 1</span><span>Frame 15</span><span>Frame 30</span>
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
              <div className="text-xs font-bold uppercase tracking-wider text-gray-700 dark:text-gray-300 mb-2">Top Attributed Packets</div>
              <div className="overflow-x-auto rounded-lg border border-gray-100 dark:border-[#2C384B]">
                <table className="w-full text-xs text-left">
                  <thead className="bg-gray-50 dark:bg-[#1E2530] text-gray-500 dark:text-gray-400 font-semibold border-b border-gray-100 dark:border-[#2C384B]">
                    <tr>
                      <th className="py-2 px-3">Rank</th><th className="py-2 px-3">Frame</th>
                      <th className="py-2 px-3">Length</th><th className="py-2 px-3">SPI</th>
                      <th className="py-2 px-3">Saliency</th><th className="py-2 px-3">Attribution</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-[#2C384B]">
                    {xaiData.threat_packets.slice(0, 8).map((p, i) => (
                      <tr key={i} className="hover:bg-gray-50/50 dark:hover:bg-[#1E2530]/50">
                        <td className="py-2 px-3 font-bold">#{p.attribution_rank}</td>
                        <td className="py-2 px-3 font-mono text-blue-500">#{p.frame_number}</td>
                        <td className="py-2 px-3 font-mono">{p.packet_length}B</td>
                        <td className="py-2 px-3 font-mono text-[11px] text-purple-400">{p.spi?.slice(0,8)}</td>
                        <td className="py-2 px-3">
                          <span className={`font-mono font-bold ${p.saliency_score > 0.6 ? 'text-red-500' : p.saliency_score > 0.3 ? 'text-amber-500' : 'text-gray-400'}`}>
                            {p.saliency_score.toFixed(3)}
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

