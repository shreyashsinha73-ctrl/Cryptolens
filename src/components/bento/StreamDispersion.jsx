import React from 'react';

const StreamDispersion = ({ dataPlane, summary }) => {
  const traffic = dataPlane?.detected_traffic || { VoIP: 40, Streaming: 35, Messaging: 25 };
  const packets = dataPlane?.total_packets || 14502;
  const hMode = summary?.heuristic_mode_prediction || 'Tunnel';
  const lMode = summary?.llm_mode_prediction || 'Tunnel';
  const consensus = hMode === lMode;

  return (
    <div className="bg-slate-200 rounded-3xl p-5 w-full flex flex-col shadow-inner">
      <div className="bg-white rounded-2xl p-6 shadow-sm flex-1 flex flex-col border border-slate-100">
        <h3 className="text-sm font-semibold text-slate-800 tracking-wide uppercase mb-1">Data-Plane Traffic Stream</h3>
        <p className="text-xs text-slate-500 mb-4">ESP bandwidth distribution & consensus</p>
        
        <div className="flex justify-between items-center mb-6">
          <div className="flex flex-col">
            <span className="text-[10px] uppercase text-slate-400 font-bold mb-0.5">Packets Analyzed</span>
            <span className="text-lg font-black text-slate-700">{packets.toLocaleString()}</span>
          </div>
          <div className={`px-3 py-1.5 rounded-full text-[10px] font-bold ${consensus ? 'bg-emerald-50 text-emerald-600 border border-emerald-100' : 'bg-amber-50 text-amber-600 border border-amber-100'}`}>
            {consensus ? '✓ Consensus' : '⚠ Conflict'}
          </div>
        </div>

        {/* SVG Multi-layered Area visualization */}
        <div className="flex-1 w-full min-h-[100px] relative rounded-xl overflow-hidden bg-slate-50">
           <svg className="absolute w-full h-full bottom-0 left-0" viewBox="0 0 100 100" preserveAspectRatio="none">
             <path d="M0,100 L0,50 Q25,30 50,60 T100,40 L100,100 Z" fill="#93c5fd" opacity="0.6"/>
             <path d="M0,100 L0,70 Q25,50 50,80 T100,60 L100,100 Z" fill="#86efac" opacity="0.7"/>
             <path d="M0,100 L0,85 Q25,75 50,90 T100,80 L100,100 Z" fill="#fcd34d" opacity="0.7"/>
           </svg>
           <div className="absolute top-2 left-2 flex flex-col gap-1.5 bg-white/80 p-2 rounded shadow-sm text-[9px] font-bold text-slate-600">
             {Object.entries(traffic).slice(0,3).map(([key, val], i) => (
               <div key={key} className="flex items-center">
                 <div className={`w-2 h-2 rounded mr-1.5 ${i===0 ? 'bg-blue-400' : i===1 ? 'bg-emerald-400' : 'bg-amber-400'}`}></div>
                 {key} ({val}%)
               </div>
             ))}
           </div>
        </div>
      </div>
    </div>
  );
};
export default StreamDispersion;
