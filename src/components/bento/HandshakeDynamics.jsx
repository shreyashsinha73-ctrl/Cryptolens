import React from 'react';

const HandshakeDynamics = ({ controlPlane }) => {
  const data = Array.isArray(controlPlane) ? controlPlane[0] : controlPlane || {};
  const lifetime = data.key_lifetime_seconds || 28800;

  return (
    <div className="bg-[#a7c2d1] rounded-3xl p-5 w-full flex flex-col shadow-inner">
      <div className="bg-white rounded-2xl p-6 shadow-sm flex-1 flex flex-col border border-slate-100">
        <h3 className="text-sm font-semibold text-slate-800 tracking-wide uppercase mb-1">Handshake & Key Lifecycle</h3>
        <p className="text-xs text-slate-500 mb-6">Key lifetime usage & rekey progression</p>
        
        {/* Curved SVG Lines visualization */}
        <div className="flex-1 min-h-[100px] relative w-full mb-6 flex flex-col justify-end">
          <svg className="w-full h-24" viewBox="0 0 400 100" preserveAspectRatio="none">
            <path d="M0,80 C100,20 300,100 400,10" fill="none" stroke="#f1f5f9" strokeWidth="6" strokeLinecap="round" />
            <path d="M0,80 C100,20 300,100 400,10" fill="none" stroke="#2563eb" strokeWidth="4" strokeDasharray="10 6" className="animate-[dash_3s_linear_infinite]" strokeLinecap="round" />
          </svg>
          <div className="absolute top-0 right-0 bg-blue-50 text-blue-600 font-bold text-[10px] px-2.5 py-1 rounded-full">
            {lifetime}s Limit
          </div>
        </div>

        {/* Clean Badges */}
        <div className="flex flex-wrap gap-2 mt-auto">
          <span className="px-3 py-1 bg-slate-50 border border-slate-100 text-slate-600 rounded-full text-[10px] font-bold uppercase">{data.ike_version || 'IKEv2'}</span>
          <span className="px-3 py-1 bg-slate-50 border border-slate-100 text-slate-600 rounded-full text-[10px] font-bold uppercase">{data.encryption_algorithm || 'AES-GCM'}</span>
          <span className="px-3 py-1 bg-slate-50 border border-slate-100 text-slate-600 rounded-full text-[10px] font-bold uppercase">{data.integrity_algorithm || 'SHA256'}</span>
          <span className="px-3 py-1 bg-slate-50 border border-slate-100 text-slate-600 rounded-full text-[10px] font-bold uppercase">DH {data.dh_group || '19'}</span>
        </div>
      </div>
      <style dangerouslySetInnerHTML={{__html: `@keyframes dash { to { stroke-dashoffset: -32; } }`}} />
    </div>
  );
};
export default HandshakeDynamics;
