import React from 'react';

const PerTunnelBreakdown = ({ tunnels = [] }) => {
  const safeTunnels = Array.isArray(tunnels) ? tunnels : (tunnels ? [tunnels] : []);

  return (
    <div className="w-full bg-white rounded-3xl shadow-sm border border-slate-100 overflow-hidden p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-800 uppercase">Monitored Tunnels</h3>
        <span className="text-xs font-bold text-slate-500 bg-slate-100 px-3 py-1 rounded-full">{safeTunnels.length} Active</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-600">
          <thead className="text-[10px] uppercase bg-slate-50 text-slate-400 font-bold">
            <tr>
              <th className="px-4 py-3 rounded-l-xl">ID</th>
              <th className="px-4 py-3">Mode</th>
              <th className="px-4 py-3">Encryption</th>
              <th className="px-4 py-3">DH Group</th>
              <th className="px-4 py-3 rounded-r-xl">PFS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {safeTunnels.map((tunnel, idx) => (
              <tr key={tunnel.id || idx} className="hover:bg-slate-50 transition-colors">
                <td className="px-4 py-3 font-mono text-xs font-semibold">{tunnel.id || `tunnel-${idx}`}</td>
                <td className="px-4 py-3 text-xs">{tunnel.operating_mode || tunnel.inferred_mode || 'Unknown'}</td>
                <td className="px-4 py-3 text-xs">{tunnel.encryption_algorithm || tunnel.encryption || 'Unknown'}</td>
                <td className="px-4 py-3 text-xs">{tunnel.dh_group || 'Unknown'}</td>
                <td className="px-4 py-3 text-xs">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${tunnel.pfs_enabled ? 'bg-emerald-100 text-emerald-600' : 'bg-rose-100 text-rose-600'}`}>
                    {tunnel.pfs_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
              </tr>
            ))}
            {safeTunnels.length === 0 && (
              <tr>
                <td colSpan="5" className="px-4 py-8 text-center text-slate-400 text-xs font-medium">No tunnel data available.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default PerTunnelBreakdown;
