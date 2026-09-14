import React from 'react';

const PerTunnelBreakdown = ({ tunnels = [] }) => {
  return (
    <div className="w-full bg-slate-900/70 border border-slate-800/80 rounded-xl shadow-xl backdrop-blur overflow-hidden">
      <div className="px-6 py-5 flex items-center justify-between">
        <h3 className="text-xs font-mono font-semibold tracking-wider text-slate-400 uppercase">Monitored IPsec Security Associations</h3>
        <span className="text-xs font-mono text-slate-400 bg-transparent px-3 py-1 rounded-md border border-slate-800">Total SAs: <span className="text-slate-200 font-bold ml-1">{tunnels.length}</span></span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-slate-300 whitespace-nowrap">
          <thead className="text-[10px] uppercase bg-slate-950/40 text-slate-500 font-mono tracking-widest">
            <tr>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">ID</th>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">Status</th>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">Encryption</th>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">DH Group</th>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">PFS</th>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">Inferred Mode</th>
              <th className="px-6 py-4 font-bold border-y border-slate-800/80">Inner Traffic</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {tunnels.map((tunnel) => {
              let statusPill = null;
              
              if (tunnel.status === 'critical') {
                statusPill = <span className="px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider uppercase bg-rose-500/10 text-rose-400 border border-rose-500/20 shadow-[0_0_8px_rgba(244,63,94,0.15)]">Critical</span>;
              } else if (tunnel.status === 'flagged') {
                statusPill = <span className="px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider uppercase bg-amber-500/10 text-amber-400 border border-amber-500/20 shadow-[0_0_8px_rgba(245,158,11,0.15)]">Flagged</span>;
              } else if (tunnel.status === 'active') {
                statusPill = <span className="px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shadow-[0_0_8px_rgba(16,185,129,0.15)]">Active</span>;
              }

              return (
                <tr key={tunnel.id} className="transition-colors hover:bg-slate-800/50 group">
                  <td className="px-6 py-4 font-mono text-xs text-slate-300 font-medium">{tunnel.id}</td>
                  <td className="px-6 py-4">{statusPill}</td>
                  <td className="px-6 py-4 font-mono text-xs text-blue-300">{tunnel.encryption}</td>
                  <td className="px-6 py-4 font-mono text-xs text-purple-300">{typeof tunnel.dh_group === 'number' ? `Group ${tunnel.dh_group}` : tunnel.dh_group}</td>
                  <td className="px-6 py-4 font-mono text-xs">
                    <span className={`${tunnel.pfs_enabled ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {tunnel.pfs_enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-400">{tunnel.inferred_mode}</td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-400">{tunnel.inner_traffic}</td>
                </tr>
              );
            })}
            {tunnels.length === 0 && (
              <tr>
                <td colSpan="7" className="px-6 py-8 text-center text-slate-500 font-mono text-sm">No active tunnels found.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default PerTunnelBreakdown;
