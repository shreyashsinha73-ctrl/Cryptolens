import React from 'react';
import Badge from './common/Badge.jsx';
import Button from './common/Button.jsx';
import Card from './common/Card.jsx';

const PerTunnelBreakdown = ({ tunnels = [] }) => {
  return (
    <Card
      title="Analyzed IPsec Configuration"
      subtitle="Deep packet telemetry & cryptographic posture breakdown"
      action={
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-[#646464] dark:text-gray-400 bg-[#F5F6FA] dark:bg-[#1B2431] px-3 py-1.5 rounded-[6px] border border-gray-200 dark:border-[#323D4E]">
            Analyses: <span className="text-[#4880FF] font-extrabold ml-1">{tunnels.length}</span>
          </span>
        </div>
      }
      padding="p-0"
      headerBorder={true}
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-[#202224] dark:text-gray-200 whitespace-nowrap font-['Nunito_Sans']">
          <thead className="text-[12px] uppercase bg-[#F5F6FA] dark:bg-[#1B2431]/80 text-[#646464] dark:text-gray-400 font-bold tracking-wider border-b border-gray-100 dark:border-[#323D4E]">
            <tr>
              <th className="px-6 py-4">Analysis ID</th>
              <th className="px-6 py-4">Risk Status</th>
              <th className="px-6 py-4">Encryption Cipher</th>
              <th className="px-6 py-4">Diffie-Hellman</th>
              <th className="px-6 py-4">PFS Status</th>
              <th className="px-6 py-4">Inferred Mode</th>
              <th className="px-6 py-4">Payload Traffic</th>
              <th className="px-6 py-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-[#323D4E]/60">
            {tunnels.map((tunnel) => {
              let badgeVariant = 'completed';
              let badgeText = 'Active';

              if (tunnel.status === 'critical') {
                badgeVariant = 'rejected';
                badgeText = 'Critical';
              } else if (tunnel.status === 'flagged') {
                badgeVariant = 'on_hold';
                badgeText = 'Flagged';
              }

              return (
                <tr
                  key={tunnel.id}
                  className="transition-colors hover:bg-gray-50/80 dark:hover:bg-[#1f2735]/60"
                >
                  <td className="px-6 py-4 font-bold text-xs text-[#202224] dark:text-white">
                    <span className="font-mono bg-gray-100 dark:bg-slate-800 px-2 py-1 rounded text-xs">
                      {tunnel.id}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <Badge variant={badgeVariant} label={badgeText} size="sm" />
                  </td>
                  <td className="px-6 py-4 text-xs font-semibold text-[#4880FF] dark:text-[#5A8CFF]">
                    {tunnel.encryption}
                  </td>
                  <td className="px-6 py-4 text-xs font-semibold text-[#6226EF] dark:text-[#a78bfa]">
                    MODP_{tunnel.dh_group}
                  </td>
                  <td className="px-6 py-4 text-xs font-bold">
                    <span
                      className={`inline-flex items-center gap-1 ${
                        tunnel.pfs_enabled
                          ? 'text-[#00B69B]'
                          : 'text-[#EF3826]'
                      }`}
                    >
                      {tunnel.pfs_enabled ? '✓ Enabled' : '✕ Disabled'}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-xs text-[#646464] dark:text-gray-400 font-medium">
                    {tunnel.inferred_mode}
                  </td>
                  <td className="px-6 py-4 text-xs text-[#646464] dark:text-gray-400 font-medium">
                    <span className="px-2 py-0.5 rounded bg-gray-100 dark:bg-slate-800 font-mono text-[11px]">
                      {tunnel.inner_traffic}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <Button
                      variant="compact"
                      size="sm"
                      onClick={() => alert(`Inspecting security parameters for ${tunnel.id}`)}
                    >
                      Inspect
                    </Button>
                  </td>
                </tr>
              );
            })}
            {tunnels.length === 0 && (
              <tr>
                <td
                  colSpan="8"
                  className="px-6 py-10 text-center text-gray-400 text-sm font-semibold"
                >
                  No IPsec configuration data available.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
};

export default PerTunnelBreakdown;
