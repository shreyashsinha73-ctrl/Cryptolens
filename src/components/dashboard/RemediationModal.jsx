import React, { useState, useEffect } from 'react';
import Badge from '../common/Badge.jsx';

export default function RemediationModal({ jobId, isOpen, onClose }) {
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('swanctl');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!isOpen || !jobId) return;
    setLoading(true);
    setError(null);
    fetch(`/api/v1/remediate/${jobId}`, { method: 'POST' })
      .then((r) => { if (!r.ok) throw new Error('Remediation failed'); return r.json(); })
      .then((d) => { setRemediation(d.remediation); setLoading(false); })
      .catch((e) => { setError(e.message); setLoading(false); });
  }, [isOpen, jobId]);

  if (!isOpen) return null;

  const code = activeTab === 'swanctl' ? remediation?.swanctl_conf
    : activeTab === 'ipsec' ? remediation?.ipsec_conf : remediation?.xfrm_script;

  const handleCopy = () => {
    if (code) { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-3xl rounded-2xl bg-white dark:bg-[#1E2530] border border-gray-100 dark:border-[#2C384B] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-gray-100 dark:border-[#2C384B] flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2">
              AI Network Hardening
              {remediation?.engine_used && <Badge variant="completed" label={`Engine: ${remediation.engine_used.toUpperCase()}`} size="sm" />}
            </h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">NIST SP 800-77 Rev. 1 & NSA CNSA 2.0</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 text-xl font-bold p-1">&times;</button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {loading ? (
            <div className="py-12 text-center text-sm text-gray-400">Generating hardened IPsec configuration...</div>
          ) : error ? (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-500">{error}</div>
          ) : remediation ? (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3 rounded-xl bg-gray-50 dark:bg-[#1A222F] border border-gray-100 dark:border-[#2C384B] text-xs">
                {[['Cipher', remediation.config.encryption, 'text-emerald-500'],
                  ['DH Group', remediation.config.dh_group, 'text-blue-500'],
                  ['PFS', 'ENABLED', 'text-emerald-500'],
                  ['Rekey', remediation.config.rekey_time, 'text-purple-400']].map(([l, v, c]) => (
                  <div key={l}>
                    <div className="text-[10px] text-gray-400 font-bold uppercase">{l}</div>
                    <div className={`font-mono font-bold ${c}`}>{v}</div>
                  </div>
                ))}
              </div>

              <div className="flex items-center justify-between border-b border-gray-100 dark:border-[#2C384B] pb-2">
                <div className="flex gap-2">
                  {[['swanctl', 'swanctl.conf'], ['ipsec', 'ipsec.conf'], ['xfrm', 'xfrm Script']].map(([k, l]) => (
                    <button key={k} onClick={() => setActiveTab(k)}
                      className={`text-xs px-3 py-1.5 rounded-lg font-medium transition ${
                        activeTab === k ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-[#232D3F] text-gray-600 dark:text-gray-300'
                      }`}>{l}</button>
                  ))}
                </div>
                <button onClick={handleCopy}
                  className="text-xs px-3 py-1 rounded-md bg-gray-100 dark:bg-[#232D3F] hover:bg-gray-200 dark:hover:bg-[#2C384B] text-gray-700 dark:text-gray-200 font-medium transition">
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>

              <pre className="p-4 rounded-xl bg-gray-900 text-gray-200 font-mono text-xs overflow-x-auto border border-gray-800 leading-relaxed max-h-72">{code}</pre>
            </>
          ) : null}
        </div>

        <div className="p-4 border-t border-gray-100 dark:border-[#2C384B] flex justify-end bg-gray-50 dark:bg-[#1A222F]">
          <button onClick={onClose} className="px-4 py-2 text-xs font-semibold rounded-lg bg-gray-200 dark:bg-[#2C384B] text-gray-700 dark:text-gray-200 hover:bg-gray-300 transition">Close</button>
        </div>
      </div>
    </div>
  );
}

