import React, { useState, useEffect, useCallback } from 'react';
import BeforeAfterDiff from './BeforeAfterDiff.jsx';
import { Skeleton } from '../common/SeverityChip.jsx';
import Badge from '../common/Badge.jsx';

const ORDER = { high: 0, medium: 1, low: 2 };
const PRIORITY_STYLE = {
  high: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30',
  medium: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30',
  low: 'bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/30',
};

export default function RemediationModal({ jobId, isOpen, onClose }) {
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('swanctl');
  const [copied, setCopied] = useState(false);
  const [advice, setAdvice] = useState(null);
  const [adviceLoading, setAdviceLoading] = useState(false);
  const [adviceError, setAdviceError] = useState(null);

  const loadAdvice = useCallback(() => {
    if (!jobId) return;
    setAdviceLoading(true);
    setAdviceError(null);
    fetch(`/api/v1/remediate/${jobId}/advice`, { method: 'POST' })
      .then((r) => { if (!r.ok) throw new Error(`Could not get advice (${r.status})`); return r.json(); })
      .then((d) => { setAdvice(d); setAdviceLoading(false); })
      .catch((e) => { setAdviceError(e.message); setAdviceLoading(false); });
  }, [jobId]);

  useEffect(() => { if (isOpen) loadAdvice(); }, [isOpen, loadAdvice]);

  useEffect(() => {
    if (!isOpen || !jobId) return;
    setLoading(true);
    setError(null);
    fetch(`/api/v1/remediate/${jobId}`, { method: 'POST' })
      .then((r) => { if (!r.ok) throw new Error('Remediation generation failed'); return r.json(); })
      .then((d) => { setRemediation(d.remediation); setLoading(false); })
      .catch((e) => { setError(e.message); setLoading(false); });
  }, [isOpen, jobId]);

  if (!isOpen) return null;

  const code = activeTab === 'swanctl' ? remediation?.swanctl_conf
    : activeTab === 'ipsec' ? remediation?.ipsec_conf : remediation?.xfrm_script;

  const handleCopy = () => {
    if (code) {
      navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const isReferenceOnly = activeTab !== 'swanctl';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-3xl rounded-2xl bg-white dark:bg-[#1E2530] border border-gray-100 dark:border-[#2C384B] shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-gray-100 dark:border-[#2C384B] flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white flex items-center gap-2 flex-wrap">
              <span>AI Network Hardening Remediation</span>
              {remediation?.engine_used && (
                <Badge variant="completed" label={`Engine: ${remediation.engine_used.toUpperCase()}`} size="sm" />
              )}
              {remediation?.validation_level && (
                <Badge
                  variant={remediation.validation_level === 'SYNTAX_VALIDATED' ? 'completed' : 'critical'}
                  label={remediation.validation_level}
                  size="sm"
                />
              )}
            </h3>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              Standards: NIST SP 800-77 Rev. 1 &amp; NSA CNSA 1.0 (Transitionary) — Authoritative: <code className="font-mono font-bold text-blue-500">swanctl.conf</code>
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 text-xl font-bold p-1 cursor-pointer">&times;</button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {/* Plain-language advice (Gemini or rules) */}
          <div className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-bold text-gray-900 dark:text-white">What to do to improve this network</span>
              {advice?.source && (
                <Badge variant="completed" label={`Source: ${advice.source === 'gemini' ? `Gemini (${advice.model})` : 'Rules-based'}`} size="sm" />
              )}
            </div>
            {adviceLoading ? (
              <div className="text-sm text-gray-400"><Skeleton lines={4} />Getting advice...</div>
            ) : adviceError ? (
              <div className="space-y-2">
                <p className="text-xs text-rose-500">{adviceError}</p>
                <button type="button" onClick={loadAdvice} className="px-3 py-1.5 rounded-lg bg-blue-600 text-white text-xs font-bold cursor-pointer">Retry</button>
              </div>
            ) : advice?.hardening_advice ? (
              <>
                <p className="text-xs text-gray-700 dark:text-gray-200 leading-relaxed">{advice.hardening_advice.summary}</p>
                {[...advice.hardening_advice.points].sort((a, b) => (ORDER[a.priority] ?? 3) - (ORDER[b.priority] ?? 3)).map((p, i) => (
                  <div key={i} className="rounded-xl border border-gray-200 dark:border-[#2C384B] p-3 space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded border ${PRIORITY_STYLE[p.priority] || PRIORITY_STYLE.low}`}>{p.priority}</span>
                      <span className="text-xs font-bold text-gray-900 dark:text-white">{p.title}</span>
                    </div>
                    <p className="text-xs text-gray-700 dark:text-gray-300"><strong>What we saw: </strong>{p.problem}</p>
                    <p className="text-xs text-gray-700 dark:text-gray-300"><strong>Why it matters: </strong>{p.why_it_matters}</p>
                    <p className="text-xs text-gray-700 dark:text-gray-300"><strong>How to fix: </strong>{p.how_to_fix}</p>
                  </div>
                ))}
                {advice.hardening_advice.not_observable_note && (
                  <p className="text-[11px] italic text-gray-500 dark:text-gray-400">Not observable: {advice.hardening_advice.not_observable_note}</p>
                )}
              </>
            ) : null}
          </div>

          {loading ? (
            <div className="py-6 text-center text-sm text-gray-400">
              <Skeleton lines={5} />
              Generating and syntax-validating hardened IPsec configuration...
            </div>
          ) : error ? (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-500">{error}</div>
          ) : remediation ? (
            <>
              {/* Hardened Config Specs */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3 rounded-xl bg-gray-50 dark:bg-[#1A222F] border border-gray-100 dark:border-[#2C384B] text-xs">
                {[
                  ['Cipher', remediation.config?.encryption, 'text-emerald-500'],
                  ['DH Group', `Group ${remediation.config?.dh_group} (ECP-384)`, 'text-blue-500'],
                  ['PFS', 'ENABLED', 'text-emerald-500'],
                  ['Rekey', remediation.config?.rekey_time || '4h', 'text-purple-400'],
                ].map(([l, v, c]) => (
                  <div key={l}>
                    <div className="text-[10px] text-gray-400 font-bold uppercase">{l}</div>
                    <div className={`font-mono font-bold ${c}`}>{v}</div>
                  </div>
                ))}
              </div>

              {/* Subnet and Peer Identifiers */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono p-2.5 bg-gray-50 dark:bg-[#1A222F] rounded-lg border border-gray-100 dark:border-[#2C384B] text-gray-600 dark:text-gray-300">
                <div><span className="text-[10px] text-gray-400 block font-sans font-bold uppercase">Local Subnet</span>{remediation.config?.local_subnet}</div>
                <div><span className="text-[10px] text-gray-400 block font-sans font-bold uppercase">Remote Subnet</span>{remediation.config?.remote_subnet}</div>
                <div><span className="text-[10px] text-gray-400 block font-sans font-bold uppercase">Local ID</span>{remediation.config?.local_id}</div>
                <div><span className="text-[10px] text-gray-400 block font-sans font-bold uppercase">Remote ID</span>{remediation.config?.remote_id}</div>
              </div>

              <BeforeAfterDiff
                diff={remediation?.config_diff}
                projected={remediation?.projected}
                engineUsed={remediation?.engine_used}
              />

              {/* Tab Selector */}
              <div className="flex items-center justify-between border-b border-gray-100 dark:border-[#2C384B] pb-2">
                <div className="flex gap-2">
                  {[
                    ['swanctl', 'swanctl.conf (Authoritative)'],
                    ['ipsec', 'ipsec.conf (Reference)'],
                    ['xfrm', 'xfrm Script (Reference)'],
                  ].map(([k, l]) => (
                    <button
                      key={k}
                      onClick={() => setActiveTab(k)}
                      className={`text-xs px-3 py-1.5 rounded-lg font-medium transition cursor-pointer ${
                        activeTab === k
                          ? 'bg-blue-600 text-white font-bold'
                          : 'bg-gray-100 dark:bg-[#232D3F] text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-[#2C384B]'
                      }`}
                    >
                      {l}
                    </button>
                  ))}
                </div>
                <button
                  onClick={handleCopy}
                  className="text-xs px-3 py-1.5 rounded-md bg-gray-100 dark:bg-[#232D3F] hover:bg-gray-200 dark:hover:bg-[#2C384B] text-gray-700 dark:text-gray-200 font-medium transition cursor-pointer flex items-center gap-1.5"
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>

              {/* Reference-only Warning Banner */}
              {isReferenceOnly && (
                <div className="bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-300 px-3.5 py-2 rounded-lg text-xs font-medium flex items-center gap-2">
                  <span className="font-bold uppercase text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-800 dark:text-amber-200 shrink-0">
                    Reference Only
                  </span>
                  <span>Notice: Only <code>swanctl.conf</code> is AST syntax-validated and authoritative for production load.</span>
                </div>
              )}

              {/* Code Display */}
              <pre className="p-4 rounded-xl bg-gray-900 text-gray-200 font-mono text-xs overflow-x-auto border border-gray-800 leading-relaxed max-h-72 select-all">
                {code}
              </pre>
            </>
          ) : null}
        </div>

        <div className="p-4 border-t border-gray-100 dark:border-[#2C384B] flex justify-end bg-gray-50 dark:bg-[#1A222F]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-gray-200 dark:bg-[#2C384B] text-gray-700 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-[#374459] transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
