import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import {
  Server,
  Play,
  RotateCcw,
  Activity,
  Zap,
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';

const TESTBED_CONFIGS = [
  {
    id: 'config_01',
    name: 'config_01_tunnel_aes256gcm_dh19_pfson',
    mode: 'Tunnel',
    cipher: 'AES-256-GCM',
    integrity: 'Combined AEAD',
    dhGroup: 'Group 19 (NIST P-256)',
    pfs: 'Enabled',
    expectedSecurity: 'High / Modern CNSA 2.0 Ready',
  },
  {
    id: 'config_02',
    name: 'config_02_tunnel_aes128gcm_dh14_pfson',
    mode: 'Tunnel',
    cipher: 'AES-128-GCM',
    integrity: 'Combined AEAD',
    dhGroup: 'Group 14 (MODP 2048)',
    pfs: 'Enabled',
    expectedSecurity: 'Medium / NIST SP 800-77 Standard',
  },
  {
    id: 'config_03',
    name: 'config_03_tunnel_aes256cbc_sha256_dh14_pfson',
    mode: 'Tunnel',
    cipher: 'AES-256-CBC',
    integrity: 'HMAC-SHA-256',
    dhGroup: 'Group 14 (MODP 2048)',
    pfs: 'Enabled',
    expectedSecurity: 'Medium / Legacy CBC Mode',
  },
  {
    id: 'config_04',
    name: 'config_04_transport_aes128cbc_sha1_dh5_pfsoff',
    mode: 'Transport',
    cipher: 'AES-128-CBC',
    integrity: 'HMAC-SHA-1',
    dhGroup: 'Group 5 (MODP 1536)',
    pfs: 'Disabled',
    expectedSecurity: 'High Risk / Obsolete Hash & No PFS',
  },
  {
    id: 'config_05',
    name: 'config_05_transport_3des_sha1_dh2_pfsoff',
    mode: 'Transport',
    cipher: '3DES-CBC',
    integrity: 'HMAC-SHA-1',
    dhGroup: 'Group 2 (MODP 1024)',
    pfs: 'Disabled',
    expectedSecurity: 'Critical Risk / Sweet32 Vulnerability',
  },
  {
    id: 'config_06',
    name: 'config_06_tunnel_3des_sha1_dh2_pfsoff',
    mode: 'Tunnel',
    cipher: '3DES-CBC',
    integrity: 'HMAC-SHA-1',
    dhGroup: 'Group 2 (MODP 1024)',
    pfs: 'Disabled',
    expectedSecurity: 'Critical Risk / Deprecated Legacy Suite',
  },
];

export default function TestbedPage() {
  const navigate = useNavigate();
  const {
    setActiveJobId,
    setUploading,
    telemetry,
  } = useApp();

  const [loadingConfig, setLoadingConfig] = useState(null);
  const [ingestingAll, setIngestingAll] = useState(false);
  const [message, setMessage] = useState(null);
  const [injectingProfile, setInjectingProfile] = useState(null);

  const handleIngestRow = async (config) => {
    setLoadingConfig(config.id);
    setMessage(null);
    try {
      const res = await fetch(`/api/v1/capture/ingest/${config.name}?force=true`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`Status ${res.status}`);
      const data = await res.json();
      const jobId = data.job_id || `testbed_${config.name}_all`;
      setActiveJobId(jobId);
      setUploading(true);
      setMessage(`Ingested ${config.id}. Loading dashboard...`);
      navigate('/dashboard');
    } catch (err) {
      setMessage(`Ingest error for ${config.id}: ${err.message}`);
    } finally {
      setLoadingConfig(null);
    }
  };

  const handleSimulateRow = (config) => {
    const jobId = `testbed_${config.name}_all`;
    setActiveJobId(jobId);
    if (telemetry?.simulateCapture) {
      telemetry.simulateCapture(jobId);
    }
    navigate('/live');
  };

  const handleIngestAll = async () => {
    setIngestingAll(true);
    setMessage(null);
    try {
      const res = await fetch('/api/v1/capture/ingest?force=true', {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`Status ${res.status}`);
      const data = await res.json();
      const firstJobId = data.results?.find(r => r.status === 'completed')?.job_id || data.job_id;
      if (firstJobId) {
        setActiveJobId(firstJobId);
        setUploading(true);
        navigate('/dashboard');
      }
    } catch (err) {
      setMessage(`Ingest all error: ${err.message}`);
    } finally {
      setIngestingAll(false);
    }
  };

  const handleInjectProfile = async (profile) => {
    setInjectingProfile(profile);
    setMessage(null);
    try {
      const res = await fetch(`/api/v1/live/inject/${profile}`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`Inject failed: ${res.status}`);
      setMessage(`Injected live simulated telemetry profile: ${profile}`);
    } catch (err) {
      setMessage(`Injection error: ${err.message}`);
    } finally {
      setInjectingProfile(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-[#0F121C] border border-[#1F2639]">
        <div>
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5 text-blue-400" />
            <h1 className="text-base font-bold text-white tracking-tight">Testbed Lab Configurations</h1>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Ground-truth IPsec topologies (config_01 to config_06) strictly audited against wire observations.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={handleIngestAll}
            disabled={ingestingAll}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs h-8 px-3 gap-1.5 cursor-pointer"
          >
            <RotateCcw className={`h-3.5 w-3.5 ${ingestingAll ? 'animate-spin' : ''}`} />
            <span>{ingestingAll ? 'Ingesting all...' : 'Ingest All Captures'}</span>
          </Button>
        </div>
      </div>

      {message && (
        <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-mono flex items-center justify-between">
          <span>{message}</span>
          <button onClick={() => setMessage(null)} className="underline cursor-pointer">Dismiss</button>
        </div>
      )}

      {/* Inject Demo Profiles Card */}
      <div className="p-4 rounded-xl bg-[#0F121C] border border-[#1F2639] space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-amber-400" />
            <span className="text-xs font-semibold text-white">Inject Live Wire Demo Profiles</span>
          </div>
          <span className="text-[11px] font-mono text-gray-500">Live sniffer &amp; WebSocket bus injection</span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {['hardened', 'vulnerable', 'attack', 'weak'].map((prof) => (
            <Button
              key={prof}
              variant="outline"
              size="sm"
              disabled={injectingProfile !== null}
              onClick={() => handleInjectProfile(prof)}
              className="border-[#1F2639] bg-[#161B26] hover:bg-[#202738] text-gray-200 text-xs h-8 px-3 capitalize cursor-pointer"
            >
              <Activity className="h-3.5 w-3.5 text-blue-400" />
              <span>{injectingProfile === prof ? 'Injecting...' : `Inject ${prof}`}</span>
            </Button>
          ))}
        </div>
      </div>

      {/* Matrix Table */}
      <div className="rounded-xl bg-[#0F121C] border border-[#1F2639] overflow-hidden">
        <div className="p-3 border-b border-[#1F2639] flex items-center justify-between">
          <span className="text-xs font-semibold text-white font-mono uppercase">
            Testbed Ground-Truth Matrix
          </span>
          <span className="text-[10px] font-mono text-gray-500">
            testbed config (ground truth, not wire evidence)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1F2639] text-gray-400 bg-[#0A0D14]">
                <th className="py-2.5 px-4 font-semibold">Config ID</th>
                <th className="py-2.5 px-4 font-semibold">Mode</th>
                <th className="py-2.5 px-4 font-semibold">Cipher / Integrity</th>
                <th className="py-2.5 px-4 font-semibold">DH Group</th>
                <th className="py-2.5 px-4 font-semibold">PFS</th>
                <th className="py-2.5 px-4 font-semibold">Security Posture</th>
                <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2639]">
              {TESTBED_CONFIGS.map((cfg) => (
                <tr key={cfg.id} className="hover:bg-[#121624] transition-colors">
                  <td className="py-3 px-4 font-bold text-white">{cfg.id}</td>
                  <td className="py-3 px-4 text-gray-300">{cfg.mode}</td>
                  <td className="py-3 px-4 text-gray-300">{cfg.cipher} &middot; {cfg.integrity}</td>
                  <td className="py-3 px-4 text-purple-400">{cfg.dhGroup}</td>
                  <td className="py-3 px-4">
                    <span className={cfg.pfs === 'Enabled' ? 'text-emerald-400' : 'text-rose-400'}>
                      {cfg.pfs}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-gray-400">{cfg.expectedSecurity}</td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <Button
                        size="sm"
                        onClick={() => handleIngestRow(cfg)}
                        disabled={loadingConfig === cfg.id}
                        className="bg-blue-600 hover:bg-blue-700 text-white font-medium text-[11px] h-7 px-2.5 cursor-pointer"
                      >
                        {loadingConfig === cfg.id ? 'Analyzing...' : 'Audit'}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleSimulateRow(cfg)}
                        className="border-[#1F2639] bg-[#161B26] hover:bg-[#202738] text-gray-300 text-[11px] h-7 px-2.5 cursor-pointer"
                      >
                        <Play className="h-3 w-3 text-emerald-400" />
                        <span>Stream</span>
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
