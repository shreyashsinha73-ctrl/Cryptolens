/**
 * Single shared selector for the five "Analysis Dimensions".
 * Used by both AnalysisDimensions (bars) and ComplianceRadar so they can never differ.
 * value: 0..1 when observable, null when not observable (never 0 / never full).
 */
const isObs = (o) => o === 'observed' || o === 'operator_supplied';

function fromBreakdown(entry) {
  // Legacy/testbed breakdowns carry only score/max_score (no observability key): treat as observed.
  const obsKey = entry && entry.observability === undefined && entry.max_score ? 'observed' : entry?.observability;
  if (!entry || !isObs(obsKey) || !entry.max_score) {
    return { value: null, obs: entry?.observability || 'not_observable', evidence: entry?.evidence_source || 'unobservable_on_wire' };
  }
  return {
    value: Math.max(0, Math.min(1, entry.score / entry.max_score)),
    obs: obsKey,
    evidence: entry.evidence_source || 'unknown',
  };
}

export function selectDimensions(score_breakdown, control_plane) {
  const sb = score_breakdown || {};
  const cp = control_plane || {};
  const enc = fromBreakdown(sb.encryption);
  const dh = fromBreakdown(sb.key_exchange);
  const pfs = fromBreakdown(sb.pfs);
  const ike = fromBreakdown(sb.ike_version);

  const g = cp.dh_group != null ? parseInt(String(cp.dh_group).replace(/\D/g, ''), 10) : NaN;
  let pqc = { value: null, obs: 'not_observable', evidence: 'unobservable_on_wire' };
  if (dh.value !== null && Number.isFinite(g)) {
    const v = g >= 19 && g <= 21 ? 1 : g >= 14 && g <= 16 ? 0.5 : 0;
    pqc = { value: v, obs: dh.obs, evidence: 'dh_group_analysis' };
  }

  return [
    { key: 'cipher_strength', label: 'Cipher Strength', ...enc },
    { key: 'key_exchange', label: 'Key Exchange', ...dh },
    { key: 'mode_pfs', label: 'Mode & PFS', ...pfs },
    { key: 'metadata_exposure', label: 'Metadata Exposure', ...ike },
    { key: 'pqc_readiness', label: 'PQC Readiness', ...pqc },
  ];
}
