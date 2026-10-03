// Pure helpers: derive an executive grade / traffic light / verdict from REAL
// scoring output (score range, coverage, findings). No invented numbers.

export function letterFor(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return '?';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function parseCoverage(coverage) {
  const m = /^(\d+)\s*\/\s*(\d+)$/.exec(String(coverage ?? ''));
  if (!m) return { observed: null, total: null, partial: true };
  const observed = Number(m[1]);
  const total = Number(m[2]);
  return { observed, total, partial: observed < total };
}

/**
 * worst/best come from score_if_unobserved_fail / score_if_unobserved_pass.
 * Partial coverage never yields a bare grade: it is shown as a range or flagged provisional.
 */
export function computeGrade({ score, worst, best, coverage, riskLevel }) {
  const lo = worst ?? score;
  const hi = best ?? score;
  const cov = parseCoverage(coverage);
  const gLo = letterFor(lo);
  const gHi = letterFor(hi);

  let label;
  if (gLo !== gHi) label = `${gLo}–${gHi}`;
  else label = cov.partial ? `${gLo}*` : gLo;

  const risk = String(riskLevel || '').toUpperCase();
  let light = 'amber';
  if (lo === null || lo === undefined) light = 'amber';
  else if (lo < 60 || risk === 'CRITICAL' || risk === 'HIGH') light = 'red';
  else if (!cov.partial && lo >= 80 && risk.startsWith('LOW')) light = 'green';

  return { label, light, partial: cov.partial, coverage: cov };
}

export function buildVerdict(findings = [], grade) {
  const count = (s) => findings.filter((f) => String(f.severity).toUpperCase() === s).length;
  const crit = count('CRITICAL');
  const high = count('HIGH');
  const med = count('MEDIUM');
  const top = findings.find((f) => ['CRITICAL', 'HIGH'].includes(String(f.severity).toUpperCase()));

  let text;
  if (crit + high > 0) {
    text = `This tunnel has ${crit + high} serious weakness${crit + high > 1 ? 'es' : ''}` +
      (top?.title ? `, the most urgent being: ${top.title}.` : '.');
  } else if (med > 0) {
    text = `No serious weaknesses were found, but ${med} moderate issue${med > 1 ? 's' : ''} should be reviewed.`;
  } else {
    text = 'No weaknesses were found in the parts of the tunnel that can be observed.';
  }
  if (grade?.partial) {
    text += ' Some settings are encrypted on the wire and could not be observed, so this result is provisional.';
  }
  return text;
}

// Plain-English tooltips for jargon.
export const GLOSSARY = {
  PFS: 'Perfect Forward Secrecy: a leaked long-term key cannot decrypt past traffic.',
  ESP: 'Encapsulating Security Payload: the part of IPsec that carries the encrypted data.',
  IKE: 'Internet Key Exchange: the handshake where the two ends agree on keys and algorithms.',
  'DH group': 'Diffie-Hellman group: the math used to agree on a shared secret. Bigger is stronger.',
  Coverage: 'How many of the 8 security controls could be seen from the capture alone.',
};
