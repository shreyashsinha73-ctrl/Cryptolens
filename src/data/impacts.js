// Single source for attacker-impact wording and references.
// Only references that are certain: CVE-2016-2183 (Sweet32), CVE-2015-4000 (Logjam).
export const IMPACTS = [
  {
    id: 'no_pfs',
    match: /\bPFS\b|forward secrecy/i,
    heading: 'No Perfect Forward Secrecy',
    impact: 'If a long-term key leaks later, traffic recorded in the past can be decrypted.',
    reference: null,
  },
  {
    id: 'sweet32',
    match: /3DES|Sweet32|\bDES\b/i,
    heading: '64-bit block cipher (3DES)',
    impact: 'Practical only at very high data volumes on one key; the risk is theoretical for typical tunnels.',
    reference: 'CVE-2016-2183 (Sweet32)',
  },
  {
    id: 'weak_dh',
    match: /DH\s*(1|2|5)\b|Group\s*(1|2|5)\b|1024-bit|Logjam/i,
    heading: '1024-bit Diffie-Hellman',
    impact: 'Within reach of nation-state precomputation, so recorded key exchanges could be broken.',
    reference: 'CVE-2015-4000 (Logjam)',
  },
  {
    id: 'sha1',
    match: /SHA-?1\b/i,
    heading: 'SHA-1 integrity',
    impact: 'Legacy algorithm that should be retired. This does not claim the tunnel is broken.',
    reference: null,
  },
];

export function impactsFor(findings = []) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const text = `${f.title || ''} ${f.category || ''}`;
    for (const imp of IMPACTS) {
      if (!seen.has(imp.id) && imp.match.test(text)) {
        seen.add(imp.id);
        out.push({ ...imp, severity: f.severity, finding: f.title });
      }
    }
  }
  return out;
}
