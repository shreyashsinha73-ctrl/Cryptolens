/**
 * Single source of truth helper for threat matrix & anomaly deduplication and counts.
 */

export function normalizeSeverity(severity) {
  const s = String(severity || 'INFO').toUpperCase().trim();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(s)) {
    return s;
  }
  if (s === 'MODERATE' || s === 'WARN' || s === 'WARNING') return 'MEDIUM';
  if (s === 'ERROR') return 'HIGH';
  return 'INFO';
}

export function mergeThreatsAndAnomalies(threatMatrix = [], anomalyAlerts = []) {
  const merged = new Map();

  // 1. Protocol Findings from PCAP Static Analysis
  (threatMatrix || []).forEach(t => {
    if (!t) return;
    const id = t.finding_id || t.id || `${t.title || 'finding'}-${t.category || 'general'}`;
    const sev = normalizeSeverity(t.severity);
    merged.set(id, {
      ...t,
      finding_id: id,
      title: t.title || t.finding || id,
      description: t.description || t.detail || 'Protocol finding',
      category: t.category || t.threat_category || 'Protocol Finding',
      severity: sev,
      is_anomaly: false,
    });
  });

  // 2. Statistical Anomalies from Live PyOD / stream
  (anomalyAlerts || []).forEach(a => {
    if (!a) return;
    const id = a.finding_id || `ANOMALY-${a.anomaly_label || 'STATISTICAL'}`;
    if (!merged.has(id)) {
      const sev = normalizeSeverity(a.severity || 'HIGH');
      merged.set(id, {
        ...a,
        finding_id: id,
        title: a.title || (a.anomaly_label ? a.anomaly_label.replace(/_/g, ' ') : 'Statistical Anomaly'),
        description: a.description || a.anomaly_reason || 'Anomaly detected in flow characteristics',
        severity: sev,
        category: a.category || 'Statistical Anomaly',
        is_anomaly: true,
        source: 'PyOD Isolation Forest',
      });
    }
  });

  return Array.from(merged.values());
}

export function getThreatCounts(threats = []) {
  const counts = {
    total: threats.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    protocolCount: 0,
    anomalyCount: 0,
  };

  (threats || []).forEach(t => {
    const sev = normalizeSeverity(t.severity).toLowerCase();
    if (counts[sev] !== undefined) {
      counts[sev]++;
    }
    if (t.is_anomaly) {
      counts.anomalyCount++;
    } else {
      counts.protocolCount++;
    }
  });

  return counts;
}
