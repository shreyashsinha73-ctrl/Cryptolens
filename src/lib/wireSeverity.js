/**
 * Pure helper deriving packet severity strictly matching existing panel logic.
 * Zero decrypted payloads - metadata only.
 *
 * Rules:
 * - 'critical': packet.severity === 'CRITICAL' || packet.is_replay
 * - 'medium': packet.severity === 'WARNING' || packet.severity === 'MEDIUM' || packet.severity === 'HIGH'
 * - 'low': default for all other standard packets (e.g. 'LOW', 'SECURE', or default ESP/IKE)
 */
export function getPacketSeverity(pkt) {
  if (!pkt) return 'low';
  if (pkt.severity === 'CRITICAL' || pkt.is_replay) return 'critical';
  if (pkt.severity === 'WARNING' || pkt.severity === 'MEDIUM' || pkt.severity === 'HIGH') return 'medium';
  return 'low';
}
