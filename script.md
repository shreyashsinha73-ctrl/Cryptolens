# CryptoLens – Live Demo Script (5:15, under 6 minutes)

**Total runtime:** 5 min 15 s, which leaves a 45 s buffer under the 6-minute limit. The most important material comes first (hook → architecture → good vs bad tunnel → score). Secondary features follow, and every feature gets time.

**Before you hit record**
- Run `npm run dev:all` and open `http://localhost:5173` (empty state).
- Keep ready:
  - Good capture: `captures/config_01_tunnel_aes256gcm_dh19_pfson_all.pcap`
  - Bad capture: `captures/config_06_tunnel_3des_sha1_dh2_pfsoff_all.pcap`
  - Mid-session capture: `ipsec_test_icmp.pcap` (12 packets: 2 IKE messages plus 10 ESP packets, ICMP traffic inside)
- Open Wireshark with the good capture in a second window, plus the README Mermaid diagram.
- Optional: set `ENABLE_CLOUD_LLM=true` to show cloud AI. Otherwise show the air-gapped template mode.

---

## 0:00 – 0:25 | Hook & Problem
**Screen:** Wireshark (opaque ESP), then the CryptoLens dashboard in its empty state.

> "This is an IPsec tunnel in Wireshark. Every packet is encrypted and looks secure. But a tunnel can silently use 3DES, a weak Diffie-Hellman group, or run without Perfect Forward Secrecy, and nothing on the wire tells you. Auditing this has traditionally needed endpoint keys or credentials. CryptoLens does it passively: no keys, no decryption."

## 0:25 – 1:00 | Architecture & Pipeline
**Screen:** Mermaid end-to-end pipeline diagram.

> "The pipeline has four stages. Stage 1 is a strongSwan testbed that produces ground-truth captures for seven configurations. Stage 2 is a passive demux that separates IKE handshake packets from ESP data packets. Stage 3 runs two tracks in parallel. The control-plane parser reads the cleartext IKEv1 and IKEv2 handshake deterministically, using tshark with a pure-Python fallback. The data-plane 1D CNN reads only packet lengths and inter-arrival times to classify tunnel mode and inner traffic. Both feed the scoring and compliance engine for NIST SP 800-77 and NSA CNSA 2.0. Stage 4 is this React SOC portal and the PDF report engine."

## 1:00 – 1:45 | Good Tunnel: Upload & Dashboard
**Screen:** Upload page → drag in `config_01` → Dashboard.

> "Let's start with a well-configured tunnel. I upload the capture. The backend demuxes it, parses the handshake and scores it. The status banner reads Tunnel Active and Audited: AES-256-GCM, DH group 19, PFS on. The score dial counts up to 100 out of 100 with zero threats."

Point out, in order:
1. Score dial and risk level.
2. **Analysis Dimensions** bars: Cipher Strength, Key Exchange, Mode & PFS, Metadata Exposure, PQC Readiness.
3. **Compliance Radar**: toggle between NIST SP 800-77 and CNSA 2.0 and show the profile assessment badge.

## 1:45 – 2:35 | Bad Tunnel: Score Collapse (key moment)
**Screen:** Upload `config_06` (3DES / DH2 / PFS off).

> "Now a misconfigured tunnel. On the wire it looks exactly the same. But CryptoLens catches 3DES, DH group 2 and no PFS, and the score collapses from 100 to 45, CRITICAL."

Point out:
- **Threat heatmap:** Sweet32 on 3DES and the weak DH group turn red.
- **Attacker-impact cards:** each weakness explained in plain language, so a non-expert understands the real-world risk.
- **Before/After diff:** the current weak parameters next to the hardened ones.

## 2:35 – 3:15 | Remediation, PDF Reports & AI Insights
**Screen:** Remediation modal → Reports page → AI Insights page.

> "Finding a problem is half the job, so CryptoLens fixes it too. One click generates a hardened `swanctl.conf` from a Jinja2 template. The Reports page exports an executive PDF for management and a technical PDF with the full threat table and remediation steps. The AI Insights page adds plain-language advice. With cloud AI off, it falls back to deterministic templates, so the whole platform works fully air-gapped, which matters for defense and critical-infrastructure networks."

## 3:15 – 4:05 | Mid-Session Capture & Why Some Dimensions Are "Not Observable"
**Screen:** Upload `ipsec_test_icmp.pcap` → Dashboard → Findings & Compliance → **Analysis Dimensions** card.

> "Now the hard case: a capture taken mid-session. It has only a couple of IKE messages and a few ESP packets, with ICMP inside. Let's look at the Analysis Dimensions. Cipher Strength and Mode & PFS read **not observable**. That is deliberate, and it is the honest answer."

**Explain *why*, in this order (this is the key talking point):**
1. **Cipher Strength:** "The cipher for the actual data tunnel, the Child SA, is negotiated inside the IKE_AUTH exchange. That message is encrypted, and the ESP packet header carries no algorithm identifier. With no keys, the cipher simply is not on the wire."
2. **Mode & PFS:** "Whether PFS is on depends on a key-exchange payload inside the encrypted Child SA setup, and tunnel vs transport is declared in that same encrypted block. In this capture the IKE_SA_INIT is also missing, so there is nothing in cleartext to read it from."
3. **The principle:** "CryptoLens never guesses. A missing value is never treated as secure and never as failing. It is shown as **not observable**, with the evidence source, and it is excluded from the score instead of being invented."
4. **What *is* observable:** "Other dimensions can still be read from the metadata that is visible, and the 1D CNN independently classifies the mode and the inner traffic, ICMP in this case, from packet sizes and timing, with an agreement flag against a heuristic baseline."
5. **The fix:** "If the operator knows the tunnel's configuration, they can supply it as a sidecar file. Those values are then clearly tagged operator-supplied, and the missing dimensions light up."

> "That is the difference between an auditor you can trust and a tool that fills in the blanks."

## 4:05 – 4:30 | Explainability & Anomaly Detection
**Screen:** Threat heatmap on the Dashboard, then the Findings page.

> "We don't want a black box. Grad-CAM saliency highlights which packet positions drove the CNN's decision, and the threat localizer pinpoints the suspicious regions. An Isolation Forest anomaly detector separately flags unusual ESP flow behavior."

## 4:30 – 4:55 | Live Monitor & Replay Protection
**Screen:** Live Monitor page → start the simulator → inject a duplicate packet.

> "On the Live Monitor, packets stream over WebSocket into the live wire graph in real time. I inject a duplicate ESP packet, and the Anti-Replay indicator flips to CONFIRMED. I can also click any packet for an AI explanation."

## 4:55 – 5:15 | Findings, Testbed & Close
**Screen:** Findings & Compliance page → Testbed page → closing slide.

> "The Findings page lists every NIST and CNSA check with its status. The Testbed page lets me ingest any of the seven ground-truth configurations or inject traffic with one click. To recap: dual-plane analysis, explainable scoring, automated remediation, PDF reporting, and honest, air-gapped-ready auditing. CryptoLens: see inside the tunnel without breaking it. Thank you."

---

## Feature Coverage Checklist
| Feature | Covered at |
|---|---|
| Passive, keyless audit concept | 0:00 |
| strongSwan testbed and ground-truth configs | 0:25 / 4:55 |
| Demux (IKE vs ESP) | 0:25 |
| Control-plane IKEv1/v2 parser (tshark + Python) | 0:25 |
| 1D CNN data-plane classifier | 0:25 / 3:15 |
| NIST SP 800-77 and CNSA 2.0 scoring | 0:25 / 1:00 |
| Upload page, score dial, Analysis Dimensions, Compliance Radar | 1:00 |
| Threat heatmap, attacker-impact cards, Before/After diff | 1:45 |
| Remediation engine (hardened swanctl.conf) | 2:35 |
| PDF reports (executive and technical) | 2:35 |
| AI Insights and air-gapped template fallback | 2:35 |
| Mid-session capture, "not observable" reasoning, operator sidecar | 3:15 |
| XAI saliency and threat localizer | 4:05 |
| Anomaly detector (Isolation Forest) | 4:05 |
| Live Monitor, WebSocket stream, packet explain | 4:30 |
| Replay-protection test | 4:30 |
| Findings and Compliance page | 4:55 |
| Testbed page (ingest and inject) | 4:55 |

## Timing Tips
- Each segment is about 60–110 spoken words. Rehearse once with a stopwatch.
- If running long, shorten the architecture and XAI segments first. Never cut the good-vs-bad contrast or the "not observable" explanation.

