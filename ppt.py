#!/usr/bin/env python3
"""CryptoLens - SIH 6-slide deck generator.  pip install python-pptx ; python build_cryptolens_deck.py"""
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
from lxml import etree

NAVY, PANEL = RGBColor(0x0A, 0x11, 0x28), RGBColor(0x0D, 0x15, 0x27)
CARD = RGBColor(0x13, 0x1E, 0x3A)
BLUE, LBLUE = RGBColor(0x3B, 0x82, 0xF6), RGBColor(0x60, 0xA5, 0xFA)
AMBER, GOLD = RGBColor(0xF5, 0x9E, 0x0B), RGBColor(0xEA, 0xB3, 0x08)
WHITE, MUTED = RGBColor(0xF8, 0xFA, 0xFC), RGBColor(0xA8, 0xB3, 0xC7)
FONT = "Calibri"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
BLANK = prs.slide_layouts[6]


def rect(s, x, y, w, h, fill=CARD, line=None, shape=MSO_SHAPE.RECTANGLE):
    r = s.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    r.fill.solid(); r.fill.fore_color.rgb = fill
    if line: r.line.color.rgb = line; r.line.width = Pt(1.25)
    else: r.line.fill.background()
    r.shadow.inherit = False
    return r


def text(s, x, y, w, h, runs, size=12, color=WHITE, bold=False, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, bullets=False, space=3):
    """runs: str or list of str / (str, {color,bold,size}) paragraphs."""
    tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame; tf.word_wrap = True; tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.05); tf.margin_top = tf.margin_bottom = Inches(0.03)
    items = [runs] if isinstance(runs, str) else runs
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align; p.space_after = Pt(space)
        segs = it if isinstance(it, list) else [it]
        for seg in segs:
            t, o = seg if isinstance(seg, tuple) else (seg, {})
            r = p.add_run(); r.text = ("•  " + t if bullets and seg is segs[0] else t)
            r.font.name = FONT; r.font.size = Pt(o.get("size", size))
            r.font.bold = o.get("bold", bold); r.font.color.rgb = o.get("color", color)
    return tb


def base(title, tag, n):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid(); s.background.fill.fore_color.rgb = NAVY
    rect(s, 0, 0, 0.14, 7.5, AMBER)
    text(s, 0.45, 0.28, 10.5, 0.3, tag, 11, AMBER, True)
    text(s, 0.45, 0.55, 12.4, 0.7, title, 26, WHITE, True)
    rect(s, 0.5, 1.25, 12.3, 0.04, BLUE)
    text(s, 0.45, 7.1, 8, 0.3, "CryptoLens  |  Team Bauna-Appetite  |  SIH 2025", 9, MUTED)
    text(s, 12.0, 7.1, 0.9, 0.3, f"{n} / 6", 9, MUTED, align=PP_ALIGN.RIGHT)
    return s


def card(s, x, y, w, h, head, lines, accent=BLUE, size=11, bullets=True):
    rect(s, x, y, w, h, CARD, accent)
    rect(s, x, y, w, 0.06, accent)
    text(s, x + 0.12, y + 0.12, w - 0.24, 0.35, head, 13, accent if accent != BLUE else LBLUE, True)
    text(s, x + 0.12, y + 0.5, w - 0.24, h - 0.55, lines, size, WHITE, bullets=bullets)


def badge(s, x, y, w, label, fill=AMBER, fg=NAVY, h=0.42, size=11):
    r = rect(s, x, y, w, h, fill, shape=MSO_SHAPE.ROUNDED_RECTANGLE)
    text(s, x, y, w, h, label, size, fg, True, PP_ALIGN.CENTER, MSO_ANCHOR.MIDDLE)


def table(s, x, y, w, rows, widths, row_h=0.8, size=10):
    gs = s.shapes.add_table(len(rows), len(rows[0]), Inches(x), Inches(y), Inches(w), Inches(row_h * len(rows)))
    t = gs.table
    gs._element.graphic.graphicData.tbl.tblPr.set("bandRow", "0")
    for i, wd in enumerate(widths): t.columns[i].width = Inches(wd)
    for ri, row in enumerate(rows):
        t.rows[ri].height = Inches(0.4 if ri == 0 else row_h)
        for ci, val in enumerate(row):
            c = t.cell(ri, ci); c.fill.solid()
            c.fill.fore_color.rgb = AMBER if ri == 0 else (CARD if ri % 2 else PANEL)
            c.vertical_anchor = MSO_ANCHOR.MIDDLE
            c.margin_left = c.margin_right = Inches(0.08)
            tf = c.text_frame; tf.word_wrap = True
            head, _, rest = val.partition("::")
            p = tf.paragraphs[0]
            r = p.add_run(); r.text = head; r.font.name = FONT; r.font.size = Pt(size)
            r.font.bold = ri == 0 or bool(rest) or ci == 0
            r.font.color.rgb = NAVY if ri == 0 else (GOLD if ci < 2 and rest else WHITE)
            if rest:
                r2 = p.add_run(); r2.text = rest; r2.font.name = FONT; r2.font.size = Pt(size); r2.font.color.rgb = WHITE
            for edge in ("a:lnL", "a:lnR", "a:lnT", "a:lnB"):  # table borders
                tcPr = c._tc.get_or_add_tcPr()
                ln = etree.SubElement(tcPr, qn(edge), w="12700")
                sf = etree.SubElement(ln, qn("a:solidFill"))
                etree.SubElement(sf, qn("a:srgbClr"), val="3B82F6")
    return t


def notes(s, t): s.notes_slide.notes_text_frame.text = t


# ───────────── SLIDE 1 ─────────────
s = prs.slides.add_slide(BLANK)
s.background.fill.solid(); s.background.fill.fore_color.rgb = NAVY
rect(s, 0, 0, 13.333, 0.9, PANEL); rect(s, 0, 0.9, 13.333, 0.05, AMBER)
text(s, 0.6, 0.25, 12, 0.5, "SMART INDIA HACKATHON 2025 / 2026  —  IDEA SUBMISSION", 16, AMBER, True)
text(s, 0.6, 1.25, 12, 0.4, [[("Problem Statement ID: ", {"color": MUTED}), ("[Insert PS ID / SIH-PS-IPSEC-01]", {"color": WHITE, "bold": True})]], 13)
text(s, 0.6, 1.65, 12.1, 0.8, "Design and Development of an AI-Driven Protocol Analysis Platform for IPsec Deployments", 20, LBLUE, True)
text(s, 0.6, 2.55, 12, 1.0, "CryptoLens", 54, WHITE, True)
text(s, 0.6, 3.6, 12, 0.5, "Intelligent Protocol Analysis, Cryptographic Auditing & Encrypted Traffic Classification Framework", 18, GOLD, True)
meta = [("Theme", "Cybersecurity / Smart Automation / Defense Infrastructure"),
        ("Category", "Software Prototype & AI Engine"),
        ("Team", "[Insert Team ID]  |  Team Bauna-Appetite")]
for i, (k, v) in enumerate(meta):
    rect(s, 0.6 + i * 4.1, 4.4, 3.95, 0.95, CARD, BLUE)
    text(s, 0.7 + i * 4.1, 4.45, 3.8, 0.3, k.upper(), 10, AMBER, True)
    text(s, 0.7 + i * 4.1, 4.75, 3.8, 0.6, v, 13, WHITE, True)
for i, b in enumerate(["Deterministic Control-Plane Parser", "1D CNN Encrypted ESP Inference",
                       "NIST SP 800-77 / CNSA 2.0 Compliance", "1-Click Auto-Remediation"]):
    badge(s, 0.6 + i * 3.08, 5.9, 2.95, b, AMBER if i % 2 == 0 else BLUE, NAVY if i % 2 == 0 else WHITE, 0.55, 11)
notes(s, "Open with the hook: IPsec protects the most sensitive links in the country, yet nobody audits how well. "
         "We are Team Bauna-Appetite and CryptoLens is our answer to this PS. In one line: it reads the IKE handshake deterministically, "
         "classifies encrypted ESP traffic with a 1D CNN without decrypting anything, scores the tunnel against NIST and CNSA 2.0, "
         "and hands back a hardened swanctl.conf. The four badges are the four things to remember. (~30 seconds)")

# ───────────── SLIDE 2 ─────────────
s = base("Automated Multi-Dimensional Cryptographic Auditor & Non-Invasive Encrypted Traffic Classifier",
         "IDEA TITLE & PROBLEM RESOLUTION", 2)
feats = [("1  strongSwan Testbed", "Docker mesh with 6+1 profiles: tunnel/transport, AES-GCM-128/256, CBC, DH 2/5/14/19, PFS on/off, IPv4/IPv6."),
         ("2  Deterministic AST IKE Dissector", "Zero-false-positive extraction of transforms, ciphers, PRF, DH IDs, SA lifetimes from IKE_SA_INIT / IKE_AUTH."),
         ("3  1D CNN ESP Inference", "ONNX model on packet lengths (S_L) + inter-arrival times (S_IAT), 30-packet window: VoIP / Video / Web / ICMP, no decryption."),
         ("4  Compliance Scoring Engine", "Weighted 0–100 score vs NIST SP 800-77 Rev.1 & CNSA 2.0: weak ciphers, missing PFS, replay window off."),
         ("5  Remediation & PDF Reports", "Hardened swanctl.conf snippets + Executive and Technical compliance PDFs.")]
for i, (h, b) in enumerate(feats):
    y = 1.45 + i * 0.86
    rect(s, 0.5, y, 7.3, 0.78, CARD, BLUE)
    text(s, 0.62, y + 0.03, 7.1, 0.3, h, 12, LBLUE, True)
    text(s, 0.62, y + 0.3, 7.1, 0.5, b, 10)
card(s, 8.0, 1.45, 4.8, 1.95, "The Problem", [
    "IPsec weaknesses are invisible to perimeter tools: 3DES / AES-CBC, DH2/5, no PFS, aggressive mode, split-tunnel.",
    "Wireshark is manual and blind to ESP payloads."], AMBER, 10.5)
card(s, 8.0, 3.5, 4.8, 1.45, "Our Solution", [
    "Control-plane dissection + data-plane ML → automated risk score, live threat detection, instant config repair."], BLUE, 10.5)
card(s, 8.0, 5.05, 4.8, 1.95, "Why We Win", [
    "Dual-plane: deterministic parser + statistical learning",
    "Zero privacy violation: no decryption, no TLS termination",
    "Closed loop: detect → score → remediate"], GOLD, 10.5)
notes(s, "Walk the five features left to right as one pipeline. Stress what is different: Wireshark is passive and manual, NIDS is signature-based. "
         "We combine a zero-error parser for what is visible (IKE) with ML for what is hidden (ESP). The CNN only sees packet sizes and timing, so privacy is preserved. "
         "End on the actionable loop: judges love that we do not stop at a report, we output the fix. (~75 seconds)")

# ───────────── SLIDE 3 ─────────────
s = base("Technical Approach: Dual-Track Ingestion & Analysis Pipeline", "PIPELINE ARCHITECTURE & TECHNOLOGIES", 3)
stages = [("TRACK 1  Testbed & Ingestion", "Dockerized strongSwan + Scapy / tshark → Demuxer (UDP 500/4500 vs IP proto 50)", BLUE),
          ("TRACK 2  Control-Plane Engine", "IKE Parser → SA State Extractor → Crypto Profile (cipher, DH, PFS, lifetime)", LBLUE),
          ("TRACK 3  Data-Plane AI Engine", "ESP stream → Features (S_L, S_IAT, entropy) → 1D CNN (ONNX) → Agreement Engine + Gemini fallback", AMBER),
          ("TRACK 4  Assessment & UI", "NIST 800-77 Scoring Matrix → Threat & Replay Detector → React SOC Dashboard + WeasyPrint PDFs", GOLD)]
for i, (h, b, c) in enumerate(stages):
    x = 0.5 + i * 3.1
    rect(s, x, 1.5, 2.9, 1.9, CARD, c); rect(s, x, 1.5, 2.9, 0.07, c)
    text(s, x + 0.1, 1.62, 2.7, 0.35, h, 11.5, c, True)
    text(s, x + 0.1, 2.0, 2.7, 1.35, b, 10.5)
    if i < 3: text(s, x + 2.88, 2.2, 0.25, 0.4, "▶", 14, AMBER, True)
text(s, 0.5, 3.6, 6, 0.35, "FRAMEWORKS & TECHNOLOGIES", 13, AMBER, True)
stack = [("1  VPN Emulation", "strongSwan 5.9+, Docker Compose, Netfilter / XFRM"),
         ("2  Dissection", "Scapy 2.5+, tshark, PyShark, raw socket buffers"),
         ("3  AI / Neural Net", "PyTorch → ONNX Runtime, 1D CNN, latency < 12 ms"),
         ("4  LLM Fallback", "Gemini 1.5 Flash: zero-shot anomaly rationale"),
         ("5  Assessment", "Custom NIST SP 800-77 Rev.1 & CNSA 2.0 matrix"),
         ("6  Remediation", "Jinja2 templates: strongSwan / Libreswan / Cisco IOS"),
         ("7  Delivery", "FastAPI (Py 3.11 async), React 18, Tailwind, Lucide, WeasyPrint")]
for i, (h, b) in enumerate(stack):
    col, row = i % 4, i // 4
    x, y = 0.5 + col * 3.1, 4.0 + row * 1.5
    rect(s, x, y, 2.9, 1.3, CARD, BLUE)
    text(s, x + 0.1, y + 0.08, 2.7, 0.3, h, 12, LBLUE, True)
    text(s, x + 0.1, y + 0.45, 2.7, 0.8, b, 10.5)
badge(s, 9.8, 5.35, 2.9, "Inference < 12 ms", AMBER, NAVY, 0.5, 13)
badge(s, 9.8, 6.0, 2.9, "ONNX < 20 MB footprint", BLUE, WHITE, 0.5, 13)
notes(s, "Trace one packet: it enters Track 1; IKE goes to Track 2, ESP goes to Track 3. Both converge in Track 4 where the score is computed. "
         "Emphasize the agreement engine: if CNN confidence is low, Gemini provides a second opinion and a human-readable rationale, so we never present a weak guess as fact. "
         "Mention the stack is all open source and runs on commodity Linux. (~75 seconds)")

# ───────────── SLIDE 4 ─────────────
s = base("Feasibility and Viability", "FEASIBILITY OF IDEA  |  RISKS vs SOLUTIONS", 4)
pill = [("Technical", "Built on IETF RFC 7296 (IKEv2) & RFC 4303 (ESP); ONNX < 20 MB suits edge gateways.", BLUE),
        ("Operational", "Passive SPAN / mirror ingestion: no latency, no inline-drop risk.", LBLUE),
        ("Scalability", "Async FastAPI workers: multi-GB PCAPs, 10,000+ pkts/sec live.", AMBER),
        ("Deployability", "Single Docker image: on-prem, cloud VPS, sovereign networks.", GOLD)]
for i, (h, b, c) in enumerate(pill):
    card(s, 0.5 + i * 3.1, 1.45, 2.95, 1.45, h, [b], c, 10.5, False)
rows = [["#", "Potential Challenge / Risk", "Proposed Solution / CryptoLens Mitigation"],
        ["1", "Mid-session ESP:: captures miss the IKE handshake.", "Engine flags unobservable parameters explicitly; CNN infers payload profile from ESP length dynamics without IKE state."],
        ["2", "Padding & obfuscation:: ESP padding masks sizes.", "Model uses cumulative IAT and burst patterns, which constant padding cannot hide."],
        ["3", "Model drift:: new apps change signatures.", "Retraining on synthetic testbed streams; Gemini consensus flags low-confidence inferences."],
        ["4", "High-throughput drops:: loss at line rate.", "Zero-copy ring buffer (tshark / AF_PACKET) + async queues in FastAPI."],
        ["5", "False remediation:: bad config severs tunnels.", "Preview diffs, syntax check via swanctl --test, non-destructive fallback config."]]
table(s, 0.5, 3.1, 12.3, rows, [0.5, 3.8, 8.0], 0.6, 10.5)
notes(s, "Top row: why this is buildable today, with standards-based parsing and a tiny runtime. Then the table, which is where judges probe. "
         "Lead with risk 1: real captures often start mid-session, and we handle it honestly by reporting what is unobservable instead of guessing. "
         "Risk 5 is our safety story: we never push config blindly; we diff, validate, and keep a rollback. (~75 seconds)")

# ───────────── SLIDE 5 ─────────────
s = base("Impact and Benefits", "POTENTIAL & IMPACT", 5)
rect(s, 0.5, 1.45, 12.3, 0.95, PANEL, AMBER)
text(s, 0.65, 1.5, 9.4, 0.9, ["Shields defense backbones and enterprise networks from silent cryptographic degradation and quantum-vulnerable key exchange.",
                              "Cuts mean-time-to-audit from hours of manual Wireshark analysis to sub-minute automated scoring."], 11.5)
badge(s, 10.3, 1.7, 2.35, "Hours → < 1 min", AMBER, NAVY, 0.5, 13)
q = [("1  Security & Strategic", BLUE, ["Visibility into encrypted tunnels without breaking privacy", "Defends against \"Harvest Now, Decrypt Later\" via CNSA 2.0 guidance", "Detects replay-counter tampering and split-tunnel leaks"]),
     ("2  Economic & Operational", LBLUE, ["Frees Tier-2/3 analysts via auto Executive & Technical PDFs", "No proprietary appliance: commodity Linux or edge hardware"]),
     ("3  Compliance & Audit", AMBER, ["Maps to NIST SP 800-77 Rev.1, ISO 27001, DoD / CNSA 2.0", "Instant crypto-compliance evidence for defense & finance audits"]),
     ("4  Financial Savings", GOLD, ["Avoids breach fines and outages from severed or intercepted VPNs", "Replaces costly proprietary enterprise network analyzers"])]
for i, (h, c, l) in enumerate(q):
    card(s, 0.5 + (i % 2) * 6.2, 2.6 + (i // 2) * 2.2, 6.1, 2.05, h, l, c, 11.5)
notes(s, "Open with the quantified claim: hours to under a minute. Then one quadrant per breath. For the strategic quadrant, explain Harvest-Now-Decrypt-Later: "
         "adversaries record encrypted traffic today and break it with quantum computers later, so weak DH groups are a long-term national risk. "
         "Close on cost: no appliance, no licence. (~60 seconds)")

# ───────────── SLIDE 6 ─────────────
s = base("Research and References", "DOCUMENTATION, STANDARDS & LITERATURE", 6)
card(s, 0.5, 1.45, 6.1, 3.3, "Documentation & Standards", [
    "NIST SP 800-77 Rev. 1: Guide to IPsec VPNs",
    "IETF RFC 7296 (IKEv2) and RFC 4303 (ESP)",
    "NSA CNSA 2.0: Commercial National Security Algorithm Suite 2.0",
    "NIST SP 800-52 Rev. 2 and FIPS 140-3"], BLUE, 12)
card(s, 6.7, 1.45, 6.1, 3.3, "Research Papers & Literature", [
    "Taylor et al., IEEE S&P: AppScanner, fingerprinting smartphone apps from encrypted traffic",
    "Wang et al., Computers & Security: end-to-end encrypted traffic classification with 1D CNNs",
    "Anderson & McGrew, ACM CCS: identifying encrypted malware traffic via contextual flow data"], AMBER, 12)
rect(s, 0.5, 4.95, 12.3, 2.0, PANEL, GOLD)
text(s, 0.5, 5.0, 12.3, 0.8, "Thank You!", 38, GOLD, True, PP_ALIGN.CENTER)
text(s, 0.5, 5.8, 12.3, 0.4, "Team Bauna-Appetite  |  CryptoLens: Securing Every Layer, Auditing Every Packet.", 15, WHITE, True, PP_ALIGN.CENTER)
text(s, 0.5, 6.35, 12.3, 0.4, "Live Demo: http://localhost:5173   |   API Docs: /docs   |   GitHub: [Insert repository link]", 12, LBLUE, False, PP_ALIGN.CENTER)
notes(s, "Say that every design choice traces to a standard or a peer-reviewed result: NIST and CNSA define 'good' configuration, RFCs define what we parse, "
         "and the three papers justify classifying encrypted traffic from length and timing. Then pivot straight to the live demo: upload a PCAP, show the score, "
         "click remediation. Verify the paper titles/venues against the originals before submission. (~45 seconds + demo)")

prs.save("CryptoLens_SIH_Deck.pptx")
print("Saved CryptoLens_SIH_Deck.pptx")