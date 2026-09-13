"""
PDF Security Assessment Report Generator (backend/services/pdf_generator.py)
Generates high-fidelity Executive and Technical PDF reports based on
real deterministic analysis results, standards compliance, and threat matrices.
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_report(job_data: Dict[str, Any], report_type: str = "executive") -> bytes:
    """
    Generates a clean, professional PDF security report from job analysis data.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    COLOR_PRIMARY = colors.HexColor("#0f172a")     # Slate 900
    COLOR_ACCENT = colors.HexColor("#2563eb")      # Blue 600
    COLOR_BORDER = colors.HexColor("#e2e8f0")      # Slate 200
    COLOR_BG_LIGHT = colors.HexColor("#f8fafc")    # Slate 50
    COLOR_TEXT = colors.HexColor("#334155")        # Slate 700
    COLOR_MUTED = colors.HexColor("#64748b")       # Slate 500

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=COLOR_PRIMARY
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=COLOR_MUTED
    )

    h2_style = ParagraphStyle(
        "Heading2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=COLOR_PRIMARY,
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=COLOR_TEXT
    )

    bold_style = ParagraphStyle(
        "Bold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13.5,
        textColor=COLOR_PRIMARY
    )

    story: List[Any] = []

    # --- Header Banner ---
    job_id = job_data.get("job_id", "N/A")
    summary = job_data.get("summary") or {}
    cp = job_data.get("control_plane") or {}
    dp = job_data.get("data_plane") or {}
    threats = job_data.get("threat_matrix", [])
    telemetry = job_data.get("demux_telemetry", {})

    report_title_str = (
        "IPsec VPN Security Assessment — Executive Report"
        if report_type.lower() == "executive"
        else "IPsec VPN Security Assessment — Technical Report"
    )

    story.append(Paragraph(report_title_str, title_style))
    story.append(Spacer(1, 4))
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"<b>Job ID:</b> {job_id} &nbsp;&nbsp;|&nbsp;&nbsp; <b>Evaluated At:</b> {gen_time}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_ACCENT, spaceBefore=0, spaceAfter=14))

    # --- Executive Summary Card ---
    risk_score = summary.get("overall_risk_score", 0)
    risk_level = summary.get("risk_level", "LOW")
    
    if risk_level == "LOW":
        badge_bg = colors.HexColor("#dcfce7")
        badge_text = colors.HexColor("#166534")
    elif risk_level in ("MEDIUM", "ELEVATED"):
        badge_bg = colors.HexColor("#fef3c7")
        badge_text = colors.HexColor("#92400e")
    elif risk_level == "HIGH":
        badge_bg = colors.HexColor("#fee2e2")
        badge_text = colors.HexColor("#991b1b")
    else:  # CRITICAL or other
        badge_bg = colors.HexColor("#fee2e2")
        badge_text = colors.HexColor("#7f1d1d")


    score_text = f"<b>{risk_score}/100</b> ({risk_level} RISK)"
    confidence_text = f"{int(summary.get('ai_confidence_score', 1.0) * 100)}% (Ground Truth Parsing)"

    overview_data = [
        [
            Paragraph("<b>Overall Posture Score</b>", body_style),
            Paragraph(score_text, ParagraphStyle("Score", parent=bold_style, textColor=badge_text)),
            Paragraph("<b>Evaluation Standard</b>", body_style),
            Paragraph("NIST SP 800-77 Rev 1 / CNSA 2.0", bold_style)
        ],
        [
            Paragraph("<b>IKE Version</b>", body_style),
            Paragraph(str(cp.get("ike_version", "N/A")), bold_style),
            Paragraph("<b>Tunnel Operating Mode</b>", body_style),
            Paragraph(str(cp.get("operating_mode", "N/A")), bold_style)
        ],
        [
            Paragraph("<b>Confidence Score</b>", body_style),
            Paragraph(confidence_text, bold_style),
            Paragraph("<b>Threat Findings Count</b>", body_style),
            Paragraph(f"<b>{len(threats)}</b> item(s)", bold_style)
        ]
    ]

    t_overview = Table(overview_data, colWidths=[130, 135, 130, 135])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_LIGHT),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_overview)
    story.append(Spacer(1, 14))

    # --- Cryptographic Control-Plane Specs ---
    story.append(Paragraph("1. Control-Plane Cryptographic Parameters", h2_style))
    
    crypto_data = [
        [Paragraph("<b>Parameter</b>", bold_style), Paragraph("<b>Negotiated Value</b>", bold_style), Paragraph("<b>NIST SP 800-77 Evaluation</b>", bold_style)],
        [
            Paragraph("Encryption Algorithm (ENCR)", body_style),
            Paragraph(str(cp.get("encryption_algorithm", "N/A")), bold_style),
            Paragraph("AES-GCM preferred; CBC legacy; 3DES prohibited", body_style)
        ],
        [
            Paragraph("Integrity Algorithm (INTEG)", body_style),
            Paragraph(str(cp.get("integrity_algorithm", "N/A")), bold_style),
            Paragraph("HMAC-SHA2 family required; MD5/SHA-1 prohibited", body_style)
        ],
        [
            Paragraph("Diffie-Hellman Group", body_style),
            Paragraph(f"Group {cp.get('dh_group', 'N/A')}", bold_style),
            Paragraph("Group 14+ (>=2048-bit) or Group 19 (P-256) compliant", body_style)
        ],
        [
            Paragraph("Pseudo-Random Function (PRF)", body_style),
            Paragraph(str(cp.get("prf_algorithm", "N/A")), bold_style),
            Paragraph("Compliant PRF derived from session parameters", body_style)
        ],
        [
            Paragraph("Perfect Forward Secrecy (PFS)", body_style),
            Paragraph("ENABLED" if cp.get("pfs_enabled") else "DISABLED", bold_style),
            Paragraph("Mandatory for Child SA rekeying under NIST guidelines", body_style)
        ],
        [
            Paragraph("SA Key Lifetime", body_style),
            Paragraph(f"{cp.get('key_lifetime_seconds', 'N/A')} seconds", bold_style),
            Paragraph("Recommended <= 28800s (8 hours) to minimize key exposure", body_style)
        ],
        [
            Paragraph("Anti-Replay Protection (ESN)", body_style),
            Paragraph("ENABLED" if cp.get("replay_protection_enabled") else "DISABLED", bold_style),
            Paragraph("Extended Sequence Numbers recommended on high-speed links", body_style)
        ],
    ]

    t_crypto = Table(crypto_data, colWidths=[170, 160, 200])
    t_crypto.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_crypto)
    story.append(Spacer(1, 14))

    # --- Threat Matrix Section ---
    story.append(Paragraph(f"2. Security Vulnerabilities & Threat Matrix ({len(threats)} Findings)", h2_style))
    if not threats:
        clean_box = [
            [Paragraph("<b>No Cryptographic Vulnerabilities Detected</b><br/><font color='#166534'>The negotiated parameters meet all compliance requirements of NIST SP 800-77 Rev 1.</font>", body_style)]
        ]
        t_clean = Table(clean_box, colWidths=[530])
        t_clean.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#bbf7d0")),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(t_clean)
    else:
        threat_table_data = [
            [
                Paragraph("<b>ID</b>", bold_style),
                Paragraph("<b>Severity</b>", bold_style),
                Paragraph("<b>Category</b>", bold_style),
                Paragraph("<b>Title & Remediation Guidance</b>", bold_style)
            ]
        ]
        for t in threats:
            sev = t.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                c_color = colors.HexColor("#991b1b")
            elif sev == "HIGH":
                c_color = colors.HexColor("#b91c1c")
            elif sev == "MEDIUM":
                c_color = colors.HexColor("#b45309")
            else:
                c_color = colors.HexColor("#475569")

            sev_p = Paragraph(f"<b>{sev}</b>", ParagraphStyle("Sev", parent=bold_style, textColor=c_color))
            desc_p = Paragraph(
                f"<b>{t.get('title', '')}</b><br/>"
                f"<font color='#64748b'>{t.get('description', '')}</font>",
                body_style
            )
            threat_table_data.append([
                Paragraph(t.get("id", "VULN"), bold_style),
                sev_p,
                Paragraph(t.get("category", "General"), body_style),
                desc_p
            ])

        t_threat = Table(threat_table_data, colWidths=[55, 65, 95, 315])
        t_threat.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_threat)

    story.append(Spacer(1, 14))

    # --- Technical Packet Telemetry Section ---
    if report_type.lower() == "technical":
        story.append(Paragraph("3. Packet Telemetry & Wire Inspection", h2_style))
        tot_pkts = telemetry.get("total_packets", "N/A")
        ctrl_pkts = telemetry.get("control_plane", {}).get("packet_count", 0)
        data_pkts = telemetry.get("data_plane", {}).get("packet_count", 0)
        other_pkts = telemetry.get("other_traffic", {}).get("packet_count", 0)

        telem_data = [
            [Paragraph("<b>Metric</b>", bold_style), Paragraph("<b>Value</b>", bold_style)],
            [Paragraph("Total Ingested Packets", body_style), Paragraph(str(tot_pkts), body_style)],
            [Paragraph("IKE Control-Plane Packets (UDP 500 / 4500)", body_style), Paragraph(str(ctrl_pkts), body_style)],
            [Paragraph("ESP Data-Plane Packets (Proto 50 / UDP 4500)", body_style), Paragraph(str(data_pkts), body_style)],
            [Paragraph("Other Non-IPsec Packets", body_style), Paragraph(str(other_pkts), body_style)],
        ]
        t_telem = Table(telem_data, colWidths=[265, 265])
        t_telem.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_telem)

    doc.build(story)
    return buffer.getvalue()
