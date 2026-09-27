from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGE_WIDTH, PAGE_HEIGHT = A4

LEFT_MARGIN = 18 * mm
RIGHT_MARGIN = 18 * mm
TOP_MARGIN = 18 * mm
BOTTOM_MARGIN = 18 * mm

DEFAULT_OUTPUT_DIR = (
    Path(__file__).resolve().parent.parent / "generated_reports"
)

REPORT_TYPES = {"executive", "technical"}

RISK_LEVELS = {
    "LOW",
    "MODERATE",
    "HIGH",
    "CRITICAL",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe(value: Any, default: str = "N/A") -> str:
    """Convert values into safe report text."""
    if value is None:
        return default

    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"

    return str(value)


def _format_percentage(value: Any) -> str:
    try:
        return f"{float(value):.2f}%"
    except (TypeError, ValueError):
        return "N/A"


def _format_bytes(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "N/A"


def _format_score(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "N/A"


def _risk_level(value: Any) -> str:
    level = str(value).upper()

    if level in RISK_LEVELS:
        return level

    return "UNKNOWN"


def _paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    """
    Convert arbitrary values into a safely escaped ReportLab Paragraph.

    Dynamic values are escaped so that strings containing characters such as
    <, >, and & are displayed literally rather than interpreted as markup.
    """
    value = _safe(text)
    return Paragraph(escape(value), style)


def _rich_paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    """
    Create a ReportLab Paragraph containing controlled markup.

    This helper is used only where the generator intentionally inserts
    ReportLab markup such as <b>...</b>. Dynamic values inside the markup
    should be escaped before being passed here.
    """
    return Paragraph(str(text), style)


# ---------------------------------------------------------------------------
# Document
# ---------------------------------------------------------------------------

class CryptoLensDocTemplate(BaseDocTemplate):
    """Base document with consistent margins and page numbering."""

    def __init__(self, filename: str | Path, **kwargs: Any) -> None:
        super().__init__(
            str(filename),
            pagesize=A4,
            leftMargin=LEFT_MARGIN,
            rightMargin=RIGHT_MARGIN,
            topMargin=TOP_MARGIN,
            bottomMargin=BOTTOM_MARGIN,
            **kwargs,
        )

        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="normal",
        )

        template = PageTemplate(
            id="CryptoLens",
            frames=[frame],
            onPage=self._draw_page_header_footer,
        )

        self.addPageTemplates([template])

    def _draw_page_header_footer(self, canvas, doc) -> None:
        canvas.saveState()

        # Header
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(
            LEFT_MARGIN,
            PAGE_HEIGHT - 10 * mm,
            "CryptoLens - IPsec VPN Security Assessment",
        )

        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            PAGE_WIDTH - RIGHT_MARGIN,
            10 * mm,
            f"Page {doc.page}",
        )

        canvas.restoreState()


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "CryptoLensTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "CryptoLensSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            spaceAfter=14,
        ),
        "section": ParagraphStyle(
            "CryptoLensSection",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            spaceBefore=10,
            spaceAfter=7,
        ),
        "subsection": ParagraphStyle(
            "CryptoLensSubsection",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            spaceBefore=7,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "CryptoLensBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "CryptoLensSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
        ),
        "table_header": ParagraphStyle(
            "CryptoLensTableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ),
        "table_cell": ParagraphStyle(
            "CryptoLensTableCell",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
        ),
        "finding_title": ParagraphStyle(
            "CryptoLensFindingTitle",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
        ),
    }


# ---------------------------------------------------------------------------
# Table builders
# ---------------------------------------------------------------------------

def _styled_table(
    data: List[List[Any]],
    widths: List[float],
    header_rows: int = 1,
) -> Table:
    table = Table(
        data,
        colWidths=widths,
        repeatRows=header_rows,
        hAlign="LEFT",
    )

    style_commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]

    if header_rows:
        style_commands.extend(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, header_rows - 1),
                    colors.HexColor("#243447"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, header_rows - 1),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, header_rows - 1),
                    "Helvetica-Bold",
                ),
            ]
        )

    table.setStyle(TableStyle(style_commands))
    return table


def _key_value_table(
    rows: Iterable[Tuple[str, Any]],
    styles: Dict[str, ParagraphStyle],
    value_width: float = 95 * mm,
) -> Table:
    data = [
        [
            _paragraph("Parameter", styles["table_header"]),
            _paragraph("Value", styles["table_header"]),
        ]
    ]

    for key, value in rows:
        data.append(
            [
                _paragraph(key, styles["table_cell"]),
                _paragraph(value, styles["table_cell"]),
            ]
        )

    return _styled_table(
        data,
        widths=[55 * mm, value_width],
    )


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _build_cover(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    summary = result.get("summary") or {}

    story = [
        Spacer(1, 22 * mm),
        Paragraph("CryptoLens", styles["title"]),
        Paragraph(
            "IPsec VPN Security Assessment Report",
            styles["subtitle"],
        ),
        Spacer(1, 6 * mm),
    ]

    cover_rows = [
        ("Job ID", _safe(result.get("job_id"))),
        ("Assessment Status", _safe(result.get("status")).upper()),
        (
            "Risk Score",
            f"{_format_score(summary.get('overall_security_score'))} / 100",
        ),
        ("Risk Level", _risk_level(summary.get("risk_level"))),
        (
            "AI Confidence",
            _format_score(
                (
                    float(summary.get("ai_confidence_score", 0)) * 100
                )
                if summary.get("ai_confidence_score") is not None
                else None
            )
            + "%",
        ),
        (
            "Heuristic / AI Agreement",
            "Yes" if summary.get("agreement_flag") else "No",
        ),
    ]

    story.append(
        _key_value_table(
            cover_rows,
            styles,
            value_width=90 * mm,
        )
    )

    story.append(Spacer(1, 8 * mm))
    return story


def _build_executive_summary(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    summary = result.get("summary") or {}
    findings = result.get("threat_matrix") or []

    score = summary.get("overall_security_score")
    risk = _risk_level(summary.get("risk_level"))

    score_text = escape(_format_score(score))
    risk_text = escape(risk)

    story = [
        Paragraph(
            "1. Executive Summary",
            styles["section"],
        ),
        _rich_paragraph(
            (
                "CryptoLens assessed the supplied IPsec traffic with an overall "
                f"security score of <b>{score_text}/100</b>, classified "
                f"as <b>{risk_text}</b>. The assessment combines protocol "
                "evidence, configured scoring rules, and the analyzer outputs "
                "available for this job."
            ),
            styles["body"],
        ),
    ]

    if findings:
        story.append(
            _paragraph(
                f"{len(findings)} finding(s) were generated during the assessment.",
                styles["body"],
            )
        )
    else:
        story.append(
            _paragraph(
                "No compliance findings were generated by the current rule set.",
                styles["body"],
            )
        )

    story.append(Spacer(1, 3 * mm))
    return story


def _build_control_plane(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    control = result.get("control_plane") or {}

    rows = [
        ("IKE Version", _safe(control.get("ike_version"))),
        ("Operating Mode", _safe(control.get("operating_mode"))),
        (
            "Encryption Algorithm",
            _safe(control.get("encryption_algorithm")),
        ),
        (
            "Integrity Algorithm",
            _safe(control.get("integrity_algorithm")),
        ),
        ("DH Group", _safe(control.get("dh_group"))),
        ("PFS", _safe(control.get("pfs_enabled"))),
        (
            "Key Lifetime (seconds)",
            _safe(control.get("key_lifetime_seconds")),
        ),
        (
            "Replay Protection",
            _safe(control.get("replay_protection_enabled")),
        ),
    ]

    return [
        Paragraph(
            "2. Control-Plane Assessment",
            styles["section"],
        ),
        _key_value_table(
            rows,
            styles,
            value_width=90 * mm,
        ),
        Spacer(1, 5 * mm),
    ]


def _build_score_breakdown(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    breakdown = result.get("score_breakdown") or {}

    categories = [
        ("Encryption", "encryption"),
        ("Integrity", "integrity"),
        ("Key Exchange", "key_exchange"),
        ("PFS", "pfs"),
        ("Replay Protection", "replay_protection"),
        ("Key Lifetime", "key_lifetime"),
        ("IKE Version", "ike_version"),
        ("Operating Mode", "mode"),
    ]

    data = [
        [
            _paragraph("Category", styles["table_header"]),
            _paragraph("Score", styles["table_header"]),
            _paragraph("Maximum", styles["table_header"]),
            _paragraph("Utilization", styles["table_header"]),
        ]
    ]

    for label, key in categories:
        item = breakdown.get(key) or {}

        score = item.get("score")
        maximum = item.get("max_score")

        try:
            utilization = f"{(float(score) / float(maximum)) * 100:.1f}%"
        except (TypeError, ValueError, ZeroDivisionError):
            utilization = "N/A"

        data.append(
            [
                _paragraph(label, styles["table_cell"]),
                _paragraph(
                    _format_score(score),
                    styles["table_cell"],
                ),
                _paragraph(
                    _format_score(maximum),
                    styles["table_cell"],
                ),
                _paragraph(
                    utilization,
                    styles["table_cell"],
                ),
            ]
        )

    return [
        Paragraph(
            "3. Score Breakdown",
            styles["section"],
        ),
        _styled_table(
            data,
            widths=[
                65 * mm,
                35 * mm,
                35 * mm,
                35 * mm,
            ],
        ),
        Spacer(1, 5 * mm),
    ]


def _build_findings(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    findings = result.get("threat_matrix") or []

    story = [
        Paragraph(
            "4. Security Findings",
            styles["section"],
        ),
    ]

    if not findings:
        story.append(
            _paragraph(
                "No findings were returned by the active compliance rules.",
                styles["body"],
            )
        )
        return story

    data = [
        [
            _paragraph("Finding ID", styles["table_header"]),
            _paragraph("Severity", styles["table_header"]),
            _paragraph("Category", styles["table_header"]),
            _paragraph("Observed Value", styles["table_header"]),
        ]
    ]

    for finding in findings:
        data.append(
            [
                _paragraph(
                    finding.get("finding_id"),
                    styles["table_cell"],
                ),
                _paragraph(
                    finding.get("severity"),
                    styles["table_cell"],
                ),
                _paragraph(
                    finding.get("category"),
                    styles["table_cell"],
                ),
                _paragraph(
                    finding.get("observed_value"),
                    styles["table_cell"],
                ),
            ]
        )

    story.append(
        _styled_table(
            data,
            widths=[
                35 * mm,
                28 * mm,
                42 * mm,
                65 * mm,
            ],
        )
    )

    story.append(Spacer(1, 5 * mm))

    for index, finding in enumerate(findings, start=1):
        title = _safe(finding.get("title"))
        description = _safe(finding.get("description"))
        source = _safe(finding.get("source"))

        title_escaped = escape(title)
        description_escaped = escape(description)
        source_escaped = escape(source)

        block = [
            Paragraph(
                f"{index}. {title_escaped}",
                styles["finding_title"],
            ),
            _rich_paragraph(
                f"<b>Description:</b> {description_escaped}",
                styles["body"],
            ),
            _rich_paragraph(
                f"<b>Source:</b> {source_escaped}",
                styles["small"],
            ),
            Spacer(1, 2 * mm),
        ]

        story.append(
            KeepTogether(block)
        )

    return story


def _build_traffic_analysis(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    data_plane = result.get("data_plane") or {}
    traffic = data_plane.get("detected_traffic") or []

    heuristic_prediction = escape(
        _safe(data_plane.get("heuristic_mode_prediction"))
    )
    ai_prediction = escape(
        _safe(data_plane.get("llm_mode_prediction"))
    )

    story = [
        Paragraph(
            "5. Traffic Analysis",
            styles["section"],
        ),
        _rich_paragraph(
            (
                "<b>Heuristic prediction:</b> "
                f"{heuristic_prediction}"
            ),
            styles["body"],
        ),
        _rich_paragraph(
            (
                "<b>AI prediction:</b> "
                f"{ai_prediction}"
            ),
            styles["body"],
        ),
    ]

    if not traffic:
        story.append(
            _paragraph(
                "No traffic-classification records were provided.",
                styles["body"],
            )
        )
        return story

    data = [
        [
            _paragraph(
                "Traffic Type",
                styles["table_header"],
            ),
            _paragraph(
                "Percentage",
                styles["table_header"],
            ),
            _paragraph(
                "Packets",
                styles["table_header"],
            ),
            _paragraph(
                "Avg. Packet Size (bytes)",
                styles["table_header"],
            ),
        ]
    ]

    for item in traffic:
        data.append(
            [
                _paragraph(
                    item.get("traffic_type"),
                    styles["table_cell"],
                ),
                _paragraph(
                    _format_percentage(item.get("percentage")),
                    styles["table_cell"],
                ),
                _paragraph(
                    _safe(item.get("packet_count")),
                    styles["table_cell"],
                ),
                _paragraph(
                    _format_bytes(item.get("avg_packet_size_bytes")),
                    styles["table_cell"],
                ),
            ]
        )

    story.append(
        _styled_table(
            data,
            widths=[
                55 * mm,
                35 * mm,
                30 * mm,
                50 * mm,
            ],
        )
    )

    return story


def _build_compliance_section(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    compliance = result.get("compliance") or {}
    standards = compliance.get("standards") or {}

    story = [
        Paragraph(
            "6. Standards Compliance Assessment",
            styles["section"],
        ),
    ]

    if not standards:
        story.append(
            _paragraph(
                "No standards compliance assessment was included in this analysis.",
                styles["body"],
            )
        )
        return story

    for standard_name, standard in standards.items():
        title = standard.get("title", standard_name)
        overall_status = _safe(
            standard.get("overall_status"),
            "NOT_ASSESSED",
        )

        counts = standard.get("counts") or {}

        story.append(
            Paragraph(
                escape(str(title)),
                styles["subsection"],
            )
        )

        summary_data = [
            [
                _paragraph(
                    "Overall Status",
                    styles["table_header"],
                ),
                _paragraph(
                    "Aligned",
                    styles["table_header"],
                ),
                _paragraph(
                    "Review",
                    styles["table_header"],
                ),
                _paragraph(
                    "Fail",
                    styles["table_header"],
                ),
                _paragraph(
                    "Not Assessed",
                    styles["table_header"],
                ),
            ],
            [
                _paragraph(
                    overall_status,
                    styles["table_cell"],
                ),
                _paragraph(
                    counts.get("ALIGNED", 0),
                    styles["table_cell"],
                ),
                _paragraph(
                    counts.get("REVIEW", 0),
                    styles["table_cell"],
                ),
                _paragraph(
                    counts.get("FAIL", 0),
                    styles["table_cell"],
                ),
                _paragraph(
                    counts.get("NOT_ASSESSED", 0),
                    styles["table_cell"],
                ),
            ],
        ]

        story.append(
            _styled_table(
                summary_data,
                widths=[
                    40 * mm,
                    30 * mm,
                    30 * mm,
                    25 * mm,
                    35 * mm,
                ],
            )
        )

        story.append(Spacer(1, 3 * mm))

        controls = standard.get("controls") or []

        if controls:
            control_data = [
                [
                    _paragraph(
                        "Control",
                        styles["table_header"],
                    ),
                    _paragraph(
                        "Status",
                        styles["table_header"],
                    ),
                    _paragraph(
                        "Observed Value",
                        styles["table_header"],
                    ),
                    _paragraph(
                        "Assessment",
                        styles["table_header"],
                    ),
                ]
            ]

            for control in controls:
                control_data.append(
                    [
                        _paragraph(
                            control.get("control"),
                            styles["table_cell"],
                        ),
                        _paragraph(
                            control.get("status"),
                            styles["table_cell"],
                        ),
                        _paragraph(
                            control.get("observed_value"),
                            styles["table_cell"],
                        ),
                        _paragraph(
                            control.get("reason")
                            or control.get("description"),
                            styles["table_cell"],
                        ),
                    ]
                )

            story.append(
                _styled_table(
                    control_data,
                    widths=[
                        38 * mm,
                        28 * mm,
                        42 * mm,
                        52 * mm,
                    ],
                )
            )

        story.append(Spacer(1, 6 * mm))

    return story


def _build_technical_metadata(
    result: Dict[str, Any],
    styles: Dict[str, ParagraphStyle],
):
    summary = result.get("summary") or {}

    return [
        Paragraph(
            "7. Assessment Metadata",
            styles["section"],
        ),
        _key_value_table(
            [
                ("Job ID", _safe(result.get("job_id"))),
                ("Status", _safe(result.get("status"))),
                (
                    "Processed Packets",
                    _safe(summary.get("processed_packets")),
                ),
                (
                    "AI Confidence",
                    (
                        f"{float(summary.get('ai_confidence_score', 0)) * 100:.2f}%"
                        if summary.get("ai_confidence_score") is not None
                        else "N/A"
                    ),
                ),
                (
                    "Heuristic / AI Agreement",
                    "Yes" if summary.get("agreement_flag") else "No",
                ),
            ],
            styles,
            value_width=90 * mm,
        ),
    ]


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_pdf(
    result: Dict[str, Any],
    output_path: str | Path | None = None,
    report_type: str = "executive",
) -> str:
    """
    Generate a CryptoLens assessment PDF from a completed analysis result.

    Parameters
    ----------
    result:
        Complete final analysis result loaded from ResultStore.
    output_path:
        Destination PDF path. If omitted, generated_reports/ is used.
    report_type:
        "executive" or "technical".

    Returns
    -------
    str
        Absolute path to the generated PDF.
    """
    report_type = str(report_type).lower().strip()

    if report_type not in REPORT_TYPES:
        raise ValueError(
            f"Unsupported report type '{report_type}'. "
            f"Use one of: {', '.join(sorted(REPORT_TYPES))}."
        )

    job_id = _safe(
        result.get("job_id"),
        "unknown_job",
    )

    if output_path is None:
        DEFAULT_OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path = (
            DEFAULT_OUTPUT_DIR
            / f"Security_Report_{job_id}_{report_type}.pdf"
        )
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    styles = _build_styles()

    document = CryptoLensDocTemplate(
        output_path
    )

    story = []

    story.extend(
        _build_cover(
            result,
            styles,
        )
    )

    story.extend(
        _build_executive_summary(
            result,
            styles,
        )
    )

    story.extend(
        _build_control_plane(
            result,
            styles,
        )
    )

    story.extend(
        _build_score_breakdown(
            result,
            styles,
        )
    )

    story.extend(
        _build_findings(
            result,
            styles,
        )
    )

    story.extend(
        _build_traffic_analysis(
            result,
            styles,
        )
    )

    story.extend(
        _build_compliance_section(
            result,
            styles,
        )
    )

    if report_type == "technical":
        story.append(PageBreak())

        story.extend(
            _build_technical_metadata(
                result,
                styles,
            )
        )

    document.build(story)

    return str(
        Path(output_path).resolve()
    )