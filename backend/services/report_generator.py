import json
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    LongTable,
    TableStyle,
)


# --------------------------------------------------
# REPORT DATA
# --------------------------------------------------

def generate_report_data(
    case: dict,
    analysis: dict,
    correlation: dict,
    integrity: dict,
    timeline: dict | None = None,
) -> dict:
    """
    Build a complete, structured TraceWeave investigation report.

    The report contains:
    - Case information
    - Investigation assessment and findings
    - Individual packet correlation records
    - Unmatched packet details
    - Chronological investigation timeline
    - Evidence integrity verification details
    """

    timeline = timeline or {}

    correlation_results = correlation.get("results", [])
    timeline_events = timeline.get("timeline", [])

    unmatched_packets = [
        item
        for item in correlation_results
        if item.get("correlation_status") == "UNMATCHED"
    ]

    return {
        "report_title": "TraceWeave Investigation Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "case": {
            "case_id": case["case_id"],
            "title": case["title"],
            "description": case.get("description", ""),
            "status": case["status"],
            "created_at": case["created_at"],
        },

        "investigation": {
            "assessment_status": analysis.get(
                "assessment_status", "UNKNOWN"
            ),
            "priority": analysis.get(
                "investigation_priority", "UNKNOWN"
            ),
            "summary": analysis.get("summary", ""),
            "metrics": analysis.get("metrics", {}),
            "findings": analysis.get("findings", []),
            "classification_note": analysis.get(
                "classification_note", ""
            ),
        },

        "correlation": {
            "total_packets": correlation.get("total_packets", 0),
            "matched": correlation.get("matched", 0),
            "unmatched": correlation.get("unmatched", 0),
            "high_confidence": correlation.get(
                "high_confidence", 0
            ),
            "medium_confidence": correlation.get(
                "medium_confidence", 0
            ),
            "skipped_log_records": correlation.get(
                "skipped_log_records", 0
            ),

            # Preserve every individual correlation result.
            "results": correlation_results,

            # These are unmatched captured packets only.
            "unmatched_packets": unmatched_packets,

            "matching_method": {
                "matching_fields": [
                    "Source IP address",
                    "Packet timestamp",
                    "Endpoint received_at timestamp",
                ],
                "time_tolerance_seconds": 5,
                "high_confidence_threshold_seconds": 1,
                "matching_rule": (
                    "A packet and endpoint log record must have "
                    "the same source IP address and a timestamp "
                    "difference of no more than 5 seconds. "
                    "Each endpoint record can be matched once."
                ),
            },
        },

        "timeline": {
            "summary": timeline.get("summary", {}),
            "events": timeline_events,
        },

        "integrity": {
            "integrity_status": integrity.get(
                "integrity_status", "UNKNOWN"
            ),
            "total_evidence": integrity.get("total_evidence", 0),
            "verified": integrity.get("verified", 0),
            "modified": integrity.get("modified", 0),
            "missing": integrity.get("missing", 0),

            # Contains expected/actual hashes and sizes.
            "evidence": integrity.get("evidence", []),
        },

        "report_scope_notes": [
            (
                "Unmatched packets represent captured network "
                "packets without an eligible endpoint log match."
            ),
            (
                "The correlation process does not classify unmatched "
                "endpoint log records."
            ),
            (
                "Correlation confidence is separate from evidence "
                "integrity status."
            ),
            (
                "Investigation priority is a rule-based review "
                "classification, not confirmation of malicious activity."
            ),
        ],
    }


# --------------------------------------------------
# JSON REPORT
# --------------------------------------------------

def save_json_report(
    report_data: dict,
    reports_directory: Path,
) -> Path:

    reports_directory.mkdir(parents=True, exist_ok=True)

    report_path = reports_directory / "investigation_report.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return report_path


# --------------------------------------------------
# PDF HELPERS
# --------------------------------------------------

def _safe_text(value) -> str:
    """Convert a value into escaped text suitable for ReportLab."""

    if value is None:
        return "N/A"

    return escape(str(value))


def _paragraph(value, style):
    return Paragraph(_safe_text(value), style)


def _format_timestamp(value) -> str:
    if value is None:
        return "N/A"

    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            ).isoformat()

        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).isoformat()

    except (ValueError, TypeError, OSError, OverflowError):
        return str(value)


def _format_hash(value) -> str:
    """Insert visual spacing into hashes to improve PDF readability."""

    if not value:
        return "N/A"

    value = str(value)
    return " ".join(
        value[index:index + 16]
        for index in range(0, len(value), 16)
    )


def _make_table(rows, widths, header=True, font_size=8):
    table = LongTable(
        rows,
        colWidths=widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT",
    )

    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
    ]

    if header:
        commands.extend([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#263B63"),
            ),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ])

    table.setStyle(TableStyle(commands))
    return table


# --------------------------------------------------
# PDF REPORT
# --------------------------------------------------

def generate_pdf_report(
    report_data: dict,
    reports_directory: Path,
) -> Path:

    reports_directory.mkdir(parents=True, exist_ok=True)

    report_path = reports_directory / "investigation_report.pdf"

    document = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="TraceWeave Investigation Report",
        author="TraceWeave Investigation Platform",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=25,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["BodyText"],
        alignment=TA_CENTER,
        fontSize=9,
        textColor=colors.grey,
        leading=13,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#263B63"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=4,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=body_style,
        fontSize=7,
        leading=9,
        wordWrap="CJK",
    )

    cell_style = ParagraphStyle(
        "ReportCell",
        parent=small_style,
        fontSize=7,
        leading=9,
    )

    footer_style = ParagraphStyle(
        "ReportFooter",
        parent=small_style,
        alignment=TA_CENTER,
        textColor=colors.grey,
    )

    story = []

    # --------------------------------------------------
    # HEADER
    # --------------------------------------------------

    story.append(
        Paragraph(
            _safe_text(report_data.get("report_title")),
            title_style,
        )
    )

    story.append(
        Paragraph(
            "An Integrity-Verified Platform for Correlating "
            "Endpoint Telemetry and Network Evidence",
            subtitle_style,
        )
    )

    story.append(Spacer(1, 15))

    # --------------------------------------------------
    # 1. CASE INFORMATION
    # --------------------------------------------------

    case = report_data.get("case", {})

    story.append(
        Paragraph("1. Case Information", heading_style)
    )

    case_rows = [
        ["Field", "Value"],
        ["Case ID", _paragraph(case.get("case_id"), cell_style)],
        ["Title", _paragraph(case.get("title"), cell_style)],
        ["Description", _paragraph(case.get("description"), cell_style)],
        ["Status", _paragraph(case.get("status"), cell_style)],
        [
            "Created At",
            _paragraph(_format_timestamp(case.get("created_at")), cell_style),
        ],
        [
            "Report Generated At",
            _paragraph(
                _format_timestamp(report_data.get("generated_at")),
                cell_style,
            ),
        ],
    ]

    story.append(
        _make_table(
            case_rows,
            [45 * mm, 129 * mm],
        )
    )

    # --------------------------------------------------
    # 2. INVESTIGATION ASSESSMENT
    # --------------------------------------------------

    analysis = report_data.get("investigation", {})

    story.append(
        Paragraph("2. Investigation Assessment", heading_style)
    )

    story.append(
        Paragraph(
            f"<b>Priority:</b> {_safe_text(analysis.get('priority'))}",
            body_style,
        )
    )

    story.append(
        Paragraph(
            "<b>Assessment Status:</b> "
            f"{_safe_text(analysis.get('assessment_status'))}",
            body_style,
        )
    )

    story.append(
        _paragraph(analysis.get("summary"), body_style)
    )

    # --------------------------------------------------
    # 3. INVESTIGATION FINDINGS
    # --------------------------------------------------

    story.append(
        Paragraph("3. Investigation Findings", heading_style)
    )

    findings = analysis.get("findings", [])

    if not findings:
        story.append(
            Paragraph("No investigation findings were recorded.", body_style)
        )

    for index, finding in enumerate(findings, 1):

        story.append(
            Paragraph(
                f"<b>{index}. "
                f"{_safe_text(finding.get('category', 'Finding'))}</b>",
                body_style,
            )
        )

        story.append(
            Paragraph(
                f"<b>Status:</b> "
                f"{_safe_text(finding.get('status'))}",
                small_style,
            )
        )

        if finding.get("count") is not None:
            story.append(
                Paragraph(
                    f"<b>Count:</b> {_safe_text(finding.get('count'))}",
                    small_style,
                )
            )

        story.append(
            _paragraph(finding.get("description"), body_style)
        )

        if finding.get("recommendation"):
            story.append(
                Paragraph(
                    "<b>Recommendation:</b> "
                    f"{_safe_text(finding.get('recommendation'))}",
                    small_style,
                )
            )

        story.append(Spacer(1, 7))

    # --------------------------------------------------
    # 4. NETWORK CORRELATION SUMMARY
    # --------------------------------------------------

    correlation = report_data.get("correlation", {})

    story.append(
        Paragraph("4. Network Correlation Summary", heading_style)
    )

    correlation_rows = [
        ["Metric", "Result"],
        ["Total Packets", str(correlation.get("total_packets", 0))],
        ["Matched Packets", str(correlation.get("matched", 0))],
        ["Unmatched Packets", str(correlation.get("unmatched", 0))],
        [
            "HIGH Confidence Matches",
            str(correlation.get("high_confidence", 0)),
        ],
        [
            "MEDIUM Confidence Matches",
            str(correlation.get("medium_confidence", 0)),
        ],
        [
            "Skipped Log Records",
            str(correlation.get("skipped_log_records", 0)),
        ],
    ]

    story.append(
        _make_table(
            correlation_rows,
            [85 * mm, 89 * mm],
        )
    )

    matching_method = correlation.get("matching_method", {})

    story.append(Spacer(1, 7))

    story.append(
        Paragraph(
            "<b>Correlation Method</b>",
            body_style,
        )
    )

    story.append(
        _paragraph(
            matching_method.get("matching_rule"),
            small_style,
        )
    )

    story.append(
        Paragraph(
            "<b>Configured time tolerance:</b> "
            f"{_safe_text(matching_method.get('time_tolerance_seconds'))} "
            "seconds",
            small_style,
        )
    )

    # --------------------------------------------------
    # 5. INDIVIDUAL CORRELATION RECORDS
    # --------------------------------------------------

    results = correlation.get("results", [])

    story.append(
        Paragraph("5. Individual Correlation Records", heading_style)
    )

    if results:

        result_rows = [[
            "Frame",
            "Status",
            "Confidence",
            "Endpoint",
            "Source IP",
            "Destination IP",
            "Time Difference",
        ]]

        for item in results:

            result_rows.append([
                _paragraph(item.get("frame_number"), cell_style),
                _paragraph(item.get("correlation_status"), cell_style),
                _paragraph(item.get("confidence"), cell_style),
                _paragraph(item.get("endpoint_id"), cell_style),
                _paragraph(item.get("source_ip"), cell_style),
                _paragraph(item.get("destination_ip"), cell_style),
                _paragraph(
                    (
                        f"{item.get('time_difference_seconds')} s"
                        if item.get("time_difference_seconds") is not None
                        else "N/A"
                    ),
                    cell_style,
                ),
            ])

        story.append(
            _make_table(
                result_rows,
                [
                    13 * mm,
                    23 * mm,
                    22 * mm,
                    25 * mm,
                    29 * mm,
                    29 * mm,
                    33 * mm,
                ],
            )
        )

        for item in results:

            story.append(Spacer(1, 5))

            story.append(
                Paragraph(
                    f"<b>Frame { _safe_text(item.get('frame_number')) } "
                    f"— {_safe_text(item.get('correlation_status'))}</b>",
                    small_style,
                )
            )

            details = [
                f"Platform: {_safe_text(item.get('platform'))}",
                f"Sequence: {_safe_text(item.get('sequence'))}",
                (
                    "Packet timestamp: "
                    f"{_safe_text(_format_timestamp(item.get('packet_timestamp')))}"
                ),
                (
                    "Endpoint sent_at: "
                    f"{_safe_text(_format_timestamp(item.get('sent_at')))}"
                ),
                (
                    "Endpoint received_at: "
                    f"{_safe_text(_format_timestamp(item.get('received_at')))}"
                ),
                (
                    "Confidence reason: "
                    f"{_safe_text(item.get('confidence_reason'))}"
                ),
            ]

            for detail in details:
                story.append(
                    Paragraph(detail, small_style)
                )

    else:
        story.append(
            Paragraph("No individual correlation records were available.", body_style)
        )

    # --------------------------------------------------
    # 6. UNMATCHED PACKET DETAILS
    # --------------------------------------------------

    unmatched = correlation.get("unmatched_packets", [])

    story.append(
        Paragraph("6. Unmatched Packet Details", heading_style)
    )

    story.append(
        Paragraph(
            "The following records represent captured packets for which "
            "no eligible endpoint log record was found.",
            body_style,
        )
    )

    if unmatched:

        unmatched_rows = [[
            "Frame",
            "Source IP",
            "Destination IP",
            "Packet Timestamp",
            "Reason",
        ]]

        for item in unmatched:

            unmatched_rows.append([
                _paragraph(item.get("frame_number"), cell_style),
                _paragraph(item.get("source_ip"), cell_style),
                _paragraph(item.get("destination_ip"), cell_style),
                _paragraph(
                    _format_timestamp(item.get("packet_timestamp")),
                    cell_style,
                ),
                _paragraph(item.get("confidence_reason"), cell_style),
            ])

        story.append(
            _make_table(
                unmatched_rows,
                [
                    15 * mm,
                    31 * mm,
                    31 * mm,
                    52 * mm,
                    45 * mm,
                ],
            )
        )

    else:
        story.append(
            Paragraph("No unmatched packets were recorded.", body_style)
        )

    story.append(
        Paragraph(
            "Note: The correlation engine reports unmatched captured packets. "
            "It does not currently produce a separate list of unused "
            "endpoint log records.",
            small_style,
        )
    )

    # --------------------------------------------------
    # 7. CHRONOLOGICAL INVESTIGATION TIMELINE
    # --------------------------------------------------

    timeline = report_data.get("timeline", {})
    timeline_events = timeline.get("events", [])
    timeline_summary = timeline.get("summary", {})

    story.append(
        Paragraph("7. Chronological Investigation Timeline", heading_style)
    )

    timeline_summary_rows = [
        ["Timeline Metric", "Count"],
        [
            "Total Events",
            str(timeline_summary.get("total_events", 0)),
        ],
        [
            "Endpoint Events",
            str(timeline_summary.get("endpoint_events", 0)),
        ],
        [
            "Network Events",
            str(timeline_summary.get("network_events", 0)),
        ],
        [
            "Correlation Events",
            str(timeline_summary.get("correlation_events", 0)),
        ],
    ]

    story.append(
        _make_table(
            timeline_summary_rows,
            [85 * mm, 89 * mm],
        )
    )

    if timeline_events:

        timeline_rows = [[
            "Timestamp",
            "Event Type",
            "Description",
            "Endpoint / Frame",
        ]]

        for event in timeline_events:

            endpoint_frame = (
                f"Endpoint: {event.get('endpoint_id') or 'N/A'}"
                f"\nFrame: {event.get('frame_number', 'N/A')}"
            )

            timeline_rows.append([
                _paragraph(
                    _format_timestamp(event.get("timestamp")),
                    cell_style,
                ),
                _paragraph(event.get("event_type"), cell_style),
                _paragraph(event.get("description"), cell_style),
                _paragraph(endpoint_frame, cell_style),
            ])

        story.append(Spacer(1, 7))

        story.append(
            _make_table(
                timeline_rows,
                [
                    43 * mm,
                    27 * mm,
                    70 * mm,
                    34 * mm,
                ],
            )
        )

        for event in timeline_events:

            extra_details = []

            for key in (
                "source_ip",
                "destination_ip",
                "sequence",
                "confidence",
                "confidence_reason",
                "time_difference_seconds",
                "evidence",
            ):
                if event.get(key) is not None:
                    extra_details.append(
                        f"{key}: {_safe_text(event.get(key))}"
                    )

            if extra_details:
                story.append(Spacer(1, 3))
                story.append(
                    _paragraph(" | ".join(extra_details), small_style)
                )

    else:
        story.append(
            Paragraph("No timeline events were available.", body_style)
        )

    # --------------------------------------------------
    # 8. EVIDENCE INTEGRITY SUMMARY
    # --------------------------------------------------

    integrity = report_data.get("integrity", {})

    story.append(
        Paragraph("8. Evidence Integrity Results", heading_style)
    )

    integrity_rows = [
        ["Metric", "Result"],
        [
            "Integrity Status",
            _paragraph(integrity.get("integrity_status"), cell_style),
        ],
        [
            "Total Evidence Files",
            str(integrity.get("total_evidence", 0)),
        ],
        ["Verified Files", str(integrity.get("verified", 0))],
        ["Modified Files", str(integrity.get("modified", 0))],
        ["Missing Files", str(integrity.get("missing", 0))],
    ]

    story.append(
        _make_table(
            integrity_rows,
            [85 * mm, 89 * mm],
        )
    )

    # --------------------------------------------------
    # 9. DETAILED EVIDENCE VERIFICATION
    # --------------------------------------------------

    evidence = integrity.get("evidence", [])

    story.append(
        Paragraph("9. Detailed Evidence Verification", heading_style)
    )

    if evidence:

        evidence_rows = [[
            "Filename",
            "Status",
            "Expected Size",
            "Actual Size",
            "Expected SHA-256",
            "Actual SHA-256",
        ]]

        for item in evidence:

            evidence_rows.append([
                _paragraph(item.get("filename"), cell_style),
                _paragraph(item.get("status"), cell_style),
                _paragraph(item.get("expected_size_bytes"), cell_style),
                _paragraph(item.get("actual_size_bytes"), cell_style),
                _paragraph(
                    _format_hash(item.get("expected_sha256")),
                    cell_style,
                ),
                _paragraph(
                    _format_hash(item.get("actual_sha256")),
                    cell_style,
                ),
            ])

        story.append(
            _make_table(
                evidence_rows,
                [
                    24 * mm,
                    19 * mm,
                    22 * mm,
                    22 * mm,
                    43 * mm,
                    44 * mm,
                ],
                font_size=7,
            )
        )

        story.append(Spacer(1, 6))

        story.append(
            Paragraph(
                "VERIFIED means the actual file size and SHA-256 hash "
                "match the saved manifest. MODIFIED means one or both "
                "values differ. MISSING means the file was not present "
                "during verification.",
                small_style,
            )
        )

    else:
        story.append(
            Paragraph("No evidence verification records were available.", body_style)
        )

    # --------------------------------------------------
    # 10. CLASSIFICATION DISCLAIMER
    # --------------------------------------------------

    story.append(
        Paragraph("10. Classification Disclaimer", heading_style)
    )

    story.append(
        _paragraph(
            analysis.get("classification_note"),
            small_style,
        )
    )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "Generated by TraceWeave Investigation Platform",
            footer_style,
        )
    )

    document.build(story)

    return report_path
