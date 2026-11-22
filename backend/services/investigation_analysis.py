
from datetime import datetime, timezone


def analyze_investigation(
    correlation_summary: dict,
    integrity_report: dict
) -> dict:
    """
    Generate an evidence-based investigation priority.

    Priority is not a malware verdict or proof of an attack.
    Correlation confidence and evidence integrity remain
    separate classifications.
    """

    findings = []
    priority = "LOW"
    assessment_status = "ASSESSMENT_COMPLETE"

    total_packets = correlation_summary.get("total_packets", 0)
    matched = correlation_summary.get("matched", 0)
    unmatched = correlation_summary.get("unmatched", 0)
    skipped = correlation_summary.get("skipped_log_records", 0)

    integrity_status = integrity_report.get(
        "integrity_status", "UNKNOWN"
    )

    # ---------------------------------------------
    # 1. CHECK EVIDENCE INTEGRITY
    # ---------------------------------------------

    if integrity_status == "INTEGRITY_FAILED":

        priority = "HIGH"

        findings.append({
            "category": "EVIDENCE_INTEGRITY",
            "status": "FAILED",
            "description": (
                "One or more evidence files do not match "
                "their saved integrity manifest."
            ),
            "recommendation": (
                "Preserve the original evidence and investigate "
                "the integrity discrepancy."
            )
        })

    elif integrity_status == "INTEGRITY_VERIFIED":

        findings.append({
            "category": "EVIDENCE_INTEGRITY",
            "status": "VERIFIED",
            "description": (
                "All evidence files match their saved "
                "SHA-256 manifest records."
            ),
            "recommendation": (
                "Retain the manifest and evidence together."
            )
        })

    else:

        priority = "HIGH"
        assessment_status = "REVIEW_REQUIRED"

        findings.append({
            "category": "EVIDENCE_INTEGRITY",
            "status": "UNKNOWN",
            "description": (
                "Evidence integrity could not be established."
            ),
            "recommendation": (
                "Review the manifest and evidence availability."
            )
        })

    # ---------------------------------------------
    # 2. CHECK CORRELATION RESULTS
    # ---------------------------------------------

    if total_packets == 0:

        priority = "HIGH"
        assessment_status = "REVIEW_REQUIRED"

        findings.append({
            "category": "NETWORK_CORRELATION",
            "status": "INSUFFICIENT_DATA",
            "description": (
                "No heartbeat packets were available "
                "for correlation."
            ),
            "recommendation": (
                "Check the PCAP evidence and capture scope."
            )
        })

    else:

        findings.append({
            "category": "NETWORK_CORRELATION",
            "status": "ANALYZED",
            "description": (
                f"{matched} of {total_packets} packets "
                "were matched with endpoint records."
            ),
            "recommendation": (
                "Review individual correlation records "
                "when investigating event discrepancies."
            )
        })

    # ---------------------------------------------
    # 3. CHECK UNMATCHED PACKETS
    # ---------------------------------------------

    if unmatched > 0:

        if priority != "HIGH":
            priority = "MEDIUM"

        findings.append({
            "category": "UNMATCHED_PACKETS",
            "status": "REVIEW_REQUIRED",
            "count": unmatched,
            "description": (
                "Some captured packets did not have "
                "an eligible matching endpoint record."
            ),
            "recommendation": (
                "Review timestamps, source addresses, "
                "and available endpoint logs."
            )
        })

    else:

        findings.append({
            "category": "UNMATCHED_PACKETS",
            "status": "NONE",
            "count": 0,
            "description": (
                "No unmatched heartbeat packets were found."
            )
        })

    # ---------------------------------------------
    # 4. CHECK SKIPPED LOG RECORDS
    # ---------------------------------------------

    if skipped > 0:

        if priority == "LOW":
            priority = "MEDIUM"

        findings.append({
            "category": "LOG_VALIDATION",
            "status": "REVIEW_REQUIRED",
            "count": skipped,
            "description": (
                "Some endpoint log records were skipped "
                "during validation."
            ),
            "recommendation": (
                "Inspect skipped records for missing or "
                "invalid fields."
            )
        })

    else:

        findings.append({
            "category": "LOG_VALIDATION",
            "status": "VALID",
            "count": 0,
            "description": (
                "No invalid endpoint log records were skipped."
            )
        })

    # ---------------------------------------------
    # 5. FINAL ASSESSMENT
    # ---------------------------------------------

    if assessment_status == "REVIEW_REQUIRED":
        summary = (
            "The available evidence is insufficient for "
            "a complete assessment. Manual review is required."
        )

    elif priority == "HIGH":
        summary = (
            "Evidence integrity requires immediate review. "
            "This classification does not establish malicious activity."
        )

    elif priority == "MEDIUM":
        summary = (
            "Some evidence discrepancies require analyst review."
        )

    else:
        summary = (
            "Available evidence passed the configured checks. "
            "No correlation discrepancies were identified."
        )

    return {
        "assessment_status": assessment_status,
        "investigation_priority": priority,
        "summary": summary,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "total_packets": total_packets,
            "matched_packets": matched,
            "unmatched_packets": unmatched,
            "high_confidence_matches": (
                correlation_summary.get("high_confidence", 0)
            ),
            "medium_confidence_matches": (
                correlation_summary.get("medium_confidence", 0)
            ),
            "skipped_log_records": skipped,
            "verified_evidence": integrity_report.get(
                "verified", 0
            ),
            "modified_evidence": integrity_report.get(
                "modified", 0
            ),
            "missing_evidence": integrity_report.get(
                "missing", 0
            )
        },
        "findings": findings,
        "classification_note": (
            "Investigation priority is a rule-based review "
            "classification, not a calibrated threat score "
            "or confirmation of an attack."
        )
    }
