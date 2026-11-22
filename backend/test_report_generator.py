from pathlib import Path

from services.case_manager import get_case
from services.correlator import correlate_events
from services.evidence_integrity import verify_evidence_integrity
from services.investigation_analysis import analyze_investigation

from services.report_generator import (
    generate_report_data,
    save_json_report,
    generate_pdf_report
)


# --------------------------------------------------
# TEST CONFIGURATION
# --------------------------------------------------

CASE_ID = "CASE-6334F4C7"

PROJECT_DIR = Path(__file__).resolve().parents[1]

CASE_DIR = PROJECT_DIR / "evidence" / "cases" / CASE_ID

REPORTS_DIR = CASE_DIR / "reports"


# --------------------------------------------------
# RETRIEVE CASE
# --------------------------------------------------

case = get_case(CASE_ID)

if not case:
    raise RuntimeError("Investigation case not found.")

capture_file = CASE_DIR / "capture.pcapng"
heartbeat_file = CASE_DIR / "heartbeats.jsonl"

if not capture_file.is_file() or not heartbeat_file.is_file():
    raise RuntimeError("Required evidence files are missing.")


# --------------------------------------------------
# GENERATE INVESTIGATION DATA
# --------------------------------------------------

correlation_report = correlate_events(
    capture_file,
    heartbeat_file
)

integrity_report = verify_evidence_integrity(
    CASE_ID,
    CASE_DIR
)

analysis_report = analyze_investigation(
    correlation_report,
    integrity_report
)


# --------------------------------------------------
# BUILD REPORT DATA
# --------------------------------------------------

report_data = generate_report_data(
    case,
    analysis_report,
    correlation_report,
    integrity_report
)


# --------------------------------------------------
# GENERATE JSON
# --------------------------------------------------

json_path = save_json_report(
    report_data,
    REPORTS_DIR
)


# --------------------------------------------------
# GENERATE PDF
# --------------------------------------------------

pdf_path = generate_pdf_report(
    report_data,
    REPORTS_DIR
)


# --------------------------------------------------
# RESULTS
# --------------------------------------------------

print("\n===== TRACEWEAVE REPORT GENERATION =====")

print("Case ID:", CASE_ID)

print("Investigation Priority:",
      analysis_report["investigation_priority"])

print("Integrity Status:",
      integrity_report["integrity_status"])

print("\nJSON Report:", json_path)
print("PDF Report:", pdf_path)

print("\n===== REPORT FILES =====")

for file in REPORTS_DIR.iterdir():
    if file.is_file():
        print(file.name, "-", file.stat().st_size, "bytes")

print("\nReport generation test completed successfully.")
