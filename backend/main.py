
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

from services.correlator import correlate_events
from services.timeline import build_timeline
from services.case_manager import get_case, list_cases
from services.evidence_integrity import verify_evidence_integrity
from services.investigation_analysis import analyze_investigation
from fastapi.responses import FileResponse

from services.report_generator import (
    generate_report_data,
    save_json_report,
    generate_pdf_report
)


app = FastAPI(
    title="Attacker Simulation and Investigation Dashboard",
    version="1.0.0"
)


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[1]

EVIDENCE_DIR = PROJECT_DIR / "evidence"

LOG_DIR = EVIDENCE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "heartbeats.jsonl"

PCAP_FILE = "evidence/pcaps/teacher-demo.pcapng"

CASES_DIR = EVIDENCE_DIR / "cases"


# --------------------------------------------------
# HEARTBEAT DATA MODEL
# --------------------------------------------------

class Heartbeat(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=50)
    platform: Literal["Ubuntu", "Windows"]
    status: Literal["ONLINE"]
    sequence: int = Field(ge=1)
    sent_at: datetime

    # Optional system information
    hostname: str | None = Field(default=None, max_length=255)
    os_version: str | None = Field(default=None, max_length=100)
    architecture: str | None = Field(default=None, max_length=50)
    uptime_seconds: float | None = Field(default=None, ge=0)


# --------------------------------------------------
# HOME ROUTE
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "project": "Attacker Simulation and Investigation Dashboard",
        "service": "Heartbeat Receiver",
        "status": "running"
    }


# --------------------------------------------------
# RECEIVE HEARTBEAT
# --------------------------------------------------

@app.post("/heartbeat")
def receive_heartbeat(data: Heartbeat, request: Request):

    event = {
        "event_type": "HEARTBEAT",
        "endpoint_id": data.endpoint_id,
        "platform": data.platform,
        "status": data.status,
        "sequence": data.sequence,

        # Windows system information
        "hostname": data.hostname,
        "os_version": data.os_version,
        "architecture": data.architecture,
        "uptime_seconds": data.uptime_seconds,

        "source_ip": request.client.host if request.client else None,
        "sent_at": data.sent_at.isoformat(),
        "received_at": datetime.now(timezone.utc).isoformat()
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return {
        "success": True,
        "message": "Heartbeat received",
        "event": event
    }


# --------------------------------------------------
# GET HEARTBEAT HISTORY
# --------------------------------------------------

@app.get("/heartbeats")
def get_heartbeats():

    if not LOG_FILE.exists():
        return {
            "total": 0,
            "events": []
        }

    with LOG_FILE.open("r", encoding="utf-8") as file:
        events = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    return {
        "total": len(events),
        "events": events
    }


# --------------------------------------------------
# GET ENDPOINT STATUS
# --------------------------------------------------

@app.get("/endpoints")
def get_endpoints():

    if not LOG_FILE.exists():
        return {
            "total": 0,
            "endpoints": []
        }

    latest_events = {}

    with LOG_FILE.open("r", encoding="utf-8") as file:

        for line in file:

            if not line.strip():
                continue

            event = json.loads(line)

            endpoint_id = event["endpoint_id"]
            latest_events[endpoint_id] = event

    now = datetime.now(timezone.utc)

    endpoints = []

    for endpoint_id, event in latest_events.items():

        last_seen = datetime.fromisoformat(
            event["received_at"]
        )

        age = (now - last_seen).total_seconds()

        status = "ONLINE" if age <= 15 else "OFFLINE"

        endpoints.append({
            "endpoint_id": endpoint_id,
            "platform": event["platform"],
            "status": status,
            "source_ip": event.get("source_ip"),
            "last_seen": event["received_at"],
            "seconds_since_last_heartbeat": round(age, 2),
            "last_sequence": event["sequence"],

            # Latest available system information
            "hostname": event.get("hostname"),
            "os_version": event.get("os_version"),
            "architecture": event.get("architecture"),
            "uptime_seconds": event.get("uptime_seconds")
        })

    return {
        "total": len(endpoints),
        "endpoints": endpoints
    }


# --------------------------------------------------
# LIST INVESTIGATION CASES
# --------------------------------------------------

@app.get("/cases")
def get_investigation_cases():

    cases = list_cases()

    return {
        "success": True,
        "total": len(cases),
        "cases": cases
    }


# --------------------------------------------------
# SHARED TIMELINE RESPONSE
# --------------------------------------------------

def create_timeline_response(
    correlation_report: dict,
    timeline_report: dict
):

    return {
        "success": True,
        "correlation_summary": {
            "total_packets": correlation_report["total_packets"],
            "matched": correlation_report["matched"],
            "unmatched": correlation_report["unmatched"],
            "high_confidence": correlation_report["high_confidence"],
            "medium_confidence": correlation_report["medium_confidence"],
            "skipped_log_records": correlation_report["skipped_log_records"]
        },
        "timeline_summary": timeline_report["summary"],
        "timeline": timeline_report["timeline"]
    }


# --------------------------------------------------
# ORIGINAL FIXED INVESTIGATION TIMELINE
# --------------------------------------------------

@app.get("/investigation/timeline")
def get_investigation_timeline():

    try:

        correlation_report = correlate_events(PCAP_FILE)

        timeline_report = build_timeline(correlation_report)

        response = create_timeline_response(
            correlation_report,
            timeline_report
        )

        response["project"] = (
            "Attacker Simulation and Investigation Dashboard"
        )
        response["investigation"] = "Heartbeat Network Analysis"

        return response

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Investigation PCAP file was not found"
        )

    except (ValueError, RuntimeError) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while generating the timeline"
        )


# --------------------------------------------------
# CASE-SPECIFIC INVESTIGATION TIMELINE
# --------------------------------------------------

@app.get("/cases/{case_id}/timeline")
def get_case_timeline(case_id: str):

    if not re.fullmatch(r"CASE-[0-9A-F]{8}", case_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid case ID format"
        )

    case = get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found"
        )

    case_directory = CASES_DIR / case_id

    pcap_path = case_directory / "capture.pcapng"
    log_path = case_directory / "heartbeats.jsonl"

    if not pcap_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Case PCAP evidence file was not found"
        )

    if not log_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Case heartbeat log was not found"
        )

    if pcap_path.stat().st_size == 0:
        raise HTTPException(
            status_code=409,
            detail="Case PCAP evidence file is empty"
        )

    if log_path.stat().st_size == 0:
        raise HTTPException(
            status_code=409,
            detail="Case heartbeat log is empty"
        )

    try:

        pcap_relative = pcap_path.relative_to(
            PROJECT_DIR
        ).as_posix()

        log_relative = log_path.relative_to(
            PROJECT_DIR
        ).as_posix()

        correlation_report = correlate_events(
            pcap_relative,
            log_relative
        )

        timeline_report = build_timeline(
            correlation_report
        )

        response = create_timeline_response(
            correlation_report,
            timeline_report
        )

        response["project"] = (
            "Attacker Simulation and Investigation Dashboard"
        )

        response["case"] = {
            "case_id": case["case_id"],
            "title": case["title"],
            "description": case["description"],
            "status": case["status"],
            "created_at": case["created_at"]
        }

        return response

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Case evidence file was not found"
        )

    except (ValueError, RuntimeError) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while generating the case timeline"
        )


# --------------------------------------------------
# CASE-SPECIFIC EVIDENCE INTEGRITY VERIFICATION
# --------------------------------------------------

@app.get("/cases/{case_id}/integrity")
def get_case_integrity(case_id: str):

    if not re.fullmatch(r"CASE-[0-9A-F]{8}", case_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid case ID format"
        )

    case = get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found"
        )

    case_directory = CASES_DIR / case_id

    if not case_directory.is_dir():
        raise HTTPException(
            status_code=404,
            detail="Case evidence directory was not found"
        )

    try:

        integrity_report = verify_evidence_integrity(
            case_id,
            case_directory
        )

        return {
            "success": True,
            "project": "Attacker Simulation and Investigation Dashboard",
            "case": {
                "case_id": case["case_id"],
                "title": case["title"],
                "status": case["status"]
            },
            "integrity_report": integrity_report
        }

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

    except (ValueError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred during evidence verification"
        )




def safe_correlate(capture_file, heartbeat_file):
    """Correlate evidence. If a required file is missing, return an empty
    result so integrity-based analysis and reports can still be produced."""
    if not capture_file.is_file() or not heartbeat_file.is_file():
        return {
            "total_packets": 0, "matched": 0, "unmatched": 0,
            "high_confidence": 0, "medium_confidence": 0,
            "skipped_log_records": 0, "results": [],
            "correlation_performed": False,
            "note": "Correlation was not performed because required evidence is missing."
        }
    return correlate_events(capture_file, heartbeat_file)


@app.get("/cases/{case_id}/analysis")
def get_case_analysis(case_id: str):
    # Validate case ID
    if not re.fullmatch(r"CASE-[0-9A-F]{8}", case_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid case ID format."
        )

    # Retrieve case
    case = get_case(case_id)

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    case_directory = CASES_DIR / case_id

    capture_file = case_directory / "capture.pcapng"
    heartbeat_file = case_directory / "heartbeats.jsonl"


    try:
        # Generate correlation results
        correlation_report = safe_correlate(capture_file, heartbeat_file)

        # Verify evidence integrity
        integrity_report = verify_evidence_integrity(
            case_id,
            case_directory
        )

        # Generate investigation assessment
        analysis_report = analyze_investigation(
            correlation_report,
            integrity_report
        )

        return {
            "success": True,
            "case": case,
            "analysis": analysis_report
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation analysis failed: {str(error)}"
        )

def prepare_case_report(case_id: str):
    # Validate case ID
    if not re.fullmatch(r"CASE-[0-9A-F]{8}", case_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid case ID format."
        )

    # Retrieve case
    case = get_case(case_id)

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    case_directory = CASES_DIR / case_id

    capture_file = case_directory / "capture.pcapng"
    heartbeat_file = case_directory / "heartbeats.jsonl"


    reports_directory = case_directory / "reports"

    try:
        # Recalculate results from current case evidence
        correlation_report = safe_correlate(capture_file, heartbeat_file)
        timeline_report = (
            {"summary": {}, "timeline": []}
            if correlation_report.get("correlation_performed") is False
            else build_timeline(correlation_report)
        )

        integrity_report = verify_evidence_integrity(
            case_id,
            case_directory
        )

        analysis_report = analyze_investigation(
            correlation_report,
            integrity_report
        )

        report_data = generate_report_data(
            case,
            analysis_report,
            correlation_report,
            integrity_report,
            timeline_report
        )

        return report_data, reports_directory

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Report preparation failed: {str(error)}"
        )



@app.get("/cases/{case_id}/reports/json")
def download_json_report(case_id: str):

    report_data, reports_directory = prepare_case_report(case_id)

    report_path = save_json_report(
        report_data,
        reports_directory
    )

    return FileResponse(
        path=str(report_path),
        media_type="application/json",
        filename="investigation_report.json"
    )





@app.get("/cases/{case_id}/reports/pdf")
def download_pdf_report(case_id: str):

    report_data, reports_directory = prepare_case_report(case_id)

    report_path = generate_pdf_report(
        report_data,
        reports_directory
    )

    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename="investigation_report.pdf"
    )
