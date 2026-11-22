
import json
from datetime import datetime
from pathlib import Path

from services.pcap_parser import parse_heartbeat_packets


PROJECT_DIR = Path(__file__).resolve().parents[2]

EVIDENCE_DIR = (PROJECT_DIR / "evidence").resolve()
LOG_DIR = (EVIDENCE_DIR / "logs").resolve()
CASES_DIR = (EVIDENCE_DIR / "cases").resolve()

DEFAULT_LOG_FILE = LOG_DIR / "heartbeats.jsonl"

TIME_TOLERANCE_SECONDS = 5
HIGH_CONFIDENCE_THRESHOLD = 1


def validate_log_path(log_path: str | None = None) -> Path:
    """Validate that the selected JSONL log is inside an allowed evidence directory."""

    selected_path = log_path or str(DEFAULT_LOG_FILE)
    path = (PROJECT_DIR / selected_path).resolve(strict=True)

    allowed_directories = [LOG_DIR, CASES_DIR]

    if not any(
        path.is_relative_to(directory)
        for directory in allowed_directories
    ):
        raise ValueError(
            "Log file must be inside evidence/logs or evidence/cases"
        )

    if not path.is_file():
        raise ValueError("Log path must point to a file")

    if path.suffix.lower() != ".jsonl":
        raise ValueError("Unsupported log file extension")

    return path


def load_heartbeat_events(log_path: str | None = None):
    """Load valid heartbeat records from the selected JSONL evidence file."""

    path = validate_log_path(log_path)

    events = []
    skipped_records = 0

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not event.get("source_ip"):
                    skipped_records += 1
                    continue

                datetime.fromisoformat(event["received_at"])

                events.append(event)

            except (json.JSONDecodeError, KeyError, ValueError):
                skipped_records += 1

    return events, skipped_records


def correlate_events(
    pcap_path: str,
    log_path: str | None = None
):
    """Correlate captured heartbeat packets with a selected endpoint log."""

    packets = parse_heartbeat_packets(pcap_path)

    events, skipped_records = load_heartbeat_events(log_path)

    results = []

    # Each endpoint log record can only be matched once.
    used_event_indices = set()

    for packet in packets:

        packet_time = packet["timestamp"]

        best_match = None
        best_match_index = None
        smallest_difference = float("inf")

        for event_index, event in enumerate(events):

            if event_index in used_event_indices:
                continue

            same_ip = (
                packet["source_ip"] == event["source_ip"]
            )

            if not same_ip:
                continue

            received_time = datetime.fromisoformat(
                event["received_at"]
            ).timestamp()

            difference = abs(received_time - packet_time)

            if (
                difference <= TIME_TOLERANCE_SECONDS
                and difference < smallest_difference
            ):
                smallest_difference = difference
                best_match = event
                best_match_index = event_index

        if best_match:

            used_event_indices.add(best_match_index)

            if smallest_difference <= HIGH_CONFIDENCE_THRESHOLD:
                confidence = "HIGH"
                confidence_reason = (
                    "Same source IP and timestamp difference "
                    "within 1 second"
                )
            else:
                confidence = "MEDIUM"
                confidence_reason = (
                    "Same source IP and timestamp difference "
                    "within 5 seconds"
                )

            results.append({
                "correlation_status": "MATCHED",
                "confidence": confidence,
                "confidence_reason": confidence_reason,
                "frame_number": packet["frame_number"],
                "endpoint_id": best_match["endpoint_id"],
                "platform": best_match["platform"],
                "sequence": best_match["sequence"],
                "source_ip": packet["source_ip"],
                "destination_ip": packet["destination_ip"],
                "packet_timestamp": packet_time,
                "sent_at": best_match["sent_at"],
                "received_at": best_match["received_at"],
                "time_difference_seconds": round(
                    smallest_difference, 6
                ),
            })

        else:

            results.append({
                "correlation_status": "UNMATCHED",
                "confidence": "UNMATCHED",
                "confidence_reason": (
                    "No eligible endpoint log record found"
                ),
                "frame_number": packet["frame_number"],
                "source_ip": packet["source_ip"],
                "destination_ip": packet["destination_ip"],
                "packet_timestamp": packet_time,
            })

    return {
        "results": results,
        "total_packets": len(packets),
        "matched": sum(
            1 for item in results
            if item["correlation_status"] == "MATCHED"
        ),
        "unmatched": sum(
            1 for item in results
            if item["correlation_status"] == "UNMATCHED"
        ),
        "high_confidence": sum(
            1 for item in results
            if item["confidence"] == "HIGH"
        ),
        "medium_confidence": sum(
            1 for item in results
            if item["confidence"] == "MEDIUM"
        ),
        "skipped_log_records": skipped_records,
    }
