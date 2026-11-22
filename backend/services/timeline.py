
from datetime import datetime, timezone


def build_timeline(correlation_report: dict):
    """
    Build a chronological investigation timeline
    from the correlation report.
    """

    timeline_events = []

    for result in correlation_report.get("results", []):

        # ------------------------------------------------
        # 1. ENDPOINT EVENT
        # ------------------------------------------------

        if result.get("sent_at"):

            timeline_events.append({
                "timestamp": result["sent_at"],
                "event_type": "ENDPOINT",
                "description": (
                    f"{result.get('platform', 'Unknown')} "
                    f"endpoint sent heartbeat"
                ),
                "endpoint_id": result.get("endpoint_id"),
                "sequence": result.get("sequence"),
                "source_ip": result.get("source_ip"),
                "evidence": "Endpoint heartbeat log",
            })

        # ------------------------------------------------
        # 2. NETWORK EVENT
        # ------------------------------------------------

        packet_timestamp = result.get("packet_timestamp")

        if packet_timestamp is not None:

            network_time = datetime.fromtimestamp(
                packet_timestamp,
                tz=timezone.utc
            ).isoformat()

            timeline_events.append({
                "timestamp": network_time,
                "event_type": "NETWORK",
                "description": (
                    "Heartbeat HTTP POST request captured"
                ),
                "endpoint_id": result.get("endpoint_id"),
                "frame_number": result.get("frame_number"),
                "source_ip": result.get("source_ip"),
                "destination_ip": result.get("destination_ip"),
                "evidence": "PCAP network capture",
            })

        # ------------------------------------------------
        # 3. CORRELATION EVENT
        # ------------------------------------------------

        if result.get("correlation_status") == "MATCHED":

            received_at = result.get("received_at")

            if received_at:

                timeline_events.append({
                    "timestamp": received_at,
                    "event_type": "CORRELATION",
                    "description": (
                        "Network packet matched with endpoint log"
                    ),
                    "endpoint_id": result.get("endpoint_id"),
                    "frame_number": result.get("frame_number"),
                    "sequence": result.get("sequence"),
                    "confidence": result.get("confidence"),
                    "confidence_reason": result.get(
                        "confidence_reason"
                    ),
                    "time_difference_seconds": result.get(
                        "time_difference_seconds"
                    ),
                    "evidence": "Endpoint and PCAP correlation",
                })

    # ------------------------------------------------
    # 4. CHRONOLOGICAL SORTING
    # ------------------------------------------------

    timeline_events.sort(
        key=lambda event: datetime.fromisoformat(
            event["timestamp"]
        )
    )

    # ------------------------------------------------
    # 5. TIMELINE SUMMARY
    # ------------------------------------------------

    summary = {
        "total_events": len(timeline_events),
        "endpoint_events": sum(
            1 for event in timeline_events
            if event["event_type"] == "ENDPOINT"
        ),
        "network_events": sum(
            1 for event in timeline_events
            if event["event_type"] == "NETWORK"
        ),
        "correlation_events": sum(
            1 for event in timeline_events
            if event["event_type"] == "CORRELATION"
        ),
    }

    return {
        "timeline": timeline_events,
        "summary": summary,
    }
