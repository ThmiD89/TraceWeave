
from unittest.mock import patch

from services.correlator import correlate_events


# One synthetic endpoint log record.
fake_events = [
    {
        "endpoint_id": "UBUNTU-TEST",
        "platform": "Ubuntu",
        "sequence": 1,
        "source_ip": "192.168.0.128",
        "sent_at": "2026-11-19T05:51:30+00:00",
        "received_at": "2026-11-19T05:51:32+00:00",
    }
]

# Two synthetic packets competing for that same log record.
fake_packets = [
    {
        "frame_number": 10,
        "timestamp": 1795067492.0,
        "source_ip": "192.168.0.128",
        "destination_ip": "192.168.0.127",
    },
    {
        "frame_number": 11,
        "timestamp": 1795067492.5,
        "source_ip": "192.168.0.128",
        "destination_ip": "192.168.0.127",
    },
]

with patch(
    "services.correlator.parse_heartbeat_packets",
    return_value=fake_packets,
), patch(
    "services.correlator.load_heartbeat_events",
    return_value=(fake_events, 0),
):

    report = correlate_events("synthetic-test.pcapng")


print("\n===== ONE-TO-ONE TEST =====\n")

for result in report["results"]:
    print(result)

print("\n===== SUMMARY =====")
print("Total packets:", report["total_packets"])
print("Matched:", report["matched"])
print("Unmatched:", report["unmatched"])
