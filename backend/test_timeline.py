from services.correlator import correlate_events
from services.timeline import build_timeline


pcap = "evidence/pcaps/teacher-demo.pcapng"

# Generate correlation report.
report = correlate_events(pcap)

# Generate investigation timeline.
timeline_report = build_timeline(report)

print("\n===== INVESTIGATION TIMELINE =====\n")

for event in timeline_report["timeline"]:
    print(event)

print("\n===== TIMELINE SUMMARY =====")

for key, value in timeline_report["summary"].items():
    print(f"{key}: {value}")
