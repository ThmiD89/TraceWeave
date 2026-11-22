
from services.correlator import correlate_events


pcap = "evidence/pcaps/teacher-demo.pcapng"

report = correlate_events(pcap)

print("\n===== EVENT CORRELATION RESULTS =====\n")

for result in report["results"]:
    print(result)

print("\n===== CORRELATION SUMMARY =====")

print("Total packets:", report["total_packets"])
print("Matched:", report["matched"])
print("Unmatched:", report["unmatched"])
print("Skipped old/incomplete log records:",
      report["skipped_log_records"])
