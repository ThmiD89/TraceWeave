from pathlib import Path

from services.evidence_integrity import calculate_sha256


CASE_DIR = Path("../evidence/cases/CASE-6334F4C7")

pcap_file = CASE_DIR / "capture.pcapng"
log_file = CASE_DIR / "heartbeats.jsonl"


print("===== EVIDENCE SHA-256 TEST =====")

for file_path in [pcap_file, log_file]:

    if not file_path.is_file():
        print(f"File not found: {file_path}")
        continue

    file_hash = calculate_sha256(file_path)

    print(f"\nFile: {file_path.name}")
    print(f"Size: {file_path.stat().st_size} bytes")
    print(f"SHA-256: {file_hash}")
