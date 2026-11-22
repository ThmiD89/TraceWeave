
import json
import shutil
from pathlib import Path

from services.evidence_integrity import verify_evidence_integrity


CASE_ID = "CASE-6334F4C7"

SOURCE_DIR = (
    Path("../evidence/cases") / CASE_ID
).resolve()

TEST_DIR = (
    Path("../evidence/integrity-test")
).resolve()


# --------------------------------------------------
# PREPARE TEMPORARY TEST COPY
# --------------------------------------------------

if not SOURCE_DIR.is_dir():
    raise FileNotFoundError("Original case directory not found")

if TEST_DIR.exists():
    shutil.rmtree(TEST_DIR)

shutil.copytree(SOURCE_DIR, TEST_DIR)


# --------------------------------------------------
# TEST 1: BASELINE VERIFICATION
# --------------------------------------------------

print("\n===== TEST 1: BASELINE VERIFICATION =====")

baseline = verify_evidence_integrity(
    CASE_ID,
    TEST_DIR,
    allow_test_directory=True
)

print(json.dumps(baseline, indent=4))

if baseline["integrity_status"] != "INTEGRITY_VERIFIED":
    raise RuntimeError("Baseline verification failed")

print("\nBaseline test passed.")

# --------------------------------------------------
# TEST 2: MODIFIED EVIDENCE DETECTION
# --------------------------------------------------

print("\n===== TEST 2: MODIFIED EVIDENCE DETECTION =====")

test_log = TEST_DIR / "heartbeats.jsonl"

with test_log.open("ab") as file:
    file.write(b"\n# TEST MODIFICATION\n")

modified_result = verify_evidence_integrity(
    CASE_ID,
    TEST_DIR,
    allow_test_directory=True
)

print(json.dumps(modified_result, indent=4))

if modified_result["integrity_status"] != "INTEGRITY_FAILED":
    raise RuntimeError("Tampering was not detected")

if modified_result["modified"] != 1:
    raise RuntimeError("Expected exactly one modified evidence file")

print("\nTampering detection test passed.")


# --------------------------------------------------
# TEST 3: MISSING EVIDENCE DETECTION
# --------------------------------------------------

print("\n===== TEST 3: MISSING EVIDENCE DETECTION =====")

# Restore a clean temporary copy from the original case.
shutil.rmtree(TEST_DIR)
shutil.copytree(SOURCE_DIR, TEST_DIR)

# Remove only the copied PCAP.
test_pcap = TEST_DIR / "capture.pcapng"
test_pcap.unlink()

missing_result = verify_evidence_integrity(
    CASE_ID,
    TEST_DIR,
    allow_test_directory=True
)

print(json.dumps(missing_result, indent=4))

if missing_result["integrity_status"] != "INTEGRITY_FAILED":
    raise RuntimeError("Missing evidence was not detected")

if missing_result["missing"] != 1:
    raise RuntimeError("Expected exactly one missing evidence file")

print("\nMissing evidence detection test passed.")
