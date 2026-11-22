from pathlib import Path
import json

from services.evidence_integrity import verify_evidence_integrity


CASE_ID = "CASE-6334F4C7"

CASE_DIR = (
    Path("../evidence/cases") / CASE_ID
).resolve()


result = verify_evidence_integrity(
    CASE_ID,
    CASE_DIR
)

print("===== EVIDENCE INTEGRITY VERIFICATION =====")
print(json.dumps(result, indent=4))
