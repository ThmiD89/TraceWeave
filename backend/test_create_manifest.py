from pathlib import Path
import json

from services.evidence_integrity import create_evidence_manifest


CASE_ID = "CASE-6334F4C7"

CASE_DIR = (
    Path("../evidence/cases") / CASE_ID
).resolve()

manifest = create_evidence_manifest(
    CASE_ID,
    CASE_DIR
)

print("===== EVIDENCE MANIFEST CREATED =====")
print(json.dumps(manifest, indent=4))

print("\nManifest location:")
print(CASE_DIR / "evidence_manifest.json")
