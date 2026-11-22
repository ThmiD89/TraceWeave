import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from services.evidence_integrity import create_evidence_manifest

BASE = Path("../evidence")
CASES = BASE / "cases"
SRC = CASES / "CASE-6334F4C7"
CASE_ID = "CASE-DEAD0005"
DST = CASES / CASE_ID

# Reset: remove any previous run of this demo case
if DST.exists():
    shutil.rmtree(DST)

DST.mkdir()
(DST / "reports").mkdir()
for name in ("capture.pcapng", "heartbeats.jsonl"):
    shutil.copy2(SRC / name, DST / name)

case = {
    "case_id": CASE_ID,
    "title": "Demo 5: Remote Tampering via SSH",
    "description": "Clean baseline; evidence will be altered over SSH during the live demo.",
    "status": "OPEN",
    "created_at": datetime.now(timezone.utc).isoformat(),
}
(DST / "case.json").write_text(json.dumps(case, indent=4))

# Manifest is built from the clean files: this is the trusted baseline
create_evidence_manifest(CASE_ID, DST)

# Register the case so the dashboard can see it
db = sqlite3.connect(BASE / "cases.db")
db.execute(
    "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?)",
    (case["case_id"], case["title"], case["description"], case["status"], case["created_at"]),
)
db.commit()
db.close()

print("Created and registered", CASE_ID)
