
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[2]

DATABASE_DIR = PROJECT_DIR / "evidence"
DATABASE_FILE = DATABASE_DIR / "cases.db"

CASES_DIR = DATABASE_DIR / "cases"

DATABASE_DIR.mkdir(parents=True, exist_ok=True)
CASES_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


# --------------------------------------------------
# CASE DIRECTORY INITIALIZATION
# --------------------------------------------------

def initialize_case_directory(case_data: dict):

    case_id = case_data["case_id"]

    # Validate case ID before constructing a path.
    if (
        not case_id.startswith("CASE-")
        or len(case_id) != 13
        or any(c not in "0123456789ABCDEF" for c in case_id[5:])
    ):
        raise ValueError("Invalid case ID")

    case_directory = CASES_DIR / case_id

    case_directory.mkdir(parents=True, exist_ok=True)

    reports_directory = case_directory / "reports"
    reports_directory.mkdir(exist_ok=True)

    pcap_file = case_directory / "capture.pcapng"
    heartbeat_file = case_directory / "heartbeats.jsonl"

    # Create empty evidence files only if they do not exist.
    pcap_file.touch(exist_ok=True)
    heartbeat_file.touch(exist_ok=True)

    metadata_file = case_directory / "case.json"

    # Preserve existing metadata rather than overwriting it.
    if not metadata_file.exists():

        with metadata_file.open("w", encoding="utf-8") as file:
            json.dump(case_data, file, indent=4)

    return case_directory


# --------------------------------------------------
# CREATE INVESTIGATION CASE
# --------------------------------------------------

def create_case(title: str, description: str = ""):

    if not title or not title.strip():
        raise ValueError("Case title cannot be empty")

    case_id = "CASE-" + uuid.uuid4().hex[:8].upper()

    created_at = datetime.now(timezone.utc).isoformat()

    case_data = {
        "case_id": case_id,
        "title": title.strip(),
        "description": description.strip(),
        "status": "OPEN",
        "created_at": created_at
    }

    case_directory = None

    try:

        # Create case directory and evidence locations.
        case_directory = initialize_case_directory(case_data)

        # Save case metadata in SQLite.
        with get_connection() as connection:

            connection.execute("""
                INSERT INTO cases (
                    case_id,
                    title,
                    description,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                case_data["case_id"],
                case_data["title"],
                case_data["description"],
                case_data["status"],
                case_data["created_at"]
            ))

        return case_data

    except Exception:

        # Remove newly created directory if database insertion fails.
        if case_directory and case_directory.exists():
            import shutil
            shutil.rmtree(case_directory, ignore_errors=True)

        raise


# --------------------------------------------------
# LIST INVESTIGATION CASES
# --------------------------------------------------

def list_cases():

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT *
            FROM cases
            ORDER BY created_at DESC
        """).fetchall()

    return [dict(row) for row in rows]


# --------------------------------------------------
# GET SINGLE INVESTIGATION CASE
# --------------------------------------------------

def get_case(case_id: str):

    with get_connection() as connection:

        row = connection.execute("""
            SELECT *
            FROM cases
            WHERE case_id = ?
        """, (case_id,)).fetchone()

    if row is None:
        return None

    return dict(row)


# --------------------------------------------------
# REPAIR EXISTING CASE DIRECTORIES
# --------------------------------------------------

def repair_case_directories():

    cases = list_cases()

    repaired = []

    for case in cases:

        initialize_case_directory(case)

        repaired.append(case["case_id"])

    return repaired


# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

initialize_database()
