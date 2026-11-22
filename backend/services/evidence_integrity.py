
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

REQUIRED_EVIDENCE_FILES = {
    "capture.pcapng",
    "heartbeats.jsonl"
}


# --------------------------------------------------
# EVIDENCE HASH CALCULATION
# --------------------------------------------------

def calculate_sha256(file_path: Path) -> str:
    """
    Calculate the SHA-256 hash of a file.
    Reads the file in chunks.
    """

    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# --------------------------------------------------
# CASE DIRECTORY VALIDATION
# --------------------------------------------------

def validate_case_directory(
    case_id: str,
    case_directory: Path,
    allow_test_directory: bool = False
) -> Path:
    """
    Validate the evidence directory.

    Normal operation accepts only the registered case directory.

    Testing mode additionally accepts one fixed temporary
    directory: evidence/integrity-test.
    """

    if not re.fullmatch(r"CASE-[0-9A-F]{8}", case_id):
        raise ValueError("Invalid case ID format")

    cases_root = (
        Path(__file__).resolve().parents[2]
        / "evidence"
        / "cases"
    ).resolve()

    case_directory = case_directory.resolve(strict=True)

    expected_directory = cases_root / case_id

    if case_directory == expected_directory:
        if not case_directory.is_dir():
            raise ValueError("Case path must be a directory")

        return case_directory

    if allow_test_directory:

        test_directory = (
            cases_root.parent / "integrity-test"
        ).resolve()

        if case_directory == test_directory:
            if not case_directory.is_dir():
                raise ValueError("Test path must be a directory")

            return case_directory

    raise ValueError("Invalid case evidence directory")


# --------------------------------------------------
# CREATE EVIDENCE MANIFEST
# --------------------------------------------------

def create_evidence_manifest(
    case_id: str,
    case_directory: Path
) -> dict:
    """
    Create an evidence integrity manifest.

    Records:
    - Filename
    - File size
    - SHA-256 hash
    - Creation timestamp

    Existing manifests are never overwritten.
    """

    case_directory = validate_case_directory(
        case_id,
        case_directory
    )

    manifest_path = case_directory / "evidence_manifest.json"

    if manifest_path.exists():
        raise FileExistsError(
            "Evidence manifest already exists. "
            "It will not be overwritten."
        )

    evidence_records = []

    for filename in sorted(REQUIRED_EVIDENCE_FILES):

        file_path = case_directory / filename

        if not file_path.is_file():
            raise FileNotFoundError(
                f"Evidence file not found: {filename}"
            )

        if file_path.stat().st_size == 0:
            raise ValueError(
                f"Evidence file is empty: {filename}"
            )

        evidence_records.append({
            "filename": filename,
            "size_bytes": file_path.stat().st_size,
            "sha256": calculate_sha256(file_path)
        })

    manifest = {
        "case_id": case_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hash_algorithm": "SHA-256",
        "evidence_count": len(evidence_records),
        "evidence": evidence_records
    }

    # Exclusive creation prevents accidental overwriting.
    with manifest_path.open("x", encoding="utf-8") as file:
        json.dump(manifest, file, indent=4)
        file.write("\n")

    return manifest


# --------------------------------------------------
# VERIFY EVIDENCE INTEGRITY
# --------------------------------------------------

def verify_evidence_integrity(
    case_id: str,
    case_directory: Path,
    allow_test_directory: bool = False
) -> dict:
    """
    Compare evidence against its saved manifest.

    Checks:
    - Manifest structure
    - Required evidence records
    - Duplicate filenames
    - Evidence existence
    - File size
    - SHA-256 hash

    Does not modify evidence or the manifest.
    """

    case_directory = validate_case_directory(
        case_id,
        case_directory,
        allow_test_directory=allow_test_directory
    )

    manifest_path = case_directory / "evidence_manifest.json"

    if not manifest_path.is_file():
        raise FileNotFoundError(
            "Evidence manifest was not found"
        )

    try:
        with manifest_path.open("r", encoding="utf-8") as file:
            manifest = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            "Evidence manifest contains invalid JSON"
        ) from error

    if not isinstance(manifest, dict):
        raise ValueError("Invalid evidence manifest")

    if manifest.get("case_id") != case_id:
        raise ValueError("Manifest case ID does not match")

    if manifest.get("hash_algorithm") != "SHA-256":
        raise ValueError("Unsupported hash algorithm")

    records = manifest.get("evidence")

    if not isinstance(records, list):
        raise ValueError("Invalid evidence records")

    if manifest.get("evidence_count") != len(records):
        raise ValueError(
            "Evidence count does not match manifest records"
        )

    # --------------------------------------------------
    # STRICT MANIFEST VALIDATION
    # --------------------------------------------------

    if len(records) != len(REQUIRED_EVIDENCE_FILES):
        raise ValueError(
            "Manifest must contain exactly the required evidence files"
        )

    manifest_files = set()

    for record in records:

        if not isinstance(record, dict):
            raise ValueError("Invalid evidence record")

        filename = record.get("filename")

        if not isinstance(filename, str):
            raise ValueError("Invalid evidence filename")

        if filename in manifest_files:
            raise ValueError("Duplicate evidence record")

        manifest_files.add(filename)

    if manifest_files != REQUIRED_EVIDENCE_FILES:
        raise ValueError(
            "Manifest must contain exactly the required evidence files"
        )

    # --------------------------------------------------
    # VERIFY EACH EVIDENCE FILE
    # --------------------------------------------------

    results = []

    for record in records:

        filename = record["filename"]
        expected_hash = record.get("sha256")
        expected_size = record.get("size_bytes")

        if (
            not isinstance(expected_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        ):
            raise ValueError(
                "Invalid SHA-256 value in manifest"
            )

        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
        ):
            raise ValueError(
                "Invalid file size in manifest"
            )

        file_path = case_directory / filename

        if not file_path.is_file():
            results.append({
                "filename": filename,
                "status": "MISSING",
                "expected_sha256": expected_hash
            })
            continue

        actual_size = file_path.stat().st_size
        actual_hash = calculate_sha256(file_path)

        size_matches = actual_size == expected_size
        hash_matches = actual_hash == expected_hash

        if size_matches and hash_matches:
            status = "VERIFIED"
        else:
            status = "MODIFIED"

        results.append({
            "filename": filename,
            "status": status,
            "expected_size_bytes": expected_size,
            "actual_size_bytes": actual_size,
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash
        })

    # --------------------------------------------------
    # INTEGRITY SUMMARY
    # --------------------------------------------------

    verified = sum(
        1 for item in results
        if item["status"] == "VERIFIED"
    )

    modified = sum(
        1 for item in results
        if item["status"] == "MODIFIED"
    )

    missing = sum(
        1 for item in results
        if item["status"] == "MISSING"
    )

    integrity_status = (
        "INTEGRITY_FAILED"
        if modified or missing
        else "INTEGRITY_VERIFIED"
    )

    return {
        "case_id": case_id,
        "integrity_status": integrity_status,
        "total_evidence": len(results),
        "verified": verified,
        "modified": modified,
        "missing": missing,
        "evidence": results
    }
