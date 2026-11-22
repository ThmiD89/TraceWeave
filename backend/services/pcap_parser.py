
import csv
import io
import shutil
import subprocess
from pathlib import Path


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[2]

EVIDENCE_DIR = (PROJECT_DIR / "evidence").resolve()

PCAP_DIR = (EVIDENCE_DIR / "pcaps").resolve()
CASES_DIR = (EVIDENCE_DIR / "cases").resolve()


# --------------------------------------------------
# TSHARK FIELDS
# --------------------------------------------------

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "http.request.method",
    "http.request.uri",
]


# --------------------------------------------------
# VALIDATE PCAP LOCATION
# --------------------------------------------------

def validate_pcap_path(pcap_path: str) -> Path:

    path = (PROJECT_DIR / pcap_path).resolve(strict=True)

    # Only allow PCAP files inside approved evidence directories.
    allowed_directories = [PCAP_DIR, CASES_DIR]

    if not any(
        path.is_relative_to(directory)
        for directory in allowed_directories
    ):
        raise ValueError(
            "PCAP must be inside evidence/pcaps or evidence/cases"
        )

    if not path.is_file():
        raise ValueError("PCAP path must point to a file")

    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Unsupported capture file extension")

    return path


# --------------------------------------------------
# PARSE HEARTBEAT PACKETS
# --------------------------------------------------

def parse_heartbeat_packets(pcap_path: str) -> list[dict]:

    path = validate_pcap_path(pcap_path)

    tshark = shutil.which("tshark")

    if not tshark:
        raise RuntimeError("TShark is not installed or not in PATH")

    command = [
        tshark,
        "-r", str(path),
        "-Y",
        'http.request.method == "POST" && '
        'http.request.uri == "/heartbeat"',
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )

    reader = csv.DictReader(io.StringIO(result.stdout))

    packets = []

    for row in reader:

        if not row.get("frame.number"):
            continue

        packets.append({
            "frame_number": int(row["frame.number"]),
            "timestamp": float(row["frame.time_epoch"]),
            "source_ip": row.get("ip.src"),
            "destination_ip": row.get("ip.dst"),
            "source_port": row.get("tcp.srcport"),
            "destination_port": row.get("tcp.dstport"),
            "tcp_stream": row.get("tcp.stream"),
            "method": row.get("http.request.method"),
            "uri": row.get("http.request.uri"),
        })

    return packets
