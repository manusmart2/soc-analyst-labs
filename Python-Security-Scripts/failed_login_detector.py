#!/usr/bin/env python3
"""
Failed Login Detector - Identify brute-force patterns in auth logs.

Usage:
    python failed_login_detector.py auth.log
    python failed_login_detector.py auth.log --threshold 5
    python failed_login_detector.py auth.log --window 300
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

FAILED_PATTERNS = [
    r"EventID[:\s=]+4625",
    r"failed.*logon",
    r"authentication.*failed",
    r"login.*failed",
]


def is_failed_login(line: str) -> bool:
    return any(re.search(p, line, re.IGNORECASE) for p in FAILED_PATTERNS)


def extract_fields(line: str) -> dict:
    fields = {}
    for name, pattern in {
        "account": r"Account Name[:\s]+(\S+)",
        "source_ip": r"Source Network Address[:\s]+(\S+)",
        "timestamp": r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})",
        "workstation": r"Workstation Name[:\s]+(\S+)",
    }.items():
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            fields[name] = match.group(1)
    return fields


def detect_brute_force(
  log_path: Path, threshold: int = 5
) -> list[dict]:
    """Detect accounts/IPs exceeding failed login threshold."""
    failures: dict[str, list] = defaultdict(list)

    for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not is_failed_login(line):
            continue
        fields = extract_fields(line)
        account = fields.get("account", "unknown")
        src_ip = fields.get("source_ip", "unknown")
        key = f"{account}|{src_ip}"
        failures[key].append(fields)

    alerts = []
    for key, attempts in failures.items():
        if len(attempts) >= threshold:
            account, src_ip = key.split("|", 1)
            alerts.append({
                "account": account,
                "source_ip": src_ip,
                "failed_attempts": len(attempts),
                "severity": "HIGH" if len(attempts) >= 10 else "MEDIUM",
            })
    return sorted(alerts, key=lambda x: x["failed_attempts"], reverse=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect brute-force login attempts")
    parser.add_argument("logfile", type=Path, help="Authentication log file")
    parser.add_argument("--threshold", "-t", type=int, default=5,
                        help="Failed attempts before alert (default: 5)")
    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"Error: File not found: {args.logfile}", file=sys.stderr)
        return 1

    alerts = detect_brute_force(args.logfile, args.threshold)

    if not alerts:
        print(f"No brute-force patterns detected (threshold: {args.threshold})")
        return 0

    print(f"=== BRUTE FORCE ALERTS (threshold: {args.threshold}) ===\n")
    for alert in alerts:
        print(f"[{alert['severity']}] Account: {alert['account']}")
        print(f"  Source IP: {alert['source_ip']}")
        print(f"  Failed attempts: {alert['failed_attempts']}")
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
