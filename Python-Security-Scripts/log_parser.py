#!/usr/bin/env python3
"""
Security Log Parser - Parse Windows Security and auth logs for key events.

Usage:
    python log_parser.py security.log
    python log_parser.py security.log --event 4625
    python log_parser.py security.log --summary
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

# Common Windows Security Event IDs
EVENT_DESCRIPTIONS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4648": "Explicit Credential Logon",
    "4672": "Special Privileges Assigned",
    "4688": "Process Creation",
    "4720": "User Account Created",
    "4726": "User Account Deleted",
    "4732": "Member Added to Security Group",
    "7045": "Service Installed",
}


def parse_log_line(line: str) -> dict | None:
    """Parse a single log line into structured fields."""
    event = {}
    patterns = {
        "event_id": r"EventID[:\s=]+(\d+)",
        "account": r"Account Name[:\s]+(\S+)",
        "source_ip": r"Source Network Address[:\s]+(\S+)",
        "logon_type": r"Logon Type[:\s]+(\d+)",
        "workstation": r"Workstation Name[:\s]+(\S+)",
        "process": r"New Process Name[:\s]+(\S+)",
        "timestamp": r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            event[key] = match.group(1)

    if "event_id" in event or any(k in line.lower() for k in ("logon", "account", "process")):
        event["raw"] = line.strip()
        return event
    return None


def parse_log_file(file_path: Path) -> list[dict]:
    """Parse entire log file."""
    events = []
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_log_line(line)
        if parsed:
            events.append(parsed)
    return events


def print_summary(events: list[dict]) -> None:
    """Print event summary statistics."""
    event_counts = Counter(e.get("event_id", "unknown") for e in events)
    print("\n=== Log Summary ===")
    print(f"Total parsed events: {len(events)}")
    print("\nEvent ID breakdown:")
    for eid, count in event_counts.most_common():
        desc = EVENT_DESCRIPTIONS.get(eid, "Unknown")
        print(f"  {eid} ({desc}): {count}")

    failed = [e for e in events if e.get("event_id") == "4625"]
    if failed:
        accounts = Counter(e.get("account", "unknown") for e in failed)
        print(f"\nFailed logins by account (top 10):")
        for acct, count in accounts.most_common(10):
            print(f"  {acct}: {count}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse security logs for key events")
    parser.add_argument("logfile", type=Path, help="Log file to parse")
    parser.add_argument("--event", "-e", help="Filter by Event ID (e.g., 4625)")
    parser.add_argument("--summary", "-s", action="store_true", help="Show summary statistics")
    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"Error: File not found: {args.logfile}", file=sys.stderr)
        return 1

    events = parse_log_file(args.logfile)

    if args.event:
        events = [e for e in events if e.get("event_id") == args.event]

    if args.summary:
        print_summary(events)
        return 0

    for event in events:
        eid = event.get("event_id", "?")
        desc = EVENT_DESCRIPTIONS.get(eid, "")
        ts = event.get("timestamp", "")
        acct = event.get("account", "")
        print(f"[{ts}] Event {eid} {desc} | Account: {acct}")

    print(f"\nTotal: {len(events)} events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
