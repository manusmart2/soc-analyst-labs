#!/usr/bin/env python3
"""
IOC Checker - Check indicators against a local IOC list.

Usage:
    python ioc_checker.py --file sample.log
    python ioc_checker.py --indicator 192.168.1.100
    python ioc_checker.py --file sample.log --iocs iocs.txt
"""

import argparse
import re
import sys
from pathlib import Path

DEFAULT_IOCS = Path(__file__).parent / "data" / "iocs.txt"

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def load_iocs(ioc_file: Path) -> set[str]:
    """Load IOCs from file (one per line, # for comments)."""
    iocs = set()
    if not ioc_file.exists():
        return iocs
    for line in ioc_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            iocs.add(line.lower())
    return iocs


def extract_indicators(text: str) -> dict[str, set[str]]:
    """Extract IPs, domains, and hashes from text."""
    return {
        "ips": set(IP_PATTERN.findall(text)),
        "domains": {d.lower() for d in DOMAIN_PATTERN.findall(text)},
        "hashes": {h.lower() for h in HASH_PATTERN.findall(text)},
    }


def check_indicator(indicator: str, iocs: set[str]) -> bool:
    return indicator.lower() in iocs


def scan_file(file_path: Path, iocs: set[str]) -> list[dict]:
    """Scan a file for IOC matches."""
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    matches = []
    for category, indicators in extract_indicators(text).items():
        for ind in indicators:
            if check_indicator(ind, iocs):
                matches.append({"type": category, "indicator": ind, "file": str(file_path)})
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Check files or indicators against an IOC list")
    parser.add_argument("--file", "-f", type=Path, help="File to scan for IOCs")
    parser.add_argument("--indicator", "-i", help="Single indicator to check")
    parser.add_argument("--iocs", type=Path, default=DEFAULT_IOCS, help="IOC list file")
    args = parser.parse_args()

    iocs = load_iocs(args.iocs)
    if not iocs:
        print(f"Warning: No IOCs loaded from {args.iocs}", file=sys.stderr)

    if args.indicator:
        found = check_indicator(args.indicator, iocs)
        status = "MATCH" if found else "NO MATCH"
        print(f"{status}: {args.indicator}")
        return 0 if not found else 1

    if args.file:
        if not args.file.exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1
        matches = scan_file(args.file, iocs)
        if matches:
            print(f"Found {len(matches)} IOC match(es) in {args.file}:")
            for m in matches:
                print(f"  [{m['type']}] {m['indicator']}")
            return 1
        print(f"No IOC matches in {args.file}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
