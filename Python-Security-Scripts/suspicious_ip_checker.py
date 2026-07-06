#!/usr/bin/env python3
"""
Suspicious IP Checker - Check IPs against threat intel and identify private/reserved ranges.

Usage:
    python suspicious_ip_checker.py 185.220.101.45
    python suspicious_ip_checker.py --file iocs.txt
    python suspicious_ip_checker.py --file access.log --extract
"""

import argparse
import ipaddress
import re
import sys
from pathlib import Path

# Known suspicious ranges (examples — extend with your threat feeds)
THREAT_INTEL_IPS = {
    "185.220.101.45",
    "45.33.32.156",
    "192.0.2.100",  # TEST-NET-1 (documentation example)
}

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def load_threat_feed(feed_path: Path | None) -> set[str]:
    """Load additional IPs from threat feed file."""
    ips = set(THREAT_INTEL_IPS)
    if feed_path and feed_path.exists():
        for line in feed_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    return ips


def classify_ip(ip_str: str) -> dict:
    """Classify an IP address."""
    result = {"ip": ip_str, "status": "UNKNOWN", "details": []}
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        result["status"] = "INVALID"
        result["details"].append("Invalid IP format")
        return result

    if ip.is_private:
        result["status"] = "PRIVATE"
        result["details"].append("RFC 1918 private address")
    elif ip.is_loopback:
        result["status"] = "LOOPBACK"
    elif ip.is_reserved:
        result["status"] = "RESERVED"
    elif ip.is_multicast:
        result["status"] = "MULTICAST"
    else:
        result["status"] = "PUBLIC"

    return result


def check_ip(ip_str: str, threat_feed: set[str]) -> dict:
    """Check IP against threat intel and classify."""
    result = classify_ip(ip_str)
    if ip_str in threat_feed:
        result["status"] = "MALICIOUS"
        result["details"].append("Found in threat intelligence feed")
    return result


def extract_ips_from_file(file_path: Path) -> set[str]:
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    return set(IP_PATTERN.findall(text))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check IPs for suspicious activity")
    parser.add_argument("ips", nargs="*", help="IP addresses to check")
    parser.add_argument("--file", "-f", type=Path, help="File with IPs or log to extract from")
    parser.add_argument("--extract", "-e", action="store_true",
                        help="Extract IPs from file instead of reading as IP list")
    parser.add_argument("--feed", type=Path, help="Custom threat feed file")
    args = parser.parse_args()

    threat_feed = load_threat_feed(args.feed)
    ips_to_check: set[str] = set(args.ips)

    if args.file:
        if not args.file.exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1
        if args.extract:
            ips_to_check.update(extract_ips_from_file(args.file))
        else:
            for line in args.file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ips_to_check.add(line)

    if not ips_to_check:
        parser.print_help()
        return 1

    malicious_count = 0
    for ip in sorted(ips_to_check):
        result = check_ip(ip, threat_feed)
        marker = "***" if result["status"] == "MALICIOUS" else "   "
        details = "; ".join(result["details"]) if result["details"] else ""
        print(f"{marker} {ip:20s} [{result['status']:10s}] {details}")
        if result["status"] == "MALICIOUS":
            malicious_count += 1

    print(f"\nChecked {len(ips_to_check)} IPs, {malicious_count} malicious")
    return 1 if malicious_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
