#!/usr/bin/env python3
"""
VirusTotal API Lookup - Query file hashes, IPs, domains, and URLs.

Requires VT_API_KEY environment variable.
Get a free API key at: https://www.virustotal.com/gui/join-us

Usage:
    set VT_API_KEY=your_key_here
    python virustotal_lookup.py --hash <sha256>
    python virustotal_lookup.py --ip 8.8.8.8
    python virustotal_lookup.py --domain example.com
    python virustotal_lookup.py --url "https://example.com"
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

VT_API_BASE = "https://www.virustotal.com/api/v3"


def get_api_key() -> str:
    key = os.environ.get("VT_API_KEY", "")
    if not key:
        print("Error: Set VT_API_KEY environment variable", file=sys.stderr)
        print("  Get a free key at https://www.virustotal.com/gui/join-us", file=sys.stderr)
        sys.exit(1)
    return key


def vt_request(endpoint: str) -> dict:
    """Make authenticated request to VirusTotal API v3."""
    api_key = get_api_key()
    url = f"{VT_API_BASE}/{endpoint}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"VT API Error {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


def lookup_hash(file_hash: str) -> None:
    data = vt_request(f"files/{file_hash}")
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    print(f"\n=== Hash: {file_hash} ===")
    print(f"Detections: {malicious}/{total}")
    print(f"MD5:    {attrs.get('md5', 'N/A')}")
    print(f"SHA1:   {attrs.get('sha1', 'N/A')}")
    print(f"SHA256: {attrs.get('sha256', 'N/A')}")

    if malicious > 0:
        print("\nTop detections:")
        for engine, result in results.items():
            if result.get("category") == "malicious":
                print(f"  {engine}: {result.get('result', 'malicious')}")


def lookup_ip(ip: str) -> None:
    data = vt_request(f"ip_addresses/{ip}")
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    print(f"\n=== IP: {ip} ===")
    print(f"Detections: {malicious}/{total}")
    print(f"Country: {attrs.get('country', 'N/A')}")
    print(f"AS Owner: {attrs.get('as_owner', 'N/A')}")
    print(f"Reputation: {attrs.get('reputation', 'N/A')}")


def lookup_domain(domain: str) -> None:
    data = vt_request(f"domains/{domain}")
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    print(f"\n=== Domain: {domain} ===")
    print(f"Detections: {malicious}/{total}")
    print(f"Registrar: {attrs.get('registrar', 'N/A')}")
    print(f"Creation Date: {attrs.get('creation_date', 'N/A')}")
    print(f"Reputation: {attrs.get('reputation', 'N/A')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="VirusTotal API lookup tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hash", help="File hash (MD5, SHA1, or SHA256)")
    group.add_argument("--ip", help="IP address to lookup")
    group.add_argument("--domain", "-d", help="Domain to lookup")
    group.add_argument("--url", "-u", help="URL to lookup")
    args = parser.parse_args()

    if args.hash:
        lookup_hash(args.hash)
    elif args.ip:
        lookup_ip(args.ip)
    elif args.domain:
        lookup_domain(args.domain)
    elif args.url:
        import base64
        url_id = base64.urlsafe_b64encode(args.url.encode()).decode().strip("=")
        data = vt_request(f"urls/{url_id}")
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        print(f"\n=== URL: {args.url} ===")
        print(f"Detections: {stats.get('malicious', 0)}/{sum(stats.values())}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
