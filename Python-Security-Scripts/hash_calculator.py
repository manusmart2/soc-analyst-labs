#!/usr/bin/env python3
"""
Hash Calculator - Compute MD5, SHA1, and SHA256 hashes for files.

Usage:
    python hash_calculator.py malware_sample.exe
    python hash_calculator.py file1.exe file2.dll
    python hash_calculator.py --string "suspicious_string"
"""

import argparse
import hashlib
import sys
from pathlib import Path

CHUNK_SIZE = 8192


def hash_file(file_path: Path) -> dict[str, str]:
    """Calculate MD5, SHA1, SHA256 for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": file_path.stat().st_size,
    }


def hash_string(text: str) -> dict[str, str]:
    """Calculate hashes for a string."""
    data = text.encode("utf-8")
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Calculate file hashes for malware analysis")
    parser.add_argument("files", nargs="*", type=Path, help="Files to hash")
    parser.add_argument("--string", "-s", help="Hash a string instead of a file")
    args = parser.parse_args()

    if args.string:
        hashes = hash_string(args.string)
        print("String hashes:")
        for algo, value in hashes.items():
            print(f"  {algo.upper()}: {value}")
        return 0

    if not args.files:
        parser.print_help()
        return 1

    for file_path in args.files:
        if not file_path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            continue
        hashes = hash_file(file_path)
        print(f"\nFile: {file_path}")
        print(f"  Size: {hashes['size']:,} bytes")
        print(f"  MD5:    {hashes['md5']}")
        print(f"  SHA1:   {hashes['sha1']}")
        print(f"  SHA256: {hashes['sha256']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
