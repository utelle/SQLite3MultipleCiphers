#!/usr/bin/env python3

import hashlib
import sys
import argparse
from pathlib import Path


def sha3_256_file(path: Path) -> str:
    h = hashlib.sha3_256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Verify SHA3-256 checksum of a file")
    parser.add_argument("file", type=Path)
    parser.add_argument("expected", type=str)

    args = parser.parse_args()

    actual = sha3_256_file(args.file)
    expected = args.expected.lower()

    print(f"File     : {args.file}")
    print(f"Expected : {expected}")
    print(f"Actual   : {actual}")

    if actual != expected:
        print("❌ SHA3 verification failed")
        sys.exit(1)

    print("✅ SHA3 verification passed")


if __name__ == "__main__":
    main()
