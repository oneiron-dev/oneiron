#!/usr/bin/env python3
"""Fail closed if the compiled credential deny list omits a policy entry."""
import argparse
from pathlib import Path


def entries(path):
    return {line.strip() for line in Path(path).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="policy/secret-blocklist.txt")
    parser.add_argument("--built", default="crates/oneiron/src/batch/secret_scan/blocklist.txt")
    args = parser.parse_args()
    missing = entries(args.source) - entries(args.built)
    if missing:
        # Never print entry values: a policy mistake could contain a live secret.
        parser.exit(1, f"SECRET-BLOCKLIST-MISSING: {len(missing)} entries\n")
    print("SECRET-BLOCKLIST-OK")


if __name__ == "__main__":
    main()
