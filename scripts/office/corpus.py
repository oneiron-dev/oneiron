#!/usr/bin/env python3
"""Pinned spreadsheet corpus normalization, classification, and stored-value checks."""
import argparse
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "crates/oneiron-docedit/tests/fixtures/spreadsheet-compat"


def load_cases(directory=FIXTURES):
    raw = (directory / "cases.json").read_bytes()
    provenance = json.loads((directory / "provenance.json").read_text())
    if hashlib.sha256(raw).hexdigest() != provenance["normalized_cases_sha256"]:
        raise ValueError("corpus content hash mismatch")
    cases = json.loads(raw)
    if len(cases) != provenance["cases"] or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("corpus count or duplicate case id")
    return cases


def classification(case):
    expected = case["expected"]
    if expected is None:
        return "probe"
    if isinstance(expected, list):
        return "array"
    if isinstance(expected, str) and expected.startswith("#"):
        return "error"
    return "value"


def same_value(actual, expected):
    # A bool is not the integer 0/1, and a missing/error cache is not a number.
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (float, int)) and isinstance(expected, (float, int)):
        return math.isfinite(actual) and math.isfinite(expected) and math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-10)
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(same_value(a, e) for a, e in zip(actual, expected))
    return type(actual) is type(expected) and actual == expected


def score(cases, results):
    """Missing values fail; probe cases never inflate the exact-value score."""
    groups = {}
    for case in cases:
        group = groups.setdefault(case["function"], {"passed": 0, "total": 0, "probes": 0})
        if classification(case) == "probe":
            group["probes"] += 1
            continue
        group["total"] += 1
        result = results.get(case["id"])
        if result is not None and result.get("status") == "ok" and same_value(result.get("value"), case["expected"]):
            group["passed"] += 1
    return groups


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    cases = load_cases()
    if args.results:
        results = json.loads(args.results.read_text())
        print(json.dumps(score(cases, results["cases"]), sort_keys=True))
    else:
        counts = {}
        for case in cases:
            kind = classification(case)
            counts[kind] = counts.get(kind, 0) + 1
        print(json.dumps({"cases": len(cases), "classes": counts}, sort_keys=True))


if __name__ == "__main__":
    main()
