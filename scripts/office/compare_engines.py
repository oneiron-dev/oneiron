#!/usr/bin/env python3
"""Compare unchanged engines against native Excel cached values, not upstream belief."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from corpus import load_cases, same_value, classification

VOLATILE = {"NOW", "TODAY", "RAND", "RANDBETWEEN", "RANDARRAY", "CELL", "INFO", "OFFSET", "INDIRECT"}


def is_volatile(case):
    formulas = [case["formula"]] + [v for v in case.get("setup_cells", {}).values() if isinstance(v, str) and v.startswith("=")]
    return any(re.search(r"(?<![A-Za-z0-9_.])" + name + r"\s*\(", formula, re.I) for formula in formulas for name in VOLATILE)


def compare(cases, goldens, engines):
    counts = {name: {"passed": 0, "total": 0, "by_function": {}} for name in engines}
    exclusions = {}
    mismatches = {name: [] for name in engines}
    for case in cases:
        golden = goldens["cases"][case["id"]]
        if golden["status"] != "ok":
            exclusions[case["id"]] = "excel-formula-rejected"
            continue
        if is_volatile(case):
            exclusions[case["id"]] = "volatile"
            continue
        for name, report in engines.items():
            row = report["cases"].get(case["id"])
            passed = bool(row and row["status"] in ("ok", "probe") and same_value(row["value"], golden["value"]))
            count = counts[name]
            group = count["by_function"].setdefault(case["function"], {"passed": 0, "total": 0})
            count["total"] += 1
            count["passed"] += int(passed)
            group["total"] += 1
            group["passed"] += int(passed)
            if not passed:
                mismatches[name].append({"id": case["id"], "classification": classification(case), "excel": golden["value"], "actual": row})
    for count in counts.values():
        count["rate"] = count["passed"] / count["total"] if count["total"] else None
    return {"counts": counts, "exclusions": exclusions, "mismatches": mismatches}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--goldens", required=True, type=Path)
    parser.add_argument("--libreoffice", required=True, type=Path)
    parser.add_argument("--formualizer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cases = load_cases()
    goldens = json.loads(args.goldens.read_bytes())
    lo = json.loads(args.libreoffice.read_bytes())
    formula = json.loads(args.formualizer.read_bytes())
    if lo["status"] != "completed" or len(lo["cases"]) != len(cases) or len(formula["cases"]) != len(cases):
        raise ValueError("incomplete engine report")
    if formula["corpus_sha256"] != goldens["input_sha256"]:
        raise ValueError("engines did not use the same input corpus")
    result = compare(cases, goldens, {"libreoffice": lo, "formualizer_unchanged": formula})
    result.update({"excel_version": goldens["excel_version"], "libreoffice_version": lo["engine"],
                   "formualizer_version": formula["engine_stamp"], "corpus_sha256": goldens["input_sha256"],
                   "input_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.goldens, args.libreoffice, args.formualizer)}})
    lo_count = result["counts"]["libreoffice"]
    formula_count = result["counts"]["formualizer_unchanged"]
    result["at_or_above_libreoffice"] = formula_count["passed"] >= lo_count["passed"]
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({name: {key: value for key, value in count.items() if key != "by_function"} for name, count in result["counts"].items()}))


if __name__ == "__main__":
    main()
