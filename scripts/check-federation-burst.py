#!/usr/bin/env python3
"""ONE-2201 const audit: federation burst policy must stay input-relative.

No const/static data declarations belong in the burst implementation or its
normalizer. This deliberately bans more than suspicious names: renaming an
absolute rate, count, or pause constant must not evade the audit. Wire-format
bounds imported by the queue are separate from rate policy. Zero/one arithmetic
identities and const functions are not data declarations.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "ratchet"))
from process_globals import strip_noise

ROOT = Path(__file__).resolve().parents[1]
DECLARATION = re.compile(r"\b(?:const|static)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")


def audit(root: Path) -> list[str]:
    policy = root / "crates/oneiron/src/sync/federation_burst"
    # Read required entry points explicitly so missing source fails closed.
    required = [policy / "mod.rs", policy / "observations.rs",
                root / "crates/oneiron/src/llm/burst_inputs.rs"]
    sources = set(required)
    sources.update(path for path in policy.rglob("*.rs")
                   if "tests" not in path.relative_to(policy).parts
                   and path.name != "tests.rs" and not path.stem.endswith("_tests"))
    findings = []
    for path in sorted(sources):
        source = strip_noise(path.read_text())
        for match in DECLARATION.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            findings.append(f"{path.relative_to(root)}:{line}: {match.group(1)}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        findings = audit(args.root)
    except (OSError, UnicodeError) as error:
        print(f"FEDERATION-BURST-AUDIT-ERROR: {error}", file=sys.stderr)
        return 1
    if findings:
        print("FEDERATION-BURST-AUDIT-FAIL\n" + "\n".join(findings), file=sys.stderr)
        return 1
    print("FEDERATION-BURST-AUDIT-OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
