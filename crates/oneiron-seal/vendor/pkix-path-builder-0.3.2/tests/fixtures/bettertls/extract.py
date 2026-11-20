#!/usr/bin/env python3
"""Extract bettertls::pathbuilding fixtures from a local x509-limbo checkout.

Run from this directory:
    python3 extract.py [path/to/limbo.json]

Default limbo.json path is ~/GIT/x509-limbo/limbo.json.

Selection covers the five failure-mode buckets identified in
pkix-difftest/baseline-limbo-analysis.md (PKIX-g9vc.4) and PKIX-lwr9's
parent epic decomposition. 25 testcases total.

Standard library only.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Selected testcases keyed by failure-mode bucket. See README.md.
SELECTED = {
    "no-path-to-anchor": ["tc1", "tc16", "tc20", "tc24", "tc28", "tc41"],
    "sig-invalid-at-1": ["tc2", "tc30", "tc31", "tc33", "tc34", "tc35"],
    "sig-invalid-at-5-or-6": ["tc48", "tc51", "tc54", "tc57", "tc60"],
    "cert-not-ca-at-6": ["tc58", "tc59"],
    "path-len-exceeds": ["tc61", "tc62", "tc64", "tc66", "tc67", "tc68"],
}


def main() -> int:
    limbo_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "GIT" / "x509-limbo" / "limbo.json"
    if not limbo_path.exists():
        sys.stderr.write(f"limbo.json not found at {limbo_path}\n")
        return 2

    with open(limbo_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    by_id = {tc["id"]: tc for tc in manifest["testcases"]}

    out_root = Path(__file__).parent
    flat_selected = [(bucket, tc) for bucket, tcs in SELECTED.items() for tc in tcs]
    written = 0
    for bucket, short_id in flat_selected:
        full_id = f"bettertls::pathbuilding::{short_id}"
        tc = by_id.get(full_id)
        if tc is None:
            sys.stderr.write(f"missing in manifest: {full_id}\n")
            return 3
        case_dir = out_root / short_id
        case_dir.mkdir(parents=True, exist_ok=True)

        (case_dir / "peer.pem").write_text(tc["peer_certificate"])
        (case_dir / "intermediates.pem").write_text(
            "".join(tc["untrusted_intermediates"])
        )
        (case_dir / "anchors.pem").write_text(
            "".join(tc["trusted_certs"])
        )

        meta = {
            "id": full_id,
            "bucket": bucket,
            "validation_time": tc["validation_time"],
            "expected_result": tc["expected_result"],
            "description": tc["description"],
            "intermediates_count": len(tc["untrusted_intermediates"]),
            "anchors_count": len(tc["trusted_certs"]),
        }
        with open(case_dir / "testcase.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, sort_keys=True)
            f.write("\n")
        written += 1

    print(f"wrote {written} fixtures under {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
