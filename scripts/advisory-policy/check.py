#!/usr/bin/env python3
"""Enforce ONE-335's exact, expiring accepted maintenance risks (Python 3.11+)."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

CARGO_DENY_VERSION = "0.19.4"
EXPIRY = "2026-10-07T00:00:00Z"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
DB_URL = "https://github.com/rustsec/advisory-db"
# The 2026-09-07 owner grant plus exact3 standing-authority extension (19 total).
# Future equivalents need inspected, explicit owner entries in this set AND policy data;
# standing delegation is not a runtime blanket allow. See POSTWAVE.md.
AUTHORIZED = {
    ("RUSTSEC-2024-0413", "atk", "0.18.2"),
    ("RUSTSEC-2024-0416", "atk-sys", "0.18.2"),
    ("RUSTSEC-2024-0412", "gdk", "0.18.2"),
    ("RUSTSEC-2024-0418", "gdk-sys", "0.18.2"),
    ("RUSTSEC-2024-0411", "gdkwayland-sys", "0.18.2"),
    ("RUSTSEC-2024-0417", "gdkx11", "0.18.2"),
    ("RUSTSEC-2024-0414", "gdkx11-sys", "0.18.2"),
    ("RUSTSEC-2024-0415", "gtk", "0.18.2"),
    ("RUSTSEC-2024-0420", "gtk-sys", "0.18.2"),
    ("RUSTSEC-2024-0419", "gtk3-macros", "0.18.2"),
    ("RUSTSEC-2024-0370", "proc-macro-error", "1.0.4"),
    ("RUSTSEC-2025-0081", "unic-char-property", "0.9.0"),
    ("RUSTSEC-2025-0075", "unic-char-range", "0.9.0"),
    ("RUSTSEC-2025-0080", "unic-common", "0.9.0"),
    ("RUSTSEC-2025-0100", "unic-ucd-ident", "0.9.0"),
    ("RUSTSEC-2025-0098", "unic-ucd-version", "0.9.0"),
    ("RUSTSEC-2026-0247", "bitmaps", "2.1.0"),
    ("RUSTSEC-2026-0248", "im", "15.1.0"),
    ("RUSTSEC-2026-0251", "sized-chunks", "0.6.5"),
}
# Separate pre-existing decisions; ONE-335 does not renew or broaden these.
EXISTING_IDS = {
    "RUSTSEC-2023-0089", "RUSTSEC-2025-0141",
    "RUSTSEC-2026-0215", "RUSTSEC-2023-0071",
}


class PolicyError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def utc_time(value):
    require(isinstance(value, str) and value.endswith("Z"), "expected UTC timestamp ending in Z")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def validate_policy(policy, lock, now):
    require(policy["schema"] == 1, "unknown policy schema")
    require(policy["status"] == "accepted-maintenance-risk-not-fixed", "not an active risk acceptance")
    require(policy["expires"] == EXPIRY, "expiry changed: new owner authority required; no renewal")
    require(now < utc_time(EXPIRY), "maintenance-risk acceptance expired; review required")
    review = policy["review"]
    require(review["automatic_renewal"] is False, "automatic renewal is forbidden")
    if review["post_wave_at"] is not None:
        require(now < utc_time(review["post_wave_at"]), "post-wave review due; acceptance ended")
    entries = policy["entries"]
    require(len(entries) == 19, "expected exactly 19 authorized maintenance risks")
    require({(e["id"], e["package"], e["version"]) for e in entries} == AUTHORIZED,
            "entry identity/version is outside the exact owner grant")
    require(len({e["id"] for e in entries}) == 19, "duplicate advisory ID")
    require(len({e["package"] for e in entries}) == 19, "duplicate package")
    for entry in entries:
        name = entry["package"]
        require(entry["id"] not in EXISTING_IDS, "cannot replace a pre-existing exception")
        matches = [p for p in lock["package"] if p["name"] == name]
        require(len(matches) == 1, f"{name}: removed or multiple locked versions; re-evaluate")
        package = matches[0]
        require(package["version"] == entry["version"], f"{name}: locked version changed; re-evaluate")
        require(package.get("source") == REGISTRY, f"{name}: locked source changed; re-evaluate")
        parents = sorted(
            f"{p['name']}@{p['version']}" for p in lock["package"]
            if any(d.split()[0] == name for d in p.get("dependencies", []))
        )
        require(parents == entry["parents"], f"{name}: dependency context changed; re-evaluate")
    for context in policy["context"]:
        parents = [p for p in lock["package"] if p["name"] == context["package"]]
        require(len(parents) == 1 and parents[0]["version"] == context["version"]
                and parents[0].get("source") == REGISTRY,
                f"{context['package']}: upstream dependency context changed; re-evaluate")
        name, version = context["dependency"].split()
        require(any(d == name or d == f"{name} {version}" for d in parents[0].get("dependencies", [])),
                f"{context['package']}: dependency chain changed; re-evaluate")
    return entries


def validate_config(text):
    config = tomllib.loads(text)
    # No target pruning (including Linux), no broad informational bypasses.
    require(config["graph"] == {"all-features": True}, "dependency graph must remain unfiltered")
    adv = config["advisories"]
    require(set(adv) == {"db-path", "db-urls", "yanked", "ignore"}, "unexpected advisory settings")
    require(adv["db-urls"] == [DB_URL], "expected the RustSec database only")
    require(adv["yanked"] == "deny", "yanked crates must remain denied")
    ignores = adv["ignore"]
    require(len(ignores) == len(EXISTING_IDS), "new permanent ignore is not authorized")
    require(all(isinstance(e, dict) and set(e) == {"id", "reason"} for e in ignores),
            "expected existing ID/reason exceptions only")
    require({e["id"] for e in ignores} == EXISTING_IDS, "permanent exception IDs changed")
    return config


def database_root(cache):
    # A private cache with one configured URL avoids validating one DB but checking another.
    roots = [p for p in cache.iterdir() if p.is_dir()]
    require(len(roots) == 1 and (roots[0] / "crates").is_dir(), "missing or ambiguous advisory database")
    return roots[0]


def validate_advisories(entries, database):
    for entry in entries:
        advisory_id = entry["id"]
        paths = list((database / "crates").glob(f"*/{advisory_id}.md"))
        expected = database / "crates" / entry["package"] / f"{advisory_id}.md"
        require(paths == [expected], f"{advisory_id}: missing, duplicate or moved advisory")
        text = expected.read_text(encoding="utf-8")
        require(text.startswith("```toml\n"), f"{advisory_id}: unknown advisory format")
        frontmatter, separator, _ = text[len("```toml\n"):].partition("\n```")
        require(bool(separator), f"{advisory_id}: unterminated advisory metadata")
        data = tomllib.loads(frontmatter)
        require(set(data) == {"advisory", "versions"}, f"{advisory_id}: advisory scope changed")
        advisory = data["advisory"]
        require(advisory["id"] == advisory_id and advisory["package"] == entry["package"],
                f"{advisory_id}: advisory identity changed")
        require(advisory.get("informational") == "unmaintained",
                f"{advisory_id}: not informational-unmaintained; vulnerabilities are not accepted")
        # New CVSS, aliases, affected platforms/functions, withdrawal, etc. require review.
        require(set(advisory) <= {"id", "package", "date", "url", "informational", "keywords"},
                f"{advisory_id}: classification metadata changed; re-evaluate")
        versions = data["versions"]
        require(set(versions) <= {"patched", "unaffected"}
                and versions.get("patched") == [] and versions.get("unaffected", []) == [],
                f"{advisory_id}: affected version scope changed; re-evaluate")


def cache_config(text, cache):
    # Preserve the existing config byte-for-byte except the private DB path.
    lines = text.splitlines(keepends=True)
    indices = [i for i, line in enumerate(lines) if line.startswith("db-path = ")]
    require(len(indices) == 1, "expected one db-path line")
    lines[indices[0]] = f"db-path = {json.dumps(str(cache))}\n"
    return "".join(lines)


def accepted_config(text, entries):
    require(text.count("ignore = [\n") == 1, "expected one advisory ignore array")
    additions = "".join(
        "    { id = " + json.dumps(e["id"]) + ", reason = "
        + json.dumps(f"ONE-335 accepted maintenance risk, NOT fixed: {e['package']}@{e['version']}; "
                     f"informational-unmaintained only; expires {EXPIRY}; post-wave review first; no renewal")
        + " },\n" for e in entries
    )
    return text.replace("ignore = [\n", "ignore = [\n" + additions, 1)


def check_command(config_path, offline=False):
    command = ["cargo", "deny", "--locked"]
    if offline:
        command.append("--offline")
    # In pinned 0.19.4, non-ignored advisories are errors; ignored IDs emit notes.
    # --deny overrides the diagnostic severity AFTER ID ignores, turning even
    # accepted notes (including pre-existing exceptions) back into errors.
    # Keep the native levels; execute() rejects any uninspected tool version.
    return command + ["check", "--disable-fetch", "--config", str(config_path)]


def execute(root, offline=False):
    policy = json.loads((root / "scripts/advisory-policy/exceptions.json").read_text(encoding="utf-8"))
    lock_path = root / "Cargo.lock"
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    entries = validate_policy(policy, lock, datetime.now(timezone.utc))
    text = (root / "deny.toml").read_text(encoding="utf-8")
    config = validate_config(text)
    version = subprocess.run(["cargo", "deny", "--version"], cwd=root, check=True,
                             capture_output=True, text=True).stdout.strip()
    require(version == f"cargo-deny {CARGO_DENY_VERSION}", "cargo-deny version changed; revalidate policy behavior")
    with tempfile.TemporaryDirectory(prefix="oneiron-advisory-policy-") as temporary:
        work = Path(temporary)
        cache = work / "advisory-db"
        effective = work / "deny.toml"
        base = cache_config(text, cache)
        effective.write_text(base, encoding="utf-8")
        if offline:
            source = Path(config["advisories"]["db-path"]).expanduser()
            if not source.is_absolute():
                source = root / source
            shutil.copytree(source, cache)
        else:
            # Fetch into a private cache, then freeze it for validation AND the actual check.
            subprocess.run(["cargo", "deny", "--locked", "fetch", "--config", str(effective), "db"],
                           cwd=root, check=True)
        validate_advisories(entries, database_root(cache))
        # Never leave the 19 broad ID ignores in deny.toml or a reusable output file.
        effective.write_text(accepted_config(base, entries), encoding="utf-8")
        validate_policy(policy, lock, datetime.now(timezone.utc))
        require(lock_path.read_bytes() == lock_bytes, "Cargo.lock changed during policy validation")
        print(f"ONE-335: 19 accepted maintenance risks, NOT fixed; expires {EXPIRY}; "
              "review at post-wave discussion or expiry, whichever comes first; no automatic renewal.",
              file=sys.stderr, flush=True)
        result = subprocess.run(check_command(effective, offline), cwd=root, check=False)
        # A check that crosses the deadline must not produce a successful acceptance.
        validate_policy(policy, lock, datetime.now(timezone.utc))
        require(lock_path.read_bytes() == lock_bytes, "Cargo.lock changed during cargo-deny")
        return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="use a private snapshot of the local advisory cache; no fetch")
    args = parser.parse_args()
    try:
        return execute(Path(__file__).resolve().parents[2], args.offline)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"advisory-policy: BLOCKED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
