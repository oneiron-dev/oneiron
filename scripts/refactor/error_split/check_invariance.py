#!/usr/bin/env python3
"""Prove the error-enum split changed shape and nothing else.

    scripts/refactor/error_split/check_invariance.py <base-rev>
    scripts/refactor/error_split/check_invariance.py HEAD --skip-size

python3 stdlib only. Exit 0 when every check passes, 1 otherwise. `<base-rev>`
is the commit the split branch was cut from; the base `error.rs` is read with
`git show <rev>:crates/oneiron/src/error.rs`.

Checks:

  a  leaf variant names       the multiset across root + domain enums equals the
                              manifest, minus variants the manifest marks `delete`
  b  #[error(...)] strings     byte-identical to base, per variant name
  c  ErrorKind frozen          the enum and its doc block are textually unchanged
  d  kind() total              every leaf is mapped, in root or in its domain,
                              with no wildcard arm anywhere in the chain
  e  no flat references        no `Error::<moved variant>` survives under crates/,
                              and no `<Domain>Error::<root variant>` was invented
  f  root surface              scripts/ratchet/root-surface-check.sh passes
  g  size_of::<Error>()        <= 128 bytes (clippy result_large_err's default)

Checks a-e are per-domain aware: a domain whose file does not exist yet is
reported as NOT SPLIT and skipped, so the same command is meaningful against an
untouched tree, after the pilot, and after the full run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)

import errparse  # noqa: E402

ERROR_RS = "crates/oneiron/src/error.rs"
SIZE_LIMIT = 128


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []
        self.failed = False

    def add(self, check: str, ok: bool | None, detail: str) -> None:
        status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        if ok is False:
            self.failed = True
        self.rows.append((check, status, detail))

    def render(self) -> str:
        width = max(len(c) for c, _, _ in self.rows)
        out = []
        for check, status, detail in self.rows:
            out.append(f"[{status}] {check.ljust(width)}  {detail}")
        return "\n".join(out)


def git_show(rev: str, path: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", REPO, "show", f"{rev}:{path}"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def read(path: str) -> str | None:
    full = os.path.join(REPO, path)
    if not os.path.exists(full):
        return None
    with open(full, encoding="utf-8") as fh:
        return fh.read()


def enum_block(text: str, name: str) -> str | None:
    """The enum's declaration plus the doc block and attributes above it."""
    lines = text.split("\n")
    try:
        body_start, close = errparse.find_enum_span(lines, name)
    except errparse.ParseError:
        return None
    head = body_start - 1
    i = head
    while i > 0:
        prev = lines[i - 1].strip()
        if prev.startswith("///") or prev.startswith("#[") or prev.startswith("//"):
            i -= 1
            continue
        break
    return "\n".join(lines[i : close + 1])


def find_error_kind(sources: dict[str, str]) -> tuple[str, str] | None:
    for path, text in sources.items():
        block = enum_block(text, "ErrorKind")
        if block is not None:
            return path, block
    return None


def match_arms(text: str, fn_name: str) -> tuple[list[str], bool] | None:
    """Return (patterns named in the arms, has_wildcard) for `fn <fn_name>`."""
    m = re.search(rf"\bfn\s+{re.escape(fn_name)}\s*\(", text)
    if not m:
        return None
    brace = text.find("{", m.end())
    if brace < 0:
        return None
    depth, i = 0, brace
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = text[brace : i + 1]
    names = re.findall(r"(?:Self|Error|[A-Za-z_][A-Za-z0-9_]*Error)::([A-Z][A-Za-z0-9_]*)", body)
    wildcard = re.search(r"^\s*_\s*(?:if\b[^=]*)?=>", body, re.M) is not None
    return names, wildcard


def check_a_b(manifest: dict, sources: dict[str, str], base: str, rep: Report) -> dict:
    """Leaf-variant multiset and #[error(...)] byte-identity."""
    base_variants = {v["name"]: v for v in errparse.parse_enum(base, "Error")}
    expected = {
        v["name"]: v for v in manifest["variants"] if v.get("action") != "delete"
    }
    deleted = [v["name"] for v in manifest["variants"] if v.get("action") == "delete"]

    wrappers = {d["wrapper"] for k, d in manifest["domains"].items() if d.get("wrapper")}
    leaves: dict[str, tuple[str, dict]] = {}
    dupes: list[str] = []
    for path, text in sources.items():
        for enum_name in {"Error"} | {d["enum"] for d in manifest["domains"].values()}:
            try:
                errparse.find_enum_span(text.split("\n"), enum_name)
            except errparse.ParseError:
                continue
            for v in errparse.parse_enum(text, enum_name):
                if enum_name == "Error" and v["name"] in wrappers:
                    continue
                if v["name"] in leaves:
                    dupes.append(v["name"])
                leaves[v["name"]] = (path, v)

    missing = sorted(set(expected) - set(leaves))
    extra = sorted(set(leaves) - set(expected))
    detail = f"{len(leaves)} leaves, expected {len(expected)}"
    if deleted:
        detail += f" ({len(deleted)} marked delete: {', '.join(deleted)})"
    if missing:
        detail += f"; MISSING {', '.join(missing[:8])}"
    if extra:
        detail += f"; UNEXPECTED {', '.join(extra[:8])}"
    if dupes:
        detail += f"; DUPLICATED {', '.join(sorted(set(dupes))[:8])}"
    rep.add("a  leaf variant names", not (missing or extra or dupes), detail)

    drift = []
    for name, (path, v) in sorted(leaves.items()):
        b = base_variants.get(name)
        if b is None:
            drift.append(f"{name} (absent at base)")
            continue
        if (v["error_attr"] or "") != (b["error_attr"] or ""):
            drift.append(f"{name} in {path}")
    rep.add(
        "b  #[error(..)] strings",
        not drift,
        f"{len(leaves)} compared against base"
        + (f"; DRIFT: {', '.join(drift[:6])}" if drift else ""),
    )
    return leaves


def check_c(sources: dict[str, str], base: str, rep: Report) -> None:
    found = find_error_kind(sources)
    base_block = enum_block(base, "ErrorKind")
    if base_block is None:
        rep.add("c  ErrorKind frozen", False, "ErrorKind not found at base")
        return
    if found is None:
        rep.add("c  ErrorKind frozen", False, "ErrorKind not found in the tree")
        return
    path, block = found
    if block == base_block:
        rep.add("c  ErrorKind frozen", True, f"byte-identical, in {path}")
        return
    b, n = base_block.split("\n"), block.split("\n")
    diff = [ln for ln in n if ln not in b][:4] + [f"-{ln}" for ln in b if ln not in n][:4]
    rep.add("c  ErrorKind frozen", False,
            f"CHANGED in {path}: {len(n)} lines vs {len(b)} at base; e.g. {diff}")


def check_d(manifest: dict, sources: dict[str, str], leaves: dict, rep: Report) -> None:
    covered: set[str] = set()
    wildcards: list[str] = []
    seen_fn = 0
    for path, text in sources.items():
        arms = match_arms(text, "kind")
        if arms is None:
            continue
        seen_fn += 1
        names, wild = arms
        covered.update(names)
        if wild:
            wildcards.append(path)
    uncovered = sorted(set(leaves) - covered)
    ok = not uncovered and not wildcards and seen_fn > 0
    detail = f"{seen_fn} kind() impl(s), {len(covered & set(leaves))}/{len(leaves)} leaves mapped"
    if uncovered:
        detail += f"; UNMAPPED {', '.join(uncovered[:8])}"
    if wildcards:
        detail += f"; WILDCARD ARM in {', '.join(wildcards)}"
    rep.add("d  kind() total", ok, detail)


def check_e(manifest: dict, rep: Report) -> None:
    domains = manifest["domains"]
    split = {
        d: info for d, info in domains.items()
        if d != "root" and os.path.exists(os.path.join(REPO, info["file"]))
    }
    moved = {
        v["name"]: v["domain"] for v in manifest["variants"]
        if v["domain"] in split and v.get("action") != "delete"
    }
    roots = {v["name"] for v in manifest["variants"] if v["domain"] == "root"}
    enum_names = {d["enum"] for d in domains.values() if d.get("enum") != "Error"}

    if not split:
        rep.add("e  no flat references", None,
                f"0 of {len(domains) - 1} domains split yet; nothing to enforce")
        return

    flat_re = re.compile(r"\bError::(" + "|".join(sorted(map(re.escape, moved))) + r")\b")
    root_re = re.compile(
        r"\b(" + "|".join(sorted(map(re.escape, enum_names))) + r")::("
        + "|".join(sorted(map(re.escape, roots))) + r")\b"
    )
    flat_hits, root_hits = [], []
    for dirpath, dirnames, filenames in os.walk(os.path.join(REPO, "crates")):
        dirnames[:] = [d for d in dirnames if d not in {"target", ".git", "node_modules", "vendor"}]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, REPO)
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            is_def = rel == ERROR_RS or rel.startswith(os.path.join("crates", "oneiron", "src", "error"))
            if not is_def:
                for m in flat_re.finditer(text):
                    flat_hits.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1} Error::{m.group(1)}")
            for m in root_re.finditer(text):
                root_hits.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1} {m.group(0)}")
    ok = not flat_hits and not root_hits
    detail = f"{len(split)}/{len(domains) - 1} domains split ({', '.join(sorted(split))})"
    if flat_hits:
        detail += f"; {len(flat_hits)} FLAT refs remain, e.g. {flat_hits[:4]}"
    if root_hits:
        detail += f"; {len(root_hits)} bag variants moved into a domain enum, e.g. {root_hits[:4]}"
    rep.add("e  no flat references", ok, detail)


def check_f(rep: Report) -> None:
    script = os.path.join(REPO, "scripts", "ratchet", "root-surface-check.sh")
    if not os.path.exists(script):
        rep.add("f  root surface", None, "scripts/ratchet/root-surface-check.sh not found")
        return
    try:
        proc = subprocess.run([script], capture_output=True, text=True, cwd=REPO)
    except OSError as exc:
        rep.add("f  root surface", None, f"could not run: {exc}")
        return
    tail = (proc.stdout + proc.stderr).strip().split("\n")[-1] if (proc.stdout or proc.stderr) else ""
    rep.add("f  root surface", proc.returncode == 0, f"exit {proc.returncode}: {tail[:140]}")


PROBE = """\
#[test]
fn error_stays_small() {
    let bytes = std::mem::size_of::<oneiron::Error>();
    assert!(bytes <= %d, "size_of::<Error>() = {bytes} bytes, limit %d");
    println!("SIZE_OF_ERROR={bytes}");
}
"""

PROBE_TOML = """\
[package]
name = "error-size-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
oneiron = { path = "%s" }

[workspace]
"""


def check_g(rep: Report, skip: bool) -> None:
    if skip:
        rep.add("g  size_of::<Error>()", None, "skipped (--skip-size)")
        return
    if shutil.which("cargo") is None:
        rep.add("g  size_of::<Error>()", None, "cargo not on PATH")
        return
    tmp = tempfile.mkdtemp(prefix="error-size-probe-")
    try:
        os.makedirs(os.path.join(tmp, "tests"))
        with open(os.path.join(tmp, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write(PROBE_TOML % os.path.join(REPO, "crates", "oneiron"))
        with open(os.path.join(tmp, "src.rs"), "w", encoding="utf-8") as fh:
            fh.write("")
        os.makedirs(os.path.join(tmp, "src"), exist_ok=True)
        with open(os.path.join(tmp, "src", "lib.rs"), "w", encoding="utf-8") as fh:
            fh.write("")
        with open(os.path.join(tmp, "tests", "size.rs"), "w", encoding="utf-8") as fh:
            fh.write(PROBE % (SIZE_LIMIT, SIZE_LIMIT))
        # The probe lives outside the repo, so it does not inherit the pinned
        # toolchain; without this it builds on the default channel and the
        # workspace's `rust-version` refuses it.
        toolchain = os.path.join(REPO, "rust-toolchain.toml")
        if os.path.exists(toolchain):
            shutil.copyfile(toolchain, os.path.join(tmp, "rust-toolchain.toml"))
        env = dict(os.environ)
        env.setdefault("CARGO_TARGET_DIR", os.path.join(tmp, "target"))
        proc = subprocess.run(
            ["cargo", "test", "--quiet", "--test", "size", "--", "--nocapture"],
            cwd=tmp, capture_output=True, text=True, env=env,
        )
        out = proc.stdout + proc.stderr
        m = re.search(r"SIZE_OF_ERROR=(\d+)", out)
        if proc.returncode == 0 and m:
            rep.add("g  size_of::<Error>()", int(m.group(1)) <= SIZE_LIMIT,
                    f"{m.group(1)} bytes (limit {SIZE_LIMIT})")
        else:
            tail = "; ".join(ln for ln in out.strip().split("\n")[-3:] if ln.strip())
            rep.add("g  size_of::<Error>()", False if m else None,
                    f"probe did not run cleanly: {tail[:200]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def collect_sources() -> dict[str, str]:
    """error.rs plus every file under crates/oneiron/src/error/."""
    out = {}
    text = read(ERROR_RS)
    if text is not None:
        out[ERROR_RS] = text
    edir = os.path.join(REPO, "crates", "oneiron", "src", "error")
    for dirpath, _, filenames in os.walk(edir):
        for fn in sorted(filenames):
            if fn.endswith(".rs"):
                rel = os.path.relpath(os.path.join(dirpath, fn), REPO)
                out[rel] = read(rel) or ""
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", help="the revision the split branch was cut from")
    ap.add_argument("--manifest", default=os.path.join(HERE, "manifest.json"))
    ap.add_argument("--skip-size", action="store_true", help="skip check g (needs cargo)")
    args = ap.parse_args()

    base = git_show(args.base, ERROR_RS)
    if base is None:
        print(f"CHECK-ERROR: cannot read {args.base}:{ERROR_RS}", file=sys.stderr)
        return 1
    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    sources = collect_sources()
    if ERROR_RS not in sources:
        print(f"CHECK-ERROR: {ERROR_RS} is missing from the tree", file=sys.stderr)
        return 1

    rep = Report()
    print(f"base {args.base}  ({len(base.splitlines())} lines of error.rs)")
    print(f"tree {', '.join(sources)}")
    print()
    leaves = check_a_b(manifest, sources, base, rep)
    check_c(sources, base, rep)
    check_d(manifest, sources, leaves, rep)
    check_e(manifest, rep)
    check_f(rep)
    check_g(rep, args.skip_size)
    print(rep.render())
    print()
    print("RESULT:", "FAIL" if rep.failed else "PASS")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
