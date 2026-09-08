#!/usr/bin/env python3
"""Deterministic code map for the Rust workspace.

Scans every crate under `crates/` (except `crates/heed` and any `vendor/` tree)
and writes three generated artifacts an agent can read instead of walking the
tree:

  docs/CODEMAP.md            the orientation map (workspace + per-crate module tables)
  docs/codemap/<crate>.md    one FILE table per crate
  docs/codemap/codemap.json  the same data, machine-readable

Modes:
  (default)   regenerate the artifacts in place
  --check     regenerate in memory and byte-compare with the committed artifacts;
              exit 1 with `CODEMAP-STALE: run python3 scripts/codemap/codemap.py`
              when they differ.  Fails CLOSED (`CODEMAP-ERROR: ...`, exit 1) on a
              missing artifact, an unreadable file, or a scan that maps nothing.
  --sizes     print the live line-count table (crate . file . loc . test?) to
              stdout, sorted by size.  Never committed: line counts move on every
              edit, so they stay out of the artifacts.

Determinism rules for the artifacts: sorted paths, LF line endings, no
timestamps, no absolute paths, no line counts (size buckets only).

Stdlib only.  Runs from any cwd: the repo root is found with
`git rev-parse --show-toplevel` from the script's own directory, falling back to
the script's location (`scripts/codemap/codemap.py` -> repo root).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

PURPOSE_MAX = 110
GIANT_BAR = 800  # ratchet bar: a non-test file at or over this is a giant
BUCKETS = (("s", 300), ("m", 800), ("L", 1500))  # upper bounds, exclusive
BUCKET_TOP = "XL"
BUCKET_ORDER = {"s": 0, "m": 1, "L": 2, "XL": 3}
NOTABLE_MAX = 8

# Line-anchored on rustfmt-formatted source.  Qualifiers (`async`, `unsafe`,
# `const`, `extern "C"`) may sit between the visibility and the item kind.
PUB_RE = re.compile(
    r"^\s*pub(?P<vis>\([^)]*\))?\s+"
    r"(?:(?:async|unsafe|const|extern\s+\"[^\"]*\"|extern)\s+)*"
    r"(?P<kind>struct|enum|trait|fn|type|const|static|mod|use)\b"
    r"(?:\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*))?"
)
IMPL_VAULT_RE = re.compile(r"^\s*impl\s+Vault\b")
SURFACE_ORDER = (
    "struct",
    "enum",
    "trait",
    "fn",
    "type",
    "const",
    "static",
    "mod",
    "re-export",
    "crate-vis",
)
NOTABLE_KINDS = {"struct", "enum", "trait"}

EXCLUDED_CRATES = {"heed"}
EXCLUDED_DIRS = {"vendor", "target"}
ROOT_FILES = {"lib.rs", "main.rs"}
MAP_PATH = PurePosixPath("docs/CODEMAP.md")
DIR_PATH = PurePosixPath("docs/codemap")
JSON_PATH = DIR_PATH / "codemap.json"
GENERATOR = "python3 scripts/codemap/codemap.py"


class CodemapError(Exception):
    """A fail-closed condition: reported as CODEMAP-ERROR, exit 1."""


# --------------------------------------------------------------------------- #
# repo root
# --------------------------------------------------------------------------- #


def find_root(explicit: str | None = None) -> Path:
    if explicit:
        root = Path(explicit).resolve()
        if not (root / "crates").is_dir():
            raise CodemapError(f"no crates/ directory under {root}")
        return root
    here = Path(__file__).resolve().parent
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=here,
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode == 0 and out.stdout.strip():
            root = Path(out.stdout.strip()).resolve()
            if (root / "crates").is_dir():
                return root
    except OSError:
        pass
    root = here.parents[1]
    if not (root / "crates").is_dir():
        raise CodemapError(f"cannot locate the repo root from {here}")
    return root


# --------------------------------------------------------------------------- #
# per-file facts
# --------------------------------------------------------------------------- #


def is_test_path(rel: str) -> bool:
    """The ratchet's non-test definition, inverted.

    A path with a `tests/` component, or a file named `tests.rs` / `*_tests.rs`.
    """
    parts = PurePosixPath(rel).parts
    if "tests" in parts[:-1]:
        return True
    name = parts[-1]
    return name == "tests.rs" or name.endswith("_tests.rs")


def bucket(loc: int) -> str:
    for label, upper in BUCKETS:
        if loc < upper:
            return label
    return BUCKET_TOP


def count_lines(data: bytes) -> int:
    """All lines, `wc -l` style plus one for an unterminated last line."""
    if not data:
        return 0
    n = data.count(b"\n")
    if not data.endswith(b"\n"):
        n += 1
    return n


def decode_lines(data: bytes) -> list[str]:
    text = data.decode("utf-8", errors="replace")
    return [line.rstrip("\r") for line in text.split("\n")]


SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\[(\"'])")


def trim_purpose(text: str, limit: int = PURPOSE_MAX) -> str:
    """Collapse whitespace, keep the first sentence, drop the trailing period, cap the length."""
    text = " ".join(text.split())
    text = SENTENCE_END_RE.split(text, maxsplit=1)[0]
    text = text.rstrip(".").rstrip()
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space >= limit // 2:
        cut = cut[:space]
    return cut.rstrip(" ,;:.") + "…"


def extract_purpose(lines: list[str]) -> str:
    """The first `//!` line of the leading doc block, or `—`.

    The line is extended to its sentence end when the sentence wraps onto the
    following `//!` lines of the same paragraph, then sentence-trimmed and
    capped at PURPOSE_MAX.  Only the file head counts: blank lines, `//`
    comments and `#![...]` attributes are skipped, and the scan stops at the
    first line of code so an inline `mod x { //! ... }` deeper in the file is
    never mistaken for the file's own purpose.
    """
    paragraph: list[str] = []
    for line in lines:
        s = line.strip()
        if paragraph:
            if s.startswith("//!") and s[3:].strip():
                paragraph.append(s[3:].strip())
                continue
            break
        if not s:
            continue
        if s.startswith("//!"):
            body = s[3:].strip()
            if body:
                paragraph.append(body)
            continue
        if s.startswith("//") or s.startswith("#!["):
            continue
        break
    if not paragraph:
        return "—"
    return trim_purpose(" ".join(paragraph))


def scan_file(path: Path, rel: str) -> dict:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CodemapError(f"unreadable file {rel}: {error}") from error
    lines = decode_lines(data)
    loc = count_lines(data)
    counts: dict[str, int] = {}
    notable: set[str] = set()
    impl_vault = False
    for line in lines:
        if IMPL_VAULT_RE.match(line):
            impl_vault = True
        m = PUB_RE.match(line)
        if not m:
            continue
        if m.group("vis"):
            key = "crate-vis"
        elif m.group("kind") == "use":
            key = "re-export"
        else:
            key = m.group("kind")
        counts[key] = counts.get(key, 0) + 1
        if key in NOTABLE_KINDS and m.group("name"):
            notable.add(m.group("name"))
    return {
        "path": rel,
        "kind": "test" if is_test_path(rel) else "src",
        "loc": loc,
        "bucket": bucket(loc),
        "surface": {k: counts[k] for k in SURFACE_ORDER if k in counts},
        "notable": sorted(notable),
        "purpose": extract_purpose(lines),
        "impl_vault": impl_vault,
    }


# --------------------------------------------------------------------------- #
# crate scan
# --------------------------------------------------------------------------- #


def crate_description(cargo_toml: Path) -> str:
    try:
        lines = decode_lines(cargo_toml.read_bytes())
    except OSError:
        return "—"
    in_package = False
    for line in lines:
        s = line.strip()
        if s.startswith("["):
            in_package = s == "[package]"
            continue
        if in_package and s.startswith("description"):
            _, _, value = s.partition("=")
            value = value.strip()
            if value[:1] in ("'", '"') and value[-1:] == value[:1]:
                value = value[1:-1]
            return trim_purpose(value) if value else "—"
    return "—"


def rust_files(crate_dir: Path) -> list[Path]:
    found = []
    for path in crate_dir.rglob("*.rs"):
        rel_parts = path.relative_to(crate_dir).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts[:-1]):
            continue
        if not path.is_file():
            continue
        found.append(path)
    return sorted(found, key=lambda p: p.relative_to(crate_dir).as_posix())


def layout_of(has_file: bool, has_dir: bool) -> str:
    if has_file and has_dir:
        return "file+dir"
    if has_dir:
        return "dir"
    return "file"


def scan_modules(crate_dir: Path, files: list[dict]) -> dict:
    """Top-level-module grain: `src/<mod>.rs` and/or `src/<mod>/`."""
    by_path = {f["path"]: f for f in files}
    names: dict[str, dict] = {}
    src = crate_dir / "src"
    if not src.is_dir():
        return names
    for rel, info in by_path.items():
        parts = PurePosixPath(rel).parts
        if parts[0] != "src" or len(parts) < 2:
            continue
        if len(parts) == 2:
            if parts[1] in ROOT_FILES:
                continue
            name = parts[1][:-3]
            slot = names.setdefault(name, {"file": False, "dir": False, "files": []})
            slot["file"] = True
        else:
            if parts[1] == "bin":
                continue
            name = parts[1]
            slot = names.setdefault(name, {"file": False, "dir": False, "files": []})
            slot["dir"] = True
        slot["files"].append(info)
    modules: dict[str, dict] = {}
    for name in sorted(names):
        slot = names[name]
        has_dir = slot["dir"] and (src / name / "mod.rs").is_file()
        # A directory reached only through a sibling file is still `file+dir`;
        # a bare directory without `mod.rs` and without a sibling is `dir`
        # by shape, but flagged so the reader knows there is no seam file.
        layout = layout_of(slot["file"], slot["dir"])
        if slot["dir"] and not slot["file"] and not has_dir:
            layout = "dir (no mod.rs)"
        head = f"src/{name}.rs" if slot["file"] else f"src/{name}/mod.rs"
        head_info = by_path.get(head)
        non_test = [f for f in slot["files"] if f["kind"] == "src"]
        largest = max((f["bucket"] for f in non_test), key=BUCKET_ORDER.get, default="—")
        modules[name] = {
            "layout": layout,
            "files": len(slot["files"]),
            "largest_src_bucket": largest,
            "impl_vault": any(f["impl_vault"] for f in slot["files"]),
            "purpose": head_info["purpose"] if head_info else "—",
        }
    return modules


def scan_crate(crate_dir: Path) -> dict:
    files = [scan_file(p, p.relative_to(crate_dir).as_posix()) for p in rust_files(crate_dir)]
    purpose = "—"
    for root_file in ("src/lib.rs", "src/main.rs"):
        info = next((f for f in files if f["path"] == root_file), None)
        if info and info["purpose"] != "—":
            purpose = info["purpose"]
            break
    if purpose == "—":
        purpose = crate_description(crate_dir / "Cargo.toml")
    modules = scan_modules(crate_dir, files)
    if not modules:
        for root_file in ("src/main.rs", "src/lib.rs"):
            info = next((f for f in files if f["path"] == root_file), None)
            if info:
                modules[root_file[4:-3]] = {
                    "layout": "file",
                    "files": 1,
                    "largest_src_bucket": info["bucket"],
                    "impl_vault": info["impl_vault"],
                    "purpose": info["purpose"],
                }
                break
    src_files = [f for f in files if f["kind"] == "src"]
    return {
        "purpose": purpose,
        "source_files": len(src_files),
        "test_files": len(files) - len(src_files),
        "over_bar": sum(1 for f in src_files if f["loc"] >= GIANT_BAR),
        "has_impl_vault": any(f["impl_vault"] for f in files),
        "modules": modules,
        "files": files,
    }


def scan_repo(root: Path) -> dict:
    crates_dir = root / "crates"
    if not crates_dir.is_dir():
        raise CodemapError(f"no crates/ directory under {root}")
    crates: dict[str, dict] = {}
    for crate_dir in sorted(crates_dir.iterdir(), key=lambda p: p.name):
        if not crate_dir.is_dir() or crate_dir.name in EXCLUDED_CRATES:
            continue
        if crate_dir.name in EXCLUDED_DIRS or not (crate_dir / "Cargo.toml").is_file():
            continue
        crates[crate_dir.name] = scan_crate(crate_dir)
    if not crates or not any(c["files"] for c in crates.values()):
        raise CodemapError("scan mapped no Rust files under crates/")
    return {"crates": crates}


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #


def cell(text: str) -> str:
    return text.replace("|", "\\|") if text else "—"


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for row in rows:
        out.append("| " + " | ".join(cell(c) for c in row) + " |")
    return out


def surface_text(surface: dict) -> str:
    if not surface:
        return "—"
    return " · ".join(f"{n} {k}" for k, n in surface.items())


def notable_text(names: list[str]) -> str:
    if not names:
        return "—"
    shown = names[:NOTABLE_MAX]
    rest = len(names) - len(shown)
    return ", ".join(shown) + (f" +{rest}" if rest else "")


def yes(flag: bool) -> str:
    return "yes" if flag else "—"


def legend_lines() -> list[str]:
    return [
        "Size buckets are line counts of the whole file: `s` < 300 · `m` 300–799 · "
        "`L` 800–1499 · `XL` ≥ 1500.",
        "`L` or `XL` on a non-test file means the file is over the 800-line ratchet bar "
        "(`scripts/ratchet/check.sh`); split it, do not grow it.",
    ]


def render_top(data: dict) -> str:
    crates = data["crates"]
    lines = [
        "# Code map",
        "",
        "Orientation map of the Rust workspace: one row per crate, then one table per crate "
        "at the top-level-module grain.",
        "Read this file first, then drill into `codemap/<crate>.md` for the per-file table "
        "(kind, size bucket, pub surface, notable types).",
        f"Generated by `{GENERATOR}` — never edit by hand; rerun it after adding, moving, "
        "or deleting a Rust file.",
        "`--check` runs as the first stage of `scripts/verify.sh` and fails when this map is "
        "stale; `--sizes` prints the live line-count table (never committed).",
        "Test files follow the ratchet definition: a `tests/` path component, `tests.rs`, "
        "or `*_tests.rs`.",
        *legend_lines(),
        "",
        "## Workspace",
        "",
    ]
    rows = []
    for name, crate in crates.items():
        rows.append(
            [
                f"[{name}](codemap/{name}.md)",
                crate["purpose"],
                str(crate["source_files"]),
                str(crate["test_files"]),
                str(crate["over_bar"]),
            ]
        )
    lines += table(["crate", "purpose", "source files", "test files", "over 800-line bar"], rows)
    for name, crate in crates.items():
        lines += ["", f"## {name}", ""]
        with_vault = crate["has_impl_vault"]
        header = ["module", "layout", "files", "largest src bucket"]
        if with_vault:
            header.append("impl Vault")
        header.append("purpose")
        rows = []
        for mod_name, mod in crate["modules"].items():
            row = [
                f"`{mod_name}`",
                mod["layout"],
                str(mod["files"]),
                mod["largest_src_bucket"],
            ]
            if with_vault:
                row.append(yes(mod["impl_vault"]))
            row.append(mod["purpose"])
            rows.append(row)
        lines += table(header, rows)
    return "\n".join(lines) + "\n"


def render_crate(name: str, crate: dict) -> str:
    lines = [
        f"# {name}",
        "",
        f"{crate['purpose']}",
        "",
        f"Generated by `{GENERATOR}` — never edit by hand. Overview: [`../CODEMAP.md`](../CODEMAP.md).",
        *legend_lines(),
        "`pub(crate)` / `pub(super)` items are counted under `crate-vis`; `pub use` under "
        "`re-export`. Notable types are `pub` structs, enums and traits.",
        "",
        "## Files",
        "",
    ]
    rows = []
    for f in crate["files"]:
        rows.append(
            [
                f"`{f['path']}`",
                f["kind"],
                f["bucket"],
                surface_text(f["surface"]),
                notable_text(f["notable"]),
                f["purpose"],
            ]
        )
    lines += table(["path", "kind", "bucket", "pub surface", "notable types", "purpose"], rows)
    return "\n".join(lines) + "\n"


def render_json(data: dict) -> str:
    out: dict = {"crates": {}}
    for name, crate in data["crates"].items():
        out["crates"][name] = {
            "purpose": crate["purpose"],
            "source_files": crate["source_files"],
            "test_files": crate["test_files"],
            "over_bar": crate["over_bar"],
            "modules": {
                mod_name: {
                    "layout": mod["layout"],
                    "files": mod["files"],
                    "largest_src_bucket": mod["largest_src_bucket"],
                    "impl_vault": mod["impl_vault"],
                    "purpose": mod["purpose"],
                }
                for mod_name, mod in crate["modules"].items()
            },
            "files": [
                {
                    "path": f["path"],
                    "kind": f["kind"],
                    "bucket": f["bucket"],
                    "surface": f["surface"],
                    "notable": f["notable"],
                    "purpose": f["purpose"],
                }
                for f in crate["files"]
            ],
        }
    return json.dumps(out, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def render_artifacts(data: dict) -> dict[PurePosixPath, bytes]:
    artifacts = {MAP_PATH: render_top(data).encode("utf-8")}
    for name, crate in data["crates"].items():
        artifacts[DIR_PATH / f"{name}.md"] = render_crate(name, crate).encode("utf-8")
    artifacts[JSON_PATH] = render_json(data).encode("utf-8")
    return artifacts


def mapped_files(data: dict) -> int:
    return sum(len(c["files"]) for c in data["crates"].values())


# --------------------------------------------------------------------------- #
# modes
# --------------------------------------------------------------------------- #


def orphan_pages(root: Path, artifacts: dict[PurePosixPath, bytes]) -> list[PurePosixPath]:
    """Generated crate pages on disk that no current crate produces."""
    out_dir = root / DIR_PATH
    if not out_dir.is_dir():
        return []
    orphans = []
    for path in sorted(out_dir.glob("*.md")):
        rel = DIR_PATH / path.name
        if rel not in artifacts:
            orphans.append(rel)
    return orphans


def write_artifacts(root: Path, artifacts: dict[PurePosixPath, bytes]) -> list[PurePosixPath]:
    changed = []
    for rel, content in artifacts.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file() and target.read_bytes() == content:
            continue
        target.write_bytes(content)
        changed.append(rel)
    for rel in orphan_pages(root, artifacts):
        (root / rel).unlink()
        changed.append(rel)
    return changed


def check_artifacts(root: Path, artifacts: dict[PurePosixPath, bytes]) -> list[str]:
    stale = []
    for rel, content in artifacts.items():
        target = root / rel
        if not target.is_file():
            stale.append(f"{rel} (missing)")
            continue
        try:
            current = target.read_bytes()
        except OSError as error:
            raise CodemapError(f"unreadable artifact {rel}: {error}") from error
        if current != content:
            stale.append(f"{rel} (differs)")
    stale += [f"{rel} (orphan)" for rel in orphan_pages(root, artifacts)]
    return stale


def print_sizes(root: Path, data: dict) -> None:
    rows = []
    for name, crate in data["crates"].items():
        for f in crate["files"]:
            rows.append((f["loc"], name, f["path"], f["kind"] == "test"))
    rows.sort(key=lambda r: (-r[0], r[1], r[2]))
    crate_w = max((len(r[1]) for r in rows), default=5)
    file_w = max((len(r[2]) for r in rows), default=4)
    print(f"{'crate':<{crate_w}}  {'file':<{file_w}}  {'loc':>6}  test?")
    for loc, name, rel, is_test in rows:
        print(f"{name:<{crate_w}}  {rel:<{file_w}}  {loc:>6}  {'yes' if is_test else '—'}")
    print(f"{len(rows)} files, {sum(r[0] for r in rows)} lines")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify the committed artifacts")
    mode.add_argument("--sizes", action="store_true", help="print the live line-count table")
    parser.add_argument("--root", help="repo root (default: detected from git / script path)")
    args = parser.parse_args(argv)
    try:
        root = find_root(args.root)
        data = scan_repo(root)
        if args.sizes:
            print_sizes(root, data)
            return 0
        artifacts = render_artifacts(data)
        if args.check:
            stale = check_artifacts(root, artifacts)
            if stale:
                for item in stale:
                    print(f"stale: {item}")
                print(f"CODEMAP-STALE: run {GENERATOR}")
                return 1
            print(f"CODEMAP-OK: {mapped_files(data)} files mapped, {len(artifacts)} artifacts current")
            return 0
        changed = write_artifacts(root, artifacts)
        print(
            f"CODEMAP-OK: {mapped_files(data)} files mapped, "
            f"{len(changed)} of {len(artifacts)} artifacts updated"
        )
        return 0
    except CodemapError as error:
        print(f"CODEMAP-ERROR: {error}")
        return 1
    except BrokenPipeError:
        # `--sizes | head`: the reader closed early; that is not an error.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
