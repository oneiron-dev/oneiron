#!/usr/bin/env python3
"""Rewrite flat `Error::Variant` references into the nested domain form.

    scripts/refactor/error_split/rewrite.py --dry-run
    scripts/refactor/error_split/rewrite.py --domains sync
    scripts/refactor/error_split/rewrite.py --domains sync --apply

python3 stdlib only. Reads `manifest.json`; rewrites every reference to a
variant whose `action` is `move`, everywhere under `crates/` EXCEPT the
definition file `crates/oneiron/src/error.rs`.

Code sites:

    Err(Error::InvalidSkillBody(x))   ->  Err(Error::Artifact(ArtifactError::InvalidSkillBody(x)))
    .ok_or(Error::EditProposalStale)  ->  .ok_or(Error::Artifact(ArtifactError::EditProposalStale))
    Err(crate::Error::Foo { a, b })   ->  Err(crate::Error::Domain(crate::error::DomainError::Foo { a, b }))
    matches!(e, Error::Foo { .. })    ->  matches!(e, Error::Domain(DomainError::Foo { .. }))

Doc and comment sites keep the plain path, because the wrapper is not part of
the name an intra-doc link resolves:

    /// [`Error::InvalidSkillBody`]   ->  /// [`ArtifactError::InvalidSkillBody`]

The nested form is used in every position because it is valid in all of them:
construction, `?`-returns, `map_err`, `matches!`, `if let`, match arms.

Idempotent: after a run, no `Error::<moved variant>` remains, and the rewritten
text contains `<Domain>Error::Variant`, which the matcher cannot match again
(no word boundary before `Error::`).

Never guessed, always listed (see `--report`): a tuple or struct variant used
as a bare function value (`map_err(Error::X)`), an occurrence inside a string
literal, and an occurrence inside a `macro_rules!` body.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

ERROR_RS = os.path.join("crates", "oneiron", "src", "error.rs")
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
REF = re.compile(r"\bError::([A-Z][A-Za-z0-9_]*)")
QUAL = re.compile(r"((?:" + IDENT + r"::)+)$")

# Qualifier in the source  ->  (outer path kept on `Error`, path prefix for the
# domain enum). `None` outer means the bare form; the domain enum then needs a
# `use`, which `--add-imports` supplies.
CODE_QUAL = {
    "": ("", ""),
    "crate::": ("crate::", "crate::error::"),
    "crate::error::": ("crate::error::", "crate::error::"),
    "error::": ("error::", "error::"),
    "oneiron::": ("oneiron::", "oneiron::error::"),
    "oneiron::error::": ("oneiron::error::", "oneiron::error::"),
}

# States from `scan`.
CODE, STRING, COMMENT, DOC = 0, 1, 2, 3


def scan(text: str) -> bytearray:
    """Classify every byte of Rust source as code, string, comment or doc.

    Handles line comments, doc comments (`///`, `//!`), block comments
    (nested), normal and raw strings (`r"..."`, `r#"..."#`), byte strings, and
    char literals, and does not mistake a lifetime (`&'static str`) for one.
    """
    out = bytearray([CODE]) * len(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            kind = DOC if (i + 2 < n and text[i + 2] in "/!") else COMMENT
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = kind
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                out[k] = COMMENT
            i = j
            continue
        if c in "rb" and i + 1 < n:
            m = re.match(r'(?:b?r|rb?)(#*)"', text[i:])
            if m:
                hashes = m.group(1)
                close = '"' + hashes
                j = text.find(close, i + m.end())
                j = n if j < 0 else j + len(close)
                for k in range(i, j):
                    out[k] = STRING
                i = j
                continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                out[k] = STRING
            i = j
            continue
        if c == "'":
            m = re.match(r"'(?:\\.[^']*|[^'\\])'", text[i:])
            if m:  # char literal, not a lifetime
                for k in range(i, i + m.end()):
                    out[k] = STRING
                i += m.end()
                continue
        i += 1
    return out


def macro_spans(text: str, states: bytearray) -> list[tuple[int, int]]:
    """Byte spans of `macro_rules!` bodies."""
    spans = []
    for m in re.finditer(r"\bmacro_rules!\s*" + IDENT + r"\s*", text):
        i = m.end()
        while i < len(text) and text[i] not in "{([":
            i += 1
        if i >= len(text):
            continue
        end = match_bracket(text, states, i)
        if end is not None:
            spans.append((m.start(), end))
    return spans


PAIRS = {"(": ")", "{": "}", "[": "]"}


def match_bracket(text: str, states: bytearray, start: int) -> int | None:
    """Index just past the bracket matching the one at `start`, code-only."""
    opener = text[start]
    closer = PAIRS[opener]
    depth, i, n = 0, start, len(text)
    while i < n:
        if states[i] == CODE:
            ch = text[i]
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return None


def next_code_char(text: str, states: bytearray, i: int) -> int:
    """Index of the next code character at or after `i`, skipping ws/comments."""
    n = len(text)
    while i < n and (text[i].isspace() or states[i] in (COMMENT, DOC)):
        i += 1
    return i


def load_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def crate_prefix(rel: str) -> str:
    """The path root a file must use to name `oneiron`'s error module."""
    parts = rel.replace("\\", "/").split("/")
    if len(parts) > 2 and parts[0] == "crates" and parts[1] == "oneiron" and parts[2] == "src":
        return "crate::error::"
    return "oneiron::error::"


def rewrite_text(text: str, rel: str, moving: dict, domains: dict,
                 add_imports: bool = True) -> tuple[str, dict]:
    """Return (new_text, stats). Never raises on unreadable syntax; it lists."""
    states = scan(text)
    macros = macro_spans(text, states)
    edits: list[tuple[int, int, str]] = []
    stats = {
        "code": 0,
        "doc": 0,
        "lines": set(),
        "unresolvable": [],
        "imports": {},
        "per_domain": collections.Counter(),
    }
    prefix = crate_prefix(rel)

    for m in REF.finditer(text):
        name = m.group(1)
        info = moving.get(name)
        if info is None:
            continue
        start, end = m.start(), m.end()
        state = states[start]
        if state == STRING:
            stats["unresolvable"].append(
                {"file": rel, "line": text.count("\n", 0, start) + 1,
                 "variant": name, "why": "inside a string literal"})
            continue
        if any(a <= start < b for a, b in macros):
            stats["unresolvable"].append(
                {"file": rel, "line": text.count("\n", 0, start) + 1,
                 "variant": name, "why": "inside a macro_rules! body"})
            continue

        qm = QUAL.search(text[max(0, start - 64):start])
        qual = qm.group(1) if qm else ""
        if qual not in CODE_QUAL:
            stats["unresolvable"].append(
                {"file": rel, "line": text.count("\n", 0, start) + 1,
                 "variant": name, "why": f"unrecognised qualifier {qual!r}"})
            continue
        outer, inner = CODE_QUAL[qual]
        dom = domains[info["domain"]]
        enum_name = dom["enum"]
        wrapper = dom["wrapper"]
        line_no = text.count("\n", 0, start) + 1

        if state in (COMMENT, DOC):
            # Doc and comment prose names the LEAF enum, never the wrapper: an
            # intra-doc link resolves a path, and the wrapper is not part of
            # the leaf's path. The full path is always spelled out on the link
            # target so no `use` is needed — a `use` that only a doc link reads
            # is an `unused_imports` warning, and the gate runs -D warnings.
            full = prefix + enum_name
            ls = text.rfind("\n", 0, start) + 1
            le = text.find("\n", start)
            le = len(text) if le < 0 else le
            line = text[ls:le]
            label = f"[`{qual}Error::{name}`]"
            at = start - len(qual) - 2  # start of "[`"
            is_label = text[at:at + len(label)] == label
            rest = line[(at - ls) + len(label):] if is_label else ""
            # `[`Error::X`]: <single path token>` is a link-reference
            # definition: the label is a display name, the target resolves it.
            if is_label and re.match(r"^:\s*[A-Za-z_][A-Za-z0-9_:]*\s*$", rest):
                edits.append((at, at + len(label), f"[`{enum_name}::{name}`]"))
            elif is_label:
                edits.append((at, at + len(label),
                              f"[`{enum_name}::{name}`]({full}::{name})"))
            else:
                edits.append((start - len(qual), end, f"{full}::{name}"))
            stats["doc"] += 1
            stats["per_domain"][info["domain"]] += 1
            stats["lines"].add(line_no)
            continue

        shape = info["shape"]
        body_end = end
        if shape in ("tuple", "struct"):
            opener = "(" if shape == "tuple" else "{"
            j = next_code_char(text, states, end)
            if j >= len(text) or text[j] != opener:
                stats["unresolvable"].append(
                    {"file": rel, "line": line_no, "variant": name,
                     "why": f"{shape} variant used without its {opener}...{PAIRS[opener]} "
                            "payload (constructor used as a function value); needs a closure"})
                continue
            closed = match_bracket(text, states, j)
            if closed is None:
                stats["unresolvable"].append(
                    {"file": rel, "line": line_no, "variant": name,
                     "why": "unbalanced payload brackets"})
                continue
            body_end = closed

        inner_path = (inner + enum_name) if inner else enum_name
        if not inner:
            stats["imports"].setdefault(enum_name, []).append(start)
        body = text[end:body_end]
        edits.append(
            (start - len(qual), body_end,
             f"{outer}Error::{wrapper}({inner_path}::{name}{body})")
        )
        stats["code"] += 1
        stats["per_domain"][info["domain"]] += 1
        stats["lines"].add(line_no)

    if add_imports and edits:
        import_edits = plan_imports(text, states, rel, stats["imports"])
        stats["imports_planned"] = len(import_edits)
        edits.extend(import_edits)
    if not edits:
        return text, stats
    edits.sort(key=lambda e: (e[0], e[1]))
    out, cursor = [], 0
    for a, b, repl in edits:
        if a < cursor:  # overlapping (a nested payload also matched) — skip
            continue
        out.append(text[cursor:a])
        out.append(repl)
        cursor = b
    out.append(text[cursor:])
    return "".join(out), stats


MOD_HEAD = re.compile(r"(?:^|\n)([ \t]*)(?:pub(?:\([^)]*\))?\s+)?mod\s+" + IDENT + r"\s*\{")
USE_HEAD = re.compile(r"(?:^|\n)([ \t]*)(?:pub(?:\([^)]*\))?\s+)?use\s")


def module_spans(text: str, states: bytearray) -> list[tuple[int, int, int, str]]:
    """(body_start, body_end, depth, indent) for every inline `mod X { .. }`."""
    spans = []
    for m in MOD_HEAD.finditer(text):
        brace = text.index("{", m.start())
        if states[brace] != CODE:
            continue
        end = match_bracket(text, states, brace)
        if end is None:
            continue
        spans.append((brace + 1, end - 1, m.group(1)))
    return [(a, b, sum(1 for x, y, _ in spans if x < a and b < y), ind) for a, b, ind in spans]


def statement_end(text: str, states: bytearray, at: int) -> int:
    """Index just past the `;` that ends the statement starting at `at`."""
    i, n = at, len(text)
    depth = 0
    while i < n:
        if states[i] == CODE:
            ch = text[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth == 0:
                return i + 1
        i += 1
    return at


def plan_imports(text: str, states: bytearray, rel: str,
                 imports: dict) -> list[tuple[int, int, str]]:
    """Edits that add `use <root>error::{...};` in the right module scope.

    A `use` at file top level is NOT in scope inside `mod tests { .. }`, so the
    statement is placed in the innermost module that encloses the references
    that need it. Placement point: after the last `use` statement already in
    that scope, else immediately after the scope's opening brace.
    """
    if not imports:
        return []
    root = "crate::" if crate_prefix(rel) == "crate::error::" else "oneiron::"
    mods = module_spans(text, states)

    def scope_of(off: int) -> tuple[int, int, str] | None:
        best = None
        for a, b, depth, indent in mods:
            if a <= off < b and (best is None or depth > best[3]):
                best = (a, b, indent, depth)
        return (best[0], best[1], best[2]) if best else None

    # scope key -> set of enum names
    wanted: dict[tuple, set] = {}
    for enum_name, offsets in imports.items():
        for off in offsets:
            wanted.setdefault(scope_of(off) or ("file", 0, ""), set()).add(enum_name)

    edits = []
    for scope, names in wanted.items():
        if scope[0] == "file":
            lo, hi, indent = 0, len(text), ""
        else:
            lo, hi, indent = scope
        region = text[lo:hi]
        needed = sorted(
            n for n in names
            if not re.search(rf"\buse\s[^;]*\b{n}\b\s*(?:,|}}|;|\sas\s)", region)
        )
        if not needed:
            continue
        stmt = (f"{indent}use {root}error::{{{', '.join(needed)}}};"
                if len(needed) > 1 else f"{indent}use {root}error::{needed[0]};")
        # last `use` statement directly in this scope (same indent, not nested)
        at = None
        for m in USE_HEAD.finditer(region):
            off = lo + m.end() - 4
            inner = scope_of(off)
            if (inner or ("file", 0, ""))[0] != (scope[0] if scope[0] != "file" else "file"):
                continue
            at = statement_end(text, states, off)
        if at is None:
            if scope[0] == "file":
                # after leading module docs and inner attributes
                at = 0
                for line in text.split("\n"):
                    if line.startswith("//!") or line.startswith("#![") or not line.strip():
                        at += len(line) + 1
                    else:
                        break
                edits.append((at, at, stmt + "\n\n"))
                continue
            at = lo
            edits.append((at, at, "\n" + stmt))
            continue
        edits.append((at, at, "\n" + stmt))
    return edits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=os.path.join(HERE, "manifest.json"))
    ap.add_argument("--domains", default="all",
                    help="comma-separated domain ids, or 'all' (default)")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    ap.add_argument("--apply", action="store_true", help="write the changes")
    ap.add_argument("--no-add-imports", action="store_true",
                    help="do not insert `use crate::error::{...}` lines")
    ap.add_argument("--report", default=None,
                    help="write the full JSON report to this path")
    ap.add_argument("--root", default=REPO)
    args = ap.parse_args()

    if args.apply == args.dry_run:
        print("rewrite: pass exactly one of --dry-run or --apply", file=sys.stderr)
        return 2

    manifest = load_manifest(args.manifest)
    domains = manifest["domains"]
    wanted = (set(domains) - {"root"} if args.domains == "all"
              else {d.strip() for d in args.domains.split(",") if d.strip()})
    unknown = wanted - set(domains)
    if unknown:
        print(f"rewrite: unknown domain(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2

    moving = {
        v["name"]: v
        for v in manifest["variants"]
        if v["action"] == "move" and v["domain"] in wanted
    }
    if not moving:
        print("rewrite: nothing to do (no moving variants in the selected domains)")
        return 0

    per_domain = collections.Counter()
    per_crate = collections.Counter()
    per_file: dict[str, dict] = {}
    unresolvable: list[dict] = []
    imports_added: dict[str, list[str]] = {}
    total_lines = 0

    for dirpath, dirnames, filenames in os.walk(os.path.join(args.root, "crates")):
        dirnames[:] = [d for d in dirnames if d not in {"target", ".git", "node_modules", "vendor"}]
        for fn in sorted(filenames):
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, args.root)
            if rel == ERROR_RS:
                continue
            try:
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            if "Error::" not in text:
                continue
            new, stats = rewrite_text(text, rel, moving, domains,
                                      add_imports=not args.no_add_imports)
            unresolvable.extend(stats["unresolvable"])
            if new == text:
                continue
            if stats.get("imports_planned"):
                imports_added[rel] = sorted(stats["imports"])
            n_lines = len(stats["lines"])
            total_lines += n_lines
            per_file[rel] = {"lines": n_lines, "code": stats["code"], "doc": stats["doc"]}
            per_crate[rel.split(os.sep)[1]] += n_lines
            per_domain.update(stats["per_domain"])
            if args.apply:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new)

    mode = "APPLIED" if args.apply else "DRY RUN"
    print(f"=== rewrite {mode}: domains {','.join(sorted(wanted))} ===")
    print(f"files changed : {len(per_file)}")
    print(f"lines changed : {total_lines}")
    print("per crate:")
    for crate, n in per_crate.most_common():
        print(f"  {crate:20s} {n:6d}")
    print("per domain (rewritten references):")
    for dom, n in per_domain.most_common():
        print(f"  {dom:14s} {n:6d}")
    if imports_added:
        print(f"imports inserted: {len(imports_added)} files")
    if unresolvable:
        print(f"UNRESOLVABLE ({len(unresolvable)}) — left untouched, fix by hand:")
        for u in unresolvable:
            print(f"  {u['file']}:{u['line']}  Error::{u['variant']}  — {u['why']}")
    else:
        print("unresolvable: none")

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "mode": mode,
                    "domains": sorted(wanted),
                    "files_changed": len(per_file),
                    "lines_changed": total_lines,
                    "per_crate": dict(per_crate),
                    "per_domain": dict(per_domain),
                    "per_file": per_file,
                    "imports_added": imports_added,
                    "unresolvable": unresolvable,
                },
                fh,
                indent=1,
            )
            fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
