#!/usr/bin/env python3
"""Ratchet metric: raw core-table writes outside the typed write doors.

Counts every call of the shape

    entities | type_index | edges_out | edges_in | short_ids | short_ids_reverse | sync_state
    (any receiver, the table named or called as a method, whitespace and line
    breaks allowed around the dot) . put | delete | delete_range (

in non-test Rust files under crates/oneiron/src, outside the five places that
own these tables: `batch/` (the builders), `ports/` (the storage ports),
`store/` (the storage ABI and manifest handshake rows), `maintain/` (index
upkeep) and `side_table/` (T47's typed keyspace, `vault_meta`/`sync_state`
side rows). Target: 0 (T48).

Non-test file: two rules, unioned.

1. The same path rule `scripts/ratchet/check.sh` uses: no `tests/` path
   component, filename is not `tests.rs`, does not end `_tests.rs` and does
   not start `tests_`.
2. A file reached ONLY through a `#[cfg(test)] mod x;` declaration (or a
   `#[cfg(test)] #[path = "..."] mod x;` one), directly or transitively
   through a chain of such declarations, or declared inside an inline
   `#[cfg(test)] mod <any name> { .. }` body. This catches the files rule 1
   misses by name: `crate::test_util` fixtures live in an inline
   `#[cfg(test)] mod test_util { .. }` block in `lib.rs` whose
   `pub(crate) mod source_scan;` child is a plain file name, and
   `origin/publication/publication_tests_a.rs`,
   `memory/tests_regressions/recall.rs`,
   `booking/publication/regressions.rs` and `branch_store_oracle/**` are each
   reached only via a `#[cfg(test)]` mount (directly, or transitively through
   a parent that is itself test-only). A production `mod` that resolves to
   the SAME target path vetoes the exclusion for that path: hiding production
   code is not the safe failure, scanning a test file as production is. This
   is a same-crate port of `crate::test_util::source_scan`
   (`crates/oneiron/src/test_util/source_scan.rs`) restricted to the subset
   that module needs for its own `SourceTree`, with one deliberate
   divergence: that module vetoes by basename alone (it also copes with
   `#[path]` mounts it cannot resolve, so a basename is sometimes all it has),
   which would wrongly keep `memory/tests_regressions/recall.rs` — reached
   only through `#[cfg(test)] mod tests_regressions;` — counted as production
   merely because an unrelated `memory/recall.rs` also exists; every mount
   this port resolves carries a full path, so its veto compares exact target
   paths instead. Unresolvable `#[path]` syntax here still keeps every
   mount's target file scanned (fail toward counting, never toward silently
   excluding).

2b. Additionally, inside a file that is NOT excluded by (1) or (2), every
   inline `#[cfg(test)] mod <any name> { .. }` BODY is masked out (replaced
   with spaces, newlines kept so line numbers stay accurate) before the call
   pattern is matched. A production file's `#[cfg(test)] mod tests { .. }`
   fixture body must not inflate a production count; `keyspace_census.py`
   does not do this yet, this script is the first to need it because its
   patterns (`entities`, `type_index`, ...) show up in inline test fixtures
   far more than `vault_meta` prose ever did (e.g. `code_memory/parts/
   lifecycle-and-tests.rs`'s inline `#[cfg(test)] mod tests` block, reached
   through an `include!`, not a `mod`, so rule (2) does not see it — only the
   inline mask does).

Whole-line `//` comments, block comments and string/char literal bodies are
stripped before matching (and before the `#[cfg(test)]`/`mod` scan that finds
(2) and 2b's ranges), so prose or a fixture byte string naming a table is
never mistaken for a call or for module structure.

Output: ONE integer on stdout, exit 0. With --list: one `path:line` line per
call, sorted, for humans reading the number.

Fails CLOSED like check.sh and keyspace_census.py: an unreadable file or a
scan that finds no source files prints `RATCHET-ERROR: ...` on stderr and
exits 1, never a silent 0.
"""

import os
import re
import sys

ROOT = "crates/oneiron/src"
DOORS = ("batch/", "ports/", "store/", "maintain/", "side_table/")
TABLES = (
    "entities",
    "type_index",
    "edges_out",
    "edges_in",
    "short_ids",
    "short_ids_reverse",
    "sync_state",
)
CALL = re.compile(
    r"\b(?:" + "|".join(TABLES) + r")(?:\(\))?\s*\.\s*(?:put|delete_range|delete)\s*\("
)

_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
_MOD_RE = re.compile(r"\bmod\b")


def is_ident_byte(ch):
    return ch in _IDENT_CHARS


def test_only_by_path(rel):
    """check.sh's path rule (the same one keyspace_census.py uses)."""
    parts = rel.split("/")
    name = parts[-1]
    return (
        "tests" in parts[:-1]
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.startswith("tests_")
    )


# --- comment / string-literal stripping (byte-length preserving) ----------


def strip_comments_and_literals(source):
    n = len(source)
    out = [" "] * n
    i = 0
    while i < n:
        ch = source[i]
        if ch == "\n":
            out[i] = "\n"
            i += 1
        elif source.startswith("//", i):
            i = _copy_until_newline(source, out, i)
        elif source.startswith("/*", i):
            i = _skip_block_comment(source, out, i)
        elif _raw_string_hashes(source, i) is not None:
            i = _skip_raw_string(source, out, i)
        elif ch == '"':
            i = _skip_quoted(source, out, i, '"')
        elif ch == "'" and _looks_like_char_literal(source, i):
            i = _skip_quoted(source, out, i, "'")
        else:
            out[i] = ch
            i += 1
    return "".join(out)


def _copy_until_newline(source, out, i):
    n = len(source)
    while i < n:
        if source[i] == "\n":
            out[i] = "\n"
            return i + 1
        i += 1
    return i


def _skip_block_comment(source, out, i):
    n = len(source)
    depth = 0
    while i < n:
        if source[i] == "\n":
            out[i] = "\n"
            i += 1
        elif source.startswith("/*", i):
            depth += 1
            i += 2
        elif source.startswith("*/", i):
            depth = max(depth - 1, 0)
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    return i


def _raw_string_hashes(source, start):
    n = len(source)
    if start >= n or source[start] != "r":
        return None
    if start > 0 and is_ident_byte(source[start - 1]):
        return None
    i = start + 1
    while i < n and source[i] == "#":
        i += 1
    if i < n and source[i] == '"':
        return i - start - 1
    return None


def _skip_raw_string(source, out, start):
    hashes = _raw_string_hashes(source, start)
    n = len(source)
    terminator = "#" * hashes
    i = start + hashes + 2
    while i < n:
        if source[i] == "\n":
            out[i] = "\n"
            i += 1
            continue
        if source[i] == '"' and source[i + 1 : i + 1 + hashes] == terminator:
            return i + hashes + 1
        i += 1
    return i


def _looks_like_char_literal(source, start):
    n = len(source)
    i = start + 1
    if i < n and source[i] == "\\":
        i += 2
    else:
        i += 1
    return i < n and source[i] == "'"


def _skip_quoted(source, out, i, quote):
    n = len(source)
    i += 1
    while i < n:
        if source[i] == "\n":
            out[i] = "\n"
            i += 1
        elif source[i] == "\\":
            i = min(i + 2, n)
        elif source[i] == quote:
            return i + 1
        else:
            i += 1
    return i


# --- inline `mod x { .. }` / `#[cfg(test)] mod x { .. }` structure --------


def after_visibility(body):
    if body.startswith("pub"):
        rest = body[3:]
        if rest[:1].isspace():
            return rest.lstrip()
        if rest.startswith("("):
            inner = rest[1:]
            close = inner.find(")")
            if close != -1 and "(" not in inner[:close]:
                return rest[1 + close + 1 :].lstrip()
    return body


def inline_module_header(source, start):
    """`[pub[(..)]] mod <ident> {` at `start` (whitespace-tolerant). Returns
    `(name, open_brace_index)` or `None`."""
    body = after_visibility(source[start:].lstrip())
    if not body.startswith("mod"):
        return None
    rest = body[3:]
    if not rest[:1].isspace():
        return None
    rest = rest.lstrip()
    name_len = 0
    while name_len < len(rest) and is_ident_byte(rest[name_len]):
        name_len += 1
    if name_len == 0:
        return None
    tail = rest[name_len:].lstrip()
    if not tail.startswith("{"):
        return None
    return rest[:name_len], len(source) - len(tail)


def matching_brace_end(text, open_idx):
    depth = 0
    for idx in range(open_idx, len(text)):
        c = text[idx]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return None


def inline_module_blocks(clean):
    """Every inline `mod <ident> { .. }` block: `(start, end, name)`."""
    blocks = []
    for m in _MOD_RE.finditer(clean):
        header = inline_module_header(clean, m.start())
        if header is None:
            continue
        name, open_idx = header
        end = matching_brace_end(clean, open_idx)
        if end is None:
            continue
        blocks.append((m.start(), end, name))
    return blocks


def inline_module_chain(blocks, at):
    enclosing = sorted((b for b in blocks if b[0] <= at < b[1]), key=lambda b: b[0])
    return [name for _, _, name in enclosing]


def cfg_test_module_ranges(source):
    """Byte ranges of every `#[cfg(test)] mod <ident> { .. }`, attribute
    included."""
    ranges = []
    needle = "#[cfg(test)]"
    search_start = 0
    while True:
        idx = source.find(needle, search_start)
        if idx == -1:
            return ranges
        cfg_start = idx
        search_start = idx + len(needle)
        header = inline_module_header(source, search_start)
        if header is None:
            continue
        _, open_idx = header
        end = matching_brace_end(source, open_idx)
        if end is None:
            return ranges
        ranges.append((cfg_start, end))
        search_start = end


def mask_cfg_test_modules(source):
    out = list(source)
    for start, end in cfg_test_module_ranges(source):
        for i in range(start, end):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


def production_source(raw):
    return mask_cfg_test_modules(strip_comments_and_literals(raw))


# --- external `mod x;` mounts, and which files they make test-only --------


def without_visibility(compact):
    if compact.endswith("pub"):
        return compact[:-3]
    idx = compact.rfind("pub(")
    if idx != -1:
        inner = compact[idx + 4 :]
        if inner.endswith(")") and "(" not in inner[:-1] and ")" not in inner[:-1]:
            return compact[:idx]
    return compact


def mount_base(parent, chain, path_attr):
    parent_dir, _, parent_file = parent.rpartition("/")
    mod_rs = parent_file in ("mod.rs", "lib.rs", "main.rs")
    if mod_rs or (path_attr and not chain):
        base = parent_dir
    else:
        stem = parent_file[:-3] if parent_file.endswith(".rs") else parent_file
        base = f"{parent_dir}/{stem}" if parent_dir else stem
    for module in chain:
        base = f"{base}/{module}" if base else module
    return base


class ExternalMount:
    __slots__ = ("parent", "targets", "cfg_test")

    def __init__(self, parent, targets, cfg_test):
        self.parent = parent
        self.targets = targets
        self.cfg_test = cfg_test


def external_mounts(sources):
    """`sources`: `[(relpath, raw_text), ..]`. Every `mod <ident>;` (plain or
    `#[path = "..."]`) declaration outside comments/literals, in source order.
    A `#[path]` mount whose literal is not a simple relative `a/b.rs`-shaped
    string is kept with an empty target list (never resolved, never hides a
    file)."""
    mounts = []
    for parent, raw in sources:
        clean = strip_comments_and_literals(raw)
        blocks = inline_module_blocks(clean)
        test_blocks = cfg_test_module_ranges(clean)
        for m in _MOD_RE.finditer(clean):
            start = m.start()
            tail = clean[start + 3 :]
            if not tail[:1].isspace():
                continue
            tail = tail.lstrip()
            name_len = 0
            while name_len < len(tail) and is_ident_byte(tail[name_len]):
                name_len += 1
            if name_len == 0:
                continue
            name = tail[:name_len]
            after_name = tail[name_len:].lstrip()
            if not after_name.startswith(";"):
                continue  # an inline `mod x { .. }`, not an external mount

            chain = inline_module_chain(blocks, start)
            inside_test_module = any(s <= start < e for s, e in test_blocks)
            prefix_start = 0
            for marker in ";{}":
                idx = clean.rfind(marker, 0, start)
                if idx + 1 > prefix_start:
                    prefix_start = idx + 1
            prefix = clean[prefix_start:start]
            compact = without_visibility("".join(prefix.split()))
            depth = 0
            for c in clean[:start]:
                if c in "{([":
                    depth += 1
                elif c in "})]":
                    depth -= 1
            simple_nesting = depth == len(chain)

            if "path=" not in compact:
                base = mount_base(parent, chain, False)
                targets = [
                    t
                    for t in (f"{base}/{name}.rs" if base else f"{name}.rs",
                              f"{base}/{name}/mod.rs" if base else f"{name}/mod.rs")
                ]
                mounts.append(
                    ExternalMount(
                        parent=parent,
                        targets=targets,
                        cfg_test=inside_test_module
                        or (simple_nesting and compact == "#[cfg(test)]"),
                    )
                )
                continue

            path_marker = prefix.find("#[path")
            if path_marker == -1:
                # `path=` came from something this scanner doesn't model (not
                # a `#[path = ".."]` attribute right before this `mod`); skip
                # this one declaration rather than guess. It stays reachable
                # only under its own file's normal rules.
                continue
            path_start = prefix_start + path_marker + len("#[path")
            bracket_rel = clean[path_start:start].find("]")
            if bracket_rel == -1:
                continue
            literal_src = raw[path_start : path_start + bracket_rel].strip()
            if not literal_src.startswith("="):
                continue
            value = literal_src[1:].strip()
            if len(value) < 2 or value[0] != '"' or value[-1] != '"':
                continue
            literal = value[1:-1]
            if "\\" in literal or '"' in literal or compact.count("path=") != 1:
                continue
            components = literal.split("/")
            simple = literal not in ("", ".", "..") and all(
                part not in ("", ".", "..") for part in components
            )
            target_base = mount_base(parent, chain, True)
            targets = (
                [f"{target_base}/{literal}" if target_base else literal]
                if simple
                else []
            )
            mounts.append(
                ExternalMount(
                    parent=parent,
                    targets=targets,
                    cfg_test=inside_test_module,
                )
            )
    return mounts


def cfg_test_external_files(sources):
    """`sources`: `{relpath: raw_text}`. Files reached ONLY through a
    `#[cfg(test)]` mount, directly or transitively, minus a production-mount
    veto.

    `source_scan.rs` vetoes by basename alone (it also has to cope with
    `#[path]` mounts it cannot resolve, so it cannot always tell two same-
    named mounts apart). Every mount this port resolves carries a full
    relative target path, so the veto here is exact-path: a production mount
    only keeps a file scanned when it resolves to that SAME file, not merely
    a same-named one elsewhere (`memory/mod.rs`'s production `mod recall;`
    must not keep `memory/tests_regressions/recall.rs` — reached only via
    `#[cfg(test)] mod tests_regressions;` — counted as production just
    because `memory/recall.rs` also exists)."""
    items = list(sources.items())
    mounts = external_mounts(items)

    tests = set()
    while True:
        before = len(tests)
        for mount in mounts:
            if mount.cfg_test or mount.parent in tests or test_only_by_path(mount.parent):
                for target in mount.targets:
                    if target in sources:
                        tests.add(target)
        if len(tests) == before:
            break

    production_targets = set()
    for mount in mounts:
        if (
            not mount.cfg_test
            and mount.parent not in tests
            and not test_only_by_path(mount.parent)
        ):
            production_targets.update(mount.targets)
    return tests - production_targets


# --- driver -----------------------------------------------------------


def read_tree(root):
    sources = {}
    for directory, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, encoding="utf-8") as handle:
                sources[rel] = handle.read()
    return sources


def main():
    repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    root = os.path.join(repo, ROOT)
    try:
        sources = read_tree(root)
    except OSError as error:
        print(f"RATCHET-ERROR: cannot read {root}: {error}", file=sys.stderr)
        return 1
    if not sources:
        print("RATCHET-ERROR: raw write census scanned no source files", file=sys.stderr)
        return 1

    cfg_test_files = cfg_test_external_files(sources)

    def is_test(rel):
        return test_only_by_path(rel) or rel in cfg_test_files

    hits = []
    scanned = 0
    for rel, text in sources.items():
        if rel.startswith(DOORS) or is_test(rel):
            continue
        scanned += 1
        masked = production_source(text)
        for match in CALL.finditer(masked):
            hits.append((rel, masked.count("\n", 0, match.start()) + 1))

    if scanned == 0:
        print(
            "RATCHET-ERROR: raw write census scanned no production source files",
            file=sys.stderr,
        )
        return 1

    if "--list" in sys.argv[1:]:
        for rel, line in sorted(hits):
            print(f"{ROOT}/{rel}:{line}")
    else:
        print(len(hits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
