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

A test-only cfg is a `#[cfg(..)]` predicate that is false in every build that
sets neither `test` (cargo's unit-test build) nor `oneiron_test_support`
(passed as `--cfg` by the integration-test command alone; it gates
`crate::test_doors` and the `*_door` modules), whatever the features and the
target are: `test`, `oneiron_test_support`, `any(test, oneiron_test_support)`,
`all(oneiron_test_support, feature = "sync")`. A predicate that a feature or
the target alone can make true, such as
`any(test, feature = "test-support", oneiron_test_support)`, is not test-only:
`--all-features` is the release build (ARCH-0019), so that code ships. A
predicate this scanner does not parse is not test-only either (fail toward
counting).

Non-test file: three rules, unioned.

1. The same path rule `scripts/ratchet/check.sh` uses: no `tests/` path
   component, filename is not `tests.rs`, does not end `_tests.rs` and does
   not start `tests_`.
2. A file reached ONLY through a `mod x;` declaration gated by a test-only
   cfg (`#[cfg(test)] mod x;`, `#[cfg(oneiron_test_support)] #[doc(hidden)]
   pub mod test_doors;`, a `#[path = "..."]` and other attributes beside the
   cfg allowed), directly or transitively through a chain of such
   declarations, or declared inside an inline `mod <any name> { .. }` body
   gated by a test-only cfg. This catches the files rule 1
   misses by name: `crate::test_util` fixtures live in an inline
   `#[cfg(test)] mod test_util { .. }` block in `lib.rs` whose
   `pub(crate) mod source_scan;` child is a plain file name, and
   `origin/publication/publication_tests_a.rs`,
   `memory/tests_regressions/recall.rs`,
   `booking/publication/regressions.rs` and `branch_store_oracle/**` are each
   reached only via a `#[cfg(test)]` mount (directly, or transitively through
   a parent that is itself test-only). A production `mod` that resolves to
   the SAME target path vetoes the exclusion for that path, and for every
   file that path mounts without a test-only cfg, transitively (stopping at
   rule 3 files and path-rule files): hiding production code is not the safe
   failure, scanning a test file as production is. This
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
3. A file whose own leading inner attributes hold a test-only cfg
   (`#![cfg(oneiron_test_support)]` at the top of
   `test_doors/fingerprint_keep_*_digests.rs`). Such a file compiles to
   nothing outside a test build whoever mounts it, so no production mount
   vetoes it, and the files it mounts are test-only through rule 2.

2b. Additionally, inside a file that is NOT excluded by (1), (2) or (3), every
   inline `mod <any name> { .. }` gated by a test-only cfg (attribute and
   BODY) is masked out (replaced
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
stripped before matching (and before the `cfg`/`mod` scan that finds (2),
(3) and 2b's ranges), so prose or a fixture byte string naming a table is
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
_CFG_ATTRIBUTE_RE = re.compile(r"#\s*\[\s*cfg\s*\(")
# The cfg names only a test build sets: cargo's unit-test build sets `test`,
# and only the integration-test command passes `--cfg oneiron_test_support`.
TEST_ONLY_CFG_NAMES = frozenset(("test", "oneiron_test_support"))


def is_ident_byte(ch):
    return ch in _IDENT_CHARS


def test_only_by_path(rel):
    """check.sh's path rule (the same one keyspace_census.py uses)."""
    parts = rel.split("/")
    name = parts[-1]
    return (
        # T36 split a cfg(test)-only recall.rs into include!-mounted children.
        # They inherit that test-only mount even though include! is not a mod edge.
        rel.startswith("memory/tests_regressions/recall/")
        or "tests" in parts[:-1]
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


# --- test-only `cfg` predicates and attributes ---------------------------


class _CfgSyntax(Exception):
    """A `cfg` predicate this scanner does not parse."""


def cfg_value_without_test_names(predicate):
    """Value of a `cfg(..)` predicate in a build that sets no name in
    TEST_ONLY_CFG_NAMES: `False` when it is false in every such build, `True`
    when it is true in every such build, `None` when a feature or the target
    decides. Whitespace is ignored, and a `key = "value"` atom's literal may be
    blanked (`strip_comments_and_literals` blanks it). Text that does not
    parse is `None`, so whatever it gates stays counted."""
    text = "".join(predicate.split())
    try:
        value, end = _cfg_predicate(text, 0)
    except _CfgSyntax:
        return None
    return value if end == len(text) else None


def _cfg_predicate(text, i):
    """Parse one predicate at `i`: `(value, index after it)`."""
    start = i
    while i < len(text) and is_ident_byte(text[i]):
        i += 1
    name = text[start:i]
    if not name:
        raise _CfgSyntax
    if text.startswith("=", i):
        i += 1
        if text.startswith('"', i):
            close = text.find('"', i + 1)
            if close == -1:
                raise _CfgSyntax
            i = close + 1
        return None, i
    if not text.startswith("(", i):
        return (False if name in TEST_ONLY_CFG_NAMES else None), i
    if name not in ("all", "any", "not"):
        raise _CfgSyntax
    i += 1
    values = []
    while not text.startswith(")", i):
        value, i = _cfg_predicate(text, i)
        values.append(value)
        if text.startswith(",", i):
            i += 1
        elif not text.startswith(")", i):
            raise _CfgSyntax
    i += 1
    if name == "not":
        if len(values) != 1:
            raise _CfgSyntax
        return (None if values[0] is None else not values[0]), i
    if name == "all":
        if False in values:
            return False, i
        return (True if all(v is True for v in values) else None), i
    if True in values:
        return True, i
    return (False if all(v is False for v in values) else None), i


def is_test_only_cfg(attribute_body):
    """`attribute_body`: the text inside `#[..]` or `#![..]`. True for a
    `cfg(<predicate>)` whose predicate is false in every build that sets no
    test-only cfg name."""
    body = "".join(attribute_body.split())
    return (
        body.startswith("cfg(")
        and body.endswith(")")
        and cfg_value_without_test_names(body[4:-1]) is False
    )


def attribute_close(text, open_bracket):
    """Index of the `]` that closes the `[` at `open_bracket`, or None."""
    depth = 0
    for idx in range(open_bracket, len(text)):
        c = text[idx]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return idx
    return None


def skip_outer_attributes(text, pos):
    """Index of the first character after the whitespace and the `#[..]`
    attributes that start at `pos`."""
    n = len(text)
    while True:
        while pos < n and text[pos].isspace():
            pos += 1
        if not text.startswith("#[", pos):
            return pos
        close = attribute_close(text, pos + 1)
        if close is None:
            return pos
        pos = close + 1


def attributes_gate_test_only(compact):
    """`compact`: the whitespace-free text between the previous item and a
    `mod` keyword, visibility removed. True when that text is a run of
    attributes and one of the outer ones is a test-only cfg. Inner `#![..]`
    attributes belong to the enclosing scope, so they gate nothing here. Any
    other text keeps the mount counted."""
    i = 0
    gated = False
    while i < len(compact):
        inner = compact.startswith("#![", i)
        if not inner and not compact.startswith("#[", i):
            return False
        open_bracket = i + (2 if inner else 1)
        close = attribute_close(compact, open_bracket)
        if close is None:
            return False
        if not inner and is_test_only_cfg(compact[open_bracket + 1 : close]):
            gated = True
        i = close + 1
    return gated


def file_gated_test_only(clean):
    """True when the stripped file's leading inner attributes hold a
    test-only cfg (`#![cfg(oneiron_test_support)]`): the whole file then
    compiles only in a test build, whatever mounts it."""
    n = len(clean)
    pos = 0
    while True:
        while pos < n and clean[pos].isspace():
            pos += 1
        if not clean.startswith("#![", pos):
            return False
        close = attribute_close(clean, pos + 2)
        if close is None:
            return False
        if is_test_only_cfg(clean[pos + 3 : close]):
            return True
        pos = close + 1


# --- inline `mod x { .. }` / test-only `#[cfg(..)] mod x { .. }` structure -


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


def test_only_module_ranges(source):
    """Byte ranges of every inline `mod <ident> { .. }` gated by a test-only
    cfg, from that `#[cfg(..)]` attribute to the module's closing brace
    (other attributes between the two allowed)."""
    ranges = []
    search_start = 0
    while True:
        match = _CFG_ATTRIBUTE_RE.search(source, search_start)
        if match is None:
            return ranges
        cfg_start = match.start()
        open_bracket = source.index("[", cfg_start)
        close = attribute_close(source, open_bracket)
        if close is None:
            return ranges
        search_start = close + 1
        if not is_test_only_cfg(source[open_bracket + 1 : close]):
            continue
        header = inline_module_header(source, skip_outer_attributes(source, close + 1))
        if header is None:
            continue
        _, open_idx = header
        end = matching_brace_end(source, open_idx)
        if end is None:
            return ranges
        ranges.append((cfg_start, end))
        search_start = end


def mask_test_only_modules(source):
    out = list(source)
    for start, end in test_only_module_ranges(source):
        for i in range(start, end):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)


def production_source(raw):
    return mask_test_only_modules(strip_comments_and_literals(raw))


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
    __slots__ = ("parent", "targets", "test_only")

    def __init__(self, parent, targets, test_only):
        self.parent = parent
        self.targets = targets
        self.test_only = test_only


def external_mounts(sources):
    """`sources`: `[(relpath, raw_text), ..]`. Returns `(mounts,
    file_gated)`: every `mod <ident>;` (plain or `#[path = "..."]`)
    declaration outside comments/literals, in source order, and the set of
    files whose leading inner attributes hold a test-only cfg (rule 3; found
    here so each file is stripped once). A `#[path]` mount whose literal is
    not a simple relative `a/b.rs`-shaped string is kept with an empty target
    list (never resolved, never hides a file)."""
    mounts = []
    file_gated = set()
    for parent, raw in sources:
        clean = strip_comments_and_literals(raw)
        if file_gated_test_only(clean):
            file_gated.add(parent)
        blocks = inline_module_blocks(clean)
        test_blocks = test_only_module_ranges(clean)
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
                        test_only=inside_test_module
                        or (simple_nesting and attributes_gate_test_only(compact)),
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
                    # A test-only cfg beside the `#[path]` attribute gates
                    # this mount exactly as it gates a plain `mod x;`.
                    test_only=inside_test_module
                    or (simple_nesting and attributes_gate_test_only(compact)),
                )
            )
    return mounts, file_gated


def test_only_external_files(sources):
    """`sources`: `{relpath: raw_text}`. Files reached ONLY through a mount
    gated by a test-only cfg, directly or transitively, minus a
    production-mount veto; plus every file gated by its own inner test-only
    cfg (rule 3), which no production mount vetoes.

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
    mounts, file_gated = external_mounts(items)

    tests = set(file_gated)
    while True:
        before = len(tests)
        for mount in mounts:
            if mount.test_only or mount.parent in tests or test_only_by_path(mount.parent):
                for target in mount.targets:
                    if target in sources:
                        tests.add(target)
        if len(tests) == before:
            break

    # The veto, to a fixed point: a file a production file mounts without a
    # test-only cfg is production, and so is every file IT mounts that way. A
    # module mounted both as a test door and as production code is rescued
    # together with its ungated children. The walk stops at files gated by
    # their own inner cfg and at files the path rule excludes.
    production = set()
    while True:
        before = len(production)
        for mount in mounts:
            parent = mount.parent
            if (
                not mount.test_only
                and (parent not in tests or parent in production)
                and parent not in file_gated
                and not test_only_by_path(parent)
            ):
                production.update(mount.targets)
        if len(production) == before:
            break
    return (tests - production) | file_gated


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

    test_only_files = test_only_external_files(sources)

    def is_test(rel):
        return test_only_by_path(rel) or rel in test_only_files

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
