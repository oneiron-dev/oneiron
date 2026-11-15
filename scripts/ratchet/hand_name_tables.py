#!/usr/bin/env python3
"""Ratchet metric 8, hand_name_tables: lists of names spelled by hand outside a Register.

A Register (Fable pass 25; `oneiron_contracts::register`) declares a closed list of names
once: a plain enum with `#[derive(Register)]` and `#[register("lower.dotted")]`. A hand
name table spells such a name a second time. Three shapes count, in .rs files under
crates/*/src with check.sh's file rule (no `tests` directory component; the name is not
tests.rs, *_tests.rs or tests_*.rs), outside what scripts/ratchet/hand_name_tables_allowlist.txt
lists:

  forward  a fn returning `&str` (any lifetime) with two or more arms `Type::Variant => "name"`
           (or `A | B => "name"`), the variants unit paths;
  reverse  a fn with two or more arms `"name" => Type::Variant`, bare or in `Some(` / `Ok(`,
           the variant a unit path (no `(` or `{` after it);
  list     a `const` array or slice whose every element is `Type::Variant`, two or more.

A table counts only when every string in it is name-shaped: 1 to 64 bytes of letters, digits
and `_ . : / -` (a table of labels or prose is not a name table). A table on a type that
derives `Register` in the same file is not counted: those are its fact columns. Comments and
the insides of string and char literals are blanked first, so neither starts a table.

It also refuses two Registers with one name: every `#[register("...")]` line is read, and a
repeated name exits 1 in every mode that counts.

The count only goes down: a new list of names is declared as a Register, and the conversions
lower baseline.json's count once per train (the Engine; adopting PRs never edit it). After the
gate goes live, the pipeline pre-flight runs `--check` on the PR merged into main, against
main's baseline.json.

Usage:
  hand_name_tables.py [TREE]                    the count and its three parts
  hand_name_tables.py --count [TREE]            the count alone (check.sh)
  hand_name_tables.py --list [TREE]             every counted table: path:line kind type fn arms
  hand_name_tables.py --names [--only PREFIX] [TREE]
      every row of every counted forward table: path:line, type, fn, variant, name (tab
      separated), the source of an adopting PR's generated names test
  hand_name_tables.py --report [TREE]           shapes the count leaves out, printed only: fns
      that dispatch on two or more name strings without building a variant, and const tables
      of ("name", value) pairs
  hand_name_tables.py --check [--baseline FILE] [TREE]
      the merge gate: exit 1 when the count is above the baseline's hand_name_tables count
      (default FILE: TREE/scripts/ratchet/baseline.json)

TREE defaults to the current directory. Exit 2, never a silent pass, on a missing tree, a
tree with no counted source file, an allowlist line without a reason, or an unreadable
baseline.
"""

import argparse
import json
import pathlib
import re
import sys

ALLOWLIST = "scripts/ratchet/hand_name_tables_allowlist.txt"
BASELINE = "scripts/ratchet/baseline.json"

# Comments, then the literals whose insides must not read as code. One pass, left to right, so a
# `//` inside a string and a `"` inside a comment are both seen for what they are. A nested block
# comment ends at its first `*/` (none is known to hold a table). The leading lookahead lets the
# engine skip to the next character that can start a lexeme (twice as fast, the same spans).
LEXEME = re.compile(
    r"""(?=[/"'br])
      (?:(?P<comment>//[^\n]*|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/)
      | b?r(?P<hashes>\#*)"(?P<raw>[\s\S]*?)"(?P=hashes)
      | "(?P<string>[^"\\]*(?:\\[\s\S][^"\\]*)*)"
      | '(?P<char>\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|[^\n])|[^'\\\n])')
    """,
    re.X,
)
# A file can hold a table only if it holds one of these. Three searches, not one alternation:
# each starts with a literal, which the engine finds fast (about ten times faster in all).
# The screen reads raw text, so a gap admits comments wherever the scan (which blanks them) admits
# white space: `Self::A => /* note */ "a"` is a forward arm.
GAP = r"(?:\s|//[^\n]*|/\*[\s\S]*?\*/)"
MAY_HOLD = (
    re.compile(r"=>" + GAP + r'*"'),
    re.compile(r'"' + GAP + r"*=>"),
    re.compile(
        r"const" + GAP + r"+\w+" + GAP + r"*:" + GAP + r"*&?" + GAP + r"*(?:'static" + GAP + r"+)?\["
    ),
)
NAME_SHAPED = re.compile(r"[A-Za-z0-9_.:/\-]{1,64}\Z")
# `Self` is one of the `[A-Z]\w*` words. Spelling it as its own alternative too made a long
# `Self::A | Self::B | ..` chain backtrack 2^n ways.
PATH = r"[A-Z]\w*::[A-Z]\w*"
# A forward arm is found from its arrow, `=> "name"`, and the chain of unit paths before it is read
# backwards (`chain_before`): a search led by a literal is fast, one led by `[A-Z]` is not.
FORWARD_ARROW = re.compile(r'=>\s*"(?P<name>[^"]*)"')
REVERSE_ARM = re.compile(
    r"\"(?P<name>[^\"]*)\"(?:\s*\|\s*\"[^\"]*\")*\s*=>\s*(?:Some\(|Ok\()?\s*"
    r"(?P<path>" + PATH + r")\b(?!\s*[({])"
)
# Any name arm, for --report: a reverse arm that builds no variant is a dispatch on names.
NAME_ARM = re.compile(r"\"(?P<name>[^\"]*)\"(?:\s*\|\s*\"[^\"]*\")*\s*=>")
LIST = re.compile(
    r"const\s+(?P<const>\w+)\s*:\s*(?:\[\s*(?P<array>[A-Z]\w*)\s*;[^\]]*\]"
    r"|&\s*(?:'static\s+)?\[\s*(?P<slice>[A-Z]\w*)\s*\])\s*=\s*&?\s*\["
)
LIST_ITEM = re.compile(r"\s*(?P<type>[A-Z]\w*)::[A-Z]\w*\s*\Z")
PAIR_TABLE = re.compile(r"\bconst\s+\w+\s*:\s*&?\s*(?:'static\s+)?\[\s*\(\s*&\s*(?:'\w+\s+)?str\b")
# No leading `\b` (it slows the search tenfold): `starts_word` checks the character before.
FN = re.compile(r"fn\s+(?P<fn>\w+)")
BODY_OR_END = re.compile(r"[{;]")
BRACKET = re.compile(r"[\[\]]")
RETURNS_STR = re.compile(r"->\s*&\s*(?:'\w+\s+)?str\b")
IMPL = re.compile(r"impl\b(?P<header>[^;{]*)\{")
ENUM = re.compile(r"\benum\s+(?P<enum>\w+)")
DERIVES_REGISTER = re.compile(r"\bderive\s*\([^)]*\bRegister\b")
REGISTER_NAME = re.compile(r'#\s*\[\s*register\s*\(\s*"')


def fail(message):
    print(f"hand_name_tables: ERROR: {message}", file=sys.stderr)
    sys.exit(2)


def counted_file(relative):
    """check.sh's rule: crates/<crate>/src/..., no tests dir, no test file name."""
    parts = relative.split("/")
    name = parts[-1]
    if len(parts) < 4 or parts[0] != "crates" or parts[2] != "src":
        return False
    return not (
        "tests" in parts[:-1]
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.startswith("tests_")
    )


def read_allowlist(tree):
    """Lines `<path>  # <reason>`; a path ending in / covers a directory."""
    path = tree / ALLOWLIST
    if not path.is_file():
        fail(f"{ALLOWLIST} is missing")
    entries = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        body, _, reason = line.partition("#")
        fields = body.split()
        if len(fields) != 1 or not reason.strip():
            fail(f"{ALLOWLIST}:{number}: want `<path>  # <reason>`: {line!r}")
        if not (tree / fields[0]).exists():
            print(f"hand_name_tables: stale allowlist entry {fields[0]}", file=sys.stderr)
        entries.append(fields[0])
    return entries


def allowed(relative, entries):
    return any(
        relative == entry or (entry.endswith("/") and relative.startswith(entry))
        for entry in entries
    )


def blanked(segment, fill):
    """The segment with every character but a newline replaced by `fill`."""
    if "\n" not in segment:
        return fill * len(segment)
    return "\n".join(fill * len(part) for part in segment.split("\n"))


def views(text):
    """`code`: comments blanked. `shape`: also the insides of literals. Same length, same lines."""
    code, shape, at = [], [], 0
    for match in LEXEME.finditer(text):
        start, end = match.span()
        kept = text[at:start]
        code.append(kept)
        shape.append(kept)
        kind = match.lastgroup
        if kind == "comment":
            blank = blanked(text[start:end], " ")
            code.append(blank)
            shape.append(blank)
        else:
            inner_start, inner_end = match.span(kind)
            code.append(text[start:end])
            shape.append(
                text[start:inner_start]
                + blanked(text[inner_start:inner_end], "x")
                + text[inner_end:end]
            )
        at = end
    code.append(text[at:])
    shape.append(text[at:])
    return "".join(code), "".join(shape)


def brace_pairs(shape):
    """Each `{` offset -> its matching `}` offset (end of file when unmatched)."""
    pairs, stack = {}, []
    for match in re.finditer(r"[{}]", shape):
        if match.group() == "{":
            stack.append(match.start())
        elif stack:
            pairs[stack.pop()] = match.start()
    for opened in stack:
        pairs[opened] = len(shape)
    return pairs


def impl_type(header):
    """The type an `impl ... {` header is for: `impl<T> Trait for Type<T> where ..` -> Type."""
    header = re.sub(r"\bwhere\b[\s\S]*", "", header)
    if re.search(r"\sfor\s", header):
        header = re.split(r"\sfor\s", header, maxsplit=1)[1]
    else:
        header = re.sub(r"^\s*<[^{]*?>(?=\s*[\w:])", "", header)
    match = re.search(r"([A-Za-z_]\w*)\s*(?:<[\s\S]*>)?\s*$", header.strip())
    return match.group(1) if match else "?"


def innermost(spans, positions):
    """For each sorted position, the innermost (start, end, item) span holding it, or None.

    The spans are brace-matched, so they nest; one sweep with a stack finds each owner."""
    spans = sorted(spans, key=lambda span: span[0])
    owners, stack, next_span = [], [], 0
    for position in positions:
        while next_span < len(spans) and spans[next_span][0] <= position:
            while stack and stack[-1][1] < spans[next_span][0]:
                stack.pop()
            stack.append(spans[next_span])
            next_span += 1
        while stack and stack[-1][1] < position:
            stack.pop()
        owners.append(stack[-1] if stack else None)
    return owners


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
SPACE = frozenset(" \t\r\n")


def starts_word(shape, at):
    """The match at `at` starts a word: what a leading `\b` would check."""
    return at == 0 or shape[at - 1] not in WORD


def word_start(shape, end):
    start = end
    while start > 0 and shape[start - 1] in WORD:
        start -= 1
    return start


def space_start(shape, end):
    while end > 0 and shape[end - 1] in SPACE:
        end -= 1
    return end


def is_upper_word(word):
    return bool(word) and "A" <= word[0] <= "Z"


def chain_before(shape, arrow):
    """The unit paths `A::B | C::D` that end just before an arrow, in order, as (type, variant).

    None when no unit path ends there. A chain stops at the first alternative that is not a unit
    path (`A::B(_) | A::C =>` gives [A::C]), as the forward regex it replaces did."""
    chain, at = [], arrow
    while True:
        at = space_start(shape, at)
        variant_start = word_start(shape, at)
        variant = shape[variant_start:at]
        type_end = variant_start - 2
        type_start = word_start(shape, type_end) if type_end >= 0 else 0
        path_type = shape[type_start:type_end] if type_end >= 0 else ""
        if not (
            is_upper_word(variant)
            and shape[type_end:variant_start] == "::"
            and is_upper_word(path_type)
        ):
            break
        chain.append((path_type, variant))
        at = space_start(shape, type_start)
        if at == 0 or shape[at - 1] != "|":
            break
        at -= 1
    return chain[::-1] or None


class Source:
    """One file's two views, its brace pairs, its impl blocks and its fn bodies."""

    def __init__(self, text):
        self.text = text
        self.code, self.shape = views(text)
        pairs = brace_pairs(self.shape)
        self.impls = []
        for match in IMPL.finditer(self.shape):
            if not starts_word(self.shape, match.start()):
                continue
            opened = match.end() - 1
            header = self.code[match.start("header") : opened]
            self.impls.append((opened, pairs[opened], impl_type(header)))
        self.fns = []
        for match in FN.finditer(self.shape):
            if not starts_word(self.shape, match.start()):
                continue
            body = BODY_OR_END.search(self.shape, match.end())
            if body is None or body.group() == ";":
                continue
            opened = body.start()
            returns_str = bool(RETURNS_STR.search(self.code[match.end() : opened]))
            self.fns.append((opened, pairs[opened], (match.group("fn"), match.start(), returns_str)))

    def literals(self, start, end):
        """The contents of the string literals between two offsets, as written."""
        return [
            self.code[start + match.start(1) : start + match.end(1)]
            for match in re.finditer(r'"([^"]*)"', self.shape[start:end])
        ]

    def type_of(self, path_type, position):
        """`Self` is the type of the innermost impl block around the position."""
        if path_type != "Self":
            return path_type
        owner = innermost(self.impls, [position])[0]
        return owner[2] if owner else "?"

    def arms_by_fn(self, pattern, keep=lambda match: True):
        """Each fn's kept matches of the pattern, each with what `keep` gave for it; a match
        belongs to the innermost fn around it."""
        kept = [(match, held) for match in pattern.finditer(self.shape) if (held := keep(match))]
        owners = innermost(self.fns, [match.start() for match, _ in kept])
        grouped = {}
        for (match, held), owner in zip(kept, owners):
            if owner is not None:
                grouped.setdefault(owner[2], []).append((match, held))
        return grouped

    def registers(self):
        """The enums of this file that derive Register."""
        found = set()
        for match in ENUM.finditer(self.shape):
            item_start = max(self.shape.rfind(mark, 0, match.start()) for mark in ";{}")
            # The shape view: a string such as `#[doc = "derive(Register)"]` is not a derive.
            if DERIVES_REGISTER.search(self.shape[item_start + 1 : match.start()]):
                found.add(match.group("enum"))
        return found

    def register_names(self):
        """(name, line) of every `#[register("...")]`."""
        names = []
        for match in REGISTER_NAME.finditer(self.shape):
            closing = self.shape.find('"', match.end())
            names.append((self.code[match.end() : closing], line_of(self.text, match.start())))
        return names


def scan(text, with_report=False):
    """The tables, report shapes (only when asked) and Register names of one file's text."""
    source = Source(text)
    shape, code = source.shape, source.code
    registers = source.registers() if "Register" in text else set()
    tables, report = [], []

    forward = source.arms_by_fn(FORWARD_ARROW, lambda match: chain_before(shape, match.start()))
    for (fn, fn_at, returns_str), arms in forward.items():
        names = [code[match.start("name") : match.end("name")] for match, _ in arms]
        if not returns_str or len(arms) < 2 or not all(NAME_SHAPED.match(n) for n in names):
            continue
        rows = []
        for (match, chain), name in zip(arms, names):
            for path_type, variant in chain:
                rows.append((source.type_of(path_type, match.start()), variant, name))
        if rows[0][0] in registers:
            continue
        tables.append(("forward", line_of(text, fn_at), rows[0][0], fn, len(arms), rows))

    for (fn, fn_at, _), held in source.arms_by_fn(REVERSE_ARM).items():
        arms = [match for match, _ in held]
        names = [n for match in arms for n in source.literals(match.start(), match.start("path"))]
        if len(arms) < 2 or not all(NAME_SHAPED.match(n) for n in names):
            continue
        first = arms[0]
        table_type = source.type_of(first.group("path").split("::")[0], first.start())
        if table_type in registers:
            continue
        tables.append(("reverse", line_of(text, fn_at), table_type, fn, len(arms), None))

    for match in LIST.finditer(shape):
        if not starts_word(shape, match.start()):
            continue
        opened, depth, closed = match.end() - 1, 0, len(shape)
        for bracket in BRACKET.finditer(shape, opened):
            depth += 1 if bracket.group() == "[" else -1
            if depth == 0:
                closed = bracket.start()
                break
        items = [item for item in code[opened + 1 : closed].split(",") if item.strip()]
        if len(items) < 2 or not all(LIST_ITEM.match(item) for item in items):
            continue
        path_type = match.group("array") or match.group("slice")
        if path_type == "Self":
            path_type = LIST_ITEM.match(items[0]).group("type")
        table_type = source.type_of(path_type, match.start())
        if table_type in registers:
            continue
        tables.append(("list", line_of(text, match.start()), table_type, match.group("const"), len(items), None))

    if not with_report:
        return tables, report, source.register_names() if "register" in text else []
    for (fn, fn_at, _), held in source.arms_by_fn(NAME_ARM).items():
        arms = [match for match, _ in held]
        building = sum(1 for _ in REVERSE_ARM.finditer(shape, arms[0].start(), arms[-1].end()))
        shaped = [m for m in arms if NAME_SHAPED.match(code[m.start("name") : m.end("name")])]
        if len(shaped) >= 2 and building == 0:
            report.append(("name-dispatch", line_of(text, fn_at), fn, len(shaped)))
    for match in PAIR_TABLE.finditer(shape):
        report.append(("pair-table", line_of(text, match.start()), "const", 0))
    return tables, report, source.register_names() if "register" in text else []


def may_hold(text):
    """A cheap screen: a file without these substrings holds no table and no Register name."""
    if "register" in text:
        return True
    return any(screen.search(text) for screen in MAY_HOLD)


def walk(tree, with_report=False):
    """(relative path, tables, report, register names) for every counted file."""
    entries = read_allowlist(tree)
    scanned = 0
    results = []
    for source in sorted((tree / "crates").glob("*/src/**/*.rs")):
        relative = source.relative_to(tree).as_posix()
        if not counted_file(relative) or allowed(relative, entries):
            continue
        scanned += 1
        text = source.read_text(errors="replace")
        if not may_hold(text):
            continue
        tables, report, names = scan(text, with_report)
        if tables or report or names:
            results.append((relative, tables, report, names))
    if scanned == 0:
        # A count of 0 is the goal; a tree with no source to count is not that.
        fail(f"no counted .rs file under {tree}/crates/*/src: not an engine tree")
    return results


def refuse_repeated_registers(results):
    """Exit 1 when two `#[register("...")]` lines give one name (pass 23, C1)."""
    seen = {}
    repeats = []
    for relative, _, _, names in results:
        for name, line in names:
            if name in seen:
                repeats.append(f"{name}: {seen[name]} and {relative}:{line}")
            else:
                seen[name] = f"{relative}:{line}"
    if repeats:
        for repeat in repeats:
            print(f"HAND-NAME-TABLES-FAIL two Registers named {repeat}")
        sys.exit(1)


def baseline_count(path):
    try:
        metrics = json.loads(path.read_text())["metrics"]
        count = metrics["hand_name_tables"]["count"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        fail(f"cannot read the hand_name_tables count from {path}: {error}")
    if not isinstance(count, int) or count < 0:
        fail(f"{path}: hand_name_tables count is not a non-negative integer")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--count", action="store_true")
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--names", action="store_true")
    mode.add_argument("--report", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--only", default="", help="--names: only paths starting with this")
    parser.add_argument("tree", nargs="?", default=".", type=pathlib.Path)
    args = parser.parse_args()
    tree = args.tree.resolve()
    if not (tree / "crates").is_dir():
        fail(f"{tree} has no crates/ directory")
    results = walk(tree, with_report=args.report)
    tables = [(relative, *table) for relative, found, _, _ in results for table in found]
    if args.list:
        for relative, kind, line, table_type, fn, arms, _ in tables:
            print(f"{relative}:{line}\t{kind}\t{table_type}\t{fn}\t{arms}")
        return
    if args.names:
        for relative, kind, line, table_type, fn, _, rows in tables:
            if kind != "forward" or not relative.startswith(args.only):
                continue
            for row_type, variant, name in rows:
                print(f"{relative}:{line}\t{row_type}\t{fn}\t{variant}\t{name}")
        return
    if args.report:
        for relative, _, report, _ in results:
            for kind, line, fn, arms in report:
                print(f"{relative}:{line}\t{kind}\t{fn}\t{arms}")
        return
    refuse_repeated_registers(results)
    if args.count:
        print(len(tables))
    elif args.check:
        baseline = baseline_count(args.baseline or tree / BASELINE)
        if len(tables) > baseline:
            print(
                f"HAND-NAME-TABLES-FAIL {len(tables)} > baseline {baseline} "
                f"(+{len(tables) - baseline}): a new list of names is declared as a Register "
                "(#[derive(Register)], oneiron_contracts::register); --list prints every table"
            )
            sys.exit(1)
        print(f"hand_name_tables ok: {len(tables)} <= baseline {baseline}")
    else:
        kinds = {kind: sum(1 for table in tables if table[1] == kind) for kind in ("forward", "reverse", "list")}
        print(f"hand_name_tables: {len(tables)}")
        print("  " + "  ".join(f"{kind} {count}" for kind, count in kinds.items()))


if __name__ == "__main__":
    main()
