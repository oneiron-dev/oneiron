#!/usr/bin/env python3
"""Proof that a PLAN-UC-04 stage 7 content-hash PR is a pure swap: every changed .rs file of BASE..HEAD equals its BASE
text with some of its `blake3::hash(` calls replaced by `ContentHash::of(`, token for token.

`ContentHash::of` is plain BLAKE3 over the same bytes (crates/oneiron-fingerprint/tests/fingerprint_rules.rs,
content_hash_is_plain_blake3_and_never_a_fingerprint), so a file that passes keeps every digest it computes.

A swapped call must be used on the spot through `.as_bytes()` (`&[u8; 32]` from both types) or `.to_hex()` (the same 64
lowercase hex digits; blake3 gives an ArrayString, ContentHash a String). A result used as a bare value (held in a
`blake3::Hash` let, field, parameter or return, compared with one, or formatted with `{:?}`, whose text differs between
the two types) is a type change, not a swap, and fails here. A call with a path before it (`x::blake3::hash(`) is not
swapped.

`ContentHash` must name the oneiron type in the head: its module-level uses import it from
oneiron_contracts::fingerprint or oneiron_fingerprint, with no `as`. When the base lacks that import, the base holds no
`ContentHash` token at all (the new import must not re-point a name that an item or a glob import gave); when the base
has it, every other `ContentHash` in the base starts a `ContentHash::of(` call. Not checked: a glob import inside a
block or an inline module that gives another `ContentHash` with an `of` function.

The comparison ignores:
  - whitespace between tokens (rustfmt may re-wrap a call that grew by 3 characters);
  - a comma right before `)`, `]` or `}` where Rust reads the list the same without it (rustfmt adds one when it splits
    a call over lines). The comma is compared exactly inside a macro call, a `macro_rules!` body or an attribute (a
    macro arm can match on it; rustfmt keeps a macro call's comma as written), and in a one-element `(...)` that is no
    call's argument list (`(x,)` is a tuple, `(x)` is x);
  - after a swapped call, the base's `.to_hex().to_string()` becoming `.to_hex()` (a second to_string would only clone).
Module-level `use` declarations are compared apart; a `use` inside a block, or right after an attribute or an outer doc
comment, is body. The head may:
  - add `use oneiron_contracts::fingerprint::ContentHash;` (or `use oneiron_fingerprint::ContentHash;`);
  - add `ContentHash` as a new list element to an existing use of one of those two paths, with the same visibility;
  - drop a use of blake3, or some elements of its list, when no name the dropped part bound is still used unqualified
    in the head file.
Comments (nested block comments too), string literals and every other token must be identical, and so must the argument
of each swapped call.

Reads git objects only; builds and runs nothing.

Usage:
  check_content_hash_swap.py [--repo DIR] [--allow-other PATH ...] BASE HEAD
      --repo         the git repository (default: the current directory)
      --allow-other  a changed file that is not a swap file (scripts/ratchet/baseline.json, this script); it is listed,
                     not checked
Prints `SWAP <n> <path>`, `OTHER <path>` or `FAIL <path>: <reason>` per changed file, then a TOTAL line.
Exit 0 = every checked file is a pure swap; 1 = a file is not; 2 = a usage or git error.
"""

import argparse
import collections
import re
import subprocess
import sys

OLD = ["blake3", "::", "hash", "("]
NEW = ["ContentHash", "::", "of", "("]
AS_BYTES = [".", "as_bytes", "(", ")"]
TO_HEX = [".", "to_hex", "(", ")"]
TO_STRING = [".", "to_string", "(", ")"]
CONTENT_PATHS = (("oneiron_contracts", "::", "fingerprint", "::"), ("oneiron_fingerprint", "::"))
CONTENT_HASH_ELEMENT = ("ContentHash",)
TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<line_comment>//[^\n]*)
  | (?P<raw_string>b?r(?P<hashes>\#*)".*?"(?P=hashes))
  | (?P<string>b?"(?:\\.|[^"\\])*")
  | (?P<char>b?'(?:\\.|[^'\\])'(?![A-Za-z_]))
  | (?P<lifetime>'[A-Za-z_]\w*)
  | (?P<ident>[A-Za-z_]\w*)
  | (?P<number>\d[\w.]*)
  | (?P<path>::)
  | (?P<punct>.)
    """,
    re.S | re.X,
)
IDENT = re.compile(r"[A-Za-z_]\w*")
# Words after which `(` opens no call's argument list (`return (x,)` returns a tuple).
KEYWORDS = frozenset(
    "as async await box break const continue dyn else enum extern false fn for if impl in let loop match mod move mut"
    " pub ref return static struct trait true type unsafe use where while yield".split()
)
OPENERS = {"(", "[", "{"}
CLOSERS = {")", "]", "}"}


class GitError(Exception):
    pass


def git(repo, *args):
    run = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if run.returncode:
        raise GitError(f"git {' '.join(args)} failed: {run.stderr.strip()[:300]}")
    return run.stdout


def block_comment_end(text, start):
    """Index just past the block comment that opens at text[start]; Rust block comments nest."""
    depth, k = 0, start
    while k < len(text):
        if text.startswith("/*", k):
            depth, k = depth + 1, k + 2
        elif text.startswith("*/", k):
            depth, k = depth - 1, k + 2
            if depth == 0:
                return k
        else:
            k += 1
    raise ValueError("unclosed block comment")


def lex(text):
    out, pos = [], 0
    while pos < len(text):
        if text.startswith("/*", pos):
            end = block_comment_end(text, pos)
            out.append(text[pos:end])
            pos = end
            continue
        match = TOKEN.match(text, pos)
        if match.lastgroup != "ws":
            out.append(match.group(0))
        pos = match.end()
    return out


def tokens(text):
    """The file's tokens without whitespace and without each comma before a closer that Rust reads the same without."""
    raw = lex(text)
    free, groups = set(), []
    for i, tok in enumerate(raw):
        prev = raw[i - 1] if i else ""
        if tok in OPENERS:
            exact = (
                bool(groups and groups[-1]["exact"])
                or prev == "!"  # a macro call, an inner attribute `#![`, or a negated group
                or (tok == "[" and prev == "#")
                or (i >= 3 and raw[i - 2] == "!" and raw[i - 3] == "macro_rules")
            )
            call = tok == "(" and (prev == ")" or (IDENT.fullmatch(prev) is not None and prev not in KEYWORDS))
            groups.append({"exact": exact, "tuple_like": tok == "(" and not call, "commas": 0, "trailing": None})
        elif tok in CLOSERS:
            if groups:
                group = groups.pop()
                one_element_tuple = group["tuple_like"] and group["commas"] == 1
                if group["trailing"] is not None and not group["exact"] and not one_element_tuple:
                    free.add(group["trailing"])
        elif tok == "," and groups:
            groups[-1]["commas"] += 1
            if i + 1 < len(raw) and raw[i + 1] in CLOSERS:
                groups[-1]["trailing"] = i
    return [tok for i, tok in enumerate(raw) if i not in free]


def skippable_comment(tok):
    """A plain comment or an inner doc (`//!`, `/*!`): it does not belong to the item after it. An outer doc does."""
    if tok.startswith("//"):
        return not (tok.startswith("///") and not tok.startswith("////"))
    if tok.startswith("/*"):
        return not (tok.startswith("/**") and not tok.startswith(("/***", "/**/")))
    return False


def split_uses(toks):
    """(body tokens, use declarations as token lists). A use declaration starts at `use` (with an optional `pub` or
    `pub(...)` before it) where a module-level item can start: outside every bracket, after `;` or `}` or at the top,
    with only plain comments in between. It ends at its `;`."""
    body, uses, depth, i = [], [], 0, 0
    while i < len(toks):
        if depth == 0:
            prev = i - 1
            while prev >= 0 and skippable_comment(toks[prev]):
                prev -= 1
            j = i
            if toks[j] == "pub":
                j += 1
                if j < len(toks) and toks[j] == "(":
                    while j < len(toks) and toks[j] != ")":
                        j += 1
                    j += 1
            if j < len(toks) and toks[j] == "use" and (prev < 0 or toks[prev] in {";", "}"}):
                k = j
                while k < len(toks) and toks[k] != ";":
                    k += 1
                uses.append(toks[i:k + 1])
                i = k + 1
                continue
        if toks[i] in OPENERS:
            depth += 1
        elif toks[i] in CLOSERS:
            depth -= 1
        body.append(toks[i])
        i += 1
    return body, uses


def call_end(toks, i):
    """Index just past the `)` that closes the call whose `(` is toks[i], or -1."""
    depth = 0
    for k in range(i, len(toks)):
        if toks[k] in OPENERS:
            depth += 1
        elif toks[k] in CLOSERS:
            depth -= 1
            if depth == 0:
                return k + 1
    return -1


def compare(base, head):
    """The number of swaps that turn `base` into `head`; ValueError at the first other difference."""
    i = j = swaps = 0
    while i < len(base) or j < len(head):
        if base[i:i + 4] == OLD and head[j:j + 4] == NEW and (i == 0 or base[i - 1] != "::"):
            b_end = call_end(base, i + 3)
            h_end = call_end(head, j + 3)
            if b_end < 0 or h_end < 0:
                raise ValueError(f"unclosed call at base token {i}")
            # The argument must match token for token; a swap nested in it counts too.
            swaps += 1 + compare(base[i + 4:b_end - 1], head[j + 4:h_end - 1])
            i, j = b_end, h_end
            if base[i:i + 8] == TO_HEX + TO_STRING and head[j:j + 4] == TO_HEX and head[j + 4:j + 8] != TO_STRING:
                i, j = i + 8, j + 4
                continue
            if base[i:i + 4] not in (AS_BYTES, TO_HEX):
                context = " ".join(base[max(0, i - 8):i + 8])
                raise ValueError(
                    f"a swapped call's result is used as a value, not through .as_bytes() or .to_hex(): `{context}`"
                )
            continue
        if i < len(base) and j < len(head) and base[i] == head[j]:
            i += 1
            j += 1
            continue
        context_b = " ".join(base[max(0, i - 8):i + 8])
        context_h = " ".join(head[max(0, j - 8):j + 8])
        raise ValueError(f"differs at base token {i} / head token {j}: base `{context_b}` head `{context_h}`")
    return swaps


def parse_use(use):
    """(visibility, path prefix, list elements as a multiset) of a use declaration:
    `pub(crate) use a::b::{C, D as E};` -> (pub ( crate ), a :: b ::, {(C), (D as E)});
    `use a::C;` -> ((), a ::, {(C)})."""
    k = use.index("use")
    visibility, tree = tuple(use[:k]), use[k + 1:-1]
    if tree and tree[-1] == "}":
        depth, opener = 0, 0
        for opener in range(len(tree) - 1, -1, -1):
            depth += (tree[opener] == "}") - (tree[opener] == "{")
            if depth == 0:
                break
        prefix, elements, element, depth = tree[:opener], [], [], 0
        for tok in tree[opener + 1:-1]:
            if tok == "," and depth == 0:
                elements.append(tuple(element))
                element = []
                continue
            depth += (tok in OPENERS) - (tok in CLOSERS)
            element.append(tok)
        if element:
            elements.append(tuple(element))
    else:
        cut = max((n + 1 for n, tok in enumerate(tree) if tok == "::"), default=0)
        prefix, elements = tree[:cut], [tuple(tree[cut:])]
    return visibility, tuple(prefix), collections.Counter(elements)


def imports_content_hash(parsed):
    _, prefix, elements = parsed
    return prefix in CONTENT_PATHS and elements[CONTENT_HASH_ELEMENT] > 0


def is_blake3(parsed):
    _, prefix, elements = parsed
    return prefix[:1] == ("blake3",) or (prefix == () and all(e[:1] == ("blake3",) for e in elements))


def unqualified_names(toks):
    """Identifiers of `toks` not written after `::` or `.` (a path segment or a field names no imported item)."""
    return {tok for n, tok in enumerate(toks) if IDENT.fullmatch(tok) and (n == 0 or toks[n - 1] not in {"::", "."})}


def check_dropped(prefix, dropped, head_names):
    for element in dropped.elements():
        if "*" in element:
            raise ValueError(f"a dropped blake3 glob import: `{' '.join(prefix + element)}`")
        bound = {tok for tok in element if IDENT.fullmatch(tok)} - {"as", "self", "_"}
        if "self" in element and len(prefix) >= 2:
            bound.add(prefix[-2])
        still = sorted(bound & head_names)
        if still:
            raise ValueError(f"a dropped blake3 import still names {', '.join(still)} in the head")


def check_uses(base_uses, head_uses, head_names):
    unmatched = [parse_use(u) for u in base_uses]
    added = []
    for parsed in map(parse_use, head_uses):
        if parsed in unmatched:
            unmatched.remove(parsed)
        else:
            added.append(parsed)
    one_content_hash = collections.Counter([CONTENT_HASH_ELEMENT])
    for visibility, prefix, elements in added:
        if visibility == () and prefix in CONTENT_PATHS and elements == one_content_hash:
            continue
        same_head = [r for r in unmatched if r[0] == visibility and r[1] == prefix]
        merged = [r for r in same_head if prefix in CONTENT_PATHS and elements == r[2] + one_content_hash]
        if merged:
            unmatched.remove(merged[0])
            continue
        narrowed = [r for r in same_head if is_blake3(r) and not elements - r[2] and elements != r[2]]
        if narrowed:
            unmatched.remove(narrowed[0])
            check_dropped(prefix, narrowed[0][2] - elements, head_names)
            continue
        written = " ".join(visibility + ("use",) + prefix)
        raise ValueError(f"added use is not the ContentHash import or a narrowed blake3 use: `{written}...`")
    for visibility, prefix, elements in unmatched:
        if not is_blake3((visibility, prefix, elements)):
            written = " ".join(visibility + ("use",) + prefix)
            raise ValueError(f"removed use does not name blake3: `{written}...`")
        check_dropped(prefix, elements, head_names)


def check_content_hash_name(base_body, base_uses, head_uses):
    """The head's `ContentHash` is the one its import names, as the module doc says."""
    if not any(imports_content_hash(parse_use(u)) for u in head_uses):
        raise ValueError(
            "the head imports no ContentHash from oneiron_contracts::fingerprint or oneiron_fingerprint at module level"
        )
    base_imported = [u for u in base_uses if imports_content_hash(parse_use(u))]
    if any("ContentHash" in u for u in base_uses if u not in base_imported):
        raise ValueError("a base use names ContentHash other than the plain import")
    for n, tok in enumerate(base_body):
        if tok == "ContentHash" and not (base_imported and base_body[n:n + 4] == NEW):
            raise ValueError("the base names ContentHash other than in a ContentHash::of( call under the import")


def check_file(base_text, head_text):
    """The number of swaps in a pure swap file; ValueError otherwise."""
    base_body, base_uses = split_uses(tokens(base_text))
    head_toks = tokens(head_text)
    head_body, head_uses = split_uses(head_toks)
    check_uses(base_uses, head_uses, unqualified_names(head_toks))
    swaps = compare(base_body, head_body)
    if swaps == 0:
        raise ValueError("no swap in a changed file")
    check_content_hash_name(base_body, base_uses, head_uses)
    return swaps


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--allow-other", action="append", default=[], metavar="PATH")
    parser.add_argument("base")
    parser.add_argument("head")
    args = parser.parse_args()
    allowed = set(args.allow_other)
    try:
        changed = [p for p in git(args.repo, "diff", "--name-only", f"{args.base}..{args.head}").splitlines() if p]
        if not changed:
            print(f"no changed file between {args.base} and {args.head}")
            return 2
        total = failed = 0
        for path in changed:
            if path in allowed:
                print(f"OTHER {path}")
                continue
            if not path.endswith(".rs"):
                print(f"FAIL {path}: not a .rs file and not --allow-other")
                failed += 1
                continue
            try:
                base_text = git(args.repo, "show", f"{args.base}:{path}")
                swaps = check_file(base_text, git(args.repo, "show", f"{args.head}:{path}"))
                print(f"SWAP {swaps} {path}")
                total += swaps
            except ValueError as error:
                print(f"FAIL {path}: {error}")
                failed += 1
    except GitError as error:
        print(error)
        return 2
    print(f"TOTAL swaps={total} files={len(changed)} failed={failed} base={args.base} head={args.head}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
