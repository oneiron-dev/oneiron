#!/usr/bin/env python3
"""Proof that a PLAN-UC-04 stage 7 content-hash PR is a pure swap: every changed .rs file of BASE..HEAD equals its BASE
text with some of its `blake3::hash(` calls replaced by `ContentHash::of(`, token for token.

`ContentHash::of` is plain BLAKE3 over the same bytes (crates/oneiron-fingerprint/tests/fingerprint_rules.rs,
content_hash_is_plain_blake3_and_never_a_fingerprint), so a file that passes keeps every digest it computes.

A swapped call must be used on the spot through `.as_bytes()` (`&[u8; 32]` from both types) or `.to_hex()` (the same 64
lowercase hex digits; blake3 gives an ArrayString, ContentHash a String). A result used as a bare value (held in a
`blake3::Hash` let, field, parameter or return, compared with one, or formatted with `{:?}`, whose text differs between
the two types) is a type change, not a swap, and fails here.

The comparison ignores:
  - whitespace between tokens (rustfmt may re-wrap a call that grew by 3 characters);
  - a comma right before `)`, `]` or `}` (rustfmt adds one when it splits a call over lines);
  - after a swapped call, the base's `.to_hex().to_string()` becoming `.to_hex()` (a second to_string would only clone).
`use` declarations are compared apart. The head may:
  - add `use oneiron_contracts::fingerprint::ContentHash;` (or `use oneiron_fingerprint::ContentHash;`);
  - add ContentHash, with no `as`, to an existing use of one of those two paths;
  - drop a use of blake3, or narrow it to a subset of its names.
Comments, string literals and every other token must be identical, and so must the argument of each swapped call.

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
CONTENT_PATHS = (["oneiron_contracts", "::", "fingerprint", "::"], ["oneiron_fingerprint", "::"])
PLAIN_IMPORTS = [["use", *path, "ContentHash", ";"] for path in CONTENT_PATHS]
TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<line_comment>//[^\n]*)
  | (?P<block_comment>/\*.*?\*/)
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
OPENERS = {"(", "[", "{"}
CLOSERS = {")", "]", "}"}
LIST_PUNCT = {",", "{", "}"}


class GitError(Exception):
    pass


def git(repo, *args):
    run = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if run.returncode:
        raise GitError(f"git {' '.join(args)} failed: {run.stderr.strip()[:300]}")
    return run.stdout


def tokens(text):
    out = [m.group(0) for m in TOKEN.finditer(text) if m.lastgroup != "ws"]
    # A comma right before a closer is rustfmt's choice, not the program's.
    return [t for i, t in enumerate(out) if not (t == "," and i + 1 < len(out) and out[i + 1] in CLOSERS)]


def split_uses(toks):
    """(body tokens, use declarations as token lists). A use declaration starts at `use` (with an optional `pub` or
    `pub(...)` before it) where an item can start, and ends at its `;`."""
    body, uses, i = [], [], 0
    while i < len(toks):
        j = i
        if toks[j] == "pub":
            j += 1
            if j < len(toks) and toks[j] == "(":
                while j < len(toks) and toks[j] != ")":
                    j += 1
                j += 1
        prev = i - 1
        while prev >= 0 and toks[prev].startswith(("//", "/*")):
            prev -= 1  # a comment (a `//!` module doc above the first use) does not end an item
        item_start = prev < 0 or toks[prev] in {";", "}", "{", "]"}
        if j < len(toks) and toks[j] == "use" and item_start:
            k = j
            while k < len(toks) and toks[k] != ";":
                k += 1
            uses.append(toks[i:k + 1])
            i = k + 1
            continue
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
        if base[i:i + 4] == OLD and head[j:j + 4] == NEW:
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
                raise ValueError(f"a swapped call's result is used as a value, not through .as_bytes() or .to_hex(): `{context}`")
            continue
        if i < len(base) and j < len(head) and base[i] == head[j]:
            i += 1
            j += 1
            continue
        context_b = " ".join(base[max(0, i - 8):i + 8])
        context_h = " ".join(head[max(0, j - 8):j + 8])
        raise ValueError(f"differs at base token {i} / head token {j}: base `{context_b}` head `{context_h}`")
    return swaps


def names(use):
    """The use's tokens without list punctuation, as a multiset."""
    return collections.Counter(t for t in use if t not in LIST_PUNCT)


def after_use(use):
    """The tokens after `use`."""
    return use[use.index("use") + 1:]


def content_path(use):
    rest = after_use(use)
    return use[0] == "use" and any(rest[:len(p)] == p for p in CONTENT_PATHS)


def check_uses(base_uses, head_uses):
    added = [u for u in head_uses if u not in base_uses]
    removed = [u for u in base_uses if u not in head_uses]
    matched = []
    for use in added:
        if use in PLAIN_IMPORTS:
            continue
        merged = [
            r for r in removed
            if content_path(use) and content_path(r)
            and names(use) - collections.Counter(["ContentHash"]) == names(r)
            and names(use)["ContentHash"] == names(r)["ContentHash"] + 1
        ]
        if merged:
            matched.append(merged[0])
            continue
        narrowed = [
            r for r in removed
            if after_use(use)[:1] == ["blake3"] and after_use(r)[:1] == ["blake3"] and use[0] == r[0]
            and not names(use) - names(r)
        ]
        if narrowed:
            matched.append(narrowed[0])
            continue
        raise ValueError(f"added use is not the ContentHash import or a narrowed blake3 use: `{' '.join(use)}`")
    for use in removed:
        if after_use(use)[:1] != ["blake3"] and not any(use is m for m in matched):
            raise ValueError(f"removed use does not name blake3: `{' '.join(use)}`")


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
                base_body, base_uses = split_uses(tokens(git(args.repo, "show", f"{args.base}:{path}")))
                head_body, head_uses = split_uses(tokens(git(args.repo, "show", f"{args.head}:{path}")))
                check_uses(base_uses, head_uses)
                swaps = compare(base_body, head_body)
                if swaps == 0:
                    raise ValueError("no swap in a changed file")
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
