#!/usr/bin/env python3
"""Ratchet metrics 9-13, test_lint_*: sleeps, wall-clock reads, network, fixed ports and real
models in test code (Fable's test-strategy verdict, sections 3 and 4).

It reads Rust test code under crates/ and apps/: every file under a `tests` directory, every
tests.rs, *_tests.rs and *_test.rs, every file gated by an inner `#![cfg(test)]`, and the item
after each `#[cfg(test)]`-style attribute in any other file. Directories named target, vendor,
node_modules, .git and fixtures-out, and the vendored crates/heed, crates/paste and crates/loro,
are skipped. Each rule looks for plain text patterns outside comments; sleep and wall-clock read
code only, the others also read string literals:

  sleep        `sleep(`, `sleep_until(`, `sleep_ms(` called as a function (not a method, not a
               definition). Wait on a barrier, a channel or the fake clock instead.
  wall-clock   `SystemTime::now`, `Instant::now`, `Utc::now`, `Local::now`,
               `OffsetDateTime::now_utc`. Use oneiron_testkit::clock::FakeClock.
  network      an http(s)/ws(s) URL to a host other than loopback, a reserved test name
               (example.com/.org/.net, .test, .example, .invalid, .localhost) or a host whose
               URIs are names only (XML namespaces and JSON schema dialects).
  fixed-port   a fixed loopback port (`127.0.0.1:8080`). Bind port 0.
  real-model   provider API key names, provider hosts, model files (.gguf, .safetensors, .onnx)
               and local model servers. Use ScriptedProvider and HashingEmbedder.

One line may opt out, with a reason, by carrying (or following a comment line that carries)
`testkit-lint: allow(<rule>[, <rule>]) <reason>`. An allow with no reason allows nothing.

Each rule is one metric, test_lint_<rule> with `-` as `_`, whose bar is its count in
scripts/ratchet/baseline.json. The count blocks no merge: the merge pipeline counts each change
and reports a raise to its author (AGENTS.md, Ratchets), who lowers it in a follow-up PR or
allows the line with its reason. A count may fall; moving a file moves its findings and changes
no count. This file replaces the Rust lint that oneiron-testkit ran only in the nightly; its
rules, allow mark and per-file baseline text are that lint's, byte for byte.

Usage:
  test_lint.py [TREE]                     the five counts with their names
  test_lint.py --count [TREE]             the five counts on one line, in the order above (check.sh)
  test_lint.py --list [--rule R] [TREE]   every finding, as path:line: rule: text (ratchet_gate.py)
  test_lint.py --baseline [TREE]          the per-file baseline text: `<rule> <total>` lines, then
                                          `<rule> <path> <count>` lines (sorted by rule, then path)

TREE defaults to the current directory. Exit 2, never a silent pass, on a missing tree or a tree
with no .rs file under crates/ or apps/.
"""

import argparse
import os
import re
import sys

RULES = ("sleep", "wall-clock", "network", "fixed-port", "real-model")

SLEEP_CALLS = ("sleep(", "sleep_until(", "sleep_ms(")
WALL_CLOCK_CALLS = ("SystemTime::now", "Instant::now", "Utc::now", "Local::now", "OffsetDateTime::now_utc")
MODEL_KEYS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
)
MODEL_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "huggingface.co",
    "api.together.xyz",
    "api.groq.com",
    "api.mistral.ai",
)
MODEL_FILES = (".gguf", ".safetensors", ".onnx")
MODEL_SERVERS = ("ollama", "llama-server", ":11434")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0")
# The hosts a fixed port is looked for after (`<host>:<port>`).
PORT_HOSTS = ("127.0.0.1", "localhost", "[::1]", "0.0.0.0")
RESERVED_SUFFIXES = ("example.com", "example.org", "example.net", ".test", ".example", ".invalid", ".localhost")
# Hosts whose URIs are names, not addresses: XML namespaces and schema dialects (`xmlns`,
# `$schema`), which a parser compares as text and no client fetches.
IDENTIFIER_HOSTS = (
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "schemas.xmlsoap.org",
    "json-schema.org",
    "www.w3.org",
    "purl.org",
)
SCHEMES = ("http://", "https://", "ws://", "wss://")
ALLOW_MARK = "testkit-lint: allow("
SKIPPED_DIRS = ("target", "vendor", "node_modules", ".git", "fixtures-out")
SKIPPED_CRATES = ("crates/heed", "crates/paste", "crates/loro")
# Characters an authority stops at.
AUTHORITY_END = frozenset("/\"'?# \\)`")
# Rust's char::is_whitespace (Unicode White_Space): what Rust's trim() removes.
RUST_WHITESPACE = "\t\n\x0b\x0c\r \x85\xa0 " + "".join(map(chr, range(0x2000, 0x200B))) + "    　"
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

CODE, STR, COMMENT = 0, 1, 2
# The bytes a lexical class can change at: a comment opening, a string or raw string opening
# (`r` then `#`* then `"`), and a quote. Every other byte is code.
LEXICAL_START = re.compile(rb'//|/\*|"|r#*"|\'')
# A text every rule needs on its line: `sleep` (each sleep call), `::now` (each wall-clock call),
# `://` (each URL), `<host>:` (each fixed port), and each model key, file and server name. None
# holds a space, so each one a rule matches in a line's code or code-and-strings text, where
# only spaces replace characters, is in the raw line too.
CANDIDATE = re.compile(
    b"|".join(
        re.escape(text.encode())
        for text in ("sleep", "::now", "://", *(host + ":" for host in PORT_HOSTS), *MODEL_KEYS, *MODEL_FILES, *MODEL_SERVERS)
    )
)
BLOCK_COMMENT_TOKEN = re.compile(rb"/\*|\*/")
STRING_TOKEN = re.compile(rb'[\\"]')


def is_ident_byte(byte):
    return 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122 or byte == 95


def is_ident_char(ch):
    return ch.isascii() and (ch.isalnum() or ch == "_")


def find_all(text, pattern):
    """The start of every non-overlapping match of `pattern`, left to right (Rust's match_indices)."""
    at = text.find(pattern)
    while at != -1:
        yield at
        at = text.find(pattern, at + len(pattern))


def classify(data):
    """The lexical class of every byte: code, string literal (quotes included) or comment.
    Good enough for test code; not a Rust parser."""
    size = len(data)
    classes = bytearray(size)
    i = 0
    while i < size:
        match = LEXICAL_START.search(data, i)
        if match is None:
            break
        start = match.start()
        first = data[start]
        cls, end = CODE, start + 1
        if first == 0x2F:  # `/`
            if data[start + 1] == 0x2F:
                newline = data.find(b"\n", start)
                cls, end = COMMENT, size if newline == -1 else newline
            else:
                cls, end = COMMENT, block_comment_end(data, start)
        elif first == 0x22:  # `"`
            cls, end = STR, string_end(data, start)
        elif first == 0x72:  # `r`
            if (
                start == 0
                or not is_ident_byte(data[start - 1])
                or (data[start - 1] == 0x62 and (start < 2 or not is_ident_byte(data[start - 2])))
            ):
                hashes = match.end() - start - 2
                cls, end = STR, raw_string_end(data, start + 1 + hashes, hashes)
        else:  # `'`
            close = char_literal_end(data, start)
            if close is not None:
                cls, end = STR, close
        end = min(max(end, start + 1), size)
        if cls != CODE:
            classes[start:end] = bytes((cls,)) * (end - start)
        i = end
    return classes


def block_comment_end(data, start):
    depth = 0
    for token in BLOCK_COMMENT_TOKEN.finditer(data, start):
        if token.group() == b"/*":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return token.end()
    return len(data)


def string_end(data, start):
    i = start + 1
    while True:
        token = STRING_TOKEN.search(data, i)
        if token is None:
            return len(data)
        if data[token.start()] == 0x5C:  # a backslash skips the byte after it
            i = token.start() + 2
        else:
            return token.start() + 1


def raw_string_end(data, quote, hashes):
    close = data.find(b'"' + b"#" * hashes, quote + 1)
    return len(data) if close == -1 else close + 1 + hashes


def char_literal_end(data, start):
    """The end of a char literal opening at `start`; None for a lifetime."""
    size = len(data)
    if start + 1 < size and data[start + 1] == 0x5C:
        # The escaped character itself may be a quote, so the closing quote is searched after it.
        if start + 3 > size:
            return None
        close = data.find(b"'", start + 3)
        return None if close == -1 else close + 1
    if start + 1 >= size:
        return None
    first = data[start + 1]
    width = 1 if first <= 0x7F else 2 if 0xC0 <= first <= 0xDF else 3 if 0xE0 <= first <= 0xEF else 4
    return start + 2 + width if start + 1 + width < size and data[start + 1 + width] == 0x27 else None


def whole_file_is_test(path):
    """Whether the file at workspace-relative `path` is test code as a whole."""
    name = path.rsplit("/", 1)[-1]
    return "tests" in path.split("/") or name == "tests.rs" or name.endswith("_tests.rs") or name.endswith("_test.rs")


def gates_on_test(attribute):
    """Whether an attribute's text (`#[cfg(...)]` or `#![cfg(...)]`) gates on `test`: as a bare cfg
    name, not part of an identifier, not inside a string such as `feature = "test-hooks"`, and not
    under `not(...)`."""
    for prefix in ("#[cfg(", "#![cfg("):
        if attribute.startswith(prefix):
            inner = attribute[len(prefix):]
            break
    else:
        return False

    def joins(ch):
        return is_ident_char(ch) or ch in '"-'

    for at in find_all(inner, "test"):
        before = inner[at - 1] if at > 0 else None
        after = inner[at + 4] if at + 4 < len(inner) else None
        if (
            not (before is not None and joins(before))
            and not (after is not None and joins(after))
            and not inner[:at].rstrip(RUST_WHITESPACE).endswith("not(")
        ):
            return True
    return False


def gated_as_test_file(data, classes):
    """Whether the file carries an inner `#![cfg(test)]`-style attribute in code: then all of it
    is test code."""
    for at in find_all(data, b"#![cfg("):
        if classes[at] != CODE:
            continue
        close = data.find(b"]", at)
        if close != -1 and gates_on_test(data[at:close + 1].decode("utf-8")):
            return True
    return False


def test_items(data, classes):
    """The byte ranges of test code in a file that is not test code as a whole: the item after each
    `#[cfg(test)]`-style attribute, through its closing brace, or through its `;` for an item with
    no body."""
    size = len(data)
    ranges = []
    search = 0
    while True:
        at = data.find(b"#[cfg(", search)
        if at == -1:
            break
        search = at + 6
        if classes[at] != CODE or (ranges and ranges[-1][0] <= at < ranges[-1][1]):
            continue
        close = data.find(b"]", at)
        if close == -1:
            break
        if not gates_on_test(data[at:close + 1].decode("utf-8")):
            continue
        i = close + 1
        depth = 0
        opened = False
        while i < size:
            if classes[i] == CODE:
                byte = data[i]
                if byte == 0x7B:  # `{`
                    if depth == 0 and not opened:
                        opened = True
                    depth += 1
                elif byte == 0x7D:  # `}`
                    depth = max(depth - 1, 0)
                    if depth == 0 and opened:
                        break
                elif byte == 0x3B and depth == 0 and not opened:  # `;`
                    opened = True
                    break
            i += 1
        if opened:
            ranges.append((at, min(i + 1, size)))
            search = min(i + 1, size)
    return ranges


def excerpt(line):
    """The line, trimmed and cut to 160 bytes."""
    line = line.strip(RUST_WHITESPACE)
    raw = line.encode("utf-8")
    if len(raw) <= 160:
        return line
    end = 160
    while 0x80 <= raw[end] <= 0xBF:
        end -= 1
    return raw[:end].decode("utf-8") + "..."


def allows(line):
    """The rules an allow on `line` names, when it gives a reason."""
    at = line.find(ALLOW_MARK)
    if at == -1:
        return []
    rest = line[at + len(ALLOW_MARK):]
    close = rest.find(")")
    if close == -1:
        return []
    names, reason = rest[:close], rest[close + 1:]
    if not reason.strip(RUST_WHITESPACE):
        return []
    return [name.strip(RUST_WHITESPACE) for name in names.split(",") if name.strip(RUST_WHITESPACE) in RULES]


def host_of(authority):
    authority = authority.rpartition("@")[2]
    if authority.startswith("["):
        host = authority[1:].split("]", 1)[0]
        return "[::1]" if host == "::1" else host
    return authority.split(":", 1)[0]


def is_local_or_reserved(host):
    host = host.rstrip(".").translate(ASCII_LOWER)
    if host in LOOPBACK_HOSTS or host.startswith("127."):
        return True
    for suffix in RESERVED_SUFFIXES:
        if suffix.startswith("."):
            # A reserved top-level name: `test` itself or any `*.test`.
            if host == suffix[1:] or host.endswith(suffix):
                return True
        elif host == suffix or host.endswith("." + suffix):
            # A reserved domain: `example.com` itself or any subdomain.
            return True
    return False


def is_identifier_host(host):
    return host.rstrip(".").translate(ASCII_LOWER) in IDENTIFIER_HOSTS


def line_rules(code, text):
    """The rules one line breaks, given its code-only text and its code-and-strings text."""
    rules = []
    for call in SLEEP_CALLS:
        if any(
            not (at > 0 and (is_ident_char(code[at - 1]) or code[at - 1] == "."))
            and not code[:at].rstrip(RUST_WHITESPACE).endswith("fn")
            for at in find_all(code, call)
        ):
            rules.append("sleep")
            break
    if any(call in code for call in WALL_CLOCK_CALLS):
        rules.append("wall-clock")
    network = fixed_port = False
    real_model = (
        any(key in text for key in MODEL_KEYS)
        or any(ext in text for ext in MODEL_FILES)
        or any(server in text for server in MODEL_SERVERS)
    )
    for scheme in SCHEMES:
        for at in find_all(text, scheme):
            authority = []
            for ch in text[at + len(scheme):]:
                if ch in AUTHORITY_END:
                    break
                authority.append(ch)
            host = host_of("".join(authority))
            if not host or "{" in host or "$" in host:
                continue
            if any(host == model or host.endswith("." + model) for model in MODEL_HOSTS):
                real_model = True
            elif not is_local_or_reserved(host) and not is_identifier_host(host):
                network = True
    for host in PORT_HOSTS:
        for at in find_all(text, host + ":"):
            if at > 0 and ((text[at - 1].isascii() and text[at - 1].isalnum()) or text[at - 1] == "."):
                continue
            digits = 0
            rest = text[at + len(host) + 1:]
            while digits < len(rest) and rest[digits] in "0123456789":
                digits += 1
            # Rust's `parse::<u32>()`: an empty run, zero, or a run above u32::MAX is no port. Leading
            # zeros are dropped first, so a run of any length is read without int()'s digit limit.
            significant = rest[:digits].lstrip("0")
            if significant and len(significant) <= 10 and int(significant) <= 0xFFFFFFFF:
                fixed_port = True
    if network:
        rules.append("network")
    if fixed_port:
        rules.append("fixed-port")
    if real_model:
        rules.append("real-model")
    return rules


def scan_source(path, source):
    """The findings in one file's source, as (path, line, rule, excerpt). `path` is
    workspace-relative; it decides whether the whole file is test code."""
    data = source.encode("utf-8")
    whole = whole_file_is_test(path)
    if not whole and not ((b"#[cfg(" in data or b"#![cfg(" in data) and b"test" in data):
        return []
    # Only a line holding a candidate can break a rule (see CANDIDATE), so the others are skipped.
    hits = [match.start() for match in CANDIDATE.finditer(data)]
    if not hits:
        return []
    classes = classify(data)
    if whole or gated_as_test_file(data, classes):
        ranges = [(0, len(data))]
    else:
        ranges = test_items(data, classes)
    if not ranges:
        return []
    findings = []
    size = len(data)
    number, counted_to, previous_start = 1, 0, -1
    for hit in hits:
        start = data.rfind(b"\n", 0, hit) + 1
        if start == previous_start:
            continue
        previous_start = start
        number += data.count(b"\n", counted_to, start)
        counted_to = start
        newline = data.find(b"\n", start)
        end = size if newline == -1 else newline
        if not any(range_start < max(end, start + 1) and start < range_end for range_start, range_end in ranges):
            continue
        line = data[start:end].decode("utf-8")
        code_chars, text_chars, offset = [], [], start
        for ch in line:
            cls = classes[offset]
            code_chars.append(ch if cls == CODE else " ")
            text_chars.append(" " if cls == COMMENT else ch)
            offset += len(ch.encode("utf-8"))
        rules = line_rules("".join(code_chars), "".join(text_chars))
        if not rules:
            continue
        here_allows = allows(line)
        # An allow on a line of its own covers the next line.
        previous_allows = []
        if start > 0:
            above = data[data.rfind(b"\n", 0, start - 1) + 1:start - 1].decode("utf-8")
            if above.lstrip(RUST_WHITESPACE).startswith("//"):
                previous_allows = allows(above)
        for rule in rules:
            if rule not in here_allows and rule not in previous_allows:
                findings.append((path, number, rule, excerpt(line)))
    return findings


def walk(root, directory, out):
    with os.scandir(directory) as listing:
        entries = sorted(listing, key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        if entry.is_dir(follow_symlinks=False):
            relative = os.path.relpath(entry.path, root).replace(os.sep, "/")
            if entry.name in SKIPPED_DIRS or relative in SKIPPED_CRATES:
                continue
            walk(root, entry.path, out)
        elif entry.is_file(follow_symlinks=False) and entry.name.endswith(".rs"):
            out.append(entry.path)


def scan_tree(root):
    """(findings, files read) under root's crates/ and apps/, in path order. A file that is not
    UTF-8 is skipped, as Rust's read_to_string refuses it."""
    files = []
    for top in ("crates", "apps"):
        directory = os.path.join(root, top)
        if os.path.isdir(directory):
            walk(root, directory, files)
    findings = []
    for file in files:
        with open(file, "rb") as handle:
            raw = handle.read()
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_source(os.path.relpath(file, root).replace(os.sep, "/"), source))
    return findings, len(files)


def totals(findings):
    counts = dict.fromkeys(RULES, 0)
    for _, _, rule, _ in findings:
        counts[rule] += 1
    return counts


def baseline_text(findings):
    """The per-file baseline: the Rust lint's lint-baseline.txt body, under this file's header."""
    per_file = {}
    for path, _, rule, _ in findings:
        per_file[(rule, path)] = per_file.get((rule, path), 0) + 1
    lines = [
        "# Test lint per-file baseline (scripts/ratchet/test_lint.py --baseline): findings per rule and per file.",
        "# The ratchet's bar is each rule's test_lint_* count in scripts/ratchet/baseline.json. Counts may fall.",
    ]
    counts = totals(findings)
    lines += [f"{rule} {counts[rule]}" for rule in RULES]
    order = {rule: index for index, rule in enumerate(RULES)}
    keys = sorted(per_file, key=lambda key: (order[key[0]], key[1].encode("utf-8", "surrogateescape")))
    lines += [f"{rule} {path} {per_file[(rule, path)]}" for rule, path in keys]
    return "\n".join(lines) + "\n"


def metric_name(rule):
    return "test_lint_" + rule.replace("-", "_")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--count", action="store_true", help="the five counts on one line (check.sh)")
    mode.add_argument("--list", action="store_true", help="every finding, as path:line: rule: text")
    mode.add_argument("--baseline", action="store_true", help="the per-file baseline text")
    parser.add_argument("--rule", choices=RULES, help="with --list: only this rule's findings")
    parser.add_argument("tree", nargs="?", default=".")
    args = parser.parse_args(argv)
    if args.rule and not args.list:
        parser.error("--rule needs --list")
    if not os.path.isdir(args.tree):
        print(f"test_lint.py: {args.tree} is not a directory", file=sys.stderr)
        return 2
    try:
        findings, read = scan_tree(args.tree)
    except OSError as error:
        print(f"test_lint.py: cannot read the tree: {error}", file=sys.stderr)
        return 2
    if read == 0:
        print(f"test_lint.py: no .rs files found under {args.tree}/crates or {args.tree}/apps", file=sys.stderr)
        return 2
    if args.list:
        for path, number, rule, text in findings:
            if args.rule is None or rule == args.rule:
                print(f"{path}:{number}: {rule}: {text}")
    elif args.baseline:
        sys.stdout.write(baseline_text(findings))
    elif args.count:
        counts = totals(findings)
        print(" ".join(str(counts[rule]) for rule in RULES))
    else:
        counts = totals(findings)
        for rule in RULES:
            print(f"{metric_name(rule)} {counts[rule]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
