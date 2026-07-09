#!/usr/bin/env bash
# GPS refactor-wave conformance gate. Single source of truth: REFACTOR-MOVE-MAP-DESIGN.md D6.
#
# Usage: scripts/refactor/conformance.sh <stage-id> <base-rev>
#   <base-rev> = the commit the stage branch was cut from.
#
# Runs, in order, first failure exits non-zero (no override flag):
#   1 forbidden-zone + allowed-files      (git diff)
#   2 surface inventory: pub decls + impl headers  (widened, F3)
#   3 moved-block rustfmt byte equivalence (cfg/container disambiguated, F2)
#   4 frozen anchors
#   5 name-uniqueness across api/*.rs (api stages)
#   6 error-literal inventory (codec stages)
#   7 WORKFLOW.md gate (cargo fmt/clippy/nextest/doctest/doc/nextest-sync)
#
# Checks 1-6 are a self-contained embedded python program (no deps beyond
# python3 + rustfmt + rg/git/awk). Check 7 shells out to cargo.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <stage-id> <base-rev>" >&2
  exit 2
fi
STAGE="$1"
BASE="$2"

ROOT="$(git rev-parse --show-toplevel)"
MOVES="$ROOT/scripts/refactor/moves"
if [ ! -f "$MOVES/$STAGE.tsv" ]; then
  echo "no manifest: $MOVES/$STAGE.tsv" >&2
  exit 2
fi

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
PAYLOAD="$TMPD/conformance_checks.py"
# extract the embedded python payload (between the PYEOF markers below)
sed -n '/^#PYEOF_BEGIN$/,/^#PYEOF_END$/p' "$0" | sed '1d;$d' | sed 's/^#>//' > "$PAYLOAD"

echo "== conformance $STAGE (base $BASE) =="
python3 "$PAYLOAD" checks "$ROOT" "$STAGE" "$BASE" "$MOVES"

# ---- check 7: the WORKFLOW.md gate (WORKFLOW.md:44-49, de-rtk'd) ----
echo "== check 7: WORKFLOW.md gate =="
cd "$ROOT"
export CARGO_TARGET_DIR="$ROOT/target"
run() { echo "+ $*"; "$@"; }
run cargo fmt --all --check
run cargo clippy --workspace --all-targets --all-features -- -D warnings
run cargo nextest run --workspace --all-features --profile full
run cargo test --doc --workspace --exclude oneiron-bench --all-features
run env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
run cargo nextest run -p oneiron --features sync --profile full
echo "OK check 7 (WORKFLOW gate)"

echo "== CONFORMANCE GREEN for $STAGE =="
exit 0

# The python payload is stored below, each line prefixed with '#>' so bash never
# parses it. conformance.sh extracts + de-prefixes it at run time.
#PYEOF_BEGIN
#>#!/usr/bin/env python3
#>"""Rust structural extractor for the refactor conformance script.
#>
#>Shape-level (NOT semantic) parsing of rustfmt-formatted Rust:
#>  - mask(): blank out string/char/comment interiors so brace counting is reliable.
#>  - canon(): token-split + single-space join -> whitespace/reflow-insensitive form.
#>  - enumerate_items(): top-level items (depth 0) + their impl-block methods (depth 1).
#>  - inventory(): every `pub..` declaration head (any indent) -> canon heads.
#>  - impl_headers(): every `impl ..` header (any indent) -> (relpath is added by caller).
#>  - find_item(): locate a manifest row's item by (kind, container, item_name, cfg),
#>    enforcing exactly-one-match.
#>  - extract/format helpers for the moved-block byte comparison.
#>
#>Relies on rustfmt having already normalised the tree (one item per line start).
#>"""
#>import re
#>import subprocess
#>import sys
#>import os
#>import tempfile
#>
#>RUSTFMT = os.environ.get("RUSTFMT_BIN", "rustfmt")
#>
#># ---------------------------------------------------------------------------
#># masking
#># ---------------------------------------------------------------------------
#>
#>_RAW_OPEN = re.compile(r'(?:b|c)?r(#*)"')
#>_STR_OPEN = re.compile(r'(?:b|c)?"')
#>_CHAR = re.compile(r"'(?:\\u\{[0-9A-Fa-f_]+\}|\\.|[^'\\\n])'")
#>
#>
#>def _is_ident(ch):
#>    return ch.isalnum() or ch == "_"
#>
#>
#>def mask(src):
#>    """Return a same-length copy of src with string/char/comment interiors
#>    replaced by spaces (newlines preserved), so { } ( ) [ ] counting is safe."""
#>    n = len(src)
#>    res = list(src)
#>    i = 0
#>    while i < n:
#>        c = src[i]
#>        prev = src[i - 1] if i > 0 else ""
#>        boundary = not (_is_ident(prev))
#>        # line comment
#>        if c == "/" and i + 1 < n and src[i + 1] == "/":
#>            j = i
#>            while j < n and src[j] != "\n":
#>                res[j] = " "
#>                j += 1
#>            i = j
#>            continue
#>        # block comment (nestable)
#>        if c == "/" and i + 1 < n and src[i + 1] == "*":
#>            depth = 1
#>            res[i] = res[i + 1] = " "
#>            j = i + 2
#>            while j < n and depth > 0:
#>                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
#>                    depth += 1
#>                    res[j] = res[j + 1] = " "
#>                    j += 2
#>                    continue
#>                if src[j] == "*" and j + 1 < n and src[j + 1] == "/":
#>                    depth -= 1
#>                    res[j] = res[j + 1] = " "
#>                    j += 2
#>                    continue
#>                if src[j] != "\n":
#>                    res[j] = " "
#>                j += 1
#>            i = j
#>            continue
#>        # raw string (needs a token boundary before the prefix)
#>        if boundary:
#>            m = _RAW_OPEN.match(src, i)
#>            if m:
#>                hashes = m.group(1)
#>                close = '"' + hashes
#>                body = m.end()
#>                for k in range(i, body):
#>                    if src[k] != "\n":
#>                        res[k] = " "
#>                idx = src.find(close, body)
#>                if idx < 0:
#>                    idx = n - len(close)
#>                end = idx + len(close)
#>                for k in range(body, min(end, n)):
#>                    if src[k] != "\n":
#>                        res[k] = " "
#>                i = end
#>                continue
#>            m = _STR_OPEN.match(src, i)
#>            if m:
#>                j = m.end()
#>                for k in range(i, j):
#>                    if src[k] != "\n":
#>                        res[k] = " "
#>                while j < n:
#>                    if src[j] == "\\":
#>                        if src[j] != "\n":
#>                            res[j] = " "
#>                        if j + 1 < n and src[j + 1] != "\n":
#>                            res[j + 1] = " "
#>                        j += 2
#>                        continue
#>                    if src[j] == '"':
#>                        res[j] = " "
#>                        j += 1
#>                        break
#>                    if src[j] != "\n":
#>                        res[j] = " "
#>                    j += 1
#>                i = j
#>                continue
#>        else:
#>            # plain '"' with no prefix still starts a string even mid-token-ish
#>            if c == '"':
#>                j = i + 1
#>                res[i] = " "
#>                while j < n:
#>                    if src[j] == "\\":
#>                        res[j] = " "
#>                        if j + 1 < n and src[j + 1] != "\n":
#>                            res[j + 1] = " "
#>                        j += 2
#>                        continue
#>                    if src[j] == '"':
#>                        res[j] = " "
#>                        j += 1
#>                        break
#>                    if src[j] != "\n":
#>                        res[j] = " "
#>                    j += 1
#>                i = j
#>                continue
#>        # char literal vs lifetime
#>        if c == "'":
#>            m = _CHAR.match(src, i)
#>            if m:
#>                for k in range(i, m.end()):
#>                    if src[k] != "\n":
#>                        res[k] = " "
#>                i = m.end()
#>                continue
#>            i += 1
#>            continue
#>        i += 1
#>    return "".join(res)
#>
#>
#># ---------------------------------------------------------------------------
#># canonicalisation
#># ---------------------------------------------------------------------------
#>
#>_CODE_TOKEN = re.compile(
#>    r'"(?:\\.|[^"\\])*"'      # string literal
#>    r"|[A-Za-z_][A-Za-z0-9_]*"  # ident/keyword
#>    r"|[0-9][0-9A-Za-z_.]*"     # number-ish
#>    r"|::|->|=>|&&|\|\||==|!=|<=|>="  # multi-char ops
#>    r"|\S"                     # any other single non-space char
#>)
#>
#>
#>def _lex(text):
#>    """(token, start, end) stream with comments atomic: a `//` comment runs
#>    to EOL, a `/* */` comment nests (matching mask()'s lexical reality), a
#>    string literal is one token. Comment/string interiors are never re-lexed
#>    as code."""
#>    out = []
#>    i, n = 0, len(text)
#>    while i < n:
#>        if text[i] in " \t\r\n":
#>            i += 1
#>            continue
#>        if text.startswith("//", i):
#>            j = text.find("\n", i)
#>            j = n if j == -1 else j
#>            out.append((text[i:j], i, j))
#>            i = j
#>            continue
#>        if text.startswith("/*", i):
#>            depth, j = 1, i + 2
#>            while j < n and depth:
#>                if text.startswith("/*", j):
#>                    depth += 1
#>                    j += 2
#>                elif text.startswith("*/", j):
#>                    depth -= 1
#>                    j += 2
#>                else:
#>                    j += 1
#>            out.append((text[i:j], i, j))
#>            i = j
#>            continue
#>        m = _CODE_TOKEN.match(text, i)
#>        if m:
#>            out.append((m.group(0), i, m.end()))
#>            i = m.end()
#>        else:
#>            i += 1
#>    return out
#>
#>
#># Keywords that can legally precede a parenthesized EXPRESSION/PATTERN — after
#># these, `(x,)` is a one-tuple and its comma is semantics, not rustfmt style.
#>_TUPLE_POS_KEYWORDS = {
#>    "return", "break", "continue", "if", "else", "while", "for", "in",
#>    "match", "loop", "move", "yield", "as", "where", "let", "mut", "ref",
#>    "const", "static", "async", "unsafe", "await", "box", "dyn", "fn",
#>    "impl",
#>}
#>
#>
#>def canon(text):
#>    """Whitespace/reflow-insensitive token form: lex (comments atomic — see
#>    _lex), rejoin with single spaces. A trailing comma before a closing
#>    bracket is dropped only when BOTH hold: the closer sits on a LATER line
#>    (rustfmt's vertical-list habit — never drop a same-line `,)` one-tuple),
#>    AND the bracket group is droppable: `[ ]` / `{ }` always (trailing commas
#>    there are never semantic in Rust), `( )` only in CALL position — matching
#>    opener directly preceded by a path ident (not a keyword), `)`, `]`,
#>    turbofish `>`, or macro `!` — because an arg-list/constructor trailing
#>    comma is style, while a non-call `(x,)` is a one-tuple. Known accepted
#>    blind spot: `a > (b,\\n)` comparisons read `>` as turbofish."""
#>    toks = _lex(text)
#>    # Per-closer droppability via bracket matching.
#>    droppable = {}
#>    stack = []
#>    for idx, (t, _s, _e) in enumerate(toks):
#>        if t in ("(", "[", "{"):
#>            prev = toks[idx - 1][0] if idx else ""
#>            call = (t != "(") or prev in (")", "]", ">", "!") or bool(
#>                re.match(r"[A-Za-z_]", prev or " ")
#>                and prev not in _TUPLE_POS_KEYWORDS)
#>            stack.append(call)
#>        elif t in (")", "]", "}"):
#>            droppable[idx] = stack.pop() if stack else True
#>    out = []
#>    for i, (t, _s, e) in enumerate(toks):
#>        if (t == "," and i + 1 < len(toks)
#>                and toks[i + 1][0] in ("}", "]", ")")
#>                and "\n" in text[e:toks[i + 1][1]]
#>                and droppable.get(i + 1, True)):
#>            continue
#>        out.append(t)
#>    return " ".join(out)
#>
#>
#>def norm_head(h):
#>    """Order-insensitive form for `use ...::{a, b, c}` heads: sort the brace
#>    group so rustfmt's import ordering (version-dependent) doesn't matter.
#>    No-op for any head without a brace group (only use-heads have one)."""
#>    if "{" not in h or "}" not in h:
#>        return h
#>    i = h.index("{")
#>    j = h.rindex("}")
#>    inner = h[i + 1:j].strip()
#>    names = sorted(p.strip() for p in inner.split(",") if p.strip())
#>    return h[:i + 1] + " " + " , ".join(names) + " " + h[j:]
#>
#>
#># ---------------------------------------------------------------------------
#># line/offset/depth bookkeeping
#># ---------------------------------------------------------------------------
#>
#>
#>class Doc:
#>    def __init__(self, src):
#>        self.src = src
#>        self.masked = mask(src)
#>        self.lines = src.split("\n")
#>        self.mlines = self.masked.split("\n")
#>        # offset of start of each line in the (masked==src length) buffer
#>        self.loff = []
#>        off = 0
#>        for ln in self.lines:
#>            self.loff.append(off)
#>            off += len(ln) + 1
#>        # brace depth ({} only) at the start of each line
#>        self.depth0 = []
#>        d = 0
#>        for ml in self.mlines:
#>            self.depth0.append(d)
#>            for ch in ml:
#>                if ch == "{":
#>                    d += 1
#>                elif ch == "}":
#>                    d -= 1
#>
#>    def line_of_offset(self, pos):
#>        # binary-ish: loff is increasing
#>        lo, hi = 0, len(self.loff) - 1
#>        while lo < hi:
#>            mid = (lo + hi + 1) // 2
#>            if self.loff[mid] <= pos:
#>                lo = mid
#>            else:
#>                hi = mid - 1
#>        return lo
#>
#>
#># item signature detection (applied to masked, lstripped line)
#>_SIG = [
#>    ("fn", re.compile(r'^(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:async|unsafe|const|default|extern(?:\s+"[^"]*")?)\s+)*fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)')),
#>    ("impl", re.compile(r"^(?:unsafe\s+)?impl\b")),
#>    ("struct", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("enum", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?enum\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("trait", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("union", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?union\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("type", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?type\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("const", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("static", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?static\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("mod", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>    ("use", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?use\b")),
#>    ("macro", re.compile(r"^macro_rules!\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
#>]
#>
#>_VIS = re.compile(r"^(pub(?:\s*\([^)]*\))?)\s")
#>
#>
#>def _match_sig(mls):
#>    """mls = lstripped masked line. Return (kind, name-or-None) or None.
#>    `const fn` etc. resolve to fn because the fn pattern is tried first."""
#>    for kind, rx in _SIG:
#>        m = rx.match(mls)
#>        if m:
#>            name = m.groupdict().get("name") if "name" in m.groupdict() else None
#>            return kind, name
#>    return None
#>
#>
#>def _scan_extent(doc, start_off):
#>    """From start_off, walk masked to find the item's terminator.
#>    Returns (body_open_off or None, end_off_inclusive). body item ends at the
#>    matching '}'; a ;-item ends at that ';'."""
#>    m = doc.masked
#>    n = len(m)
#>    pd = bd = cd = 0  # () [] {} depths
#>    body_open = None
#>    i = start_off
#>    while i < n:
#>        ch = m[i]
#>        if ch == "(":
#>            pd += 1
#>        elif ch == ")":
#>            pd -= 1
#>        elif ch == "[":
#>            bd += 1
#>        elif ch == "]":
#>            bd -= 1
#>        elif ch == "{":
#>            if pd == 0 and bd == 0 and body_open is None:
#>                body_open = i
#>                cd = 1
#>                i += 1
#>                # walk to matching close
#>                while i < n and cd > 0:
#>                    if m[i] == "{":
#>                        cd += 1
#>                    elif m[i] == "}":
#>                        cd -= 1
#>                    i += 1
#>                return body_open, i - 1
#>            cd += 1
#>        elif ch == "}":
#>            cd -= 1
#>        elif ch == ";":
#>            if pd == 0 and bd == 0 and body_open is None:
#>                return None, i
#>        i += 1
#>    return body_open, n - 1
#>
#>
#>def _leading_block(doc, sig_line):
#>    """Walk up from sig_line over contiguous doc-comment / attribute lines.
#>    Multi-line #[...] attributes are consumed via bracket matching on masked.
#>    Stops at a blank line or any non-attr/non-doc line."""
#>    cur = sig_line - 1
#>    top = sig_line
#>    while cur >= 0:
#>        s = doc.lines[cur].strip()
#>        ms = doc.mlines[cur].strip()
#>        if s == "":
#>            break
#>        # `///` outer doc + `#[...]` outer attr attach to the FOLLOWING item.
#>        # `//!` inner doc + `#![...]` inner attr document the ENCLOSING module and
#>        # must NOT be swallowed by the first item below them.
#>        if s.startswith("///") and not s.startswith("////"):
#>            top = cur
#>            cur -= 1
#>            continue
#>        if ms.startswith("#[") and not ms.startswith("#!["):
#>            top = cur
#>            cur -= 1
#>            continue
#>        # possible tail of a multi-line attribute: line ends with ] and bracket
#>        # accounting over the masked span back to a '#[' start balances.
#>        if ms.endswith("]"):
#>            # accumulate upward until bracket depth balances at a #[ line
#>            depth = 0
#>            k = cur
#>            found = None
#>            while k >= 0:
#>                mk = doc.mlines[k]
#>                depth += mk.count("]") - mk.count("[")
#>                if depth == 0 and (mk.lstrip().startswith("#[") or mk.lstrip().startswith("#![")):
#>                    found = k
#>                    break
#>                if depth < 0:
#>                    break
#>                k -= 1
#>            if found is not None:
#>                top = found
#>                cur = found - 1
#>                continue
#>        break
#>    return top
#>
#>
#>def _cfgs_of(doc, lead_start, sig_line):
#>    """cfg predicate strings (canon) from #[cfg(...)] attributes in the lead
#>    block. Located via masked text (correct paren matching) but sliced from the
#>    original source so string literals like "sync" survive."""
#>    if lead_start >= sig_line:
#>        return []
#>    lo = doc.loff[lead_start]
#>    hi = doc.loff[sig_line]
#>    seg = doc.masked[lo:hi]
#>    out = []
#>    for m in re.finditer(r"#\s*\[\s*cfg\s*\(", seg):
#>        depth = 0
#>        i = m.end() - 1  # at '('
#>        start = m.end()
#>        while i < len(seg):
#>            if seg[i] == "(":
#>                depth += 1
#>            elif seg[i] == ")":
#>                depth -= 1
#>                if depth == 0:
#>                    out.append(canon(doc.src[lo + start:lo + i]))
#>                    break
#>            i += 1
#>    return out
#>
#>
#>def _vis_of(doc, sig_line):
#>    m = _VIS.match(doc.lines[sig_line].strip())
#>    return canon(m.group(1)) if m else ""
#>
#>
#>def enumerate_items(doc):
#>    """Top-level items (depth 0). impl items get a 'methods' list (depth-1 fns/consts/types)."""
#>    items = []
#>    i = 0
#>    N = len(doc.lines)
#>    while i < N:
#>        if doc.depth0[i] != 0:
#>            i += 1
#>            continue
#>        mls = doc.mlines[i].lstrip()
#>        sig = _match_sig(mls)
#>        if not sig:
#>            i += 1
#>            continue
#>        kind, name = sig
#>        start_off = doc.loff[i] + (len(doc.mlines[i]) - len(mls))
#>        body_open, end_off = _scan_extent(doc, start_off)
#>        end_line = doc.line_of_offset(end_off)
#>        lead = _leading_block(doc, i)
#>        header = None
#>        if kind == "impl":
#>            header = canon(doc.src[start_off:body_open]) if body_open is not None else canon(mls)
#>        item = {
#>            "kind": kind,
#>            "name": name,
#>            "header": header,
#>            "sig_line": i,
#>            "lead_start": lead,
#>            "end_line": end_line,
#>            "body_open_line": doc.line_of_offset(body_open) if body_open is not None else None,
#>            "vis": _vis_of(doc, i),
#>            "cfgs": _cfgs_of(doc, lead, i),
#>            "methods": [],
#>        }
#>        if kind == "impl" and body_open is not None:
#>            inner_depth = doc.depth0[i] + 1
#>            j = item["body_open_line"] + 1
#>            while j <= end_line:
#>                if doc.depth0[j] == inner_depth:
#>                    mjs = doc.mlines[j].lstrip()
#>                    msig = _match_sig(mjs)
#>                    if msig and msig[0] in ("fn", "const", "type"):
#>                        mkind, mname = msig
#>                        mstart = doc.loff[j] + (len(doc.mlines[j]) - len(mjs))
#>                        mbo, meo = _scan_extent(doc, mstart)
#>                        mel = doc.line_of_offset(meo)
#>                        mlead = _leading_block(doc, j)
#>                        item["methods"].append({
#>                            "kind": "method" if mkind == "fn" else mkind,
#>                            "name": mname,
#>                            "sig_line": j,
#>                            "lead_start": mlead,
#>                            "end_line": mel,
#>                            "vis": _vis_of(doc, j),
#>                            "cfgs": _cfgs_of(doc, mlead, j),
#>                        })
#>                        j = mel + 1
#>                        continue
#>                j += 1
#>        items.append(item)
#>        i = end_line + 1
#>    return items
#>
#>
#>def item_text(doc, it):
#>    return "\n".join(doc.lines[it["lead_start"]:it["end_line"] + 1])
#>
#>
#>def logical_head(doc, sig_line):
#>    """canon of the declaration head. For `use`, up to the terminating ';'
#>    (brace groups are part of the import list, not a body). For everything else,
#>    up to the body-open '{', '=', or ';' at zero depth. Reflow-insensitive."""
#>    mls = doc.mlines[sig_line].lstrip()
#>    start_off = doc.loff[sig_line] + (len(doc.mlines[sig_line]) - len(mls))
#>    is_use = bool(re.match(r"^(?:pub(?:\s*\([^)]*\))?\s+)?use\b", mls))
#>    stops = ";" if is_use else "{;="
#>    m = doc.masked
#>    n = len(m)
#>    pd = bd = 0
#>    i = start_off
#>    while i < n:
#>        ch = m[i]
#>        if ch == "(":
#>            pd += 1
#>        elif ch == ")":
#>            pd -= 1
#>        elif ch == "[":
#>            bd += 1
#>        elif ch == "]":
#>            bd -= 1
#>        elif pd == 0 and bd == 0 and ch in stops:
#>            break
#>        i += 1
#>    return norm_head(canon(doc.src[start_off:i]))
#>
#>
#>_INV = re.compile(r"^\s*pub(?:\s*\((?:crate|super|in\s+[^)]+)\))?\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:default\s+)?(?:extern(?:\s+\"[^\"]*\")?\s+)?(?:fn|struct|enum|trait|type|const|static|mod|use|union)\b")
#>_IMPLHDR = re.compile(r"^\s*(?:unsafe\s+)?impl\b")
#>
#>
#>def inventory(doc):
#>    """All pub declaration heads (canon), any indentation."""
#>    out = []
#>    for i, ml in enumerate(doc.mlines):
#>        if _INV.match(ml):
#>            out.append(logical_head(doc, i))
#>    return out
#>
#>
#>def impl_headers(doc):
#>    """All impl-block headers (canon), any indentation."""
#>    out = []
#>    n = len(doc.masked)
#>    for i, ml in enumerate(doc.mlines):
#>        if _IMPLHDR.match(ml):
#>            mls = ml.lstrip()
#>            start_off = doc.loff[i] + (len(ml) - len(mls))
#>            bo, eo = _scan_extent(doc, start_off)
#>            if bo is not None:
#>                out.append(canon(doc.src[start_off:bo]))
#>    return out
#>
#>
#>def find_item(doc, kind, container, name, cfg):
#>    """Return list of matching item dicts (with doc-relative extent) for the row."""
#>    items = enumerate_items(doc)
#>    cfgc = canon(cfg) if cfg and cfg != "-" else None
#>    matches = []
#>    if kind == "method":
#>        cc = canon(container)
#>        for it in items:
#>            if it["kind"] == "impl" and it["header"] == cc:
#>                for m in it["methods"]:
#>                    if m["kind"] == "method" and m["name"] == name:
#>                        if cfgc is None or cfgc in m["cfgs"]:
#>                            matches.append(m)
#>    elif kind == "impl":
#>        want = canon(name)
#>        for it in items:
#>            if it["kind"] == "impl" and it["header"] == want:
#>                if cfgc is None or cfgc in it["cfgs"]:
#>                    matches.append(it)
#>    elif kind == "mod":
#>        for it in items:
#>            if it["kind"] == "mod" and it["name"] == name:
#>                if cfgc is None or cfgc in it["cfgs"]:
#>                    matches.append(it)
#>    elif container and container not in ("-", "") and container.split()[0] == "mod":
#>        # container = "mod tests" (or another named mod): item lives inside that mod body
#>        modname = container.split()[-1]
#>        for it in items:
#>            if it["kind"] == "mod" and it["name"] == modname and it["body_open_line"] is not None:
#>                for m in items_in_mod(doc, it):
#>                    mk = "method" if m["kind"] == "fn" and kind == "method" else m["kind"]
#>                    if (mk == kind or m["kind"] == kind) and m["name"] == name:
#>                        if cfgc is None or cfgc in m["cfgs"]:
#>                            matches.append(m)
#>    else:
#>        for it in items:
#>            if it["kind"] == kind and it["name"] == name:
#>                if cfgc is None or cfgc in it["cfgs"]:
#>                    matches.append(it)
#>    return matches
#>
#>
#>def items_in_mod(doc, mod_item):
#>    """Enumerate fn/const/type/struct/enum/impl items directly inside a mod body."""
#>    out = []
#>    inner_depth = doc.depth0[mod_item["sig_line"]] + 1
#>    j = mod_item["body_open_line"] + 1
#>    while j <= mod_item["end_line"]:
#>        if doc.depth0[j] == inner_depth:
#>            mjs = doc.mlines[j].lstrip()
#>            msig = _match_sig(mjs)
#>            if msig:
#>                mkind, mname = msig
#>                mstart = doc.loff[j] + (len(doc.mlines[j]) - len(mjs))
#>                mbo, meo = _scan_extent(doc, mstart)
#>                mel = doc.line_of_offset(meo)
#>                mlead = _leading_block(doc, j)
#>                out.append({
#>                    "kind": mkind, "name": mname, "sig_line": j, "lead_start": mlead,
#>                    "end_line": mel,
#>                    "body_open_line": doc.line_of_offset(mbo) if mbo is not None else None,
#>                    "vis": _vis_of(doc, j), "cfgs": _cfgs_of(doc, mlead, j),
#>                })
#>                j = mel + 1
#>                continue
#>        j += 1
#>    return out
#>
#>
#># ---------------------------------------------------------------------------
#># declared-edit application + delta-shape validation (TS D6 #3/#4, D9.4 #2)
#># ---------------------------------------------------------------------------
#>
#>_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*(::)?$")
#>
#>
#>def apply_edits(text, edits):
#>    """edits = list of (old_stripped, new_stripped). Replace each fragment line
#>    whose stripped form == old with new (indentation preserved)."""
#>    lines = text.split("\n")
#>    for i, ln in enumerate(lines):
#>        s = ln.strip()
#>        for old, new in edits:
#>            if s == old:
#>                indent = ln[:len(ln) - len(ln.lstrip())]
#>                lines[i] = indent + new
#>                break
#>    return "\n".join(lines)
#>
#>
#>def _edit_delta_ok_core(old, new, allow_exceptions=True):
#>    """True iff old→new is a legal declared edit: every changed region is pure
#>    `::`-path text, a single string-literal token swapped for a string-literal
#>    token (relative include_str!/include_bytes! paths broken by a directory-depth
#>    change), a pure path-segment removal (`crate::types::X` → `crate::X`, the
#>    module-un-mount class), or the single visibility-promotion exception
#>    (empty→`pub(crate)` prepended). Multiple regions are allowed (a line may
#>    carry more than one `types::X` occurrence re-pointed at once); each must be
#>    pure-path. allow_exceptions=False drops the string-literal and
#>    vis-promotion exceptions — comment interiors are path-re-points ONLY."""
#>    old_toks = [t for t, _s, _e in _lex(old)]
#>    nt = [t for t, _s, _e in _lex(new)]
#>    if old_toks == nt:
#>        return False  # a no-op edit is not a valid declared edit
#>    if len(old_toks) == len(nt):
#>        # position-wise: collect maximal runs of differing tokens; each must be
#>        # a pure ::-path segment on both sides (e.g. `types` -> `registry`).
#>        i = 0
#>        n = len(old_toks)
#>        while i < n:
#>            if old_toks[i] == nt[i]:
#>                i += 1
#>                continue
#>            j = i
#>            while j < n and old_toks[j] != nt[j]:
#>                j += 1
#>            if (allow_exceptions and j - i == 1
#>                    and old_toks[i].startswith('"') and nt[i].startswith('"')):
#>                # string-literal → string-literal single-token swap
#>                i = j
#>                continue
#>            if not (_PATH_RE.match("".join(old_toks[i:j])) and _PATH_RE.match("".join(nt[i:j]))):
#>                return False
#>            # must be a genuine path SEGMENT: adjacent to `::` on one side
#>            # (rejects a bare identifier / variable rename)
#>            if not ((i > 0 and old_toks[i - 1] == "::") or (j < n and old_toks[j] == "::")):
#>                return False
#>            i = j
#>        return True
#>    # length differs: single-region prefix/suffix (covers the vis exception)
#>    p = 0
#>    while p < len(old_toks) and p < len(nt) and old_toks[p] == nt[p]:
#>        p += 1
#>    s = 0
#>    while s < len(old_toks) - p and s < len(nt) - p and old_toks[-1 - s] == nt[-1 - s]:
#>        s += 1
#>    old_reg = old_toks[p:len(old_toks) - s]
#>    new_reg = nt[p:len(nt) - s]
#>    # the ONLY visibility exception is pub(crate) (TS D2 promotions); a bare
#>    # `pub` insertion is public-API widening and must never validate as a
#>    # declared edit
#>    if allow_exceptions and old_reg == [] and "".join(new_reg) == "pub(crate)":
#>        return True
#>    # every length-changing path edit must sit at a `::` boundary OUTSIDE the
#>    # changed region: the unchanged token just before or just after the region
#>    # must be `::` (mirrors the equal-length branch guard). Rejects bare
#>    # identifier rewrites (`old` -> `crate::new`), leading-qualifier removals
#>    # (`crate::types::Foo` -> `types::Foo`), and non-path deletions
#>    # (`foo(crate::types::X)` -> `foo()`).
#>    if not ((p > 0 and old_toks[p - 1] == "::")
#>            or (s > 0 and old_toks[len(old_toks) - s] == "::")):
#>        return False
#>    if new_reg == [] and "::" in old_reg and _PATH_RE.match("".join(old_reg)):
#>        # pure ::-path segment REMOVAL (module un-mount: crate::types::X ->
#>        # crate::X). The removed run must include its `::` separator so the
#>        # surviving path stays well-formed; _PATH_RE's trailing-`::` form
#>        # covers the `types ::` shape the prefix/suffix split produces.
#>        return True
#>    if not old_reg or not new_reg:
#>        return False
#>    return bool(_PATH_RE.match("".join(old_reg)) and _PATH_RE.match("".join(new_reg)))
#>
#>
#>def edit_delta_ok(old, new):
#>    """_edit_delta_ok_core, plus the comment-interior class: comment-atomic
#>    lexing makes a `///` doctest line ONE token, so an interior path re-point
#>    (the ForeignWorldId doctest frag-edit class) can never satisfy the token
#>    rules on the raw line. When both sides carry the SAME comment marker,
#>    validate the interiors as pure path re-points — a marker change
#>    (`///`→`//`), any non-path interior delta, and the string-literal /
#>    vis-promotion exceptions (code-line classes, meaningless and fail-open
#>    inside comment text) all still fail."""
#>    if _edit_delta_ok_core(old, new):
#>        return True
#>    o, n = old.lstrip(), new.lstrip()
#>    for pre in ("///", "//!", "//"):
#>        if o.startswith(pre) and n.startswith(pre):
#>            return _edit_delta_ok_core(o[len(pre):], n[len(pre):],
#>                                       allow_exceptions=False)
#>    return False
#>
#>
#># ---------------------------------------------------------------------------
#># flat-name set from lib.rs (TS D6 #6 / CONV D3.2 contract check)
#># ---------------------------------------------------------------------------
#>
#>def flat_names(doc):
#>    """Set of names exported by lib.rs's `pub use` groups (the flat façade).
#>    Handles `pub use crate::m::{A, B as C};` and `pub use crate::m::Name;`."""
#>    names = set()
#>    for it in enumerate_items(doc):
#>        if it["kind"] != "use" or it["vis"] != "pub":
#>            continue
#>        head = logical_head(doc, it["sig_line"])  # canon, e.g. "pub use crate :: m :: { A , B }"
#>        if "{" in head:
#>            inner = head[head.index("{") + 1:head.rindex("}")]
#>            parts = [p.strip() for p in inner.split(",") if p.strip()]
#>        else:
#>            # trailing single name after last ::
#>            toks = head.split()
#>            parts = [toks[-1]] if toks else []
#>        for part in parts:
#>            t = part.split()
#>            if "as" in t:
#>                names.add(t[t.index("as") + 1])
#>            elif t:
#>                names.add(t[-1])
#>    return names
#>
#>
#># ---------------------------------------------------------------------------
#># rustfmt normalisation + byte compare helpers
#># ---------------------------------------------------------------------------
#>
#>_FMT_CONFIG = "wrap_comments=false,normalize_comments=false,format_code_in_doc_comments=false,normalize_doc_attributes=false,reorder_imports=false,reorder_modules=false"
#>
#>
#>def rustfmt(fragment):
#>    """Format a fragment with default config + edition 2024, comment-touching
#>    options forced off, run from a scratch cwd so no repo rustfmt.toml applies.
#>    Returns formatted text or raises RuntimeError."""
#>    with tempfile.TemporaryDirectory() as td:
#>        p = subprocess.run(
#>            [RUSTFMT, "--edition", "2024", "--config", _FMT_CONFIG, "--emit", "stdout"],
#>            input=fragment, capture_output=True, text=True, cwd=td,
#>        )
#>        if p.returncode != 0:
#>            raise RuntimeError("rustfmt failed: " + p.stderr.strip())
#>        out = p.stdout
#>        # rustfmt --emit stdout prepends a filename banner line on some versions;
#>        # strip a leading "stdin:\n" style banner if present.
#>        if out.startswith("stdin:\n") or out.startswith("<stdin>:\n"):
#>            out = out.split("\n", 1)[1]
#>            if out.startswith("\n"):
#>                out = out[1:]
#>        return out
#>
#>
#>_DUMMY_OPEN = "impl __Dummy {"
#>
#>
#>def _dewrap(fmted):
#>    lines = fmted.split("\n")
#>    # drop trailing empty lines
#>    while lines and lines[-1].strip() == "":
#>        lines.pop()
#>    assert lines and lines[0].strip() == _DUMMY_OPEN, "wrap missing open"
#>    assert lines[-1].strip() == "}", "wrap missing close"
#>    inner = lines[1:-1]
#>    dedented = []
#>    for ln in inner:
#>        dedented.append(ln[4:] if ln.startswith("    ") else ln.lstrip() if ln.strip() == "" else ln)
#>    return "\n".join(dedented).rstrip("\n")
#>
#>
#>_SIG_LINE = re.compile(r"^(\s*)(pub(?:\s*\([^)]*\))?\s+)((?:async\s+|unsafe\s+|const\s+|default\s+|extern[^ ]*\s+)*(?:fn|struct|enum|trait|type|const|static|union|mod|use)\b)")
#>
#>
#>def strip_item_vis(fragment):
#>    """Remove a leading pub(...)/pub token from the item's signature line
#>    (the first line whose lstripped form starts with an optional pub + item kw)."""
#>    lines = fragment.split("\n")
#>    for idx, ln in enumerate(lines):
#>        m = _SIG_LINE.match(ln)
#>        if m:
#>            lines[idx] = m.group(1) + m.group(3) + ln[m.end():]
#>            break
#>        # base side: sig line without pub -> nothing to strip, but detect to stop
#>        if re.match(r"^\s*(?:async\s+|unsafe\s+|const\s+|default\s+|extern[^ ]*\s+)*(?:fn|struct|enum|trait|type|const|static|union|mod|use)\b", ln):
#>            break
#>    return "\n".join(lines)
#>
#>
#>def normalized_fragment(text, is_fn, header_change):
#>    """Full normalisation pipeline for one extracted item.
#>
#>    header_change: the added `pub(crate) ` token is stripped from the signature
#>    BEFORE rustfmt (not after), so both sides present the identical private form
#>    and format identically. Stripping after rustfmt would false-fail when the
#>    added token pushes a single-line signature past the width limit and rustfmt
#>    reflows it (D6's after-rustfmt spec is fragile on that case)."""
#>    if header_change:
#>        text = strip_item_vis(text)
#>    if is_fn:
#>        wrapped = _DUMMY_OPEN + "\n" + text + "\n}\n"
#>        body = _dewrap(rustfmt(wrapped))
#>    else:
#>        body = rustfmt(text + "\n").rstrip("\n")
#>    return body
#>
#>
#># ---------------------------------------------------------------------------
#># CLI (debugging / generator use)
#># ---------------------------------------------------------------------------
#>
#>def _load(path):
#>    with open(path, encoding="utf-8") as f:
#>        return Doc(f.read())
#>
#>
#># ==== driver (checks 1-6) ====
#>import collections
#>import glob
#>R = sys.modules[__name__]
#>
#># Guard zone (in-flight collision guard, TS D6 #1). LIFTED by owner 2026-07-08
#># (ONE-1443=063340de5, ONE-1554=b2437d700 both landed). When lifted, these files
#># are allowed iff a stage lists them; when not, they are globally forbidden.
#># The old batch/outbound/anchored_annotation LEAVE-ALONE fence is GONE.
#>GUARD = [
#>    "crates/oneiron/src/agent_def.rs", "crates/oneiron/src/agent_def/",
#>    "crates/oneiron/src/edit_settle.rs", "crates/oneiron/src/edit_settle/",
#>]
#>LIFTED = True
#>
#>
#>class Violation(Exception):
#>    def __init__(self, check, msg):
#>        self.check = check
#>        super().__init__(msg)
#>
#>
#># ---- file access (injection points for the self-test) --------------------
#>
#>def git_show(root, rev, path):
#>    p = subprocess.run(["git", "-C", root, "show", f"{rev}:{path}"],
#>                       capture_output=True, text=True)
#>    return p.stdout if p.returncode == 0 else None
#>
#>
#>def base_file(root, base, path):
#>    return git_show(root, base, path)
#>
#>
#>def head_file(root, path):
#>    return git_show(root, "HEAD", path)
#>
#>
#>def changed_files(root, base):
#>    # --no-renames: git's rename detection collapses a pure `git mv` to the
#>    # dst path only, which would hide the src side from every inventory diff
#>    # (check 2 would read all of a relocated file's decls as undeclared adds).
#>    # The gate always needs both sides listed.
#>    p = subprocess.run(["git", "-C", root, "diff", "--name-only", "--no-renames",
#>                        base, "HEAD"],
#>                       capture_output=True, text=True)
#>    if p.returncode != 0:
#>        raise Violation(0, f"git diff failed: {p.stderr.strip()}")
#>    return [ln for ln in p.stdout.split("\n") if ln.strip()]
#>
#>
#># ---- manifest parsing ----------------------------------------------------
#>
#>TSV_COLS = ["kind", "container", "item_name", "cfg", "src_file", "dst_file", "header_change"]
#>
#>
#>def parse_tsv(path):
#>    rows = []
#>    with open(path, encoding="utf-8") as f:
#>        for ln in f:
#>            ln = ln.rstrip("\n")
#>            if not ln.strip() or ln.lstrip().startswith("#"):
#>                continue
#>            parts = ln.split("\t")
#>            if len(parts) != 7:
#>                raise Violation(0, f"bad TSV row ({len(parts)} cols): {ln!r}")
#>            rows.append(dict(zip(TSV_COLS, parts)))
#>    return rows
#>
#>
#>def parse_decls(path):
#>    sections = collections.defaultdict(list)
#>    cur = None
#>    with open(path, encoding="utf-8") as f:
#>        for ln in f:
#>            ln = ln.rstrip("\n")
#>            if ln.startswith("## "):
#>                cur = ln[3:].strip()
#>                sections.setdefault(cur, [])
#>                continue
#>            if cur is None or ln.strip() == "":
#>                continue
#>            sections[cur].append(ln)
#>    return sections
#>
#>
#>def _parse_edits(decls):
#>    """`## edit` rows: file<TAB>old<TAB>new (old/new stripped). Returns list."""
#>    out = []
#>    for ln in decls.get("edit", []):
#>        parts = ln.split("\t")
#>        if len(parts) != 3:
#>            raise Violation(0, f"bad edit row (file<TAB>old<TAB>new): {ln!r}")
#>        out.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
#>    return out
#>
#>
#>def _parse_fragedits(decls):
#>    """`## frag-edit` rows: src_file<TAB>old<TAB>new — applied to a moved item's
#>    base fragment (TS D9.4 #2, the ForeignWorldId doctest class)."""
#>    out = []
#>    for ln in decls.get("frag-edit", []):
#>        parts = ln.split("\t")
#>        if len(parts) != 3:
#>            raise Violation(0, f"bad frag-edit row: {ln!r}")
#>        out.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
#>    return out
#>
#>
#>def _parse_comments(decls):
#>    """`## comment` rows: src:start-end<TAB>dst (interstitial // blocks)."""
#>    out = []
#>    for ln in decls.get("comment", []):
#>        parts = ln.split("\t")
#>        if len(parts) != 2:
#>            raise Violation(0, f"bad comment row (src:start-end<TAB>dst): {ln!r}")
#>        loc, dst = parts[0].strip(), parts[1].strip()
#>        try:
#>            src, rng = loc.rsplit(":", 1)
#>            a, b = rng.split("-")
#>            out.append((src, int(a), int(b), dst))
#>        except ValueError:
#>            raise Violation(0, f"bad comment row (src:start-end<TAB>dst): {ln!r}")
#>    return out
#>
#>
#>def _parse_adds(decls):
#>    """`## add` rows: file<TAB>exact-stripped-line — non-item lines a stage adds to
#>    a dst (module doc, imports, `impl Vault {`, `}`, `mod tests;`)."""
#>    out = collections.defaultdict(list)
#>    for ln in decls.get("add", []):
#>        parts = ln.split("\t", 1)
#>        if len(parts) != 2:
#>            raise Violation(0, f"bad add row (file<TAB>line): {ln!r}")
#>        out[parts[0].strip()].append(parts[1])
#>    return out
#>
#>
#>def _strip_nonblank(text):
#>    return [ln.strip() for ln in text.split("\n") if ln.strip()]
#>
#>
#>def _is_use(s):
#>    return s.startswith("use ") or s.startswith("pub use ") or s.startswith("pub(crate) use ")
#>
#>
#>def _content_lines(text):
#>    """Stripped non-blank lines EXCLUDING `use` statements — check-8 accounting
#>    ignores imports (executor-reconciled per TS D2.3, gate-verified; a private
#>    `use` cannot smuggle code behavior, and smuggled items are still caught)."""
#>    return [s for s in (ln.strip() for ln in text.split("\n")) if s and not _is_use(s)]
#>
#>
#>def _nonuse_lines(text):
#>    """Stripped non-blank lines excluding whole use STATEMENTS — multi-line
#>    aware, unlike _content_lines: a `use …::{` header pulls its continuation
#>    lines (through the terminating `;`) out of the remainder too. A use
#>    statement cannot contain an interior `;` in code, but a comment on a
#>    continuation line can — so the terminator scan runs on masked text
#>    (comment/string interiors blanked) to stay exact."""
#>    lines = text.split("\n")
#>    masked = R.mask(text).split("\n")
#>    skip = set()
#>    i = 0
#>    while i < len(lines):
#>        if _is_use(lines[i].strip()):
#>            j = i
#>            skip.add(j)
#>            while ";" not in masked[j] and j + 1 < len(lines):
#>                j += 1
#>                skip.add(j)
#>            i = j + 1
#>        else:
#>            i += 1
#>    out = []
#>    for k, ln in enumerate(lines):
#>        s = ln.strip()
#>        if s and k not in skip:
#>            out.append(s)
#>    return out
#>
#>
#># ---- check 1: forbidden zone + allowed files -----------------------------
#>
#>def check1(root, base, decls):
#>    changed = changed_files(root, base)
#>    forbid = ([] if LIFTED else list(GUARD)) + [x.strip() for x in decls.get("forbid", [])]
#>    allowed = set(x.strip() for x in decls.get("allowed", []))
#>    for f in changed:
#>        for fb in forbid:
#>            if fb.endswith("/"):
#>                if f.startswith(fb):
#>                    raise Violation(1, f"forbidden-zone file touched: {f} (under {fb})")
#>            elif f == fb:
#>                raise Violation(1, f"forbidden-zone file touched: {f}")
#>        if f not in allowed:
#>            raise Violation(1, f"changed file not in allowed list: {f}")
#>    return (f"OK check 1 (forbidden-zone{' [guard lifted]' if LIFTED else ''} + "
#>            f"allowed-files): {len(changed)} changed file(s)")
#>
#>
#># ---- check 2: surface inventory + flat-name-set --------------------------
#>
#>def _counter_diff(base_c, head_c):
#>    return head_c - base_c, base_c - head_c
#>
#>
#>def _parse_signed(lines):
#>    added, removed = collections.Counter(), collections.Counter()
#>    for ln in lines:
#>        if not ln:
#>            continue
#>        sign, content = ln[0], ln[1:].strip()
#>        if sign == "+":
#>            added[content] += 1
#>        elif sign == "-":
#>            removed[content] += 1
#>        else:
#>            raise Violation(2, f"bad decl/impl-delta line (no +/-): {ln!r}")
#>    return added, removed
#>
#>
#>def _parse_signed_impl(lines):
#>    added, removed = collections.Counter(), collections.Counter()
#>    for ln in lines:
#>        if not ln:
#>            continue
#>        sign, content = ln[0], ln[1:].strip()
#>        if sign not in "+-":
#>            raise Violation(2, f"bad impl-delta sign (expected leading +/-): {ln!r}")
#>        parts = content.split("\t")
#>        if len(parts) != 2:
#>            raise Violation(2, f"bad impl-delta line (file<TAB>header): {ln!r}")
#>        (added if sign == "+" else removed)[(parts[0].strip(), parts[1].strip())] += 1
#>    return added, removed
#>
#>
#>def _parse_filemoves(decls):
#>    out = []
#>    for ln in decls.get("filemove", []):
#>        parts = ln.split("\t")
#>        if len(parts) != 2:
#>            raise Violation("F", f"bad filemove row (src<TAB>dst): {ln!r}")
#>        out.append((parts[0].strip(), parts[1].strip()))
#>    # one-to-one: a shared src duplicates a file, a shared dst drops one —
#>    # neither is a relocation, and check C's exemption would hide the rest.
#>    srcs = [s for s, _ in out]
#>    dsts = [d for _, d in out]
#>    if len(set(srcs)) != len(srcs) or len(set(dsts)) != len(dsts):
#>        raise Violation("F", f"filemove rows must be one-to-one "
#>                             f"(duplicate src or dst): {out}")
#>    return out
#>
#>
#>def check2(root, base, decls):
#>    changed = [f for f in changed_files(root, base)
#>               if f.endswith(".rs") and f.startswith("crates/")]
#>    # `## filemove` (dst -> src): check F proves dst is byte-identical to
#>    # src at base, so a relocated file's impl headers are keyed under the
#>    # base path — the per-file (f, h) keys then net out instead of reading
#>    # as one file's removals plus another file's additions. The global decl
#>    # Counter needs no remap: identical decl strings cancel on their own.
#>    fm = {d: s for (s, d) in _parse_filemoves(decls)}
#>    base_inv, head_inv = collections.Counter(), collections.Counter()
#>    base_impl, head_impl = collections.Counter(), collections.Counter()
#>    lib_touched = False
#>    for f in changed:
#>        if f.endswith("/lib.rs"):
#>            lib_touched = True
#>        bt = base_file(root, base, f)
#>        if bt is not None:
#>            d = R.Doc(bt)
#>            base_inv.update(R.inventory(d))
#>            base_impl.update((f, h) for h in R.impl_headers(d))
#>        ht = head_file(root, f)
#>        if ht is not None:
#>            d = R.Doc(ht)
#>            head_inv.update(R.inventory(d))
#>            head_impl.update((fm.get(f, f), h) for h in R.impl_headers(d))
#>
#>    add, rem = _counter_diff(base_inv, head_inv)
#>    exp_add, exp_rem = _parse_signed(decls.get("decl", []))
#>    if add != exp_add or rem != exp_rem:
#>        _report_diff(2, "declaration inventory (2a)", add, rem, exp_add, exp_rem)
#>    add_i, rem_i = _counter_diff(base_impl, head_impl)
#>    exp_add_i, exp_rem_i = _parse_signed_impl(decls.get("impl-delta", []))
#>    if add_i != exp_add_i or rem_i != exp_rem_i:
#>        _report_diff(2, "impl-header inventory (2b)", add_i, rem_i, exp_add_i, exp_rem_i,
#>                     fmt=lambda t: f"{t[0]}\t{t[1]}")
#>
#>    flat_note = ""
#>    if lib_touched or decls.get("flat-name-check"):
#>        libpath = "crates/oneiron/src/lib.rs"
#>        bt = base_file(root, base, libpath)
#>        ht = head_file(root, libpath)
#>        if bt is not None and ht is not None:
#>            bset = R.flat_names(R.Doc(bt))
#>            hset = R.flat_names(R.Doc(ht))
#>            if bset != hset:
#>                raise Violation(2, "flat-name façade SET changed (must diff empty):\n"
#>                                   f"  removed: {sorted(bset - hset)}\n  added: {sorted(hset - bset)}")
#>            flat_note = f", flat-name set stable ({len(bset)})"
#>    return (f"OK check 2 (surface inventory): {len(add)} decl+ / {len(rem)} decl- / "
#>            f"{len(add_i)} impl+ / {len(rem_i)} impl-{flat_note}")
#>
#>
#>def _report_diff(check, label, add, rem, exp_add, exp_rem, fmt=str):
#>    lines = [f"{label} mismatch (actual HEAD-vs-BASE vs manifest):"]
#>    for tag, actual, expected in (("added(+)", add, exp_add), ("removed(-)", rem, exp_rem)):
#>        for k in sorted(expected - actual, key=fmt):
#>            lines.append(f"  {tag} declared but MISSING: {fmt(k)}")
#>        for k in sorted(actual - expected, key=fmt):
#>            lines.append(f"  {tag} observed but UNDECLARED: {fmt(k)}")
#>    raise Violation(check, "\n".join(lines))
#>
#>
#># ---- check E: declared-edit validation -----------------------------------
#>
#>def checkE(root, base, decls, tsv):
#>    edits = _parse_edits(decls)
#>    fragedits = _parse_fragedits(decls)
#>    for f, old, new in edits:
#>        if not R.edit_delta_ok(old, new):
#>            raise Violation("E", f"illegal edit delta (not a single ::-path region): "
#>                               f"{f}: {old!r} -> {new!r}")
#>        bt = base_file(root, base, f)
#>        if bt is None:
#>            raise Violation("E", f"edit base file missing: {f}")
#>        base_lines = _strip_nonblank(bt)
#>        if base_lines.count(old) == 0:
#>            raise Violation("E", f"edit old-line not present at BASE {f}: {old!r}")
#>        ht = head_file(root, f)
#>        head_lines = _strip_nonblank(ht) if ht is not None else []
#>        if head_lines.count(new) == 0:
#>            # rustfmt reflows an applied edit across lines when the ::-path
#>            # swap pushes the line past the width limit (types->registry on a
#>            # 99-char guard). Fall back to token-form matching: canon is
#>            # whitespace/reflow-insensitive but keeps string literals intact,
#>            # so a reflowed application passes and content changes still fail.
#>            cht = " " + R.canon(ht or "") + " "
#>            if " " + R.canon(new) + " " not in cht:
#>                raise Violation("E", f"edit new-line not present at HEAD {f}: {new!r}")
#>            if " " + R.canon(old) + " " in cht:
#>                raise Violation("E", f"edit old-line still present at HEAD {f}: {old!r}")
#>        if head_lines.count(old) != 0:
#>            raise Violation("E", f"edit old-line still present at HEAD {f}: {old!r}")
#>    for src, old, new in fragedits:
#>        if not R.edit_delta_ok(old, new):
#>            raise Violation("E", f"illegal frag-edit delta: {src}: {old!r} -> {new!r}")
#>        bt = base_file(root, base, src)
#>        if bt is None or old not in _strip_nonblank(bt):
#>            raise Violation("E", f"frag-edit old-line not at BASE {src}: {old!r}")
#>    return f"OK check E (declared edits): {len(edits)} consumer edit(s), {len(fragedits)} frag-edit(s)"
#>
#>
#>def _edits_for_file(edits, f):
#>    return [(old, new) for (ef, old, new) in edits if ef == f]
#>
#>
#># ---- check 3: moved-block byte equivalence -------------------------------
#>
#>def _exactly_one(matches, where, row):
#>    if len(matches) == 0:
#>        raise Violation(3, f"item NOT FOUND in {where} (item not yet moved / wrong key): "
#>                           f"kind={row['kind']} container={row['container']!r} "
#>                           f"name={row['item_name']!r} cfg={row['cfg']!r}")
#>    if len(matches) > 1:
#>        raise Violation(3, f"AMBIGUOUS: {len(matches)} matches in {where}: "
#>                           f"kind={row['kind']} name={row['item_name']!r}")
#>    return matches[0]
#>
#>
#>def mod_inner(doc, it):
#>    mls = doc.mlines[it["sig_line"]].lstrip()
#>    start_off = doc.loff[it["sig_line"]] + (len(doc.mlines[it["sig_line"]]) - len(mls))
#>    bo, eo = R._scan_extent(doc, start_off)
#>    return doc.src[bo + 1:eo]
#>
#>
#>def _find_row(doc, row):
#>    if row["kind"] == "method":
#>        return R.find_item(doc, "method", row["container"], row["item_name"], row["cfg"])
#>    if row["kind"] == "impl":
#>        return R.find_item(doc, "impl", "-", row["item_name"], row["cfg"])
#>    if row["container"] and row["container"] not in ("-", ""):
#>        return R.find_item(doc, row["kind"], row["container"], row["item_name"], row["cfg"])
#>    return R.find_item(doc, row["kind"], "-", row["item_name"], row["cfg"])
#>
#>
#>def check3(root, base, tsv, decls):
#>    edits = _parse_edits(decls)
#>    fragedits = _parse_fragedits(decls)
#>    n = 0
#>    for row in tsv:
#>        bt = base_file(root, base, row["src_file"])
#>        if bt is None:
#>            raise Violation(3, f"src_file missing at base: {row['src_file']}")
#>        bdoc = R.Doc(bt)
#>
#>        if row["kind"] == "mod":
#>            bm = _exactly_one(R.find_item(bdoc, "mod", "-", row["item_name"], row["cfg"]),
#>                              f"BASE {row['src_file']}", row)
#>            base_frag = mod_inner(bdoc, bm)
#>            fe = [(o, nw) for (s, o, nw) in fragedits if s == row["src_file"]]
#>            base_frag = R.apply_edits(base_frag, fe)
#>            ht = head_file(root, row["dst_file"])
#>            if ht is None:
#>                raise Violation(3, f"dst not present — item not yet moved: {row['dst_file']}")
#>            # mod_inner starts right after `{`, so the fragment carries a leading
#>            # newline that rustfmt preserves — strip outer blank lines on both
#>            # sides before comparing.
#>            base_norm = R.rustfmt(base_frag.strip("\n") + "\n").rstrip("\n")
#>            head_norm = R.rustfmt(ht.strip("\n") + "\n").rstrip("\n")
#>            if base_norm != head_norm:
#>                raise Violation(3, f"MOD body mismatch: {row['src_file']}:mod {row['item_name']} "
#>                                   f"!= {row['dst_file']}")
#>            # src-side: the inline mod must be gone, replaced by a declaration-only
#>            # mount (`mod NAME;`) so cargo actually wires the new dst file — without
#>            # this a copy-left-behind (or unwired dst) passes as a "move".
#>            hsrc = head_file(root, row["src_file"])
#>            if hsrc is None:
#>                raise Violation(3, f"src missing at HEAD for mod row: {row['src_file']}")
#>            hm = _exactly_one(R.find_item(R.Doc(hsrc), "mod", "-", row["item_name"], row["cfg"]),
#>                              f"HEAD {row['src_file']}", row)
#>            if hm["body_open_line"] is not None:
#>                raise Violation(3, f"inline mod {row['item_name']} still has a body in src at HEAD "
#>                                   f"({row['src_file']}) — expected declaration-only mount "
#>                                   f"(mod {row['item_name']};)")
#>            n += 1
#>            continue
#>
#>        bm = _exactly_one(_find_row(bdoc, row), f"BASE {row['src_file']}", row)
#>        base_text = R.item_text(bdoc, bm)
#>        fe = [(o, nw) for (s, o, nw) in fragedits if s == row["src_file"]]
#>        base_text = R.apply_edits(base_text, _edits_for_file(edits, row["src_file"]) + fe)
#>
#>        ht = head_file(root, row["dst_file"])
#>        if ht is None:
#>            raise Violation(3, f"dst not present — item not yet moved: {row['dst_file']} "
#>                               f"(item {row['item_name']})")
#>        hdoc = R.Doc(ht)
#>        hm = _exactly_one(_find_row(hdoc, row), f"HEAD {row['dst_file']}", row)
#>        head_text = R.item_text(hdoc, hm)
#>
#>        if row["src_file"] != row["dst_file"]:
#>            hsrc = head_file(root, row["src_file"])
#>            if hsrc is not None:
#>                still = _find_row(R.Doc(hsrc), row)
#>                if len(still) != 0:
#>                    raise Violation(3, f"item STILL present in src at HEAD "
#>                                       f"({row['src_file']}): {row['item_name']} — copy left behind")
#>
#>        is_fn = row["kind"] in ("method", "fn")
#>        hc = row["header_change"] == "yes"
#>        try:
#>            base_norm = R.normalized_fragment(base_text, is_fn, hc)
#>            head_norm = R.normalized_fragment(head_text, is_fn, hc)
#>        except Exception as e:
#>            raise Violation(3, f"rustfmt/normalise failed for {row['item_name']}: {e}")
#>        if base_norm != head_norm:
#>            raise Violation(3, f"MOVED-BLOCK mismatch: {row['item_name']} "
#>                               f"({row['src_file']} -> {row['dst_file']})\n"
#>                               + _first_diff(base_norm, head_norm))
#>        n += 1
#>    return f"OK check 3 (moved-block equivalence): {n} item(s) byte-identical"
#>
#>
#>def _first_diff(a, b):
#>    al, bl = a.split("\n"), b.split("\n")
#>    for i in range(max(len(al), len(bl))):
#>        x = al[i] if i < len(al) else "<eof>"
#>        y = bl[i] if i < len(bl) else "<eof>"
#>        if x != y:
#>            return f"    first diff @ line {i+1}:\n      BASE: {x!r}\n      HEAD: {y!r}"
#>    return "    (lengths differ)"
#>
#>
#># ---- check 4: frozen anchors ---------------------------------------------
#>
#>def check4(root, base, decls):
#>    edits = _parse_edits(decls)
#>    n = 0
#>    for ln in decls.get("anchors", []):
#>        parts = ln.split("\t")
#>        if len(parts) != 5:
#>            raise Violation(4, f"bad anchor row (need 5 cols): {ln!r}")
#>        kind, container, name, cfg, f = [p.strip() for p in parts]
#>        bt = base_file(root, base, f)
#>        ht = head_file(root, f)
#>        if bt is None or ht is None:
#>            raise Violation(4, f"anchor file missing base/head: {f}")
#>        bdoc, hdoc = R.Doc(bt), R.Doc(ht)
#>        row = {"kind": kind, "container": container, "item_name": name, "cfg": cfg}
#>        bm = _exactly_one(_find_row(bdoc, row), f"BASE {f}", row)
#>        hm = _exactly_one(_find_row(hdoc, row), f"HEAD {f}", row)
#>        is_fn = kind in ("method", "fn")
#>        base_text = R.apply_edits(R.item_text(bdoc, bm), _edits_for_file(edits, f))
#>        base_norm = R.normalized_fragment(base_text, is_fn, False)
#>        head_norm = R.normalized_fragment(R.item_text(hdoc, hm), is_fn, False)
#>        if base_norm != head_norm:
#>            raise Violation(4, f"FROZEN ANCHOR changed: {kind} {name} in {f}\n"
#>                               + _first_diff(base_norm, head_norm))
#>        n += 1
#>    return f"OK check 4 (frozen anchors): {n} anchor(s) unchanged"
#>
#>
#># ---- check 5: name-uniqueness (api stages) -------------------------------
#>
#>def check5(root, stage, decls):
#>    globs = [g.strip() for g in decls.get("uniqueness", [])]
#>    if not globs:
#>        return "OK check 5 (name-uniqueness): skipped"
#>    names = collections.Counter()
#>    seen = 0
#>    for g in globs:
#>        for f in sorted(glob.glob(os.path.join(root, g))):
#>            rel = os.path.relpath(f, root)
#>            ht = head_file(root, rel)
#>            if ht is None:
#>                continue
#>            seen += 1
#>            for it in R.enumerate_items(R.Doc(ht)):
#>                if it["kind"] in ("impl", "use", "mod") or not it["name"]:
#>                    continue
#>                # key by Rust namespace: a type and a value sharing a name do not
#>                # collide under glob re-exports, so they must not trip the gate
#>                ns = {"struct": "type", "enum": "type", "trait": "type", "type": "type",
#>                      "union": "type", "fn": "value", "const": "value",
#>                      "static": "value"}.get(it["kind"], it["kind"])
#>                names[(ns, it["name"])] += 1
#>    dups = {k: v for k, v in names.items() if v > 1}
#>    if dups:
#>        raise Violation(5, "duplicate top-level names across modules: "
#>                           + ", ".join(f"{k[1]} ({k[0]})×{v}" for k, v in sorted(dups.items())))
#>    return f"OK check 5 (name-uniqueness): {seen} file(s), no duplicates"
#>
#>
#># ---- check 6: error-literal inventory ------------------------------------
#>
#>_ERRLIT = re.compile(r'Error::(?:Invalid\w+Body|InvariantViolation|CorruptedIndex|Invalid\w+|MaintenanceKindNotWritable)\(\s*"(?:\\.|[^"\\])*"')
#>
#># scaffolding lines that legitimately remain after every item is excised from a
#># deleted file (check X): module doc, imports, attrs, mod decls, mod-tests shell braces.
#>_SCAFFOLD = re.compile(r'^(//!|use\s|pub\s+use\s|pub\(crate\)\s+use\s|#!?\[|(pub(\([^)]*\))?\s+)?mod\b|\})')
#>
#>
#>def _strip_line_comments(text):
#>    return "\n".join(re.sub(r"//.*$", "", ln) for ln in text.split("\n"))
#>
#>
#>def check6(root, base, decls):
#>    files = [x.strip() for x in decls.get("error-literal", [])]
#>    if not files:
#>        return "OK check 6 (error-literal): skipped"
#>    for f in files:
#>        bt = base_file(root, base, f) or ""
#>        ht = head_file(root, f) or ""
#>        bc = collections.Counter(_ERRLIT.findall(_strip_line_comments(bt)))
#>        hc = collections.Counter(_ERRLIT.findall(_strip_line_comments(ht)))
#>        if bc != hc:
#>            raise Violation(6, f"error-literal multiset changed in {f}: "
#>                               f"+{list((hc-bc).elements())} -{list((bc-hc).elements())}")
#>    return f"OK check 6 (error-literal): {len(files)} module(s) unchanged"
#>
#>
#># ---- check 8: insertion integrity ----------------------------------------
#>
#>def _excise_items(doc, rows_for_dst):
#>    drop = set()
#>    for row in rows_for_dst:
#>        if row["kind"] == "mod":
#>            continue
#>        m = _find_row(doc, row)
#>        if len(m) != 1:
#>            raise Violation(8, f"check8 could not uniquely locate {row['item_name']} "
#>                               f"in dst {row['dst_file']} ({len(m)} matches)")
#>        it = m[0]
#>        drop.update(range(it["lead_start"], it["end_line"] + 1))
#>    return drop
#>
#>
#>def check8(root, base, tsv, decls):
#>    edits = _parse_edits(decls)
#>    adds = _parse_adds(decls)
#>    comments = _parse_comments(decls)
#>    by_dst = collections.defaultdict(list)
#>    for row in tsv:
#>        by_dst[row["dst_file"]].append(row)
#>
#>    n = 0
#>    for dst, rows in by_dst.items():
#>        if all(r["kind"] == "mod" for r in rows):
#>            continue  # pure tests-mod move: check 3 covers it (whole-file compare)
#>        ht = head_file(root, dst)
#>        if ht is None:
#>            raise Violation(8, f"dst missing at HEAD: {dst}")
#>        hdoc = R.Doc(ht)
#>        drop = _excise_items(hdoc, rows)
#>        remaining = "\n".join(ln for i, ln in enumerate(hdoc.lines) if i not in drop)
#>        head_set = collections.Counter(_content_lines(remaining))
#>
#>        bt = base_file(root, base, dst)
#>        base_edited = R.apply_edits(bt, _edits_for_file(edits, dst)) if bt is not None else ""
#>        base_set = collections.Counter(_content_lines(base_edited))
#>
#>        # dst import delta: plain imports stay executor-reconciled (they are
#>        # compile-verified and moved code is byte-identical), but the sharp
#>        # shadow vectors must be DECLARED in ## add — aliases (`as`) and glob
#>        # imports can silently re-bind bare names in pre-existing dst code
#>        # (explicit use beats `use super::*`), and `pub use` changes API surface
#>        base_uses = collections.Counter(
#>            ln.strip() for ln in base_edited.split("\n") if _is_use(ln.strip()))
#>        head_uses = collections.Counter(
#>            ln.strip() for ln in remaining.split("\n") if _is_use(ln.strip()))
#>        declared_uses = collections.Counter(
#>            s for s in (a.strip() for a in adds.get(dst, [])) if _is_use(s))
#>        for u in (head_uses - base_uses - declared_uses):
#>            if (" as " in u or "::*" in u
#>                    or u.startswith("pub use") or u.startswith("pub(crate) use")):
#>                raise Violation(8, f"undeclared hazardous import in dst {dst}: {u!r} "
#>                                   f"(aliases, globs, and re-exports must be declared in ## add)")
#>
#>        add_set = collections.Counter(s for s in (a.strip() for a in adds.get(dst, []))
#>                                      if s and not _is_use(s))
#>        for (csrc, ca, cb, cdst) in comments:
#>            if cdst != dst:
#>                continue
#>            cbt = base_file(root, base, csrc)
#>            if cbt is None:
#>                raise Violation(8, f"comment src missing at base: {csrc}")
#>            clines = "\n".join(cbt.split("\n")[ca - 1:cb])
#>            add_set.update(_content_lines(clines))
#>
#>        expected = base_set + add_set
#>        if head_set != expected:
#>            lines = [f"insertion integrity FAIL in {dst}:"]
#>            for k in sorted(head_set - expected):
#>                lines.append(f"  UNDECLARED line present in dst: {k!r}")
#>            for k in sorted(expected - head_set):
#>                lines.append(f"  declared/base line MISSING from dst: {k!r}")
#>            raise Violation(8, "\n".join(lines))
#>        n += 1
#>    return f"OK check 8 (insertion integrity): {n} dst file(s) clean"
#>
#>
#># ---- check F: file relocation (B1 git mv) --------------------------------
#>
#># source-relative constructs rebind against the new directory while staying
#># byte-identical: include!/include_str!/include_bytes! paths, #[path] mounts,
#># and declaration-only `mod x;` rows can compile green against the WRONG file
#># if one exists at the destination-relative location. Such files need an
#># edit-based stage, not a filemove.
#>_RELOC_UNSAFE = re.compile(
#>    r"\binclude(?:_str|_bytes)?!|#\s*\[\s*path\b"
#>    r"|^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*;", re.M)
#>
#>
#>def checkF(root, base, decls, tsv):
#>    n = 0
#>    moved = set(r["src_file"] for r in tsv) | set(r["dst_file"] for r in tsv)
#>    edited = ({f for (f, _, _) in _parse_edits(decls)}
#>              | {f for (f, _, _) in _parse_fragedits(decls)})
#>    for src, dst in _parse_filemoves(decls):
#>        # no overlap with item-move or edit rows: this check proves dst equals
#>        # src-at-base byte-for-byte, so an item ALSO moved out of (or edited
#>        # in) the same file would survive in dst silently duplicated — the
#>        # TSV absence check runs against the deleted src path and trivially
#>        # passes.
#>        for p in (src, dst):
#>            if p in moved or p in edited:
#>                raise Violation("F", f"filemove path overlaps item-move/edit "
#>                                     f"rows (must be a pure relocation): {p}")
#>        bsrc = base_file(root, base, src)
#>        hdst = head_file(root, dst)
#>        hsrc = head_file(root, src)
#>        if bsrc is None:
#>            raise Violation("F", f"filemove src missing at base: {src}")
#>        if hdst is None:
#>            raise Violation("F", f"filemove dst missing at HEAD: {dst}")
#>        if hsrc is not None:
#>            raise Violation("F", f"filemove src still present at HEAD: {src}")
#>        if base_file(root, base, dst) is not None:
#>            raise Violation("F", f"filemove dst already exists at base "
#>                                 f"(relocation cannot overwrite): {dst}")
#>        if bsrc != hdst:
#>            raise Violation("F", f"filemove content changed: {src} != {dst} "
#>                               f"(relocation must be byte-identical)")
#>        m = _RELOC_UNSAFE.search(R.mask(bsrc))
#>        if m:
#>            raise Violation("F", f"filemove src contains relocation-unsafe "
#>                                 f"construct {m.group(0)!r} (include!/"
#>                                 f"include_str!/include_bytes!/#[path]/"
#>                                 f"`mod x;`): {src}")
#>        n += 1
#>    return f"OK check F (file relocation): {n} file(s) relocated byte-identically"
#>
#>
#># ---- check C: consumer-diff-shape (anti-smuggle net) ---------------------
#>
#>def _git_diff_file(root, base, f):
#>    p = subprocess.run(["git", "-C", root, "diff", "--no-color", "-U0", base, "HEAD", "--", f],
#>                       capture_output=True, text=True)
#>    return p.stdout if p.returncode == 0 else ""
#>
#>
#>def checkC(root, base, tsv, decls):
#>    """A CONSUMER file's non-import content must match BASE line-for-line
#>    (compared as stripped non-blank lines, the gate-wide granularity)
#>    modulo the `## edit` rows declared for THAT file. Import statements —
#>    including the continuation lines of multi-line `use …::{…};` blocks —
#>    are executor-reconciled and verified by the build, check 2 and the
#>    flat-name set instead. Replaces the per-diff-line shape check, which
#>    (a) could not recognize multi-line use-block continuation lines and
#>    (b) keyed declared edits globally, letting an edit for file A authorize
#>    the same-looking change in file B."""
#>    edits = _parse_edits(decls)
#>    fragedits = _parse_fragedits(decls)
#>    dst = set(r["dst_file"] for r in tsv)
#>    src = set(r["src_file"] for r in tsv)
#>    # `## consumer-exempt`: files with declared STRUCTURAL edits that aren't
#>    # import-shaped (e.g. the U stage deleting #[path] mod mounts in types.rs).
#>    # Verified elsewhere: gate compile + conventions-gate #[path]==0 + flat-name set.
#>    # `## exhaust`: whole-file deletions validated by check_exhaustion, which
#>    # runs after this check — without the exemption the deletion false-fails
#>    # here first.
#>    # `## filemove`: both sides of a relocation are verified byte-identical
#>    # by check F, which is strictly stronger than this check.
#>    fm_files = {p for sd in _parse_filemoves(decls) for p in sd}
#>    exempt = dst | src | fm_files | {"crates/oneiron/src/lib.rs"} | set(
#>        x.strip() for x in decls.get("consumer-exempt", [])) | set(
#>        x.strip() for x in decls.get("exhaust", []))
#>    n = 0
#>    for f in changed_files(root, base):
#>        if not f.endswith(".rs") or f in exempt:
#>            continue
#>        n += 1
#>        bt = base_file(root, base, f) or ""
#>        ht = head_file(root, f) or ""
#>        fe = ([(o, nw) for (ef, o, nw) in edits if ef == f]
#>              + [(o, nw) for (sf, o, nw) in fragedits if sf == f])
#>        base_rem = _nonuse_lines(R.apply_edits(bt, fe)) if fe else _nonuse_lines(bt)
#>        head_rem = _nonuse_lines(ht)
#>        if base_rem != head_rem:
#>            # rustfmt may reflow a line the declared edit lengthened past the
#>            # width limit — the line lists then differ only in wrapping. canon
#>            # compares the joined token streams (string literals kept intact),
#>            # so pure reflow passes and any token change still fails.
#>            if R.canon("\n".join(base_rem)) == R.canon("\n".join(head_rem)):
#>                continue
#>            import difflib
#>            d = [ln for ln in difflib.unified_diff(base_rem, head_rem, lineterm="", n=0)
#>                 if not ln.startswith(("---", "+++"))]
#>            raise Violation("C", f"consumer non-import content changed beyond declared "
#>                               f"edits in {f} (first divergences, base-with-edits vs HEAD):\n"
#>                               + "\n".join(d[:12]))
#>    return f"OK check C (consumer-diff-shape): {n} consumer file(s) import-only beyond declared edits"
#>
#>
#># ---- check X: src-exhaustion (T12 finale) --------------------------------
#>
#>def check_exhaustion(root, base, decls):
#>    ex = [x.strip() for x in decls.get("exhaust", [])]
#>    if not ex:
#>        return "OK check X (src-exhaustion): skipped"
#>    movesdir = decls["_movesdir"][0]
#>    union_stages = decls["_exhaust_stages"]
#>    n = 0
#>    for src in ex:
#>        bt = base_file(root, base, src)
#>        if bt is None:
#>            raise Violation("X", f"exhaustion src missing at base: {src}")
#>        if head_file(root, src) is not None:
#>            raise Violation("X", f"exhaustion src still present at HEAD "
#>                                 f"(must be deleted): {src}")
#>        doc = R.Doc(bt)
#>        drop = set()
#>        for st in union_stages:
#>            stsv = parse_tsv(os.path.join(movesdir, f"{st}.tsv"))
#>            sdecls = parse_decls(os.path.join(movesdir, f"{st}.decls"))
#>            for row in stsv:
#>                if row["src_file"] != src:
#>                    continue
#>                if row["kind"] == "mod":
#>                    m = R.find_item(doc, "mod", "-", row["item_name"], row["cfg"])
#>                else:
#>                    m = _find_row(doc, row)
#>                if len(m) == 1:
#>                    drop.update(range(m[0]["lead_start"], m[0]["end_line"] + 1))
#>            for (csrc, ca, cb, cdst) in _parse_comments(sdecls):
#>                if csrc == src:
#>                    drop.update(range(ca - 1, cb))
#>        # excise whole `use` items (multi-line import trees) and SAFE `mod` items: the
#>        # `mod tests` shell (its fns were moved individually above) + declaration-only
#>        # `#[path] pub mod` mounts. A non-tests mod WITH a body is NOT auto-excised — its
#>        # items must be moved individually or they surface as residue (MINOR: prevents a
#>        # future missed mod's contents being silently swallowed).
#>        for it in R.enumerate_items(doc):
#>            if it["kind"] == "use":
#>                drop.update(range(it["lead_start"], it["end_line"] + 1))
#>            elif it["kind"] == "mod" and (it["name"] == "tests" or it["body_open_line"] is None):
#>                drop.update(range(it["lead_start"], it["end_line"] + 1))
#>        # residue must be SCAFFOLDING only (D9.4 #3): module doc, imports, attrs, mod
#>        # decls, and the emptied `mod tests { use super::*; }` shell all vanish with the
#>        # deleted file — they are not items. Anything else = an item that wasn't moved.
#>        residue = [ln.strip() for i, ln in enumerate(doc.lines)
#>                   if i not in drop and ln.strip() and not _SCAFFOLD.match(ln.strip())]
#>        if residue:
#>            raise Violation("X", f"src-exhaustion FAIL: {src} has {len(residue)} "
#>                               f"non-scaffolding line(s) — item not moved, first: {residue[0]!r}")
#>        n += 1
#>    return f"OK check X (src-exhaustion): {n} src file(s) fully accounted"
#>
#>
#># ---- driver --------------------------------------------------------------
#>
#>def run_checks(root, stage, base, movesdir):
#>    tsv = parse_tsv(os.path.join(movesdir, f"{stage}.tsv"))
#>    decls = parse_decls(os.path.join(movesdir, f"{stage}.decls"))
#>    decls["_movesdir"] = [movesdir]
#>    decls["_exhaust_stages"] = [x.strip() for x in decls.get("exhaust-stages", [])]
#>    results = [
#>        check1(root, base, decls),
#>        check2(root, base, decls),
#>        checkE(root, base, decls, tsv),
#>        check3(root, base, tsv, decls),
#>        check4(root, base, decls),
#>        check5(root, stage, decls),
#>        check6(root, base, decls),
#>        check8(root, base, tsv, decls),
#>        checkC(root, base, tsv, decls),
#>        checkF(root, base, decls, tsv),
#>        check_exhaustion(root, base, decls),
#>    ]
#>    return results
#>
#>
#>def main(argv):
#>    if len(argv) < 4 or argv[0] != "checks":
#>        print("usage: driver checks <root> <stage> <base> [<movesdir>]", file=sys.stderr)
#>        return 2
#>    root, stage, base = argv[1], argv[2], argv[3]
#>    movesdir = argv[4] if len(argv) > 4 else os.path.join(root, "scripts/refactor/moves")
#>    try:
#>        for line in run_checks(root, stage, base, movesdir):
#>            print(line)
#>    except Violation as v:
#>        print(f"CONFORMANCE FAILED at check {v.check}:\n{v}", file=sys.stderr)
#>        return 1
#>    except RuntimeError as e:
#>        print(f"CONFORMANCE ERROR (tooling, not a manifest verdict): {e}", file=sys.stderr)
#>        return 1
#>    except ValueError as e:
#>        print(f"CONFORMANCE ERROR (manifest parse): {e}", file=sys.stderr)
#>        return 1
#>    print(f"CONFORMANCE checks 1-8 PASSED for stage {stage}")
#>    return 0
#>
#>
#>if __name__ == "__main__":
#>    sys.exit(main(sys.argv[1:]))
#>
#PYEOF_END
