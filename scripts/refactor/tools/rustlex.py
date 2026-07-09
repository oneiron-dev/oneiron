#!/usr/bin/env python3
"""Rust structural extractor for the refactor conformance script.

Shape-level (NOT semantic) parsing of rustfmt-formatted Rust:
  - mask(): blank out string/char/comment interiors so brace counting is reliable.
  - canon(): token-split + single-space join -> whitespace/reflow-insensitive form.
  - enumerate_items(): top-level items (depth 0) + their impl-block methods (depth 1).
  - inventory(): every `pub..` declaration head (any indent) -> canon heads.
  - impl_headers(): every `impl ..` header (any indent) -> (relpath is added by caller).
  - find_item(): locate a manifest row's item by (kind, container, item_name, cfg),
    enforcing exactly-one-match.
  - extract/format helpers for the moved-block byte comparison.

Relies on rustfmt having already normalised the tree (one item per line start).
"""
import re
import subprocess
import sys
import os
import tempfile

RUSTFMT = os.environ.get("RUSTFMT_BIN", "rustfmt")

# ---------------------------------------------------------------------------
# masking
# ---------------------------------------------------------------------------

_RAW_OPEN = re.compile(r'(?:b|c)?r(#*)"')
_STR_OPEN = re.compile(r'(?:b|c)?"')
_CHAR = re.compile(r"'(?:\\u\{[0-9A-Fa-f_]+\}|\\.|[^'\\\n])'")


def _is_ident(ch):
    return ch.isalnum() or ch == "_"


def mask(src):
    """Return a same-length copy of src with string/char/comment interiors
    replaced by spaces (newlines preserved), so { } ( ) [ ] counting is safe."""
    n = len(src)
    res = list(src)
    i = 0
    while i < n:
        c = src[i]
        prev = src[i - 1] if i > 0 else ""
        boundary = not (_is_ident(prev))
        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i
            while j < n and src[j] != "\n":
                res[j] = " "
                j += 1
            i = j
            continue
        # block comment (nestable)
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            res[i] = res[i + 1] = " "
            j = i + 2
            while j < n and depth > 0:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    res[j] = res[j + 1] = " "
                    j += 2
                    continue
                if src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    res[j] = res[j + 1] = " "
                    j += 2
                    continue
                if src[j] != "\n":
                    res[j] = " "
                j += 1
            i = j
            continue
        # raw string (needs a token boundary before the prefix)
        if boundary:
            m = _RAW_OPEN.match(src, i)
            if m:
                hashes = m.group(1)
                close = '"' + hashes
                body = m.end()
                for k in range(i, body):
                    if src[k] != "\n":
                        res[k] = " "
                idx = src.find(close, body)
                if idx < 0:
                    idx = n - len(close)
                end = idx + len(close)
                for k in range(body, min(end, n)):
                    if src[k] != "\n":
                        res[k] = " "
                i = end
                continue
            m = _STR_OPEN.match(src, i)
            if m:
                j = m.end()
                for k in range(i, j):
                    if src[k] != "\n":
                        res[k] = " "
                while j < n:
                    if src[j] == "\\":
                        if src[j] != "\n":
                            res[j] = " "
                        if j + 1 < n and src[j + 1] != "\n":
                            res[j + 1] = " "
                        j += 2
                        continue
                    if src[j] == '"':
                        res[j] = " "
                        j += 1
                        break
                    if src[j] != "\n":
                        res[j] = " "
                    j += 1
                i = j
                continue
        else:
            # plain '"' with no prefix still starts a string even mid-token-ish
            if c == '"':
                j = i + 1
                res[i] = " "
                while j < n:
                    if src[j] == "\\":
                        res[j] = " "
                        if j + 1 < n and src[j + 1] != "\n":
                            res[j + 1] = " "
                        j += 2
                        continue
                    if src[j] == '"':
                        res[j] = " "
                        j += 1
                        break
                    if src[j] != "\n":
                        res[j] = " "
                    j += 1
                i = j
                continue
        # char literal vs lifetime
        if c == "'":
            m = _CHAR.match(src, i)
            if m:
                for k in range(i, m.end()):
                    if src[k] != "\n":
                        res[k] = " "
                i = m.end()
                continue
            i += 1
            continue
        i += 1
    return "".join(res)


# ---------------------------------------------------------------------------
# canonicalisation
# ---------------------------------------------------------------------------

_CODE_TOKEN = re.compile(
    # string literal — the escape class must span newlines ([\s\S], not .)
    # or a \-newline line-continuation desyncs quote pairing and swallows
    # code tokens into a bogus mega-"string" (T4 defect, context_pack tests)
    r'"(?:\\[\s\S]|[^"\\])*"'
    r"|[A-Za-z_][A-Za-z0-9_]*"  # ident/keyword
    r"|[0-9][0-9A-Za-z_.]*"     # number-ish
    r"|::|->|=>|&&|\|\||==|!=|<=|>="  # multi-char ops
    r"|\S"                     # any other single non-space char
)


def _lex(text):
    """(token, start, end) stream with comments atomic: a `//` comment runs
    to EOL, a `/* */` comment nests (matching mask()'s lexical reality), a
    string literal is one token. Comment/string interiors are never re-lexed
    as code."""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text[i] in " \t\r\n":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append((text[i:j], i, j))
            i = j
            continue
        if text.startswith("/*", i):
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
            out.append((text[i:j], i, j))
            i = j
            continue
        m = _CODE_TOKEN.match(text, i)
        if m:
            out.append((m.group(0), i, m.end()))
            i = m.end()
        else:
            i += 1
    return out


# Keywords that can legally precede a parenthesized EXPRESSION/PATTERN — after
# these, `(x,)` is a one-tuple and its comma is semantics, not rustfmt style.
_TUPLE_POS_KEYWORDS = {
    "return", "break", "continue", "if", "else", "while", "for", "in",
    "match", "loop", "move", "yield", "as", "where", "let", "mut", "ref",
    "const", "static", "async", "unsafe", "await", "box", "dyn", "fn",
    "impl",
}


def canon(text):
    """Whitespace/reflow-insensitive token form: lex (comments atomic — see
    _lex), rejoin with single spaces. A trailing comma before a closing
    bracket is dropped only when BOTH hold: the closer sits on a LATER line
    (rustfmt's vertical-list habit — never drop a same-line `,)` one-tuple),
    AND the bracket group is droppable: `[ ]` / `{ }` always (trailing commas
    there are never semantic in Rust), `( )` only in CALL position — matching
    opener directly preceded by a path ident (not a keyword), `)`, `]`,
    turbofish `>`, or macro `!` — because an arg-list/constructor trailing
    comma is style, while a non-call `(x,)` is a one-tuple. Known accepted
    blind spot: `a > (b,\\n)` comparisons read `>` as turbofish."""
    toks = _lex(text)
    # Per-closer droppability via bracket matching.
    droppable = {}
    stack = []
    for idx, (t, _s, _e) in enumerate(toks):
        if t in ("(", "[", "{"):
            prev = toks[idx - 1][0] if idx else ""
            call = (t != "(") or prev in (")", "]", ">", "!") or bool(
                re.match(r"[A-Za-z_]", prev or " ")
                and prev not in _TUPLE_POS_KEYWORDS)
            stack.append(call)
        elif t in (")", "]", "}"):
            droppable[idx] = stack.pop() if stack else True
    out = []
    for i, (t, _s, e) in enumerate(toks):
        if (t == "," and i + 1 < len(toks)
                and toks[i + 1][0] in ("}", "]", ")")
                and "\n" in text[e:toks[i + 1][1]]
                and droppable.get(i + 1, True)):
            continue
        out.append(t)
    return " ".join(out)


def norm_head(h):
    """Order-insensitive form for `use ...::{a, b, c}` heads: sort the brace
    group so rustfmt's import ordering (version-dependent) doesn't matter.
    No-op for any head without a brace group (only use-heads have one)."""
    if "{" not in h or "}" not in h:
        return h
    i = h.index("{")
    j = h.rindex("}")
    inner = h[i + 1:j].strip()
    names = sorted(p.strip() for p in inner.split(",") if p.strip())
    return h[:i + 1] + " " + " , ".join(names) + " " + h[j:]


# ---------------------------------------------------------------------------
# line/offset/depth bookkeeping
# ---------------------------------------------------------------------------


class Doc:
    def __init__(self, src):
        self.src = src
        self.masked = mask(src)
        self.lines = src.split("\n")
        self.mlines = self.masked.split("\n")
        # offset of start of each line in the (masked==src length) buffer
        self.loff = []
        off = 0
        for ln in self.lines:
            self.loff.append(off)
            off += len(ln) + 1
        # brace depth ({} only) at the start of each line
        self.depth0 = []
        d = 0
        for ml in self.mlines:
            self.depth0.append(d)
            for ch in ml:
                if ch == "{":
                    d += 1
                elif ch == "}":
                    d -= 1

    def line_of_offset(self, pos):
        # binary-ish: loff is increasing
        lo, hi = 0, len(self.loff) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.loff[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo


# item signature detection (applied to masked, lstripped line)
_SIG = [
    ("fn", re.compile(r'^(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:async|unsafe|const|default|extern(?:\s+"[^"]*")?)\s+)*fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)')),
    ("impl", re.compile(r"^(?:unsafe\s+)?impl\b")),
    ("struct", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("enum", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?enum\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("trait", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("union", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?union\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("type", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?type\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("const", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("static", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?static\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("mod", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
    ("use", re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?use\b")),
    ("macro", re.compile(r"^macro_rules!\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)")),
]

_VIS = re.compile(r"^(pub(?:\s*\([^)]*\))?)\s")


def _match_sig(mls):
    """mls = lstripped masked line. Return (kind, name-or-None) or None.
    `const fn` etc. resolve to fn because the fn pattern is tried first."""
    for kind, rx in _SIG:
        m = rx.match(mls)
        if m:
            name = m.groupdict().get("name") if "name" in m.groupdict() else None
            return kind, name
    return None


def _scan_extent(doc, start_off):
    """From start_off, walk masked to find the item's terminator.
    Returns (body_open_off or None, end_off_inclusive). body item ends at the
    matching '}'; a ;-item ends at that ';'."""
    m = doc.masked
    n = len(m)
    pd = bd = cd = 0  # () [] {} depths
    body_open = None
    i = start_off
    while i < n:
        ch = m[i]
        if ch == "(":
            pd += 1
        elif ch == ")":
            pd -= 1
        elif ch == "[":
            bd += 1
        elif ch == "]":
            bd -= 1
        elif ch == "{":
            if pd == 0 and bd == 0 and body_open is None:
                body_open = i
                cd = 1
                i += 1
                # walk to matching close
                while i < n and cd > 0:
                    if m[i] == "{":
                        cd += 1
                    elif m[i] == "}":
                        cd -= 1
                    i += 1
                return body_open, i - 1
            cd += 1
        elif ch == "}":
            cd -= 1
        elif ch == ";":
            if pd == 0 and bd == 0 and body_open is None:
                return None, i
        i += 1
    return body_open, n - 1


def _leading_block(doc, sig_line):
    """Walk up from sig_line over contiguous doc-comment / attribute lines.
    Multi-line #[...] attributes are consumed via bracket matching on masked.
    Stops at a blank line or any non-attr/non-doc line."""
    cur = sig_line - 1
    top = sig_line
    while cur >= 0:
        s = doc.lines[cur].strip()
        ms = doc.mlines[cur].strip()
        if s == "":
            break
        # `///` outer doc + `#[...]` outer attr attach to the FOLLOWING item.
        # `//!` inner doc + `#![...]` inner attr document the ENCLOSING module and
        # must NOT be swallowed by the first item below them.
        if s.startswith("///") and not s.startswith("////"):
            top = cur
            cur -= 1
            continue
        if ms.startswith("#[") and not ms.startswith("#!["):
            top = cur
            cur -= 1
            continue
        # possible tail of a multi-line attribute: line ends with ] and bracket
        # accounting over the masked span back to a '#[' start balances.
        if ms.endswith("]"):
            # accumulate upward until bracket depth balances at a #[ line
            depth = 0
            k = cur
            found = None
            while k >= 0:
                mk = doc.mlines[k]
                depth += mk.count("]") - mk.count("[")
                if depth == 0 and (mk.lstrip().startswith("#[") or mk.lstrip().startswith("#![")):
                    found = k
                    break
                if depth < 0:
                    break
                k -= 1
            if found is not None:
                top = found
                cur = found - 1
                continue
        break
    return top


def _cfgs_of(doc, lead_start, sig_line):
    """cfg predicate strings (canon) from #[cfg(...)] attributes in the lead
    block. Located via masked text (correct paren matching) but sliced from the
    original source so string literals like "sync" survive."""
    if lead_start >= sig_line:
        return []
    lo = doc.loff[lead_start]
    hi = doc.loff[sig_line]
    seg = doc.masked[lo:hi]
    out = []
    for m in re.finditer(r"#\s*\[\s*cfg\s*\(", seg):
        depth = 0
        i = m.end() - 1  # at '('
        start = m.end()
        while i < len(seg):
            if seg[i] == "(":
                depth += 1
            elif seg[i] == ")":
                depth -= 1
                if depth == 0:
                    out.append(canon(doc.src[lo + start:lo + i]))
                    break
            i += 1
    return out


def _vis_of(doc, sig_line):
    m = _VIS.match(doc.lines[sig_line].strip())
    return canon(m.group(1)) if m else ""


def enumerate_items(doc):
    """Top-level items (depth 0). impl items get a 'methods' list (depth-1 fns/consts/types)."""
    items = []
    i = 0
    N = len(doc.lines)
    while i < N:
        if doc.depth0[i] != 0:
            i += 1
            continue
        mls = doc.mlines[i].lstrip()
        sig = _match_sig(mls)
        if not sig:
            i += 1
            continue
        kind, name = sig
        start_off = doc.loff[i] + (len(doc.mlines[i]) - len(mls))
        body_open, end_off = _scan_extent(doc, start_off)
        end_line = doc.line_of_offset(end_off)
        lead = _leading_block(doc, i)
        header = None
        if kind == "impl":
            header = canon(doc.src[start_off:body_open]) if body_open is not None else canon(mls)
        item = {
            "kind": kind,
            "name": name,
            "header": header,
            "sig_line": i,
            "lead_start": lead,
            "end_line": end_line,
            "body_open_line": doc.line_of_offset(body_open) if body_open is not None else None,
            "vis": _vis_of(doc, i),
            "cfgs": _cfgs_of(doc, lead, i),
            "methods": [],
        }
        if kind == "impl" and body_open is not None:
            inner_depth = doc.depth0[i] + 1
            j = item["body_open_line"] + 1
            while j <= end_line:
                if doc.depth0[j] == inner_depth:
                    mjs = doc.mlines[j].lstrip()
                    msig = _match_sig(mjs)
                    if msig and msig[0] in ("fn", "const", "type"):
                        mkind, mname = msig
                        mstart = doc.loff[j] + (len(doc.mlines[j]) - len(mjs))
                        mbo, meo = _scan_extent(doc, mstart)
                        mel = doc.line_of_offset(meo)
                        mlead = _leading_block(doc, j)
                        item["methods"].append({
                            "kind": "method" if mkind == "fn" else mkind,
                            "name": mname,
                            "sig_line": j,
                            "lead_start": mlead,
                            "end_line": mel,
                            "vis": _vis_of(doc, j),
                            "cfgs": _cfgs_of(doc, mlead, j),
                        })
                        j = mel + 1
                        continue
                j += 1
        items.append(item)
        i = end_line + 1
    return items


def item_text(doc, it):
    return "\n".join(doc.lines[it["lead_start"]:it["end_line"] + 1])


def logical_head(doc, sig_line):
    """canon of the declaration head. For `use`, up to the terminating ';'
    (brace groups are part of the import list, not a body). For everything else,
    up to the body-open '{', '=', or ';' at zero depth. Reflow-insensitive."""
    mls = doc.mlines[sig_line].lstrip()
    start_off = doc.loff[sig_line] + (len(doc.mlines[sig_line]) - len(mls))
    is_use = bool(re.match(r"^(?:pub(?:\s*\([^)]*\))?\s+)?use\b", mls))
    stops = ";" if is_use else "{;="
    m = doc.masked
    n = len(m)
    pd = bd = 0
    i = start_off
    while i < n:
        ch = m[i]
        if ch == "(":
            pd += 1
        elif ch == ")":
            pd -= 1
        elif ch == "[":
            bd += 1
        elif ch == "]":
            bd -= 1
        elif pd == 0 and bd == 0 and ch in stops:
            break
        i += 1
    return norm_head(canon(doc.src[start_off:i]))


_INV = re.compile(r"^\s*pub(?:\s*\((?:crate|super|in\s+[^)]+)\))?\s+(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:default\s+)?(?:extern(?:\s+\"[^\"]*\")?\s+)?(?:fn|struct|enum|trait|type|const|static|mod|use|union)\b")
_IMPLHDR = re.compile(r"^\s*(?:unsafe\s+)?impl\b")


def inventory(doc):
    """All pub declaration heads (canon), any indentation."""
    out = []
    for i, ml in enumerate(doc.mlines):
        if _INV.match(ml):
            out.append(logical_head(doc, i))
    return out


def impl_headers(doc):
    """All impl-block headers (canon), any indentation."""
    out = []
    n = len(doc.masked)
    for i, ml in enumerate(doc.mlines):
        if _IMPLHDR.match(ml):
            mls = ml.lstrip()
            start_off = doc.loff[i] + (len(ml) - len(mls))
            bo, eo = _scan_extent(doc, start_off)
            if bo is not None:
                out.append(canon(doc.src[start_off:bo]))
    return out


def find_item(doc, kind, container, name, cfg):
    """Return list of matching item dicts (with doc-relative extent) for the row."""
    items = enumerate_items(doc)
    cfgc = canon(cfg) if cfg and cfg != "-" else None
    matches = []
    if kind == "method":
        cc = canon(container)
        for it in items:
            if it["kind"] == "impl" and it["header"] == cc:
                for m in it["methods"]:
                    if m["kind"] == "method" and m["name"] == name:
                        if cfgc is None or cfgc in m["cfgs"]:
                            matches.append(m)
    elif kind == "impl":
        want = canon(name)
        for it in items:
            if it["kind"] == "impl" and it["header"] == want:
                if cfgc is None or cfgc in it["cfgs"]:
                    matches.append(it)
    elif kind == "mod":
        for it in items:
            if it["kind"] == "mod" and it["name"] == name:
                if cfgc is None or cfgc in it["cfgs"]:
                    matches.append(it)
    elif container and container not in ("-", "") and container.split()[0] == "mod":
        # container = "mod tests" (or another named mod): item lives inside that mod body
        modname = container.split()[-1]
        for it in items:
            if it["kind"] == "mod" and it["name"] == modname and it["body_open_line"] is not None:
                for m in items_in_mod(doc, it):
                    mk = "method" if m["kind"] == "fn" and kind == "method" else m["kind"]
                    if (mk == kind or m["kind"] == kind) and m["name"] == name:
                        if cfgc is None or cfgc in m["cfgs"]:
                            matches.append(m)
    else:
        for it in items:
            if it["kind"] == kind and it["name"] == name:
                if cfgc is None or cfgc in it["cfgs"]:
                    matches.append(it)
    return matches


def items_in_mod(doc, mod_item):
    """Enumerate fn/const/type/struct/enum/impl items directly inside a mod body."""
    out = []
    inner_depth = doc.depth0[mod_item["sig_line"]] + 1
    j = mod_item["body_open_line"] + 1
    while j <= mod_item["end_line"]:
        if doc.depth0[j] == inner_depth:
            mjs = doc.mlines[j].lstrip()
            msig = _match_sig(mjs)
            if msig:
                mkind, mname = msig
                mstart = doc.loff[j] + (len(doc.mlines[j]) - len(mjs))
                mbo, meo = _scan_extent(doc, mstart)
                mel = doc.line_of_offset(meo)
                mlead = _leading_block(doc, j)
                out.append({
                    "kind": mkind, "name": mname, "sig_line": j, "lead_start": mlead,
                    "end_line": mel,
                    "body_open_line": doc.line_of_offset(mbo) if mbo is not None else None,
                    "vis": _vis_of(doc, j), "cfgs": _cfgs_of(doc, mlead, j),
                })
                j = mel + 1
                continue
        j += 1
    return out


# ---------------------------------------------------------------------------
# declared-edit application + delta-shape validation (TS D6 #3/#4, D9.4 #2)
# ---------------------------------------------------------------------------

_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*(::)?$")


def apply_edits(text, edits):
    """edits = list of (old_stripped, new_stripped). Replace each fragment line
    whose stripped form == old with new (indentation preserved)."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        s = ln.strip()
        for old, new in edits:
            if s == old:
                indent = ln[:len(ln) - len(ln.lstrip())]
                lines[i] = indent + new
                break
    return "\n".join(lines)


def _edit_delta_ok_core(old, new, allow_exceptions=True):
    """True iff old→new is a legal declared edit: every changed region is pure
    `::`-path text, a single string-literal token swapped for a string-literal
    token (relative include_str!/include_bytes! paths broken by a directory-depth
    change), a pure path-segment removal (`crate::types::X` → `crate::X`, the
    module-un-mount class), or the single visibility-promotion exception
    (empty→`pub(crate)` prepended). Multiple regions are allowed (a line may
    carry more than one `types::X` occurrence re-pointed at once); each must be
    pure-path. allow_exceptions=False drops the string-literal and
    vis-promotion exceptions — comment interiors are path-re-points ONLY."""
    old_toks = [t for t, _s, _e in _lex(old)]
    nt = [t for t, _s, _e in _lex(new)]
    if old_toks == nt:
        return False  # a no-op edit is not a valid declared edit
    if len(old_toks) == len(nt):
        # position-wise: collect maximal runs of differing tokens; each must be
        # a pure ::-path segment on both sides (e.g. `types` -> `registry`).
        i = 0
        n = len(old_toks)
        while i < n:
            if old_toks[i] == nt[i]:
                i += 1
                continue
            j = i
            while j < n and old_toks[j] != nt[j]:
                j += 1
            if (allow_exceptions and j - i == 1
                    and old_toks[i].startswith('"') and nt[i].startswith('"')):
                # string-literal → string-literal single-token swap
                i = j
                continue
            if not (_PATH_RE.match("".join(old_toks[i:j])) and _PATH_RE.match("".join(nt[i:j]))):
                return False
            # must be a genuine path SEGMENT: adjacent to `::` on one side
            # (rejects a bare identifier / variable rename)
            if not ((i > 0 and old_toks[i - 1] == "::") or (j < n and old_toks[j] == "::")):
                return False
            i = j
        return True
    # length differs: single-region prefix/suffix (covers the vis exception)
    p = 0
    while p < len(old_toks) and p < len(nt) and old_toks[p] == nt[p]:
        p += 1
    s = 0
    while s < len(old_toks) - p and s < len(nt) - p and old_toks[-1 - s] == nt[-1 - s]:
        s += 1
    old_reg = old_toks[p:len(old_toks) - s]
    new_reg = nt[p:len(nt) - s]
    # the ONLY visibility exception is pub(crate) (TS D2 promotions); a bare
    # `pub` insertion is public-API widening and must never validate as a
    # declared edit
    if allow_exceptions and old_reg == [] and "".join(new_reg) == "pub(crate)":
        return True
    # every length-changing path edit must sit at a `::` boundary OUTSIDE the
    # changed region: the unchanged token just before or just after the region
    # must be `::` (mirrors the equal-length branch guard). Rejects bare
    # identifier rewrites (`old` -> `crate::new`), leading-qualifier removals
    # (`crate::types::Foo` -> `types::Foo`), and non-path deletions
    # (`foo(crate::types::X)` -> `foo()`).
    if not ((p > 0 and old_toks[p - 1] == "::")
            or (s > 0 and old_toks[len(old_toks) - s] == "::")):
        return False
    if new_reg == [] and "::" in old_reg and _PATH_RE.match("".join(old_reg)):
        # pure ::-path segment REMOVAL (module un-mount: crate::types::X ->
        # crate::X). The removed run must include its `::` separator so the
        # surviving path stays well-formed; _PATH_RE's trailing-`::` form
        # covers the `types ::` shape the prefix/suffix split produces.
        return True
    if not old_reg or not new_reg:
        return False
    return bool(_PATH_RE.match("".join(old_reg)) and _PATH_RE.match("".join(new_reg)))


def edit_delta_ok(old, new):
    """_edit_delta_ok_core, plus the comment-interior class: comment-atomic
    lexing makes a `///` doctest line ONE token, so an interior path re-point
    (the ForeignWorldId doctest frag-edit class) can never satisfy the token
    rules on the raw line. When both sides carry the SAME comment marker,
    validate the interiors as pure path re-points — a marker change
    (`///`→`//`), any non-path interior delta, and the string-literal /
    vis-promotion exceptions (code-line classes, meaningless and fail-open
    inside comment text) all still fail."""
    if _edit_delta_ok_core(old, new):
        return True
    o, n = old.lstrip(), new.lstrip()
    for pre in ("///", "//!", "//"):
        if o.startswith(pre) and n.startswith(pre):
            return _edit_delta_ok_core(o[len(pre):], n[len(pre):],
                                       allow_exceptions=False)
    return False


# ---------------------------------------------------------------------------
# flat-name set from lib.rs (TS D6 #6 / CONV D3.2 contract check)
# ---------------------------------------------------------------------------

def flat_names(doc):
    """Set of names exported by lib.rs's `pub use` groups (the flat façade).
    Handles `pub use crate::m::{A, B as C};` and `pub use crate::m::Name;`."""
    names = set()
    for it in enumerate_items(doc):
        if it["kind"] != "use" or it["vis"] != "pub":
            continue
        head = logical_head(doc, it["sig_line"])  # canon, e.g. "pub use crate :: m :: { A , B }"
        if "{" in head:
            inner = head[head.index("{") + 1:head.rindex("}")]
            parts = [p.strip() for p in inner.split(",") if p.strip()]
        else:
            # trailing single name after last ::
            toks = head.split()
            parts = [toks[-1]] if toks else []
        for part in parts:
            t = part.split()
            if "as" in t:
                names.add(t[t.index("as") + 1])
            elif t:
                names.add(t[-1])
    return names


# ---------------------------------------------------------------------------
# rustfmt normalisation + byte compare helpers
# ---------------------------------------------------------------------------

_FMT_CONFIG = "wrap_comments=false,normalize_comments=false,format_code_in_doc_comments=false,normalize_doc_attributes=false,reorder_imports=false,reorder_modules=false"


def rustfmt(fragment):
    """Format a fragment with default config + edition 2024, comment-touching
    options forced off, run from a scratch cwd so no repo rustfmt.toml applies.
    Returns formatted text or raises RuntimeError."""
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run(
            [RUSTFMT, "--edition", "2024", "--config", _FMT_CONFIG, "--emit", "stdout"],
            input=fragment, capture_output=True, text=True, cwd=td,
        )
        if p.returncode != 0:
            raise RuntimeError("rustfmt failed: " + p.stderr.strip())
        out = p.stdout
        # rustfmt --emit stdout prepends a filename banner line on some versions;
        # strip a leading "stdin:\n" style banner if present.
        if out.startswith("stdin:\n") or out.startswith("<stdin>:\n"):
            out = out.split("\n", 1)[1]
            if out.startswith("\n"):
                out = out[1:]
        return out


_DUMMY_OPEN = "impl __Dummy {"


def _dewrap(fmted):
    lines = fmted.split("\n")
    # drop trailing empty lines
    while lines and lines[-1].strip() == "":
        lines.pop()
    assert lines and lines[0].strip() == _DUMMY_OPEN, "wrap missing open"
    assert lines[-1].strip() == "}", "wrap missing close"
    inner = lines[1:-1]
    dedented = []
    for ln in inner:
        dedented.append(ln[4:] if ln.startswith("    ") else ln.lstrip() if ln.strip() == "" else ln)
    return "\n".join(dedented).rstrip("\n")


_SIG_LINE = re.compile(r"^(\s*)(pub(?:\s*\([^)]*\))?\s+)((?:async\s+|unsafe\s+|const\s+|default\s+|extern[^ ]*\s+)*(?:fn|struct|enum|trait|type|const|static|union|mod|use)\b)")


def strip_item_vis(fragment):
    """Remove a leading pub(...)/pub token from the item's signature line
    (the first line whose lstripped form starts with an optional pub + item kw)."""
    lines = fragment.split("\n")
    for idx, ln in enumerate(lines):
        m = _SIG_LINE.match(ln)
        if m:
            lines[idx] = m.group(1) + m.group(3) + ln[m.end():]
            break
        # base side: sig line without pub -> nothing to strip, but detect to stop
        if re.match(r"^\s*(?:async\s+|unsafe\s+|const\s+|default\s+|extern[^ ]*\s+)*(?:fn|struct|enum|trait|type|const|static|union|mod|use)\b", ln):
            break
    return "\n".join(lines)


def normalized_fragment(text, is_fn, header_change):
    """Full normalisation pipeline for one extracted item.

    header_change: the added `pub(crate) ` token is stripped from the signature
    BEFORE rustfmt (not after), so both sides present the identical private form
    and format identically. Stripping after rustfmt would false-fail when the
    added token pushes a single-line signature past the width limit and rustfmt
    reflows it (D6's after-rustfmt spec is fragile on that case)."""
    if header_change:
        text = strip_item_vis(text)
    if is_fn:
        wrapped = _DUMMY_OPEN + "\n" + text + "\n}\n"
        body = _dewrap(rustfmt(wrapped))
    else:
        body = rustfmt(text + "\n").rstrip("\n")
    return body


# ---------------------------------------------------------------------------
# CLI (debugging / generator use)
# ---------------------------------------------------------------------------

def _load(path):
    with open(path, encoding="utf-8") as f:
        return Doc(f.read())


def main(argv):
    cmd = argv[0]
    if cmd == "enumerate":
        doc = _load(argv[1])
        for it in enumerate_items(doc):
            base = f"{it['kind']:8} {it['name'] or it['header']!s:40} sig@{it['sig_line']+1} lead@{it['lead_start']+1} end@{it['end_line']+1} vis={it['vis']!r} cfg={it['cfgs']}"
            print(base)
            for m in it["methods"]:
                print(f"    method {m['name']:40} sig@{m['sig_line']+1} end@{m['end_line']+1} vis={m['vis']!r} cfg={m['cfgs']}")
    elif cmd == "find":
        # find <file> <kind> <container> <name> <cfg>
        doc = _load(argv[1])
        ms = find_item(doc, argv[2], argv[3], argv[4], argv[5])
        print(f"{len(ms)} match(es)")
        for m in ms:
            print(f"  sig@{m['sig_line']+1} lead@{m['lead_start']+1} end@{m['end_line']+1} vis={m['vis']!r}")
    elif cmd == "inventory":
        doc = _load(argv[1])
        for h in inventory(doc):
            print(h)
    elif cmd == "impls":
        doc = _load(argv[1])
        for h in impl_headers(doc):
            print(h)
    else:
        print("unknown", cmd, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
