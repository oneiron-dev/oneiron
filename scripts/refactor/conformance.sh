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
#>_TOKEN = re.compile(
#>    r'"(?:\\.|[^"\\])*"'      # string literal
#>    r"|[A-Za-z_][A-Za-z0-9_]*"  # ident/keyword
#>    r"|[0-9][0-9A-Za-z_.]*"     # number-ish
#>    r"|::|->|=>|&&|\|\||==|!=|<=|>="  # multi-char ops
#>    r"|\S"                     # any other single non-space char
#>)
#>
#>
#>def canon(text):
#>    """Whitespace/reflow-insensitive token form: split into Rust-ish tokens,
#>    rejoin with single spaces. Trailing commas before a closing bracket are
#>    dropped so rustfmt's multi-line trailing-comma habit is invisible."""
#>    toks = _TOKEN.findall(text)
#>    out = []
#>    for i, t in enumerate(toks):
#>        if t == "," and i + 1 < len(toks) and toks[i + 1] in ("}", "]", ")"):
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
#>        if s.startswith("///") or s.startswith("//!"):
#>            top = cur
#>            cur -= 1
#>            continue
#>        if ms.startswith("#[") or ms.startswith("#!["):
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
#>    else:
#>        for it in items:
#>            if it["kind"] == kind and it["name"] == name:
#>                if cfgc is None or cfgc in it["cfgs"]:
#>                    matches.append(it)
#>    return matches
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
#>    ded = []
#>    for ln in inner:
#>        ded.append(ln[4:] if ln.startswith("    ") else ln.lstrip() if ln.strip() == "" else ln)
#>    return "\n".join(ded).rstrip("\n")
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
#>GLOBAL_FORBID = [
#>    "crates/oneiron/src/batch.rs",
#>    "crates/oneiron/src/outbound.rs",
#>    "crates/oneiron/src/anchored_annotation.rs",
#>    "crates/oneiron/src/agent_def.rs",
#>    "crates/oneiron/src/agent_def/",
#>    "crates/oneiron/src/edit_settle.rs",
#>    "crates/oneiron/src/edit_settle/",
#>]
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
#>    p = subprocess.run(["git", "-C", root, "diff", "--name-only", base, "HEAD"],
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
#>            if cur is None:
#>                continue
#>            if ln.strip() == "":
#>                continue
#>            sections[cur].append(ln)
#>    return sections
#>
#>
#># ---- check 1: forbidden zone + allowed files -----------------------------
#>
#>def check1(root, base, decls):
#>    changed = changed_files(root, base)
#>    forbid = list(GLOBAL_FORBID) + [x.strip() for x in decls.get("forbid", [])]
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
#>    return f"OK check 1 (forbidden-zone + allowed-files): {len(changed)} changed file(s)"
#>
#>
#># ---- check 2: surface inventory (declarations + impl headers) ------------
#>
#>def _counter_diff(base_c, head_c):
#>    added = head_c - base_c
#>    removed = base_c - head_c
#>    return added, removed
#>
#>
#>def _parse_signed(lines):
#>    added = collections.Counter()
#>    removed = collections.Counter()
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
#>def check2(root, base, decls):
#>    changed = [f for f in changed_files(root, base)
#>               if f.endswith(".rs") and f.startswith("crates/")]
#>    base_inv, head_inv = collections.Counter(), collections.Counter()
#>    base_impl, head_impl = collections.Counter(), collections.Counter()
#>    for f in changed:
#>        bt = base_file(root, base, f)
#>        if bt is not None:
#>            d = R.Doc(bt)
#>            base_inv.update(R.inventory(d))
#>            base_impl.update((f, h) for h in R.impl_headers(d))
#>        ht = head_file(root, f)
#>        if ht is not None:
#>            d = R.Doc(ht)
#>            head_inv.update(R.inventory(d))
#>            head_impl.update((f, h) for h in R.impl_headers(d))
#>
#>    add, rem = _counter_diff(base_inv, head_inv)
#>    exp_add, exp_rem = _parse_signed(decls.get("decl", []))
#>    if add != exp_add or rem != exp_rem:
#>        _report_diff(2, "declaration inventory (2a)", add, rem, exp_add, exp_rem)
#>
#>    add_i, rem_i = _counter_diff(base_impl, head_impl)
#>    exp_add_i, exp_rem_i = _parse_signed_impl(decls.get("impl-delta", []))
#>    if add_i != exp_add_i or rem_i != exp_rem_i:
#>        _report_diff(2, "impl-header inventory (2b)", add_i, rem_i, exp_add_i, exp_rem_i,
#>                     fmt=lambda t: f"{t[0]}\t{t[1]}")
#>    return f"OK check 2 (surface inventory): {len(add)} decl+ / {len(rem)} decl- / {len(add_i)} impl+ / {len(rem_i)} impl-"
#>
#>
#>def _parse_signed_impl(lines):
#>    added, removed = collections.Counter(), collections.Counter()
#>    for ln in lines:
#>        if not ln:
#>            continue
#>        sign, content = ln[0], ln[1:].strip()
#>        parts = content.split("\t")
#>        if len(parts) != 2:
#>            raise Violation(2, f"bad impl-delta line (need file<TAB>header): {ln!r}")
#>        key = (parts[0].strip(), parts[1].strip())
#>        (added if sign == "+" else removed)[key] += 1
#>    return added, removed
#>
#>
#>def _report_diff(check, label, add, rem, exp_add, exp_rem, fmt=str):
#>    lines = [f"{label} mismatch (actual HEAD-vs-BASE vs manifest):"]
#>    for tag, actual, expected in (("added(+)", add, exp_add), ("removed(-)", rem, exp_rem)):
#>        missing = expected - actual   # declared but not observed
#>        extra = actual - expected     # observed but not declared
#>        for k in sorted(missing, key=fmt):
#>            lines.append(f"  {tag} declared but MISSING: {fmt(k)}")
#>        for k in sorted(extra, key=fmt):
#>            lines.append(f"  {tag} observed but UNDECLARED: {fmt(k)}")
#>    raise Violation(check, "\n".join(lines))
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
#>                           f"kind={row['kind']} container={row['container']!r} "
#>                           f"name={row['item_name']!r} cfg={row['cfg']!r}")
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
#>    return R.find_item(doc, row["kind"], "-", row["item_name"], row["cfg"])
#>
#>
#>def check3(root, base, tsv):
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
#>            ht = head_file(root, row["dst_file"])
#>            if ht is None:
#>                raise Violation(3, f"dst_file not present — item not yet moved: {row['dst_file']}")
#>            base_norm = R.rustfmt(base_frag + "\n").rstrip("\n")
#>            head_norm = R.rustfmt(ht + ("" if ht.endswith("\n") else "\n")).rstrip("\n")
#>            if base_norm != head_norm:
#>                raise Violation(3, f"MOD body mismatch: {row['src_file']}:mod {row['item_name']} "
#>                                   f"!= {row['dst_file']}")
#>            n += 1
#>            continue
#>
#>        bm = _exactly_one(_find_row(bdoc, row), f"BASE {row['src_file']}", row)
#>        base_text = R.item_text(bdoc, bm)
#>        ht = head_file(root, row["dst_file"])
#>        if ht is None:
#>            raise Violation(3, f"dst_file not present — item not yet moved: {row['dst_file']} "
#>                               f"(item {row['item_name']})")
#>        hdoc = R.Doc(ht)
#>        hm = _exactly_one(_find_row(hdoc, row), f"HEAD {row['dst_file']}", row)
#>        head_text = R.item_text(hdoc, hm)
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
#>    anchors = decls.get("anchors", [])
#>    n = 0
#>    for ln in anchors:
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
#>        base_norm = R.normalized_fragment(R.item_text(bdoc, bm), is_fn, False)
#>        head_norm = R.normalized_fragment(R.item_text(hdoc, hm), is_fn, False)
#>        if base_norm != head_norm:
#>            raise Violation(4, f"FROZEN ANCHOR changed: {kind} {name} in {f}\n" + _first_diff(base_norm, head_norm))
#>        n += 1
#>    return f"OK check 4 (frozen anchors): {n} anchor(s) unchanged"
#>
#>
#># ---- check 5: name-uniqueness (api stages) -------------------------------
#>
#>def check5(root, stage, decls):
#>    globs = [g.strip() for g in decls.get("uniqueness", [])]
#>    if not globs:
#>        return "OK check 5 (name-uniqueness): skipped (not an api stage)"
#>    names = collections.Counter()
#>    seen_files = 0
#>    for g in globs:
#>        for f in sorted(glob.glob(os.path.join(root, g))):
#>            rel = os.path.relpath(f, root)
#>            ht = head_file(root, rel)
#>            if ht is None:
#>                continue
#>            seen_files += 1
#>            for it in R.enumerate_items(R.Doc(ht)):
#>                # mod/use/impl don't participate in `use self::<domain>::*` glob
#>                # ambiguity (module names live in a different namespace than the
#>                # value/type items the glob re-exports).
#>                if it["kind"] in ("impl", "use", "mod") or not it["name"]:
#>                    continue
#>                names[it["name"]] += 1
#>    dups = {k: v for k, v in names.items() if v > 1}
#>    if dups:
#>        raise Violation(5, "duplicate top-level item names across api modules (glob re-export "
#>                           "ambiguity): " + ", ".join(f"{k}×{v}" for k, v in sorted(dups.items())))
#>    return f"OK check 5 (name-uniqueness): {seen_files} file(s), no duplicates"
#>
#>
#># ---- check 6: error-literal inventory (codec stages) ---------------------
#>
#>_ERRLIT = re.compile(r'Error::(?:Invalid\w+Body|InvariantViolation)\(\s*"(?:\\.|[^"\\])*"')
#>
#>
#>def _strip_line_comments(text):
#>    return "\n".join(re.sub(r"//.*$", "", ln) for ln in text.split("\n"))
#>
#>
#>def check6(root, base, decls):
#>    files = [x.strip() for x in decls.get("error-literal", [])]
#>    if not files:
#>        return "OK check 6 (error-literal): skipped (not a codec stage)"
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
#># ---- driver --------------------------------------------------------------
#>
#>def run_checks(root, stage, base, movesdir):
#>    tsv = parse_tsv(os.path.join(movesdir, f"{stage}.tsv"))
#>    decls = parse_decls(os.path.join(movesdir, f"{stage}.decls"))
#>    results = []
#>    results.append(check1(root, base, decls))
#>    results.append(check2(root, base, decls))
#>    results.append(check3(root, base, tsv))
#>    results.append(check4(root, base, decls))
#>    results.append(check5(root, stage, decls))
#>    results.append(check6(root, base, decls))
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
#>    print(f"CONFORMANCE checks 1-6 PASSED for stage {stage}")
#>    return 0
#>
#>
#>if __name__ == "__main__":
#>    sys.exit(main(sys.argv[1:]))
#>
#PYEOF_END
