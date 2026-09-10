"""Shared parsing for the error-enum split tooling. python3 stdlib only.

Two jobs:

* `parse_enum` — pull the variants of a named `enum` out of Rust source, with
  their shape, payload, attributes and doc block. It is a brace/paren matcher,
  not a Rust parser; it is correct for `crates/oneiron/src/error.rs`, whose
  variants are rustfmt-normalised, and it fails loudly on anything it cannot
  read rather than skipping it.
* `test_line_numbers` — the 1-based lines of a file that sit inside a
  `#[cfg(test)]` item, so reference counts can separate production from test.
"""

from __future__ import annotations

import re

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


class ParseError(Exception):
    """Raised when the source does not have the shape this module assumes."""


def split_top(text: str) -> list[str]:
    """Split on commas that are not inside brackets."""
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def find_enum_span(lines: list[str], enum_name: str) -> tuple[int, int]:
    """Return (first body line, closing-brace line), both 0-based indices."""
    head = re.compile(rf"^\s*(pub(\([^)]*\))?\s+)?enum\s+{re.escape(enum_name)}\s*\{{\s*$")
    for i, line in enumerate(lines):
        if head.match(line):
            depth = line.count("{") - line.count("}")
            j = i
            while depth > 0 and j + 1 < len(lines):
                j += 1
                depth += lines[j].count("{") - lines[j].count("}")
            if depth != 0:
                raise ParseError(f"unterminated enum {enum_name}")
            return i + 1, j
    raise ParseError(f"enum {enum_name} not found")


def parse_enum(text: str, enum_name: str) -> list[dict]:
    """Parse the variants of `enum_name`.

    Each variant is a dict: name, shape (unit/tuple/struct), payload (list of
    type strings for tuples, `field: Type` strings for structs, None for unit),
    error_attr (the verbatim `#[error(...)]` block or None), cfg (list of
    verbatim `#[cfg(...)]` lines), other_attrs, docs (verbatim `///` lines),
    line (1-based first line of the variant), text (verbatim source).
    """
    lines = text.split("\n")
    start, end = find_enum_span(lines, enum_name)
    body = lines[start:end]

    variants: list[dict] = []
    docs: list[str] = []
    attrs: list[str] = []
    i = 0
    while i < len(body):
        raw = body[i]
        stripped = raw.strip()
        if stripped.startswith("///") or stripped.startswith("//"):
            docs.append(raw)
            i += 1
            continue
        if stripped.startswith("#["):
            chunk = [raw]
            depth = raw.count("[") - raw.count("]")
            while depth > 0:
                i += 1
                if i >= len(body):
                    raise ParseError(f"unterminated attribute in {enum_name}")
                chunk.append(body[i])
                depth += body[i].count("[") - body[i].count("]")
            attrs.append("\n".join(chunk))
            i += 1
            continue
        if not stripped:
            docs, attrs = [], []
            i += 1
            continue
        m = re.match(rf"^({IDENT})\s*(.*)$", stripped)
        if not m or not m.group(1)[0].isupper():
            raise ParseError(f"unreadable line in {enum_name}: {raw!r}")
        name, rest = m.group(1), m.group(2)
        first = i
        chunk = [raw]
        if rest.startswith("{"):
            shape = "struct"
            opener, closer = "{", "}"
        elif rest.startswith("("):
            shape = "tuple"
            opener, closer = "(", ")"
        else:
            shape = "unit"
            opener = closer = ""
        if opener:
            depth = raw.count(opener) - raw.count(closer)
            while depth > 0:
                i += 1
                if i >= len(body):
                    raise ParseError(f"unterminated variant {name}")
                chunk.append(body[i])
                depth += body[i].count(opener) - body[i].count(closer)
        vtext = "\n".join(chunk)

        payload = None
        if shape == "tuple":
            inner = vtext[vtext.index("(") + 1 : vtext.rindex(")")]
            payload = [p.strip() for p in split_top(inner) if p.strip()]
        elif shape == "struct":
            inner = vtext[vtext.index("{") + 1 : vtext.rindex("}")]
            payload = []
            for field in split_top(inner):
                field = field.strip()
                if not field or field.startswith("//"):
                    continue
                # strip per-field attributes (#[source], #[from], doc lines)
                keep = [
                    ln
                    for ln in field.split("\n")
                    if not ln.strip().startswith("#[") and not ln.strip().startswith("//")
                ]
                cleaned = re.sub(r"\s+", " ", " ".join(keep)).strip()
                if cleaned:
                    payload.append(cleaned)

        error_attr, cfg, other = None, [], []
        for attr in attrs:
            flat = re.sub(r"\s+", " ", attr.strip())
            if flat.startswith("#[error("):
                error_attr = attr.strip()
            elif flat.startswith("#[cfg("):
                cfg.append(flat)
            else:
                other.append(flat)

        variants.append(
            {
                "name": name,
                "shape": shape,
                "payload": payload,
                "error_attr": error_attr,
                "cfg": cfg,
                "other_attrs": other,
                "docs": [d.strip() for d in docs],
                "line": start + first + 1,
                "text": vtext,
                "has_source": "#[source]" in vtext,
                "has_from": "#[from]" in vtext,
            }
        )
        docs, attrs = [], []
        i += 1
    return variants


def test_line_numbers(text: str) -> set[int]:
    """1-based line numbers inside a `#[cfg(test)]` item."""
    lines = text.split("\n")
    out: set[int] = set()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("#[cfg(test)]") or stripped.startswith("#[cfg(all(test"):
            j = i
            while j < len(lines) and "{" not in lines[j] and j - i < 8:
                j += 1
            if j < len(lines) and "{" in lines[j]:
                depth = lines[j].count("{") - lines[j].count("}")
                k = j
                while depth > 0 and k + 1 < len(lines):
                    k += 1
                    depth += lines[k].count("{") - lines[k].count("}")
                out.update(range(i + 1, k + 2))
                i = k + 1
                continue
        i += 1
    return out


def is_test_path(rel_path: str) -> bool:
    """True for whole files that are test or bench material."""
    parts = rel_path.replace("\\", "/").split("/")
    return "tests" in parts or "benches" in parts or parts[-1] == "tests.rs"
