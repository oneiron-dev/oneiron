#!/usr/bin/env python3
"""Schema validation of the OF-510 deck gate's candidates (step 5, FIX 8590).

  fetch DIR           fetch the pinned ECMA-376 Part 4 transitional XML Schemas
                      into DIR once (kept across runs); exit 0 when they are ready
  validate DIR [PKG]  validate every markup part of a .pptx (PKG, or stdin)
                      against them with xmllint; one JSON object on stdout

ARCH-0077 step 5: schema validation is necessary but not sufficient, so the
engine half (`deck-gate-cases`) calls `validate` on each candidate and on the
deck it came from, binds the report to the candidate's SHA-256 and charges only
the diagnostics the origin did not already have. Markup Compatibility (ECMA-376
Part 3) is processed first, as a consumer that understands no extension: the
attributes and elements of mc:Ignorable namespaces are dropped, and each
mc:AlternateContent becomes its mc:Fallback (or nothing). A part whose root no
transitional schema declares (relationships, content types, core properties,
Office 2013+ parts such as modern comments) is named as unvalidated.

Exit 2 when the validator cannot run (no schema set, a pin mismatch, no xmllint,
a schema that does not compile): the run then records the evidence as absent.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

# The schema set: ECMA-376 5th edition (December 2016), Part 4, Transitional
# Migration Features, whose archive carries the transitional XML Schemas.
SOURCE = 'https://ecma-international.org/wp-content/uploads/ECMA-376-4_5th_edition_december_2016.zip'
SOURCE_SHA256 = 'bd25da1109f73762356596918bf5ff8b74a1331642dba5f1c1d1dfc6bed34ecd'
INNER = 'OfficeOpenXML-XMLSchema-Transitional.zip'
INNER_SHA256 = 'd34187520749998af306faf1b730e568b0ca6d88ad24638a407c0a9bb4ca04fc'
PROFILE = 'ecma-376-4:2016-transitional'
PIN = 'schema-set.json'
SET = 'schema-set.xsd'
# The schemas the wrapper imports; theirs import the rest (DrawingML main,
# chart, diagram, picture, shared types).
ROOTS = {
    'http://schemas.openxmlformats.org/presentationml/2006/main': 'pml.xsd',
    'http://schemas.openxmlformats.org/drawingml/2006/chartDrawing': 'dml-chartDrawing.xsd',
    'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties':
        'shared-documentPropertiesExtended.xsd',
    'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties':
        'shared-documentPropertiesCustom.xsd',
}
# The root namespaces the set declares global elements in, by those imports.
COVERED = frozenset(ROOTS) | {f'http://schemas.openxmlformats.org/drawingml/2006/{name}'
                              for name in ('main', 'chart', 'diagram', 'picture', 'lockedCanvas')}
MC = 'http://schemas.openxmlformats.org/markup-compatibility/2006'
LINE = re.compile(r'^(?P<file>.+?):(?P<line>\d+): (?P<rest>.*)$')


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- fetch -------------------------------------------------------------------

def wrapper() -> str:
    imports = ''.join(f'  <xsd:import namespace="{ns}" schemaLocation="xsd/{name}"/>\n'
                      for ns, name in sorted(ROOTS.items()))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            'targetNamespace="urn:oneiron:deck-gate:schema-set">\n' + imports + '</xsd:schema>\n')


def ready(root: Path) -> dict | None:
    """The pin of a schema set already in `root` whose files match it."""
    try:
        pin = json.loads((root / PIN).read_text())
        if pin.get('inner_sha256') != INNER_SHA256 or (root / SET).read_text() != wrapper():
            return None
        for name, digest in pin['files'].items():
            if sha256((root / 'xsd' / name).read_bytes()) != digest:
                return None
        return pin
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def fetch(root: Path) -> int:
    if ready(root):
        print(f'schema set kept in {root}')
        return 0
    root.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(SOURCE, timeout=60) as response:
            archive = response.read()
        if sha256(archive) != SOURCE_SHA256:
            raise ValueError(f'{SOURCE} does not match its pin: {sha256(archive)}')
        inner = zipfile.ZipFile(io.BytesIO(archive)).read(INNER)
        if sha256(inner) != INNER_SHA256:
            raise ValueError(f'{INNER} does not match its pin: {sha256(inner)}')
        files = {}
        target = root / 'xsd'
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir()
        with zipfile.ZipFile(io.BytesIO(inner)) as schemas:
            for name in schemas.namelist():
                if name.endswith('.xsd') and '/' not in name and not name.startswith('.'):
                    data = schemas.read(name)
                    (target / name).write_bytes(data)
                    files[name] = sha256(data)
        (root / SET).write_text(wrapper())
        (root / PIN).write_text(json.dumps({'source': SOURCE, 'sha256': SOURCE_SHA256, 'inner': INNER,
                                            'inner_sha256': INNER_SHA256, 'profile': PROFILE,
                                            'files': files}, indent=2) + '\n')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print(f'schema set unavailable: {exc}', file=sys.stderr)
        return 1
    print(f'schema set ready in {root} ({len(files)} schemas)')
    return 0


# ---- Markup Compatibility ----------------------------------------------------

def namespace(tag: str) -> str:
    return tag[1:].split('}', 1)[0] if tag.startswith('{') else ''


def compatible(data: bytes) -> ET.Element:
    """The part as a consumer of no extension reads it (ECMA-376 Part 3)."""
    scopes: dict[ET.Element, dict[str, str]] = {}
    stack: list[dict[str, str]] = [{}]
    pending: dict[str, str] = {}
    root = None
    for event, item in ET.iterparse(io.BytesIO(data), events=('start-ns', 'start', 'end')):
        if event == 'start-ns':
            pending[item[0]] = item[1]
        elif event == 'start':
            scope = {**stack[-1], **pending}
            pending = {}
            scopes[item] = scope
            stack.append(scope)
            root = item if root is None else root
        else:
            stack.pop()
    if root is None:
        raise ValueError('no root element')

    def walk(element: ET.Element, ignorable: frozenset[str]) -> None:
        listed = element.get(f'{{{MC}}}Ignorable', '')
        own = ignorable | {scopes[element][prefix] for prefix in listed.split() if prefix in scopes[element]}
        for key in list(element.attrib):
            if namespace(key) in own or namespace(key) == MC:
                del element.attrib[key]
        kept: list[ET.Element] = []
        for child in list(element):
            ns = namespace(child.tag)
            if child.tag.endswith('}extLst'):
                # An extension list's own content is open (xsd:any, lax): kept as written.
                kept.append(child)
            elif child.tag == f'{{{MC}}}AlternateContent':
                fallback = child.find(f'{{{MC}}}Fallback')
                for taken in list(fallback) if fallback is not None else []:
                    walk(taken, own)
                    kept.append(taken)
            elif ns not in own and ns != MC:
                walk(child, own)
                kept.append(child)
        element[:] = kept

    walk(root, frozenset())
    return root


# ---- validate ----------------------------------------------------------------

def unavailable(why: str) -> int:
    print(f'schema validator unavailable: {why}', file=sys.stderr)
    return 2


def validate(root: Path, package: bytes) -> int:
    pin = ready(root)
    if pin is None:
        return unavailable(f'no pinned schema set in {root} (run fetch first)')
    xmllint = shutil.which('xmllint')
    if not xmllint:
        return unavailable('xmllint is not installed')
    version = subprocess.run([xmllint, '--version'], capture_output=True, text=True, check=False)
    libxml = (version.stderr or version.stdout).splitlines()[0].strip() if (version.stderr or version.stdout) else '?'
    unvalidated: dict[str, int] = {}
    diagnostics: set[str] = set()
    with tempfile.TemporaryDirectory(prefix='deck-schema-') as tmp:
        files: dict[str, str] = {}
        try:
            archive = zipfile.ZipFile(io.BytesIO(package))
        except zipfile.BadZipFile as exc:
            diagnostics.add(f'the package is not a ZIP archive: {exc}')
            archive = None
        for at, name in enumerate(sorted(archive.namelist()) if archive else []):
            if not (name.endswith('.xml') or name.endswith('.rels')):
                continue
            try:
                element = compatible(archive.read(name))
            except (ET.ParseError, ValueError, KeyError) as exc:
                diagnostics.add(f'{name}: does not parse: {exc}')
                continue
            if namespace(element.tag) not in COVERED:
                unvalidated[element.tag] = unvalidated.get(element.tag, 0) + 1
                continue
            path = Path(tmp) / f'{at:05}.xml'
            path.write_bytes(ET.tostring(element, encoding='utf-8', xml_declaration=True))
            files[str(path)] = name
        if files:
            run = subprocess.run([xmllint, '--noout', '--nonet', '--schema', str(root / SET), *files],
                                 capture_output=True, text=True, check=False)
            for line in run.stderr.splitlines():
                if 'Schemas parser error' in line or 'failed to compile' in line or 'WXS schema' in line:
                    return unavailable(line.strip())
                found = LINE.match(line)
                if found and found.group('file') in files:
                    diagnostics.add(f"{files[found.group('file')]}: {found.group('rest').strip()}")
                elif line.strip() and not any(line.startswith(f) for f in files):
                    diagnostics.add(line.strip())
    print(json.dumps({
        'sha256': sha256(package),
        'validator': f"xmllint ({libxml}), ECMA-376 Part 4 transitional XSDs {pin['inner_sha256']}",
        'profile': PROFILE,
        'diagnostics': sorted(diagnostics),
        'unvalidated': [f'{tag} ({n} parts)' for tag, n in sorted(unvalidated.items())],
    }, ensure_ascii=False))
    return 0


def main() -> int:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == 'fetch':
        return fetch(Path(args[1]))
    if len(args) in (2, 3) and args[0] == 'validate':
        package = Path(args[2]).read_bytes() if len(args) == 3 and args[2] != '-' else sys.stdin.buffer.read()
        return validate(Path(args[1]), package)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
