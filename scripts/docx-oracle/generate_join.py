#!/usr/bin/env python3
"""Deterministic DOCX paragraph-mark oracle fixtures (ARCH-0075 §3).

The table shape mirrors the Apache-2.0 stemma conformance case
`spec_para_mark_join_blocked_target::reject_joins_across_table_emptied_by_same_reject`
at pinned commit ad1e70deac0a828d5162ac3b3f2186c2bb0c075e.
"""
import argparse
import zipfile
from pathlib import Path

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
MARK = '<w:ins w:id="1" w:author="A" w:date="2024-01-01T00:00:00Z"/>'
SIMPLE = (
    '<w:p><w:pPr><w:rPr><w:del w:id="1" w:author="A" '
    'w:date="2024-01-01T00:00:00Z"/></w:rPr></w:pPr>'
    '<w:r><w:t xml:space="preserve">Alpha </w:t></w:r></w:p>'
    '<w:p><w:r><w:t>beta.</w:t></w:r></w:p>'
)
TABLE = (
    '<w:p><w:pPr><w:rPr>' + MARK + '</w:rPr></w:pPr>'
    '<w:r><w:t xml:space="preserve">Alpha </w:t></w:r></w:p>'
    '<w:tbl><w:tblPr/><w:tblGrid><w:gridCol/></w:tblGrid>'
    '<w:tr><w:trPr><w:ins w:id="2" w:author="A" '
    'w:date="2024-01-01T00:00:00Z"/></w:trPr>'
    '<w:tc><w:tcPr/><w:p><w:r><w:t>inserted cell</w:t></w:r>'
    '</w:p></w:tc></w:tr></w:tbl>'
    '<w:p><w:r><w:t>beta.</w:t></w:r></w:p>'
)

def generate(kind: str, path: Path) -> None:
    if kind not in {"simple", "table"}:
        raise ValueError("join case must be simple or table")
    body = SIMPLE if kind == "simple" else TABLE
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?><Types '
            'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships '
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>'
        ),
        "word/_rels/document.xml.rels": (
            '<?xml version="1.0" encoding="UTF-8"?><Relationships '
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
        ),
        "word/document.xml": (
            '<?xml version="1.0" encoding="UTF-8"?><w:document '
            f'xmlns:w="{W}"><w:body>{body}<w:sectPr/></w:body></w:document>'
        ),
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, value in parts.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            archive.writestr(info, value)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("simple", "table"))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(args.case, args.output)
