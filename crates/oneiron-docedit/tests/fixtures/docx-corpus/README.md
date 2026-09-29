# docx-corpus manifest (provenance only, context not acceptance)

`manifest.json` records a bounded representative corpus for native DOCX
acceptance context: 45 entries (40 standalone .docx + 5 docx4j paragraph-XML
fragments that are NOT standalone .docx).

Fixture BYTES live only in `.w7/docx-corpus/` (uncommitted worktree scratch).
Nothing third-party is vendored here: all three upstreams are Apache-2.0
(POI trunk, docx4j VERSION_17_1_1, stemma v0.6.0 taken under Apache-2.0),
which permits redistribution with license+notice, but the root seat decides
whether any bytes enter the repo. The manifest (paths, pins, sha256,
licenses, per-case narrow-edit mapping) is committable provenance.

No oracle values are fabricated: expected strings noted in `note` fields are
the upstream test's own assertions, quoted as pointers, never claimed as ours.
Word/LibreOffice measurement is the oracle seat's job.

Extraction for non-docx suites is documented in `manifest.json`
`extraction_notes`: docx4j accept/compare inputs are inline XML strings and
single-paragraph files; stemma conformance is Rust assertions over
input/before+after .docx pairs.
