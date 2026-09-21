# Measured formualizer source and owned changes

The original source pin is formualizer workbook/eval 0.9.3 and parser/common
3.1.2. Five published archives were copied after SHA-256 verification; original
archive pins remain in `PROVENANCE.json`. Apache-2.0 is the selected licence.
Both upstream licences, notices and copyright text remain in each package.

## Decision correction

The initial 754/811 scalar compatibility score (LibreOffice 753/811) supported an
experimental fork. Full fresh-Excel SpreadsheetBench evidence supersedes that
rationale: unchanged formualizer matches only 753/2,951 scored workbooks versus
LibreOffice 2,648/2,951. ARCH-0075's real-workbook rewrite criterion applies.
FUSE truth is pending. This source is an opt-in candidate and reusable evaluator
substrate, not the selected default or a completed rewrite. The host precision
fallback is unchanged.

## Owned evaluator patch 0.9.3-oneiron.1

`formualizer-eval/src/interpreter.rs` now propagates a typed error on either side
of `&` in both AST and arena paths, before text coercion. Fresh Excel input
`16a898dc323d3c56ee6e265125e49c6d796e81ca8af449ee2f3954d25fe4b9e2`
(SpreadsheetBench 50066/1 answer) exposed the defect: an `INDEX`/`MATCH` #N/A
became the string "#N/A", so the outer IFERROR returned incorrect text. The
original raw corpus output and comparison remain preserved; this fix is not a
new corpus score. Literal text "#N/A" still remains text.

Runtime stamps distinguish this patched evaluator from the original 0.9.3
measurements. Frozen unchanged/native-v3 executables and receipts do not change.
The adapter still owns retained OPC cache patches, external-link fallback,
date/epoch conversion, _xlfn serialization and the explicit EditSession opt-in.
