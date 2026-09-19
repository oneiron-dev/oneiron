# Measured formualizer fork

Decision: keep and own the measured evaluator, not rewrite it. The unchanged
0.9.3 workbook/eval engine with 3.1.2 parser/common scored 754/811 native Excel
cases, above LibreOffice's 753/811 on exactly the same deterministic case set.
The full per-function comparison lives under
`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat/measurements/`.

These five published crate archives are copied byte-for-byte after SHA-256
verification against the pre-fork Cargo.lock entries. `PROVENANCE.json` records
those pins. Apache-2.0 is the chosen licence. Both upstream licence files,
notices and copyright text remain in each package. No evaluator source has
changed. Root Cargo patches select these owned copies, and excludes keep
third-party source out of workspace formatting and lint policy.

The versioned `oneiron-xlsx-formula` integration owns the retained OPC cache
writer, external-link routing, numeric date/time representation, Unicode-safe
_xlfn spelling, and EditSession adapter. It does not use the upstream DOM file
writer. Unsupported package features stay on the supplied precision fallback.
The original unchanged-engine measurements remain valid for these unchanged
algorithm bytes; project compile and adapter tests validate the path binding.
