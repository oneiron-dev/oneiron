# In-process XLSX formula engine

The default recalc of the core's edit round trip. `oneiron::edit_roundtrip` wraps every
host `EditSession` unless the host opts out (`EditSession::recalc_policy` returning
`RecalcPolicy::SessionOnly`): the host keeps its narrow editor, and
`FormualizerEngine::recalculate_xlsx` recalculates every workbook it admits, reading each
package under the host's document limits (`Vault::docedit_package_limits`; the raw
`run_edit_roundtrip` uses the shipped ceilings). Supported local XLSX workbooks recalculate
through one multi-sheet graph. Only formula spellings and scalar cached values change; the
retained OPC package keeps every other record and unknown XML. This crate depends on
`oneiron-docedit`, never on the core.

The host's own recalc (LibreOffice headless in production) is the precision fallback for
refused workbooks only: unsupported features (defined names, shared/array/table formulas,
spill serialization) and formulas needing caller context or volatile semantics.
External-link workbooks keep their link-preserving route to the host, and
`preserve_external_links` refuses host output that alters or drops a link.

The evaluator is formualizer 0.9.3 from the org fork `oneiron-dev/formualizer`, pinned
by rev in the root manifest (0.9.3-oneiron.3): upstream plus the owned patch that keeps
a typed error on either side of `&`, plus the Excel parity work on the fork's
`oneiron/parity` branch (ONE-2700 parts 1 and 3). `docs/ops/forked-dependencies.md` records the
fork branch, the rev and the patches. Nothing of formualizer is vendored here.

The corpus rule (default only at or above LibreOffice on the same corpus) is met at fork
rev `e29e4ee7`: 2,866 of the 2,982 formula-bearing fresh-Excel SpreadsheetBench workbooks
are fully Excel-identical (2,835 of the 2,951 LibreOffice 25.8 was measured on, against its
2,648), and 808 of the 811 pinned native Excel goldens, against LibreOffice's 753 (the
unchanged evaluator scored 754; the three misses are recording artifacts). The
comparison uses a pinned UTC instant. Production volatile or context-dependent formulas
route to the precision fallback, not that clock.

Recalculated versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.3`.
The corpus report separately identifies the evaluator (`ENGINE_STAMP`). A no-recalc
plan records no stamp; fallback runs record the fallback's own engine and version.

Binaries: `measure` scores the pinned compatibility corpus
(`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat`), and `recalc_native`
writes one retained native recalculation for an application-oracle check.
