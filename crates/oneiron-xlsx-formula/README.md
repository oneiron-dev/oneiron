# In-process XLSX formula engine

`InProcessSession::opt_in(fallback, limits)` implements the core's edit round-trip
`EditSession`. It keeps the supplied narrow editor and precision fallback and reads
every package under the host's document limits (`Vault::docedit_package_limits`).
Supported local XLSX workbooks recalculate through one multi-sheet graph. Only formula
spellings and scalar cached values change; the retained OPC package keeps every other
record and unknown XML. External links, defined names, shared/array/table formulas and
spill serialization stay on the precision fallback. Destructive external-link fallback
output is refused.

The evaluator is formualizer 0.9.3 from the org fork `oneiron-dev/formualizer`, pinned
by rev in the root manifest (0.9.3-oneiron.2): upstream plus the owned patch that keeps
a typed error on either side of `&`, plus the Excel parity work on the fork's
`oneiron/parity` branch (ONE-2700 part 1). `docs/ops/forked-dependencies.md` records the
fork branch, the rev and the patches. Nothing of formualizer is vendored here.

The unchanged evaluator scored 754/811 native Excel goldens, versus LibreOffice's
753/811 on the same deterministic cases; the parity fork scores 809/811 and 2,700 of
the 2,951 SpreadsheetBench cases. The separate real-workbook corpus gate remains
unmet, so this adapter is opt-in, not the default: the host owns session
construction. The comparison uses a pinned UTC instant. Production volatile or
context-dependent formulas route to the supplied precision fallback, not that clock.

Recalculated versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.2`.
The corpus report separately identifies the evaluator (`ENGINE_STAMP`). A no-recalc
plan records no stamp; fallback runs record the fallback's own engine and version.

Binaries: `measure` scores the pinned compatibility corpus
(`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat`), and `recalc_native`
writes one retained native recalculation for an application-oracle check.
