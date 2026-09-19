# In-process XLSX formula engine

`InProcessSession::opt_in(fallback)` implements the document organ's `EditSession`.
It keeps the supplied narrow editor and precision fallback. Supported local XLSX
workbooks recalculate through one multi-sheet graph. Only formula spellings and
scalar cached values change; other package records and unknown XML stay retained.
External links, defined names, shared/array/table formulas and spill serialization
stay on the precision fallback. Destructive external-link fallback output refuses.

The unchanged evaluator scored 754/811 native Excel goldens, versus LibreOffice's
753/811 on the same deterministic cases. The separate real-workbook corpus gate
remains unmet, so this adapter is opt-in, not the default. The host owns session construction. `vendor/formualizer/PROVENANCE.md` records
the fork decision and byte-identical upstream source pins. No evaluator rewrite
was justified. The comparison uses a pinned UTC instant. Production volatile or context-dependent
formulas route to the supplied precision fallback, not that comparison clock.

Production XLSX versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3`.
The baseline corpus report separately identifies the unchanged upstream evaluator.
The adapter's version is not hidden behind the upstream version. A no-recalc plan
stamps `none`; fallback runs report their actual supplied engine/version.
