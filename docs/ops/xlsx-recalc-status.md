# XLSX recalculation status (L4106)

An XLSX export or preview either recalculates in process or keeps the
projected package's cached values and marks the file to recalculate on
open (`calcPr fullCalcOnLoad="1"`). Recording this status does not change
either path's existing bytes, calculation behavior, or cached values.

## Record-level reason

`OfficeBodyExportRecord.recalc_failure` and `XlsxPreview.recalc_failure`
(`crates/oneiron/src/office_body/records.rs`) carry the same typed
`OfficeRecalcFailure { code, detail }`: the engine's `FormulaError::code()`
(for example `engine-error`, `unsupported-workbook`) and its display
string. No new frontier, identifier or hash is added to the exported file.

Outcome invariant on XLSX paths: exactly one of `recalc` and
`recalc_failure` is `Some` (success sets the stamp, fallback sets the
failure). DOCX and deck exports set both to `None`: they recalculate
nothing. Live reads keep the success-stamp check only; a fallback there
keeps the body's held values as before.

## Preview-only unit marker

On a fallback preview, each computed cell of the read-back book (a
formula, or a shared/array/data-table member) carries
`XlsxCell.recalc = Some(XlsxCellRecalc::CachedAfterFailure)`
(`crates/oneiron-docedit/src/xlsx_body/model.rs`). It means only that
this preview did not recompute the cell and its value is the existing
cache; it is not a per-cell engine error and says nothing about
correctness. Raw reads leave it `None` (omitted on the wire), so the raw
docedit contract grammar is unchanged, as are the Loro schema and the
body cells. The export record has no per-cell surface, so it carries the
record-level reason only.

## Scope notes

- No refusal, blanking, gate, default, ABI or schema bump. Preview and
  export status is covered; live reads keep their existing held-value
  behavior. This is not whole FIX4106 closure or a per-cell correctness proof.
- SDK/uniffi mirrors regenerate through the normal generator; never
  hand-edited.
