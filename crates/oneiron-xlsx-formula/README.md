# In-process XLSX formula engine

The default recalc of the core's edit round trip. `oneiron::edit_roundtrip` wraps every
host `EditSession` unless the host opts out (`EditSession::recalc_policy` returning
`RecalcPolicy::SessionOnly`): the host keeps its narrow editor, and
`FormualizerEngine::recalculate_xlsx` recalculates every workbook it admits, reading each
package under the host's document limits (`Vault::docedit_package_limits`; the raw
`run_edit_roundtrip` uses the shipped ceilings). The recalculation is the fork's retained
cache writer, `formualizer_workbook::recalculate_xlsx_bytes` (upstream feature
`xlsx-recalc`), run under the stricter of each host limit and its own. One multi-sheet
graph evaluates ordinary, shared and array formulas, dynamic arrays inside their saved
extent, defined names, tables and structured references, and the workbook's iteration
settings. Only formula caches, their value types, calculate-always flags and Excel's rich
error tags change; the package keeps every other byte. This crate depends on
`oneiron-docedit`, never on the core.

The host's own recalc (LibreOffice headless in production) is the precision fallback for
refused workbooks only. The adapter refuses, before any output:

- external links: they keep their link-preserving route to the host, and
  `preserve_external_links` refuses host output that alters or drops a link;
- a formula, in a cell or a defined name, that needs caller context or volatile reference
  semantics (NOW, TODAY, RAND, RANDBETWEEN, RANDARRAY, CELL, INFO, OFFSET, INDIRECT), called
  or passed by name (`_xleta.RANDBETWEEN`);
- a function the engine does not implement, after the `_xlfn.`/`_xlws.` prefixes resolve
  as the engine resolves them, where the engine would cache `#NAME?`;
- a workbook name used as a function: a defined name that holds a LAMBDA, a name passed where
  MAP, REDUCE, SCAN, BYROW, BYCOL, MAKEARRAY, GROUPBY or PIVOTBY take their LAMBDA, or a
  defined name called like a function. The engine does not resolve workbook LAMBDA names
  yet and would cache `#NAME?`; LET names and LAMBDA parameters stay native;
- a shared or inline string whose OOXML escapes the writer's reader (Calamine 0.36) decodes
  differently from Excel: it decodes `_x00HH_` but keeps `_x20AC_` (the euro sign) as seven
  characters. It decodes no escape in a literal `t="str"` value, a cell formula, a defined
  name or its formula, or a sheet, table or table-column name, so any escape there falls
  back (`"_x20AC_"` in a defined name is `"€"` to Excel);
- precision-as-displayed (`fullPrecision="0"`): the writer calculates at full precision;
- a formula over the size, token or nesting bound that keeps evaluation off deep recursion,
  or one the parser cannot read;
- what the writer cannot write exactly, such as a dynamic array larger than its saved extent;
- a result the host could not read back under its own limits, such as a worksheet whose new
  caches take it over the XML node limit;
- a recalculation the edit gate would refuse: one that changes `xl/richData/` (the rich value
  of a new `#SPILL!` or `#CALC!`), which the gate passes through byte for byte, or a changed
  worksheet holding a modern function without its OOXML prefix (the writer never rewrites
  formula text).

A package the retained OPC reader refuses fails outright, as before. Malformed workbook
content fails outright too, as it did before the writer: the adapter reads the workbook, its
relationships, the shared strings, every worksheet and every table a worksheet relates as the
old loader did, and refuses a missing, unreadable, off-grid or repeated cell address, a literal
its type cannot hold (a number that is not one, a boolean other than 0 or 1, a shared-string
index past the table, an inline string without its text), an invalid `date1904` flag, a broken
sheet list, a missing, non-numeric or repeated sheet ID, a repeated defined name or one scoped
past the sheets, and a table part that is malformed XML, missing, unnamed, named twice, or
whose range is unreadable or not spanned by its columns. Valid content the writer does not
support (sheet ID 0, two header rows) still goes to the fallback. Every part the writer reads
(the workbook, shared strings, worksheets, each table wherever its worksheet's relationship
puts it, content types, styles, cell metadata and rich data) must fit the host's XML node and
depth limits, or the workbook fails outright. A relationship part that does not fit goes to
the fallback, as before: the external-link check fails closed.

The evaluator is formualizer 0.9.3 from the org fork `oneiron-dev/formualizer`, pinned
by rev in the root manifest (0.9.3-oneiron.8): upstream plus the owned patch that keeps
a typed error on either side of `&`, plus the Excel parity work on the fork's
`oneiron/parity` branch (ONE-2700 parts 1 and 3 and the third, fourth and fifth parity loops). `docs/ops/forked-dependencies.md` records the
fork branch, the rev and the patches. Nothing of formualizer is vendored here.

The corpus rule (default only at or above LibreOffice on the same corpus) is met at fork
rev `63e2ec69`: through the writer, 2,963 of the 2,967 scored fresh-Excel SpreadsheetBench
workbooks (truth recorded on Excel for Windows 16.0.20430; cells downstream of NOW/TODAY/RAND
skipped) are fully Excel-identical (LibreOffice 25.8 matched 2,648 of the 2,951 it was measured
on), and all 811 pinned native Excel goldens (recorded on Excel for Windows 16.0.20430; the
goldens reader resolves Excel's rich-value error caches since 2026-10-03), against
LibreOffice's 753 (the unchanged evaluator scored 754). The comparison uses a pinned UTC
instant. Production volatile or context-dependent formulas route to the precision fallback,
not that clock.

The shipped adapter on the same corpus (2026-10-06, `recalc_native` over the 5,455 saved
originals, 3,040 of them with formulas; the retained OPC reader admits their ZIP directory
entries): 2,508 of the 3,040 formula workbooks (82.5%) recalculate natively, none is refused
outright and 532 fall back: 279 for external links, 223 for caller context (132 clock or
random functions, 82 OFFSET or INDIRECT only, 9 CELL), 21 for functions the engine lacks, 3
for precision-as-displayed, 3 over the token bound and 3 for an unreadable defined name. All
2,508 native workbooks match Excel (none of their 388,407 scored cells differs), and every
native output passes the edit gate. The checks for escaped names and formulas, related tables
and malformed workbook metadata change no corpus workbook's decision or output bytes.

Recalculated versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.8`.
The corpus report separately identifies the evaluator (`ENGINE_STAMP`). A no-recalc
plan records no stamp; fallback runs record the fallback's own engine and version.

Binaries: `measure` scores the pinned compatibility corpus
(`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat`), and `recalc_native INPUT
OUTPUT` runs the shipped adapter on one workbook. It writes the native recalculation and
exits 0, or writes nothing and exits 3 when the adapter refuses the workbook to the
fallback, 4 when the engine fails (the round trip falls back too) and 2 when the round trip
refuses the package outright; stdout carries a JSON report with the reason.
