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

- the external links the engine cannot read as Excel does with the linked workbook closed (see
  "Linked workbooks" below); `preserve_external_links` refuses host output that alters or drops
  a link;
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

## Linked workbooks

A formula names a linked workbook by its place in the workbook's `<externalReferences>` list
(`[1]Sheet!A1`), and the link's part (`xl/externalLinks/externalLinkN.xml`) keeps the values Excel
last read from it. With the linked workbook closed, Excel for Windows computes from those saved
values, and so does the engine: a saved cell is its value, a cell not saved is blank, a sheet the
link does not name is `#REF!`, and on a sheet Excel could not read at its last refresh
(`refreshError`), or saved nothing for, every cell not saved is `#REF!`. ROW, COLUMN, ROWS,
COLUMNS and INDEX go by the reference as written, and an ordinary formula intersects a linked range
with its own cell. Such workbooks recalculate natively, and every link part, link relationship and
link content type, and every relationship part with an external target, stays byte for byte (the
edit gate checks the link join and the parts too). Evidence: probes 1 to 3 of the fork's
`ops/excel-extlinks-probe-20261006.md` (Excel for Windows 16.0.20430, 192 cases) and the
SpreadsheetBench workbooks with links (Excel truth recorded with links not updated).

These forms keep the fallback, each with its own reason: a DDE or OLE link; a link part the check
cannot read, or one that links nothing it knows; an external relationship other than a hyperlink, a
link's path or a pivot cache's external source; a link list or link content type the edit gate cannot
join; a reference by file name, to `[0]` (the workbook itself) or to a link the list does not hold;
a name defined in the linked workbook (`[1]!Rate`); a 3D linked reference; a linked reference in a
reference operator (`:`, intersection, union), directly, through INDEX or through a name; a
multi-cell linked range passed on by a function that returns references (IF, CHOOSE, IFS, XLOOKUP,
OFFSET, INDIRECT, LET), by INDEX unless it narrows it to one cell, or given to AREAS, RANK or
GETPIVOTDATA, or standing as the whole formula (the engine holds a linked range as values with no
position, so intersection and the criteria functions' `#VALUE!` would not see it); a linked range
reaching a criteria function's range through a name; and an open or very large linked range, read
only up to the last saved cell (plus one `#REF!` on a sheet with a refresh error), unless its
function gives Excel's result from those cells: INDEX at one cell, ROWS, COLUMNS, exact MATCH,
VLOOKUP and HLOOKUP, SUM, AVERAGE, MIN, MAX, PRODUCT, COUNT, CONCAT, the criteria functions' ranges
(`#VALUE!` for any closed linked range), and COUNTA where the unsaved cells are blank. Counting the
unsaved cells, pairing the range with one of another length, ROW over it and approximate searches
stay the fallback's.

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
the fallback, as before: the link check fails closed.

The evaluator is formualizer 0.9.3 from the org fork `oneiron-dev/formualizer`, pinned
by rev in the root manifest (0.9.3-oneiron.9): upstream plus the owned patch that keeps
a typed error on either side of `&`, plus the Excel parity work on the fork's
`oneiron/parity` branch (ONE-2700 parts 1 and 3, the third, fourth and fifth parity loops, and
stage 2's linked workbooks). `docs/ops/forked-dependencies.md` records the
fork branch, the rev and the patches. Nothing of formualizer is vendored here.

The corpus rule (default only at or above LibreOffice on the same corpus) is met at fork
rev `91599813`: through the writer, all 2,967 scored fresh-Excel SpreadsheetBench
workbooks (truth recorded on Excel for Windows 16.0.20430; cells downstream of NOW/TODAY/RAND
skipped) are fully Excel-identical (LibreOffice 25.8 matched 2,648 of the 2,951 it was measured
on), and all 811 pinned native Excel goldens (recorded on Excel for Windows 16.0.20430; the
goldens reader resolves Excel's rich-value error caches since 2026-10-03), against
LibreOffice's 753 (the unchanged evaluator scored 754). The comparison uses a pinned UTC
instant. Production volatile or context-dependent formulas route to the precision fallback,
not that clock.

The shipped adapter on the same corpus (2026-10-07, `recalc_native` over the 5,455 saved
originals, 3,040 of them with formulas; the retained OPC reader admits their ZIP directory
entries): 2,705 of the 3,040 formula workbooks (89.0%) recalculate natively, none is refused
outright and 335 fall back: 274 for caller context, 32 for functions the engine lacks, 15 for
precision-as-displayed, 8 for linked-workbook forms the engine does not read as Excel does (5
linked ranges INDEX selects at a computed row, 3 approximate VLOOKUPs over open linked ranges),
3 over the token bound and 3 for an unreadable defined name. All 2,705 native workbooks match
Excel (none of their 537,893 scored cells differs), and every native output passes the edit
gate. Of the 279 formula workbooks with external links or external relationship targets, which
all fell back before, 197 recalculate natively (none of their 149,486 scored cells differs from
Excel), 74 now meet another reason (51 caller context, 12 precision-as-displayed, 11 unknown
functions) and 8 a linked-workbook form. The checks for escaped names and formulas, related tables
and malformed workbook metadata change no corpus workbook's decision or output bytes.

Recalculated versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.9`.
The corpus report separately identifies the evaluator (`ENGINE_STAMP`). A no-recalc
plan records no stamp; fallback runs record the fallback's own engine and version.

Binaries: `measure` scores the pinned compatibility corpus
(`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat`), and `recalc_native INPUT
OUTPUT` runs the shipped adapter on one workbook. It writes the native recalculation and
exits 0, or writes nothing and exits 3 when the adapter refuses the workbook to the
fallback, 4 when the engine fails (the round trip falls back too) and 2 when the round trip
refuses the package outright; stdout carries a JSON report with the reason.
