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

The recalculation behaves like Excel recalculating at edit time. Its caller passes a
`RecalcClock`: the instant NOW() and TODAY() read (sampled once, so every call agrees), the
local UTC offset their date and time use, and the seed of RAND, RANDBETWEEN and RANDARRAY. The
core takes it from the host session (`EditSession::recalc_clock`), else samples the host's
clock, its local offset and a fresh seed from the operating system when the recalc runs,
which is what the host's own recalc reads. The same clock and seed recalculate the same
bytes. Like the clock, where the workbook was opened from belongs to the host: the caller may
pass a `DocumentLocation`, the folder as Excel for Windows prints it with its trailing separator
and the file's name (`C:\Reports\` and `Budget.xlsx`; `DocumentLocation::from_path` splits
`C:\Reports\Budget.xlsx`), and the core takes it from the host session
(`EditSession::recalc_location`). CELL("filename") then prints Excel's text,
`C:\Reports\[Budget.xlsx]Sheet1` for the reference's sheet, and CELL("address") of another
sheet's cell names the file, `[Budget.xlsx]Other!$B$2`, quoted as Excel quotes it
(ops/excel-hostinfo-probe-20261008.md). Without a location the recalc reads the one Excel last
saved: the workbook's own cached CELL("filename") values, when each names a folder, a file and
one of the workbook's sheets and they agree; a workbook that reads its location and has neither
falls back. OFFSET, INDIRECT (A1 and R1C1 text) and CELL's `col`, `contents`, `row` and `type`,
`address` of a reference written without a sheet and text that is no info type (`#VALUE!`), and
INFO's `memavail`, `memused` and `totmem` (`#N/A`) and text that is no type (`#VALUE!`), read
the workbook alone and recalculate natively. A defined name evaluates for the formula that uses it, as Excel
evaluates it: relative R1C1 text and ROW() in a name read the calling cell
(`Prev = INDIRECT("RC[-1]",FALSE)` in B2 reads A2), and a random call in a name is one more
draw of the calling formula, so the same clock and seed still recalculate the same bytes.

The host's own recalc (LibreOffice headless in production) is the precision fallback for
refused workbooks only. The adapter refuses, before any output:

- the external links the engine cannot read as Excel does with the linked workbook closed (see
  "Linked workbooks" below); `preserve_external_links` refuses host output that alters or drops
  a link;
- a formula, in a cell or a defined name, that reads what only the host knows: INFO's
  `directory`, `numfile`, `origin`, `osversion`, `recalc`, `release` and `system` (the
  application that calculates) or a computed INFO type; CELL without a reference (the active
  cell), with `"format"`, `"color"`, `"parentheses"`, `"prefix"`, `"protect"` or `"width"` (cell
  formatting the engine does not model), with a computed info type, or passed by name
  (`_xleta.CELL`); and CELL with `"filename"`, or with `"address"` of a reference that names a
  sheet or is computed, when neither the caller nor the workbook's caches give the location
  (above). Each reason names the call;
- INDIRECT text that names a workbook (`'[Book.xlsx]Sheet1'!A1`, `Book.xlsx!Total`), literal
  or computed: Excel reads it from that workbook when it is open, this one under the name it
  was saved with, which the recalc does not know. The writer refuses the workbook as soon as
  evaluation meets such text, whatever IFERROR makes of the closed workbook's `#REF!`;
- an Excel function the engine does not implement, after the `_xlfn.`/`_xlws.` prefixes
  resolve as the engine resolves them, where the engine would cache `#NAME?`: a bare name of
  the Excel 2007 file format's functions (with the bare names the fork's list lacks, from
  LibreOffice's and Apache POI's function tables: DBCS, the name a file gives JIS, USDOLLAR,
  YEN, DATESTRING, NUMBERSTRING, the Thai functions and EUROCONVERT), one written `_xlfn.` or
  `_xlws.`, one passed by name (`_xleta.`), or an Excel 4.0 macro function a defined name may
  call (any `GET.` name, `EVALUATE`, `FILES` and the others);
- a call that Excel may resolve through code the file does not carry: an XLL add-in's
  function (`_xll.Foo`), and, in a package holding a VBA project (`xl/vbaProject.bin`, or any
  part typed `application/vnd.ms-office.vbaProject`), any called name the engine does not
  resolve, which Excel with macros enabled would call. Every other called name is outside
  Excel's function list as the file spells it (`IMAGE` without `_xlfn.`, `EOM`, a VBA
  function saved in an `.xlsx`, Google Sheets' `__xludf.DUMMYFUNCTION` and `arrayformula`):
  Excel for Windows reads it as an undefined name, `#NAME?`, whatever the call's arguments
  hold, which IFERROR and the criteria functions see, and the engine does the same natively,
  in a cell or a defined name. Excel saves `ca="1"` on such a formula only when it evaluated
  the call; the writer flags every formula holding one, so a call in an IF branch Excel does
  not take is saved calculate-always where Excel saves no flag, as a volatile call there is
  (the cached values agree);
- a workbook name used as a function: a defined name that holds a LAMBDA, a name passed where
  MAP, REDUCE, SCAN, BYROW, BYCOL, MAKEARRAY, GROUPBY or PIVOTBY take their LAMBDA, a
  defined name called like a function, or a linked workbook's name called as one
  (`[1]!Fn(1)`, as Excel writes an add-in workbook's function). The engine does not resolve
  workbook LAMBDA names yet and would cache `#NAME?`; LET names and LAMBDA parameters stay
  native;
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
edit gate checks the link join and the parts too). Evidence: probes 1 to 5 of the fork's
`ops/excel-extlinks-probe-20261006.md` (Excel for Windows 16.0.20430, 216 cases) and the
SpreadsheetBench workbooks with links (Excel truth recorded with links not updated).

These forms keep the fallback, each with its own reason: a DDE or OLE link; a link part the check
cannot read, or one that links nothing it knows; an external relationship other than a hyperlink, a
link's path or a pivot cache's external source; a link list or link content type the edit gate
cannot join; link markup the engine's reader would read where Excel reads none (it matches the list
entry, the relationship, the cache's elements and their attributes by local name, so a vendor
extension's look-alike `u:cell` would replace a saved value); an OOXML escape in a linked sheet name
or a saved value (`a_x0001_b` is three characters to Excel, nine to the reader), or a saved value of
a type the reader takes otherwise (`t="s"`, a number that is not one); a reference by file name, to
`[0]` (the workbook itself) or to a link the list does not hold; a name defined in the linked
workbook (`[1]!Rate`, `[1]Sheet1!Rate`); a 3D linked reference; a linked reference in a reference
operator (`:`, intersection, union), directly, through INDEX or through a name; a multi-cell linked
range passed on by a function that returns references (IF, CHOOSE, IFS, XLOOKUP, OFFSET, INDIRECT,
LET), by INDEX unless it narrows it to one cell, or given to AREAS, RANK or GETPIVOTDATA, or
standing as the whole formula (the engine holds a linked range as values with no position, so
intersection and the criteria functions' `#VALUE!` would not see it); a linked reference, one cell
too, reaching a criteria function's range through INDEX, IF, CHOOSE, another function or a name
(Excel's `#VALUE!`; the engine computes it), or reaching ROW, COLUMN, ROWS, COLUMNS, ISREF, AREAS,
ISFORMULA, FORMULATEXT, SHEET or SHEETS through IF, CHOOSE or another function that hands it on as
values (INDEX hands on the reference); a linked reference bound to a LET name or a LAMBDA parameter;
and an open or very large linked range, read only up to the last saved cell (plus one `#REF!` on a
sheet with a refresh error), unless its function gives Excel's result from those cells: INDEX at one
cell, ROWS, COLUMNS, exact MATCH, VLOOKUP and HLOOKUP, SUM, AVERAGE, MIN, MAX, PRODUCT, COUNT,
CONCAT, the criteria functions' ranges (`#VALUE!` for any closed linked range), and COUNTA where the
unsaved cells are blank. Counting the unsaved cells, pairing the range with one of another length,
ROW over it and approximate searches stay the fallback's. A workbook name that reads a linked
workbook, itself or through another name, is checked where each formula uses it, as if its formula
were written there (`ROW(Chosen)` with `Chosen` holding `IF(TRUE,[1]S!$A$3)` falls back as
`ROW(IF(TRUE,[1]S!$A$3))` does). A name with a relative linked reference anywhere in its formula
(`IF(TRUE,[1]S!$A3)`) falls back wherever it is used, itself or through another name: Excel moves
the reference with the cell using the name, and the engine does not.

A package the retained OPC reader refuses fails outright, as before. Malformed workbook content,
linked or not, fails outright too, as it did before the writer: the adapter reads the workbook, its
relationships, the shared strings, every worksheet and every table a worksheet relates as the old
loader did, and refuses a missing, unreadable, off-grid or repeated cell address, a literal its type
cannot hold (a number that is not one, a boolean other than 0 or 1, a shared-string index past the
table, an inline string without its text), an invalid `date1904` flag, a broken sheet list, a
missing, non-numeric or repeated sheet ID, a repeated defined name or one scoped past the sheets, a
table part that is malformed XML, missing, unnamed, named twice, or whose range is unreadable or not
spanned by its columns, and a link part that is malformed XML. Valid content the writer does not
support (sheet ID 0, two header rows) still goes to the fallback. Every part the writer reads (the
workbook, shared strings, worksheets, each table wherever its worksheet's relationship puts it, each
link part, content types, styles, cell metadata and rich data) must fit the host's XML node and
depth limits, or the workbook fails outright. A relationship part that does not fit goes to the
fallback, as before: the link check fails closed.

The evaluator is formualizer 0.9.3 from the org fork `oneiron-dev/formualizer`, pinned
by rev in the root manifest (0.9.3-oneiron.12): upstream plus the owned patch that keeps
a typed error on either side of `&`, plus the Excel parity work on the fork's
`oneiron/parity` branch (ONE-2700 parts 1 and 3, the third, fourth and fifth parity loops,
stage 2's linked workbooks and caller-context functions, five commits picked from upstream's
`main`, and stage 2 wave 2's closed-linked-workbook forms, host information, precision as
displayed, `#REF!` operands and spill references). `docs/ops/forked-dependencies.md` records
the fork branch, the rev and the patches.
Nothing of formualizer is vendored here.

The corpus rule (default only at or above LibreOffice on the same corpus) is met at fork
rev `468a333b`: through the writer, all 2,967 scored fresh-Excel SpreadsheetBench
workbooks (truth recorded on Excel for Windows 16.0.20430; cells downstream of NOW/TODAY/RAND
skipped) are fully Excel-identical (LibreOffice 25.8 matched 2,648 of the 2,951 it was measured
on), and all 811 pinned native Excel goldens (recorded on Excel for Windows 16.0.20430; the
goldens reader resolves Excel's rich-value error caches since 2026-10-03), against
LibreOffice's 753 (the unchanged evaluator scored 754). The comparison uses a pinned UTC
instant; the edit round trip uses the caller's clock (above).

The shipped adapter on the same corpus (2026-10-08, fork rev `492b432a`, `recalc_native` over
the 5,455 saved originals, 3,040 of them with formulas; the retained OPC reader admits their ZIP
directory entries): 2,994 of the 3,040 formula workbooks (98.5%) recalculate natively, none is
refused outright and 46 fall back: 15 for precision-as-displayed, 8 for linked-workbook forms the
engine does not read as Excel does (5 linked ranges INDEX selects at a computed row, 3 approximate
VLOOKUPs over open linked ranges), 6 for CELL("filename") with neither a caller location nor a
cached path, 6 past the evaluation depth bound, 6 for a reference to the workbook itself (`[0]`)
and 5 over the token bound. The 2,921 native workbooks with scored cells match Excel (none of their
1,043,569 scored cells differs); the other 73 hold only cells downstream of NOW, TODAY and RAND,
which the comparison skips. Given the file the Excel truth was recorded from
(`recalc_native --location`), the 6 CELL("filename") workbooks (SpreadsheetBench 342-46)
recalculate natively and match Excel; SpreadsheetBench 118-8's 6 then stop at the depth bound. The
fork rev's `#REF!` operands and spill references take SpreadsheetBench 14207 and 49667 (12
workbooks that fell back for parsing and `_xlfn.ANCHORARRAY`) native, matching Excel on every
scored cell. Of the 32 that fell back for an unregistered
function before, 27 recalculate natively and match Excel on every scored cell, those calling the
names too: 6 with `IMAGE` written without `_xlfn.` (`#NAME?`), 3 with the VBA function `ClrCnt`
and no VBA project (`#NAME?`), 3 with `EOM` in a SUMIFS criterion (0), 6 with Google Sheets'
`__xludf.DUMMYFUNCTION` and 3 with its `arrayformula`, inside IFERROR (IFERROR's value), and 6
whose `TjDAY()` sits in an IF branch Excel does not take (`""`). Of the 279 formula workbooks with
external links or external relationship targets, which all fell back before, 242 recalculate
natively (none of the 480,230 scored cells of the first 236 differs from Excel; the other 6 are
the `TjDAY` workbooks), 29 meet another reason (12 precision-as-displayed, 6 CELL("filename"), 6
the workbook itself, 5 `_xlfn.ANCHORARRAY`) and 8 a linked-workbook form. Of the 274
that fell back for caller context, 254 recalculate natively (none of their 384,165 scored cells
differs); 12 read CELL("filename"), 6 the workbook itself and 2 pass the token bound. The checks
for escaped names and formulas, related tables and malformed workbook metadata change no corpus
workbook's decision or output bytes.

Recalculated versions stamp `oneiron-xlsx-formula/0.1.0+formualizer.0.9.3-oneiron.12`.
The corpus report separately identifies the evaluator (`ENGINE_STAMP`). A no-recalc
plan records no stamp; fallback runs record the fallback's own engine and version.

Binaries: `measure` scores the pinned compatibility corpus
(`crates/oneiron-docedit/tests/fixtures/spreadsheet-compat`), and `recalc_native
[--location PATH] INPUT OUTPUT` runs the shipped adapter on one workbook, with PATH the file as
the host that opened it names it (`C:\Reports\Budget.xlsx`), else without a location. It
writes the native recalculation and exits 0, or writes nothing and exits 3 when the adapter
refuses the workbook to the fallback, 4 when the engine fails (the round trip falls back too)
and 2 when the round trip refuses the package outright; stdout carries a JSON report with the
reason.
