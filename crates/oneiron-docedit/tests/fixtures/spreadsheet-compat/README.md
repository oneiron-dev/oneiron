# Spreadsheet compatibility fixtures

Source: **Can I Spreadsheet? — Open spreadsheet formula compatibility dataset**,
https://canispreadsheet.com/data.html, https://github.com/xxaflabsxx/spreadsheet-compat.
License: Creative Commons Attribution 4.0, https://creativecommons.org/licenses/by/4.0/.
The upstream dataset card is preserved alongside this file.

`cases.json` normalizes the 277 `data/tests/*.json` files from the pinned v1.0.1
Zenodo archive into 834 cases. Each row adds its source function; other fields and
case order are unchanged. `provenance.json` pins both archive and normalized bytes.
This is larger than the 604-case count in ARCH-0075. No cases were silently discarded.

`expected` contains upstream expectations, **not** measured Excel goldens.
Oracle outputs must live separately and carry app version, input/output hashes,
calendar mode, and recalc-canary evidence. Probe-only cases have no fixed expectation
and must not be counted as exact-value matches.

`excel/goldens.json` and `excel/cached-workbooks.zip` are the measured Excel goldens: 834 cases
recorded on **Excel for Windows 16.0.20430.20118** (en-US region, 2026-10-02) by
`scripts/office/win_excel_cases.py` (COM: one new workbook per case, setup cells typed as the
corpus says, the `Z1` canary, the formula at the check anchor, calculate, save) and pinned by
`scripts/office/collect_excel_goldens.py`. On 2026-10-03 the reader learned Excel's rich-value error
caches (`#CALC!`, `#SPILL!` and the other errors newer than the file format are saved as a `#VALUE!`
cell plus an `xl/richData` record naming the real error); the receipt and goldens were re-read from
the same 2026-10-02 workbooks, which changed one value (FILTER_all_false_no_default is `#CALC!`). The first recording (Excel for Mac 16.112.4, a
Japanese-region Mac) differed in 7 values: DOLLAR's currency symbol, TRIM with a Mac Roman
CHAR(160), VALUE of a currency string, and the four NOW/TODAY/RAND cases. Where Excel for
Windows and Excel for Mac differ, Windows is the reference (ruling 2026-10-01).

