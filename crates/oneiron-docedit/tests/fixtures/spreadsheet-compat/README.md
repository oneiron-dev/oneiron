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
