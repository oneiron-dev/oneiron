# Spreadsheet formula compatibility dataset (Excel / Google Sheets / LibreOffice)

An open dataset recording, for ~600 spreadsheet functions, whether each is available in
**Microsoft Excel**, **Google Sheets**, and **LibreOffice Calc** — with the LibreOffice
verdicts produced by *actually executing* each formula in headless LibreOffice (not scraped
from documentation). As far as we know it is the only openly available **executed**
cross-application spreadsheet-compatibility dataset.

- **Homepage / source:** https://canispreadsheet.com/data.html
- **Methodology:** https://canispreadsheet.com/methodology.html
- **License:** Creative Commons Attribution 4.0 (CC BY 4.0) — free to use with attribution.
- **Files:** `compat.csv` (one row per function, headered) and `compat.json` (object keyed by function name). Both are regenerated from the site's live test results.

## Columns

| Column | Type | Meaning |
|---|---|---|
| `function` | string | Function name, uppercase (e.g. `VLOOKUP`). |
| `category` | string | Function category (e.g. "Lookup and reference"). |
| `in_excel` | bool | Documented as available in Microsoft Excel. |
| `in_google_sheets` | bool | Documented as available in Google Sheets. |
| `in_libreoffice` | bool | Documented as available in LibreOffice Calc. |
| `libreoffice_verdict` | string | Result of executing a real test case in LibreOffice (e.g. `supported`, `unsupported`); empty if the function is documented-only and not yet in the executed test set. |
| `libreoffice_version_tested` | string | LibreOffice version the executed test ran on (e.g. `25.8.7.3`). |
| `libreoffice_newly_supported_in` | string | LibreOffice version in which the function first started working, when known (from testing across multiple versions); empty otherwise. |

## How it's produced

Excel and Google Sheets availability come from each vendor's official function
documentation. LibreOffice verdicts come from writing each function's formula into a
workbook, converting it headlessly with LibreOffice (`soffice --headless`), and reading
back the recalculated result — with canary formulas proving the sheet actually
recalculated. Tests are run across several LibreOffice versions to capture when support
was added. Full harness, authored test cases, and per-version raw results:
https://github.com/xxaflabsxx/spreadsheet-compat

## Citation

> Can I Spreadsheet? — Open spreadsheet formula compatibility dataset. https://canispreadsheet.com/data.html (CC BY 4.0).

## Limitations

- Excel / Google Sheets verdicts are documentation-based, not live-executed (only
  LibreOffice is executed).
- The executed LibreOffice test set covers the most-used functions; documented-only
  functions have empty `libreoffice_verdict`.
- Corrections and additions welcome via the GitHub repository.
