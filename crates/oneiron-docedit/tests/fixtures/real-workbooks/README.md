# Real-workbook measurement inputs

ARCH-0075 requires this set as well as spreadsheet-compat. Acquisition is pinned
in `provenance.json`; corpus workbooks are local-only and are not redistributed.
SpreadsheetBench (RUCKBReasoning, pinned commit in the receipt) is CC BY-SA 4.0.
FUSE (Barik et al., DOI 10.5281/zenodo.581678) is CC BY 4.0. The Witan Labs
xlsx-corpus-bench harness is Apache-2.0.

The acquired SpreadsheetBench archive yields 5,455 distinct workbooks. The FUSE
source returned HTTP 504 on the initial and repeated download. The API endpoint
subsequently delivered the complete archive. Its published size and MD5 passed;
`fuse-download-receipt.json` pins the resulting SHA-256. Extraction classified 249,376 members and retained 10,702 unique XLSX files.
`fuse-manifest.jsonl.gz` pins their hashes and source-member names; its decompressed
SHA-256 is recorded in the provenance and extraction receipt. The archive
contains split `FUSE.7z` volumes; the selected inner archive is
`fuse-cc-binaries.tar.gz`. Non-ZIP and non-XLSX inputs are classified separately.
Fresh comparisons remain pending. Witan's full
15,970-workbook result excludes its Excel skips and uses freshly recalculated
Excel truth files that are not published with the harness. Original saved
caches can support a diagnostic measurement, not a claim of the same oracle.
The formula adapter remains explicit opt-in; the compatibility score alone
must not be called the complete two-corpus default-selection decision.

The unchanged upstream cache-only executable completed 5,455 workbooks. Of 1,225,018 scored formula cells, 49,073 matched their saved caches. This is a diagnostic, not fresh Excel truth or a release threshold. 3,163 workbook recalculations refused explicitly; the largest class is upstream ZIP-local-extra metadata support (2,152). The original cell-count denominator includes refused files rather than hiding them.

Complete stored measurement receipts are checked offline by
`scripts/tests/test_real_workbook_receipts.py`: the compressed manifests pin the
exact cohorts, and compressed rows must reproduce the published classification
and diagnostic arithmetic. CI runs these checks together with the stored Office
goldens. No app is launched by those tests, and no diagnostic is promoted to
fresh Excel truth.
