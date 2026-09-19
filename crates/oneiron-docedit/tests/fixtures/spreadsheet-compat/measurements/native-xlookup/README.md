# Native XLOOKUP application observation

The input starts from `XLOOKUP_exact_match`. Its `_xlfn.` prefix is removed and
its F1 cache is changed from 2 to 0. The native adapter restores both the prefix
and the value. Excel 16.112.4 reads 2 and saves the native output normally.

Only worksheet parts are redistributed; full Office files stay in ignored scratch
because their document properties contain local application metadata. Archive
hashes, engine identity, and the exact observed script are pinned in the receipt.
The driver's literal `tab` separator collided with Excel's dictionary. Its
successful output was recovered explicitly. Excel dropped its unmodified startup
Book1 on open. The later inventory relaunched Excel; that verified blank startup
workbook was closed. No saved unrelated workbook was closed, no app was killed,
and the shared lock was released. The reusable driver now uses ASCII character 9
and separately recognizes the untouched startup workbook.
