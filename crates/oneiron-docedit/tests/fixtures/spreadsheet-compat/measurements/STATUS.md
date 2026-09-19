# Native Excel comparison

All 834 pinned cases were measured with unchanged formualizer 0.9.3. Excel
16.112.4 supplies the cached-value truth; upstream expected values are not goldens.
The 811 deterministic, accepted formulas score:

| Engine | Matches | Rate |
|---|---:|---:|
| formualizer 0.9.3, unchanged | 754 / 811 | 92.9716% |
| LibreOffice 25.8.2.2 | 753 / 811 | 92.8483% |

Twenty-two volatile cases and one Excel-rejected malformed LET formula are
explicitly excluded. Per-function counts and every mismatch are in `comparison.json`.
The adapter serializes date/time values as Excel numeric caches. The earlier
746/811 comparison used display strings for those values and is superseded.
No upstream evaluator code changed between the two measurements.

This meets ARCH-0075's same-corpus threshold for selecting the in-process route.
The real-XLSX adapter still sends external links and unsupported workbook features
to the existing precision fallback. A same-corpus score does not imply all Excel
features are supported. The crate's package/property tests exercise that routing.

Original native-workbook SHA-256 and privacy-normalized fixture SHA-256 are both
recorded in `../excel/goldens.json`. Native receipts retain exact Office versions.
