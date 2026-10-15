# Retained OPC fixture

Original synthetic test data, not an Office oracle result.
`retained-opc.zip` has deflated Office XML, an unknown namespace node, a custom XML part,
ZIP extra fields, entry comments and an archive comment. Generated with Python's ZIP writer.
SHA-256: `8f5caa84f02d27964809f65df03f270cd20fda33be98cbd671e8d6fe35e460f4`.

No third-party documents or personal data are included.

# Archived Office receipts

Office oracle receipts from W7-C14 (real-workbook runs, spreadsheet measurements, the DOCX
comparison and the PPTArena identity run) are evidence of past runs and are not stored here.
`archived-receipts.json` names each one by its old path under this folder, its size and its
BLAKE3; the kept branch `w7/W7-C14` holds the same bytes. The inputs those runs read (corpus
cases, Excel goldens, manifests, DOCX fixtures) do live here.
