# docx fixtures (synthetic, not Word oracle output)

`minimal-document.xml`: two plain-text paragraphs with run properties,
paragraph properties, and an unknown-namespace sibling. The unit tests in
`src/docx/tests.rs` inline the same bytes; this file is the oracle-readable
reference for the representative input shape.

No third-party documents, no Word-produced bytes, no personal data. Word
validity is judged by the Mac oracle opening the example output
(`examples/docx_tracked_change.rs`), never claimed here.
