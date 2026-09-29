# docx fixtures (synthetic, not Word oracle output)

`minimal-document.xml`: two plain-text paragraphs with run properties,
paragraph properties, and an unknown-namespace sibling. It is the
oracle-readable reference for the representative input shape. The W7-C14
DOCX writer tests that inline the same bytes (`src/docx/tests.rs` and
`examples/docx_tracked_change.rs` on the kept branch `w7/W7-C14`) are not on
main yet; they come with the port of that writer onto this crate.

No third-party documents, no Word-produced bytes, no personal data. Word
validity is judged by the Mac oracle opening the writer's output, never
claimed here.
