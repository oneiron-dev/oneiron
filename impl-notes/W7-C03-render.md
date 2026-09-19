# E-sign renderer integration (SGN04/05/07)

## API

The planned API is implemented unchanged in `blob_artifact::esign::render`:
- `prepare_esign_pdf(original: &[u8], request: PdfPreparation<'_>) -> Result<PreparedEsignPdf, PdfPreparationError>`.
- `PdfPreparation { document_ref: &str, item: u32, state: &EsignState, audit: &[EsignEventRow], canonical_url: &str, signature_images: &BTreeMap<String, SignatureRaster> }`.
- `SignatureRaster { width: u32, height: u32, rgba: Vec<u8> }` contains caller-decoded straight-alpha RGBA in top-to-bottom order.
- `PreparedEsignPdf { bytes: Vec<u8>, original_sha256: [u8;32], audit_chain_sha256: [u8;32], original_pages: u32, appendix_pages: u32 }`.
- `render_field_geometry(&FieldGeometry, [f64;4]) -> Result<PdfFieldRect, PdfPreparationError>` converts top-left percentages into PDF bottom-left crop coordinates.

Parent owns module declarations, re-exports, Cargo, orchestration, generated codemap, and build/test execution. Required new deps remain lopdf `=0.44.0`, default-features=false, and qrcode `=0.14.1`, default-features=false. Existing `flate2`, `sha2`, `serde_json`, and `thiserror` are reused.

## Implemented behavior

`render.rs` is the public seam and orchestration. Named children are `render/preflight.rs`, `render/source.rs`, `render/fields.rs`, and `render/evidence.rs`. All non-test files remain under 800 lines.

- Rebuilds a fresh catalog and page tree while retaining original page order, content, inherited boxes, and copied static resources.
- Resource references are remapped; cycles, missing parser objects, and active constructs refuse. Category maps handle legal resource names such as `/A` without mistaking them for actions. Inherited page data is borrowed, not deeply cloned per page. Repeated overlay resources are inserted in place.
- Catalog/page actions and unreferenced attachments are omitted. Reachable unsafe visual constructs refuse instead of silently changing their appearance.
- Every recorded field is burned into its selected original page. Text uses bounded Courier layout; checkboxes use paths; signature images use RGB plus an alpha-mask XObject. Missing, malformed, zero-sized, oversize, or fully transparent signature images refuse. Reference text is never substituted for pixels.
- Recorded rejection adds a visible red REJECTED mark to every original page.
- A certificate and metadata pages always follow the originals. Certificate includes the immutable original digest and version, document/item identifiers, outcome, audit digest/count, recipient and field summaries, and a vector QR for the caller-issued HTTPS capability URL.
- Full canonical audit JSON is rendered into additional pages only when requested. Unicode/control metadata is escaped; literal backslashes are escaped too so the representation stays unambiguous. The SHA-256 chain covers canonical raw event bytes, not the escaped display.
- Bounded canonical audit serialization precedes state cloning/replay. The complete chain is checked, replayed, and compared with the supplied projection. Inconsistent evidence refuses.
- No signing, key custody, networking, clock reads, I/O, or deployment hostname creation occurs in this layer. Parent must pass **all returned bytes** to the existing native PAdES implementation. These tests do not claim a CMS/PAdES verification proof; parent owns that integration.

## Explicit static-PDF limitations

This is not an HTML renderer, arbitrary-PDF flattener, or general Unicode font engine.

Admission is deliberately restricted to single-revision classic-xref PDFs. Incremental/linearized `/Prev` revisions, xref streams/hybrid xrefs, and object streams refuse. This prevents old hidden signature revisions and per-object-stream expansion from bypassing preparation checks. Encrypted PDFs refuse before decryption; signatures/ByteRange/signature fields anywhere in admitted objects refuse.

AcroForms, nonempty annotations, optional-content layers, page rotation, non-unit UserUnit, catalog OutputIntents/AlternatePresentations, Type3 fonts, inline images, external streams, PostScript/dynamic XObjects, and unsupported content operators refuse. OutputIntents refuse rather than silently losing color-management semantics. Static Image/Form XObjects and static tiling resources are copied; Form/pattern content is checked too. Page/Form content accepts unfiltered streams or one FlateDecode filter with no predictor. Other content filters refuse. Original image/font resource streams are retained as static resources, not transcoded.

The original draft called lopdf's bounded Flate helper. Source review found that helper intentionally recovers truncated/checksum-invalid compressed data. The implementation now uses the existing native flate2 decoder with bounded output and requires an actual stream end and exact compressed-input consumption. This prevents signing a recovered partial original.

Field text is printable ASCII plus newline. Unsupported Unicode and too-small text layout refuse. Certificate/trail metadata stays lossless through escaping. Canonical URLs use a narrow ASCII HTTPS DNS/IPv4-host grammar with optional port; no userinfo, fragments, IPv6 literals, or whitespace. The caller owns URL issuance and its capability scope.

Budgets: input 16 MiB, serialized output 64 MiB, copied-resource bytes 64 MiB, decoded original-page content 16 MiB total, canonical audit 4 MiB/10,000 rows, originals 1,000 pages, 50,000 objects, bounded graph depth/nodes, per-image dimensions <=2048, total generated raster bytes 64 MiB. Failures are typed refusals, never an unsigned success.

## Tests and validation

`render_tests.rs` has ten tests using serialized/reparsed real lopdf PDFs. They cover:
- original page order/text/crop, actual overlay geometry, signature RGB and alpha pixels;
- certificate digests/recipient metadata/URL/QR and every complete audit row;
- rejection marks and optional-trail omission;
- action/attachment stripping while original text remains;
- static Form/font reference copying and nested dynamic-content refusal;
- missing/invalid/invisible signature-image refusal;
- native-encrypted fixtures with empty and nonempty passwords, and unreachable signature objects;
- AcroForm/annotations/OC/rotation/UserUnit/PS/external/inline/cyclic-resource refusals;
- page-count errors, incremental revision markers, object streams, and unbalanced graphics;
- valid compressed content, truncated Flate, expansion bombs, chain/projection forgery, unsupported field Unicode, overflow, invalid page and URL/geometry bounds.

Ran only scoped rustfmt (success). No Cargo build or tests were run by this child, per the assigned sole-target boundary. Parent should run the scoped render tests and compile/clippy gates on the Mac target, then the native preparation-to-PAdES integration test. Do not record these source-level checks as a green runtime gate.
