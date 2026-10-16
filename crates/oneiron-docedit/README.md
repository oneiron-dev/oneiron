# oneiron-docedit: native document editing

The crate edits Office documents natively and keeps every byte it does not
own. `src/lib.rs` exports these surfaces:

- `retained_opc`: the bounded, retained OPC package (below). The deck,
  edit and patch surfaces work on it; Word revisions go through stemma.
- `deck`: typed, read-only deck views. Each value names the part, element and
  attribute it came from. The template view reads masters and layouts for
  creation.
- `design_plan`: compiles a kept brief and a template into a validated
  `DesignPlan`.
- `emit`: writes a checked deck candidate from a `DesignPlan`, then re-imports
  it and checks the write set, relationships, content types and id scopes.
- `graphic`: compiles a closed SVG subset to editable DrawingML shapes, or
  binds a verified PNG/JPEG. Nothing is rasterized.
- `edit`: in-place value edits (`set_text`, `replace_run_text`, `set_xfrm`,
  `move_in_slide_space`, `set_picture`, `set_notes`) and structural edits
  (`add_shape`, `delete_shape`, `reparent`, `duplicate_slide`,
  `reorder_slides`). Each edit is one checked operation on a copy; a refusal
  leaves the package as it was.
- `native_patch`: native tables and bounded classic charts, with the chart's
  caches and embedded workbook written as one checked operation.
- Word revisions: `revise`, `revise_with_limits` and `revise_with_notes` apply
  a tracked-change transaction through the pinned stemma fork and refuse
  output that fails the blocking OOXML linker (`validate_blocking`).
  `PROVENANCE.md` records the fork, its licenses and local changes.
- `ooxml` and `xlfn`: the offset-preserving OOXML reader and Excel's `_xlfn.`
  storage qualifiers, shared by the writers.
- `contract`: the engine contract over all of the above. It is one versioned
  op table (`docx.*`, `xlsx.*`, `deck.*`, `contract.describe`) with typed JSON
  args, byte inputs named by index, typed replies, named outputs and closed
  refusal codes. The hosted documents API serves the same table;
  `docs/ops/documents-api-handoff.md` is the handoff.

## Retained OPC substrate

`retained_opc::Package::open(bytes, Limits)` requires caller-supplied positive
ZIP and XML budgets. The engine host resolves its shipped
`docedit_resource_policy` manifest row (or tighter trusted rows) and passes a
plain `Limits` value. Standalone organ callers supply their own values. The
ZIP32 reader checks entry counts, compressed archive size, per-part expansion,
and total expansion. It retains
original archive bytes, central metadata, entry ordering, and even ZIP entries
outside the relationship graph. It rejects unsupported compression, encryption,
ZIP64, overlapping records, unsafe or duplicate part names, and CRC errors.

`export()` of an unchanged package returns the original byte stream. The
`Package` write doors are:

- `replace_text` targets a unique leaf by QName path and prior text. It
  splices escaped text into the retained XML bytes, leaving unknown
  attributes, node order, namespace context, extensions, and alternate content
  at their original offsets.
- `replace_xml_part` replaces one whole XML part with bytes the caller derived
  from it. The bytes pass the same XML validation and limits as a leaf edit.
- `add_part` adds a new part and declares its content type; `relate` adds a
  relationship and writes the relationship part.
- `replace_nested_package` replaces an embedded OPC package (a chart's
  workbook); the new bytes must open under the same limits.
- `Package::create(Limits)` starts an empty package for creation.

A bounded Expat XML 1.0/Namespaces parse owns both
the semantic text and source offsets, including UTF-8 BOM. It refuses DTDs,
invalid references and namespace bindings, and over-budget depth/nodes before
minting a leaf target. The candidate is parsed again under the same budgets and
checked against its requested text and unchanged prefix/suffix before it can
replace the old part. Ambiguous or mixed-content targets refuse atomically.
Changed parts retain their compression method; other local records, compressed
payloads, and central metadata pass through. Digital-signature relationships
and content types, including non-default locations, make the package read-only.
Malformed signature metadata also refuses edits; no-op export remains exact.
`Package` alone knows no docx/xlsx/pptx semantics: a caller that writes through
it directly must still validate the format-specific closure and the
transaction's allowed-part set before settle.

`tests/fixtures/` includes small synthetic DOCX/XLSX/PPTX ZIPs and reuses the
checked-in office oracle's clean PPTX. To run the opt-in, hash-pinned PPTArena
pair (which has mixed asset provenance and **must not be committed**):

```sh
python3 scripts/office/deck_oracle.py acquire pptarena-001 \
  crates/oneiron-docedit/tests/fixtures/pptarena-001
cargo test -p oneiron-docedit --test identity --all-features \
  optional_pinned_pptarena_pair_proves_identity_without_redistributing_decks -- --ignored
```

The pinned manifest is `scripts/office/pptarena.json`. This pair proves ZIP
no-op identity and one XML edit plus passthrough for each of its original and
ground-truth decks. It does not claim PowerPoint oracle or all 100 edit cases.
