# oneiron-docedit: retained OPC substrate

`retained_opc::Package::open(bytes, Limits)` requires caller-supplied positive
ZIP and XML budgets. The engine host resolves its shipped
`docedit_resource_policy` manifest row (or tighter trusted rows) and passes a
plain `Limits` value. Standalone organ callers supply their own values. The
ZIP32 reader checks entry counts, compressed archive size, per-part expansion,
and total expansion. It retains
original archive bytes, central metadata, entry ordering, and even ZIP entries
outside the relationship graph. It rejects unsupported compression, encryption,
ZIP64, overlapping records, unsafe or duplicate part names, and CRC errors.

`export()` of an unchanged package returns the original byte stream. The only
edit door today, `replace_text`, targets a unique leaf by QName path and prior
text; it splices escaped text into the retained XML bytes, leaving unknown
attributes, node order, namespace context, extensions, and alternate content
at their original offsets. A bounded Expat XML 1.0/Namespaces parse owns both
the semantic text and source offsets, including UTF-8 BOM. It refuses DTDs,
invalid references and namespace bindings, and over-budget depth/nodes before
minting a leaf target. The candidate is parsed again under the same budgets and
checked against its requested text and unchanged prefix/suffix before it can
replace the old part. Ambiguous or mixed-content targets refuse atomically.
Changed parts retain their compression method; other local records, compressed
payloads, and central metadata pass through. Digital-signature relationships
and content types, including non-default locations, make the package read-only.
Malformed signature metadata also refuses edits; no-op export remains exact. This is a substrate, not a docx/xlsx/pptx
semantic writer or a relationship linker: callers must still validate the
format-specific closure and transaction's allowed-part set before settle.

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
