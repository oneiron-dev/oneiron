# oneiron-docedit: retained OPC substrate

`retained_opc::Package::open(bytes, Limits)` reads ZIP32 OPC packages with checked entry counts,
compressed archive size, per-part expansion, and total expansion. It retains
original archive bytes, central metadata, entry ordering, and even ZIP entries
outside the relationship graph. It rejects unsupported compression, encryption,
ZIP64, overlapping records, unsafe or duplicate part names, and CRC errors.

`export()` of an unchanged package returns the original byte stream. The only
edit door today, `replace_text`, targets a unique leaf by QName path and prior
text; it splices escaped text into the retained XML bytes, leaving unknown
attributes, node order, namespace context, extensions, and alternate content
at their original offsets. Changed parts retain their compression method;
other local records, compressed payloads, and central metadata pass through.
An edit on a signed package refuses. This is a substrate, not a docx/xlsx/pptx
semantic writer or a relationship linker: callers must still validate the
format-specific closure and transaction's allowed-part set before settle.

`tests/fixtures/` includes small synthetic DOCX/XLSX/PPTX ZIPs and reuses the
checked-in office oracle's clean PPTX. To run the opt-in, hash-pinned PPTArena
pair (which has mixed asset provenance and **must not be committed**):

```sh
python3 scripts/office/deck_oracle.py acquire pptarena-001   crates/oneiron-docedit/tests/fixtures/pptarena-001
cargo test -p oneiron-docedit --test identity --all-features   optional_pinned_pptarena_pair_proves_identity_without_redistributing_decks
```

The pinned manifest is `scripts/office/pptarena.json`. This pair proves ZIP
no-op identity and one XML edit plus passthrough for each of its original and
ground-truth decks. It does not claim PowerPoint oracle or all 100 edit cases.
