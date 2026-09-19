# Memory Wire facade census

This is the complete **shipped SDK facade**, in Rust catalog order. It is
not a claim that every engine-internal method is a public SDK verb.
`FACADE_VERB_CATALOG` in `crates/oneiron-remote/src/lib.rs` owns this list.
Names are stable: a new export or rename must update the engine catalog,
both bindings and their export-census tests in one reviewed change.

- `witness`
- `claim_upsert`
- `recall`
- `receipts`
