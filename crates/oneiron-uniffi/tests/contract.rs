//! External drift guard for the exported head-contract surface.
//!
//! This test names only the public crate root. It never constructs a
//! definition-only handle — the test-only constructor is private on purpose —
//! so everything here is a naming and signature property, checked through the
//! same door a real consumer would use.

use oneiron_uniffi::{
    BlobVersionView, ClaimListFilter, ClaimViews, EXPORTED_UNIFFI_RUST_NAMES,
    EXPORTED_UNIFFI_VERBS, EntityRead, EntityViews, HEAD_MEMORY_PACK_SCHEMA_VERSION, LexicalHits,
    NeighborHits, NeighborOpts, Oneiron, OneironError, ReadReceipt,
};

/// The exact camel-case rule the generated Swift names follow.
fn camel(rust_name: &str) -> String {
    let mut out = String::with_capacity(rust_name.len());
    let mut upper_next = false;
    for ch in rust_name.chars() {
        if ch == '_' {
            upper_next = true;
            continue;
        }
        if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

#[test]
fn exported_rust_names_camel_case_to_the_pinned_sdk_names() {
    assert_eq!(
        EXPORTED_UNIFFI_RUST_NAMES.len(),
        EXPORTED_UNIFFI_VERBS.len()
    );

    for (rust_name, sdk_name) in EXPORTED_UNIFFI_RUST_NAMES.iter().zip(EXPORTED_UNIFFI_VERBS) {
        assert_eq!(
            &camel(rust_name),
            sdk_name,
            "exported Rust method {rust_name} drifted from pinned SDK name {sdk_name}",
        );
    }
}

#[test]
fn pinned_verb_ledger_has_no_duplicates_and_no_actor_rebinding() {
    let mut unique = EXPORTED_UNIFFI_VERBS.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        EXPORTED_UNIFFI_VERBS.len(),
        unique.len(),
        "duplicate entry in the exported head surface",
    );

    assert!(
        !EXPORTED_UNIFFI_VERBS.contains(&"asActor"),
        "actor rebinding is a handle operation, not a head-contract verb",
    );
}

/// The amended blob rows: bytes cross as bytes, both timestamps are optional
/// signed Unix seconds, and the read side is version-addressed.
#[test]
fn blob_signatures_match_the_head_contract_rows() {
    type Appended = Result<BlobVersionView, OneironError>;
    type MaybeText = Option<String>;
    type MaybeUnixSeconds = Option<i64>;
    type ReadBack = Result<Option<Vec<u8>>, OneironError>;

    let _: fn(
        &Oneiron,
        String,
        Vec<u8>,
        MaybeText,
        MaybeUnixSeconds,
        MaybeUnixSeconds,
    ) -> Appended = Oneiron::append_blob_version;

    let _: fn(&Oneiron, String, u64) -> ReadBack = Oneiron::read_blob_version;
}

/// Every read verb answers with its rows and the read's receipt; no read
/// verb returns bare rows.
#[test]
fn read_verbs_return_their_receipt() {
    type Read<T> = Result<T, OneironError>;

    let _: fn(&Oneiron, String) -> Read<EntityRead> = Oneiron::get_entity;
    let _: fn(&Oneiron, Vec<String>) -> Read<EntityViews> = Oneiron::hydrate;
    let _: fn(&Oneiron, ClaimListFilter) -> Read<ClaimViews> = Oneiron::claim_list;
    let _: fn(&Oneiron, String) -> Read<ClaimViews> = Oneiron::claim_history;
    let _: fn(&Oneiron, String, u32) -> Read<LexicalHits> = Oneiron::query_bm25;
    let _: fn(&Oneiron, String, NeighborOpts) -> Read<NeighborHits> = Oneiron::neighbors;
    let _: fn(&EntityRead) -> &ReadReceipt = |read| &read.narrowing;
}

#[test]
fn memory_pack_schema_version_is_exported_from_core() {
    assert_eq!(
        HEAD_MEMORY_PACK_SCHEMA_VERSION,
        oneiron::MEMORY_PACK_VERSION
    );
}
