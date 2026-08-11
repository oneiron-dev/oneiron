//! External drift guard for the exported head-contract surface.
//!
//! This test names only the public crate root. It never constructs a
//! definition-only handle — the test-only constructor is private on purpose —
//! so everything here is a naming and signature property, checked through the
//! same door a real consumer would use.

use oneiron_uniffi::{
    BlobVersionView, EXPORTED_UNIFFI_RUST_NAMES, EXPORTED_UNIFFI_VERBS,
    HEAD_MEMORY_PACK_SCHEMA_VERSION, Oneiron, OneironError, PINNED_HEAD_CONTRACT_VERBS,
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
fn head_contract_verbs_match_exported_proc_macro_surface() {
    assert_eq!(EXPORTED_UNIFFI_VERBS, PINNED_HEAD_CONTRACT_VERBS);
    assert_eq!(PINNED_HEAD_CONTRACT_VERBS.len(), 27);
}

#[test]
fn exported_rust_names_camel_case_to_the_pinned_sdk_names() {
    assert_eq!(
        EXPORTED_UNIFFI_RUST_NAMES.len(),
        PINNED_HEAD_CONTRACT_VERBS.len()
    );

    for (rust_name, sdk_name) in EXPORTED_UNIFFI_RUST_NAMES
        .iter()
        .zip(PINNED_HEAD_CONTRACT_VERBS)
    {
        assert_eq!(
            &camel(rust_name),
            sdk_name,
            "exported Rust method {rust_name} drifted from pinned SDK name {sdk_name}",
        );
    }
}

#[test]
fn pinned_verb_ledger_has_no_duplicates_and_no_actor_rebinding() {
    let mut sorted = PINNED_HEAD_CONTRACT_VERBS.to_vec();
    sorted.sort_unstable();
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(sorted, deduped, "duplicate entry in the pinned verb ledger");

    assert!(
        !PINNED_HEAD_CONTRACT_VERBS.contains(&"asActor"),
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

#[test]
fn memory_pack_schema_version_is_exported_from_core() {
    assert_eq!(
        HEAD_MEMORY_PACK_SCHEMA_VERSION,
        oneiron::MEMORY_PACK_VERSION
    );
}
