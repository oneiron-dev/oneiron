//! K-proof (oracle): the archive's retained side row key keeps its bytes.
//!
//! `retained_side_row_key` now starts through the fingerprint crate's K door
//! (`purposes::archive::RETAINED_SIDE_ROW_KEY`) and takes the value hash from `ContentHash`.
//! A vault stores its retained rows under this key and deduplicates on it, and reading a
//! stored row back and importing an archive both recompute it and refuse a row filed under
//! another. So the head must give the bytes of the hand-started recipe for every input.
//! `base::retained_side_row_key` is that recipe, as
//! `crates/oneiron/src/batch/export/archive_retained_side_rows.rs` had it at b1bba8a04f63
//! (lines 76-95), with the row's three identity fields as its arguments.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fingerprint_keep_archive_retained_side_row`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::archive_side_catalogue::retained_side_row_physical_key;
use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};

mod base {
    const RETAINED_SIDE_ROW_DOMAIN: &[u8] = b"oneiron.archive.retained_side_row.v1";

    pub(super) fn retained_side_row_key(
        source_table: &str,
        source_key: &[u8],
        source_value: &[u8],
    ) -> [u8; 32] {
        let value_hash = blake3::hash(source_value);
        let mut hasher = blake3::Hasher::new();
        hasher.update(RETAINED_SIDE_ROW_DOMAIN);
        for part in [
            source_table.as_bytes(),
            source_key,
            value_hash.as_bytes().as_slice(),
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }
}

/// Retained tuples as (source table, source key, source value): empty parts, bytes that are
/// no UTF-8, one byte moved across each part boundary, and a value of many BLAKE3 chunks.
fn tuples() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let long_value: Vec<u8> = (0..70_000_u32)
        .map(|at| u8::try_from(at % 251).expect("a remainder below 251"))
        .collect();
    vec![
        (
            "SNAPSHOT_READ_SETTINGS".to_owned(),
            Vec::new(),
            vec![0x91, 0x02],
        ),
        ("SNAPSHOT_READ_SETTINGS".to_owned(), vec![0x00], Vec::new()),
        ("HOOKS_RECEIPT".to_owned(), vec![0xff; 32], vec![0xc0]),
        ("HOOKS_RECEIPT".to_owned(), vec![0xff; 31], vec![0xff, 0xc0]),
        ("AB".to_owned(), b"C".to_vec(), b"D".to_vec()),
        ("A".to_owned(), b"BC".to_vec(), b"D".to_vec()),
        ("A".to_owned(), b"B".to_vec(), b"CD".to_vec()),
        (String::new(), Vec::new(), Vec::new()),
        ("LEGAL_HOLD".to_owned(), vec![0x80, 0xfe, 0x00], long_value),
    ]
}

#[test]
fn the_retained_side_row_key_keeps_the_hand_started_recipe() {
    let mut keys = Vec::new();
    for (source_table, source_key, source_value) in tuples() {
        let key = retained_side_row_physical_key(&source_table, &source_key, &source_value);
        assert_eq!(
            key,
            base::retained_side_row_key(&source_table, &source_key, &source_value),
            "the key of ({source_table:?}, {source_key:02x?}, {} value bytes) keeps its bytes",
            source_value.len()
        );
        keys.push(key);
    }
    let distinct: std::collections::BTreeSet<[u8; 32]> = keys.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        keys.len(),
        "tuples that differ in any identity part file under different keys"
    );
}

#[test]
fn the_registry_names_the_retained_side_row_recipe() {
    let purpose = purposes::archive::RETAINED_SIDE_ROW_KEY;
    assert_eq!(purpose.tag(), "oneiron.archive.retained_side_row.v1");
    assert_eq!(purpose.hash(), LegacyHash::Blake3);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
}
