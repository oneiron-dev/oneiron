//! Moved from `crates/oneiron/src/blob_artifact/family.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::blob_artifact::family::ArtifactKind;

pub fn hash_hex(hash: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*hash).to_hex().to_string()
}
