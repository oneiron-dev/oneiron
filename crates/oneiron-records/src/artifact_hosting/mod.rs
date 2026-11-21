//! Moved from `crates/oneiron/src/artifact_hosting/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::artifact_hosting::preview;
pub use oneiron_store::artifact_hosting::vocabulary::ARTIFACT_POINTER_CHANNELS;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactExportRef;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactPublishVerbStatus;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactSnapshotRef;

#[must_use]
pub fn artifact_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
