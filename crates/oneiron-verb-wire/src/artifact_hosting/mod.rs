//! Moved from `crates/oneiron/src/artifact_hosting/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::artifact_hosting::vocabulary::ArtifactPointerChannel;
pub use oneiron_store::artifact_hosting::preview;
pub use oneiron_store::artifact_hosting::vocabulary::ARTIFACT_POINTER_CHANNELS;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactExportRef;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactPublishVerbStatus;
pub use oneiron_store::artifact_hosting::vocabulary::ArtifactSnapshotRef;

pub const ARTIFACT_CHANNEL_PUBLISHED: u8 = 0;

pub const ARTIFACT_CHANNEL_PREVIEW: u8 = 1;

impl ArtifactPointerChannel {
    #[must_use]
    const fn from_key_byte(byte: u8) -> Option<Self> {
        match byte {
            ARTIFACT_CHANNEL_PUBLISHED => Some(Self::Published),
            ARTIFACT_CHANNEL_PREVIEW => Some(Self::Preview),
            _ => None,
        }
    }
}
pub mod access;
pub mod door_types;
pub mod vocabulary;
