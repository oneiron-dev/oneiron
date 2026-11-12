//! Moved from `crates/oneiron/src/artifact_hosting/vocabulary.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::artifact_hosting::ARTIFACT_CHANNEL_PREVIEW;
use crate::artifact_hosting::ARTIFACT_CHANNEL_PUBLISHED;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::artifact_hosting::vocabulary::*;
use oneiron_store::code_snapshot::snapshot::CodebaseForkHash;
use oneiron_store::code_snapshot::snapshot::CodebaseSnapshot;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArtifactPointerChannel {
    #[default]
    Published,
    Preview,
}

impl ArtifactPointerChannel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Published => ARTIFACT_POINTER_CHANNELS[0],
            Self::Preview => ARTIFACT_POINTER_CHANNELS[1],
        }
    }

    #[must_use]
    pub const fn key_byte(self) -> u8 {
        match self {
            Self::Published => ARTIFACT_CHANNEL_PUBLISHED,
            Self::Preview => ARTIFACT_CHANNEL_PREVIEW,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "published" => Ok(Self::Published),
            "preview" => Ok(Self::Preview),
            _ => Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "artifact pointer channel must be published or preview",
            ))),
        }
    }
}
