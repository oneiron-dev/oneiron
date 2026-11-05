//! Result-body manifests, occurrence identifiers and their format bounds.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const CODE_RUN_REPLAY_HASH_LEN: usize = 32;
pub const CODE_RUN_OUTPUT_HANDLE_PREFIX: &str = "code-run-output:blake3:";
pub const CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES: usize = 1024;

/// The preview text of a body withheld without a specific reason.
pub const CODE_RUN_OUTPUT_PREVIEW_WITHHELD: &str = "[preview withheld]";

/// Compact preview stored in a replay record beside a raw output handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRunOutputPreview {
    pub codec: String,
    pub text: String,
    pub truncated: bool,
}

/// What a result body holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRunOutputKind {
    /// The whole body is UTF-8.
    Text,
    /// Anything else, kept byte for byte.
    Binary,
}

impl CodeRunOutputKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Binary => "binary",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "binary" => Some(Self::Binary),
            _ => None,
        }
    }
}

pub fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid_code_run_replay(field));
    }
    Ok(())
}

pub fn invalid_code_run_replay(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidCodeArtifactBody(message))
}
