//! Moved from `crates/oneiron/src/agent_def/portable_source.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;

pub const FORMAT: &str = "oneiron.agent-birth-source.v1";

pub fn invalid(reason: &'static str) -> Error {
    Error::Artifact(oneiron_base::error::ArtifactError::InvalidAgentDefBody(
        reason,
    ))
}
