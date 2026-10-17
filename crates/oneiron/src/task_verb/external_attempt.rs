//! The payload of one external try on a TASK (OF-220, OF-540).
//!
//! A peer or child takes a TASK as one `tasks.external` try. The accept that
//! enqueues the try freezes into its payload the brief revision it is leased
//! under and the team run the TASK was created in, so a retry or a release
//! keeps both, and neither a later brief revision nor the project's current
//! pattern retargets a try already taken. One decoder reads it for status,
//! receipts and children.

use serde::{Deserialize, Serialize};

use crate::agent_dispatch::TeamRunStamp;
use crate::error::{Error, RecordError, Result};

use super::brief::BriefStamp;

/// What one external try was leased under.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalTaskAttemptInput {
    /// The brief revision the try works to; `None` for a TASK with no brief.
    pub(crate) brief: Option<BriefStamp>,
    /// The team run the TASK's creator worked in; `None` is no team run.
    pub(crate) team: Option<TeamRunStamp>,
}

fn invalid() -> Error {
    Error::Record(RecordError::InvalidTaskBody("tasks.external.payload"))
}

/// One external try's payload, as named MessagePack.
pub(crate) fn encode(brief: Option<BriefStamp>, team: Option<TeamRunStamp>) -> Result<Vec<u8>> {
    if let Some(team) = &team {
        team.validate()?;
    }
    rmp_serde::to_vec_named(&ExternalTaskAttemptInput { brief, team }).map_err(|_| invalid())
}

/// Reads one external try's payload. A payload that does not decode, or
/// carries a team stamp `TeamReceipt` would refuse, is an error, never a
/// quiet "no brief, no team".
pub(crate) fn decode(payload: &[u8]) -> Result<ExternalTaskAttemptInput> {
    let input: ExternalTaskAttemptInput = rmp_serde::from_slice(payload).map_err(|_| invalid())?;
    if let Some(team) = &input.team {
        team.validate()?;
    }
    Ok(input)
}
