//! Moved from `crates/oneiron/src/verbs/answer_forward.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::verbs::answer_forward::TaskAnswerForwardStatusRequest;
use serde::Deserialize;
use serde::Serialize;

/// `tasks.answer.forward.challenge`'s answer (FIX 20468): the challenge
/// bytes the engine door builds, in lowercase hex, so a transport carries
/// them whole as one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerForwardChallenge {
    /// The challenge, two lowercase hex characters per byte. The person
    /// signs `CapabilitySlip::binding_transcript` of the decoded bytes.
    pub challenge: String,
}

impl TaskAnswerForwardChallenge {
    /// The answer for the challenge bytes `challenge`.
    #[must_use]
    pub fn from_bytes(challenge: &[u8]) -> Self {
        Self {
            challenge: oneiron_contracts::entity_id::bytes_to_hex_lower(challenge),
        }
    }
}
