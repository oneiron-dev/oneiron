//! The served rows of a person's word on an ask this node did not admit
//! (FIX 20468): `tasks.answer.forward.challenge`, `tasks.answer.forward` and
//! `tasks.answer.forward.status`, over the engine doors FIX 7494 built
//! ([`Memory::tasks_answer_forward`](crate::memory::Memory::tasks_answer_forward)).
//!
//! The person reads the challenge, signs it with their slip's binding key
//! through `CapabilitySlip::binding_transcript`, and relays the act with
//! that proof. The proof binds this one intent. The request that carries it
//! authenticates apart, as every request does.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::task_verb::{AskForwardAct, AskForwardHolderProof, TaskAskHandle};

/// `tasks.answer.forward.challenge`'s input: the ask, the person's intent
/// key and the act they will relay under it (FIX 20468). The answer is the
/// challenge ([`TaskAnswerForwardChallenge`]). The person signs
/// `CapabilitySlip::binding_transcript(challenge)` with their slip's binding
/// key, never the bytes alone.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerForwardChallengeRequest {
    pub handle: TaskAskHandle,
    /// The person's key for this intent. The same key with the same act is
    /// the same intent.
    pub intent_key: String,
    pub act: AskForwardAct,
}

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
            challenge: crate::entity_id::bytes_to_hex_lower(challenge),
        }
    }
}

/// `tasks.answer.forward`'s input: the challenge request's fields and the
/// person's proof over that challenge (FIX 20468). The proof's token is no
/// record ref.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerForwardRequest {
    pub handle: TaskAskHandle,
    pub intent_key: String,
    pub act: AskForwardAct,
    pub proof: AskForwardHolderProof,
}

/// `tasks.answer.forward.status`'s input: the intent a relay answered with
/// (FIX 20468). Only the intent's own holder reads where it stands.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAnswerForwardStatusRequest {
    /// The receipt's `intent_ref`, 32 hex.
    pub intent_ref: EntityId,
}
