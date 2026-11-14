//! The input and answer of `vault.agent.run_effect.answer` (FIX 4747 slice
//! 7), a host door: the vault owner's answer to the inbox ask a moved agent
//! run's replayed step raised when it makes a call that the machine which
//! ran it before may already have made, the ask's one-tap actions. A server
//! runs it under the vault owner's proof; an embedded handle runs it as its
//! embedded owner. An agent never answers it.
//!
//! Resend releases the call for one more call under the same intent id,
//! which the run makes at its next pass over it. No resend leaves it: the
//! call answers the step that it may have happened elsewhere, and the run
//! goes on without it. The first answer settles the ask; a later one finds
//! it settled.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::AgentRunEffectAnswerOutcome;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::agent_run_effect::{
    AgentRunEffectAnswer, AgentRunEffectAnswered,
};

/// `vault.agent.run_effect.answer` under the owner's proof.
///
/// # Errors
///
/// An `intent_ref` that is not 64 hex digits; a proof that is not a live
/// owner's; a run TASK that does not read.
pub fn answer_agent_run_effect_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentRunEffectAnswer,
) -> MemoryResult<AgentRunEffectAnswered> {
    let intent_id = crate::task_verb::decode_hex::<32>(&input.intent_ref).ok_or_else(|| {
        MemoryError::bad_request("intent_ref is not the 64 hex digits of an intent id")
    })?;
    let outcome = vault.answer_agent_run_effect(owner, input.task_ref, intent_id, input.resend)?;
    Ok(AgentRunEffectAnswered {
        task_ref: input.task_ref,
        intent_ref: crate::entity_id::bytes_to_hex_lower(&intent_id),
        resend: input.resend,
        outcome,
    })
}
