//! `self.memory.diary.pinned`: the caller reads an agent's diary with each entry's live NOTE
//! revision, stating a reason the agent sees in its read log (OF-490, ONE-2510). The door is
//! [`Memory::read_agent_diary_pinned_filtered`]: the caller's `diary.read` Grants decide which
//! entries it gets, an agent that reviews answers the reason first, a person reads with their
//! authentication, and every entry also passes the caller's ordinary read lane (credential,
//! destination and room ceilings). This file is the row's wire: the existing query input, and the
//! door's outcome with its pins as a closed DTO a remote client decodes.

use super::diary::DiaryQueryRequest;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::diary_pinned::{DiaryPinnedEntry, DiaryPinnedOutcome};

/// `self.memory.diary.pinned` on a handle: reads as the handle's actor, under the owner proof its
/// host bound when the owner made this request in person ([`Memory::with_owner_authorship`]), else
/// the embedded owner's own proof when the handle is that owner ([`Memory::embedded_owner`]), and
/// none otherwise. Any other person's surface is refused; an agent or system reads as itself.
pub fn self_memory_diary_pinned_embedded(
    memory: &Memory<'_>,
    input: DiaryQueryRequest,
) -> MemoryResult<DiaryPinnedOutcome> {
    let embedded = match memory.owner_authorship() {
        None if memory.actor_class() == EdgeActorClass::Human => {
            memory.embedded_owner("self.memory.diary.pinned").ok()
        }
        _ => None,
    };
    let proof = memory.owner_authorship().or(embedded.as_ref());
    diary_pinned_as(memory, proof, input)
}

/// `self.memory.diary.pinned` under `proof`: the server's host door passes the owner proof the
/// caller's credential carries, or none, and the gate decides.
pub fn diary_pinned_as(
    memory: &Memory<'_>,
    proof: Option<&AuthenticatedOwner>,
    input: DiaryQueryRequest,
) -> MemoryResult<DiaryPinnedOutcome> {
    input.validate()?;
    let agent = EntityId::from_hex(&input.agent)
        .map_err(|_| MemoryError::bad_request("agent is not an entity id"))?;
    let (outcome, pins) = memory.read_agent_diary_pinned_filtered(proof, agent, &input.reason)?;
    Ok(DiaryPinnedOutcome {
        outcome: outcome.into(),
        pins: pins
            .into_iter()
            .map(|(id, revision)| DiaryPinnedEntry { id, revision })
            .collect(),
    })
}
