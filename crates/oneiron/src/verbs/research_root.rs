//! `vault.research.create_root` (CAMPAIGN-ROOT): the owner, or an agent whose
//! live owner Grant names it and lists this verb, enqueues one parentless
//! root attempt with a run of its own through ordinary agent dispatch, so
//! `vault.research.bind` can bind a campaign to it.
//!
//! Creation is all it does. The caller's standing is checked in the dispatch
//! writer itself (`AgentDispatcher::dispatch_research_root`), on a repeat of a
//! pending intent too. Who drives the created root is unchanged: the owner,
//! or the agent running that root (`controller_in_txn`); the creator gains
//! no control of it. The wire names no attempt, run, parent, result or
//! approval: the engine mints the run and the queue the attempt.

use serde::{Deserialize, Serialize};

use crate::EdgeActorClass;
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, QueuedRequester, ResearchRootRequest,
};
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::context_projection::CONTEXT_SPEC_MAX_TEXT_BYTES;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// The verb a Grant lists to name root creation: the row's own name.
const CREATE_ROOT_VERB: &str = "vault.research.create_root";

#[doc(hidden)]
use oneiron_verb_wire::verbs::research_root::INTENT_KEY_MAX_BYTES;
#[doc(hidden)]
pub use oneiron_verb_wire::verbs::research_root::{ResearchRootReceipt, ResearchRootWire};

/// `vault.research.create_root` on the caller's handle.
///
/// # Errors
///
/// BAD_REQUEST for an invalid wire; FORBIDDEN for a caller that is neither
/// the vault owner nor an agent with a live owner Grant listing the verb,
/// checked in the dispatch writer; every refusal of ordinary root dispatch
/// (an agent that is not dispatchable, a different agent or brief on a
/// pending intent, launch admission); storage errors.
pub fn research_create_root(
    memory: &Memory<'_>,
    input: ResearchRootWire,
) -> MemoryResult<ResearchRootReceipt> {
    input.validate()?;
    let vault = memory.vault();
    let outcome = AgentDispatcher::new(vault).dispatch_research_root(
        ResearchRootRequest {
            agent: input.agent,
            dedupe_key: format!(
                "research-root:{}:{}",
                memory.actor().to_hex(),
                input.intent_key
            ),
            briefing: input.briefing,
            requester: QueuedRequester::of_memory(memory),
            now: vault.now_recorded_at(),
        },
        |txn| admit_creator_in_txn(memory, txn),
    )?;
    let (status, enqueued) = match outcome {
        AgentDispatchOutcome::Dispatched(status) => (status, true),
        AgentDispatchOutcome::Existing(status) => (status, false),
        _ => {
            return Err(crate::Error::InvariantViolation(
                "a research root dispatch enqueues one agent attempt",
            )
            .into());
        }
    };
    let run_id = status
        .attempt
        .run_id
        .ok_or(crate::Error::InvariantViolation(
            "a research root carries its run",
        ))?;
    Ok(ResearchRootReceipt {
        root: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
        run_id,
        enqueued,
    })
}

/// The vault owner, or an agent one live Grant from a live owner names and
/// lists [`CREATE_ROOT_VERB`] for, in `txn`.
fn admit_creator_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    let vault = memory.vault();
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        return Ok(());
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        CREATE_ROOT_VERB,
    )? {
        Ok(standing) if standing.grant.is_some() => Ok(()),
        Err(NoStanding::PactStandingLapsed) => Err(refused(PACT_STANDING_LAPSED)),
        Ok(_) | Err(NoStanding::NotStanding) => Err(refused(
            "no live Grant from a live owner names this agent and lists the verb",
        )),
    }
}

/// The verb's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{CREATE_ROOT_VERB} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
