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

/// Byte cap on an intent key: the campaign record's bound on a ref.
const INTENT_KEY_MAX_BYTES: usize = 256;

/// `vault.research.create_root`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRootWire {
    /// The dispatchable agent definition the root attempt runs.
    pub agent: EntityId,
    /// The caller's name for this root: a repeat while the root is still
    /// pending returns that root and its run.
    pub intent_key: String,
    /// The root's brief, carried as its context briefing.
    pub briefing: String,
}

impl ResearchRootWire {
    /// Refuses a blank or over-long intent key or brief.
    ///
    /// # Errors
    ///
    /// BAD_REQUEST naming the field and its bound.
    pub fn validate(&self) -> MemoryResult<()> {
        if self.intent_key.trim().is_empty() || self.intent_key.len() > INTENT_KEY_MAX_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a research root's intent_key is 1 to {INTENT_KEY_MAX_BYTES} bytes and not blank"
            )));
        }
        if self.briefing.trim().is_empty() || self.briefing.len() > CONTEXT_SPEC_MAX_TEXT_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a research root's briefing is 1 to {CONTEXT_SPEC_MAX_TEXT_BYTES} bytes and not blank"
            )));
        }
        Ok(())
    }
}

/// The root a `vault.research.create_root` call enqueued or found pending.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRootReceipt {
    /// The queued root attempt: bind a campaign to it with `vault.research.bind`.
    pub root: EntityId,
    /// The run the root carries.
    pub run_id: String,
    /// False when the call returned the pending root an earlier call with the
    /// same intent enqueued.
    pub enqueued: bool,
}

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
        |txn| admit_owner_or_granted_in_txn(memory, txn, CREATE_ROOT_VERB),
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
/// lists `verb` for, in `txn`.
pub(super) fn admit_owner_or_granted_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
) -> MemoryResult<()> {
    let vault = memory.vault();
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        return Ok(());
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            verb,
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        verb,
    )? {
        Ok(standing) if standing.grant.is_some() => Ok(()),
        Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
        Ok(_) | Err(NoStanding::NotStanding) => Err(refused(
            verb,
            "no live Grant from a live owner names this agent and lists the verb",
        )),
    }
}

/// `verb`'s refusal of a caller it does not admit.
fn refused(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
