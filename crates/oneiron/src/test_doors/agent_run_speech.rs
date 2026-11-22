//! A door for the integration tests to make a claimed agent run speak as its
//! engine executor's durable speech does: under the run ref its host
//! dispatcher takes from the leased attempt and the executor run id, into
//! the run's own conversation (PLAN-RUN-FULL-TRACE-INTO-SUB-SESSION).
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::agent_dispatch::{AgentDispatchStatus, agent_dispatch_run_actor};
use crate::code_run::{ExecutorStorage, HostSelfDispatcher};
use crate::error::Result;
use crate::memory::WitnessAssertions;
use crate::off_record::ExecutorUtterance;
use crate::{EntityId, Vault};

/// Witnesses `text` as one visible `self.speak` bubble of the leased agent
/// run `claimed`, whose executor run is `run`, at bridge position `order`:
/// the run's actor and host dispatcher as the resident pump binds them, the
/// storage door the dispatcher's speech takes. Answers the TURN it landed.
///
/// # Errors
///
/// A lease the dispatcher refuses, and the witness door's refusals.
pub fn speak_as_agent_run(
    vault: &Vault,
    claimed: &AgentDispatchStatus,
    run: EntityId,
    text: &str,
    order: u32,
) -> Result<EntityId> {
    let actor = agent_dispatch_run_actor(&claimed.input, claimed.attempt.id)?;
    let dispatcher = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &claimed.attempt)?;
    let receipt = ExecutorStorage::Canonical(vault).witness_executor_utterance_sourced(
        dispatcher.run_ref(),
        Some(run),
        ExecutorUtterance::Speak,
        text,
        vault.now_recorded_at(),
        order,
        actor,
        WitnessAssertions::default(),
    )?;
    Ok(receipt.turn_id)
}
