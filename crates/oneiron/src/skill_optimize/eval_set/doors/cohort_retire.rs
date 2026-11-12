//! `vault.evals.cohorts.retire` (LEARNING-04, ND-130): the vault owner, or an
//! agent whose live owner Grant lists the verb, retires a served sealed
//! cohort that is not its seat's reference. The caller is checked in the
//! writer that retires, before the primitive's own refusals and its replay;
//! a repeat keeps the first date and receipt, whoever asks. The receipt names
//! the caller as its author (LEARN-RETIRE-SOURCE = B); the eval-authoring
//! skill's own retirements keep naming its attempt.

use serde::{Deserialize, Serialize};

use super::super::cohort::{EvalCohort, EvalCohortRetirementAuthor};
use crate::EdgeActorClass;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// The verb a Grant lists to name the retirement: the row's own name.
const RETIRE_VERB: &str = "vault.evals.cohorts.retire";

/// Why an agent with no conferring Grant is refused.
const NO_GRANT: &str = "no live Grant from a live owner names this agent and lists the verb";

/// `vault.evals.cohorts.retire`'s input: the cohort and why. Who retires it,
/// the exposure it retires on and the time come from the engine.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortRetireRequest {
    pub cohort: EntityId,
    /// Why the cohort retires: at most 512 bytes once trimmed.
    pub reason: String,
}

/// `vault.evals.cohorts.retire` on the caller's handle: the retired cohort,
/// with its receipt. A cohort that already retired comes back with its first
/// date and receipt.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the live vault owner nor an agent
/// with a live owner Grant listing the verb; a missing cohort, the reference
/// cohort, a cohort that served nothing, an empty or unbounded reason;
/// storage errors.
pub fn retire_cohort(
    memory: &Memory<'_>,
    input: EvalCohortRetireRequest,
) -> MemoryResult<EvalCohort> {
    let vault = memory.vault();
    let at = vault.now_recorded_at();
    vault.try_with_write_txn_grouped(|txn| {
        let author = admit_retirer_in_txn(memory, txn)?;
        Ok(vault.retire_eval_cohort_in_txn(txn, &input.cohort, &input.reason, author, at)?)
    })
}

/// The author a retirement names, in `txn`: the vault owner while a live
/// person, or an agent on the live owner Grant that lists the verb. The
/// caller's actor binding and any credential it presented are checked first.
fn admit_retirer_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<EvalCohortRetirementAuthor> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused("the caller's credential is no longer live"));
    }
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        if !crate::consent::person_is_live_in_txn(vault, txn, &memory.actor())? {
            return Err(refused("the vault owner is not a live person"));
        }
        return Ok(EvalCohortRetirementAuthor::Owner {
            person: memory.actor(),
        });
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
        RETIRE_VERB,
    )? {
        Ok(standing) => Ok(EvalCohortRetirementAuthor::Agent {
            agent: memory.actor(),
            grant: standing.grant.ok_or_else(|| refused(NO_GRANT))?,
        }),
        Err(NoStanding::PactStandingLapsed) => Err(refused(PACT_STANDING_LAPSED)),
        Err(NoStanding::NotStanding) => Err(refused(NO_GRANT)),
    }
}

/// The verb's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{RETIRE_VERB} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
