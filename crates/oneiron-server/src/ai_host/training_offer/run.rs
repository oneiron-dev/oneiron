//! `vault.coach.training_offers.run` on this host (LEARNING-08): one Coach
//! offer pass run now, inside the request, as the nightly worker runs it.
//! Running the nightly pass now is a cadence act, so the caller is the owner
//! or a holder of the maintenance-cadence class of `engine.controls`, checked
//! in the writer that admits the request's own Coach attempt. The pass draws
//! on the same day budget as the nightly pass (`DAY_BUDGET_UNITS`).
//! Its offers are the Coach's, and each waits on the owner's answer.
use oneiron::EntityId;
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerRunnerStore};
use oneiron::federation::EngineControlActor;
use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError, MemoryResult};
use oneiron::skill_optimize::offer_doors::{
    OFFER_PASS_RUN_VERB, OfferPassRunAdmission, OfferPassRunAnswer, OfferPassRunRequest,
    admit_offer_pass_run, offers_of_attempt,
};

use super::super::coach_heal::{LEASE_OWNER, settle};
use super::super::coach_host::{
    BUDGET_ID as COACH_HOST_BUDGET_ID, BUDGET_UNITS as COACH_HOST_BUDGET_UNITS,
};
use crate::server::SyncServer;

/// Admits `actor` and the request's own Coach offer attempt in one writer,
/// runs the pass on it, settles the attempt on the Coach queue's lease and
/// budget line, and answers how the pass ended with the ids of the offers
/// it raised.
///
/// # Errors
///
/// The admission's refusal of a caller that is neither the live owner nor a
/// maintenance-cadence holder; a pass that failed, after its attempt failed
/// with it; storage errors.
pub(crate) fn run_now(
    server: &SyncServer,
    actor: EngineControlActor<'_>,
    input: OfferPassRunRequest,
) -> MemoryResult<OfferPassRunAnswer> {
    let vault = server.vault();
    let store = DreamerRunnerStore::new(vault);
    let now = vault.now_recorded_at();
    let (admitted, caller) = match admit_offer_pass_run(
        vault,
        actor,
        input,
        AdmitDreamerAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now,
            budget_id: COACH_HOST_BUDGET_ID.to_owned(),
            budget_total_units: COACH_HOST_BUDGET_UNITS,
            reserve_units: 1,
            started_milestone: None,
        },
    )? {
        OfferPassRunAdmission::Admitted { attempt, caller } => (attempt, caller),
        OfferPassRunAdmission::Waiting { attempt } => {
            return Ok(OfferPassRunAnswer::Waiting { attempt });
        }
    };
    let attempt = EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?;
    match super::draft(server, &admitted, now) {
        Ok(end) => {
            settle(vault, &store, &admitted, Ok(()), COACH_HOST_BUDGET_ID)?;
            Ok(OfferPassRunAnswer::Ran {
                attempt,
                caller,
                end,
                offers: offers_of_attempt(vault, attempt)?
                    .into_iter()
                    .map(|offer| offer.id)
                    .collect(),
            })
        }
        Err(error) => {
            let kind = error.kind();
            settle(vault, &store, &admitted, Err(error), COACH_HOST_BUDGET_ID)?;
            Err(MemoryError::new(
                MEMORY_CODE_INTERNAL,
                format!("{OFFER_PASS_RUN_VERB} failed on this host: {kind:?}"),
                &["Read vault.coach.training_offers.result for the attempt's state."],
            ))
        }
    }
}
