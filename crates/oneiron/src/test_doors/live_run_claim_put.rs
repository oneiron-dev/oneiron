//! Doors for `tests/live_run_claim_put.rs` (#6881, review 6881 P1): the gate
//! fixtures (`gate::live_run_claim_put_fixture`): the checker vault, the claim,
//! the first-party agent's id and the claim write door with a checker injected;
//! and the run's claim put as a live-run door makes it, with the host's checker
//! lent (FIX LIVE-RUN-CHECKER-INJECT).
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::code_run::{HostSelfDispatcher, SelfDispatchOutcome, SelfMemoryPutClaimCall};
use crate::entity_id::EntityId;
use crate::llm::BoundedAutoChecker;
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteEnvelope};

/// A vault whose only policy manifest lets the first-party agent land
/// Generated Auto writes, naming the host checker `knob` when one is given.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn checker_vault(knob: Option<&str>) -> Result<(tempfile::TempDir, Vault)> {
    crate::gate::live_run_claim_put_fixture::checker_vault(knob)
}

/// A valid Dreamer-shaped Generated `profile.name` claim with `approval`, its
/// evidence TURN seeded.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn checker_body(vault: &Vault, approval: ClaimApprovalStatus) -> Result<ClaimBody> {
    crate::gate::live_run_claim_put_fixture::checker_body(vault, approval)
}

/// The claim write door (`gate::check_claim_policy_for_write_with_record`)
/// with `checker` injected; its transaction commits either way.
///
/// # Errors
/// The gate's refusal, or the store's.
#[doc(hidden)]
pub fn gate_claim_write(
    vault: &Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    checker: Option<&BoundedAutoChecker>,
    persist_pending_consent: bool,
) -> Result<()> {
    crate::gate::live_run_claim_put_fixture::gate_claim_write(
        vault,
        claim_id,
        body,
        envelope,
        checker,
        persist_pending_consent,
    )
}

/// The first-party connector's actor id (`gate::FIRST_PARTY_CONNECTOR_ACTOR_ID`).
#[doc(hidden)]
#[must_use]
pub fn first_party_connector_actor_id() -> EntityId {
    crate::gate::live_run_claim_put_fixture::first_party_connector_actor_id()
}

/// `actor`'s run `run` as the live-run door builds it: lent the host's auto
/// checker (`HostSelfDispatcher::with_auto_checker`, as `on_live_run` lends
/// `decision_host().auto_checker()`), without the live run's acquired lease.
///
/// # Errors
/// The dispatcher's.
#[doc(hidden)]
pub fn live_run_dispatcher<'a>(
    vault: &'a Vault,
    actor: WriteActor,
    run: &str,
    host_checker: &'a BoundedAutoChecker,
) -> Result<HostSelfDispatcher<'a>> {
    Ok(HostSelfDispatcher::new(vault, actor, run)?.with_auto_checker(host_checker))
}

/// The run's claim put asking what `HostSelfDispatcher::put_claim_from_host`
/// asks of the gates for a claim whose predicate is not critical (FIX 3983):
/// Auto first, and when a gate pends the Auto request, Proposed, so it lands
/// with its pending review. Without the live run's acquired lease.
///
/// # Errors
/// The gate's refusal, or the store's.
#[doc(hidden)]
pub fn put_claim_as_live_run(
    run: &HostSelfDispatcher<'_>,
    call: SelfMemoryPutClaimCall,
) -> Result<SelfDispatchOutcome> {
    match run.dispatch_memory_put_claim_requesting(
        call.clone(),
        None,
        ClaimApprovalStatus::Auto,
        true,
    ) {
        Err(error) if crate::gate::gate_rejection_pends(&error) => run
            .dispatch_memory_put_claim_requesting(call, None, ClaimApprovalStatus::Proposed, true),
        outcome => outcome,
    }
}
