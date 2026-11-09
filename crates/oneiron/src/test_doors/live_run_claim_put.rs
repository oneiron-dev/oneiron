//! Doors for `tests/live_run_claim_put.rs` (#6881, review 6881 P1): the gate
//! fixtures (`gate::live_run_claim_put_fixture`): the checker vault, the claim,
//! the first-party agent's id and the claim write door with a checker injected.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::entity_id::EntityId;
use crate::llm::BoundedAutoChecker;
use crate::vault::Vault;
use crate::write_envelope::WriteEnvelope;

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
