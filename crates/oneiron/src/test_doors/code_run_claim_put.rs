//! Door for `tests/restriction_removal_doors.rs`: the candidate writer a
//! code run's `vault.claims.put` lands through
//! (`Vault::put_claim_candidate_with_landing_returning_actual`, called by
//! `code_run::dispatcher::memory_verbs` and the off-record executor). The
//! dispatcher's own reference and gate checks run before it and are not
//! under test; the writer's edit check is.

use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::error::Result;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, TimeRange, Vault};

/// Puts a claim of `predicate` about `subject` holding `value` at `id` as
/// `actor`, Observed and Proposed, as a code run's put asks. Returns the id
/// that landed: `id`, or a fresh successor that closed the claim at `id`.
///
/// # Errors
///
/// The writer's refusal.
pub fn put_claim_as_code_run(
    vault: &Vault,
    actor: WriteActor,
    id: EntityId,
    predicate: &str,
    subject: EntityId,
    value: rmpv::Value,
    at: u64,
) -> Result<EntityId> {
    let candidate = ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, 1.0);
    let provenance = WriteProvenance::new(rmpv::Value::Map(vec![(
        rmpv::Value::from("door"),
        rmpv::Value::from("test_doors::code_run_claim_put"),
    )]))?;
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Observed,
        provenance,
        ClaimApprovalStatus::Proposed,
    );
    vault.put_claim_candidate_with_landing_returning_actual(
        &id,
        candidate,
        &envelope,
        TimeRange { start: at, end: at },
        at,
        |_| Ok(()),
    )
}
