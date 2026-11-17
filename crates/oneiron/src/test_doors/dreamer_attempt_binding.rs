//! Admitted strength and conflict-settlement attempts for bound job clients.
//! A strength claim lands through a real consolidation pass and its
//! observation through the strength writer. Both job types use their
//! production enqueue and the maintenance lane's own admission, including
//! the authority stamp and run-tree row. Nothing here mints a binding or commits.

use crate::attempt_queue::AttemptId;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::dreamer_runner::maintenance::{CONFLICT_SETTLE_FACET, CONSOLIDATION_STRENGTH_FACET};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// The lease owner every strength admission here takes.
pub const STRENGTH_LEASE_OWNER: &str = "strength-binding-worker";
/// The run the strength attempt is enqueued in.
pub const STRENGTH_RUN: &str = "run-strength-binding";

/// One claim the Dreamer landed, observed with one independent source.
#[derive(Debug, Clone)]
pub struct ObservedStrengthClaim {
    /// The Generated claim the pass landed.
    pub claim: EntityId,
    /// The user-stated claim about the same person it is observed with.
    pub source: EntityId,
    /// The consolidation attempt that landed it.
    pub seed: AttemptId,
}

/// Lands one Generated `profile.name` claim about a person through one
/// consolidation pass, and observes it with a user-stated `profile.hobby`
/// claim about the same person, stored one second ahead of the clock, as
/// its source.
///
/// # Errors
///
/// The vault's, or a pass that lands no single claim with a person subject.
pub fn observe_strength_claim(vault: &Vault) -> Result<ObservedStrengthClaim> {
    let reply = serde_json::json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "owen"}],
        }],
    })
    .to_string();
    let pass =
        super::consolidation::consolidate_unbound_turn(vault, "call me owen", None, None, &reply)?;
    let &[claim] = pass.landed.as_slice() else {
        return Err(Error::InvalidConfig(format!(
            "the pass landed {} claims, not one",
            pass.landed.len()
        )));
    };
    let person = super::derive::claim_subject(vault, claim)?
        .ok_or_else(|| Error::InvalidConfig("the generated claim has no person subject".into()))?;
    let latest = vault.now_recorded_at().saturating_add(1);
    let mut body = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(person),
        rmpv::Value::from("yuki"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let source = EntityId::now();
    vault.put_claim(
        &source,
        &body,
        TimeRange {
            start: latest,
            end: latest,
        },
        latest,
    )?;
    super::steward::record_strength_observations(
        vault,
        claim,
        &[source],
        latest.saturating_mul(1_000),
    )?;
    Ok(ObservedStrengthClaim {
        claim,
        source,
        seed: pass.attempt,
    })
}

/// Enqueues the strength attempt of `parent` in [`STRENGTH_RUN`], as the
/// nightly recipe wake does (with its authority stamp and run-tree row),
/// then admits it ([`admit_strength_attempt`]).
///
/// # Errors
///
/// The vault's, or as [`admit_strength_attempt`].
pub fn enqueue_strength_attempt(
    vault: &Vault,
    parent: AttemptId,
    now: u64,
) -> Result<DreamerAdmittedAttempt> {
    enqueue_unadmitted_strength_attempt(vault, parent, now)?;
    admit_strength_attempt(vault, now)
}

/// Enqueues `parent`'s strength attempt at `now` as the nightly recipe wake
/// does (with its authority stamp and run-tree row), and leaves it queued
/// for a wake pass to admit (untangle 6.9c PR 4).
///
/// # Errors
///
/// The vault's.
pub fn enqueue_unadmitted_strength_attempt(
    vault: &Vault,
    parent: AttemptId,
    now: u64,
) -> Result<()> {
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn(|txn| {
        store.enqueue_consolidation_strength_in_txn(txn, parent, Some(STRENGTH_RUN.into()), now)
    })
}

/// Admits the next maintenance attempt under [`STRENGTH_LEASE_OWNER`] at
/// `now`, through the maintenance lane's own admission: a strength attempt
/// enqueued or released before.
///
/// # Errors
///
/// The vault's, or an admission of nothing or of another job.
pub fn admit_strength_attempt(vault: &Vault, now: u64) -> Result<DreamerAdmittedAttempt> {
    let DreamerAdmissionOutcome::Admitted(admitted) = DreamerRunnerStore::new(vault)
        .admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: STRENGTH_LEASE_OWNER.to_owned(),
            now,
            budget_id: "strength-binding".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "no strength attempt was admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != CONSOLIDATION_STRENGTH_FACET {
        return Err(Error::InvalidConfig(format!(
            "the maintenance lane admitted {}",
            admitted.status.payload.attempt_type
        )));
    }
    Ok(*admitted)
}

/// The lease owner every conflict-settlement admission here takes.
pub const CONFLICT_SETTLE_LEASE_OWNER: &str = "conflict-settle-binding-worker";
/// The run the conflict-settlement attempt is enqueued in.
pub const CONFLICT_SETTLE_RUN: &str = "run-conflict-settle-binding";

/// Enqueues one conflict-settlement attempt through the production enqueue,
/// with the authority stamp and run-tree row a recipe wake records.
/// Returns whether a new attempt was enqueued rather than deduped.
///
/// # Errors
///
/// The production enqueue's authority-stamp, run-tree and storage errors.
pub fn enqueue_conflict_settle_attempt(vault: &Vault, now: u64) -> Result<bool> {
    vault.with_write_txn(|txn| {
        DreamerRunnerStore::new(vault).enqueue_conflict_settle_in_txn(
            txn,
            Some(CONFLICT_SETTLE_RUN.into()),
            now,
        )
    })
}

/// Admits the next maintenance attempt as a conflict-settlement job under
/// [`CONFLICT_SETTLE_LEASE_OWNER`] at `now`, through the lane's own admission.
///
/// # Errors
///
/// The vault's, or an admission of nothing or of another job type.
pub fn admit_conflict_settle_attempt(vault: &Vault, now: u64) -> Result<DreamerAdmittedAttempt> {
    let DreamerAdmissionOutcome::Admitted(admitted) = DreamerRunnerStore::new(vault)
        .admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: CONFLICT_SETTLE_LEASE_OWNER.to_owned(),
            now,
            budget_id: "conflict-settle-binding".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "no conflict-settlement attempt was admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != CONFLICT_SETTLE_FACET {
        return Err(Error::InvalidConfig(format!(
            "the maintenance lane admitted {}",
            admitted.status.payload.attempt_type
        )));
    }
    Ok(*admitted)
}

/// Runs the native maintenance dispatcher on an admitted conflict-settlement
/// attempt without a host runner, returning its park outcome.
///
/// # Errors
///
/// An attempt of another job type, or the dispatcher's storage errors.
pub fn execute_unlent_conflict_settle(
    vault: &Vault,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<crate::dreamer_wake::DreamerAttemptExecution> {
    use crate::dreamer_wake::{WakeAttemptContext, WakePassDeadline};

    if admitted.status.attempt.kind != crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND
        || admitted.status.payload.attempt_type != CONFLICT_SETTLE_FACET
    {
        return Err(Error::InvalidConfig(
            "the native conflict-settlement door requires its admitted job type".into(),
        ));
    }
    let deadline = WakePassDeadline::with_clock(60_000, std::sync::Arc::new(|| 0));
    crate::dreamer_runner::maintenance::execute(
        admitted,
        &WakeAttemptContext {
            vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: "conflict-settle-binding",
            now_ms: now.saturating_mul(1_000),
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        },
        None,
    )
}
