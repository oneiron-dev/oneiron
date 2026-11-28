//! Doors for `tests/task_types_promote.rs` (lead COORD-E2E-TREE-PIN = A,
//! 24 Nov 2026 22:45): the Coach tree gate's last step, which an admitting
//! ruling reaches after its held-out replay, on one revision and the head it
//! revises, without the scorer; and an open revision of a head as the
//! Coach's package revision is born, for that step to rule on.

use rmpv::Value;

use crate::claim::ClaimApprovalStatus;
use crate::dreamer_runner::maintenance::type_tree_upkeep::TreeGateOutcome;
use crate::error::{ArtifactError, Error, Result};
use crate::skill::SkillLifecycle;
use crate::skill_hub::SkillPackageFormat;
use crate::skill_optimize::SkillEditDisposition;
use crate::task_type::TaskTypeTree;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// What the gate's last step does with `proposal` over `predecessor` under
/// the ruling `disposition`: [`TreeGateOutcome::Ruled`] when the owner pinned
/// `predecessor` (nothing is put in force, and the proposal is answered),
/// else optimizer admission and supersession as the gate runs them.
///
/// # Errors
///
/// As the gate's write: storage errors and the supersession door's refusals.
pub fn coach_tree_gate_last_step(
    vault: &Vault,
    proposal: &EntityId,
    predecessor: &EntityId,
    disposition: SkillEditDisposition,
    now: u64,
) -> Result<TreeGateOutcome> {
    crate::dreamer_runner::maintenance::put_revision_in_force_for_test(
        vault,
        proposal,
        predecessor,
        disposition,
        now,
    )
}

/// An open revision of `head`, `candidate` + `proposed` as the Coach's
/// package revision is born (`skill_optimize::propose_skill_package_revision`):
/// `head`'s skill at a new version, its package with the seeded tree. The
/// optimizer's own stamp (attempt, cycle, actor) is not written: the gate's
/// last step reads none of it.
///
/// # Errors
///
/// [`ArtifactError::SkillPackageUnavailable`] for a head whose package this
/// vault does not hold; the package and record doors' refusals; storage
/// errors.
pub fn coach_proposal_over(vault: &Vault, head: &EntityId, at: u64) -> Result<EntityId> {
    vault.with_write_txn_grouped(|txn| {
        let base = vault.read_skill_record_in_txn(txn, head)?;
        let mut package = vault
            .runtime_skill_package_in_txn(txn, head, &base)?
            .ok_or(Error::Artifact(ArtifactError::SkillPackageUnavailable {
                revision: *head,
            }))?;
        let mut record = base.clone();
        record.version = crate::agent_dispatch::next_version(&base.version, &base.version);
        record.lifecycle_status = SkillLifecycle::Candidate;
        record.approval_status = ClaimApprovalStatus::Proposed;
        record.provenance = Value::Map(vec![(
            Value::from("source"),
            Value::from("test-coach-proposal"),
        )]);
        let content = serde_json::to_vec_pretty(&TaskTypeTree::seeded())
            .map_err(|_| Error::InvariantViolation("type tree does not encode"))?;
        package.files = crate::agent_dispatch::fork_files(
            &package,
            &record.skill_id,
            &record.version,
            &content,
        )?;
        package.format = SkillPackageFormat::Native;
        record.content_hash = Some(package.content_hash()?);
        let package =
            crate::skill_hub::package_from_source(&record, package.files, package.format)?;
        let proposal = vault.store.clock.entity_id()?;
        let occurred = TimeRange { start: at, end: at };
        vault.put_skill_record_in_txn(txn, &proposal, &record, occurred, at)?;
        vault.persist_hub_package_in_txn(txn, &proposal, &package)?;
        Ok(proposal)
    })
}
