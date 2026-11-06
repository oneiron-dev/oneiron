//! FIX 3611: a completed random audit as the anchor of a contribution check.
//! The host's checker names its protocol with each check it makes
//! ([`CheckerProtocol`]). A random audit of every objective of the seal's
//! exact result freezes its contract ([`AuditContract`]) in the seal's own
//! row, in the write that admits the check. Nothing rebuilds it later from
//! the checker's prompt as it stands then. The seal's public request and
//! outcome types are unchanged: the contract sits beside the receipt in a
//! private stored form ([`StoredSeal`]).
//!
//! A single-call workflow step binds its answer to its capsule by the
//! digest and length of its text (`code_run::bind_workflow_step_answer`).
//! The audit names that capsule only when its bound answer is the seal's
//! result ([`AuditedAnswer`]): the same attempt alone is not enough.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptQueue;
use crate::code_run::{CapsuleHost, StepReplayCapsule, step_replay_capsules_in_txn};
use crate::compaction::output::OutputRef;
use crate::model_binding::ModelRole;
use crate::{EntityId, Result, Vault};

use super::{ObjectiveFinding, SealCheckKind, SealedAttemptReceipt};

/// The checker a host put a seal check to (FIX 3611): the digest of its
/// protocol and wording, and the role its judge was routed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerProtocol {
    pub digest: [u8; 32],
    pub role: ModelRole,
}

/// A completed random audit's frozen contract (FIX 3611): what a
/// contribution check scores both of its forks by. It is taken from the
/// check as it was admitted and never changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditContract {
    /// The audit's check reference: the outcome receipt its anchor names.
    pub check: String,
    /// The rate the audit was drawn at.
    pub rate: f64,
    /// The checker's protocol and the role its judge was routed on.
    pub protocol: CheckerProtocol,
    /// The independent judge that checked the result, as it served.
    pub judge_revision: String,
    /// Every objective the audit examined, in the order it asked them.
    pub objectives: Vec<String>,
    /// One finding per objective.
    pub findings: Vec<ObjectiveFinding>,
    /// Unix seconds the result was checked.
    pub checked_at: u64,
}

impl AuditContract {
    /// Whether the audited result passed, by [`flaw_free`].
    #[must_use]
    pub fn passed(&self) -> bool {
        flaw_free(&self.findings)
    }
}

/// An audit's pass rule (FIX 3611): no finding names a flaw. The original
/// check and both forks of a contribution check are scored by this rule.
#[must_use]
pub fn flaw_free(findings: &[ObjectiveFinding]) -> bool {
    findings.iter().all(|finding| !finding.flaw_present)
}

/// The capsule whose bound answer is the audited result (FIX 3611): its
/// key, the digest of the request it sent, and the answer's digest and
/// length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuditedAnswer {
    pub(crate) attempt: EntityId,
    pub(crate) lease_generation: u32,
    pub(crate) step: u64,
    pub(crate) request_hash: [u8; 32],
    pub(crate) answer: OutputRef,
}

/// A completed random audit as the seal keeps it (FIX 3611): its frozen
/// contract, and the capsule whose answer it audited when one binds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SealedAudit {
    pub(crate) contract: AuditContract,
    pub(crate) answer: Option<AuditedAnswer>,
}

/// The seal's stored row (FIX 3611): the receipt its doors return, and a
/// completed random audit beside it. It is private to the seal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct StoredSeal {
    pub(super) receipt: SealedAttemptReceipt,
    pub(super) audit: Option<SealedAudit>,
}

impl StoredSeal {
    /// A seal with no frozen audit.
    pub(super) fn new(receipt: SealedAttemptReceipt) -> Self {
        Self {
            receipt,
            audit: None,
        }
    }
}

/// The audit that the check at `index` of `receipt` freezes, checked under
/// `protocol` (FIX 3611). Only a completed random audit counts: drawn at
/// its own rate, of every objective of the seal's exact result. `None` for
/// any other check.
///
/// # Errors
///
/// Storage errors.
pub(super) fn freeze_audit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &SealedAttemptReceipt,
    index: usize,
    protocol: CheckerProtocol,
) -> Result<Option<SealedAudit>> {
    let Some(check) = receipt.checks.get(index) else {
        return Ok(None);
    };
    let Some(outcome) = &check.outcome else {
        return Ok(None);
    };
    let drawn = receipt
        .draw
        .as_ref()
        .is_some_and(|draw| draw.selected() && draw.rate.to_bits() == check.request.rate.to_bits());
    if check.request.kind != SealCheckKind::RandomAudit
        || !drawn
        || check.request.result_ref != receipt.result_ref
        || check.request.objectives != receipt.confession.objectives
    {
        return Ok(None);
    }
    let contract = AuditContract {
        check: check.request.reference.clone(),
        rate: check.request.rate,
        protocol,
        judge_revision: outcome.judge_revision.clone(),
        objectives: check
            .request
            .objectives
            .iter()
            .map(|objective| objective.objective.clone())
            .collect(),
        findings: outcome.findings.clone(),
        checked_at: outcome.checked_at,
    };
    Ok(Some(SealedAudit {
        contract,
        answer: audited_answer_in_txn(vault, txn, receipt)?,
    }))
}

/// The capsule whose bound answer is `receipt`'s result, read in `txn`
/// (FIX 3611): the one finalized single-call workflow capsule of the try
/// that settled the attempt, still holding its content, whose answer has
/// the result's digest and length, while the attempt still names that
/// result. `None` when no capsule, or more than one, binds it.
fn audited_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &SealedAttemptReceipt,
) -> Result<Option<AuditedAnswer>> {
    let Ok(result) = OutputRef::from_handle(&receipt.result_ref) else {
        return Ok(None);
    };
    let Some(attempt) = AttemptQueue::new(vault).get_in_txn(txn, receipt.confession.attempt)?
    else {
        return Ok(None);
    };
    if !attempt
        .result_ref
        .as_ref()
        .is_some_and(|stored| stored.as_str() == receipt.result_ref)
    {
        return Ok(None);
    }
    let run = EntityId::from_bytes(*receipt.confession.attempt.as_bytes())?;
    let mut bound = step_replay_capsules_in_txn(vault, txn, run)?
        .into_iter()
        .filter(|capsule| binds_result(capsule, attempt.attempt_count, result));
    let (Some(capsule), None) = (bound.next(), bound.next()) else {
        return Ok(None);
    };
    Ok(Some(AuditedAnswer {
        attempt: capsule.attempt,
        lease_generation: capsule.lease_generation,
        step: capsule.step,
        request_hash: capsule.request_hash,
        answer: result,
    }))
}

/// Whether `capsule` is a finalized single-call workflow capsule of lease
/// `generation` that still holds its content and whose bound answer is
/// `result`.
fn binds_result(capsule: &StepReplayCapsule, generation: u32, result: OutputRef) -> bool {
    capsule.host == CapsuleHost::WorkflowStep
        && capsule.step == 0
        && capsule.lease_generation == generation
        && capsule.content.actor().is_some()
        && capsule.binding.is_some()
        && capsule.answer == Some(result)
}
