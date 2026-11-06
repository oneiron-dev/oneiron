//! FIX 3611: a completed random audit as the anchor of a contribution check.
//! The host's checker names its protocol with each check it makes, and the
//! rung that answered: where it ran and the route it went out on, which
//! names its route prompt by digest ([`CheckerProtocol`]). A random audit of
//! every objective of the seal's exact result freezes its contract
//! ([`AuditContract`]) in the seal's own row, in the write that admits the
//! check. Nothing rebuilds it later from the checker's prompt or route as
//! they stand then. An audit whose checker could not name its answering
//! rung anchors nothing. The seal's public request and outcome types are
//! unchanged: the contract sits beside the receipt in a private stored form
//! ([`StoredSeal`]).
//!
//! A single-call workflow step binds its answer to its capsule by the
//! digest and length of its text (`code_run::bind_workflow_step_answer`).
//! The audit names that capsule only when its bound answer is the seal's
//! result ([`AuditedAnswer`]): the same attempt alone is not enough.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::code_run::{
    CapsuleHost, ReplayRoutePin, StepReplayCapsule, step_replay_capsules_in_txn,
};
use crate::compaction::output::OutputRef;
use crate::model_binding::ModelRole;
use crate::receipt::attempt_pack_receipt_id;
use crate::{EntityId, ModelLocality, Result, Vault};

use super::{ObjectiveFinding, SEALS, SealCheckKind, SealedAttemptReceipt};

/// The checker a host put a seal check to (FIX 3611): the digest of its
/// protocol and wording, the role its judge was routed on, and the rung
/// that answered there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerProtocol {
    pub digest: [u8; 32],
    pub role: ModelRole,
    /// Where the judge's answering rung ran, and the route it went out on
    /// as it answered, which names its route prompt by digest, never by
    /// text. `None` when the check could not name that rung: its audit
    /// anchors nothing.
    pub judge_rung: Option<(ModelLocality, ReplayRoutePin)>,
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
    /// The checker's protocol, the role its judge was routed on and the
    /// rung that answered there.
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

/// `attempt`'s frozen random audit, read in `txn` (FIX 3611), while the
/// capsule it names still binds the seal's result as its answer. A seal with
/// no frozen audit, an audit no capsule bound, an audit whose checker named
/// no answering rung, an erased capsule and a changed answer or result are
/// none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn bound_random_audit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<SealedAudit>> {
    let Some(stored) = SEALS.get(&vault.store, txn, attempt.as_bytes())? else {
        return Ok(None);
    };
    let Some(audit) = stored.audit else {
        return Ok(None);
    };
    let (Some(answer), Some(_)) = (audit.answer, &audit.contract.protocol.judge_rung) else {
        return Ok(None);
    };
    let current = audited_answer_in_txn(vault, txn, &stored.receipt)?;
    Ok((current == Some(answer)).then_some(audit))
}

/// The frozen contract of the random audit `outcome_receipt` names, of the
/// attempt whose terminal pack receipt is `attempt_receipt` (FIX 3611).
/// `None` when that audit froze no contract.
///
/// # Errors
///
/// Storage errors.
pub fn audit_contract(
    vault: &Vault,
    attempt_receipt: &str,
    outcome_receipt: &str,
) -> Result<Option<AuditContract>> {
    let Some(attempt) = pack_receipt_attempt(attempt_receipt) else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    Ok(SEALS
        .get(&vault.store, &txn, attempt.as_bytes())?
        .and_then(|stored| stored.audit)
        .map(|audit| audit.contract)
        .filter(|contract| contract.check == outcome_receipt))
}

/// The attempt a terminal pack receipt id names, when it is exactly one.
pub(crate) fn pack_receipt_attempt(receipt: &str) -> Option<AttemptId> {
    let (_, hex) = receipt.rsplit_once(':')?;
    let entity = EntityId::from_hex(hex).ok()?;
    let attempt = AttemptId::from_bytes(entity.as_bytes()).ok()?;
    (attempt_pack_receipt_id(&attempt) == receipt).then_some(attempt)
}
