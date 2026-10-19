//! Typed owner doors for the seal's existing receipts and check lifecycle.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::seal_checks::queue_seal_checks_as_owner;
use crate::dreamer_runner::maintenance::validate_owner_in_txn;
use crate::learning::honesty::{SealAssessment, seal_assessment};
use crate::{Error, Result, Vault};

use super::{
    AttemptConfession, SEALS, SealCheckKind, SealCheckOutcome, SealCheckRequest,
    SealedAttemptReceipt, audit_rate_in_txn, draw_audit,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealAttemptRequest {
    pub attempt: AttemptId,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealPendingRequest {
    #[serde(default)]
    pub attempt: Option<AttemptId>,
}

/// Completion names a persisted request, never a caller-selected audit rate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealCompleteRequest {
    pub attempt: AttemptId,
    pub kind: SealCheckKind,
    pub outcome: SealCheckOutcome,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealRunRequest {}

/// A normal Coach job; its existing leased runner performs the checks.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealRunReceipt {
    pub job: AttemptId,
}

/// Findings move task quality; the confession reward remains separate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealReceiptView {
    pub receipt: SealedAttemptReceipt,
    pub assessment: SealAssessment,
    pub honesty_reward: f64,
}

impl From<SealedAttemptReceipt> for SealReceiptView {
    fn from(receipt: SealedAttemptReceipt) -> Self {
        let assessment = seal_assessment(&receipt);
        Self {
            receipt,
            assessment,
            honesty_reward: assessment.honesty_reward(),
        }
    }
}

/// Adds only the immutable report and its directed recheck requests.
pub fn confess_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &AttemptConfession,
) -> Result<SealReceiptView> {
    vault.with_write_txn_grouped(|txn| {
        validate_owner_in_txn(vault, txn, owner)?;
        vault
            .record_attempt_confession_in_txn(txn, input, crate::unix_seconds_now())
            .map(Into::into)
    })
}

/// Draws one passing attempt once, without running a checker. The owner can
/// inspect the stamp before releasing an external checker or queuing the Coach.
pub fn audit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SealAttemptRequest,
) -> Result<SealReceiptView> {
    vault.with_write_txn_grouped(|txn| {
        validate_owner_in_txn(vault, txn, owner)?;
        let mut receipt = vault
            .sealed_attempt_receipt_in_txn(txn, input.attempt)?
            .ok_or(Error::EntityNotFound)?;
        if receipt.passing && receipt.draw.is_none() {
            let rate = audit_rate_in_txn(vault, txn)?;
            draw_audit(&mut receipt, rate, crate::unix_seconds_now());
            SEALS.put(&vault.store, txn, input.attempt.as_bytes(), &receipt)?;
        }
        Ok(receipt.into())
    })
}

pub fn receipt_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SealAttemptRequest,
) -> Result<Option<SealReceiptView>> {
    let txn = vault.store.env.read_txn()?;
    validate_owner_in_txn(vault, &txn, owner)?;
    Ok(vault
        .sealed_attempt_receipt_in_txn(&txn, input.attempt)?
        .map(Into::into))
}

pub fn pending_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SealPendingRequest,
) -> Result<Vec<SealCheckRequest>> {
    let txn = vault.store.env.read_txn()?;
    validate_owner_in_txn(vault, &txn, owner)?;
    let mut requests = vault.pending_seal_checks_in_txn(&txn)?;
    requests.retain(|request| {
        input
            .attempt
            .is_none_or(|attempt| request.attempt == attempt)
    });
    requests.sort_by(|a, b| (a.created_at, &a.reference).cmp(&(b.created_at, &b.reference)));
    Ok(requests)
}

/// The owner attests an independent external check. The engine's existing
/// admission validates the objectives, evidence, time and immutable completion,
/// then projects findings and the audit-rate fit in this same write.
pub fn complete_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SealCompleteRequest,
) -> Result<SealReceiptView> {
    vault.with_write_txn_grouped(|txn| {
        validate_owner_in_txn(vault, txn, owner)?;
        let receipt = vault
            .sealed_attempt_receipt_in_txn(txn, input.attempt)?
            .ok_or(Error::EntityNotFound)?;
        let model = |revision: &str| {
            revision
                .rsplit_once('@')
                .map_or(revision, |(model, _)| model)
                .to_owned()
        };
        if model(&input.outcome.judge_revision) == model(&receipt.executor) {
            return Err(Error::InvalidClaimBody(
                "a seal check requires a judge other than the executor",
            ));
        }
        vault
            .record_seal_check_outcome_in_txn(
                txn,
                input.attempt,
                input.kind,
                &input.outcome,
                crate::unix_seconds_now(),
            )
            .map(Into::into)
    })
}

pub fn run_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &SealRunRequest,
) -> Result<SealRunReceipt> {
    Ok(SealRunReceipt {
        job: queue_seal_checks_as_owner(vault, owner, crate::unix_seconds_now())?,
    })
}
