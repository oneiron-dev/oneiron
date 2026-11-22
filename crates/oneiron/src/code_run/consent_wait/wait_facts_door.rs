//! Test door (`--cfg oneiron_test_support`; never API): writes the fact that
//! closes a code consent wait to a further answer, its first answer or its
//! settlement, onto the control row through the lifecycle table. It drives
//! no held effect, makes no consent act and appends no receipt, so only a
//! test of what reads the row's state may use it
//! (`test_doors::ask_answer_proof`).

use super::binding::{put_code_consent_wait_in_txn, read_code_consent_wait_in_txn};
use super::types::{
    CodeConsentAnswerStamp, CodeConsentCheckpoint, CodeConsentChoice, CodeConsentSettleOutcome,
    CodeConsentSettlement,
};
use crate::Vault;
use crate::consent::CodeWaitCommand;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::GateDecisionId;

/// Seals wait `wait_id` and stamps it with a first answer of `answerer`
/// that approves once on the word `word_ref`: the state the answer's writer
/// leaves while the approved effect has not settled.
///
/// # Errors
///
/// An unknown wait, a wait the lifecycle table lets neither seal nor answer,
/// and storage errors.
pub(crate) fn answer_code_consent_wait_for_test(
    vault: &Vault,
    wait_id: EntityId,
    answerer: EntityId,
    word_ref: EntityId,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        let mut row =
            read_code_consent_wait_in_txn(vault, txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        row.checkpoint = Some(CodeConsentCheckpoint {
            wait_generation: 0,
            step_hash: [0; 32],
            bridge_call_count: 1,
            step_checkpoint_count: 1,
            output_count: 0,
            last_state_hash: [0; 32],
        });
        put_code_consent_wait_in_txn(vault, txn, &mut row, CodeWaitCommand::Seal)?;
        row.answer = Some(CodeConsentAnswerStamp {
            choice: CodeConsentChoice::ApproveOnce,
            remember_asking_lineage: false,
            word_ref,
            answerer,
            principal_ref: answerer.to_hex(),
            authentication: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
            decision: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
            remembered: None,
            standing_grant: None,
            policy_frontier: [0; 32],
            holder_basis: None,
            answered_at_ms: crate::unix_millis_now(),
        });
        put_code_consent_wait_in_txn(vault, txn, &mut row, CodeWaitCommand::Answer)
    })
}

/// Settles wait `wait_id` refused with no answer: the state its expiry or
/// its effect's release leaves.
///
/// # Errors
///
/// An unknown wait, a wait the lifecycle table does not let settle, and
/// storage errors.
pub(crate) fn settle_code_consent_wait_refused_for_test(
    vault: &Vault,
    wait_id: EntityId,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        let mut row =
            read_code_consent_wait_in_txn(vault, txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        row.settlement = Some(CodeConsentSettlement {
            receipt: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
            outcome: CodeConsentSettleOutcome::Refused,
            reason_codes: vec!["settled_by_a_test_door".to_owned()],
            reply_digest: [0; 32],
            external_reply: false,
            settled_at_ms: crate::unix_millis_now(),
        });
        put_code_consent_wait_in_txn(vault, txn, &mut row, CodeWaitCommand::Settle)
    })
}
