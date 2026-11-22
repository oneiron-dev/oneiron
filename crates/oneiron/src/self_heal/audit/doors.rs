//! Typed owner doors for the seal's existing receipts and check lifecycle,
//! and an agent's read doors beside them (restriction census C54).

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::seal_checks::queue_seal_checks_as_owner;
use crate::dreamer_runner::maintenance::validate_owner_in_txn;
use crate::edge::EdgeActorClass;
use crate::learning::honesty::{SealAssessment, seal_assessment};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::setting::SettingScope;
use crate::{EntityId, Error, Result, Vault};

use super::setting_keys::SEAL_AUDIT_DELEGATE_READ;
use super::{
    AttemptConfession, SEALS, SealCheckRequest, SealedAttemptReceipt, audit_rate_in_txn, draw_audit,
};

/// `vault.seal.receipt_as`, the name a Grant lists to name the agent's receipt read.
const SEAL_RECEIPT_AS_VERB: &str = "vault.seal.receipt_as";
/// `vault.seal.pending_as`, the name a Grant lists to name the agent's pending read.
const SEAL_PENDING_AS_VERB: &str = "vault.seal.pending_as";
/// `vault.seal.audit_as`, the name a Grant lists to name the agent's audit draw.
const SEAL_AUDIT_AS_VERB: &str = "vault.seal.audit_as";

#[doc(hidden)]
pub use oneiron_verb_wire::self_heal::audit::doors::{
    SealAttemptRequest, SealCompleteRequest, SealPendingRequest, SealRunReceipt, SealRunRequest,
};

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
        let mut stored = SEALS
            .get(&vault.store, txn, input.attempt.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if stored.receipt.passing && stored.receipt.draw.is_none() {
            let rate = audit_rate_in_txn(vault, txn, &stored.receipt)?;
            draw_audit(&mut stored.receipt, rate, crate::unix_seconds_now());
            SEALS.put(&vault.store, txn, input.attempt.as_bytes(), &stored)?;
        }
        Ok(stored.receipt.into())
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

/// [`receipt_as_owner`] beside the rows the seal's content was derived from
/// ([`seal_source_rows_in_txn`], FIX 8164), read in the receipt's snapshot,
/// so a host releases it by them right before it serializes it.
pub fn receipt_sourced_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SealAttemptRequest,
) -> Result<(Option<SealReceiptView>, Vec<EntityId>)> {
    let txn = vault.store.env.read_txn()?;
    validate_owner_in_txn(vault, &txn, owner)?;
    let Some(receipt) = vault.sealed_attempt_receipt_in_txn(&txn, input.attempt)? else {
        return Ok((None, Vec::new()));
    };
    let rows = seal_source_rows_in_txn(
        vault,
        &txn,
        receipt.confession.attempt,
        receipt.confession.subject,
        &receipt.result_ref,
    )?;
    Ok((Some(receipt.into()), rows))
}

/// [`pending_as_owner`], each pending check beside the rows its attempt's
/// content was derived from ([`seal_source_rows_in_txn`], FIX 8164), all read
/// in one snapshot, so a host keeps only the checks its caller's destination
/// admits and counts only those.
pub fn pending_sourced_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SealPendingRequest,
) -> Result<Vec<(SealCheckRequest, Vec<EntityId>)>> {
    let txn = vault.store.env.read_txn()?;
    validate_owner_in_txn(vault, &txn, owner)?;
    let mut sourced = Vec::new();
    for receipt in SEALS
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(_, stored)| stored.receipt)
    {
        if input
            .attempt
            .is_some_and(|attempt| receipt.confession.attempt != attempt)
        {
            continue;
        }
        let mut pending = receipt
            .checks
            .iter()
            .filter(|check| check.outcome.is_none())
            .map(|check| check.request.clone())
            .peekable();
        if pending.peek().is_none() {
            continue;
        }
        let rows = seal_source_rows_in_txn(
            vault,
            &txn,
            receipt.confession.attempt,
            receipt.confession.subject,
            &receipt.result_ref,
        )?;
        sourced.extend(pending.map(|request| (request, rows.clone())));
    }
    sourced
        .sort_by(|(a, _), (b, _)| (a.created_at, &a.reference).cmp(&(b.created_at, &b.reference)));
    Ok(sourced)
}

/// The rows a seal's content was derived from, read in `txn` (FIX 8164): the
/// subject its confession measured, the attempt's TASK, its durable result
/// when that names a row, and the rows the attempt's producers recorded its
/// inputs read from, as far as they recorded them. A read set they left
/// unknown adds no row, so it never withholds the seal: only a row known to
/// be among its sources narrows it.
fn seal_source_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    subject: EntityId,
    result_ref: &str,
) -> Result<Vec<EntityId>> {
    let mut rows = vec![subject];
    rows.extend(reference_row(result_ref));
    if let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, attempt)? {
        rows.extend(record.task_ref.as_deref().and_then(reference_row));
        if let Some(read) = record.read_set.as_ref().and_then(|set| set.rows.as_deref()) {
            rows.extend_from_slice(read);
        }
    }
    rows.sort_unstable();
    rows.dedup();
    Ok(rows)
}

/// The row a stored reference names (`<kind>:<hex>`, with or without an
/// `@<revision>` pin), `None` when it names none.
pub(crate) fn reference_row(reference: &str) -> Option<EntityId> {
    let reference = reference
        .split_once('@')
        .map_or(reference, |(head, _)| head);
    reference
        .rsplit(':')
        .next()
        .and_then(|hex| EntityId::from_hex(hex).ok())
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
                None,
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

/// The handle's own agent, or the refusal of any other caller: these doors
/// are an agent's; the owner reads through the owner doors above.
fn seal_agent(memory: &Memory<'_>, verb: &str) -> MemoryResult<EntityId> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is an agent's door: the caller is no agent"),
            &["Read the seal through the owner's door with the owner's own credential."],
        ));
    }
    Ok(memory.actor())
}

/// `agent`'s standing for the seal read `verb` in `txn`: its live Grant
/// listing `verb`, then the owner's `SEAL_AUDIT_DELEGATE_READ` row for it.
/// With the key off the read stays the owner's, as at every owner seal door.
fn admit_seal_agent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    verb: &str,
) -> MemoryResult<()> {
    if crate::authority::principal_standing_in_txn(vault, txn, agent, EdgeActorClass::Agent, verb)?
        .is_none()
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{verb} takes a live Grant listing {verb}: no live Grant from a live owner names this caller and lists the verb"
            ),
            &["Have the owner grant this caller the verb by name."],
        ));
    }
    let delegated = SEAL_AUDIT_DELEGATE_READ
        .read_in_txn(vault, txn, &[SettingScope::Agent(agent)], None)?
        .value;
    if !delegated {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{verb} is the vault owner's: the owner has not turned on {} for this agent",
                SEAL_AUDIT_DELEGATE_READ.spec.name
            ),
            &["Ask the owner to turn the setting on for this agent."],
        ));
    }
    Ok(())
}

/// The rows `lane` must read, in `txn`, for its agent to read `receipt`:
/// [`seal_source_rows_in_txn`]'s and the project it ran in, when its
/// attempt's producers recorded a complete read set (FIX 7073). `None` when
/// they recorded none, or when `lane` does not read every such row: a seal
/// no complete set proves stays the owner's, as a heal context's trace part
/// does (FIX 10093).
fn agent_seal_rows_in_txn(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    receipt: &SealedAttemptReceipt,
) -> Result<Option<Vec<EntityId>>> {
    let attempt = receipt.confession.attempt;
    let complete = AttemptQueue::new(vault)
        .get_in_txn(txn, attempt)?
        .is_some_and(|record| record.source_rows().is_some());
    if !complete {
        return Ok(None);
    }
    let mut rows = seal_source_rows_in_txn(
        vault,
        txn,
        attempt,
        receipt.confession.subject,
        &receipt.result_ref,
    )?;
    rows.extend(receipt.project);
    rows.sort_unstable();
    rows.dedup();
    if lane.entities_readable_in_txn(txn, &rows)?.contains(&false) {
        return Ok(None);
    }
    Ok(Some(rows))
}

/// `vault.seal.receipt_as`: [`receipt_as_owner`] for the handle's own agent,
/// under its live Grant listing the verb and the owner's
/// `SEAL_AUDIT_DELEGATE_READ` row for it, judged in the receipt's own
/// snapshot of the agent's read lane. A seal the lane may not read whole
/// (`agent_seal_rows_in_txn`) answers `None`, as no seal does.
///
/// # Errors
/// `FORBIDDEN` for a caller that is no agent, an agent with no such Grant,
/// and an agent the owner has not turned the key on for; a credential that no
/// longer holds; storage faults.
pub fn receipt_as_agent(
    memory: &Memory<'_>,
    input: SealAttemptRequest,
) -> MemoryResult<Option<SealReceiptView>> {
    let agent = seal_agent(memory, SEAL_RECEIPT_AS_VERB)?;
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let read = lane.read_projected(&[], None, |txn, _| {
        memory.prove_read_authority_in_txn(txn)?;
        admit_seal_agent_in_txn(vault, txn, agent, SEAL_RECEIPT_AS_VERB)?;
        let Some(receipt) = vault.sealed_attempt_receipt_in_txn(txn, input.attempt)? else {
            return Ok::<_, MemoryError>(None);
        };
        Ok(agent_seal_rows_in_txn(vault, &lane, txn, &receipt)?.map(|rows| (receipt, rows)))
    })?;
    Ok(read.value.map(|(receipt, rows)| {
        memory.produced_from(rows);
        receipt.into()
    }))
}

/// `vault.seal.pending_as`: the pending checks [`pending_sourced_as_owner`]
/// lists, for the handle's own agent, admitted as [`receipt_as_agent`]
/// admits: a check whose seal the agent's lane may not read whole is left
/// out, never counted. Same order as the owner's list.
///
/// # Errors
/// As [`receipt_as_agent`].
pub fn pending_as_agent(
    memory: &Memory<'_>,
    input: SealPendingRequest,
) -> MemoryResult<Vec<SealCheckRequest>> {
    let agent = seal_agent(memory, SEAL_PENDING_AS_VERB)?;
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let read = lane.read_projected(&[], None, |txn, _| {
        memory.prove_read_authority_in_txn(txn)?;
        admit_seal_agent_in_txn(vault, txn, agent, SEAL_PENDING_AS_VERB)?;
        let mut kept = Vec::new();
        let mut served = Vec::new();
        for receipt in SEALS
            .scan(&vault.store, txn)?
            .into_iter()
            .map(|(_, stored)| stored.receipt)
        {
            if input
                .attempt
                .is_some_and(|attempt| receipt.confession.attempt != attempt)
            {
                continue;
            }
            let pending: Vec<SealCheckRequest> = receipt
                .checks
                .iter()
                .filter(|check| check.outcome.is_none())
                .map(|check| check.request.clone())
                .collect();
            if pending.is_empty() {
                continue;
            }
            let Some(rows) = agent_seal_rows_in_txn(vault, &lane, txn, &receipt)? else {
                continue;
            };
            kept.extend(pending);
            served.extend(rows);
        }
        Ok::<_, MemoryError>((kept, served))
    })?;
    let (mut kept, served) = read.value;
    memory.produced_from(served);
    kept.sort_by(|a, b| (a.created_at, &a.reference).cmp(&(b.created_at, &b.reference)));
    Ok(kept)
}

/// `vault.seal.audit_as`: [`audit_as_owner`] for the handle's own agent,
/// admitted as [`receipt_as_agent`] admits, in the draw's own write. A seal
/// the agent's lane may not read whole is not drawn and answers not found, as
/// no seal does.
///
/// # Errors
/// As [`receipt_as_agent`]; `NOT_FOUND` for no seal the agent may read.
pub fn audit_as_agent(
    memory: &Memory<'_>,
    input: SealAttemptRequest,
) -> MemoryResult<SealReceiptView> {
    let agent = seal_agent(memory, SEAL_AUDIT_AS_VERB)?;
    let vault = memory.vault();
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let (receipt, rows) = memory.with_verified_actor_write_txn(|txn| {
        memory.prove_read_authority_in_txn(txn)?;
        admit_seal_agent_in_txn(vault, txn, agent, SEAL_AUDIT_AS_VERB)?;
        let mut stored = SEALS
            .get(&vault.store, txn, input.attempt.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let Some(rows) = agent_seal_rows_in_txn(vault, &lane, txn, &stored.receipt)? else {
            return Err(Error::EntityNotFound.into());
        };
        if stored.receipt.passing && stored.receipt.draw.is_none() {
            let rate = audit_rate_in_txn(vault, txn, &stored.receipt)?;
            draw_audit(&mut stored.receipt, rate, crate::unix_seconds_now());
            SEALS.put(&vault.store, txn, input.attempt.as_bytes(), &stored)?;
        }
        Ok((stored.receipt, rows))
    })?;
    memory.produced_from(rows);
    Ok(receipt.into())
}
