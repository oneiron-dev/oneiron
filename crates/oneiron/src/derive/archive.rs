//! The archive item (kind 6): an agent archives its own weak claim,
//! reversibly, under its live `archive` grant and the strength archive's own
//! fence; the owner's cleanup restore lifts it.

use super::batch::DerivedArchive;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::strength::{
    ConsolidationStrengthSnapshot, archive_claim_in_txn, archive_fence_in_txn, policy_in_txn,
};
use crate::error::Result;
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Vault};

/// The refusal of an archive whose commit names no attempt to bind the
/// archive's snapshot and tombstone to.
pub const ARCHIVE_NEEDS_ATTEMPT: &str = "gate.deny.derive.archive_needs_attempt";

/// The refusal of an archive of a row that is no live claim.
pub const ARCHIVE_NOT_A_CLAIM: &str = "gate.deny.derive.archive_not_a_claim";

/// The refusal of an archive whose score is not below the owner's strength
/// policy row.
pub const ARCHIVE_SCORE_NOT_BELOW_POLICY: &str = "gate.deny.derive.archive_score_not_below_policy";

/// The reason a landed archive's receipt names.
const ARCHIVE_ALLOWED: &str = "gate.allow.derive.archive";

/// Stages `item`: the archive verdict over the claim, the strength
/// archive's fence and the owner's policy row, then the archive in a
/// savepoint of `txn`.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedArchive,
) -> Result<ItemOutcome> {
    let claim = context.resolve(&item.claim)?;
    let actor = context.stamp.actor;
    let Some(attempt) = context.stamp.attempt else {
        return refuse(vault, txn, context, claim, ARCHIVE_NEEDS_ATTEMPT);
    };
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Archive,
        Some(claim),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, claim, refusal.token()),
    };
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &claim)?.is_live() {
        return refuse(vault, txn, context, claim, ARCHIVE_NOT_A_CLAIM);
    }
    let Some(raw) =
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store.read(), txn, &claim)?
    else {
        return refuse(vault, txn, context, claim, ARCHIVE_NOT_A_CLAIM);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        .filter(|_| raw.len() > ENTITY_METADATA_HEADER_LEN)
    else {
        return refuse(vault, txn, context, claim, ARCHIVE_NOT_A_CLAIM);
    };
    let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return refuse(vault, txn, context, claim, ARCHIVE_NOT_A_CLAIM);
    };
    let policy = policy_in_txn(vault, txn)?;
    let now_ms = context.now.saturating_mul(1_000);
    if let Some(fence) = archive_fence_in_txn(
        vault,
        txn,
        actor.entity_ref(),
        &claim,
        &body,
        header.learned_at,
        now_ms,
        &policy,
    )? {
        return refuse(vault, txn, context, claim, fence.token());
    }
    if !item.score.is_finite() || item.score >= policy.archive_below {
        return refuse(vault, txn, context, claim, ARCHIVE_SCORE_NOT_BELOW_POLICY);
    }
    let snapshot = ConsolidationStrengthSnapshot {
        attempt,
        at_ms: now_ms,
        revision: *blake3::hash(&raw).as_bytes(),
        signals: item.signals,
        score: item.score,
        selection: vault.consolidation_selection_in_txn(txn)?,
        policy,
    };
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    archive_claim_in_txn(vault, &mut savepoint, claim, &snapshot, *attempt.as_bytes())?;
    savepoint.commit()?;
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(claim),
        &[ARCHIVE_ALLOWED.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows: vec![claim],
        approval: None,
        receipt: Some(receipt),
    })
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    claim: EntityId,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, Some(claim), &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
