//! The archive item (kind 6): an agent archives its own weak claim,
//! reversibly, under its live `archive` grant and the strength archive's own
//! fence; the owner's cleanup restore lifts it.

use super::batch::DerivedArchive;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::selection::{SelectionConfig, selection_config_pin_in_txn};
use crate::dreamer_consolidation::strength::{
    ConsolidationStrengthPolicy, ConsolidationStrengthSnapshot, OBSERVATIONS, archive_claim_in_txn,
    archive_fence_in_txn, observation_pin_in_txn, policy_in_txn, strength_policy_pin_in_txn,
};
use crate::error::Result;
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::snapshot_read::{
    ObservedClaimStatus, classify_observation_sources_in_txn,
    observation_reader_scope_for_actor_in_txn,
};
use crate::{EntityId, Vault};

/// The refusal of an archive whose commit names no attempt to bind the
/// archive's snapshot and tombstone to.
pub const ARCHIVE_NEEDS_ATTEMPT: &str = "gate.deny.derive.archive_needs_attempt";

/// The refusal of an archive of a row that is no live claim.
pub const ARCHIVE_NOT_A_CLAIM: &str = "gate.deny.derive.archive_not_a_claim";

/// The refusal of an archive whose score is not below the owner's strength
/// policy row.
pub const ARCHIVE_SCORE_NOT_BELOW_POLICY: &str = "gate.deny.derive.archive_score_not_below_policy";

/// The refusal of an archive whose strength policy pin no longer matches
/// the live policy.
pub const ARCHIVE_POLICY_CHANGED: &str = "gate.deny.derive.archive_policy_changed";

/// The refusal of an archive whose scoring config pin no longer matches
/// the live config.
pub const ARCHIVE_CONFIG_CHANGED: &str = "gate.deny.derive.archive_config_changed";

/// The refusal of an archive whose observation pin is missing or no longer
/// matches the stored observation row.
pub const ARCHIVE_OBSERVATION_CHANGED: &str = "gate.deny.derive.archive_observation_changed";

/// The refusal of an archive whose stored observations name no source.
pub const ARCHIVE_NO_OBSERVED_SOURCE: &str = "gate.deny.derive.archive_no_observed_source";

/// The refusal of an archive one of whose observed sources the actor no
/// longer reads.
pub const ARCHIVE_SOURCE_WITHHELD: &str = "gate.deny.derive.archive_source_withheld";

/// The refusal of an archive one of whose observed sources moved since it
/// was observed.
pub const ARCHIVE_SOURCE_MOVED: &str = "gate.deny.derive.archive_source_moved";

/// The reason a landed archive's receipt names.
const ARCHIVE_ALLOWED: &str = "gate.allow.derive.archive";

/// Stages `item`: the archive verdict over the claim, the live claim row,
/// then the pins, the observed sources, the fence and the score through a
/// savepoint of `txn`, then the archive.
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
    let now_ms = context.now.saturating_mul(1_000);
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let checked = recheck_archive_observations_in_txn(
        vault,
        &savepoint,
        context,
        item,
        claim,
        &body,
        header.learned_at,
    )?;
    let (policy, selection) = match checked {
        Ok(values) => values,
        Err(token) => {
            drop(savepoint);
            return refuse(vault, txn, context, claim, token);
        }
    };
    let snapshot = ConsolidationStrengthSnapshot {
        attempt,
        at_ms: now_ms,
        revision: *blake3::hash(&raw).as_bytes(),
        signals: item.signals,
        score: item.score,
        selection,
        policy,
    };
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

/// Rechecks `item`'s pins, sources, fence and score in `txn`, for the actor
/// of `context` at its clock: the live policy, config and observation pins,
/// a stored row with sources, each source current under the actor's engine
/// read and record scope, then the fence and the score. Matching pins keep
/// the live policy and config exact for the snapshot. Returns the live
/// policy and config, or the refusal's token.
///
/// # Errors
///
/// Storage errors.
fn recheck_archive_observations_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedArchive,
    claim: EntityId,
    body: &crate::claim::ClaimBody,
    learned_at: u64,
) -> Result<std::result::Result<(ConsolidationStrengthPolicy, SelectionConfig), &'static str>> {
    let actor = context.stamp.actor;
    if strength_policy_pin_in_txn(vault, txn)? != item.policy_pin {
        return Ok(Err(ARCHIVE_POLICY_CHANGED));
    }
    if selection_config_pin_in_txn(vault, txn)? != item.config_pin {
        return Ok(Err(ARCHIVE_CONFIG_CHANGED));
    }
    match observation_pin_in_txn(vault, txn, &claim)? {
        Some(live) if live == item.observation_pin => {}
        _ => return Ok(Err(ARCHIVE_OBSERVATION_CHANGED)),
    }
    let Some(observations) = OBSERVATIONS.get(&vault.store, txn, &claim)? else {
        return Ok(Err(ARCHIVE_OBSERVATION_CHANGED));
    };
    if observations.sources.is_empty() {
        return Ok(Err(ARCHIVE_NO_OBSERVED_SOURCE));
    }
    let Some(scope) = observation_reader_scope_for_actor_in_txn(vault, txn, actor.entity_ref())?
    else {
        return Ok(Err(ARCHIVE_SOURCE_WITHHELD));
    };
    let Some(key) = crate::claim::ScopedReadActorKey::for_engine_actor(actor) else {
        return Ok(Err(ARCHIVE_SOURCE_WITHHELD));
    };
    let read = vault.scoped_read(key);
    let (status, _) =
        classify_observation_sources_in_txn(vault, txn, &read, scope.as_ref(), &observations)?;
    match status {
        ObservedClaimStatus::Current => {}
        ObservedClaimStatus::Withheld => return Ok(Err(ARCHIVE_SOURCE_WITHHELD)),
        ObservedClaimStatus::Moved => return Ok(Err(ARCHIVE_SOURCE_MOVED)),
    }
    let policy = policy_in_txn(vault, txn)?;
    if let Some(fence) = archive_fence_in_txn(
        vault,
        txn,
        actor.entity_ref(),
        &claim,
        body,
        learned_at,
        context.now.saturating_mul(1_000),
        &policy,
    )? {
        return Ok(Err(fence.token()));
    }
    if !item.score.is_finite() || item.score >= policy.archive_below {
        return Ok(Err(ARCHIVE_SCORE_NOT_BELOW_POLICY));
    }
    let selection = vault.consolidation_selection_in_txn(txn)?;
    Ok(Ok((policy, selection)))
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
