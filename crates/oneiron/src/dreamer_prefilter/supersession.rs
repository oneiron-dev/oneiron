//! Per-turn membership makes receipt replacement independent of batch shape.
//! Only overlapping decisions are retired. A partially superseded round keeps
//! its original identity/time and a rollup of its remaining current decisions.

use super::*;

const MEMBER_PREFIX: &[u8] = b"dreamer:prefilter:member:v1:";

fn member_key(scope: DreamerConsolidationScope, turn: &EntityId) -> Vec<u8> {
    let mut key = MEMBER_PREFIX.to_vec();
    key.extend_from_slice(scope.attempt_kind().as_bytes());
    key.push(b':');
    key.extend_from_slice(turn.as_bytes());
    key
}

pub(super) fn round_hash(scope: DreamerConsolidationScope, turns: &[WorkingSetTurn]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:dreamer-prefilter-round:v1");
    hasher.update(scope.attempt_kind().as_bytes());
    hasher.update(&partition_round_hash(turns));
    *hasher.finalize().as_bytes()
}

pub(super) fn index_round(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    round: &[u8; 32],
    turns: &[WorkingSetTurn],
) -> Result<()> {
    for turn in turns {
        vault
            .store
            .vault_meta
            .put(txn, &member_key(scope, &turn.turn_id), round)?;
    }
    Ok(())
}

fn corrupt_membership() -> Error {
    Error::CorruptedIndex("dreamer prefilter round membership")
}

pub(super) fn retire_overlapping_decisions(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    scope: DreamerConsolidationScope,
    turns: &[WorkingSetTurn],
) -> Result<()> {
    // Lookup is proportional to this input and its overlapping prior rounds,
    // not a walk over all historical receipts. Scope lanes are independent.
    let mut overlaps: BTreeMap<[u8; 32], BTreeSet<[u8; 16]>> = BTreeMap::new();
    for turn in turns {
        if let Some(raw) = vault
            .store
            .vault_meta
            .get(txn, &member_key(scope, &turn.turn_id))?
        {
            let round = raw.as_ref().try_into().map_err(|_| corrupt_membership())?;
            overlaps
                .entry(round)
                .or_default()
                .insert(*turn.turn_id.as_bytes());
        }
    }
    for (round, replaced) in overlaps {
        let key = prefilter_round_key(&round);
        let mut row: PrefilterRoundRow = {
            let raw = vault
                .store
                .vault_meta
                .get(txn, &key)?
                .ok_or_else(corrupt_membership)?;
            rmp_serde::from_slice(&raw).map_err(|_| corrupt_membership())?
        };
        let members: BTreeSet<_> = row.members.iter().copied().collect();
        if row.version != PREFILTER_RECEIPT_VERSION
            || members.len() != row.members.len()
            || row.scanned != members.len() as u64
            || row.passed.checked_add(row.skipped) != Some(row.scanned)
            || !replaced.is_subset(&members)
        {
            return Err(corrupt_membership());
        }
        for bytes in &replaced {
            let turn = EntityId::from_bytes(*bytes).map_err(|_| corrupt_membership())?;
            let skip_key = prefilter_skip_key(&round, &turn);
            let skip: Option<PrefilterSkipRow> = vault
                .store
                .vault_meta
                .get(txn, &skip_key)?
                .map(|raw| rmp_serde::from_slice(&raw).map_err(|_| corrupt_membership()))
                .transpose()?;
            if let Some(skip) = skip {
                if skip.version != PREFILTER_RECEIPT_VERSION {
                    return Err(corrupt_membership());
                }
                row.skipped = row.skipped.checked_sub(1).ok_or_else(corrupt_membership)?;
                row.estimated_tokens_saved = row
                    .estimated_tokens_saved
                    .checked_sub(skip.estimated_tokens)
                    .ok_or_else(corrupt_membership)?;
                vault.store.vault_meta.delete(txn, &skip_key)?;
            } else {
                row.passed = row.passed.checked_sub(1).ok_or_else(corrupt_membership)?;
            }
            row.scanned = row.scanned.checked_sub(1).ok_or_else(corrupt_membership)?;
            vault
                .store
                .vault_meta
                .delete(txn, &member_key(scope, &turn))?;
        }
        row.members.retain(|turn| !replaced.contains(turn));
        if row.skipped == 0 {
            // As for a fresh all-pass round, no residual all-pass rollup or
            // membership rows are retained after the final skip is rescued.
            for bytes in &row.members {
                let turn = EntityId::from_bytes(*bytes).map_err(|_| corrupt_membership())?;
                vault
                    .store
                    .vault_meta
                    .delete(txn, &member_key(scope, &turn))?;
            }
            vault.store.vault_meta.delete(txn, &key)?;
        } else {
            let encoded = rmp_serde::to_vec_named(&row).map_err(|_| corrupt_membership())?;
            vault.store.vault_meta.put(txn, &key, &encoded)?;
        }
    }
    Ok(())
}
