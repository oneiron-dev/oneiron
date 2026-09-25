//! Per-turn membership makes receipt replacement independent of batch shape.
//! Only overlapping decisions are retired. A partially superseded round keeps
//! its original identity/time and a rollup of its remaining current decisions.

use crate::side_table::{self, Raw, SideKey, SideTable};

use super::*;

/// Turn to screening round index. Key: `scope.attempt_kind()` text ":" id16.
const MEMBER: SideTable<MemberKey, [u8; 32], Raw> = SideTable::new(&side_table::PREFILTER_MEMBER);

/// A member row's key: the scope's attempt-kind text, a literal `:`, then the turn id — spelled
/// explicitly because the text is variable-width, so it cannot lead a fixed-width key tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MemberKey {
    attempt_kind: String,
    turn: EntityId,
}

impl MemberKey {
    fn new(scope: DreamerConsolidationScope, turn: EntityId) -> Self {
        Self {
            attempt_kind: scope.attempt_kind().to_owned(),
            turn,
        }
    }
}

impl SideKey for MemberKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.attempt_kind.as_bytes());
        out.push(b':');
        out.extend_from_slice(self.turn.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        // The turn id is a fixed 16 bytes; everything before the ':' that
        // precedes it is the scope's attempt-kind text.
        let split = bytes.len().checked_sub(16)?;
        let (head, turn_bytes) = bytes.split_at(split);
        let (attempt_kind, separator) = head.split_at(head.len().checked_sub(1)?);
        if separator != b":" {
            return None;
        }
        Some(Self {
            attempt_kind: std::str::from_utf8(attempt_kind).ok()?.to_owned(),
            turn: EntityId::from_bytes(turn_bytes.try_into().ok()?).ok()?,
        })
    }
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
        MEMBER.put(
            &vault.store,
            txn,
            &MemberKey::new(scope, turn.turn_id),
            round,
        )?;
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
        if let Some(round) = MEMBER.get(&vault.store, txn, &MemberKey::new(scope, turn.turn_id))? {
            overlaps
                .entry(round)
                .or_default()
                .insert(*turn.turn_id.as_bytes());
        }
    }
    for (round, replaced) in overlaps {
        let mut row = ROUND
            .get(&vault.store, txn, &round)?
            .ok_or_else(corrupt_membership)?;
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
            let skip = SKIP.get(&vault.store, txn, &(round, turn))?;
            if let Some(skip) = skip {
                if skip.version != PREFILTER_RECEIPT_VERSION {
                    return Err(corrupt_membership());
                }
                row.skipped = row.skipped.checked_sub(1).ok_or_else(corrupt_membership)?;
                row.estimated_tokens_saved = row
                    .estimated_tokens_saved
                    .checked_sub(skip.estimated_tokens)
                    .ok_or_else(corrupt_membership)?;
                SKIP.delete(&vault.store, txn, &(round, turn))?;
            } else {
                row.passed = row.passed.checked_sub(1).ok_or_else(corrupt_membership)?;
            }
            row.scanned = row.scanned.checked_sub(1).ok_or_else(corrupt_membership)?;
            MEMBER.delete(&vault.store, txn, &MemberKey::new(scope, turn))?;
        }
        row.members.retain(|turn| !replaced.contains(turn));
        if row.skipped == 0 {
            // As for a fresh all-pass round, no residual all-pass rollup or
            // membership rows are retained after the final skip is rescued.
            for bytes in &row.members {
                let turn = EntityId::from_bytes(*bytes).map_err(|_| corrupt_membership())?;
                MEMBER.delete(&vault.store, txn, &MemberKey::new(scope, turn))?;
            }
            ROUND.delete(&vault.store, txn, &round)?;
        } else {
            ROUND.put(&vault.store, txn, &round, &row)?;
        }
    }
    Ok(())
}
