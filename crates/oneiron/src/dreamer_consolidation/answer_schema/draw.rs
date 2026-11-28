//! The answer-schema check's nightly draw (HOUSE-SCHEMA-CHECK): up to eight of the night's
//! captured TURN calls, stably ranked, every source still reading.

use super::capture::{CapturedTurnCall, captures_of_in_txn};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedRead as ClaimRead;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use oneiron_contracts::fingerprint::ContentHash;

/// How many captures one night draws at most.
pub(crate) const DRAW_TAKE: usize = 8;

/// The night's drawable captures: its descendants' captures whose every source row still
/// reads live, each with its key. A source with no live bytes (erased, or never there)
/// drops its capture; withdrawn rows read no live bytes either.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn draw_pool_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ClaimRead<'_>,
    descendants: &[AttemptId],
) -> Result<Vec<((AttemptId, [u8; 32]), CapturedTurnCall)>> {
    let mut pool = Vec::new();
    for descendant in descendants {
        for (key, capture) in captures_of_in_txn(&vault.store, txn, *descendant)? {
            if sources_read_in_txn(read, txn, &capture.sources)? {
                pool.push((key, capture));
            }
        }
    }
    Ok(pool)
}

/// Whether every row of `sources` still reads live.
///
/// # Errors
///
/// Storage faults.
fn sources_read_in_txn(
    read: &ClaimRead<'_>,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> Result<bool> {
    for source in sources {
        if read.entity_raw_live_in(txn, source)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One capture's rank hash under a night: the content hash (plain BLAKE3) of
/// `id16(night) || capture key`.
pub(crate) fn rank_key(night: AttemptId, key: &(AttemptId, [u8; 32])) -> [u8; 32] {
    let mut keyed = Vec::with_capacity(16 + 48);
    keyed.extend_from_slice(night.as_bytes());
    key.encode_into(&mut keyed);
    ContentHash::of(&keyed).into_bytes()
}

/// Ranks the pool by [`rank_key`] ascending and takes the first eight: the night's stable
/// selection. Returns each taken key with its rank hash, in draw order.
pub(crate) fn select(
    night: AttemptId,
    pool: &[((AttemptId, [u8; 32]), CapturedTurnCall)],
) -> Vec<((AttemptId, [u8; 32]), [u8; 32])> {
    let mut ranked: Vec<(_, [u8; 32])> = pool
        .iter()
        .map(|(key, _)| (*key, rank_key(night, key)))
        .collect();
    ranked.sort_by_key(|(_, rank)| *rank);
    ranked.truncate(DRAW_TAKE);
    ranked
}

/// The night's draw for `test_doors::dreamer_answer_schema`: the pool's stable selection,
/// read as the vault's Dreamer authority.
///
/// # Errors
///
/// Storage faults.
#[cfg(oneiron_test_support)]
pub(crate) fn draw_for_test(vault: &Vault, night: AttemptId) -> Result<Vec<(AttemptId, [u8; 32])>> {
    let read = super::super::nightly_merge::merge_read(vault, vault.dreamer_authority()?)?;
    let txn = vault.store.env.read_txn()?;
    let descendants = super::check::descendants_in_txn(vault, &txn, night, false)?;
    let pool = draw_pool_in_txn(vault, &txn, &read, &descendants)?;
    Ok(select(night, &pool)
        .into_iter()
        .map(|(key, _)| key)
        .collect())
}

/// One pair's seed: the first eight bytes of its rank hash, big-endian, as `u64`.
pub(crate) fn pair_seed(rank: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        rank[0], rank[1], rank[2], rank[3], rank[4], rank[5], rank[6], rank[7],
    ])
}
