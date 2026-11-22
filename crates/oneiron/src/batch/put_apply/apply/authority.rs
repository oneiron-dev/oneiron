//! First-seen and sequence observation for AUTHORITY_LOG puts, staged in the same transaction.

use super::*;

/// Keep first observation, signer maximum and replay advisory in the same put transaction.
/// Returns whether this put stores the row's hash here for the first time.
/// All three read the envelope only, so a row whose record does not open
/// here takes them too (census L5-22 1a-iii).
pub(super) fn observe_authority_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &crate::EntityId,
    key: &str,
    row: Option<&oneiron_authority::authority::FoldRow>,
    hash: Option<&oneiron_contracts::authority::AuthorityEntryHash>,
    replicated: bool,
    mutation_recorded_at: u64,
) -> Result<bool> {
    let observed_secs = authority_observation_secs_for_write(store, wtxn, mutation_recorded_at)?;
    let sidecar_key = key.to_owned();
    if !crate::authority::AUTHORITY_FIRST_SEEN.contains(store, wtxn, &sidecar_key)? {
        crate::authority::AUTHORITY_FIRST_SEEN.put(store, wtxn, &sidecar_key, &observed_secs)?;
        // The row takes its store-order sequence with its sidecar (FIX 12369).
        crate::authority::store_order::note_first_stored_in_txn(store, wtxn, id)?;
    }
    // H213: the transaction's owner sweeps stale stamps after it commits.
    store.record_hooks.note_authority_row();
    if let (Some(row), Some(hash)) = (row, hash) {
        let first_observation =
            crate::authority::record_authority_sequence_observation_in_txn(store, wtxn, row, hash)?;
        if replicated && first_observation {
            crate::authority::observe_authority_replay_in_txn(
                store,
                wtxn,
                row.signer_key(),
                observed_secs,
            )?;
        }
        return Ok(first_observation);
    }
    Ok(false)
}
