use super::*;

/// Keep first observation, signer maximum and replay advisory in the same put transaction.
/// Returns whether this put stores the row's hash here for the first time.
pub(super) fn observe_authority_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    key: &str,
    entry: Option<&crate::authority::AuthorityLogEntry>,
    hash: Option<&crate::authority::AuthorityEntryHash>,
    replicated: bool,
    mutation_recorded_at: u64,
) -> Result<bool> {
    let observed_secs = authority_observation_secs_for_write(store, wtxn, mutation_recorded_at)?;
    let sidecar_key = key.to_owned();
    if !crate::authority::AUTHORITY_FIRST_SEEN.contains(store, wtxn, &sidecar_key)? {
        crate::authority::AUTHORITY_FIRST_SEEN.put(store, wtxn, &sidecar_key, &observed_secs)?;
    }
    // H213: the transaction's owner sweeps stale stamps after it commits.
    crate::federation::note_authority_row();
    if let (Some(entry), Some(hash)) = (entry, hash) {
        let first_observation = crate::authority::record_authority_sequence_observation_in_txn(
            store, wtxn, entry, hash,
        )?;
        if replicated && first_observation {
            crate::authority::observe_authority_replay_in_txn(
                store,
                wtxn,
                &entry.signer.public_key,
                observed_secs,
            )?;
        }
        return Ok(first_observation);
    }
    Ok(false)
}
