//! The fold on a vault that adopted a checkpoint image (OF-469): see
//! [`fold_adopted_in_txn`].

use super::*;

/// The fold on a vault that adopted `adopted` (OF-469): its stored rows are
/// the covered rows it still holds, never tail and never read again, and the
/// tail past the image, which folds from the image with the tail's own
/// first-seen times and observations alone; no clock is read for a covered
/// row. None where the image cannot answer yet every covered row is held:
/// the stored log then folds whole. Each `arriving` row folds as a stored row
/// first seen now (FIX 2535).
pub(super) fn fold_adopted_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    key: AuthorityCacheKey,
    adopted: &VerifiedAuthorityCheckpoint,
    required: &BTreeSet<AuthorityEntryHash>,
    arriving: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> Result<Option<AuthorityTailFold>> {
    let image = adopted.image();
    // The store id is the row's content hash: a held covered row is known
    // by its id alone.
    let covered_ids: BTreeMap<_, _> = image
        .covered
        .iter()
        .filter_map(|hash| Some((authority_log_entity_id_from_hash(hash).ok()?, *hash)))
        .collect();
    let mut held_covered = BTreeSet::new();
    let mut tail = Vec::new();
    for id in authority_log_ids_in_txn(store, txn)? {
        if let Some(hash) = covered_ids.get(&id) {
            held_covered.insert(*hash);
            continue;
        }
        let entry = decode_authority_log_entry_body(&authority_log_body_in_txn(store, txn, &id)?)?;
        let hash = authority_entry_hash(&entry)?;
        if image.rows.contains_key(&hash) {
            held_covered.insert(hash);
        } else {
            tail.push((hash, entry));
        }
    }
    for (hash, entry) in arriving {
        if image.rows.contains_key(hash) {
            held_covered.insert(*hash);
        } else if !tail.iter().any(|(stored, _)| stored == hash) {
            tail.push((*hash, entry.clone()));
        }
    }
    let backfilled = AUTHORITY_FIRST_SEEN_BACKFILLED.contains(
        store,
        txn,
        &authority_first_seen_backfill_key(),
    )?;
    let mut first_seen_at_secs = BTreeMap::new();
    for (hash, _) in &tail {
        let first_seen = if arriving.contains_key(hash) {
            key.now_secs
        } else {
            readonly_first_seen_for(store, txn, hash, backfilled, key.now_secs)?
        };
        first_seen_at_secs.insert(*hash, first_seen);
    }
    let rows: Vec<_> = tail
        .iter()
        .map(|(hash, entry)| crate::authority::fold_resume::RowMeta::of(Some(*hash), entry))
        .collect();
    let observations =
        crate::authority::sequence_observation::authority_local_observations_of_rows_in_txn(
            store, txn, &rows,
        )?;
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    let folded = crate::authority::adopted_fold::fold_adopted_checkpoint_tail(
        adopted,
        crate::authority::adopted_fold::AdoptedTail {
            tail: &tail,
            held_covered: &held_covered,
            required,
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: key.now_secs,
            peer_consent_roots: &peer_consent_roots,
            observations: &observations,
            posture,
            pin: key.pin.as_ref(),
            keep_replay: false,
        },
    )?;
    Ok(match folded {
        crate::authority::adopted_fold::AdoptedTailFold::Complete {
            fold,
            next_deadline_secs,
        } => {
            tracing::trace!(target: "oneiron::authority::cache", generation = key.generation, rows = tail.len(), "authority fold past the adopted checkpoint");
            Some(AuthorityTailFold::Complete {
                view: AuthorityView {
                    fold: Arc::new(fold),
                    generation: key.generation,
                },
                next_deadline_secs,
                continuation: None,
            })
        }
        crate::authority::adopted_fold::AdoptedTailFold::NeedHistory(request)
            if request.missing.is_empty() =>
        {
            None
        }
        crate::authority::adopted_fold::AdoptedTailFold::NeedHistory(request) => {
            Some(AuthorityTailFold::NeedHistory(request))
        }
    })
}

/// What the fold on a vault that adopted a checkpoint image needs and this
/// vault does not hold (OF-469), through the fold's own preflight, so a
/// delivery fetches exactly what the fold asks for: nothing when the fold
/// answers. A hash the image covers is never left out for being attested
/// when the fold needs its row. None on a vault with no adoption, and where
/// every covered row is held: the stored log's own request stands there.
pub(in crate::authority) fn adopted_history_request_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    required: &BTreeSet<AuthorityEntryHash>,
) -> Result<Option<AuthorityHistoryRequest>> {
    let Some(adopted) =
        crate::authority::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?
    else {
        return Ok(None);
    };
    let key = authority_cache_key(store, posture, txn)?;
    Ok(
        match fold_adopted_in_txn(
            store,
            posture,
            txn,
            key,
            &adopted,
            required,
            &BTreeMap::new(),
        )? {
            Some(AuthorityTailFold::NeedHistory(request)) => Some(request),
            Some(AuthorityTailFold::Complete { .. }) => Some(AuthorityHistoryRequest {
                vault_id: Some(adopted.image().vault_id),
                checkpoint: Some(adopted.id()),
                missing: BTreeSet::new(),
            }),
            None => None,
        },
    )
}
