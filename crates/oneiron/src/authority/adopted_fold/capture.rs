//! The image-grade capture of the tail past an adopted image (OF-469,
//! slice D), [`capture_adopted_checkpoint_tail`], and the successor image's
//! replay evidence, [`successor_replay`].

use super::super::checkpoint_image::{ReplayEvidence, ReplayPoint, parents_first_of};
use super::super::fold_resume::ImageFold;
use super::tail_gaps::parent_gaps;
use super::*;

/// What a later image built past the adopted one keeps of the tail's fold
/// (OF-469, slice D): see [`capture_adopted_checkpoint_tail`].
pub(in crate::authority) enum AdoptedImageFold {
    /// The fold at the new frontier, image-grade, and the covered approvals
    /// the stale-roster window could still expire.
    Captured {
        fold: Box<ImageFold>,
        stale_approvals: BTreeSet<AuthorityEntryHash>,
    },
    /// History the build needs, as [`AdoptedTailFold::NeedHistory`] names
    /// it: a request naming nothing means every covered row is held here,
    /// and the stored log builds the image whole.
    NeedHistory(AuthorityHistoryRequest),
}

/// The image-grade fold of `log`'s tail past the adopted image, with no
/// clock (OF-469, slice D). The tail folds on the image's frontier states
/// exactly as [`fold_adopted_checkpoint_tail`] folds it, under the same
/// guards, and the capture keeps what a fold past the new image reads: the
/// state at each row of the new frontier (an untouched old frontier row keeps
/// the image's), the merged state, the projected once fold before any
/// install's stale window, and the safety indexes grown by the tail. The
/// caller hands the ancestor-closed tail alone (a row above a gap stays
/// unresolved) and no first-seen time: no install view is built.
pub(in crate::authority) fn capture_adopted_checkpoint_tail(
    adopted: &VerifiedAuthorityCheckpoint,
    log: AdoptedTail<'_>,
) -> Result<AdoptedImageFold> {
    let image = adopted.image();
    let tail: BTreeMap<_, _> = log
        .tail
        .iter()
        .map(|(hash, entry)| (*hash, entry))
        .collect();
    debug_assert!(
        log.believed.is_none(),
        "an image-grade capture counts every tail row it is handed"
    );
    let gaps = parent_gaps(image, &tail);
    let whole = |reason| {
        AdoptedImageFold::NeedHistory(whole_history(
            adopted,
            &gaps,
            log.held_covered,
            Some(reason),
        ))
    };
    if !gaps.is_empty() {
        return Ok(whole(AuthorityHistoryReason::UnheldRows));
    }
    let floors = if image_stands_here(image, log) {
        tail_folds_past(image, &tail, log)
    } else {
        Err(AuthorityHistoryReason::ImageContextMoved)
    };
    let floors = match floors {
        Ok(floors) => floors,
        Err(reason) => return Ok(whole(reason)),
    };
    let settled = match settle_tail(image, &tail, log, floors)? {
        Ok(settled) => settled,
        Err(reason) => return Ok(whole(reason)),
    };
    // The settlement projects over its own merge, which the projection
    // returns as the final one: it is never absent, and this refusal names
    // no reason.
    let SettledTail {
        judged,
        states,
        merged,
        writers,
        issuers,
        uncounted,
        pairs,
        counted_pairs,
        ancestry,
        issues,
        projected,
        fold,
        final_merged: Some(final_merged),
        revoke_facts,
        marks,
        retired_keys,
        handoff_or_appointment_retired_keys,
        closed_handoffs,
        // The whole build keeps the once fold before any cap of a fold with
        // no vouch.
        no_vouch: _,
    } = settled
    else {
        return Ok(AdoptedImageFold::NeedHistory(whole_history(
            adopted,
            &gaps,
            log.held_covered,
            None,
        )));
    };
    // The new frontier: each old frontier row and tail row no tail row
    // names. No covered row names a tail row.
    let named: BTreeSet<_> = tail
        .values()
        .flat_map(|entry| entry.parent_hashes.iter().copied())
        .collect();
    let frontier: BTreeSet<_> = image
        .frontier
        .iter()
        .chain(tail.keys())
        .filter(|hash| !named.contains(*hash))
        .copied()
        .collect();
    let per_parent = frontier
        .iter()
        .chain(log.required)
        .map(|hash| {
            let state = if tail.contains_key(hash) {
                states.get(hash).cloned()
            } else {
                image.state_at(hash).flatten()
            };
            (*hash, state)
        })
        .collect();
    let replay = if log.keep_replay {
        successor_replay(image, &tail, &states, &frontier)
    } else {
        ReplayEvidence::FrontierOnly
    };
    let frontier_ancestry = frontier
        .iter()
        .filter_map(|hash| Some((*hash, *ancestry.get(hash)?)))
        .collect();
    let mut missing_parents = image.safety.missing_parents.clone();
    missing_parents.extend(
        judged
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .filter(|parent| !judged.contains_key(*parent) && !image.rows.contains_key(*parent))
            .copied(),
    );
    let mut bound_keys = image.safety.bound_keys.clone();
    for (hash, state) in &states {
        if judged.get(hash).is_some_and(is_main) {
            super::fold_resume::add_bound_keys(&mut bound_keys, state);
        }
    }
    // The confirms a whole build keeps (`fold_resume::ImageFold`): the
    // image's, and each tail confirm that folds to a state. The admission
    // join of `tail_folds_past` also holds a confirm the fold then rejects
    // (its signer revoked or out of its ancestry), which spends no id or
    // nonce in the whole fold (row ADOPTED-TAIL-INVALID-CONFIRM-JOINS-SUCCESSOR).
    let mut confirm_ids = image.safety.confirm_ids.clone();
    let mut confirm_nonces = image.safety.confirm_nonces.clone();
    let folded_confirms = judged
        .iter()
        .filter(|(hash, _)| states.contains_key(*hash))
        .filter_map(|(_, entry)| match &entry.op {
            AuthorityOp::FederationConfirm(action) => Some(action),
            _ => None,
        });
    for action in folded_confirms {
        confirm_ids.insert(action.confirm_id);
        confirm_nonces.insert(action.nonce);
    }
    // The approvals a covered revocation could expire on a reader's own
    // clock: the stale-roster window reads only rows carried whole.
    let read_whole: Vec<&AuthorityLogEntry> = projected
        .values()
        .chain(
            judged
                .iter()
                .filter(|(hash, _)| !projected.contains_key(*hash))
                .map(|(_, entry)| entry),
        )
        .collect();
    let stale_approvals = super::stale_roster::stale_roster_subject_approvals(&read_whole, &fold);
    let safety = super::checkpoint_image::CheckpointSafety {
        issuers,
        uncounted,
        pairs,
        counted_pairs,
        frontier_ancestry,
        revoke_facts,
        retired_keys,
        handoff_or_appointment_retired_keys,
        closed_handoffs,
        crossed_revocations: image.safety.crossed_revocations.clone(),
        unsettled: image.safety.unsettled,
        issues,
        missing_parents,
        marks,
        revocations: crate::authority::fold_state::to_btree_set_map(
            &final_merged.actor_revocation_hashes,
        ),
        writers,
        bound_keys,
        confirm_ids,
        confirm_nonces,
        nonce_provenance: crate::authority::fold_state::to_btree_set_map(
            &merged.critical_write_confirm_nonce_provenance,
        ),
    };
    Ok(AdoptedImageFold::Captured {
        fold: Box::new(ImageFold {
            per_parent,
            replay,
            merged,
            fold,
            safety,
        }),
        stale_approvals,
    })
}

/// The replay evidence of an image built past `image` over `tail`, whose
/// new frontier is `frontier` (FIX 3007): the state at every row the new
/// image covers off that frontier, from the old image's replay points and
/// frontier states and the tail's settled states, encoded afresh over the
/// whole coverage as a fresh build encodes it, so a root's rebuild of the
/// same rows compares equal byte for byte. Kept encodings are never
/// spliced. None past an image that keeps none, or whose evidence does not
/// decode.
fn successor_replay(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    frontier: &BTreeSet<AuthorityEntryHash>,
) -> ReplayEvidence {
    let ReplayEvidence::Rows(kept) = &image.replay else {
        return ReplayEvidence::FrontierOnly;
    };
    let mut parents = BTreeMap::new();
    let mut settled = BTreeMap::new();
    for hash in kept.keys().chain(image.per_parent.keys()) {
        if frontier.contains(hash) {
            continue;
        }
        let (Some(row), Some(state)) = (image.rows.get(hash), image.state_at(hash)) else {
            return super::checkpoint_image::AUTHORITY_REPLAY_OVERFLOW;
        };
        parents.insert(*hash, row.parents.clone());
        if let Some(state) = state {
            settled.insert(*hash, state);
        }
    }
    for (hash, entry) in tail {
        if frontier.contains(hash) {
            continue;
        }
        parents.insert(*hash, entry.parent_hashes.clone());
        if let Some(state) = states.get(hash) {
            settled.insert(*hash, state.clone());
        }
    }
    if kept.len() < image.covered.len() - image.per_parent.len() {
        // No dropped base may change a retained point's encoding. The common
        // image compactor selects the full-state suffix after normalization,
        // using all covered row parents, including the older missing cut.
        return ReplayEvidence::Rows(
            parents
                .keys()
                .map(|hash| {
                    let point = settled.remove(hash).map_or(ReplayPoint::Rejected, |state| {
                        ReplayPoint::Full(Box::new(state))
                    });
                    (*hash, point)
                })
                .collect(),
        );
    }
    ReplayEvidence::points_of(
        &parents_first_of(&parents),
        &|hash| parents.get(hash).cloned(),
        &|hash| settled.get(hash).cloned(),
        &BTreeMap::new(),
    )
    .map_or(
        super::checkpoint_image::AUTHORITY_REPLAY_OVERFLOW,
        ReplayEvidence::Rows,
    )
}
