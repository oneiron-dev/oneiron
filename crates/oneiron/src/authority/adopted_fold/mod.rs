//! The authority fold past an adopted checkpoint image (OF-469, slice C;
//! identity.md, "Resumable checkpoints and cold authority history"). The
//! image stands in for the history it covers: only the stored rows past it
//! fold here, each on the image's frontier states.
//!
//! The scheduler takes the image's frontier states as seeds, and every tail
//! row still passes its own transition's checks. The fold starts from the
//! image's merged state and safety indexes, merges the tail's states, and
//! projects through the image-backed row reads a resumed fold uses
//! ([`super::fold_resume::Resumed`]). This install's own observations are
//! the tail's alone: no first-seen time, sequence floor or vouch is read or
//! made for a covered row. A zero tail still projects under this install's
//! pin and finishes its heads and sequences over the covered rows.
//!
//! The tail it folds is the resumed fold's: ops that leave every earlier
//! row's fate as it was ([`super::fold_resume::admits_past`]), each on a
//! frontier, tail or covered parent, a world key record on stated parents
//! alone (FIX 4881). A late fork, a tail row on a covered row off the
//! frontier, folds on the state the image's replay evidence keeps there
//! (FIX 3007, [`super::checkpoint_image::ReplayEvidence`]); another pin or
//! peer set than the image's is judged again where it reaches a covered row
//! ([`context`], FIX 3004, 3005). Anything else needs history, never a fold
//! of the rows held: a late fork the image keeps no state for, an op outside
//! that set, another posture, a covered row another pin or peer set moves,
//! or a guard a resumed fold declines at. That request names every covered
//! row not held here, since only the whole history folds past such a row
//! (CALLS "FIX 3007 history closure"); a parent neither covered nor held is
//! named alone.
//!
//! A later image on the adopting vault folds the same tail the same way, with
//! no clock and no install view, and keeps the fold at the new frontier
//! image-grade ([`capture_adopted_checkpoint_tail`], OF-469 slice D).

use std::collections::{BTreeMap, BTreeSet};

use super::checkpoint_image::{ReplayEvidence, parents_first_of};
use super::fold_resume::{ConfirmKeys, ImageFold, RowMeta};
use super::*;
use crate::error::Result;

mod context;
mod settle;

use context::image_stands_here;
use settle::{SettledTail, settle_tail};

/// The fold past an adopted image.
pub(super) enum AdoptedTailFold {
    /// The fold as this install reads it, and the next second it changes on
    /// its own.
    Complete {
        fold: AuthorityFold,
        next_deadline_secs: Option<u64>,
    },
    /// History the fold needs: no fold answers. A request naming nothing
    /// means every covered row is held here: the stored log folds whole.
    NeedHistory(AuthorityHistoryRequest),
}

/// The stored rows past an adopted image, and what this install folds them
/// under.
#[derive(Clone, Copy)]
pub(super) struct AdoptedTail<'a> {
    /// Each stored row the image does not cover, with its hash.
    pub(super) tail: &'a [(AuthorityEntryHash, AuthorityLogEntry)],
    /// The covered rows still stored here: held, never tail.
    pub(super) held_covered: &'a BTreeSet<AuthorityEntryHash>,
    /// Hashes a caller names as needed: the fold past the image needs them
    /// held or kept, and the image-grade capture keeps each one's state
    /// beside the new frontier's (a seal's causal point, FIX 4649).
    pub(super) required: &'a BTreeSet<AuthorityEntryHash>,
    /// The tail rows' first-seen seconds, and no covered row's.
    pub(super) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(super) now_secs: u64,
    pub(super) peer_consent_roots: &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// The tail rows' observations, and no covered row's.
    pub(super) observations: &'a AuthorityLocalObservations,
    pub(super) posture: crate::HostingPrivacyPosture,
    pub(super) pin: Option<&'a PinnedRoot>,
    /// Whether an image-grade capture keeps the replay evidence of the rows
    /// it covers past the new frontier (FIX 3007): a later image's build
    /// does, an act's causal points never read it.
    pub(super) keep_replay: bool,
}

/// The fold of `log`'s tail past the adopted image, or the history it needs.
/// A carried body that does not decode is corruption: the image verified.
pub(super) fn fold_adopted_checkpoint_tail(
    adopted: &VerifiedAuthorityCheckpoint,
    log: AdoptedTail<'_>,
) -> Result<AdoptedTailFold> {
    let image = adopted.image();
    let need = |missing: BTreeSet<AuthorityEntryHash>| {
        AdoptedTailFold::NeedHistory(AuthorityHistoryRequest {
            vault_id: Some(image.vault_id),
            checkpoint: Some(adopted.id()),
            missing,
        })
    };
    let tail: BTreeMap<_, _> = log
        .tail
        .iter()
        .map(|(hash, entry)| (*hash, entry))
        .collect();
    // What a fetch of the rows themselves closes: a parent neither covered
    // nor held, and a named hash neither held nor a kept frontier state.
    let gaps: BTreeSet<_> = tail
        .values()
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter(|parent| !image.rows.contains_key(*parent))
        .chain(
            log.required
                .iter()
                .filter(|hash| !log.held_covered.contains(*hash))
                .filter(|hash| !image.keeps_state(hash)),
        )
        .filter(|hash| !tail.contains_key(*hash))
        .copied()
        .collect();
    // What only the whole history closes: every covered row not held here.
    let whole = || AdoptedTailFold::NeedHistory(whole_history(adopted, &gaps, log.held_covered));
    let confirms = if image_stands_here(image, log) {
        tail_folds_past(image, &tail, log)
    } else {
        None
    };
    let Some(confirms) = confirms else {
        return Ok(whole());
    };
    if !gaps.is_empty() {
        return Ok(need(gaps.clone()));
    }
    let Some(settled) = settle_tail(image, &tail, log, confirms)? else {
        return Ok(whole());
    };
    let SettledTail {
        projected, fold, ..
    } = settled;
    // This install's own view, over the rows its stale-roster window reads:
    // the tail's first-seen times are the only ones it has.
    let window_secs = log.observations.policy.stale_roster_window_secs;
    let read_whole: Vec<&AuthorityLogEntry> = projected
        .values()
        .chain(
            tail.iter()
                .filter(|(hash, _)| !projected.contains_key(*hash))
                .map(|(_, entry)| *entry),
        )
        .filter(|entry| super::fold_resume::is_projected(&entry.op))
        .collect();
    let mut view = super::install_fold::install_view(
        &read_whole,
        fold,
        log.first_seen_at_secs,
        Some(log.now_secs),
        window_secs,
        log.pin,
    );
    if view.rests_on_counting() && !super::install_fold::stale_chains(&view).is_empty() {
        return Ok(whole());
    }
    let mut metas: BTreeMap<_, _> = image
        .rows
        .iter()
        .map(|(hash, row)| {
            let meta = RowMeta {
                hash: Some(*hash),
                signer: &row.signer,
                seq: row.seq,
                parents: &row.parents,
                world: row.world,
            };
            (*hash, meta)
        })
        .collect();
    for (hash, entry) in &tail {
        metas
            .entry(*hash)
            .or_insert_with(|| RowMeta::of(Some(*hash), entry));
    }
    let metas: Vec<_> = metas.into_values().collect();
    super::install_fold::finish_install_fold_of(&metas, &mut view);
    let next_deadline_secs = super::stale_roster::next_stale_roster_deadline(
        &read_whole,
        &view,
        log.first_seen_at_secs,
        log.now_secs,
        window_secs,
    )
    .into_iter()
    .chain(view.install.no_vouch_deadline)
    .min();
    Ok(AdoptedTailFold::Complete {
        fold: view,
        next_deadline_secs,
    })
}

/// What a later image built past the adopted one keeps of the tail's fold
/// (OF-469, slice D): see [`capture_adopted_checkpoint_tail`].
pub(super) enum AdoptedImageFold {
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
pub(super) fn capture_adopted_checkpoint_tail(
    adopted: &VerifiedAuthorityCheckpoint,
    log: AdoptedTail<'_>,
) -> Result<AdoptedImageFold> {
    let image = adopted.image();
    let tail: BTreeMap<_, _> = log
        .tail
        .iter()
        .map(|(hash, entry)| (*hash, entry))
        .collect();
    let gaps: BTreeSet<_> = tail
        .values()
        .flat_map(|entry| entry.parent_hashes.iter())
        .filter(|parent| !image.rows.contains_key(*parent) && !tail.contains_key(*parent))
        .copied()
        .collect();
    let whole = || AdoptedImageFold::NeedHistory(whole_history(adopted, &gaps, log.held_covered));
    if !gaps.is_empty() {
        return Ok(whole());
    }
    let confirms = if image_stands_here(image, log) {
        tail_folds_past(image, &tail, log)
    } else {
        None
    };
    let Some(confirms) = confirms else {
        return Ok(whole());
    };
    let Some(SettledTail {
        judged,
        states,
        merged,
        writers,
        uncounted,
        pairs,
        counted_pairs,
        ancestry,
        confirms,
        issues,
        projected,
        fold,
        final_merged: Some(final_merged),
    }) = settle_tail(image, &tail, log, confirms)?
    else {
        return Ok(whole());
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
        issuers: image.safety.issuers.clone(),
        uncounted,
        pairs,
        counted_pairs,
        frontier_ancestry,
        revoke_facts: image.safety.revoke_facts.clone(),
        retired_keys: image.safety.retired_keys.clone(),
        closed_handoffs: image.safety.closed_handoffs.clone(),
        unsettled: image.safety.unsettled,
        issues,
        missing_parents,
        marks: image.safety.marks.clone(),
        revocations: final_merged.actor_revocation_hashes,
        writers,
        bound_keys,
        confirm_ids: confirms.0,
        confirm_nonces: confirms.1,
        nonce_provenance: merged.critical_write_confirm_nonce_provenance.clone(),
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

/// What a fold past an image asks for where it cannot tell which covered
/// rows a tail row depends on (CALLS "FIX 3007 history closure"): every
/// covered row not held here. No narrower closure is claimed until a fold
/// can refold one from held rows and kept states.
const AUTHORITY_HISTORY_UNKNOWN_DEPENDENCIES: UnknownDependencies =
    UnknownDependencies::WholeHistory;

/// The policy hook behind [`AUTHORITY_HISTORY_UNKNOWN_DEPENDENCIES`].
#[derive(Clone, Copy)]
enum UnknownDependencies {
    /// Every covered row not held here.
    WholeHistory,
}

/// The request only the whole history closes: `gaps`, and every covered row
/// not held here, since only the whole history folds past such a row.
fn whole_history(
    adopted: &VerifiedAuthorityCheckpoint,
    gaps: &BTreeSet<AuthorityEntryHash>,
    held_covered: &BTreeSet<AuthorityEntryHash>,
) -> AuthorityHistoryRequest {
    match AUTHORITY_HISTORY_UNKNOWN_DEPENDENCIES {
        UnknownDependencies::WholeHistory => {}
    }
    let image = adopted.image();
    let mut missing = gaps.clone();
    missing.extend(
        image
            .covered
            .iter()
            .filter(|hash| !held_covered.contains(*hash)),
    );
    AuthorityHistoryRequest {
        vault_id: Some(image.vault_id),
        checkpoint: Some(adopted.id()),
        missing,
    }
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

/// Whether every tail row folds past the image as a resumed fold's tail row
/// would: each parent on the frontier or in the tail (a covered parent off
/// the frontier is a late fork), an op that leaves every earlier row's fate
/// as it was (a world key record among them, FIX 4881), no row a sequence
/// floor refuses, none signed by a
/// retired key, none a covered row names, and no withdrawal on a frontier
/// row the image holds rejected (only older states could judge it). Some
/// with the log's confirms once the tail's joined them; None otherwise.
fn tail_folds_past(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
) -> Option<ConfirmKeys> {
    let mut confirms = (
        image.safety.confirm_ids.clone(),
        image.safety.confirm_nonces.clone(),
    );
    let folds_past = tail.iter().all(|(hash, entry)| {
        // A covered parent off the frontier folds on its replay state (FIX
        // 3007) where the image keeps one a late fork may seed from.
        let parents_stand = entry.parent_hashes.iter().all(|parent| {
            if !image.rows.contains_key(parent) {
                return true;
            }
            if image.holds_rejected(parent) {
                return !super::revoke_proof::restrictive_withdrawal(&entry.op);
            }
            image.per_parent.contains_key(parent)
                || (image.keeps_state(parent) && context::seeds_late_fork(image, parent))
        });
        let retired = std::iter::once(&entry.signer)
            .chain(&entry.cosigns)
            .any(|signature| image.safety.retired_keys.contains(&signature.public_key));
        parents_stand
            && !retired
            && !image.safety.missing_parents.contains(hash)
            && log
                .observations
                .sequence_floors
                .get(hash)
                .is_none_or(|floor| entry.seq >= *floor)
            && super::fold_resume::admits_past(&image.aggregate.merged, entry, &mut confirms)
    });
    folds_past.then_some(confirms)
}

/// Whether `entry` is a main-log row, no world's side row.
fn is_main(entry: &AuthorityLogEntry) -> bool {
    super::world_privacy::side_world(&entry.op).is_none()
}
