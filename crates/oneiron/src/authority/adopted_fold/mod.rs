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
//! the tail's: no sequence floor or vouch is read or made for a covered row,
//! and a covered row's only first-seen time is the receipt of this install's
//! own first sight of it, which its adoption keeps for each covered row the
//! stale-roster window reads (FOLDPAST-COVERED-APPROVAL-CLOCK). A zero tail
//! still projects under this install's pin and finishes its heads and
//! sequences over the covered rows.
//!
//! The tail it folds is the resumed fold's: ops that leave every earlier
//! row's fate as it was ([`super::fold_resume::admits_past`]), and an actor
//! revocation or a slip or Grant withdrawal, a federation lifecycle act or a
//! membership execution with every covered row in its causal past, on a
//! clean image this install judges as it was built, whose whole tail then
//! folds, a device revocation so placed, an actor binding or rebinding so
//! placed whether the fold accepts it or not, a re-root so placed as the tail's
//! only handoff, whose whole tail then folds and whose fence closes as in the
//! whole fold, a machine's roster revision or removal so placed, whose whole
//! tail then folds, or a row of a kind that folds past
//! the image only as rejected, with no state (FIX 11760), each on a
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

use super::checkpoint_image::{ReplayEvidence, ReplayPoint, parents_first_of};
use super::fold_resume::{ConfirmKeys, ImageFold, RowMeta};
use super::*;
use crate::error::Result;

mod context;
mod result_parents;
mod settle;

pub(crate) use result_parents::proven_residence_result_parents_in_txn;

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
    /// The tail rows' first-seen seconds, and each covered row's this
    /// install kept a receipt of: its own first sight, at its adoption of the
    /// image for a row it never stored (FOLDPAST-COVERED-APPROVAL-CLOCK).
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
            reason: None,
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
    // the tail's first-seen times, and the receipts of its own first sight
    // of covered rows its adoption kept.
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
    // A covered approval a tail revocation leaves on a revoked key expires
    // at min(its first-seen receipt, revocation first seen) + window + 1, as
    // a device that fetched the whole history at its adoption computes; the
    // receipt is the adoption for a row this install never stored before
    // (FOLDPAST-COVERED-APPROVAL-CLOCK = A, Engine 16 Nov 00:48). Where a
    // receipt is missing (an image adopted before adoption kept them) its
    // window could never start here: only the whole history decides it.
    if !super::stale_roster::stale_roster_clocks_complete(
        &read_whole,
        &fold,
        log.first_seen_at_secs,
    ) {
        return Ok(whole());
    }
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
        issuers,
        uncounted,
        pairs,
        counted_pairs,
        ancestry,
        confirms,
        issues,
        projected,
        fold,
        final_merged: Some(final_merged),
        revoke_facts,
        marks,
        retired_keys,
        closed_handoffs,
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
        issuers,
        uncounted,
        pairs,
        counted_pairs,
        frontier_ancestry,
        revoke_facts,
        retired_keys,
        closed_handoffs,
        unsettled: image.safety.unsettled,
        issues,
        missing_parents,
        marks,
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
        reason: None,
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

/// Whether every tail row folds past the image as a resumed fold's tail row
/// would: each parent on the frontier or in the tail (a covered parent off
/// the frontier is a late fork), an op that leaves every earlier row's fate
/// as it was (a world key record among them, FIX 4881), no row a sequence
/// floor refuses, none signed by a
/// retired key, none a covered row names, and no withdrawal on a frontier
/// row the image holds rejected (only older states could judge it). None for
/// a residence result past an image that dropped its residence bodies for
/// [`super::checkpoint_image::AUTHORITY_RESIDENCE_BODY_OVERFLOW`], as at
/// fold 14 (FIX 11400). Some with the log's confirms once the tail's joined
/// them; None otherwise.
fn tail_folds_past(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
) -> Option<ConfirmKeys> {
    if image.residence_overflow
        && tail
            .values()
            .any(|entry| matches!(entry.op, AuthorityOp::ResidenceResult(_)))
    {
        return None;
    }
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
            // A serial row first: a confirm a covered one spent folds
            // rejected and never joins the log's confirms.
            && (serial_withdrawal(image, tail, log, entry)
                || serial_fold_past(image, tail, log, entry)
                || super::fold_resume::admits_past(&image.aggregate.merged, entry, &mut confirms))
    });
    folds_past.then_some(confirms)
}

/// A withdrawal [`super::fold_resume::admits_past`] leaves to the history
/// that folds past the image all the same (FIX 11760): an actor revocation,
/// a slip withdrawal or a Grant's, under [`folds_serially`]'s conditions. Its tail
/// must then fold whole, and its actor revocations' facts join the image's
/// ([`settle::settle_tail`]).
fn serial_withdrawal(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    entry: &AuthorityLogEntry,
) -> bool {
    settle::serial_withdrawal_op(&entry.op) && folds_serially(image, tail, log, entry)
}

/// Another row [`super::fold_resume::admits_past`] leaves to the history
/// that folds past the image all the same (FIX 11760), under [`folds_serially`]'s
/// conditions: a federation lifecycle act or a membership execution, whose
/// tail must then fold whole, a device revocation
/// ([`settle::serial_roster_revoke_op`]), an actor binding or rebinding
/// ([`settle::serial_binding_op`]), a re-root that is the tail's only one
/// ([`settle::serial_handoff_op`]), whose tail must then fold whole, a
/// machine's roster revision or removal ([`settle::serial_machine_op`]),
/// whose tail must then fold whole, or a
/// row of a kind that folds past only as rejected
/// ([`settle::folds_rejected_op`]), which must then fold with no state. An
/// owner anchor's mark on a machine folds through the anchor's own chain
/// (`anchor_fold`), which this fold does not settle past an image: it still
/// needs the whole history. Two
/// tail re-roots could fence one another, which only the whole history
/// settles. A rotation or a non-agent enrollment stands only in a re-root's
/// pre-handoff line, and only a tail re-root names a tail row in its line,
/// so such a row folds rejected past the image only in a tail with no
/// re-root; for the other kinds that condition is only conservative.
fn serial_fold_past(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    entry: &AuthorityLogEntry,
) -> bool {
    let op = if settle::serial_fold_past_op(&entry.op)
        || settle::serial_roster_revoke_op(&entry.op)
        || settle::serial_binding_op(&entry.op)
    {
        true
    } else if settle::serial_handoff_op(&entry.op) {
        tail.values()
            .filter(|row| settle::serial_handoff_op(&row.op))
            .count()
            == 1
    } else if settle::serial_machine_op(&entry.op) {
        !matches!(entry.signer_key(), AuthorityKey::Ed25519(key)
            if image.aggregate.merged.root_anchors.contains_key(key))
    } else {
        settle::folds_rejected_op(image, entry)
            && !tail
                .values()
                .any(|row| matches!(row.op, AuthorityOp::ReRoot { .. }))
    };
    op && folds_serially(image, tail, log, entry)
}

/// Whether the tail row `entry` folds on the image's states as the whole
/// fold folds it: a clean image this install judges as it was built (its
/// building pin and peer set), with every covered row in the row's causal
/// past. No covered row is concurrent with it, so it changes no covered
/// row's fate, and its parents' states are the whole fold's own.
fn folds_serially(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    entry: &AuthorityLogEntry,
) -> bool {
    image.building_pin == log.pin.copied()
        && image.aggregate.peers == *log.peer_consent_roots
        && clean_image(image)
        && covered_past(image, tail, entry)
}

/// Whether every row `image` covers folded valid, with no issue, missing
/// parent or unsettled handoff: its states are the whole fold's own.
fn clean_image(image: &AuthorityCheckpointV2) -> bool {
    let valid = &image.fold().valid_entries;
    !image.safety.unsettled
        && image.safety.issues.is_empty()
        && image.safety.missing_parents.is_empty()
        && image.covered.iter().all(|hash| valid.contains(hash))
}

/// Whether every row `image` covers is in the causal past of the tail row
/// `entry`: each image frontier row is a parent of it or of a tail row it
/// descends from. Covered rows close over their ancestors and no covered row
/// names a frontier row, so reaching every frontier row reaches them all. A
/// parent neither tail nor covered leaves it unproved.
fn covered_past(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut reached = BTreeSet::new();
    let mut stack = entry.parent_hashes.clone();
    while let Some(at) = stack.pop() {
        if !seen.insert(at) {
            continue;
        }
        if let Some(row) = tail.get(&at) {
            stack.extend(row.parent_hashes.iter().copied());
        } else if image.rows.contains_key(&at) {
            reached.insert(at);
        } else {
            return false;
        }
    }
    image.frontier.iter().all(|leaf| reached.contains(leaf))
}

/// Whether `entry` is a main-log row, no world's side row.
fn is_main(entry: &AuthorityLogEntry) -> bool {
    super::world_privacy::side_world(&entry.op).is_none()
}
