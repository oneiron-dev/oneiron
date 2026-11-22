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
//! or a guard a resumed fold declines at. A tail row that floors covered
//! rows folds past them where each is of an op a floor never refuses and
//! records the whole fold's forks ([`covered_floors`], FIX
//! [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]). That request names every covered
//! row not held here, since only the whole history folds past such a row
//! (CALLS "FIX 3007 history closure"); a parent neither covered nor held is
//! named alone where a row this install believes rests on it. A gap only rows
//! it does not believe reach refuses nothing: the rows above it fold as
//! invalid, as the stored log's fold holds them, and the whole request still
//! names it (FIX [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]). The request says
//! why ([`AuthorityHistoryReason`]): the first refusing row in hash order, and
//! its first failing check in the order the fold makes them, so a retirement
//! door can tell a fetch that closes it from one that closes it only while the
//! covered rows are held somewhere.
//!
//! A later image on the adopting vault folds the same tail the same way, with
//! no clock and no install view, and keeps the fold at the new frontier
//! image-grade ([`capture_adopted_checkpoint_tail`], OF-469 slice D).

use std::collections::{BTreeMap, BTreeSet};

use super::fold_resume::RowMeta;
use super::*;
use crate::error::Result;
use oneiron_contracts::authority::AuthorityHistoryReason;

mod capture;
mod context;
mod covered_floors;
mod result_parents;
mod settle;
mod tail_gaps;

pub(super) use capture::{AdoptedImageFold, capture_adopted_checkpoint_tail};
pub(crate) use result_parents::proven_residence_result_parents_in_txn;

use context::image_stands_here;
use covered_floors::{CoveredFloors, NoVouchPast};
use settle::{SettledTail, settle_tail};
use tail_gaps::{keep_dropped_verdicts, refusing_gaps};

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
    /// The tail rows this install believes (`AuthorityStructure::believes`):
    /// the live fold refuses only for the gaps these rows rest on, and holds
    /// the rows above any other gap invalid. None: every tail row counts, as
    /// an image-grade capture reads them (it stays free of install facts).
    pub(super) believed: Option<&'a BTreeSet<AuthorityEntryHash>>,
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
            reason: Some(AuthorityHistoryReason::UnheldRows),
        })
    };
    let tail: BTreeMap<_, _> = log
        .tail
        .iter()
        .map(|(hash, entry)| (*hash, entry))
        .collect();
    // What a fetch of the rows themselves closes: a parent neither covered
    // nor held, and a named hash neither held nor a kept frontier state.
    let required_gaps: Vec<_> = log
        .required
        .iter()
        .filter(|hash| !log.held_covered.contains(*hash))
        .filter(|hash| !image.keeps_state(hash))
        .filter(|hash| !tail.contains_key(*hash))
        .copied()
        .collect();
    // Only the gaps the believed rows rest on refuse the fold; the tail rows
    // above any other gap drop out of what it settles ([`refusing_gaps`]).
    let (gaps, tail, dropped) = refusing_gaps(image, tail, log.believed, required_gaps);
    // What only the whole history closes: every covered row not held here,
    // for the reason the fold past the image refuses.
    let whole = |reason| {
        AdoptedTailFold::NeedHistory(whole_history(
            adopted,
            &gaps,
            log.held_covered,
            Some(reason),
        ))
    };
    let floors = if image_stands_here(image, log) {
        tail_folds_past(image, &tail, log)
    } else {
        Err(AuthorityHistoryReason::ImageContextMoved)
    };
    let floors = match floors {
        Ok(floors) => floors,
        Err(reason) => return Ok(whole(reason)),
    };
    if !gaps.is_empty() {
        return Ok(need(gaps.clone()));
    }
    let settled = match settle_tail(image, &tail, log, floors)? {
        Ok(settled) => settled,
        Err(reason) => return Ok(whole(reason)),
    };
    let SettledTail {
        projected,
        mut fold,
        no_vouch,
        issues,
        ..
    } = settled;
    keep_dropped_verdicts(&mut fold, issues.len(), &dropped, &tail, image);
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
        return Ok(whole(AuthorityHistoryReason::StaleRosterWindow));
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
        return Ok(whole(AuthorityHistoryReason::StaleRosterWindow));
    }
    // An image that dropped its residence bodies cannot show the keys a
    // covered forked directive rests on (row SEQ-FLOOR-S-WITHHELD-COSIGN).
    if context::dropped_body_fork_may_expire(image, &view) {
        return Ok(whole(AuthorityHistoryReason::ResidenceBodiesDropped));
    }
    // The whole install fold's fold with no vouch folds as this one does
    // here, so its cap is the cap of this fold by itself (`NoVouchPast`).
    if no_vouch == NoVouchPast::Identical {
        super::install_fold::cap_by_identical_no_vouch_fold(&mut view);
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
/// not held here, since only the whole history folds past such a row, for
/// `reason`, why the fold past the image refuses. A reader whose tail holds
/// a row that does not open here asks it with no gaps (census L5-22 1a-iii).
pub(in crate::authority) fn whole_history(
    adopted: &VerifiedAuthorityCheckpoint,
    gaps: &BTreeSet<AuthorityEntryHash>,
    held_covered: &BTreeSet<AuthorityEntryHash>,
    reason: Option<AuthorityHistoryReason>,
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
        reason,
    }
}

/// Whether every tail row folds past the image as a resumed fold's tail row
/// would: each parent on the frontier or in the tail (a covered parent off
/// the frontier is a late fork), an op that leaves every earlier row's fate
/// as it was (a world key record among them, FIX 4881), no row past a floor
/// and no covered row of a tail row's signer past one
/// ([`tail_signers_covered_rows_unfloored`]), a covered floor moved only on
/// rows of an op a floor never refuses with no row to vouch it away
/// ([`rows_floors_unmoved`], [`covered_floors::floored_covered_rows`], FIX
/// [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]), none signed by a retired key, none
/// a covered row names, and no withdrawal on a frontier
/// row the image holds rejected (only older states could judge it). None for
/// a residence result past an image that dropped its residence bodies for
/// [`super::checkpoint_image::AUTHORITY_RESIDENCE_BODY_OVERFLOW`], as at
/// fold 14 (FIX 11400). Ok with the covered rows the tail floors; otherwise
/// why the first tail row in hash order that does not fold past refuses: the
/// first condition it fails, in the order checked here. The confirms each
/// row's admission joins only admit the next ones: a confirm that then folds
/// rejected spends nothing in the whole fold ([`settle_tail`]).
fn tail_folds_past(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
) -> std::result::Result<CoveredFloors, AuthorityHistoryReason> {
    // A root appointment is counted over its whole ancestry, and one arriving
    // can burn its anchor and un-count an appointment the image counted
    // (OWNER-ANCHOR-ROOT-RECOVERY): the whole history folds it.
    if tail
        .values()
        .any(|entry| matches!(entry.op, AuthorityOp::RootAppointment(_)))
    {
        return Err(AuthorityHistoryReason::OpNotFoldedPast);
    }
    if image.residence_overflow
        && tail
            .values()
            .any(|entry| matches!(entry.op, AuthorityOp::ResidenceResult(_)))
    {
        return Err(AuthorityHistoryReason::ResidenceBodiesDropped);
    }
    // A tail an owner key's line could reach where the image's kept states
    // do not show it is judged by the whole log (row
    // CARRIER-PROOF-OLD-PARENTS).
    if super::owner_key_line::tail_reaches_old_parents(image, tail) {
        return Err(AuthorityHistoryReason::OwnerKeyLineReachesCovered);
    }
    // Only the rows the whole fold judges set or carry a floor
    // (`fold_engine::judged_entries`): a tail row whose signature fails is
    // neither a link nor a setter, as it is in no ancestry of the whole fold.
    let signed: BTreeMap<_, _> = tail
        .iter()
        .filter(|(_, entry)| verify_entry_signatures(entry).is_ok())
        .map(|(hash, entry)| (*hash, *entry))
        .collect();
    let floored = covered_floors::tail_floored_rows(image, &signed)
        .ok_or(AuthorityHistoryReason::SequenceFloorMoved)?;
    let mut confirms = (
        image.safety.confirm_ids.clone(),
        image.safety.confirm_nonces.clone(),
    );
    for (hash, entry) in tail {
        if let Some(reason) = parent_refusal(image, entry) {
            return Err(reason);
        }
        // The fence's own signers: a reserve-only owner key proof is none
        // (`retired_signers::entry_signer_keys`, REVIEW-9961 P1).
        let retired = super::retired_signers::entry_signer_keys(entry)
            .any(|key| image.safety.retired_keys.contains(key));
        if retired {
            return Err(AuthorityHistoryReason::RetiredSigner);
        }
        if image.safety.missing_parents.contains(hash) {
            return Err(AuthorityHistoryReason::UncleanImage);
        }
        // A serial row first: a confirm a covered one spent folds
        // rejected and never joins the log's confirms.
        if !(serial_withdrawal(image, tail, log, entry)
            || serial_fold_past(image, tail, log, entry)
            || super::fold_resume::admits_past(&image.aggregate.merged, entry, &mut confirms))
        {
            return Err(op_refusal(image, tail, log, entry));
        }
    }
    Ok(CoveredFloors::of(floored))
}

/// Why a parent of the tail row `entry` does not stand past the image, or
/// None where each does. A parent the image does not cover stands here (a
/// tail row, or a gap the fold asks for). A covered parent off the frontier
/// folds on its replay state (FIX 3007) where the image keeps one a late
/// fork may seed from. No withdrawal stands on a row the image holds
/// rejected: only older states could judge it.
fn parent_refusal(
    image: &AuthorityCheckpointV2,
    entry: &AuthorityLogEntry,
) -> Option<AuthorityHistoryReason> {
    entry.parent_hashes.iter().find_map(|parent| {
        if !image.rows.contains_key(parent) {
            return None;
        }
        if image.holds_rejected(parent) {
            return super::revoke_proof::restrictive_withdrawal(&entry.op)
                .then_some(AuthorityHistoryReason::RejectedRowCrossed);
        }
        let seeded = image.per_parent.contains_key(parent)
            || (image.keeps_state(parent) && context::seeds_late_fork(image, parent));
        (!seeded).then_some(AuthorityHistoryReason::LateForkWithoutState)
    })
}

/// Why the tail row `entry`, which neither [`serial_withdrawal`],
/// [`serial_fold_past`] nor [`super::fold_resume::admits_past`] takes, does
/// not fold past the image: for a serial kind, the condition of
/// [`folds_serially`] it fails; for any other, its op.
fn op_refusal(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    entry: &AuthorityLogEntry,
) -> AuthorityHistoryReason {
    if (settle::serial_withdrawal_op(&entry.op) || serial_fold_past_kind(image, tail, entry))
        && let Some(reason) = serial_refusal(image, tail, log, entry)
    {
        return reason;
    }
    AuthorityHistoryReason::OpNotFoldedPast
}

/// Whether `tail` moves no covered row's sequence floor and holds no row
/// past its own (`rows_floor`): per signer and scope, the tail's rows rise
/// strictly above the image's top, the lowest descends from the covered row
/// at that top, and each next from the one below it, along that scope's
/// rows. A covered row under no top sits past its floor with no row at or
/// above it that vouches for it, so a tail row that misses it changes no
/// floor; every other covered row is then among each tail row's ancestors.
/// No tail row vouches for a covered row past its floor
/// ([`tail_signers_covered_rows_unfloored`]). That gate runs first, so a
/// tail signer's covered rows in a scope rise strictly and one sits at the
/// top; several at one top answer false.
///
/// The rows form that chain exactly when each tail row's highest row of its
/// signer and scope below it ([`covered_floors::tail_key_rows_below`], one
/// pass) is the row before it: the top, then each tail row in turn. A later
/// tail row below an earlier one would close a cycle with the chain, which
/// no hash-linked log holds (FIX [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST]: a
/// walk per tail signer cost each one the whole spine its top sat below).
///
/// Only the rows the whole fold judges count (`fold_engine::judged_entries`,
/// review R2 of [SEQUENCE-FLOOR-DELIVERY-ORDER]): a row, covered or tail,
/// that names a side row of another world is none of them. It is no top and
/// sets no floor, and no walk passes through it to the rows below, as no
/// ancestry of the whole fold does. No walk passes through a covered row the
/// image holds rejected either (review round 2 of #8449): the image does not
/// tell a row the fold refused from one it never judged, so a tail row that
/// reaches a top only across such a row sends the tail to the whole history.
/// Every image build decodes each row it covers through
/// `decode_authority_log_entry_body`, which refuses a bad signature, so no
/// top is a row the whole fold leaves unjudged.
fn rows_floors_unmoved(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    let violates = |world: Option<crate::EntityId>, parents: &[AuthorityEntryHash]| {
        covered_floors::names_other_world(image, tail, world, parents)
    };
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, entry) in tail {
        let world = crate::authority::world_privacy::side_world(&entry.op);
        if violates(world, &entry.parent_hashes) {
            continue;
        }
        scopes
            .entry((entry.signer_key(), world))
            .or_default()
            .push((entry.seq, *hash));
    }
    let mut tops = BTreeMap::<_, (u64, Vec<AuthorityEntryHash>)>::new();
    for (hash, row) in &image.rows {
        let key = (&row.signer, row.world);
        if !scopes.contains_key(&key) || violates(row.world, &row.parents) {
            continue;
        }
        let top = tops.entry(key).or_insert((row.seq, Vec::new()));
        if row.seq > top.0 {
            *top = (row.seq, Vec::new());
        }
        if row.seq == top.0 {
            top.1.push(*hash);
        }
    }
    let Some(below) = covered_floors::tail_key_rows_below(image, tail, scopes.keys().copied())
    else {
        return false;
    };
    scopes.iter_mut().all(|(key, rows)| {
        rows.sort_unstable();
        let mut lower = match tops.get(key).map(|(seq, rows)| (*seq, rows.as_slice())) {
            None => None,
            Some((seq, &[top])) => Some((seq, top)),
            Some(_) => return false,
        };
        rows.iter().all(|&(seq, hash)| {
            let rises = match lower {
                None => !below.contains_key(&hash),
                Some((lower_seq, lower_row)) => {
                    seq > lower_seq && below.get(&hash) == Some(&lower_row)
                }
            };
            lower = Some((seq, hash));
            rises
        })
    })
}

/// Whether every tail row's signer signed its covered rows, in each sequence
/// scope (`world_privacy::side_world`), as one chain: sequences strictly
/// rise, and each row descends from the one below it along that scope's rows
/// (`rows_floor::highest_key_row_below`). Then no covered row of a tail
/// row's signer sits past a floor (`rows_floor::rows_sequence_floors`), and
/// no tail row vouches for one (`sequence_ancestry`): a row vouches only for
/// rows of its own signer, and [`rows_floors_unmoved`] keeps the tail from
/// moving a covered floor, or [`covered_floors::floored_covered_rows`] from
/// moving one but onto rows a floor never refuses, which no row vouches
/// for. Otherwise a tail row at or above a covered row's
/// floor that descends from it may lift that floor in the whole fold, so the
/// row the image holds refused past it (review R1 of
/// [SEQUENCE-FLOOR-DELIVERY-ORDER]) or landed restriction only (Astra round 1
/// E1) counts whole there; only the whole history judges that. A forked
/// signer's tail so folds whole, as a resumed fold's base with a row past
/// its floor does (`fold_resume::capture`). A false answer only sends the
/// tail to the whole history. A row that names a side row of another world
/// is left out and never walked, as in [`rows_floors_unmoved`].
///
/// The chain check is [`covered_floors::covered_rows_unfloored`], over the
/// tail's signers.
fn tail_signers_covered_rows_unfloored(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    let signers: BTreeSet<_> = tail.values().map(|entry| entry.signer_key()).collect();
    covered_floors::covered_rows_unfloored(image, |signer| signers.contains(signer))
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
    serial_fold_past_kind(image, tail, entry) && folds_serially(image, tail, log, entry)
}

/// Whether the tail row `entry` is of a kind [`serial_fold_past`] takes past
/// `image` in `tail`, before [`folds_serially`]'s conditions.
fn serial_fold_past_kind(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
) -> bool {
    if settle::serial_fold_past_op(&entry.op)
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
    }
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
    serial_refusal(image, tail, log, entry).is_none()
}

/// Why the tail row `entry` does not fold serially ([`folds_serially`]): the
/// first of its conditions it fails, in this order. None where it does.
fn serial_refusal(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    entry: &AuthorityLogEntry,
) -> Option<AuthorityHistoryReason> {
    if image.building_pin != log.pin.copied() || image.aggregate.peers != *log.peer_consent_roots {
        Some(AuthorityHistoryReason::ImageContextMoved)
    } else if !clean_image(image) {
        Some(AuthorityHistoryReason::UncleanImage)
    } else {
        covered_past_refusal(image, tail, entry)
    }
}

/// Whether every row `image` covers folded valid, with no issue, missing
/// parent or unsettled handoff: its states are the whole fold's own. A fork
/// record (`AuthorityFoldIssue::SequenceFork`) is no verdict: its row counts
/// in full, so it leaves the image clean.
fn clean_image(image: &AuthorityCheckpointV2) -> bool {
    let valid = &image.fold().valid_entries;
    !image.safety.unsettled
        && image
            .safety
            .issues
            .iter()
            .all(|issue| matches!(issue, AuthorityFoldIssue::SequenceFork(_)))
        && image.safety.missing_parents.is_empty()
        && image.covered.iter().all(|hash| valid.contains(hash))
}

/// Why a row `image` covers may be outside the causal past of the tail row
/// `entry`, or None where every one is in it: each image frontier row is a
/// parent of it or of a tail row it descends from. Covered rows close over
/// their ancestors and no covered row names a frontier row, so reaching
/// every frontier row reaches them all. An ancestor neither tail nor covered
/// leaves it unproved, for that row ([`AuthorityHistoryReason::UnheldRows`]),
/// even where the walk reached every frontier row elsewhere; a whole walk
/// that misses a frontier row proves a covered row concurrent with `entry`.
fn covered_past_refusal(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
) -> Option<AuthorityHistoryReason> {
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
            return Some(AuthorityHistoryReason::UnheldRows);
        }
    }
    (!image.frontier.iter().all(|leaf| reached.contains(leaf)))
        .then_some(AuthorityHistoryReason::CoveredRowConcurrent)
}

/// Whether `entry` is a main-log row, no world's side row.
fn is_main(entry: &AuthorityLogEntry) -> bool {
    super::world_privacy::side_world(&entry.op).is_none()
}

#[cfg(oneiron_test_support)]
pub(crate) use covered_floors::{covered_rows_unfloored_for_door, tail_floored_rows_for_door};
