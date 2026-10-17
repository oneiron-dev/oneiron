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
//! frontier or tail parent. Anything else needs history, never a fold of the
//! rows held: a tail row on a covered row off the frontier (a late fork,
//! whose parent state the image never kept), an op outside that set, a
//! context the image was not built under (another install pin, posture or
//! peer set), or a guard a resumed fold declines at. That request names
//! every covered row not held here, since only the whole history folds past
//! such a row; a parent neither covered nor held is named alone.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::fold_engine::FoldContext;
use super::fold_project::Settled;
use super::fold_resume::{Resumed, RowMeta};
use super::*;
use crate::error::Result;

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
    /// Hashes a caller names as needed.
    pub(super) required: &'a BTreeSet<AuthorityEntryHash>,
    /// The tail rows' first-seen seconds, and no covered row's.
    pub(super) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(super) now_secs: u64,
    pub(super) peer_consent_roots: &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// The tail rows' observations, and no covered row's.
    pub(super) observations: &'a AuthorityLocalObservations,
    pub(super) posture: crate::HostingPrivacyPosture,
    pub(super) pin: Option<&'a PinnedRoot>,
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
                .filter(|hash| !image.per_parent.contains_key(*hash)),
        )
        .filter(|hash| !tail.contains_key(*hash))
        .copied()
        .collect();
    // What only the whole history closes: every covered row not held here.
    let whole = || {
        let mut missing = gaps.clone();
        missing.extend(
            image
                .covered
                .iter()
                .filter(|hash| !log.held_covered.contains(*hash)),
        );
        need(missing)
    };
    if !image_stands_here(image, log) || !tail_folds_past(image, &tail, log) {
        return Ok(whole());
    }
    if !gaps.is_empty() {
        return Ok(need(gaps.clone()));
    }
    let mut issues = image.safety.issues.clone();
    let judged = judged_tail(image, &tail, &mut issues);
    let uncounted: BTreeSet<_> = image
        .safety
        .uncounted
        .iter()
        .copied()
        .chain(
            judged
                .iter()
                .filter(|(_, entry)| super::log_budget::is_uncounted(entry, &image.safety.issuers))
                .map(|(hash, _)| *hash),
        )
        .collect();
    let (pairs, counted_pairs) = tail_pairs(image, &judged, &uncounted);
    let memory_floor_bytes = super::log_budget::fold_memory_floor(Some(&log.observations.policy));
    if super::log_budget::fold_projected_bytes(image.covered.len() + judged.len(), pairs)
        > memory_floor_bytes
    {
        return Ok(whole());
    }
    // Each tail row folds on its parents' states as the scheduler folds it,
    // the frontier's kept states seeding it.
    let (consent_arm, _) = super::fold_engine::own_log_inputs(log.posture, None);
    let no_handoff_line = BTreeSet::new();
    let context = FoldContext {
        sequence_floors: Some(&log.observations.sequence_floors),
        floor_vouched: (!log.observations.unvouched).then_some(&log.observations.vouched),
        install_held: None,
        entry_ancestors: None,
        peer_consent_roots: log.peer_consent_roots,
        consent_arm,
        hosted: log.posture == crate::HostingPrivacyPosture::Hosted,
        machine_standing: &super::machine_standing::every_chain,
        pre_handoff_entries: Some(&no_handoff_line),
        memory_floor_bytes,
        pin: log.pin,
    };
    let seed: BTreeMap<_, _> = image
        .per_parent
        .iter()
        .filter_map(|(hash, state)| Some((*hash, state.clone()?)))
        .collect();
    let mut states =
        super::fold_schedule::fold_entry_states_seeded(&judged, &seed, context, &mut issues);
    states.retain(|hash, _| judged.contains_key(hash));
    if states
        .values()
        .any(|state| state.federation_pacts != image.aggregate.merged.federation_pacts)
    {
        return Ok(whole());
    }
    let mut merged = image.aggregate.merged.clone();
    let mut writers = image.safety.writers.clone();
    for state in states.values() {
        merged = merge_states(&merged, state);
        super::fold_resume::add_writers(&mut writers, state);
    }
    let mut valid_entries = image.fold().valid_entries.clone();
    valid_entries.extend(states.keys().copied());
    // The rows a fold past the image reads whole: carried bodies of the
    // projected kinds alone, whatever else an image carries.
    let mut projected = BTreeMap::new();
    for (hash, row) in &image.rows {
        if let Some(body) = &row.body {
            let entry = decode_authority_log_entry_body(body)?;
            if super::fold_resume::is_projected(&entry.op) {
                projected.insert(*hash, entry);
            }
        }
    }
    let rows = Resumed {
        marks: &image.safety.marks,
        fold: image.fold(),
        revocations: &image.safety.revocations,
        bound_keys: &image.safety.bound_keys,
        chain: states.iter().map(|(hash, state)| (*hash, state)).collect(),
        writers: &writers,
        missed: Cell::new(false),
    };
    // The projection reads rows only for world-key envelopes, and no tail
    // row is a world-key record.
    let (fold, _) = super::fold_project::project_once(
        Settled {
            merged: Some(merged),
            valid_entries,
            by_hash: &projected,
            revoke_facts: &image.safety.revoke_facts,
            retired_keys: image.safety.retired_keys.clone(),
            closed_handoffs: image.safety.closed_handoffs.clone(),
            unsettled: image.safety.unsettled,
            counted_ancestor_pairs: counted_pairs,
            issues,
        },
        &rows,
        context,
    );
    if rows.missed.get()
        || fold.machines != image.fold().machines
        || fold.worlds != image.fold().worlds
        || fold.refused_world_edits != image.fold().refused_world_edits
        || approves_on_revoked_key(&fold, &judged, &states)
    {
        return Ok(whole());
    }
    // This install's own view, over the rows its stale-roster window reads:
    // the tail's first-seen times are the only ones it has.
    let window_secs = log.observations.policy.stale_roster_window_secs;
    let read_whole: Vec<&AuthorityLogEntry> = projected
        .values()
        .chain(tail.values().copied())
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
    if !view.worlds.is_empty() && !super::install_fold::stale_chains(&view).is_empty() {
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

/// Whether the image's fold is the one this install would reach: built under
/// this install's pin (identity canon leaves no recount of world keys under
/// another), its posture and its admitted peers' consent roots.
fn image_stands_here(image: &AuthorityCheckpointV2, log: AdoptedTail<'_>) -> bool {
    image.building_pin == log.pin.copied()
        && image.aggregate.posture == log.posture
        && image.aggregate.peers == *log.peer_consent_roots
}

/// Whether every tail row folds past the image as a resumed fold's chain row
/// would: each parent on the frontier or in the tail (a covered parent off
/// the frontier is a late fork), a main-log op that leaves every earlier
/// row's fate as it was, no row a sequence floor refuses, none signed by a
/// retired key, none a covered row names, and no withdrawal on a frontier
/// row the image holds rejected (only older states could judge it).
fn tail_folds_past(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
) -> bool {
    let mut confirms = (
        image.safety.confirm_ids.clone(),
        image.safety.confirm_nonces.clone(),
    );
    tail.iter().all(|(hash, entry)| {
        let parents_stand = entry.parent_hashes.iter().all(|parent| {
            match (
                image.rows.contains_key(parent),
                image.per_parent.get(parent),
            ) {
                (true, None) => false,
                (true, Some(None)) => !super::revoke_proof::restrictive_withdrawal(&entry.op),
                _ => true,
            }
        });
        let retired = std::iter::once(&entry.signer)
            .chain(&entry.cosigns)
            .any(|signature| image.safety.retired_keys.contains(&signature.public_key));
        parents_stand
            && !retired
            && !image.safety.missing_parents.contains(hash)
            && super::world_privacy::side_world(&entry.op).is_none()
            && log
                .observations
                .sequence_floors
                .get(hash)
                .is_none_or(|floor| entry.seq >= *floor)
            && super::fold_resume::admits_past(&image.aggregate.merged, entry, &mut confirms)
    })
}

/// The tail rows a fold judges, as `fold_engine::judged_entries` judges them:
/// each well signed, none hanging off a side entry of another world. The
/// rest go to `issues`.
fn judged_tail(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    issues: &mut Vec<AuthorityFoldIssue>,
) -> BTreeMap<AuthorityEntryHash, AuthorityLogEntry> {
    let mut judged = BTreeMap::new();
    for (hash, entry) in tail {
        if verify_entry_signatures(entry).is_ok() {
            judged.insert(*hash, (*entry).clone());
        } else {
            issues.push(AuthorityFoldIssue::InvalidEntry(*hash));
        }
    }
    let world_of = |hash: &AuthorityEntryHash| {
        judged
            .get(hash)
            .and_then(|entry| super::world_privacy::side_world(&entry.op))
            .or_else(|| image.rows.get(hash).and_then(|row| row.world))
    };
    let violations: Vec<_> = judged
        .iter()
        .filter(|(_, entry)| {
            let world = super::world_privacy::side_world(&entry.op);
            entry
                .parent_hashes
                .iter()
                .any(|parent| world_of(parent).is_some_and(|parent| world != Some(parent)))
        })
        .map(|(hash, _)| *hash)
        .collect();
    for hash in violations {
        judged.remove(&hash);
        issues.push(AuthorityFoldIssue::InvalidEntry(hash));
    }
    judged
}

/// The whole log's ancestor pairs and counted pairs, as
/// `ancestor_index::entry_ancestor_index` counts them: the image's, and each
/// judged tail row's ancestors over the image's rows and the tail. A row on
/// one parent with known counts adds that parent's ancestry and the parent;
/// any other row walks its ancestry.
fn tail_pairs(
    image: &AuthorityCheckpointV2,
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    uncounted: &BTreeSet<AuthorityEntryHash>,
) -> (u64, u64) {
    let parents_of = |hash: &AuthorityEntryHash| {
        judged
            .get(hash)
            .map(|entry| entry.parent_hashes.as_slice())
            .or_else(|| image.rows.get(hash).map(|row| row.parents.as_slice()))
    };
    let counted = |hash: &AuthorityEntryHash| u64::from(!uncounted.contains(hash));
    let mut known = image.safety.frontier_ancestry.clone();
    let (mut pairs, mut counted_pairs) = (image.safety.pairs, image.safety.counted_pairs);
    for hash in parents_first(judged) {
        let (ancestors, counted_ancestors) = match judged[&hash].parent_hashes.as_slice() {
            [parent] if known.contains_key(parent) => {
                let (ancestors, counted_ancestors) = known[parent];
                (ancestors + 1, counted_ancestors + counted(parent))
            }
            parents => {
                let mut seen = BTreeSet::new();
                let mut stack = parents.to_vec();
                while let Some(at) = stack.pop() {
                    if seen.insert(at) {
                        stack.extend(parents_of(&at).into_iter().flatten().copied());
                    }
                }
                let counted_ancestors: u64 = seen.iter().map(counted).sum();
                (seen.len() as u64, counted_ancestors)
            }
        };
        known.insert(hash, (ancestors, counted_ancestors));
        pairs = pairs.saturating_add(ancestors);
        counted_pairs = counted_pairs.saturating_add(counted(&hash) * counted_ancestors);
    }
    (pairs, counted_pairs)
}

/// `rows`' hashes, each after every parent of it among `rows`, ties by
/// hash; a row on a cycle comes last.
fn parents_first(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> Vec<AuthorityEntryHash> {
    let mut waiting = BTreeMap::new();
    let mut children = BTreeMap::<_, Vec<_>>::new();
    let mut ready = BTreeSet::new();
    for (hash, entry) in rows {
        let parents: BTreeSet<_> = entry
            .parent_hashes
            .iter()
            .filter(|parent| rows.contains_key(*parent))
            .collect();
        for parent in &parents {
            children.entry(**parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.insert(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut order = Vec::with_capacity(rows.len());
    while let Some(hash) = ready.pop_first() {
        order.push(hash);
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.insert(*child);
                }
            }
        }
    }
    order.extend(waiting.into_keys());
    order
}

/// Whether a valid tail approval rests on a key the fold holds revoked. Its
/// stale-roster window would start at this install's first sight of the
/// covered revocation, a time this install never recorded: no clock is
/// imported, so the whole history must decide it.
fn approves_on_revoked_key(
    fold: &AuthorityFold,
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> bool {
    states.keys().any(|hash| {
        let Some(entry) = judged.get(hash) else {
            return false;
        };
        let approval = match &entry.op {
            AuthorityOp::BindActor { .. } | AuthorityOp::RebindActor { .. } => true,
            AuthorityOp::FederationConfirm(action) => action.kind != AuthorityConfirmKind::Revoke,
            AuthorityOp::CriticalWriteConfirm(action) => {
                action.disposition == CriticalWriteConfirmDisposition::Clear
            }
            AuthorityOp::MachineProfile(profile) => profile.role != MachineRole::Removed,
            _ => false,
        };
        approval
            && std::iter::once(&entry.signer)
                .chain(&entry.cosigns)
                .any(|signature| {
                    fold.roster
                        .get(&signature.public_key)
                        .is_some_and(|device| device.revoked)
                })
    })
}
