//! The tail's seeded fold past an adopted image, settled and projected
//! (OF-469, slice C): what the live fold past the image and a later image
//! built past it share ([`super::fold_adopted_checkpoint_tail`],
//! [`super::capture_adopted_checkpoint_tail`]).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use super::super::fold_engine::FoldContext;
use super::super::fold_project::Settled;
use super::super::fold_resume::{ConfirmKeys, Resumed};
use super::*;
use crate::EntityId;
use crate::error::Result;

/// The tail's seeded fold past the image, settled and projected: what this
/// install's fold past the image and a later image built past it share.
pub(super) struct SettledTail {
    pub(super) judged: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pub(super) states: BTreeMap<AuthorityEntryHash, FoldState>,
    /// The image's merged state with every tail state merged in.
    pub(super) merged: FoldState,
    pub(super) writers: BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    pub(super) uncounted: BTreeSet<AuthorityEntryHash>,
    pub(super) pairs: u64,
    pub(super) counted_pairs: u64,
    /// The ancestors and counted ancestors of each image frontier row and
    /// each judged tail row.
    pub(super) ancestry: BTreeMap<AuthorityEntryHash, (u64, u64)>,
    /// The confirms in the log once the tail joined them.
    pub(super) confirms: ConfirmKeys,
    /// The issues before the projection.
    pub(super) issues: Vec<AuthorityFoldIssue>,
    /// The covered rows a fold past the image reads whole, from their
    /// carried bodies.
    pub(super) projected: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    /// The projected once fold, before any install's stale window.
    pub(super) fold: AuthorityFold,
    /// The projection's final merge.
    pub(super) final_merged: Option<FoldState>,
}

/// The tail's fold on the image's frontier states, merged into the image's
/// fold and projected, with `confirms` the confirms once the tail joined
/// them ([`tail_folds_past`]); None wherever only the whole history folds
/// the tail. A carried body that does not decode is corruption.
pub(super) fn settle_tail(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    log: AdoptedTail<'_>,
    confirms: ConfirmKeys,
) -> Result<Option<SettledTail>> {
    let mut issues = image.safety.issues.clone();
    let judged = judged_tail(image, tail, &mut issues);
    let uncounted: BTreeSet<_> = image
        .safety
        .uncounted
        .iter()
        .copied()
        .chain(
            judged
                .iter()
                .filter(|(_, entry)| {
                    crate::authority::log_budget::is_uncounted(entry, &image.safety.issuers)
                })
                .map(|(hash, _)| *hash),
        )
        .collect();
    let (pairs, counted_pairs, ancestry) = tail_pairs(image, &judged, &uncounted);
    let memory_floor_bytes =
        crate::authority::log_budget::fold_memory_floor(Some(&log.observations.policy));
    if crate::authority::log_budget::fold_projected_bytes(image.covered.len() + judged.len(), pairs)
        > memory_floor_bytes
    {
        return Ok(None);
    }
    // Each tail row folds on its parents' states as the scheduler folds it,
    // the frontier's kept states seeding it.
    let (consent_arm, _) = crate::authority::fold_engine::own_log_inputs(log.posture, None);
    let no_handoff_line = BTreeSet::new();
    let summaries = crate::authority::fold_engine::ImagePast {
        image,
        judged: &judged,
    };
    let causal = crate::authority::fold_engine::CausalPast::new(&summaries);
    let context = FoldContext {
        sequence_floors: Some(&log.observations.sequence_floors),
        floor_vouched: (!log.observations.unvouched).then_some(&log.observations.vouched),
        install_held: None,
        entry_ancestors: None,
        causal_past: Some(&causal),
        peer_consent_roots: log.peer_consent_roots,
        consent_arm,
        hosted: log.posture == crate::HostingPrivacyPosture::Hosted,
        machine_standing: &crate::authority::machine_standing::every_chain,
        pre_handoff_entries: Some(&no_handoff_line),
        memory_floor_bytes,
        pin: log.pin,
    };
    let mut seed: BTreeMap<_, _> = image
        .per_parent
        .iter()
        .filter_map(|(hash, state)| Some((*hash, state.clone()?)))
        .collect();
    // A late fork's covered parent seeds from its replay state (FIX 3007);
    // a point that does not decode leaves the whole history to fold it.
    for parent in judged.values().flat_map(|entry| entry.parent_hashes.iter()) {
        if !image.rows.contains_key(parent)
            || image.per_parent.contains_key(parent)
            || seed.contains_key(parent)
            || image.holds_rejected(parent)
        {
            continue;
        }
        let Some(Some(state)) = image.state_at(parent) else {
            return Ok(None);
        };
        seed.insert(*parent, state);
    }
    let mut states = crate::authority::fold_schedule::fold_entry_states_seeded(
        &judged,
        &seed,
        context,
        &mut issues,
    );
    // A key record's request walk that met a row the image shows nothing of
    // judged nothing here (FIX 5464): only the whole history does.
    if causal.incomplete() {
        return Ok(None);
    }
    // A world key record, or a restrictive main-log choice (a world edit,
    // grant travel, checkpoint policy, home pick or training choice), on a
    // row with no state here (a frontier row the image holds rejected, a
    // rejected tail row) is folded again with that row crossed
    // (`world_refold`), which only the whole history does (FIX 4881, 5463),
    // as is a root request, the owner's cancel of one or its result (FIX
    // 5584, 5649), the request's kind read from the tail or the image.
    let kind_of = |request: &AuthorityEntryHash| match judged.get(request) {
        Some(asked) => crate::authority::world_refold::request_kind(asked),
        None => crate::authority::world_refold::carried_request_kind(image, request),
    };
    if judged.iter().any(|(hash, entry)| {
        crate::authority::world_refold::refolds(&entry.op, kind_of)
            && !states.contains_key(hash)
            && entry
                .parent_hashes
                .iter()
                .any(|parent| !states.contains_key(parent))
    }) {
        return Ok(None);
    }
    states.retain(|hash, _| judged.contains_key(hash));
    if states
        .values()
        .any(|state| state.federation_pacts != image.aggregate.merged.federation_pacts)
    {
        return Ok(None);
    }
    let mut merged = image.aggregate.merged.clone();
    let mut writers = image.safety.writers.clone();
    for state in states.values() {
        merged = merge_states(&merged, state);
        crate::authority::fold_resume::add_writers(&mut writers, state);
    }
    let mut valid_entries = image.fold().valid_entries.clone();
    valid_entries.extend(states.keys().copied());
    // The rows a fold past the image reads whole: carried bodies of the
    // projected kinds alone, whatever else an image carries, and the judged
    // tail's rows of those kinds (a world key record's envelopes, FIX 4881).
    let mut projected = BTreeMap::new();
    for (hash, row) in &image.rows {
        if let Some(body) = &row.body {
            let entry = decode_authority_log_entry_body(body)?;
            if crate::authority::fold_resume::is_projected(&entry.op) {
                projected.insert(*hash, entry);
            }
        }
    }
    // Under another pin than the image's, the guards below read the image's
    // own fold as this install projects it (FIX 3004).
    let here = (log.pin.copied() != image.building_pin)
        .then(|| image_fold_under(image, &projected, context));
    let image_fold = here.as_ref().unwrap_or_else(|| image.fold());
    for (hash, entry) in &judged {
        if crate::authority::fold_resume::is_projected(&entry.op) {
            projected.insert(*hash, entry.clone());
        }
    }
    let rows = Resumed {
        marks: &image.safety.marks,
        fold: image.fold(),
        revocations: &image.safety.revocations,
        bound_keys: &image.safety.bound_keys,
        chain: states
            .iter()
            .filter(|(hash, _)| judged.get(*hash).is_some_and(is_main))
            .map(|(hash, state)| (*hash, state))
            .collect(),
        writers: &writers,
        missed: Cell::new(false),
    };
    // The projection reads rows only for world-key envelopes, the image's
    // and the tail's alike.
    let (fold, final_merged) = crate::authority::fold_project::project_once(
        Settled {
            merged: Some(merged.clone()),
            valid_entries,
            by_hash: &projected,
            revoke_facts: &image.safety.revoke_facts,
            retired_keys: image.safety.retired_keys.clone(),
            closed_handoffs: image.safety.closed_handoffs.clone(),
            unsettled: image.safety.unsettled,
            counted_ancestor_pairs: counted_pairs,
            issues: issues.clone(),
        },
        &rows,
        context,
    );
    if rows.missed.get()
        || fold.machines != image_fold.machines
        || !crate::authority::world_privacy::worlds_unmoved_past(
            &fold,
            image_fold,
            judged.iter().map(|(hash, entry)| (*hash, entry)),
        )
        || approves_on_revoked_key(&fold, &judged, &states)
    {
        return Ok(None);
    }
    Ok(Some(SettledTail {
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
        final_merged,
    }))
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
            .and_then(|entry| crate::authority::world_privacy::side_world(&entry.op))
            .or_else(|| image.rows.get(hash).and_then(|row| row.world))
    };
    let violations: Vec<_> = judged
        .iter()
        .filter(|(_, entry)| {
            let world = crate::authority::world_privacy::side_world(&entry.op);
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
/// any other row walks its ancestry. With each image frontier row's and
/// each judged tail row's ancestors and counted ancestors.
fn tail_pairs(
    image: &AuthorityCheckpointV2,
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    uncounted: &BTreeSet<AuthorityEntryHash>,
) -> (u64, u64, BTreeMap<AuthorityEntryHash, (u64, u64)>) {
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
    (pairs, counted_pairs, known)
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

/// The image's own fold, projected under `context` (this install's pin) from
/// its merge and its rows read whole, `projected`: what the tail is compared
/// against where the image was built under another pin (FIX 3004).
fn image_fold_under(
    image: &AuthorityCheckpointV2,
    projected: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    context: FoldContext<'_>,
) -> AuthorityFold {
    let rows = Resumed {
        marks: &image.safety.marks,
        fold: image.fold(),
        revocations: &image.safety.revocations,
        bound_keys: &image.safety.bound_keys,
        chain: Vec::new(),
        writers: &image.safety.writers,
        missed: Cell::new(false),
    };
    crate::authority::fold_project::project_once(
        Settled {
            merged: Some(image.aggregate.merged.clone()),
            valid_entries: image.fold().valid_entries.clone(),
            by_hash: projected,
            revoke_facts: &image.safety.revoke_facts,
            retired_keys: image.safety.retired_keys.clone(),
            closed_handoffs: image.safety.closed_handoffs.clone(),
            unsettled: image.safety.unsettled,
            counted_ancestor_pairs: image.safety.counted_pairs,
            issues: image.safety.issues.clone(),
        },
        &rows,
        context,
    )
    .0
}
