//! The tail-row walks settle_tail reads: device revocation fences, tail issuers,
//! judged rows, parent pairs and order, revoked-key approvals, image fold under a context.

use super::*;

/// The keys the tail's device revocations retire, as the whole fold's
/// settlement retires them (`retired_signers`, a revocation's fence): the
/// revoked key of each one the tail folds to a state (a rejected one closes
/// no fence). Every covered row is in such a revocation's causal past
/// ([`super::serial_fold_past`]), so its line holds them all and its fence
/// refuses none, and no covered fence refuses it (no tail row is signed by a
/// key the image retired, [`super::tail_folds_past`]). None where its fence
/// could refuse a tail row outside its line, one beside it or above it that
/// the revoked key signs and that folds to a state: the whole fold drops
/// such a row with its descendants (`RetiredSigner`), which only the whole
/// history folds here. This test is stricter than the whole fold's
/// (`Fence::signed_outside`): it exempts no genesis, no anchored row and no
/// row of another vault.
pub(super) fn serial_revocation_fences(
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> Option<BTreeSet<AuthorityKey>> {
    let mut retired = BTreeSet::new();
    for (hash, entry) in judged {
        let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
            continue;
        };
        if !states.contains_key(hash) {
            continue;
        }
        let keys = BTreeSet::from([revoked_key.clone()]);
        if signed_outside_tail_line(hash, &keys, judged, states) {
            return None;
        }
        retired.insert(revoked_key.clone());
    }
    Some(retired)
}

/// Whether `keys` sign, as primary or co-signer
/// (`retired_signers::entry_signer_keys`), a judged tail row with a state
/// outside the line of the tail row `row`: it and its tail ancestors. Only a
/// row with a state stands for a fence to refuse. Each covered row is in that
/// line where every covered row is in `row`'s causal past.
pub(super) fn signed_outside_tail_line(
    row: &AuthorityEntryHash,
    keys: &BTreeSet<AuthorityKey>,
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> bool {
    let mut line = BTreeSet::from([*row]);
    let mut stack: Vec<AuthorityEntryHash> = judged
        .get(row)
        .map(|entry| entry.parent_hashes.clone())
        .unwrap_or_default();
    while let Some(at) = stack.pop() {
        if let Some(entry) = judged.get(&at)
            && line.insert(at)
        {
            stack.extend(entry.parent_hashes.iter().copied());
        }
    }
    judged.iter().any(|(hash, entry)| {
        !line.contains(hash)
            && states.contains_key(hash)
            && crate::authority::retired_signers::entry_signer_keys(entry)
                .any(|key| keys.contains(key))
    })
}

/// The slip issuers once the tail joins the image's history: the consent
/// structure's own (`log_structure::authority_structure`), read as the whole
/// fold reads it for its image (`fold_resume::ImageFold`), from the rows it
/// judges (`fold_engine::judged_entries`) in hash order: the image's carried
/// bodies (it carries each genesis, enrollment, rotation, re-root, owner key
/// enrollment, root record and machine profile whole) and the judged tail
/// ([`judged_tail`]). A row that hangs off another world's side row admits no
/// key here, as in the whole fold, though the store door, which reads raw
/// rows, counts it: a tail row (Astra foldpast4 P2), or a carried row of an
/// image with issues, which a tail of rows
/// [`crate::authority::fold_resume::admits_past`] takes, such as agent
/// enrollments, still folds past (Spark r5 P2). A rotation, an enrollment or
/// a re-root an admitter signed admits its owner key there whether or not the
/// fold applies the row, as in the whole history. None where a key only the
/// tail admits signed a covered slip row: that row would leave the counted
/// ancestry, which only the whole history counts again.
pub(super) fn tail_issuers(
    image: &AuthorityCheckpointV2,
    carried: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    judged: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> Option<BTreeSet<AuthorityKey>> {
    let covered_world = |hash: &AuthorityEntryHash| image.rows.get(hash).and_then(|row| row.world);
    let rows: BTreeMap<_, _> = carried
        .iter()
        .filter(|(_, entry)| !hangs_off_another_world(entry, &covered_world))
        .chain(judged)
        .collect();
    let mut issuers =
        crate::authority::log_structure::authority_structure(rows.values().copied()).issuers;
    // Nothing leaves the set.
    issuers.extend(image.safety.issuers.iter().cloned());
    let recounted = image.rows.values().any(|row| {
        row.slip_op && issuers.contains(&row.signer) && !image.safety.issuers.contains(&row.signer)
    });
    (!recounted).then_some(issuers)
}

/// The tail rows a fold judges, as `fold_engine::judged_entries` judges them:
/// each well signed, none hanging off a side entry of another world. The
/// rest go to `issues`.
pub(super) fn judged_tail(
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
        .filter(|(_, entry)| hangs_off_another_world(entry, &world_of))
        .map(|(hash, _)| *hash)
        .collect();
    for hash in violations {
        judged.remove(&hash);
        issues.push(AuthorityFoldIssue::InvalidEntry(hash));
    }
    judged
}

/// Whether `entry` names a side row of a world other than its own as a
/// parent, `world_of` giving each parent's world: a row
/// `world_privacy::side_branch_violations` drops before any fold path.
fn hangs_off_another_world(
    entry: &AuthorityLogEntry,
    world_of: impl Fn(&AuthorityEntryHash) -> Option<EntityId>,
) -> bool {
    let world = crate::authority::world_privacy::side_world(&entry.op);
    entry
        .parent_hashes
        .iter()
        .any(|parent| world_of(parent).is_some_and(|parent| world != Some(parent)))
}

/// The whole log's ancestor pairs and counted pairs, as
/// `ancestor_index::entry_ancestor_index` counts them: the image's, and each
/// judged tail row's ancestors over the image's rows and the tail. A row on
/// one parent with known counts adds that parent's ancestry and the parent;
/// any other row walks its ancestry. With each image frontier row's and
/// each judged tail row's ancestors and counted ancestors.
pub(super) fn tail_pairs(
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
/// stale-roster window could start at this install's first sight of a
/// covered revocation, which a vault adopted with no receipt for it never
/// recorded: no clock is imported, so the whole history must decide it. A
/// covered approval on a tail-revoked key is timed past the image instead
/// ([`super::fold_adopted_checkpoint_tail`]).
pub(super) fn approves_on_revoked_key(
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
pub(super) fn image_fold_under(
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
        base_writers: &image.safety.writers,
        missed: Cell::new(false),
    };
    crate::authority::fold_project::project_once(
        Settled {
            merged: Some(image.aggregate.merged.clone()),
            valid_entries: image.fold().valid_entries.clone(),
            by_hash: projected,
            revoke_facts: &image.safety.revoke_facts,
            retired_keys: image.safety.retired_keys.clone(),
            handoff_or_appointment_retired_keys: image
                .safety
                .handoff_or_appointment_retired_keys
                .clone(),
            closed_handoffs: image.safety.closed_handoffs.clone(),
            crossed_revocations: image.safety.crossed_revocations.clone(),
            unsettled: image.safety.unsettled,
            counted_ancestor_pairs: image.safety.counted_pairs,
            issues: image.safety.issues.clone(),
        },
        &rows,
        context,
    )
    .0
}
