//! The covered rows a tail floors past an adopted image (FIX
//! [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY], Astra r4 F1 on #8449; FIX
//! [ADOPTED-FOLD-GATE-TEST]).
//!
//! A tail row that rises past a covered row of its signer and scope on
//! another branch sets that row's floor (`rows_floor`). Where each row it
//! floors is of an op a floor never refuses (`floor_refuses`: a world key
//! record among them), the floor changes no transition and no state: the
//! whole fold counts the row in full and records its `SequenceFork`. The fold
//! past the image then folds the tail as before and records the whole fold's
//! fork block ([`CoveredFloors::issues_past`]). Where a machine removal
//! starts the whole install fold's fold with no vouch
//! (`install_fold::NoVouch`), the live fold past the image applies that
//! fold's cap only where the fold with no vouch provably folds as this one
//! does ([`CoveredFloors::no_vouch_past`]). Everything else still needs
//! history: a floored row of another op or with no carried body, a row that
//! could vouch a floor away, a floored tail row, a tail row with an issue of
//! its own or not counted, a handoff anywhere, and a fold with no vouch this
//! fold cannot stand for.

use std::collections::{BTreeMap, BTreeSet};

use super::super::checkpoint_image::parents_first_of;
use super::*;

/// The covered rows `tail` floors, where the tail's rows of each signer and
/// scope rise above the image's top as one chain (each above, and descending
/// along that scope's rows from, the one below it): each covered row of that
/// scope outside the lowest tail row's ancestry, whose floor that row sets.
/// No tail row then sits past a floor. None where the tail floors no covered
/// row (it fails `rows_floors_unmoved` some other way), where the ancestry
/// walk meets a row the image cannot tell the whole fold judged
/// ([`judged_ancestors`]), or where some row could vouch a floor away
/// ([`vouch_tip_free`]).
///
/// `tail` is the tail's well-signed rows. A row, covered or tail, that names
/// a side row of another world is none of the whole fold's judged rows: it
/// sets no floor and gets none, as in `rows_floors_unmoved`.
pub(super) fn floored_covered_rows(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> Option<BTreeSet<AuthorityEntryHash>> {
    let world_of = |hash: &AuthorityEntryHash| match tail.get(hash) {
        Some(entry) => crate::authority::world_privacy::side_world(&entry.op),
        None => image.rows.get(hash).and_then(|row| row.world),
    };
    let violates = |world: Option<crate::EntityId>, parents: &[AuthorityEntryHash]| {
        parents
            .iter()
            .any(|parent| world_of(parent).is_some_and(|parent_world| world != Some(parent_world)))
    };
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, entry) in tail {
        let world = crate::authority::world_privacy::side_world(&entry.op);
        if !violates(world, &entry.parent_hashes) {
            scopes
                .entry((entry.signer_key(), world))
                .or_default()
                .push((entry.seq, *hash));
        }
    }
    let mut covered = BTreeMap::<_, Vec<AuthorityEntryHash>>::new();
    let mut tops = BTreeMap::<_, u64>::new();
    for (hash, row) in &image.rows {
        let key = (&row.signer, row.world);
        if scopes.contains_key(&key) && !violates(row.world, &row.parents) {
            covered.entry(key).or_default().push(*hash);
            let top = tops.entry(key).or_insert(row.seq);
            *top = (*top).max(row.seq);
        }
    }
    // A judged row's parents, where the image tells the row was judged: a
    // tail row and a covered row neither held rejected nor naming another
    // world's side row.
    let judged_parents = |hash: &AuthorityEntryHash| match tail.get(hash) {
        Some(entry) => (!violates(
            crate::authority::world_privacy::side_world(&entry.op),
            &entry.parent_hashes,
        ))
        .then_some(entry.parent_hashes.as_slice()),
        None => image
            .rows
            .get(hash)
            .filter(|row| !image.holds_rejected(hash) && !violates(row.world, &row.parents))
            .map(|row| row.parents.as_slice()),
    };
    let row = |hash: &AuthorityEntryHash| Some((judged_parents(hash)?, world_of(hash)));
    let mut floored = BTreeSet::new();
    for (key, rows) in &mut scopes {
        rows.sort_unstable();
        let rises = tops.get(key).is_none_or(|top| rows[0].0 > *top)
            && rows.windows(2).all(|pair| {
                pair[0].0 < pair[1].0
                    && crate::authority::rows_floor::descends_within_scope(
                        &pair[0].1,
                        &tail[&pair[1].1].parent_hashes,
                        key.1,
                        row,
                    )
            });
        if !rises {
            return None;
        }
        let Some(below) = covered.get(key) else {
            continue;
        };
        let past = judged_ancestors(&tail[&rows[0].1].parent_hashes, judged_parents)?;
        floored.extend(below.iter().filter(|hash| !past.contains(*hash)).copied());
    }
    (!floored.is_empty() && vouch_tip_free(image, tail, &floored)).then_some(floored)
}

/// The ancestors of a row with `parents`, as the whole fold's ancestor index
/// holds them (`ancestor_index::entry_ancestor_index`, over the judged
/// rows); None where `judged_parents` cannot tell a row's (a row neither
/// covered nor in the tail, a covered row the image holds rejected, which it
/// does not tell from one no fold judged, or a row that names another
/// world's side row). Only an exact ancestry decides which covered rows a
/// tail row floors.
fn judged_ancestors<'a>(
    parents: &'a [AuthorityEntryHash],
    judged_parents: impl Fn(&AuthorityEntryHash) -> Option<&'a [AuthorityEntryHash]>,
) -> Option<BTreeSet<AuthorityEntryHash>> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<_> = parents.iter().collect();
    while let Some(hash) = stack.pop() {
        if seen.insert(*hash) {
            stack.extend(judged_parents(hash)?);
        }
    }
    Some(seen)
}

/// Whether no row could vouch a floored row's floor away
/// (`sequence_ancestry`: a later row of its signer at or above the floor, or
/// a roster row, with the floored row among its ancestors): no row of a
/// floored row's signer above that signer's lowest floored row descends from
/// a floored row, the floored rows themselves aside. A floored row sits below
/// its own floor and is of an op no roster row is (`floor_refuses`), so it
/// vouches for none. Descent follows every covered and tail row's parents,
/// across worlds, a superset of the whole fold's ancestry: a false answer
/// only sends the tail to the whole history.
fn vouch_tip_free(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    floored: &BTreeSet<AuthorityEntryHash>,
) -> bool {
    let signer_seq = |hash: &AuthorityEntryHash| match tail.get(hash) {
        Some(entry) => Some((entry.signer_key(), entry.seq)),
        None => image.rows.get(hash).map(|row| (&row.signer, row.seq)),
    };
    let mut lowest = BTreeMap::<&AuthorityKey, u64>::new();
    for (signer, seq) in floored.iter().filter_map(signer_seq) {
        let low = lowest.entry(signer).or_insert(seq);
        *low = (*low).min(seq);
    }
    let mut children = BTreeMap::<_, Vec<_>>::new();
    let parent_links = image
        .rows
        .iter()
        .map(|(hash, row)| (hash, row.parents.as_slice()))
        .chain(
            tail.iter()
                .map(|(hash, entry)| (hash, entry.parent_hashes.as_slice())),
        );
    for (hash, parents) in parent_links {
        for parent in parents {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    let mut seen = BTreeSet::new();
    let mut stack: Vec<_> = floored.iter().copied().collect();
    while let Some(at) = stack.pop() {
        for child in children.get(&at).into_iter().flatten() {
            if seen.insert(*child) {
                stack.push(*child);
            }
        }
    }
    seen.iter()
        .filter(|hash| !floored.contains(*hash))
        .filter_map(signer_seq)
        .all(|(signer, seq)| lowest.get(signer).is_none_or(|low| seq <= *low))
}

/// Whether every covered row's signer `signer` names signed its covered
/// rows, in each sequence scope (`world_privacy::side_world`), as one chain:
/// sequences strictly rise, and each row descends from the one below it
/// along that scope's rows (`rows_floor::descends_within_scope`). Then none
/// of those signers' covered rows sits past a floor
/// (`rows_floor::rows_sequence_floors`). A row that names a side row of
/// another world is left out and never walked.
///
/// Cost: one parents-first order of the covered rows; then each pair of a
/// signer's rows next to each other in a scope walks only rows that order
/// puts between the two, so one signer's walks in a scope pass each covered
/// row and parent link at most once. Different signers' walks share no such
/// bound (Astra round 2 F1: signers whose rows sit either side of one long
/// chain each walk all of it): the check costs O(K (rows + links) log rows)
/// for the K signers with two or more covered rows in one scope. Each walk
/// stays inside its upper row's ancestry, and a row is the upper of at most
/// one pair, so the check does no more work than building the covered rows'
/// ancestor index (`entry_ancestor_index`) for the whole fold a false answer
/// falls back to. It holds one visited set at a time.
pub(super) fn covered_rows_unfloored(
    image: &AuthorityCheckpointV2,
    signer: impl Fn(&AuthorityKey) -> bool,
) -> bool {
    let violates = |world: Option<crate::EntityId>, parents: &[AuthorityEntryHash]| {
        parents.iter().any(|parent| {
            image
                .rows
                .get(parent)
                .and_then(|parent| parent.world)
                .is_some_and(|parent_world| world != Some(parent_world))
        })
    };
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, row) in &image.rows {
        if signer(&row.signer) && !violates(row.world, &row.parents) {
            scopes
                .entry((&row.signer, row.world))
                .or_default()
                .push((row.seq, *hash));
        }
    }
    if scopes.values().all(|rows| rows.len() < 2) {
        return true;
    }
    let parents: BTreeMap<_, _> = image
        .rows
        .iter()
        .map(|(hash, row)| (*hash, row.parents.clone()))
        .collect();
    let rank: BTreeMap<_, _> = parents_first_of(&parents)
        .into_iter()
        .enumerate()
        .map(|(rank, hash)| (hash, rank))
        .collect();
    scopes.into_iter().all(|((_, world), mut rows)| {
        rows.sort_unstable();
        rows.windows(2).all(|pair| {
            let ((lower_seq, lower), (upper_seq, upper)) = (pair[0], pair[1]);
            // A row before `lower` in the order has no path to it.
            let lower_rank = rank[&lower];
            lower_seq < upper_seq
                && crate::authority::rows_floor::descends_within_scope(
                    &lower,
                    &image.rows[&upper].parents,
                    world,
                    |hash| {
                        let row = image.rows.get(hash)?;
                        (rank[hash] > lower_rank && !violates(row.world, &row.parents))
                            .then_some((row.parents.as_slice(), row.world))
                    },
                )
        })
    })
}

/// What the whole install fold's fold with no vouch
/// (`install_fold::NoVouch`) makes of a fold past an image whose tail floors
/// covered rows ([`CoveredFloors::no_vouch_past`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NoVouchPast {
    /// The fold past the image applies no cap: the tail floors no covered
    /// row, and the fold past the image is as before; or no machine removal
    /// starts a fold with no vouch.
    Idle,
    /// A fold with no vouch runs and folds as this fold does: the live fold
    /// applies its cap (`install_fold::cap_by_identical_no_vouch_fold`). An
    /// image keeps the fold before that cap, as the whole build does.
    Identical,
}

/// The covered rows a tail floors ([`floored_covered_rows`]), and what the
/// image's carried bodies show of the fold past them
/// ([`CoveredFloors::note`]).
#[derive(Default)]
pub(super) struct CoveredFloors {
    floored: BTreeSet<AuthorityEntryHash>,
    /// The floored rows whose carried body is of an op a floor never refuses.
    granting: BTreeSet<AuthorityEntryHash>,
    /// Whether a carried body is a handoff (a re-root).
    handoff: bool,
    /// Whether a carried body removes a machine.
    removal: bool,
    /// The covered rows whose carried body lands restriction only below a
    /// floor or under a hold (`lands_restriction_only`). Every such kind
    /// carries its body (`checkpoint_image::row`).
    restrictions: Vec<AuthorityEntryHash>,
}

impl CoveredFloors {
    pub(super) fn of(floored: BTreeSet<AuthorityEntryHash>) -> Self {
        Self {
            floored,
            ..Self::default()
        }
    }

    /// Whether the tail floors no covered row.
    pub(super) fn is_empty(&self) -> bool {
        self.floored.is_empty()
    }

    /// Notes covered row `hash`, whose carried body is of `op`: only a tail
    /// that floors a covered row reads these.
    pub(super) fn note(&mut self, hash: &AuthorityEntryHash, op: &AuthorityOp) {
        if self.floored.is_empty() {
            return;
        }
        if self.floored.contains(hash) && crate::authority::entry_transition::floor_refuses(op) {
            self.granting.insert(*hash);
        }
        self.handoff |= matches!(op, AuthorityOp::ReRoot { .. });
        self.removal |= crate::authority::revoke_proof::removes_machine(op);
        if crate::authority::entry_transition::lands_restriction_only(op) {
            self.restrictions.push(*hash);
        }
    }

    /// The issues before the projection past the image, for a tail that
    /// floors covered rows and adds no issue of its own: each of the image's
    /// issues but its forks, in the image's order, then one fork block in
    /// hash order, the image's forks and each counted floored row's. The
    /// whole fold records every counted row past its floor in one block,
    /// after every other issue (`fold_engine`); a floored row the image holds
    /// rejected records none.
    pub(super) fn issues_past(&self, image: &AuthorityCheckpointV2) -> Vec<AuthorityFoldIssue> {
        let valid = &image.fold().valid_entries;
        let mut forks: BTreeSet<_> = self
            .floored
            .iter()
            .filter(|hash| valid.contains(*hash))
            .copied()
            .collect();
        let mut issues = Vec::with_capacity(image.safety.issues.len() + forks.len());
        for issue in &image.safety.issues {
            match issue {
                AuthorityFoldIssue::SequenceFork(hash) => {
                    forks.insert(*hash);
                }
                other => issues.push(other.clone()),
            }
        }
        issues.extend(forks.into_iter().map(AuthorityFoldIssue::SequenceFork));
        issues
    }

    /// What the whole install fold's fold with no vouch makes of the tail
    /// past the image, the tail settled into `states` and projected into the
    /// once fold `fold` over the rows read whole, `read_whole`; None where
    /// this fold cannot stand for it.
    ///
    /// Each floored row must carry a body of an op a floor never refuses, so
    /// it counts in full whatever its floor. No handoff may stand anywhere:
    /// its probes judge its line under no floor (`fold_engine`). With no
    /// vouch this install observed, only a machine removal starts a fold with
    /// no vouch, and a floored row of such an op always does then
    /// (`NoVouch::of`). That fold folds as this one where no covered row sits
    /// past a floor before the tail, so the floored rows are the only rows
    /// past one and fold alike under it, a removal's branch with and without
    /// its vouch (`revoke_proof`) among them; where no row that lands
    /// restriction only is left uncounted and the image and the fold hold
    /// none back, so it holds nothing here; where no approval waits on the
    /// stale-roster window, so it sets no deadline; and where every machine
    /// chain's head is live or removed, so it holds no chain
    /// (`NoVouch::uncounted`).
    pub(super) fn no_vouch_past(
        &self,
        image: &AuthorityCheckpointV2,
        tail: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
        observations: &AuthorityLocalObservations,
        states: &BTreeMap<AuthorityEntryHash, FoldState>,
        fold: &AuthorityFold,
        read_whole: &[&AuthorityLogEntry],
    ) -> Option<NoVouchPast> {
        if self.floored.is_empty() {
            return Some(NoVouchPast::Idle);
        }
        let tail_handoff = tail
            .values()
            .any(|entry| matches!(entry.op, AuthorityOp::ReRoot { .. }));
        if self.granting.len() != self.floored.len()
            || self.handoff
            || tail_handoff
            || observations.unvouched
            || !observations.vouched.is_empty()
        {
            return None;
        }
        let tail_removal = tail
            .values()
            .any(|entry| crate::authority::revoke_proof::removes_machine(&entry.op));
        if !self.removal && !tail_removal {
            return Some(NoVouchPast::Idle);
        }
        let valid = &image.fold().valid_entries;
        let counted = self.restrictions.iter().all(|hash| valid.contains(hash))
            && tail.iter().all(|(hash, entry)| {
                !crate::authority::entry_transition::lands_restriction_only(&entry.op)
                    || states.contains_key(hash)
            });
        let heads_stand = fold.machines.values().all(|machine| {
            machine
                .chains()
                .map(|(_, head)| head)
                .chain(&machine.roster_trusted)
                .all(|head| head.is_live() || head.removed)
        });
        let identical = counted
            && heads_stand
            && image.unresolved.held_back.is_empty()
            && fold.install.held_back.is_empty()
            && crate::authority::stale_roster::stale_roster_subject_approvals(read_whole, fold)
                .is_empty()
            && covered_rows_unfloored(image, |_| true);
        identical.then_some(NoVouchPast::Identical)
    }
}
