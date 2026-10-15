//! The batch-end refresh of each touched project (sections 2 and 6 of the
//! PR 3 contract). It authenticates the revisions whose chain and mint are now
//! held, persists the within-budget fold, freezes a project that passed its
//! budget at its last verified frontier, and, while frozen, applies every
//! valid descendant of the frozen head as a narrowing meet (ruling F2
//! condition 1), so no flood can freeze a replica ahead of a removal.
use super::fold::{ProjectDisposition, ProjectEffective, reason};
use super::history_policy::{
    PROJECT_CYCLE_QUESTION, PROJECT_FRONTIER, PROJECT_FROZEN_APPLIED, PROJECT_FROZEN_WAIT_PROJECT,
    ProjectCycleQuestion, ProjectFreeze, ProjectFrontierRecord, budget_count,
};
use super::read::{ProjectReader, ProjectVerdict};
use super::revision::{
    HeldRevisions, ProjectRevisionHash, REVISION_AWAITING_MINT, REVISIONS, RevisionOrigin,
    authenticate, held_in_txn, slip_id_of,
};
use super::validity::FoldCx;
use super::*;
use crate::store::Store;
use std::collections::BTreeMap;

/// How often one batch end refreshes a project another project's change
/// woke; a project-parent cycle stops here.
const MAX_REFRESH_ROUNDS: u32 = 4;

/// Refreshes every touched project once, with every project its parents tie
/// it to, then each project whose frozen descendants waited on a project
/// whose view changed.
pub(crate) fn refresh_project_frontiers(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    touched: &BTreeSet<EntityId>,
) -> Result<()> {
    if touched.is_empty() {
        return Ok(());
    }
    let Some(kind) = project_type(store) else {
        return Ok(());
    };
    let mut queue = touched.clone();
    let mut rounds: BTreeMap<EntityId, u32> = BTreeMap::new();
    while let Some(project) = queue.pop_first() {
        if rounds
            .get(&project)
            .is_some_and(|round| *round >= MAX_REFRESH_ROUNDS)
        {
            continue;
        }
        // A component is decided as one, so every member's record is written
        // from that one decision (Astra #1434b, r14 F4).
        for (member, changed) in refresh_component(store, txn, posture, kind, project)? {
            *rounds.entry(member).or_default() += 1;
            queue.remove(&member);
            if !changed {
                continue;
            }
            for key in PROJECT_FROZEN_WAIT_PROJECT.scan_keys(store, txn, member.as_bytes())? {
                PROJECT_FROZEN_WAIT_PROJECT.delete(store, txn, &key)?;
                queue.insert(key.1.0);
            }
        }
    }
    Ok(())
}

/// A REVISIONS row: (project, hash) to (companion id, origin).
type Indexed = ((EntityId, ProjectRevisionHash), (EntityId, RevisionOrigin));

/// The indexed revisions whose chain or mint was missing.
fn pending(store: &Store, txn: &heed::RoTxn<'_>, project: EntityId) -> Result<Vec<Indexed>> {
    Ok(REVISIONS
        .scan_from(store, txn, project.as_bytes())?
        .into_iter()
        .filter(|(_, (_, origin))| {
            matches!(
                origin,
                RevisionOrigin::AwaitingParent | RevisionOrigin::AwaitingMint
            )
        })
        .collect())
}

/// Authenticates each indexed revision whose chain and mint are held. Every
/// row is authenticated once: Authenticated and Forged are final.
fn authenticate_pending(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    project: EntityId,
    kind: u8,
) -> Result<()> {
    let indexed = pending(store, txn, project)?;
    if indexed.is_empty() {
        return Ok(());
    }
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let held: HeldRevisions = held_in_txn(store, txn, project, kind)?;
    for (key, (id, before)) in indexed {
        let after = authenticate(&held, &fold, key.1);
        let slip = held.get(&key.1).and_then(|row| slip_id_of(&row.revision));
        if after == before {
            continue;
        }
        REVISIONS.put(store, txn, &key, &(id, after))?;
        if let Some(slip) = slip {
            let wait = (slip, key);
            if after == RevisionOrigin::AwaitingMint {
                REVISION_AWAITING_MINT.put(store, txn, &wait, &())?;
            } else {
                REVISION_AWAITING_MINT.delete(store, txn, &wait)?;
            }
        }
    }
    Ok(())
}

/// What one refresh writes, decided over a read of the transaction.
enum Refresh {
    /// No PROJECT row, or over budget with no record: nothing to keep.
    Nothing,
    Within(Box<ProjectFrontierRecord>),
    Frozen(Box<ProjectFrontierRecord>, Drained),
}

#[derive(Default)]
struct Drained {
    applied: Vec<ProjectRevisionHash>,
    /// (parent project, revision) pairs a parent project's refresh retries.
    waits: Vec<(EntityId, ProjectRevisionHash)>,
}

/// Authenticates `project` and every member of its component, decides the
/// component once, and writes each member's record and the owner's question.
/// Returns each member with whether its served view changed.
fn refresh_component(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    kind: u8,
    project: EntityId,
) -> Result<Vec<(EntityId, bool)>> {
    authenticate_pending(store, txn, posture, project, kind)?;
    let now = crate::ports::recorded_at_in_txn(store, txn)?;
    let mut authenticated = BTreeSet::from([project]);
    let (members, dark, plans) = loop {
        let mut waiting = Vec::new();
        {
            let reader = ProjectReader::new(store, txn, posture)?.ok_or_else(invalid)?;
            let Some(decided) = reader.decide(project)? else {
                return Ok(Vec::new());
            };
            let members = reader.component(project)?.to_vec();
            for member in &members {
                if authenticated.insert(*member) && !pending(store, txn, *member)?.is_empty() {
                    waiting.push(*member);
                }
            }
            if waiting.is_empty() {
                let dark = matches!(&decided.frontier.disposition,
                    ProjectDisposition::Unauthorized { reason } if reason.as_str() == super::fold::reason::CYCLE_BOUND);
                let mut plans = Vec::new();
                for member in &members {
                    plans.push((*member, plan(&reader, store, txn, kind, *member, now)?));
                }
                break (members, dark, plans);
            }
        }
        // A member's newly authenticated rows can change the component.
        for member in waiting {
            authenticate_pending(store, txn, posture, member, kind)?;
        }
    };
    ask_owner(store, txn, &members, dark, now)?;
    let mut changed = Vec::new();
    for (member, plan) in plans {
        changed.push((member, write(store, txn, member, plan)?));
    }
    Ok(changed)
}

/// What one member's refresh writes, read with its old record.
type Plan = (Option<ProjectFrontierRecord>, Refresh);

fn plan(
    reader: &ProjectReader<'_, '_>,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    project: EntityId,
    now: u64,
) -> Result<Plan> {
    let old = PROJECT_FRONTIER.get(store, txn, &project)?;
    let Some(decided) = reader.decide(project)? else {
        return Ok((old, Refresh::Nothing));
    };
    let refresh = if let Some(fold) = &decided.fold {
        Refresh::Within(Box::new(ProjectFrontierRecord {
            witness: fold.frontier.witness.clone(),
            disposition: fold.frontier.disposition.clone(),
            effective: fold.frontier.effective.clone(),
            dependencies: fold.dependencies.clone(),
            evidence: fold.evidence.clone(),
            verified_at: now,
            frozen: None,
        }))
    } else if let Some(mut record) = old.clone() {
        let held = held_in_txn(store, txn, project, kind)?;
        let cx = reader.door_cx(project, &held)?;
        let count = budget_count(&cx)?;
        record.frozen.get_or_insert(ProjectFreeze {
            at_counted: count,
            narrowed: false,
        });
        let applied: BTreeSet<ProjectRevisionHash> = PROJECT_FROZEN_APPLIED
            .scan_keys(store, txn, project.as_bytes())?
            .into_iter()
            .map(|(_, hash)| hash)
            .collect();
        let drained = drain(&cx, &mut record, &applied)?;
        if !drained.applied.is_empty()
            && let Some(freeze) = record.frozen.as_mut()
        {
            freeze.narrowed = true;
        }
        Refresh::Frozen(Box::new(record), drained)
    } else {
        Refresh::Nothing
    };
    Ok((old, refresh))
}

/// Writes one member's planned record; whether its served view changed.
fn write(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    (old, refresh): Plan,
) -> Result<bool> {
    let record = match refresh {
        Refresh::Nothing => return Ok(false),
        Refresh::Within(record) => {
            if old.as_ref().is_some_and(|old| old.frozen.is_some()) {
                PROJECT_FROZEN_APPLIED.delete_from(store, txn, project.as_bytes())?;
            }
            *record
        }
        Refresh::Frozen(record, drained) => {
            for hash in drained.applied {
                PROJECT_FROZEN_APPLIED.put(store, txn, &(project, hash), &())?;
            }
            for (parent, hash) in drained.waits {
                PROJECT_FROZEN_WAIT_PROJECT.put(store, txn, &(parent, (project, hash)), &())?;
            }
            *record
        }
    };
    let changed = old.as_ref().is_none_or(|old| !old.same_view(&record));
    PROJECT_FRONTIER.put(store, txn, &project, &record)?;
    Ok(changed)
}

/// The owner's question about a cycle past its bound (OF-520), kept under
/// each member: raised for a dark component, and removed, with every row of
/// its former component, once a member's component is lit or changed.
fn ask_owner(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    members: &[EntityId],
    dark: bool,
    now: u64,
) -> Result<()> {
    let want = (dark && members.len() > 1).then(|| members.to_vec());
    for member in members {
        let old = PROJECT_CYCLE_QUESTION.get(store, txn, member)?;
        if let Some(old) = &old
            && Some(&old.members) != want.as_ref()
        {
            for other in &old.members {
                let stale = PROJECT_CYCLE_QUESTION
                    .get(store, txn, other)?
                    .is_some_and(|question| question.members == old.members);
                if stale && !members.contains(other) {
                    PROJECT_CYCLE_QUESTION.delete(store, txn, other)?;
                }
            }
        }
        match (&want, old) {
            (Some(want), Some(old)) if old.members == *want => {}
            (Some(want), _) => {
                let question = ProjectCycleQuestion {
                    members: want.clone(),
                    raised_at: now,
                };
                PROJECT_CYCLE_QUESTION.put(store, txn, member, &question)?;
            }
            (None, Some(_)) => {
                PROJECT_CYCLE_QUESTION.delete(store, txn, member)?;
            }
            (None, None) => {}
        }
    }
    Ok(())
}

/// Whether a verdict waits on a parent project's mutable facts.
fn waits_on_parent_project(verdict: ProjectVerdict) -> bool {
    matches!(
        verdict,
        ProjectVerdict::Pending(reason::PARENT_MISSING | reason::PARENT_PENDING)
            | ProjectVerdict::Quarantined(
                reason::PARENT_HIDDEN | reason::EXCEEDS_PARENT | reason::SPAWN
            )
    )
}

/// Applies, as meets, every held descendant of the frozen head that is valid
/// at its own parent now, of any rank and through any intervening board act.
/// Each row is applied once; a child waits on its parent's application, and
/// one whose verdict depends on a parent project waits under that project.
/// Resolutions install nothing here, and leader, board, parents and claims
/// scope never change while frozen.
fn drain(
    cx: &FoldCx<'_, '_, '_>,
    record: &mut ProjectFrontierRecord,
    applied: &BTreeSet<ProjectRevisionHash>,
) -> Result<Drained> {
    let mut drained = Drained::default();
    let Some(head) = record.witness.as_ref().map(|witness| witness.head) else {
        return Ok(drained);
    };
    let Some(effective) = record.effective.as_mut() else {
        return Ok(drained);
    };
    let mut done = applied.clone();
    let mut queue: BTreeSet<ProjectRevisionHash> = std::iter::once(&head)
        .chain(applied)
        .flat_map(|node| cx.held.children_of(node).copied().collect::<Vec<_>>())
        .filter(|child| !done.contains(child))
        .collect();
    while let Some(node) = queue.pop_first() {
        if done.contains(&node) {
            continue;
        }
        let verdict = cx.verdict(node)?;
        let Some(authority) = cx.authority_of(&node) else {
            continue;
        };
        if verdict == ProjectVerdict::Visible {
            ProjectEffective::meet(effective, authority);
            done.insert(node);
            drained.applied.push(node);
            queue.extend(
                cx.held
                    .children_of(&node)
                    .filter(|child| !done.contains(child)),
            );
        } else if waits_on_parent_project(verdict) {
            for parent in lineage_parents(cx, node) {
                drained.waits.push((parent, node));
            }
        }
    }
    Ok(drained)
}

/// Every parent project named along `node`'s held lineage: a verdict that
/// waits on a parent project may come from an ancestor's bounds, so the
/// retry waits on each of them.
fn lineage_parents(cx: &FoldCx<'_, '_, '_>, node: ProjectRevisionHash) -> BTreeSet<EntityId> {
    let mut parents = BTreeSet::new();
    let mut next = Some(node);
    for _ in 0..=MAX_PROJECT_ANCHORS {
        let Some(row) = next.and_then(|at| cx.row(&at)) else {
            break;
        };
        if let Some(authority) = row.authority() {
            parents.extend(
                authority
                    .parents
                    .iter()
                    .filter_map(|parent| EntityId::from_hex(parent).ok()),
            );
        }
        next = row.parent();
    }
    parents
}
