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

/// How often one batch end decides a project: each refresh another
/// project's change woke, each decision again after a frozen member's drain,
/// and each again after a project it read changed. A project-parent cycle,
/// or a chain of drains, stops here.
const MAX_REFRESH_ROUNDS: u32 = 4;

#[cfg(test)]
thread_local! {
    /// The rounds allowed, scaled down for a test.
    pub(super) static REFRESH_ROUNDS: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
    /// How many component decisions this thread's refreshes made.
    pub(super) static DECISIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn max_rounds() -> u32 {
    #[cfg(test)]
    {
        REFRESH_ROUNDS
            .with(std::cell::Cell::get)
            .unwrap_or(MAX_REFRESH_ROUNDS)
    }
    #[cfg(not(test))]
    {
        MAX_REFRESH_ROUNDS
    }
}

/// Refreshes every touched project, with every project its parents tie it
/// to, after each queued project it reads; then each project whose frozen
/// descendants waited on a project whose view changed, each project whose
/// decision read a project that changed after it, and each held child of a
/// touched or changed project.
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
    let mut schedule = Schedule {
        queue: touched.clone(),
        children: held_children(store, txn, kind)?,
        ..Schedule::default()
    };
    // A held re-parent waiting on a touched project's head, mint or lineage
    // is decided again with the same signed bytes (ruling (d)).
    for project in touched {
        schedule.wake_children(*project, &[]);
    }
    // The projects to refresh before the queue's own order.
    let mut ahead = std::collections::VecDeque::new();
    loop {
        let project = match ahead.pop_front() {
            Some(project) if schedule.queue.remove(&project) => project,
            Some(_) => continue,
            None => match schedule.queue.pop_first() {
                Some(project) => project,
                None => break,
            },
        };
        if schedule.spent(&project) {
            continue;
        }
        // A component is decided as one, so every member's record is written
        // from that one decision (Astra #1434b, r14 F4), and after the queued
        // projects it reads, parents first (Sol r18 F2, Astra r18 F1; one
        // walk, Sol r19 F1, Astra r19 F1).
        match refresh_component(store, txn, posture, kind, project, &mut schedule)? {
            Some(parents) => {
                schedule.queue.insert(project);
                schedule.deferred.insert(project);
                ahead.push_front(project);
                for parent in parents.into_iter().rev() {
                    ahead.push_front(parent);
                }
            }
            None => schedule.deferred.clear(),
        }
    }
    Ok(())
}

/// The batch end's queue, the rounds each project has spent, and what each
/// decision read.
#[derive(Default)]
struct Schedule {
    queue: BTreeSet<EntityId>,
    rounds: BTreeMap<EntityId, u32>,
    /// Every project each project's last decision read: one that changes
    /// after it decides it again (Sol r18 F2, Astra r18 F1).
    reads: BTreeMap<EntityId, BTreeSet<EntityId>>,
    /// The projects waiting, since the last refresh, on a queued project
    /// they read; none is waited on in turn.
    deferred: BTreeSet<EntityId>,
    /// Each project's held children: the projects with a held state that
    /// names it as a parent or witnesses one of its heads (ruling (d)).
    children: BTreeMap<EntityId, BTreeSet<EntityId>>,
}

impl Schedule {
    fn spent(&self, project: &EntityId) -> bool {
        self.rounds
            .get(project)
            .is_some_and(|round| *round >= max_rounds())
    }

    /// `project`'s rows or record changed: each project outside `members`
    /// whose decision read it is decided again.
    fn changed(&mut self, project: EntityId, members: &[EntityId]) {
        for (reader, read) in &self.reads {
            if read.contains(&project) && !members.contains(reader) {
                self.queue.insert(*reader);
            }
        }
    }

    /// `project` was touched or changed: each held child of it outside
    /// `members` is decided again.
    fn wake_children(&mut self, project: EntityId, members: &[EntityId]) {
        if let Some(children) = self.children.get(&project) {
            self.queue.extend(
                (children.iter())
                    .filter(|child| !members.contains(child))
                    .copied(),
            );
        }
    }
}

/// Every project's held children, read from held history at the refresh's
/// start: the parents and witnessed parents each project's held states name,
/// whatever those states' verdicts (ruling (d)). No table keeps it, so a
/// restart needs no repair.
fn held_children(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    kind: u8,
) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    let mut children: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
    for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(store, txn, kind, None)? {
        let child = row?;
        for held in held_in_txn(store, txn, child, kind)?.rows.values() {
            let Some(authority) = held.revision.authority() else {
                continue;
            };
            let named = (authority.parents.iter())
                .filter_map(|parent| EntityId::from_hex(parent).ok())
                .chain(authority.parent_heads.iter().map(|witness| witness.project));
            for parent in named.filter(|parent| *parent != child) {
                children.entry(parent).or_default().insert(child);
            }
        }
    }
    Ok(children)
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
/// row is authenticated once: Authenticated and Forged are final. Whether
/// any row's origin changed.
fn authenticate_pending(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    project: EntityId,
    kind: u8,
) -> Result<bool> {
    let indexed = pending(store, txn, project)?;
    if indexed.is_empty() {
        return Ok(false);
    }
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let held: HeldRevisions = held_in_txn(store, txn, project, kind)?;
    let mut changed = false;
    for (key, (id, before)) in indexed {
        let after = authenticate(&held, &fold, key.1);
        let slip = held.get(&key.1).and_then(|row| slip_id_of(&row.revision));
        if after == before {
            continue;
        }
        changed = true;
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
    Ok(changed)
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
/// component once, and writes each member's record and the owner's question
/// from that decision. A frozen member whose drain lands a narrowing changes
/// what the decision read, so its record is written first and the component
/// is decided again (Sol r15 F4). Each decision is a round of every member;
/// at the last round a drain is left for the project's next refresh, so no
/// member's record is written from a decision its drain changed (Sol and
/// Astra r16 F2). A component holding a member that has spent its rounds is
/// not decided again and waits for its next refresh (r17 F2). The queued
/// projects the component reads, outside it, are returned, parents first, to
/// be refreshed before anything is decided (Sol r18 F2, Astra r18 F1).
fn refresh_component(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    kind: u8,
    project: EntityId,
    schedule: &mut Schedule,
) -> Result<Option<Vec<EntityId>>> {
    let now = crate::ports::recorded_at_in_txn(store, txn)?;
    let mut authenticated = BTreeSet::new();
    let mut changed: BTreeMap<EntityId, bool> = BTreeMap::new();
    let mut members = Vec::new();
    loop {
        let first = members.is_empty();
        let decision = decide_component(
            store,
            txn,
            posture,
            (kind, project, now, first),
            &mut authenticated,
            schedule,
        )?;
        let (decided, dark, plans) = match decision {
            Step::After(parents) => return Ok(Some(parents)),
            Step::Spent => break,
            Step::Decided(decision) => decision,
        };
        members = decided;
        let drained: BTreeSet<EntityId> = (plans.iter())
            .filter(|(_, (_, refresh))| {
                matches!(refresh, Refresh::Frozen(_, drained) if !drained.applied.is_empty())
            })
            .map(|(member, _)| *member)
            .collect();
        let mut last = false;
        for member in &members {
            let round = schedule.rounds.entry(*member).or_default();
            *round += 1;
            last |= *round >= max_rounds();
        }
        let settled = drained.is_empty() || members.len() == 1;
        if settled || last {
            ask_owner(store, txn, &members, dark, now)?;
        }
        for (member, plan) in plans {
            // Before the last round only the drains; at it, all but them.
            if settled || drained.contains(&member) != last {
                *changed.entry(member).or_default() |= write(store, txn, member, plan)?;
            }
        }
        if settled || last {
            break;
        }
    }
    // A changed member wakes the frozen rows waiting on it, and decides
    // again each project outside the component that read it.
    for (member, changed) in changed {
        schedule.queue.remove(&member);
        if !changed {
            continue;
        }
        for key in PROJECT_FROZEN_WAIT_PROJECT.scan_keys(store, txn, member.as_bytes())? {
            PROJECT_FROZEN_WAIT_PROJECT.delete(store, txn, &key)?;
            schedule.queue.insert(key.1.0);
        }
        schedule.changed(member, &members);
        schedule.wake_children(member, &members);
    }
    Ok(None)
}

/// A component's members, whether it is dark, and each member's plan.
type Decision = (Vec<EntityId>, bool, Vec<(EntityId, Plan)>);

/// What one attempt at a component's decision came to.
enum Step {
    /// The queued projects the component reads, parents first: refreshed
    /// before it.
    After(Vec<EntityId>),
    /// A member has spent its rounds: nothing is decided.
    Spent,
    Decided(Decision),
}

/// One decision of `project`'s component after every member's pending rows
/// are authenticated, recording what it read. Before the refresh's `first`
/// decision, the queued projects the component reads are refreshed first.
fn decide_component(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    posture: crate::HostingPrivacyPosture,
    (kind, project, now, first): (u8, EntityId, u64, bool),
    authenticated: &mut BTreeSet<EntityId>,
    schedule: &mut Schedule,
) -> Result<Step> {
    loop {
        let mut waiting = Vec::new();
        {
            let reader = ProjectReader::new(store, txn, posture)?.ok_or_else(invalid)?;
            let members = reader.component(project)?.to_vec();
            if first {
                // The component has read every project its parents lead to,
                // closed parents first.
                let ahead: Vec<EntityId> = (reader.parents_first().into_iter())
                    .filter(|id| {
                        !members.contains(id)
                            && schedule.queue.contains(id)
                            && !schedule.spent(id)
                            && !schedule.deferred.contains(id)
                    })
                    .collect();
                if !ahead.is_empty() {
                    return Ok(Step::After(ahead));
                }
            }
            for member in &members {
                if authenticated.insert(*member) && !pending(store, txn, *member)?.is_empty() {
                    waiting.push(*member);
                }
            }
            if waiting.is_empty() {
                if members.iter().any(|member| schedule.spent(member)) {
                    return Ok(Step::Spent);
                }
                #[cfg(test)]
                DECISIONS.with(|count| count.set(count.get() + 1));
                let Some(decided) = reader.decide(project)? else {
                    return Ok(Step::Decided((Vec::new(), false, Vec::new())));
                };
                let dark = matches!(&decided.frontier.disposition,
                    ProjectDisposition::Unauthorized { reason } if reason.as_str() == super::fold::reason::CYCLE_BOUND);
                let mut plans = Vec::new();
                for member in &members {
                    plans.push((*member, plan(&reader, store, txn, kind, *member, now)?));
                }
                let read = reader.read_projects();
                for member in &members {
                    schedule.reads.insert(*member, read.clone());
                }
                return Ok(Step::Decided((members, dark, plans)));
            }
        }
        // A member's newly authenticated rows can change the component, and
        // what every earlier decision read of it.
        for member in waiting {
            if authenticate_pending(store, txn, posture, member, kind)? {
                schedule.changed(member, &[]);
            }
        }
    }
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
        // The crossing: the project freezes, and the owner's question opens.
        record.frozen.get_or_insert(ProjectFreeze {
            at_counted: count,
            narrowed: false,
            raised_at: now,
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
        ProjectVerdict::Pending(
            reason::PARENT_MISSING | reason::PARENT_PENDING | reason::PARENT_HEAD_PENDING
        ) | ProjectVerdict::Quarantined(
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
