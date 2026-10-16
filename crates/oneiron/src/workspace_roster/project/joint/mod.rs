//! One decision for projects whose parents name each other (Astra #1434b;
//! Engine rulings (a) and (E), PR3-CONTRACT section 5b). The reader stack
//! and entry order play no part: a component of "names as parent" is solved
//! once, as a function of its held revisions, and every door reads it.
//!
//! - A signed state that reads a parent inside the component, or sits over
//!   one that does, is open; every other is judged as before.
//! - A member's world assigns each of its open states stands or not,
//!   downward-closed by lineage. A board successor whose signer sits on the
//!   board of every state down to the first naming no parent in the
//!   component (or the root) is a conduit: it stands on that base alone and
//!   hangs under its nearest standing ancestor, so an open prior installs
//!   nothing.
//! - A state is admitted in a joint world when every parent's view there
//!   admits it and no such view's parent chain returns to its project. A
//!   root is not judged by a view whose chain returns to it: that view names
//!   it, so it came after.
//! - The least fixpoint: valid when admitted in every world, invalid in
//!   none, otherwise undefined. Each member serves the meet of its worlds'
//!   views at the deepest state every world's walk passes, and its parents
//!   are then checked against the served views.
//! - Past the policy's bound on one member's worlds, or on the decision's
//!   work, every member serves no authority, and the refresh raises the
//!   owner's question (OF-520).
use super::fold::{
    ProjectDisposition, ProjectEffective, ProjectFold, ProjectFrontier, ProjectRank, fold_project,
    rank_at, reason, unsigned_frontier,
};
use super::history_policy::{ProjectDependencies, ProjectEvidenceSet, frozen_frontier, policy_in};
use super::read::{Decided, Facts, ProjectReader, ProjectVerdict, stored_verdict};
use super::revision::{ProjectRevision, ProjectRevisionHash};
use super::validity::{FoldCx, parent_view, read_parents, refusal};
use super::*;
use std::collections::BTreeMap;
use std::rc::Rc;

mod serve;

type Hash = ProjectRevisionHash;

/// The decision's work allowed per world the bound admits, for each held row
/// and member of the component: fold visits, reachability scans and
/// served-chain walks.
const WORK_PER_WORLD: u64 = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Label {
    Decided(ProjectVerdict),
    Open,
}

/// One held signed state of a member.
struct State {
    hash: Hash,
    prior: Option<Hash>,
    authority: ProjectAuthority,
    signer: String,
    birth: bool,
    host: bool,
    /// The parents its admission reads in the component: (member, spawned under).
    inside: Vec<(usize, bool)>,
    /// Whether it names a parent in the component, read or not: a host
    /// state reads none past its birth (Astra #1434 r15 F7).
    names_inside: bool,
}

struct Member {
    id: EntityId,
    facts: Rc<Facts>,
    /// Signed states, each after its prior.
    states: Vec<State>,
    labels: BTreeMap<Hash, Label>,
    /// The base each board conduit stands on.
    conduits: BTreeMap<Hash, Hash>,
    /// A frozen or unsigned member's one frontier, or one whose seals
    /// conflict; a frozen one's parent reads are checked again under the
    /// served views (`serve`).
    fixed: Option<ProjectFrontier>,
}

/// One world of a member: the open states that stand, and its fold.
struct World {
    stands: BTreeSet<Hash>,
    fold: ProjectFold,
}

impl World {
    fn view(&self) -> &Option<ProjectEffective> {
        &self.fold.frontier.effective
    }
}

struct Solver<'s, 'a, 't> {
    reader: &'s ProjectReader<'a, 't>,
    members: Vec<Member>,
    at: BTreeMap<EntityId, usize>,
    bound: u64,
    max_revisions: u64,
    /// Work spent, and the most the decision may spend before it serves no
    /// authority.
    work: std::cell::Cell<u64>,
    budget: u64,
}

/// Decides every member of one component.
pub(super) fn solve(
    reader: &ProjectReader<'_, '_>,
    ids: &[EntityId],
) -> Result<BTreeMap<EntityId, Rc<Decided>>> {
    let policy = policy_in(reader.store(), reader.txn())?;
    let at: BTreeMap<EntityId, usize> = (ids.iter().enumerate())
        .map(|(index, id)| (*id, index))
        .collect();
    let mut solver = Solver {
        reader,
        members: Vec::new(),
        at,
        bound: policy.cycle_worlds_max,
        max_revisions: policy.max_revisions,
        work: std::cell::Cell::new(0),
        budget: 0,
    };
    let mut size = ids.len() as u64;
    for id in ids {
        let member = solver.member(*id, policy.max_revisions)?;
        size += member.facts.held.rows.len() as u64;
        solver.members.push(member);
    }
    #[cfg(test)]
    let per_world = WORK_SCALE
        .with(std::cell::Cell::get)
        .unwrap_or(WORK_PER_WORLD);
    #[cfg(not(test))]
    let per_world = WORK_PER_WORLD;
    solver.budget = (solver.bound)
        .saturating_mul(per_world)
        .saturating_mul(size);
    solver.decide_outside()?;
    let Some(plain) = solver.all_worlds(false)? else {
        return solver.dark();
    };
    solver.find_conduits(&plain);
    let Some(mut worlds) = solver.all_worlds(true)? else {
        return solver.dark();
    };
    loop {
        let changed = solver.step(&worlds);
        if solver.spent() {
            return solver.dark();
        }
        if changed.is_empty() {
            let decided = solver.serve(worlds)?;
            return if solver.spent() {
                solver.dark()
            } else {
                Ok(decided)
            };
        }
        // A member's worlds read only its own labels.
        for index in changed {
            match solver.worlds(index, true)? {
                Some(member) => worlds[index] = member,
                None => return solver.dark(),
            }
        }
    }
}

impl Solver<'_, '_, '_> {
    fn member(&self, id: EntityId, max_revisions: u64) -> Result<Member> {
        let facts = self.reader.facts(id)?.ok_or_else(invalid)?;
        let mut member = Member {
            id,
            facts: Rc::clone(&facts),
            states: Vec::new(),
            labels: BTreeMap::new(),
            conduits: BTreeMap::new(),
            fixed: None,
        };
        if facts.over_budget {
            let cx = FoldCx::intrinsic(self.reader, id, &facts.held);
            let fixed = frozen_frontier(self.reader, &cx, facts.count, max_revisions, false)?;
            self.charge(cx.visits());
            member.fixed = Some(fixed);
            return Ok(member);
        }
        if !facts.signed {
            // Main's stored-row rule without its parent reads, which the
            // component makes below; a signed row with no held history
            // serves nothing here.
            let verdict = match facts.record.write_proof {
                None => stored_verdict(self.reader, id, &facts.record.authority())?,
                Some(_) => ProjectVerdict::Quarantined(reason::CYCLE),
            };
            member.fixed = Some(unsigned_frontier(id, &facts.record, verdict)?);
            return Ok(member);
        }
        if facts.seals.len() > 1 {
            // Conflicting owner seals, none of them retired: no authority,
            // and no state of it reads a parent (Astra #1434c F2).
            member.fixed = Some(ProjectFrontier {
                id,
                disposition: ProjectDisposition::ConflictingSeals {
                    seals: facts.seals.clone(),
                },
                witness: None,
                effective: None,
            });
            return Ok(member);
        }
        let mut order: Vec<(usize, Hash)> = Vec::new();
        for (hash, row) in &facts.held.rows {
            let Some(verdict) = facts.intrinsic.get(hash) else {
                continue;
            };
            if row.revision.authority().is_none() {
                continue;
            }
            // Outside the owner's seal nothing is judged with its parents, so
            // a world whose seal fails serves nothing rather than walk it.
            let sealed = facts.sealed.as_ref();
            if sealed.is_some_and(|tree| !tree.contains(hash)) {
                let off = ProjectVerdict::Quarantined(reason::SEALED_OFF);
                member.labels.insert(*hash, Label::Decided(off));
                continue;
            }
            member.labels.insert(*hash, Label::Decided(*verdict));
            // Only a state valid on its own lineage reads parents here.
            if matches!(row.revision, ProjectRevision::Signed { .. })
                && *verdict == ProjectVerdict::Visible
            {
                let mut depth = 0;
                let mut at = row.revision.parent();
                while let Some(prior) = at.filter(|_| depth <= 4 * MAX_PROJECT_ANCHORS) {
                    depth += 1;
                    at = facts.held.get(&prior).and_then(|row| row.revision.parent());
                }
                self.charge(depth as u64 + 1);
                order.push((depth, *hash));
            }
        }
        order.sort();
        for (_, hash) in order {
            let Some(ProjectRevision::Signed {
                authority, parent, ..
            }) = facts.held.get(&hash).map(|row| &row.revision)
            else {
                continue;
            };
            let signer = facts.signers.get(&hash).cloned().unwrap_or_default();
            let host = signer == "host";
            let mut inside = Vec::new();
            for (parent_id, spawned_under) in read_parents(authority, parent.is_none(), host)? {
                if let Some(index) = self.at.get(&parent_id) {
                    inside.push((*index, spawned_under));
                }
            }
            let names_inside = (authority.parents.iter())
                .filter_map(|parent| EntityId::from_hex(parent).ok())
                .any(|parent| self.at.contains_key(&parent));
            member.states.push(State {
                hash,
                prior: *parent,
                authority: authority.clone(),
                signer,
                birth: parent.is_none(),
                host,
                inside,
                names_inside,
            });
        }
        Ok(member)
    }

    /// Judges every state whose standing no other member decides, in
    /// lineage order; the rest open.
    fn decide_outside(&mut self) -> Result<()> {
        for index in 0..self.members.len() {
            for at in 0..self.members[index].states.len() {
                let label = self.first_label(index, at)?;
                let hash = self.members[index].states[at].hash;
                self.members[index].labels.insert(hash, label);
            }
        }
        Ok(())
    }

    fn first_label(&self, index: usize, at: usize) -> Result<Label> {
        let member = &self.members[index];
        let state = &member.states[at];
        let intrinsic = member.labels.get(&state.hash).copied();
        if intrinsic != Some(Label::Decided(ProjectVerdict::Visible)) {
            return Ok(
                intrinsic.unwrap_or(Label::Decided(ProjectVerdict::Pending(reason::NOT_HELD)))
            );
        }
        let prior = state
            .prior
            .and_then(|prior| member.labels.get(&prior).copied());
        if let Some(Label::Decided(verdict)) = prior
            && verdict != ProjectVerdict::Visible
        {
            return Ok(Label::Decided(verdict));
        }
        let birth = state.birth;
        self.charge(state.authority.parents.len() as u64 + 1);
        for (parent, spawned_under) in read_parents(&state.authority, birth, state.host)? {
            if self.at.contains_key(&parent) {
                continue;
            }
            let view = match parent_view(self.reader, parent)? {
                Ok(view) => view,
                Err(verdict) => return Ok(Label::Decided(verdict)),
            };
            let why = refusal(
                &view,
                &state.authority,
                &state.signer,
                spawned_under,
                state.host,
            );
            if let Some(why) = why {
                return Ok(Label::Decided(ProjectVerdict::Quarantined(why)));
            }
        }
        Ok(if !state.inside.is_empty() || prior == Some(Label::Open) {
            Label::Open
        } else {
            Label::Decided(ProjectVerdict::Visible)
        })
    }

    /// Each open board successor's conduit base, if any (ruling (a), the
    /// settle leg): the successor leaves the cycle (it names no parent in the
    /// component), its signer sits on the board of its prior and of every
    /// state down to the first naming no parent in the component, or the
    /// root, and each state on the way is open and fits some plain view of
    /// every parent in the component it reads.
    fn find_conduits(&mut self, plain: &[Vec<World>]) {
        for index in 0..self.members.len() {
            let mut conduits = BTreeMap::new();
            let member = &self.members[index];
            let states: BTreeMap<Hash, &State> = (member.states.iter())
                .map(|state| (state.hash, state))
                .collect();
            for state in &member.states {
                let Some(prior) = state.prior else {
                    continue;
                };
                if state.names_inside
                    || member.labels.get(&state.hash) != Some(&Label::Open)
                    || member.labels.get(&prior) != Some(&Label::Open)
                {
                    continue;
                }
                let seated = |authority: &ProjectAuthority| {
                    state.host || rank_at(authority, &state.signer) == Some(ProjectRank::Board)
                };
                let mut at = prior;
                let base = loop {
                    let Some(ancestor) = states.get(&at) else {
                        break None;
                    };
                    let scan: usize = (ancestor.inside.iter())
                        .map(|(parent, _)| plain[*parent].len())
                        .sum();
                    if !self.charge(scan as u64 + 1) {
                        break None;
                    }
                    if !seated(&ancestor.authority) {
                        break None;
                    }
                    if !ancestor.names_inside {
                        break Some(at);
                    }
                    let fits = (ancestor.inside.iter()).all(|(parent, spawned_under)| {
                        plain[*parent].iter().any(|world| {
                            world.view().as_ref().is_some_and(|view| {
                                refusal(
                                    view,
                                    &ancestor.authority,
                                    &ancestor.signer,
                                    *spawned_under,
                                    ancestor.host,
                                )
                                .is_none()
                            })
                        })
                    });
                    if !fits || member.labels.get(&at) != Some(&Label::Open) {
                        break None;
                    }
                    match ancestor.prior {
                        None => break Some(at),
                        Some(next) => at = next,
                    }
                };
                if let Some(base) = base {
                    conduits.insert(state.hash, base);
                }
            }
            self.members[index].conduits = conduits;
        }
    }

    fn all_worlds(&self, conduits: bool) -> Result<Option<Vec<Vec<World>>>> {
        let mut all = Vec::new();
        for index in 0..self.members.len() {
            if self.spent() {
                return Ok(None);
            }
            match self.worlds(index, conduits)? {
                Some(worlds) => all.push(worlds),
                None => return Ok(None),
            }
        }
        Ok(Some(all))
    }

    /// Every downward-closed assignment of a member's open states, folded;
    /// `None` past the bound or the work budget.
    fn worlds(&self, index: usize, conduits: bool) -> Result<Option<Vec<World>>> {
        let member = &self.members[index];
        if let Some(fixed) = &member.fixed {
            let fold = ProjectFold {
                frontier: fixed.clone(),
                verdicts: BTreeMap::new(),
                dependencies: ProjectDependencies::default(),
                forks: Vec::new(),
                evidence: ProjectEvidenceSet::default(),
            };
            return Ok(Some(vec![World {
                stands: BTreeSet::new(),
                fold,
            }]));
        }
        let open: Vec<&State> = (member.states.iter())
            .filter(|state| member.labels.get(&state.hash) == Some(&Label::Open))
            .collect();
        let limit = self.bound.saturating_mul(open.len() as u64 + 1);
        let mut assignments: Vec<BTreeSet<Hash>> = vec![BTreeSet::new()];
        for state in &open {
            let mut more = Vec::new();
            if !self.charge(assignments.len() as u64) {
                return Ok(None);
            }
            for assigned in &assignments {
                let on =
                    |hash: &Option<Hash>| hash.is_none_or(|hash| member.stands(&hash, assigned));
                let base = conduits
                    .then(|| member.conduits.get(&state.hash).copied())
                    .flatten();
                if on(&state.prior) || base.is_some_and(|base| member.stands(&base, assigned)) {
                    self.charge(assigned.len() as u64);
                    let mut with = assigned.clone();
                    with.insert(state.hash);
                    more.push(with);
                }
            }
            assignments.extend(more);
            if assignments.len() as u64 > limit {
                return Ok(None);
            }
        }
        let mut worlds = Vec::new();
        let mut views: Vec<Option<ProjectEffective>> = Vec::new();
        for stands in assignments {
            let fold = self.fold_world(member, &stands)?;
            if !self.charge(views.len() as u64) {
                return Ok(None);
            }
            if !views.contains(&fold.frontier.effective) {
                views.push(fold.frontier.effective.clone());
                if views.len() as u64 > self.bound {
                    return Ok(None);
                }
            }
            worlds.push(World { stands, fold });
        }
        Ok(Some(worlds))
    }

    fn fold_world(&self, member: &Member, stands: &BTreeSet<Hash>) -> Result<ProjectFold> {
        let facts = &member.facts;
        let mut verdicts = BTreeMap::new();
        for (hash, label) in &member.labels {
            verdicts.insert(*hash, member.verdict_in(hash, *label, stands));
        }
        let mut walked = 0;
        let rehomed = member.rehomed(stands, &mut walked);
        self.charge(walked);
        #[cfg(test)]
        WORLD_FOLDS.with(|count| count.set(count.get() + 1));
        let cx = FoldCx::seeded(
            self.reader,
            member.id,
            &facts.held,
            verdicts,
            facts.signers.clone(),
            rehomed,
        );
        let fold = fold_project(&cx, &facts.record);
        self.charge(cx.visits() + facts.held.rows.len() as u64);
        fold
    }

    /// Adds `units` of work; whether the decision is still within its budget.
    fn charge(&self, units: u64) -> bool {
        self.work.set(self.work.get().saturating_add(units));
        !self.spent()
    }

    fn spent(&self) -> bool {
        self.work.get() > self.budget
    }

    /// One Kleene step over every open state at once; the members whose
    /// labels changed. It stops early once the work budget is spent.
    fn step(&mut self, worlds: &[Vec<World>]) -> BTreeSet<usize> {
        let candidates: Vec<Vec<Option<ProjectEffective>>> = worlds
            .iter()
            .map(|worlds| {
                let mut views: Vec<Option<ProjectEffective>> = Vec::new();
                for world in worlds {
                    self.charge(views.len() as u64 + 1);
                    if !views.contains(world.view()) {
                        views.push(world.view().clone());
                    }
                }
                views
            })
            .collect();
        let mut next = Vec::new();
        for (index, member) in self.members.iter().enumerate() {
            for state in &member.states {
                if member.labels.get(&state.hash) != Some(&Label::Open) {
                    continue;
                }
                if self.spent() {
                    return BTreeSet::new();
                }
                let label = self.judge(index, state, &worlds[index], &candidates);
                if label != Label::Open {
                    next.push((index, state.hash, label));
                }
            }
        }
        let mut changed = BTreeSet::new();
        for (index, hash, label) in next {
            self.members[index].labels.insert(hash, label);
            changed.insert(index);
        }
        changed
    }

    fn judge(
        &self,
        index: usize,
        state: &State,
        own: &[World],
        candidates: &[Vec<Option<ProjectEffective>>],
    ) -> Label {
        let member = &self.members[index];
        let base = member.conduits.get(&state.hash).copied();
        let lineage = |world: &World| {
            state
                .prior
                .is_none_or(|prior| member.stands(&prior, &world.stands))
                || base.is_some_and(|base| member.stands(&base, &world.stands))
        };
        let scans: usize = (state.inside.iter())
            .map(|(parent, _)| candidates[*parent].len())
            .sum();
        self.charge(2 * own.len() as u64 + 3 * scans as u64);
        let (every, some) = (own.iter().all(lineage), own.iter().any(lineage));
        let admits = |view: &Option<ProjectEffective>, spawned_under: bool| {
            view.as_ref().is_some_and(|view| {
                refusal(
                    view,
                    &state.authority,
                    &state.signer,
                    spawned_under,
                    state.host,
                )
                .is_none()
            })
        };
        // Some joint world admits it with no chain returning.
        let free = self.avoiding(index, candidates, |member, view| {
            (state.inside.iter())
                .find(|(parent, _)| *parent == member)
                .is_none_or(|(_, spawned_under)| admits(view, *spawned_under))
        });
        let exists = (state.inside.iter()).all(|(parent, _)| free.contains(parent));
        let all = (state.inside.iter()).all(|(parent, spawned_under)| {
            candidates[*parent].iter().all(|view| {
                let only = |member: usize, other: &Option<ProjectEffective>| {
                    member != *parent || other == view
                };
                if state.birth {
                    // A view whose chain must return names this root, so it
                    // came after it and does not judge it.
                    admits(view, *spawned_under) || !self.can_avoid(index, view, candidates, only)
                } else {
                    admits(view, *spawned_under) && !self.can_return(index, view, candidates, only)
                }
            })
        });
        let judged = !state.birth
            || (state.inside.iter()).all(|(parent, _)| {
                self.avoiding(index, candidates, |_, _| true)
                    .contains(parent)
            });
        // A state falls on its bounds, not the cycle, when some parent has a
        // view whose chain can stay clear of it and none such admits it.
        let fits_none = (state.inside.iter()).any(|(parent, spawned_under)| {
            let clear: Vec<&Option<ProjectEffective>> = (candidates[*parent].iter())
                .filter(|view| {
                    self.can_avoid(index, view, candidates, |member, other| {
                        member != *parent || other == *view
                    })
                })
                .collect();
            !clear.is_empty() && clear.iter().all(|view| !admits(view, *spawned_under))
        });
        if every && all && judged {
            Label::Decided(ProjectVerdict::Visible)
        } else if !some || !exists {
            Label::Decided(ProjectVerdict::Quarantined(if some && fits_none {
                reason::EXCEEDS_PARENT
            } else {
                reason::CYCLE
            }))
        } else {
            Label::Open
        }
    }

    fn inside_parents(&self, view: &Option<ProjectEffective>) -> Vec<usize> {
        view.iter()
            .flat_map(|view| view.parents.iter())
            .filter_map(|parent| EntityId::from_hex(parent).ok())
            .filter_map(|parent| self.at.get(&parent).copied())
            .collect()
    }

    /// The members whose chains can all stay clear of `target`: the largest
    /// set whose every member has an allowed view with every parent in the
    /// component inside the set.
    fn avoiding(
        &self,
        target: usize,
        candidates: &[Vec<Option<ProjectEffective>>],
        allowed: impl Fn(usize, &Option<ProjectEffective>) -> bool,
    ) -> BTreeSet<usize> {
        let mut set: BTreeSet<usize> = (0..self.members.len())
            .filter(|member| *member != target)
            .collect();
        loop {
            let scan: usize = set.iter().map(|member| candidates[*member].len()).sum();
            if !self.charge(set.len() as u64 + scan as u64) {
                return BTreeSet::new();
            }
            let keep: BTreeSet<usize> = (set.iter().copied())
                .filter(|member| {
                    candidates[*member].iter().any(|view| {
                        allowed(*member, view)
                            && self
                                .inside_parents(view)
                                .iter()
                                .all(|parent| set.contains(parent))
                    })
                })
                .collect();
            if keep == set {
                return set;
            }
            set = keep;
        }
    }

    fn can_avoid(
        &self,
        target: usize,
        view: &Option<ProjectEffective>,
        candidates: &[Vec<Option<ProjectEffective>>],
        allowed: impl Fn(usize, &Option<ProjectEffective>) -> bool,
    ) -> bool {
        let free = self.avoiding(target, candidates, allowed);
        (self.inside_parents(view).iter()).all(|parent| free.contains(parent))
    }

    /// Whether some choice of views leads `view`'s parent chain back to `target`.
    fn can_return(
        &self,
        target: usize,
        view: &Option<ProjectEffective>,
        candidates: &[Vec<Option<ProjectEffective>>],
        allowed: impl Fn(usize, &Option<ProjectEffective>) -> bool,
    ) -> bool {
        let mut seen = BTreeSet::new();
        let mut todo = self.inside_parents(view);
        while let Some(member) = todo.pop() {
            if !self.charge(1) {
                return false;
            }
            if member == target {
                return true;
            }
            if !seen.insert(member) || !self.charge(candidates[member].len() as u64) {
                continue;
            }
            for other in &candidates[member] {
                if allowed(member, other) {
                    todo.extend(self.inside_parents(other));
                }
            }
        }
        false
    }
}

impl Member {
    /// Where each standing state over a fallen prior hangs: a conduit, decided
    /// or assigned, under its nearest standing ancestor.
    /// `walked` counts the ancestors the walks pass.
    fn rehomed(&self, assigned: &BTreeSet<Hash>, walked: &mut u64) -> BTreeMap<Hash, Vec<Hash>> {
        let mut rehomed: BTreeMap<Hash, Vec<Hash>> = BTreeMap::new();
        for state in &self.states {
            let Some(prior) = state.prior else {
                continue;
            };
            if !self.stands(&state.hash, assigned) || self.stands(&prior, assigned) {
                continue;
            }
            let held = &self.facts.held;
            let mut at = prior;
            while !self.stands(&at, assigned) {
                *walked += 1;
                match held.get(&at).and_then(|row| row.revision.parent()) {
                    Some(next) => at = next,
                    None => break,
                }
            }
            rehomed.entry(at).or_default().push(state.hash);
        }
        rehomed
    }

    fn stands(&self, hash: &Hash, assigned: &BTreeSet<Hash>) -> bool {
        match self.labels.get(hash) {
            Some(Label::Decided(verdict)) => *verdict == ProjectVerdict::Visible,
            Some(Label::Open) => assigned.contains(hash),
            None => false,
        }
    }

    fn verdict_in(&self, hash: &Hash, label: Label, stands: &BTreeSet<Hash>) -> ProjectVerdict {
        match label {
            Label::Decided(verdict) => verdict,
            Label::Open if stands.contains(hash) => ProjectVerdict::Visible,
            Label::Open => ProjectVerdict::Quarantined(reason::CYCLE),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// How many member worlds this thread folded: a component's work is
    /// linear in its held history (Engine ruling, the 200-chain check).
    pub(super) static WORLD_FOLDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The work allowed per world, scaled down for a test.
    pub(super) static WORK_SCALE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    /// How many decisions went dark past the work budget, not the world bound.
    pub(super) static WORK_DARK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
