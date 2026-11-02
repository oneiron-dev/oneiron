//! A component member's worlds, each folded, and the decision's work, both
//! counted against the bounds the decision once withheld authority at: past
//! one, its scan check is raised and every world is still decided (rule 5).
use super::super::fold::{ProjectEffective, ProjectFold, fold_project};
use super::super::history_policy::{ProjectDependencies, ProjectEvidenceSet};
use super::super::validity::FoldCx;
use super::super::*;
use super::{Hash, Label, Member, Solver, State, World};
use crate::scan_check::{EngineScan, ScanCount};
use std::collections::BTreeMap;

impl Solver<'_, '_, '_> {
    /// Every member's worlds, in member order.
    pub(super) fn all_worlds(&self, conduits: bool) -> Result<Vec<Vec<World>>> {
        (0..self.members.len())
            .map(|index| self.worlds(index, conduits))
            .collect()
    }

    /// Every downward-closed assignment of a member's open states, folded,
    /// however many. Its assignments are counted against the bound times its
    /// open states plus one, and its distinct views against the bound.
    pub(super) fn worlds(&self, index: usize, conduits: bool) -> Result<Vec<World>> {
        let member = &self.members[index];
        if let Some(fixed) = &member.fixed {
            let fold = ProjectFold {
                frontier: fixed.clone(),
                verdicts: BTreeMap::new(),
                dependencies: ProjectDependencies::default(),
                forks: Vec::new(),
                evidence: ProjectEvidenceSet::default(),
            };
            return Ok(vec![World {
                stands: BTreeSet::new(),
                fold,
            }]);
        }
        let open: Vec<&State> = (member.states.iter())
            .filter(|state| member.labels.get(&state.hash) == Some(&Label::Open))
            .collect();
        let limit = self.bound.saturating_mul(open.len() as u64 + 1);
        let mut assignments: Vec<BTreeSet<Hash>> = vec![BTreeSet::new()];
        for state in &open {
            let mut more = Vec::new();
            self.charge(assignments.len() as u64);
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
        }
        let assignment_rows = assignments.len() as u64;
        let scan = EngineScan::ProjectCycleAssignments;
        self.observe(scan, member.id, limit, assignment_rows);
        let mut worlds = Vec::new();
        let mut views: Vec<Option<ProjectEffective>> = Vec::new();
        for stands in assignments {
            let fold = self.fold_world(member, &stands)?;
            self.charge(views.len() as u64);
            if !views.contains(&fold.frontier.effective) {
                views.push(fold.frontier.effective.clone());
            }
            worlds.push(World { stands, fold });
        }
        let view_rows = views.len() as u64;
        let scan = EngineScan::ProjectCycleWorlds;
        self.observe(scan, member.id, self.bound, view_rows);
        Ok(worlds)
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
        super::WORLD_FOLDS.with(|count| count.set(count.get() + 1));
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

    /// Adds `units` to the decision's work.
    pub(super) fn charge(&self, units: u64) {
        self.work.set(self.work.get().saturating_add(units));
    }

    /// Counts `rows` of `scan` for `member` against `threshold`, its bound's
    /// resolved formula: past it the check is raised and the decision reads
    /// on.
    pub(super) fn observe(&self, scan: EngineScan, member: EntityId, threshold: u64, rows: u64) {
        let mut count = ScanCount::start_at(scan, member.as_bytes(), threshold);
        count.rows(usize::try_from(rows).unwrap_or(usize::MAX));
        count.defer(self.reader.store());
    }
}
