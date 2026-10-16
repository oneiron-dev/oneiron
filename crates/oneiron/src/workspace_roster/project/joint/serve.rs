//! The served side of a component's decision: each member's frontier,
//! checked under its parents' served views, and the bound's dark answer.
use super::super::fold::{
    ProjectDisposition, ProjectEffective, ProjectFold, ProjectForkConflict, ProjectFrontier,
    ProjectRank, ProjectWitness, rank_at, reason,
};
use super::super::history_policy::{
    ProjectDependencies, ProjectEvidenceSet, counted_set, frozen_frontier,
};
use super::super::read::{Decided, ProjectVerdict};
use super::super::revision::anchor_of;
use super::super::validity::{FoldCx, parent_view};
use super::super::*;
use super::{Hash, Label, Member, Solver, World};
use std::collections::BTreeMap;
use std::rc::Rc;

impl Solver<'_, '_, '_> {
    /// Each member's served frontier, then its parents against the served
    /// views, to a fixpoint.
    pub(super) fn serve(&self, worlds: Vec<Vec<World>>) -> Result<BTreeMap<EntityId, Rc<Decided>>> {
        let mut served: Vec<(ProjectFrontier, Option<ProjectFold>)> = Vec::new();
        for (member, worlds) in self.members.iter().zip(worlds) {
            served.push(self.served(member, worlds)?);
        }
        loop {
            let mut changed = false;
            for index in 0..served.len() {
                let Some(effective) = served[index].0.effective.clone() else {
                    continue;
                };
                if !self.charge(1) {
                    // `solve` answers dark.
                    return Ok(BTreeMap::new());
                }
                if let Err(verdict) = self.parent_bounds(index, &effective, &served)? {
                    let frontier = &mut served[index].0;
                    match &mut frontier.disposition {
                        // As a frozen record that no longer re-checks.
                        ProjectDisposition::OverBudget { state, .. } => state.frozen_head = None,
                        disposition => *disposition = ProjectDisposition::of_verdict(verdict),
                    }
                    frontier.witness = None;
                    frontier.effective = None;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut decided = BTreeMap::new();
        for (member, (frontier, fold)) in self.members.iter().zip(served) {
            let fold = fold.map(|fold| ProjectFold {
                frontier: frontier.clone(),
                ..fold
            });
            decided.insert(
                member.id,
                Rc::new(Decided {
                    frontier,
                    fold,
                    labels: self.labels(member, reason::CYCLE),
                    rehomed: member.rehomed(&BTreeSet::new(), &mut 0),
                }),
            );
        }
        Ok(decided)
    }

    fn served(
        &self,
        member: &Member,
        mut worlds: Vec<World>,
    ) -> Result<(ProjectFrontier, Option<ProjectFold>)> {
        if let Some(fixed) = &member.fixed {
            let fold = if member.facts.over_budget {
                None
            } else {
                Some(ProjectFold {
                    frontier: fixed.clone(),
                    verdicts: self.verdicts(member, reason::CYCLE)?,
                    dependencies: ProjectDependencies::default(),
                    forks: Vec::new(),
                    evidence: ProjectEvidenceSet::default(),
                })
            };
            return Ok((fixed.clone(), fold));
        }
        let verdicts = self.verdicts(member, reason::CYCLE)?;
        let first = worlds.swap_remove(0);
        self.charge(worlds.len() as u64 + 1);
        let agree = worlds.iter().all(|world| {
            world.fold.frontier.disposition == first.fold.frontier.disposition
                && world.fold.frontier.witness == first.fold.frontier.witness
                && world.view() == first.view()
        });
        if agree {
            let path = first.fold.dependencies.path.clone();
            let dependencies = self.combined(path, &first, &worlds, &verdicts);
            let fold = ProjectFold {
                verdicts,
                dependencies,
                ..first.fold
            };
            return Ok((fold.frontier.clone(), Some(fold)));
        }
        let id = member.id;
        let no_authority = |disposition| ProjectFrontier {
            id,
            disposition,
            witness: None,
            effective: None,
        };
        let path = &first.fold.dependencies.path;
        let walks: Vec<BTreeSet<&Hash>> = (worlds.iter())
            .map(|world| world.fold.dependencies.path.iter().collect())
            .collect();
        let read: usize = walks.iter().map(BTreeSet::len).sum();
        self.charge((read + path.len() * (worlds.len() + 1)) as u64);
        let common = path
            .iter()
            .rposition(|node| walks.iter().all(|walk| walk.contains(node)));
        let fold = |frontier: ProjectFrontier, dependencies: ProjectDependencies| ProjectFold {
            frontier,
            verdicts: verdicts.clone(),
            dependencies,
            forks: Vec::new(),
            evidence: first.fold.evidence.clone(),
        };
        let (Some(common), Some(mut effective)) = (common, first.view().clone()) else {
            let frontier = no_authority(ProjectDisposition::unauthorized(reason::CYCLE));
            return Ok((frontier.clone(), Some(fold(frontier, Default::default()))));
        };
        for world in &worlds {
            match world.view() {
                Some(view) => effective.meet_view(view),
                None => {
                    let frontier = no_authority(ProjectDisposition::unauthorized(reason::CYCLE));
                    return Ok((frontier.clone(), Some(fold(frontier, Default::default()))));
                }
            }
        }
        let carrier = path[common];
        let (Some(authority), Some(anchor)) = (
            member
                .facts
                .held
                .get(&carrier)
                .and_then(|row| row.revision.authority()),
            anchor_of(&member.facts.held, carrier),
        ) else {
            let frontier = no_authority(ProjectDisposition::unauthorized(reason::TOO_DEEP));
            return Ok((frontier.clone(), Some(fold(frontier, Default::default()))));
        };
        effective.leader = authority.leader.clone();
        effective.board = authority.board.clone();
        effective.parents = authority.parents.clone();
        effective.claims_scope_ref = authority.claims_scope_ref.clone();
        effective.bound_by_parents = member
            .facts
            .signers
            .get(&carrier)
            .is_some_and(|signer| signer != "host");
        let undefined = (member.labels.iter())
            .filter(|(_, label)| **label == Label::Open)
            .map(|(hash, _)| *hash)
            .collect();
        let forks = self.open_forks(member, carrier, &first, &worlds)?;
        let frontier = ProjectFrontier {
            id,
            disposition: ProjectDisposition::ParentCycle {
                anchor: carrier,
                undefined,
                forks,
            },
            witness: Some(ProjectWitness {
                head: carrier,
                anchor,
            }),
            effective: Some(effective),
        };
        let dependencies = self.combined(path[..=common].to_vec(), &first, &worlds, &verdicts);
        Ok((frontier.clone(), Some(fold(frontier, dependencies))))
    }

    /// The forks a member's disagreeing worlds leave open (ruling (a)): each
    /// world's own tie, and, where the worlds' walks part at the served state
    /// `carrier`, the children they installed there. No world's ranked or
    /// resolved winner is final; the causal tips come from a fold where the
    /// anchor stands.
    fn open_forks(
        &self,
        member: &Member,
        carrier: Hash,
        first: &World,
        others: &[World],
    ) -> Result<Vec<ProjectForkConflict>> {
        let worlds: Vec<&World> = std::iter::once(first).chain(others).collect();
        let mut forks: BTreeMap<Hash, ProjectForkConflict> = BTreeMap::new();
        for world in &worlds {
            let ProjectDisposition::Fork {
                anchor,
                rank,
                contenders,
                resolution_tips,
            } = &world.fold.frontier.disposition
            else {
                continue;
            };
            let fork = forks.entry(*anchor).or_insert_with(|| ProjectForkConflict {
                anchor: *anchor,
                rank: *rank,
                contenders: BTreeSet::new(),
                resolution_tips: BTreeSet::new(),
            });
            fork.rank = fork.rank.max(*rank);
            fork.contenders.extend(contenders.iter().copied());
            fork.resolution_tips.extend(resolution_tips.iter().copied());
        }
        let taken: BTreeSet<Hash> = (worlds.iter())
            .filter_map(|world| {
                let path = &world.fold.dependencies.path;
                let at = path.iter().position(|node| *node == carrier)?;
                path.get(at + 1).copied()
            })
            .collect();
        self.charge(worlds.len() as u64 + taken.len() as u64);
        if taken.len() > 1 {
            let facts = &member.facts;
            let authority = (facts.held.get(&carrier)).and_then(|row| row.revision.authority());
            let rank = (taken.iter())
                .filter_map(|child| rank_at(authority?, facts.signers.get(child)?))
                .max()
                .unwrap_or(ProjectRank::Leader);
            // The carrier stands in every world, so its envelopes are judged
            // as each world judges them.
            let cx = FoldCx::seeded(
                self.reader,
                member.id,
                &facts.held,
                self.labels(member, reason::CYCLE).unwrap_or_default(),
                facts.signers.clone(),
                BTreeMap::new(),
            );
            let tips = cx.resolution_tips(carrier)?;
            self.charge(cx.visits());
            let fork = forks.entry(carrier).or_insert_with(|| ProjectForkConflict {
                anchor: carrier,
                rank,
                contenders: BTreeSet::new(),
                resolution_tips: BTreeSet::new(),
            });
            fork.rank = fork.rank.max(rank);
            fork.contenders.extend(taken);
            fork.resolution_tips.extend(tips);
        }
        Ok(forks.into_values().collect())
    }

    /// Every world's dependencies on one record (Astra #1434c F1): `path`,
    /// and beside it each node any world's walk, settlement or seal rests
    /// on, so freezing drops none. A node the component holds valid is
    /// checked as the fold verifies it; one resting on a state the cycle
    /// left undefined, on its own lineage.
    fn combined(
        &self,
        path: Vec<Hash>,
        first: &World,
        others: &[World],
        verdicts: &BTreeMap<Hash, ProjectVerdict>,
    ) -> ProjectDependencies {
        let worlds: Vec<&World> = std::iter::once(first).chain(others).collect();
        let seal = first.fold.dependencies.seal;
        let mut dependencies = ProjectDependencies {
            path,
            seal: (worlds.iter())
                .all(|world| world.fold.dependencies.seal == seal)
                .then_some(seal)
                .flatten(),
            ..ProjectDependencies::default()
        };
        let mut listed: BTreeSet<Hash> = dependencies.checked().copied().collect();
        for world in worlds {
            let theirs = &world.fold.dependencies;
            self.charge(theirs.checked().count() as u64);
            let beside = (theirs.path.iter())
                .chain(&theirs.contenders)
                .chain(&theirs.seal)
                .map(|hash| (hash, false))
                .chain(theirs.resolutions.iter().map(|hash| (hash, true)));
            for (hash, resolution) in beside {
                if !listed.insert(*hash) {
                    continue;
                }
                if verdicts.get(hash) != Some(&ProjectVerdict::Visible) {
                    dependencies.undefined.push(*hash);
                } else if resolution {
                    dependencies.resolutions.push(*hash);
                } else {
                    dependencies.contenders.push(*hash);
                }
            }
        }
        dependencies
    }

    /// Main's step 4 over the component's served views: each parent serves
    /// authority, a view bound by its parents fits under each, a frozen
    /// member's saved dependencies are each admitted under their parents
    /// (section 6), and no served chain returns to the member.
    fn parent_bounds(
        &self,
        index: usize,
        effective: &ProjectEffective,
        served: &[(ProjectFrontier, Option<ProjectFold>)],
    ) -> Result<std::result::Result<(), ProjectVerdict>> {
        let member = &self.members[index];
        if Some(member.id) == self.reader.root() {
            return Ok(Ok(()));
        }
        if effective.parents.is_empty() {
            return Ok(Err(ProjectVerdict::Quarantined(reason::PARENTLESS)));
        }
        for parent in &effective.parents {
            let parent = EntityId::from_hex(parent)
                .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
            let view = match self.view_of(parent, served)? {
                Ok(view) => view,
                Err(verdict) => return Ok(Err(verdict)),
            };
            if effective.bound_by_parents && !effective.fits_under(&view) {
                return Ok(Err(ProjectVerdict::Quarantined(reason::EXCEEDS_PARENT)));
            }
        }
        if member.facts.over_budget && member.fixed.is_some() {
            // The frozen re-check again, every parent read in the component
            // taking its served view: the closure its saved view rests on
            // (lineage, seal and resolution envelopes) is checked as alone.
            let views: BTreeMap<EntityId, Option<ProjectEffective>> = (self.members.iter())
                .zip(served)
                .map(|(other, (frontier, _))| (other.id, frontier.effective.clone()))
                .collect();
            let facts = &member.facts;
            let cx = FoldCx::under(self.reader, member.id, &facts.held, Rc::new(views));
            let fixed = frozen_frontier(self.reader, &cx, facts.count, self.max_revisions, false)?;
            self.charge(cx.visits() + served.len() as u64);
            if fixed.effective.is_none() {
                return Ok(Err(ProjectVerdict::Quarantined(reason::PARENT_HIDDEN)));
            }
        }
        let mut seen = BTreeSet::from([index]);
        let mut todo = self.inside_parents(&Some(effective.clone()));
        while let Some(at) = todo.pop() {
            if at == index {
                return Ok(Err(ProjectVerdict::Quarantined(reason::CYCLE)));
            }
            if !self.charge(1) {
                // `solve` answers dark.
                return Ok(Ok(()));
            }
            if seen.insert(at) {
                todo.extend(self.inside_parents(&served[at].0.effective));
            }
        }
        Ok(Ok(()))
    }

    /// A parent's served view: a member's from this decision, any other
    /// project's from the reader.
    fn view_of(
        &self,
        parent: EntityId,
        served: &[(ProjectFrontier, Option<ProjectFold>)],
    ) -> Result<std::result::Result<ProjectEffective, ProjectVerdict>> {
        Ok(match self.at.get(&parent) {
            Some(at) => (served[*at].0.effective.clone())
                .ok_or(ProjectVerdict::Quarantined(reason::PARENT_HIDDEN)),
            None => parent_view(self.reader, parent)?,
        })
    }

    /// Every held row's verdict: a state's label (an undefined one refused
    /// for `open`), and each envelope judged from them; a frozen or unsigned
    /// member's rows each on their own lineage.
    fn verdicts(
        &self,
        member: &Member,
        open: &'static str,
    ) -> Result<BTreeMap<Hash, ProjectVerdict>> {
        let labels = self.labels(member, open).unwrap_or_default();
        let facts = &member.facts;
        let cx = FoldCx::seeded(
            self.reader,
            member.id,
            &facts.held,
            labels,
            facts.signers.clone(),
            member.rehomed(&BTreeSet::new(), &mut 0),
        );
        let mut verdicts = BTreeMap::new();
        for hash in facts.held.rows.keys() {
            verdicts.insert(*hash, cx.verdict(*hash)?);
        }
        self.charge(cx.visits());
        Ok(verdicts)
    }

    /// Each state's label, an undefined one refused for `open`.
    fn labels(
        &self,
        member: &Member,
        open: &'static str,
    ) -> Option<BTreeMap<Hash, ProjectVerdict>> {
        member.fixed.is_none().then(|| {
            (member.labels.iter())
                .map(|(hash, label)| {
                    let verdict = match label {
                        Label::Decided(verdict) => *verdict,
                        Label::Open => ProjectVerdict::Quarantined(open),
                    };
                    (*hash, verdict)
                })
                .collect()
        })
    }

    /// Past the world bound or the work budget: no member serves authority.
    pub(super) fn dark(&self) -> Result<BTreeMap<EntityId, Rc<Decided>>> {
        #[cfg(test)]
        if self.spent() {
            super::WORK_DARK.with(|dark| dark.set(dark.get() + 1));
        }
        let mut decided = BTreeMap::new();
        for member in &self.members {
            let frontier = ProjectFrontier {
                id: member.id,
                disposition: ProjectDisposition::unauthorized(reason::CYCLE_BOUND),
                witness: None,
                effective: None,
            };
            let cx = FoldCx::intrinsic(self.reader, member.id, &member.facts.held);
            let fold = (!member.facts.over_budget).then(|| -> Result<ProjectFold> {
                Ok(ProjectFold {
                    frontier: frontier.clone(),
                    verdicts: self.verdicts(member, reason::CYCLE_BOUND)?,
                    dependencies: ProjectDependencies::default(),
                    forks: Vec::new(),
                    evidence: ProjectEvidenceSet::of(None, &counted_set(&cx)?),
                })
            });
            decided.insert(
                member.id,
                Rc::new(Decided {
                    frontier,
                    fold: fold.transpose()?,
                    labels: self.labels(member, reason::CYCLE_BOUND),
                    rehomed: BTreeMap::new(),
                }),
            );
        }
        Ok(decided)
    }
}
