//! The served side of a component's decision: each member's frontier,
//! checked under its parents' served views, and the bound's dark answer.
use super::super::fold::{
    ProjectDisposition, ProjectEffective, ProjectFold, ProjectFrontier, ProjectWitness, reason,
};
use super::super::history_policy::{ProjectDependencies, ProjectEvidenceSet, counted_set};
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
                if let Err(verdict) = self.parent_bounds(index, &effective, &served)? {
                    let frontier = &mut served[index].0;
                    frontier.disposition = ProjectDisposition::of_verdict(verdict);
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
            if let Some(fold) = &fold {
                self.reader.publish_forks(&fold.forks);
            }
            decided.insert(
                member.id,
                Rc::new(Decided {
                    frontier,
                    fold,
                    labels: self.labels(member),
                    rehomed: member.rehomed(&BTreeSet::new()),
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
            let fold = (!member.facts.over_budget).then(|| ProjectFold {
                frontier: fixed.clone(),
                verdicts: BTreeMap::new(),
                dependencies: ProjectDependencies::default(),
                forks: Vec::new(),
                evidence: ProjectEvidenceSet::default(),
            });
            return Ok((fixed.clone(), fold));
        }
        let verdicts = self.verdicts(member)?;
        let first = worlds.swap_remove(0);
        let agree = worlds.iter().all(|world| {
            world.fold.frontier.disposition == first.fold.frontier.disposition
                && world.fold.frontier.witness == first.fold.frontier.witness
                && world.view() == first.view()
        });
        if agree {
            let fold = ProjectFold {
                verdicts,
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
        let common = path.iter().rposition(|node| {
            (worlds.iter()).all(|world| world.fold.dependencies.path.contains(node))
        });
        let fold = |frontier: ProjectFrontier, path: Vec<Hash>| ProjectFold {
            frontier,
            verdicts: verdicts.clone(),
            dependencies: ProjectDependencies {
                path,
                ..ProjectDependencies::default()
            },
            forks: Vec::new(),
            evidence: first.fold.evidence.clone(),
        };
        let (Some(common), Some(mut effective)) = (common, first.view().clone()) else {
            let frontier = no_authority(ProjectDisposition::unauthorized(reason::CYCLE));
            return Ok((frontier.clone(), Some(fold(frontier, Vec::new()))));
        };
        for world in &worlds {
            match world.view() {
                Some(view) => effective.meet_view(view),
                None => {
                    let frontier = no_authority(ProjectDisposition::unauthorized(reason::CYCLE));
                    return Ok((frontier.clone(), Some(fold(frontier, Vec::new()))));
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
            return Ok((frontier.clone(), Some(fold(frontier, Vec::new()))));
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
        let frontier = ProjectFrontier {
            id,
            disposition: ProjectDisposition::ParentCycle {
                anchor: carrier,
                undefined,
            },
            witness: Some(ProjectWitness {
                head: carrier,
                anchor,
            }),
            effective: Some(effective),
        };
        Ok((
            frontier.clone(),
            Some(fold(frontier, path[..=common].to_vec())),
        ))
    }

    /// Main's step 4 over the component's served views: each parent serves
    /// authority, a view bound by its parents fits under each, and no
    /// served chain returns to the member.
    fn parent_bounds(
        &self,
        index: usize,
        effective: &ProjectEffective,
        served: &[(ProjectFrontier, Option<ProjectFold>)],
    ) -> Result<std::result::Result<(), ProjectVerdict>> {
        let id = self.members[index].id;
        if Some(id) == self.reader.root() {
            return Ok(Ok(()));
        }
        if effective.parents.is_empty() {
            return Ok(Err(ProjectVerdict::Quarantined(reason::PARENTLESS)));
        }
        for parent in &effective.parents {
            let parent = EntityId::from_hex(parent)
                .map_err(|_| RecordError::InvalidProjectBody("invalid parent id"))?;
            let view = match self.at.get(&parent) {
                Some(at) => match &served[*at].0.effective {
                    Some(view) => view.clone(),
                    None => return Ok(Err(ProjectVerdict::Quarantined(reason::PARENT_HIDDEN))),
                },
                None => match parent_view(self.reader, parent)? {
                    Ok(view) => view,
                    Err(verdict) => return Ok(Err(verdict)),
                },
            };
            if effective.bound_by_parents && !effective.fits_under(&view) {
                return Ok(Err(ProjectVerdict::Quarantined(reason::EXCEEDS_PARENT)));
            }
        }
        let mut seen = BTreeSet::from([index]);
        let mut todo = self.inside_parents(&Some(effective.clone()));
        while let Some(at) = todo.pop() {
            if at == index {
                return Ok(Err(ProjectVerdict::Quarantined(reason::CYCLE)));
            }
            if seen.insert(at) {
                todo.extend(self.inside_parents(&served[at].0.effective));
            }
        }
        Ok(Ok(()))
    }

    /// Every held row's verdict: a state's label (an undefined one is a
    /// cycle's), and each envelope judged from them.
    fn verdicts(&self, member: &Member) -> Result<BTreeMap<Hash, ProjectVerdict>> {
        let labels = self.labels(member).unwrap_or_default();
        let facts = &member.facts;
        let cx = FoldCx::seeded(
            self.reader,
            member.id,
            &facts.held,
            labels,
            facts.signers.clone(),
            member.rehomed(&BTreeSet::new()),
        );
        let mut verdicts = BTreeMap::new();
        for hash in facts.held.rows.keys() {
            verdicts.insert(*hash, cx.verdict(*hash)?);
        }
        Ok(verdicts)
    }

    fn labels(&self, member: &Member) -> Option<BTreeMap<Hash, ProjectVerdict>> {
        member.fixed.is_none().then(|| {
            (member.labels.iter())
                .map(|(hash, label)| {
                    let verdict = match label {
                        Label::Decided(verdict) => *verdict,
                        Label::Open => ProjectVerdict::Quarantined(reason::CYCLE),
                    };
                    (*hash, verdict)
                })
                .collect()
        })
    }

    /// Past the bound: no member serves authority.
    pub(super) fn dark(&self) -> Result<BTreeMap<EntityId, Rc<Decided>>> {
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
                    verdicts: BTreeMap::new(),
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
                    labels: self.labels(member).map(|labels| {
                        (labels.into_iter())
                            .map(|(hash, verdict)| match verdict {
                                ProjectVerdict::Quarantined(reason::CYCLE) => {
                                    (hash, ProjectVerdict::Quarantined(reason::CYCLE_BOUND))
                                }
                                verdict => (hash, verdict),
                            })
                            .collect()
                    }),
                    rehomed: BTreeMap::new(),
                }),
            );
        }
        Ok(decided)
    }
}
