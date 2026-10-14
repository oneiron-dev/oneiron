//! The fork rule (Astra #1434 F1). At a fork each contender's branch first
//! folds to its own frontier, using every held descendant, so a board act
//! below a leader child takes part. A branch ranks as the highest-ranked act
//! in it since the fork; the top branch wins alone, and branches tied at the
//! top meet their frontiers with the anchor's own bounds, so a tie still
//! installs no widening. A principal that a held act in one branch deposes
//! or removes takes no authority from what it signed in a sibling branch.
//! Every step is a function of the held set: no arrival order, no arbitrary
//! winner.
use super::fold::{ProjectEffective, ProjectRank, rank_at};
use super::revision::ProjectRevisionHash;
use super::validity::{FoldCx, Settlement};
use super::*;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Principals whose signatures carry no authority below a fork.
pub(super) type Excluded = BTreeSet<String>;

/// How the walk leaves one node.
pub(super) enum Step {
    /// No valid child: the node is the head.
    Head,
    Advance {
        winner: ProjectRevisionHash,
        resolution: Option<ProjectRevisionHash>,
    },
    Tie {
        rank: ProjectRank,
        contenders: BTreeSet<ProjectRevisionHash>,
    },
}

/// One node folded to its frontier.
pub(super) struct Fork {
    pub(super) step: Step,
    pub(super) valid: BTreeSet<ProjectRevisionHash>,
    pub(super) settlement: Settlement,
    /// The exclusions each candidate's branch folds under, a sibling's
    /// depositions included.
    pub(super) below: BTreeMap<ProjectRevisionHash, Excluded>,
    /// The highest rank of any act below the node the frontier keeps; `None`
    /// at a head.
    pub(super) rank: Option<ProjectRank>,
    /// The bounds the frontier serves: the head's, or at a tie the anchor's
    /// met with every contender's frontier. `None` when the node is no state.
    pub(super) view: Option<ProjectEffective>,
    /// Every node the view relies on, with the settlements and depositions
    /// that decided its forks.
    pub(super) nodes: BTreeSet<ProjectRevisionHash>,
}

/// One held act below a fork, for the exclusion pass.
struct Act {
    branch: usize,
    parent: Option<usize>,
    hash: ProjectRevisionHash,
    signer: String,
    /// The principals whose rank this act lowers from its parent's.
    deposes: Vec<String>,
}

impl FoldCx<'_, '_, '_> {
    /// How `node` folds when the principals in `excluded` carry no authority
    /// below it. Memoized unless a depth refusal shaped it.
    pub(super) fn fork(&self, node: ProjectRevisionHash, excluded: &Excluded) -> Result<Rc<Fork>> {
        let key = (node, excluded.clone());
        if let Some(known) = self.forks.borrow().get(&key) {
            return Ok(Rc::clone(known));
        }
        let refusals = self.refusals();
        let fork = Rc::new(self.fold_fork(node, excluded)?);
        if self.refusals() == refusals {
            self.forks.borrow_mut().insert(key, Rc::clone(&fork));
        }
        Ok(fork)
    }

    fn fold_fork(&self, node: ProjectRevisionHash, excluded: &Excluded) -> Result<Fork> {
        let valid = self.valid_children(node)?;
        let settlement = self.settlement(node)?;
        let authority = self.authority_of(&node);
        let mut fork = Fork {
            step: Step::Head,
            below: BTreeMap::new(),
            rank: None,
            view: authority.map(ProjectEffective::bounds),
            nodes: BTreeSet::from([node]),
            valid,
            settlement,
        };
        // A settlement that excluded a valid child shapes the frontier,
        // whatever follows it.
        let settled = (fork.settlement.superseded.iter()).any(|lost| fork.valid.contains(lost));
        if settled {
            fork.nodes.extend(fork.settlement.closure.iter().copied());
        }
        let Some(authority) = authority else {
            return Ok(fork);
        };
        let candidates = self.live_children(&fork.valid, &fork.settlement, excluded);
        if candidates.is_empty() {
            return Ok(fork);
        }
        let acts = self.acts_below(node, &candidates, excluded)?;
        let (over, under) = exclusions(&acts);
        let mut kept = Vec::new();
        for (branch, child) in candidates.iter().enumerate() {
            let mut below = excluded.clone();
            below.extend(depositions(&acts, &over, move |at| at != branch));
            if self
                .signer(child)
                .is_some_and(|signer| below.contains(&signer))
            {
                continue;
            }
            fork.below.insert(*child, below);
            kept.push(*child);
        }
        // The acts whose depositions excluded a sibling decide the fork too.
        for (at, act) in acts.iter().enumerate() {
            let excludes = |signer: &String| {
                under
                    .iter()
                    .any(|lost| acts[*lost].branch != act.branch && acts[*lost].signer == *signer)
            };
            if !over.contains(&at) && act.deposes.iter().any(excludes) {
                fork.nodes.insert(act.hash);
            }
        }
        let mut branches = BTreeMap::new();
        for child in &kept {
            let branch = self.fork(*child, &fork.below[child])?;
            let rank = self
                .signer(child)
                .and_then(|signer| rank_at(authority, &signer))
                .max(branch.rank);
            branches.insert(*child, (rank, branch));
        }
        let Some(top) = branches.values().filter_map(|(rank, _)| *rank).max() else {
            return Ok(fork);
        };
        let at_top: Vec<ProjectRevisionHash> = branches
            .iter()
            .filter(|(_, (rank, _))| *rank == Some(top))
            .map(|(child, _)| *child)
            .collect();
        fork.rank = Some(top);
        if let [winner] = at_top[..] {
            let (_, branch) = &branches[&winner];
            fork.view = branch.view.clone();
            fork.nodes.extend(branch.nodes.iter().copied());
            fork.step = Step::Advance {
                winner,
                resolution: fork.settlement.tip.filter(|_| settled),
            };
        } else {
            // Every unexcluded contender meets, of any rank (point E).
            for (_, branch) in branches.values() {
                if let (Some(view), Some(frontier)) = (&mut fork.view, &branch.view) {
                    view.meet_view(frontier);
                }
                fork.nodes.extend(branch.nodes.iter().copied());
            }
            fork.step = Step::Tie {
                rank: top,
                contenders: kept.into_iter().collect(),
            };
        }
        Ok(fork)
    }

    /// The valid children of `node` a settlement left standing, and none an
    /// excluded principal signed.
    fn live_children(
        &self,
        valid: &BTreeSet<ProjectRevisionHash>,
        settlement: &Settlement,
        excluded: &Excluded,
    ) -> Vec<ProjectRevisionHash> {
        valid
            .iter()
            .filter(|child| !settlement.superseded.contains(child))
            .filter(|child| {
                !self
                    .signer(child)
                    .is_some_and(|signer| excluded.contains(&signer))
            })
            .copied()
            .collect()
    }

    /// Every live act in each candidate's branch, parents before children.
    fn acts_below(
        &self,
        node: ProjectRevisionHash,
        candidates: &[ProjectRevisionHash],
        excluded: &Excluded,
    ) -> Result<Vec<Act>> {
        let mut acts: Vec<Act> = Vec::new();
        for (branch, child) in candidates.iter().enumerate() {
            let mut todo = vec![(*child, node, None)];
            while let Some((hash, parent, parent_at)) = todo.pop() {
                let (Some(prior), Some(next), Some(signer)) = (
                    self.authority_of(&parent),
                    self.authority_of(&hash),
                    self.signer(&hash),
                ) else {
                    continue;
                };
                acts.push(Act {
                    branch,
                    parent: parent_at,
                    hash,
                    signer,
                    deposes: std::iter::once(&prior.leader)
                        .chain(&prior.board)
                        .filter(|held| rank_at(next, held) < rank_at(prior, held))
                        .cloned()
                        .collect(),
                });
                let at = acts.len() - 1;
                let valid = self.valid_children(hash)?;
                let settlement = self.settlement(hash)?;
                for grandchild in self.live_children(&valid, &settlement, excluded) {
                    todo.push((grandchild, hash, Some(at)));
                }
            }
        }
        Ok(acts)
    }
}

/// The principals the acts outside `discounted` depose, in the branches
/// `counts` names.
fn depositions<'a>(
    acts: &'a [Act],
    discounted: &'a BTreeSet<usize>,
    counts: impl Fn(usize) -> bool + 'a,
) -> impl Iterator<Item = String> + 'a {
    acts.iter()
        .enumerate()
        .filter(move |(at, act)| !discounted.contains(at) && counts(act.branch))
        .flat_map(|(_, act)| act.deposes.iter().cloned())
}

/// The acts that take no authority when the acts in `discounted` depose no
/// one: those whose signer a sibling branch deposes, and their descendants.
fn excluded_by(acts: &[Act], discounted: &BTreeSet<usize>) -> BTreeSet<usize> {
    let mut deposed: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
    for (at, act) in acts.iter().enumerate() {
        if !discounted.contains(&at) {
            for held in &act.deposes {
                deposed.entry(held).or_default().insert(act.branch);
            }
        }
    }
    let mut out = BTreeSet::new();
    for (at, act) in acts.iter().enumerate() {
        let challenged = deposed
            .get(act.signer.as_str())
            .is_some_and(|branches| branches.iter().any(|branch| *branch != act.branch));
        if challenged || act.parent.is_some_and(|parent| out.contains(&parent)) {
            out.insert(at);
        }
    }
    out
}

/// Two branches can each depose the other's signer, so exclusion is taken
/// at the least fixpoint of excluding twice (the well-founded reading): an
/// act is excluded only when an act that is itself never excluded deposes
/// its signer. Mutual depositions exclude neither side, and the branches
/// compare by rank as they stand. Returns the acts that may be excluded and
/// those that are.
fn exclusions(acts: &[Act]) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let mut under = BTreeSet::new();
    loop {
        let over = excluded_by(acts, &under);
        let next = excluded_by(acts, &over);
        if next == under {
            return (over, under);
        }
        under = next;
    }
}
