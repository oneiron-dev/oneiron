//! The fork rule (Astra #1434 F1). At a fork each contender's branch first
//! folds to its own frontier, using every held descendant, so a board act
//! below a leader child takes part. A branch ranks as the highest-ranked act
//! in it since the fork; the top branch wins alone, and branches tied at the
//! top meet their frontiers with the anchor's own bounds, so a tie still
//! installs no widening. A principal that a held act in one branch deposes
//! or removes takes no authority from what it signed in a sibling branch,
//! a resolution included. Every step is a function of the held set: no
//! arrival order, no arbitrary winner.
use super::fold::{ProjectEffective, ProjectRank, rank_at};
use super::read::ProjectVerdict;
use super::revision::{ProjectRevision, ProjectRevisionHash};
use super::validity::{FoldCx, Settlement};
use super::*;
use std::collections::BTreeMap;
use std::rc::Rc;

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
    /// The highest rank of any act below the node the frontier keeps; `None`
    /// at a head.
    pub(super) rank: Option<ProjectRank>,
    /// The bounds the frontier serves: the head's, or at a tie the anchor's
    /// met with every contender's frontier. `None` when the node is no state.
    pub(super) view: Option<ProjectEffective>,
    /// Every node the view relies on, with the settlements on its way.
    pub(super) nodes: BTreeSet<ProjectRevisionHash>,
}

/// What takes no authority in the tree below one root.
pub(super) struct Exclusion {
    /// Resolutions whose signer, or whose successor's signer, a held act in
    /// a sibling branch deposes: they settle nothing. An act below a
    /// contender the resolution itself settles does not count against its
    /// successor, since that contender leaves if the resolution stands.
    pub(super) void: BTreeSet<ProjectRevisionHash>,
    /// Signed revisions that take no authority, with their subtrees.
    pub(super) excluded: BTreeSet<ProjectRevisionHash>,
    /// Every node the exclusion relies on: each act that deposes anyone, and
    /// each settlement that superseded a valid child.
    pub(super) relied: BTreeSet<ProjectRevisionHash>,
}

/// One valid signed revision below a root. Acts are kept in preorder, so
/// the subtree of the act at `at` is the range `at..end`.
struct Act {
    hash: ProjectRevisionHash,
    parent: Option<usize>,
    end: usize,
    signer: String,
    /// The principals whose rank this act lowers from its parent's.
    deposes: Vec<String>,
}

impl FoldCx<'_, '_, '_> {
    /// How `node` folds in the tree below `root`. Memoized unless a depth
    /// refusal shaped it.
    pub(super) fn fork(
        &self,
        root: ProjectRevisionHash,
        node: ProjectRevisionHash,
    ) -> Result<Rc<Fork>> {
        if let Some(known) = self.forks.borrow().get(&(root, node)) {
            return Ok(Rc::clone(known));
        }
        let refusals = self.refusals();
        let fork = Rc::new(self.fold_fork(root, node)?);
        if self.refusals() == refusals {
            self.forks
                .borrow_mut()
                .insert((root, node), Rc::clone(&fork));
        }
        Ok(fork)
    }

    /// The exclusions of the tree below `root`, memoized the same way.
    pub(super) fn exclusion(&self, root: ProjectRevisionHash) -> Result<Rc<Exclusion>> {
        if let Some(known) = self.exclusions.borrow().get(&root) {
            return Ok(Rc::clone(known));
        }
        let refusals = self.refusals();
        let exclusion = Rc::new(self.exclude(root)?);
        if self.refusals() == refusals {
            self.exclusions
                .borrow_mut()
                .insert(root, Rc::clone(&exclusion));
        }
        Ok(exclusion)
    }

    fn fold_fork(&self, root: ProjectRevisionHash, node: ProjectRevisionHash) -> Result<Fork> {
        let exclusion = self.exclusion(root)?;
        let valid = self.valid_children(node)?;
        let settlement = self.settlement(node, &exclusion.void)?;
        let authority = self.authority_of(&node);
        let mut fork = Fork {
            step: Step::Head,
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
        let mut branches = BTreeMap::new();
        for child in &fork.valid {
            if fork.settlement.superseded.contains(child) || exclusion.excluded.contains(child) {
                continue;
            }
            let branch = self.fork(root, *child)?;
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
                contenders: branches.into_keys().collect(),
            };
        }
        Ok(fork)
    }

    /// One pass over the tree below `root`. A resolution is void when a held
    /// act off its own line deposes its signer, or an act off its
    /// successor's line, outside the contenders it settles, deposes its
    /// successor's signer: it settles nothing, so the children it named stay
    /// in contention. Then,
    /// over the children no standing settlement superseded, the well-founded
    /// exclusion of section 5a.
    fn exclude(&self, root: ProjectRevisionHash) -> Result<Exclusion> {
        let acts = self.acts_below(root)?;
        let at: BTreeMap<ProjectRevisionHash, usize> = (acts.iter().enumerate())
            .map(|(index, act)| (act.hash, index))
            .collect();
        let all: Vec<usize> = (0..acts.len()).collect();
        let mut exclusion = Exclusion {
            void: BTreeSet::new(),
            excluded: BTreeSet::new(),
            relied: (acts.iter())
                .filter(|act| !act.deposes.is_empty())
                .map(|act| act.hash)
                .collect(),
        };
        let held = Deposers::of(&acts, &all);
        let nodes: Vec<ProjectRevisionHash> = std::iter::once(root)
            .chain(acts.iter().map(|act| act.hash))
            .collect();
        for node in &nodes {
            let position = at.get(node).copied();
            for hash in self.held.resolutions_at(node) {
                let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(hash) else {
                    continue;
                };
                if self.verdict(*hash)? != ProjectVerdict::Visible {
                    continue;
                }
                let next = at.get(&resolution.next).copied();
                let settled: Vec<usize> = (resolution.contenders.iter())
                    .filter(|contender| **contender != resolution.next)
                    .filter_map(|contender| at.get(contender).copied())
                    .collect();
                let signer = self.signer(hash);
                if signer.is_some_and(|signer| held.challenge(&acts, position, &signer, &[]))
                    || next.is_some_and(|next| {
                        held.challenge(&acts, Some(next), &acts[next].signer, &settled)
                    })
                {
                    exclusion.void.insert(*hash);
                }
            }
        }
        // A child a standing settlement superseded leaves with its subtree.
        let mut live = vec![true; acts.len()];
        for node in &nodes {
            let valid = self.valid_children(*node)?;
            let settlement = self.settlement(*node, &exclusion.void)?;
            if (settlement.superseded.iter()).any(|lost| valid.contains(lost)) {
                exclusion.relied.extend(settlement.closure.iter().copied());
            }
            for lost in &settlement.superseded {
                if let Some(&index) = at.get(lost) {
                    live[index..acts[index].end].fill(false);
                }
            }
        }
        let live: Vec<usize> = all.into_iter().filter(|index| live[*index]).collect();
        exclusion.excluded = (well_founded(&acts, &live).into_iter())
            .map(|index| acts[index].hash)
            .collect();
        Ok(exclusion)
    }

    /// Every valid signed revision below `root`, in preorder.
    fn acts_below(&self, root: ProjectRevisionHash) -> Result<Vec<Act>> {
        let mut acts: Vec<Act> = Vec::new();
        let mut todo: Vec<(ProjectRevisionHash, ProjectRevisionHash, Option<usize>)> =
            (self.valid_children(root)?.into_iter())
                .rev()
                .map(|child| (child, root, None))
                .collect();
        while let Some((hash, parent, parent_at)) = todo.pop() {
            let (Some(prior), Some(next), Some(signer)) = (
                self.authority_of(&parent),
                self.authority_of(&hash),
                self.signer(&hash),
            ) else {
                continue;
            };
            acts.push(Act {
                hash,
                parent: parent_at,
                end: 0,
                signer,
                deposes: std::iter::once(&prior.leader)
                    .chain(&prior.board)
                    .filter(|held| rank_at(next, held) < rank_at(prior, held))
                    .cloned()
                    .collect(),
            });
            let at = acts.len() - 1;
            for child in self.valid_children(hash)?.into_iter().rev() {
                todo.push((child, hash, Some(at)));
            }
        }
        // A preorder subtree is contiguous: each act's size adds to its parent's.
        let mut size = vec![1; acts.len()];
        for index in (0..acts.len()).rev() {
            if let Some(parent) = acts[index].parent {
                size[parent] += size[index];
            }
        }
        for (index, act) in acts.iter_mut().enumerate() {
            act.end = index + size[index];
        }
        Ok(acts)
    }
}

/// Who deposes each principal, among some acts, by act index in order.
struct Deposers<'a>(BTreeMap<&'a str, Vec<usize>>);

impl<'a> Deposers<'a> {
    fn of(acts: &'a [Act], counted: &[usize]) -> Self {
        let mut map: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for index in counted {
            for held in &acts[*index].deposes {
                map.entry(held).or_default().push(*index);
            }
        }
        Self(map)
    }

    /// Whether an act off the line through `position`, outside the subtrees
    /// at `apart` (which lie off that line), deposes `principal`. An
    /// ancestor's deposition is history and a descendant's comes after; only
    /// a sibling branch's challenges. The root's line (`None`) holds every act.
    fn challenge(
        &self,
        acts: &[Act],
        position: Option<usize>,
        principal: &str,
        apart: &[usize],
    ) -> bool {
        let (Some(deposers), Some(at)) = (self.0.get(principal), position) else {
            return false;
        };
        let within = |top: usize| {
            deposers.partition_point(|index| *index < acts[top].end)
                - deposers.partition_point(|index| *index < top)
        };
        let mut uncounted = within(at) + apart.iter().map(|top| within(*top)).sum::<usize>();
        let mut up = acts[at].parent;
        while let Some(ancestor) = up {
            uncounted += usize::from(deposers.binary_search(&ancestor).is_ok());
            up = acts[ancestor].parent;
        }
        deposers.len() > uncounted
    }
}

/// The acts among `live` that a deposition excludes when the acts in
/// `discounted` depose no one, with their live subtrees.
fn excluded_by(acts: &[Act], live: &[usize], discounted: &BTreeSet<usize>) -> BTreeSet<usize> {
    let counted: Vec<usize> = (live.iter())
        .filter(|index| !discounted.contains(index))
        .copied()
        .collect();
    let deposers = Deposers::of(acts, &counted);
    let mut out = BTreeSet::new();
    for index in live {
        let act = &acts[*index];
        if act.parent.is_some_and(|parent| out.contains(&parent))
            || deposers.challenge(acts, Some(*index), &act.signer, &[])
        {
            out.insert(*index);
        }
    }
    out
}

/// Two branches can each depose the other's signer, so exclusion is the
/// least fixpoint of excluding twice (the well-founded reading, Engine
/// ruling 2026-10-14): an act is excluded only when an act that is never
/// itself excluded, in a sibling branch, deposes its signer. Mutual
/// depositions exclude neither side, and a chain resolves from its
/// unchallenged end.
fn well_founded(acts: &[Act], live: &[usize]) -> BTreeSet<usize> {
    let mut under = BTreeSet::new();
    if live.iter().all(|index| acts[*index].deposes.is_empty()) {
        return under;
    }
    loop {
        let over = excluded_by(acts, live, &under);
        let next = excluded_by(acts, live, &over);
        if next == under {
            return under;
        }
        under = next;
    }
}
