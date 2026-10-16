//! The fork rule (Astra #1434 F1). At a fork each contender's branch first
//! folds to its own frontier, using every held descendant, so a board act
//! below a leader child takes part. A branch ranks as the highest-ranked act
//! in it since the fork; the top branch wins alone, and branches tied at the
//! top meet their frontiers with the anchor's own bounds, so a tie still
//! installs no widening. A principal that a held act in one branch deposes
//! or removes takes no authority from what it signed in a sibling branch,
//! a resolution included, unless that act itself takes none. Two
//! resolutions that do not build on each other settle nothing, even where
//! this fold cannot use one of them (ruling (b)). Every step is a function
//! of the held set: no arrival order, no arbitrary winner.
use super::fold::{ProjectEffective, ProjectRank, rank_at, reason};
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
    /// Why the frontier serves no authority: a child that fell only for its
    /// parent's bounds, which no valid branch outranks, at or below the node.
    pub(super) blocked: Option<&'static str>,
}

/// What takes no authority in the tree below one root.
pub(super) struct Exclusion {
    /// The settlements that stand, by node. A node's settlement is absent
    /// when it has none or none stands: its children stay in contention.
    pub(super) settled: BTreeMap<ProjectRevisionHash, Settlement>,
    /// Signed revisions that take no authority, with their subtrees: those a
    /// deposition excludes and those a standing settlement supersedes.
    pub(super) excluded: BTreeSet<ProjectRevisionHash>,
    /// Every node the labelling relies on: each act that deposes anyone,
    /// and each valid resolution in the tree.
    pub(super) relied: BTreeSet<ProjectRevisionHash>,
    /// The acts never excluded that depose each principal.
    pub(super) deposers: BTreeMap<String, Vec<ProjectRevisionHash>>,
    /// The nodes whose resolutions race (two or more causal tips): no
    /// settlement there stands and no branch there wins alone.
    pub(super) raced: BTreeSet<ProjectRevisionHash>,
}

/// One valid signed revision below a root. Acts are kept in preorder, so
/// the subtree of the act at `at` is the range `at..end`.
struct Act {
    hash: ProjectRevisionHash,
    parent: Option<usize>,
    end: usize,
    signer: String,
    /// The principals whose rank this act lowers from its parent's, each once.
    deposes: Vec<String>,
}

/// One valid resolution below a root. It supersedes every child its prior
/// closure names but its successor, and overrides every other resolution at
/// its node that does not build on it.
struct Resolver {
    node: ProjectRevisionHash,
    /// The act index of the node (`None`: the root).
    anchor: Option<usize>,
    /// The first resolver at the same node.
    node_first: usize,
    /// The resolvers it builds on, itself included.
    builds_on: Vec<usize>,
    /// Its verified signer.
    signer: Option<String>,
    /// The act index of its successor.
    next: Option<usize>,
    /// The act indices it supersedes.
    settles: Vec<usize>,
    settlement: Settlement,
    /// Whether its node's resolutions race: then it stands in no fold.
    raced: bool,
}

impl FoldCx<'_, '_, '_> {
    /// How `node` folds in the tree below `root`, memoized for the fold, so
    /// the walk, the served view and the dependencies rest on one labelling
    /// even where the depth guard refused (Sol #1434 r11 F2).
    pub(super) fn fork(
        &self,
        root: ProjectRevisionHash,
        node: ProjectRevisionHash,
    ) -> Result<Rc<Fork>> {
        if let Some(known) = self.forks.borrow().get(&(root, node)) {
            return Ok(Rc::clone(known));
        }
        let fork = Rc::new(self.fold_fork(root, node)?);
        self.forks
            .borrow_mut()
            .insert((root, node), Rc::clone(&fork));
        Ok(fork)
    }

    /// The labelling of the tree below `root`, memoized the same way.
    pub(super) fn exclusion(&self, root: ProjectRevisionHash) -> Result<Rc<Exclusion>> {
        if let Some(known) = self.exclusions.borrow().get(&root) {
            return Ok(Rc::clone(known));
        }
        let exclusion = Rc::new(self.exclude(root)?);
        self.exclusions
            .borrow_mut()
            .insert(root, Rc::clone(&exclusion));
        Ok(exclusion)
    }

    fn fold_fork(&self, root: ProjectRevisionHash, node: ProjectRevisionHash) -> Result<Fork> {
        let exclusion = self.exclusion(root)?;
        let raced = exclusion.raced.contains(&node);
        let valid = self.valid_children(node)?;
        let settlement = exclusion.settled.get(&node).cloned().unwrap_or_default();
        let authority = self.authority_of(&node);
        let mut fork = Fork {
            step: Step::Head,
            rank: None,
            view: authority.map(ProjectEffective::bounds),
            nodes: BTreeSet::from([node]),
            valid,
            settlement,
            blocked: None,
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
        // A child that falls only for its parent's bounds hands no authority
        // back to this node or to a sibling it does not lose to (Engine
        // ruling on #1434): a parent's narrowing never widens the child. A
        // child whose signer an act never excluded deposes off its line
        // takes nothing, as a valid act of that signer would not.
        let mut fallen: Option<(Option<ProjectRank>, &'static str)> = None;
        for child in self.held.children_of(&node) {
            if fork.settlement.superseded.contains(child) {
                continue;
            }
            let (
                ProjectVerdict::Quarantined(why @ (reason::EXCEEDS_PARENT | reason::PARENT_HIDDEN)),
                Some(signer),
            ) = (self.verdict(*child)?, self.signer(child))
            else {
                continue;
            };
            if (exclusion.deposers.get(&signer).into_iter().flatten())
                .any(|deposer| !self.on_line(root, node, *deposer))
            {
                continue;
            }
            let rank = rank_at(authority, &signer);
            if fallen.is_none_or(|(highest, _)| rank > highest) {
                fallen = Some((rank, why));
            }
        }
        let top = branches.values().filter_map(|(rank, _)| *rank).max();
        if let Some((rank, why)) = fallen
            && top.is_none_or(|top| rank >= Some(top))
        {
            fork.rank = rank.max(top);
            fork.view = None;
            fork.blocked = Some(why);
            return Ok(fork);
        }
        let Some(top) = top else {
            return Ok(fork);
        };
        let at_top: Vec<ProjectRevisionHash> = branches
            .iter()
            .filter(|(_, (rank, _))| *rank == Some(top))
            .map(|(child, _)| *child)
            .collect();
        fork.rank = Some(top);
        // At a race no branch wins alone: a competitor this fold cannot use
        // settles nothing, so the usable contenders meet (ruling (b)).
        if let [winner] = at_top[..]
            && !raced
        {
            let (_, branch) = &branches[&winner];
            fork.view = branch.view.clone();
            fork.blocked = branch.blocked;
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
                fork.blocked = fork.blocked.or(branch.blocked);
                fork.nodes.extend(branch.nodes.iter().copied());
            }
            if fork.blocked.is_some() {
                fork.view = None;
            }
            fork.step = Step::Tie {
                rank: top,
                contenders: branches.into_keys().collect(),
            };
        }
        Ok(fork)
    }

    /// Whether `hash` lies on the line from `root` down to `node`.
    fn on_line(
        &self,
        root: ProjectRevisionHash,
        node: ProjectRevisionHash,
        hash: ProjectRevisionHash,
    ) -> bool {
        let mut at = Some(node);
        while let Some(here) = at {
            if here == hash {
                return true;
            }
            if here == root {
                return false;
            }
            at = self.held.get(&here).and_then(|row| row.revision.parent());
        }
        false
    }

    /// One pass over the tree below `root`: the well-founded labelling of
    /// section 5a over every valid act and resolution. A deposition attacks
    /// each act its target signed off the deposing act's line. A resolution
    /// attacks what it supersedes and every resolution at its node that does
    /// not build on it; it is attacked when an act off its node's line
    /// deposes its signer, or an act off its successor's line, outside what
    /// it supersedes, deposes the successor's signer. Only an attack by what
    /// is never itself excluded counts.
    fn exclude(&self, root: ProjectRevisionHash) -> Result<Exclusion> {
        let acts = self.acts_below(root)?;
        let at: BTreeMap<ProjectRevisionHash, usize> = (acts.iter().enumerate())
            .map(|(index, act)| (act.hash, index))
            .collect();
        let mut relied: BTreeSet<ProjectRevisionHash> = (acts.iter())
            .filter(|act| !act.deposes.is_empty())
            .map(|act| act.hash)
            .collect();
        let mut resolvers: Vec<Resolver> = Vec::new();
        let mut raced = BTreeSet::new();
        let nodes = std::iter::once((root, None))
            .chain((acts.iter().enumerate()).map(|(index, act)| (act.hash, Some(index))));
        for (node, anchor) in nodes {
            let node_first = resolvers.len();
            // The race is read from the authorized envelopes, before this
            // fold's cycle or deposition removes any (ruling (b)).
            let race = self.resolution_tips(node)?.len() > 1;
            if race {
                raced.insert(node);
            }
            for settlement in self.settlements(node)? {
                let Some(tip) = settlement.tip else {
                    continue;
                };
                let Some(ProjectRevision::Resolution { resolution, .. }) = self.row(&tip) else {
                    continue;
                };
                relied.insert(tip);
                resolvers.push(Resolver {
                    node,
                    anchor,
                    node_first,
                    builds_on: Vec::new(),
                    signer: self.signer(&tip),
                    next: at.get(&resolution.next).copied(),
                    settles: (settlement.superseded.iter())
                        .filter_map(|lost| at.get(lost).copied())
                        .collect(),
                    settlement,
                    raced: race,
                });
            }
            let node_end = resolvers.len();
            let index_of: BTreeMap<ProjectRevisionHash, usize> = (node_first..node_end)
                .filter_map(|index| Some((resolvers[index].settlement.tip?, index)))
                .collect();
            for resolver in &mut resolvers[node_first..node_end] {
                resolver.builds_on = (resolver.settlement.closure.iter())
                    .filter_map(|hash| index_of.get(hash).copied())
                    .collect();
            }
        }
        let (out, over) = well_founded(&acts, &resolvers);
        let mut deposers: BTreeMap<String, Vec<ProjectRevisionHash>> = BTreeMap::new();
        for (act, _) in acts.iter().zip(&over).filter(|(_, over)| !**over) {
            for principal in &act.deposes {
                deposers
                    .entry(principal.clone())
                    .or_default()
                    .push(act.hash);
            }
        }
        Ok(Exclusion {
            excluded: (acts.iter().zip(&out))
                .filter(|(_, out)| **out)
                .map(|(act, _)| act.hash)
                .collect(),
            settled: (resolvers.into_iter().enumerate())
                .filter(|(index, _)| !over[acts.len() + index])
                .map(|(_, resolver)| (resolver.node, resolver.settlement))
                .collect(),
            relied,
            deposers,
            raced,
        })
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
                deposes: deposed(prior, next),
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

/// The principals whose rank (as `rank_at` reads it) `next` lowers from
/// `prior`'s, each once: a leader who also sits on the board is one
/// principal. Each board is read into a set once, so an act costs the size
/// of its two authorities.
fn deposed(prior: &ProjectAuthority, next: &ProjectAuthority) -> Vec<String> {
    let rank = |authority: &ProjectAuthority, board: &BTreeSet<&str>, held: &str| {
        if held == "host" || board.contains(held) {
            Some(ProjectRank::Board)
        } else if authority.leader == held {
            Some(ProjectRank::Leader)
        } else {
            None
        }
    };
    let before: BTreeSet<&str> = prior.board.iter().map(String::as_str).collect();
    let after: BTreeSet<&str> = next.board.iter().map(String::as_str).collect();
    let principals: BTreeSet<&str> = std::iter::once(prior.leader.as_str())
        .chain(before.iter().copied())
        .collect();
    principals
        .into_iter()
        .filter(|&held| rank(next, &after, held) < rank(prior, &before, held))
        .map(str::to_owned)
        .collect()
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

/// What the acts and resolutions outside `discounted` attack: acts by
/// index, then resolutions after them. An attacked act's subtree goes with it.
fn attacked(acts: &[Act], resolvers: &[Resolver], discounted: &[bool]) -> Vec<bool> {
    let counted: Vec<usize> = (0..acts.len())
        .filter(|index| !discounted[*index])
        .collect();
    let deposers = Deposers::of(acts, &counted);
    let standing = |index: usize| !discounted[acts.len() + index];
    let mut at_node = vec![0; resolvers.len()];
    for (index, resolver) in resolvers.iter().enumerate() {
        if standing(index) {
            at_node[resolver.node_first] += 1;
        }
    }
    let mut out = vec![false; acts.len() + resolvers.len()];
    let mut superseded = vec![false; acts.len()];
    for (index, resolver) in resolvers.iter().enumerate() {
        let built_on = (resolver.builds_on.iter())
            .filter(|other| standing(**other))
            .count();
        out[acts.len() + index] = resolver.raced
            || at_node[resolver.node_first] > built_on
            || (resolver.signer.as_deref())
                .is_some_and(|signer| deposers.challenge(acts, resolver.anchor, signer, &[]))
            || resolver.next.is_some_and(|next| {
                deposers.challenge(acts, Some(next), &acts[next].signer, &resolver.settles)
            });
        if standing(index) {
            for lost in &resolver.settles {
                superseded[*lost] = true;
            }
        }
    }
    for (index, act) in acts.iter().enumerate() {
        out[index] = act.parent.is_some_and(|parent| out[parent])
            || superseded[index]
            || deposers.challenge(acts, Some(index), &act.signer, &[]);
    }
    out
}

/// Two branches can each depose the other's signer, so the labelling is the
/// least fixpoint of attacking twice (the well-founded reading, Engine
/// ruling 2026-10-14): what an act or resolution that is never itself
/// excluded attacks is excluded, and what nothing left standing attacks
/// stands. Mutual depositions exclude neither side, a chain resolves from
/// its unchallenged end, and two resolutions neither builds on settle
/// nothing, nor does either once a deposition or a cycle takes the other
/// (a raced resolver is always attacked). Returns the excluded set and the
/// set anything not excluded attacks.
fn well_founded(acts: &[Act], resolvers: &[Resolver]) -> (Vec<bool>, Vec<bool>) {
    let mut under = vec![false; acts.len() + resolvers.len()];
    loop {
        let over = attacked(acts, resolvers, &under);
        let next = attacked(acts, resolvers, &over);
        if next == under {
            return (under, over);
        }
        under = next;
    }
}
