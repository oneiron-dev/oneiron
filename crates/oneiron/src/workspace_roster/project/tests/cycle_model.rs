//! The reference for parent cycles (Astra #1434b; Engine rulings (a) and (E)),
//! written from the definition and sharing nothing with the fold: a brute
//! force over every assignment of the undecided revisions of a component.
//!
//! Each project has a birth and a tree of signed revisions; each revision
//! names one parent (the root R or another project), a resource mask and a
//! depth. Board revisions rank above leader ones, the board never changes and
//! every revision keeps the members, so no deposition or resolution applies.
//! The rule:
//! - Components are the strongly connected sets of "names as parent" over
//!   intrinsically valid revisions; they are solved parents first.
//! - A revision is undecided when it names a parent in its component or sits
//!   over an undecided one; every other is judged once, as before.
//! - A world assigns each undecided revision stands or not. A revision stands
//!   when assigned so and its prior stands, or, for a board conduit, when its
//!   base stands; it then hangs under its nearest standing ancestor.
//! - A revision is admitted in a world when its parent's view there has
//!   authority, it fits under that view, and that view's parent chain does
//!   not return to its project. A root is not judged by a view whose chain
//!   returns (that view is in its causal future); with none left it fails.
//! - Least fixpoint: valid when admitted in every world, invalid in none,
//!   else undefined. A project serves the meet of its worlds' views with the
//!   parent of the deepest node every world's walk passes.
//! - Past the bound (views or assignments per member) a component serves no
//!   authority. Served views then drop any that fit no served parent or
//!   close a served cycle.
use std::collections::BTreeSet;

pub(super) const KEPT: u8 = 1;
pub(super) const EXTRA: u8 = 2;
pub(super) const ROOT_DEPTH: u8 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Rank {
    Leader,
    Board,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Rev {
    pub(super) project: usize,
    /// The earlier revision of the same project; `None`: over its birth.
    pub(super) prior: Option<usize>,
    /// `None`: the root R.
    pub(super) parent: Option<usize>,
    pub(super) mask: u8,
    pub(super) depth: u8,
    pub(super) signer: Rank,
    /// Delivered after every other revision, as a replayed companion.
    pub(super) withheld: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Graph {
    pub(super) projects: usize,
    /// `Some(q)`: q's leader spawned the project under q; else under R.
    pub(super) born_under: Vec<Option<usize>>,
    pub(super) revs: Vec<Rev>,
    pub(super) bound: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct View {
    pub(super) mask: u8,
    pub(super) depth: u8,
    pub(super) parent: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Label {
    Valid,
    Invalid,
    Undefined,
}

#[derive(Debug)]
pub(super) struct Expected {
    pub(super) served: Vec<Option<View>>,
    /// Per revision of the graph; births are not listed.
    pub(super) labels: Vec<Label>,
    /// Per project: its component passed the bound.
    pub(super) dark: Vec<bool>,
}

#[derive(Clone, Copy)]
struct Node {
    project: usize,
    prior: Option<usize>,
    parent: Option<usize>,
    mask: u8,
    depth: u8,
    rank: Rank,
}

/// The births' depth: one below the root's, or below the spawning project's birth.
pub(super) fn birth_depth(graph: &Graph, project: usize) -> u8 {
    match graph.born_under[project] {
        None => ROOT_DEPTH - 1,
        Some(parent) => birth_depth(graph, parent) - 1,
    }
}

fn fits(node: &Node, view: &View) -> bool {
    node.depth < view.depth && node.mask & !view.mask == 0
}

fn root_view() -> View {
    View {
        mask: KEPT | EXTRA,
        depth: ROOT_DEPTH,
        parent: None,
    }
}

struct Solver<'g> {
    graph: &'g Graph,
    /// Births first (node p is project p's birth), then held revisions.
    nodes: Vec<Option<Node>>,
    intrinsic: Vec<bool>,
    comp: Vec<usize>,
    label: Vec<Label>,
    /// Invalid only for its parent's bounds, with its lineage standing.
    fallen: Vec<bool>,
    undecided: Vec<bool>,
    conduit: Vec<Option<usize>>,
    served: Vec<Option<Option<View>>>,
    dark: Vec<bool>,
}

/// The reference answer for the revisions `held` (indexed like `graph.revs`).
pub(super) fn solve(graph: &Graph, held: &[bool]) -> Expected {
    let projects = graph.projects;
    let mut nodes: Vec<Option<Node>> = (0..projects)
        .map(|project| {
            Some(Node {
                project,
                prior: None,
                parent: graph.born_under[project],
                mask: KEPT | EXTRA,
                depth: birth_depth(graph, project),
                rank: Rank::Board,
            })
        })
        .collect();
    for (index, rev) in graph.revs.iter().enumerate() {
        nodes.push(held[index].then_some(Node {
            project: rev.project,
            prior: Some(rev.prior.map_or(rev.project, |prior| projects + prior)),
            parent: rev.parent,
            mask: rev.mask,
            depth: rev.depth,
            rank: rev.signer,
        }));
    }
    let mut intrinsic = vec![false; nodes.len()];
    for index in 0..nodes.len() {
        intrinsic[index] = match nodes[index] {
            None => false,
            Some(node) => match node.prior {
                None => true,
                Some(prior) => {
                    let before = nodes[prior];
                    intrinsic[prior]
                        && before.is_some_and(|before| {
                            node.rank == Rank::Board
                                || (node.parent == before.parent
                                    && node.mask & !before.mask == 0
                                    && node.depth <= before.depth)
                        })
                }
            },
        };
    }
    let mut reach = vec![vec![false; projects]; projects];
    for (index, node) in nodes.iter().enumerate() {
        if let Some(Node {
            project,
            parent: Some(parent),
            ..
        }) = node
            && intrinsic[index]
        {
            reach[*project][*parent] = true;
        }
    }
    for via in 0..projects {
        for from in 0..projects {
            for to in 0..projects {
                if reach[from][via] && reach[via][to] {
                    reach[from][to] = true;
                }
            }
        }
    }
    let comp = (0..projects)
        .map(|p| {
            (0..projects)
                .find(|q| *q == p || (reach[p][*q] && reach[*q][p]))
                .unwrap_or(p)
        })
        .collect();
    let mut solver = Solver {
        graph,
        label: vec![Label::Invalid; nodes.len()],
        fallen: vec![false; nodes.len()],
        undecided: vec![false; nodes.len()],
        conduit: vec![None; nodes.len()],
        nodes,
        intrinsic,
        comp,
        served: vec![None; projects],
        dark: vec![false; projects],
    };
    while let Some(next) = (0..projects).find(|p| {
        solver.served[*p].is_none()
            && solver.comp[*p] == *p
            && (0..projects).filter(|q| solver.comp[*q] == *p).all(|q| {
                solver
                    .external_parents(q)
                    .all(|r| solver.served[r].is_some())
            })
    }) {
        solver.component(next);
    }
    Expected {
        served: solver.served.iter().map(|view| view.flatten()).collect(),
        labels: solver.label[projects..].to_vec(),
        dark: solver.dark,
    }
}

impl Solver<'_> {
    fn node(&self, index: usize) -> Node {
        self.nodes[index].expect("held node")
    }

    fn inside(&self, comp: usize, parent: Option<usize>) -> bool {
        parent.is_some_and(|parent| self.comp[parent] == comp)
    }

    fn external_parents(&self, project: usize) -> impl Iterator<Item = usize> + '_ {
        (0..self.nodes.len())
            .filter(move |index| self.intrinsic[*index])
            .filter_map(move |index| {
                let node = self.node(index);
                (node.project == project)
                    .then_some(node.parent)
                    .flatten()
                    .filter(|parent| self.comp[*parent] != self.comp[project])
            })
    }

    fn admitted_outside(&self, node: &Node) -> bool {
        match node.parent {
            None => fits(node, &root_view()),
            Some(parent) => self.served[parent]
                .flatten()
                .is_some_and(|view| fits(node, &view)),
        }
    }

    fn members(&self, comp: usize) -> Vec<usize> {
        (0..self.graph.projects)
            .filter(|p| self.comp[*p] == comp)
            .collect()
    }

    fn component(&mut self, comp: usize) {
        let members = self.members(comp);
        let held: Vec<usize> = (0..self.nodes.len())
            .filter(|index| self.nodes[*index].is_some_and(|node| self.comp[node.project] == comp))
            .collect();
        for &index in &held {
            let node = self.node(index);
            if !self.intrinsic[index] {
                self.label[index] = Label::Invalid;
                continue;
            }
            let prior_undecided = node.prior.is_some_and(|prior| self.undecided[prior]);
            // Refused by a parent outside the component: invalid in every
            // world, on its bounds unless its lineage already fell.
            if !self.inside(comp, node.parent) && !self.admitted_outside(&node) {
                self.label[index] = Label::Invalid;
                self.fallen[index] = node
                    .prior
                    .is_some_and(|prior| self.label[prior] != Label::Invalid);
                continue;
            }
            if self.inside(comp, node.parent) || prior_undecided {
                self.undecided[index] = true;
                self.label[index] = Label::Undefined;
                continue;
            }
            let prior_valid = node
                .prior
                .is_none_or(|prior| self.label[prior] == Label::Valid);
            self.label[index] = if prior_valid {
                Label::Valid
            } else {
                Label::Invalid
            };
        }
        let undecided: Vec<usize> = held
            .iter()
            .copied()
            .filter(|index| self.undecided[*index])
            .collect();
        if undecided.is_empty() {
            self.finish(comp, &members);
            return;
        }
        // The plain worlds (lineage only) judge each conduit's priors.
        let Some(plain) = self.worlds(comp, &members, &undecided, false) else {
            return self.go_dark(&members);
        };
        for &index in &undecided {
            self.conduit[index] = self.conduit_base(comp, index, &plain);
        }
        loop {
            let open: Vec<usize> = undecided
                .iter()
                .copied()
                .filter(|index| self.label[*index] == Label::Undefined)
                .collect();
            let Some(worlds) = self.worlds(comp, &members, &open, true) else {
                return self.go_dark(&members);
            };
            let mut next = Vec::new();
            for &index in &open {
                let (mut judged, mut all, mut none) = (false, true, true);
                for world in &worlds.joint {
                    let Some(ok) = self.ok(comp, index, world) else {
                        continue;
                    };
                    judged = true;
                    all &= ok;
                    none &= !ok;
                }
                next.push(match (judged, all, none) {
                    (false, _, _) | (true, _, true) => Label::Invalid,
                    (true, true, _) => Label::Valid,
                    _ => Label::Undefined,
                });
            }
            let changed = open
                .iter()
                .zip(&next)
                .any(|(index, label)| self.label[*index] != *label);
            for (index, label) in open.iter().zip(next) {
                if label == Label::Invalid {
                    self.fallen[*index] = self.bounds(comp, *index, &worlds);
                }
                self.label[*index] = label;
            }
            if !changed {
                break;
            }
        }
        self.finish(comp, &members);
    }

    fn go_dark(&mut self, members: &[usize]) {
        for member in members {
            self.served[*member] = Some(None);
            self.dark[*member] = true;
        }
    }

    /// The board conduit of an undecided board revision naming no parent in
    /// the component: the first ancestor naming none either (or the root),
    /// when every ancestor on the way fits some plain view of its parent.
    fn conduit_base(&self, comp: usize, index: usize, plain: &Worlds) -> Option<usize> {
        let node = self.node(index);
        let prior = node.prior?;
        // Only a successor that leaves the cycle (ruling condition 2).
        if node.rank != Rank::Board || !self.undecided[prior] || self.inside(comp, node.parent) {
            return None;
        }
        let mut at = prior;
        loop {
            let ancestor = self.node(at);
            if !self.inside(comp, ancestor.parent) {
                return Some(at);
            }
            let parent = ancestor.parent?;
            if !plain.views[parent]
                .iter()
                .any(|view| view.is_some_and(|view| fits(&ancestor, &view)))
            {
                return None;
            }
            match ancestor.prior {
                None => return Some(at),
                Some(next) => at = next,
            }
        }
    }

    /// Every assignment of `open` (each a joint world), with each member's
    /// views; `None` past the bound.
    fn worlds(
        &self,
        comp: usize,
        members: &[usize],
        open: &[usize],
        conduits: bool,
    ) -> Option<Worlds> {
        let mut seen = BTreeSet::new();
        let mut joint = Vec::new();
        for bits in 0u32..(1 << open.len()) {
            let mut assigned = vec![false; self.nodes.len()];
            for (slot, index) in open.iter().enumerate() {
                assigned[*index] = bits & (1 << slot) != 0;
            }
            let stands = self.stands(comp, &assigned, conduits);
            // Joint worlds that stand alike are one world.
            if seen.insert(stands.clone()) {
                joint.push(stands);
            }
        }
        let mut views = vec![Vec::new(); self.graph.projects];
        for &member in members {
            let own: Vec<usize> = open
                .iter()
                .copied()
                .filter(|index| self.node(*index).project == member)
                .collect();
            let mut assignments = BTreeSet::new();
            let mut distinct = BTreeSet::new();
            for world in &joint {
                assignments.insert(own.iter().map(|index| world[*index]).collect::<Vec<_>>());
                distinct.insert(self.walk(member, world).map(|(view, _)| view));
            }
            if distinct.len() > self.graph.bound
                || assignments.len() > self.graph.bound * (own.len() + 1)
            {
                return None;
            }
            views[member] = distinct.into_iter().collect();
        }
        Some(Worlds { joint, views })
    }

    /// Which nodes stand under one assignment.
    fn stands(&self, comp: usize, assigned: &[bool], conduits: bool) -> Vec<bool> {
        let mut stands = vec![false; self.nodes.len()];
        for index in 0..self.nodes.len() {
            let Some(node) = self.nodes[index] else {
                continue;
            };
            if self.comp[node.project] != comp {
                continue;
            }
            stands[index] = match self.label[index] {
                Label::Valid => true,
                Label::Invalid => false,
                Label::Undefined => {
                    assigned[index]
                        && (node.prior.is_none_or(|prior| stands[prior])
                            || (conduits && self.conduit[index].is_some_and(|base| stands[base])))
                }
            };
        }
        stands
    }

    /// Whether an invalid `index` fell on its parent's bounds, not on its
    /// lineage or the cycle: its lineage stands in some world, and some view
    /// of its parent whose chain stays clear of it exists while none admits it.
    fn bounds(&self, comp: usize, index: usize, worlds: &Worlds) -> bool {
        let node = self.node(index);
        let lineage = |world: &Vec<bool>| {
            node.prior.is_none_or(|prior| world[prior])
                || self.conduit[index].is_some_and(|base| world[base])
        };
        if node.prior.is_none() || !worlds.joint.iter().any(lineage) {
            return false;
        }
        let Some(parent) = node.parent.filter(|parent| self.comp[*parent] == comp) else {
            return !self.admitted_outside(&node);
        };
        let clear: Vec<Option<View>> = (worlds.joint.iter())
            .filter(|world| !self.returns(comp, parent, node.project, world))
            .map(|world| self.walk(parent, world).map(|(view, _)| view))
            .collect();
        !clear.is_empty()
            && !clear
                .iter()
                .any(|view| view.is_some_and(|view| fits(&node, &view)))
    }

    /// Whether `index` is admitted in `world`; `None` when its parent's view
    /// there is in its causal future (a root judged by a returning view).
    fn ok(&self, comp: usize, index: usize, world: &[bool]) -> Option<bool> {
        let node = self.node(index);
        let lineage = node.prior.is_none_or(|prior| world[prior])
            || self.conduit[index].is_some_and(|base| world[base]);
        let Some(parent) = node.parent.filter(|parent| self.comp[*parent] == comp) else {
            return Some(lineage && self.admitted_outside(&node));
        };
        if self.returns(comp, parent, node.project, world) {
            return if node.prior.is_none() {
                None
            } else {
                Some(false)
            };
        }
        let view = self.walk(parent, world).map(|(view, _)| view);
        Some(lineage && view.is_some_and(|view| fits(&node, &view)))
    }

    fn returns(&self, comp: usize, from: usize, to: usize, world: &[bool]) -> bool {
        let mut seen = BTreeSet::new();
        let mut at = from;
        loop {
            let Some((view, _)) = self.walk(at, world) else {
                return false;
            };
            match view.parent {
                Some(next) if next == to => return true,
                Some(next) if self.comp[next] == comp && seen.insert(next) => at = next,
                _ => return false,
            }
        }
    }

    /// A member's view in a world and the nodes its walk passes.
    fn walk(&self, member: usize, world: &[bool]) -> Option<(View, Vec<usize>)> {
        if !world[member] {
            return None;
        }
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); self.nodes.len()];
        let mut fallen: Vec<Vec<usize>> = vec![Vec::new(); self.nodes.len()];
        for index in self.graph.projects..self.nodes.len() {
            let Some(node) = self.nodes[index] else {
                continue;
            };
            if node.project != member {
                continue;
            }
            if self.fallen[index]
                && let Some(prior) = node.prior.filter(|prior| world[*prior])
            {
                fallen[prior].push(index);
            }
            if !world[index] {
                continue;
            }
            let mut at = node.prior.expect("a revision has a prior");
            while !world[at] {
                at = self.node(at).prior.expect("a standing base");
            }
            children[at].push(index);
        }
        let (view, _, path) = self.frontier(member, &children, &fallen);
        Some((view?, path))
    }

    /// A node's frontier; `None` when a child fallen on its parent's bounds
    /// is not outranked there (it hands no authority back), or below.
    fn frontier(
        &self,
        at: usize,
        children: &[Vec<usize>],
        fallen: &[Vec<usize>],
    ) -> (Option<View>, Option<Rank>, Vec<usize>) {
        let node = self.node(at);
        let own = View {
            mask: node.mask,
            depth: node.depth,
            parent: node.parent,
        };
        let branches: Vec<Branch> = children[at]
            .iter()
            .map(|child| {
                let (view, rank, path) = self.frontier(*child, children, fallen);
                (*child, view, rank.max(Some(self.node(*child).rank)), path)
            })
            .collect();
        let top = branches.iter().filter_map(|branch| branch.2).max();
        let blocking = fallen[at].iter().map(|index| self.node(*index).rank).max();
        if let Some(rank) = blocking
            && top.is_none_or(|top| rank >= top)
        {
            return (None, Some(rank).max(top), vec![at]);
        }
        let Some(top) = top else {
            return (Some(own), None, vec![at]);
        };
        let at_top: Vec<_> = branches
            .iter()
            .filter(|branch| branch.2 == Some(top))
            .collect();
        if let [(_, view, _, path)] = at_top[..] {
            let mut walked = vec![at];
            walked.extend(path);
            return (*view, Some(top), walked);
        }
        let mut met = own;
        for (_, view, _, _) in &branches {
            let Some(view) = view else {
                return (None, Some(top), vec![at]);
            };
            met.mask &= view.mask;
            met.depth = met.depth.min(view.depth);
        }
        (Some(met), Some(top), vec![at])
    }

    fn finish(&mut self, comp: usize, members: &[usize]) {
        let open: Vec<usize> = (0..self.nodes.len())
            .filter(|index| self.label[*index] == Label::Undefined && self.undecided[*index])
            .filter(|index| self.comp[self.node(*index).project] == comp)
            .collect();
        let Some(worlds) = self.worlds(comp, members, &open, true) else {
            return self.go_dark(members);
        };
        for &member in members {
            let walks: Vec<Option<(View, Vec<usize>)>> = worlds
                .joint
                .iter()
                .map(|world| self.walk(member, world))
                .collect();
            let served = if walks.iter().any(Option::is_none) {
                None
            } else {
                let walks: Vec<(View, Vec<usize>)> = walks.into_iter().flatten().collect();
                let common: BTreeSet<usize> = walks
                    .iter()
                    .map(|(_, path)| path.iter().copied().collect::<BTreeSet<_>>())
                    .reduce(|a, b| a.intersection(&b).copied().collect())
                    .unwrap_or_default();
                let carrier = common
                    .into_iter()
                    .max_by_key(|index| (self.lineage_depth(*index), *index))
                    .expect("the birth is on every walk");
                let mut met = walks[0].0;
                for (view, _) in &walks {
                    met.mask &= view.mask;
                    met.depth = met.depth.min(view.depth);
                }
                met.parent = self.node(carrier).parent;
                Some(met)
            };
            self.served[member] = Some(served);
        }
        // Served views fit their served parents and close no cycle.
        loop {
            let mut changed = false;
            for &member in members {
                let Some(Some(view)) = self.served[member] else {
                    continue;
                };
                let fits_parent = match view.parent {
                    None => view.depth < ROOT_DEPTH,
                    Some(parent) => self.served[parent].flatten().is_some_and(|above| {
                        view.depth < above.depth && view.mask & !above.mask == 0
                    }),
                };
                if !fits_parent || self.served_cycle(member) {
                    self.served[member] = Some(None);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn served_cycle(&self, member: usize) -> bool {
        let mut seen = BTreeSet::new();
        let mut at = member;
        while let Some(Some(view)) = self.served[at] {
            match view.parent {
                Some(next) if next == member => return true,
                Some(next) if seen.insert(next) => at = next,
                _ => return false,
            }
        }
        false
    }

    fn lineage_depth(&self, mut index: usize) -> usize {
        let mut depth = 0;
        while let Some(prior) = self.node(index).prior {
            depth += 1;
            index = prior;
        }
        depth
    }
}

/// One child's branch: the child, its frontier, its rank and its walk.
type Branch = (usize, Option<View>, Option<Rank>, Vec<usize>);

struct Worlds {
    /// Distinct standing sets over the whole component.
    joint: Vec<Vec<bool>>,
    /// Per member, its distinct views (`None`: no authority).
    views: Vec<Vec<Option<View>>>,
}

/// A fixed nonzero xorshift stream.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub(super) fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// Astra's fixture (seed 0): A0 and B0 under R, B1 (B's board, under A,
/// kept and extra, depth 2) withheld, A1 (A's board, under B, kept, depth 0).
pub(super) fn astra() -> Graph {
    let rev = |project, prior, parent, mask, depth, withheld| Rev {
        project,
        prior,
        parent,
        mask,
        depth,
        signer: Rank::Board,
        withheld,
    };
    Graph {
        projects: 2,
        born_under: vec![None, None],
        revs: vec![
            rev(0, None, None, KEPT | EXTRA, 3, false),
            rev(1, None, None, KEPT, 1, false),
            rev(1, Some(1), Some(0), KEPT | EXTRA, 2, true),
            rev(0, Some(0), Some(1), KEPT, 0, false),
        ],
        bound: 64,
    }
}

/// A small random graph: 2-3 projects (the third sometimes born under the
/// first), 3-8 revisions with re-parenting, narrowing, widening and board
/// successors over undecided priors; every eleventh seed bounds one view.
pub(super) fn generate(seed: u64) -> Graph {
    if seed == 0 {
        return astra();
    }
    let mut rng = Rng::new(seed);
    let projects = 2 + rng.below(2) as usize;
    let mut born_under = vec![None; projects];
    if projects == 3 && rng.below(2) == 0 {
        born_under[2] = Some(0);
    }
    let mut graph = Graph {
        projects,
        born_under,
        revs: Vec::new(),
        bound: if seed % 11 == 5 { 1 } else { 64 },
    };
    let count = 3 + rng.below(6) as usize;
    while graph.revs.len() < count {
        let project = rng.below(projects as u64) as usize;
        let own: Vec<usize> = (0..graph.revs.len())
            .filter(|index| graph.revs[*index].project == project)
            .collect();
        let pick = rng.below(own.len() as u64 + 1) as usize;
        let prior = own.get(pick).copied();
        let (before_parent, before_mask, before_depth) = match prior {
            Some(prior) => {
                let rev = &graph.revs[prior];
                (rev.parent, rev.mask, rev.depth)
            }
            None => (
                graph.born_under[project],
                KEPT | EXTRA,
                birth_depth(&graph, project),
            ),
        };
        let rev = if rng.below(6) == 0 {
            Rev {
                project,
                prior,
                parent: before_parent,
                mask: before_mask & (1 + rng.below(3) as u8),
                depth: rng.below(u64::from(before_depth) + 1) as u8,
                signer: Rank::Leader,
                withheld: rng.below(3) == 0,
            }
        } else {
            let others: Vec<usize> = (0..projects).filter(|q| *q != project).collect();
            let parent = match rng.below(3) {
                0 => None,
                _ => Some(others[rng.below(others.len() as u64) as usize]),
            };
            Rev {
                project,
                prior,
                parent,
                mask: 1 + rng.below(3) as u8,
                depth: rng.below(9) as u8,
                signer: Rank::Board,
                withheld: rng.below(3) == 0,
            }
        };
        let same = |other: &Rev| {
            Rev {
                withheld: false,
                ..other.clone()
            } == Rev {
                withheld: false,
                ..rev.clone()
            }
        };
        if rev.mask != 0 && !graph.revs.iter().any(same) {
            graph.revs.push(rev);
        }
    }
    graph
}

#[test]
fn the_reference_serves_astras_fixture_as_ruled() {
    let graph = astra();
    let expected = solve(&graph, &[true; 4]);
    let narrowed = |depth| {
        Some(View {
            mask: KEPT,
            depth,
            parent: None,
        })
    };
    assert_eq!(expected.served, vec![narrowed(0), narrowed(1)]);
    assert_eq!(
        expected.labels,
        vec![
            Label::Valid,
            Label::Valid,
            Label::Undefined,
            Label::Undefined
        ]
    );
}
