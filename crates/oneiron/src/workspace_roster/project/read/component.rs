//! A project's facts on its own and the component of "names as parent" it
//! belongs to: what `joint.rs` decides together.
use super::super::history_policy::{PROJECT_FRONTIER, budget_count, policy_in};
use super::super::revision::{ProjectRevision, ProjectRevisionHash, RevisionOrigin};
use super::super::validity::FoldCx;
use super::super::*;
use super::{Facts, ProjectReader, ProjectVerdict};
use std::collections::BTreeMap;
use std::rc::Rc;

impl ProjectReader<'_, '_> {
    /// One project's facts; `None` when no PROJECT row is stored.
    pub(in super::super) fn facts(&self, id: EntityId) -> Result<Option<Rc<Facts>>> {
        if let Some(known) = self.facts.borrow().get(&id) {
            return Ok(known.clone());
        }
        let facts = match self.stored_row(id)? {
            None => None,
            Some(record) => Some(Rc::new(self.read_facts(id, record)?)),
        };
        self.facts.borrow_mut().insert(id, facts.clone());
        Ok(facts)
    }

    fn read_facts(&self, id: EntityId, record: ProjectRecord) -> Result<Facts> {
        let held = self.held_of(id)?;
        let cx = FoldCx::intrinsic(self, id, &held);
        let count = budget_count(&cx)?;
        let over_budget = count > policy_in(self.store, self.txn)?.max_revisions;
        let mut signed = false;
        let mut edges = BTreeSet::new();
        let parents_of = |authority: &ProjectAuthority, edges: &mut BTreeSet<EntityId>| {
            edges.extend(
                (authority.parents.iter()).filter_map(|parent| EntityId::from_hex(parent).ok()),
            );
        };
        for (hash, row) in &held.rows {
            if matches!(row.revision, ProjectRevision::Signed { .. })
                && cx.origin(*hash)? == RevisionOrigin::Authenticated
            {
                signed = true;
            }
        }
        if over_budget {
            // A frozen view rests on its saved record alone: the parents of
            // every state its re-check reads (each dependency's lineage, and
            // the states its seal and resolution envelopes read).
            if let Some(saved) = PROJECT_FRONTIER.get(self.store, self.txn, &id)? {
                // A context of its own: a state the count judged (a seal
                // the saved record never read) names nothing here (Sol and
                // Astra #1434 r16 F1), nor does an undefined node, checked on
                // its own lineage.
                let saved_cx = FoldCx::intrinsic(self, id, &held);
                for hash in saved.dependencies.checked() {
                    saved_cx.verdict(*hash)?;
                }
                for (hash, verdict) in saved_cx.judged().0 {
                    if let Some(authority) = saved_cx.authority_of(&hash)
                        && verdict == ProjectVerdict::Visible
                    {
                        parents_of(authority, &mut edges);
                    }
                }
                if let Some(effective) = &saved.effective {
                    edges.extend(
                        (effective.parents.iter())
                            .filter_map(|parent| EntityId::from_hex(parent).ok()),
                    );
                }
            }
        }
        // The one choice of the owner's unretired seals, the same in every
        // world since no target's verdict enters it (ruling (c)), and the one
        // tip's tree: discovery, the solver and every fold that reads parents
        // keep to it (Engine, Astra-c).
        let seals = if over_budget {
            BTreeSet::new()
        } else {
            cx.seal_status()?.tips.clone()
        };
        let sealed = sealed_tree(&cx, &seals);
        if !over_budget {
            // Each state a fold reading parents can judge names its parents
            // here: under one owner seal, only its tree, which is all such a
            // fold judges (validity.rs); with conflicting seals, every one,
            // since the fold judges each seal (Astra #1434c F2). A boundary
            // does only once a valid signed state builds on it, as for root
            // selection.
            let visible = |hash: &ProjectRevisionHash| -> Result<bool> {
                Ok(cx.verdict(*hash)? == ProjectVerdict::Visible)
            };
            for (hash, row) in &held.rows {
                let Some(authority) = row.revision.authority() else {
                    continue;
                };
                if !visible(hash)? || sealed.as_ref().is_some_and(|tree| !tree.contains(hash)) {
                    continue;
                }
                if matches!(row.revision, ProjectRevision::Boundary { .. }) {
                    let mut built_on = false;
                    for child in held.children_of(hash) {
                        built_on |= visible(child)?;
                    }
                    if !built_on {
                        continue;
                    }
                }
                parents_of(authority, &mut edges);
            }
        }
        if !signed {
            parents_of(&record.authority(), &mut edges);
        }
        edges.remove(&id);
        let (intrinsic, signers) = if over_budget {
            Default::default()
        } else {
            cx.judged()
        };
        drop(cx);
        Ok(Facts {
            record,
            held,
            count,
            over_budget,
            signed,
            intrinsic,
            signers,
            edges,
            seals,
            sealed,
        })
    }

    /// The strongly connected set of "names as parent" holding `id`, in id
    /// order (Tarjan, iterative), memoized for every set the search closes.
    pub(crate) fn component(&self, id: EntityId) -> Result<Rc<Vec<EntityId>>> {
        if let Some(known) = self.components.borrow().get(&id) {
            return Ok(Rc::clone(known));
        }
        let mut index: BTreeMap<EntityId, (usize, usize)> = BTreeMap::new();
        let mut stack: Vec<EntityId> = Vec::new();
        let mut on_stack = BTreeSet::new();
        let mut calls: Vec<(EntityId, Vec<EntityId>)> = Vec::new();
        let visit = |node: EntityId,
                     index: &mut BTreeMap<EntityId, (usize, usize)>,
                     stack: &mut Vec<EntityId>,
                     on_stack: &mut BTreeSet<EntityId>|
         -> Result<Vec<EntityId>> {
            let next = index.len();
            index.insert(node, (next, next));
            stack.push(node);
            on_stack.insert(node);
            let mut edges: Vec<EntityId> = match self.facts(node)? {
                Some(facts) => facts.edges.iter().copied().collect(),
                None => Vec::new(),
            };
            edges.reverse();
            Ok(edges)
        };
        let edges = visit(id, &mut index, &mut stack, &mut on_stack)?;
        calls.push((id, edges));
        while let Some((node, edges)) = calls.last_mut() {
            let node = *node;
            if let Some(next) = edges.pop() {
                if self.components.borrow().contains_key(&next) || self.facts(next)?.is_none() {
                    continue;
                }
                match index.get(&next) {
                    None => {
                        let edges = visit(next, &mut index, &mut stack, &mut on_stack)?;
                        calls.push((next, edges));
                    }
                    Some((at, _)) if on_stack.contains(&next) => {
                        let at = *at;
                        let entry = index.get_mut(&node).ok_or_else(invalid)?;
                        entry.1 = entry.1.min(at);
                    }
                    Some(_) => {}
                }
                continue;
            }
            calls.pop();
            let (at, low) = index[&node];
            if let Some((caller, _)) = calls.last() {
                let caller = *caller;
                let entry = index.get_mut(&caller).ok_or_else(invalid)?;
                entry.1 = entry.1.min(low);
            }
            if at == low {
                let mut members = Vec::new();
                while let Some(member) = stack.pop() {
                    on_stack.remove(&member);
                    members.push(member);
                    if member == node {
                        break;
                    }
                }
                members.sort();
                self.closed.borrow_mut().extend(members.iter().copied());
                let members = Rc::new(members);
                for member in members.iter() {
                    self.components
                        .borrow_mut()
                        .insert(*member, Rc::clone(&members));
                }
            }
        }
        self.components
            .borrow()
            .get(&id)
            .cloned()
            .ok_or_else(invalid)
    }
}

/// The states the one seal tip keeps: its next and every descendant, and
/// its next's lineage, which the seal's own verdict reads. A seal it retires
/// roots nothing and its verdict reads no retired target, so no retired
/// seal's lineage is kept (ruling (c)). None without a seal or when seals
/// conflict.
fn sealed_tree(
    cx: &FoldCx<'_, '_, '_>,
    tips: &BTreeSet<ProjectRevisionHash>,
) -> Option<BTreeSet<ProjectRevisionHash>> {
    let tip = *tips.first().filter(|_| tips.len() == 1)?;
    let mut tree = BTreeSet::new();
    let Some(ProjectRevision::Seal { seal: active, .. }) = cx.row(&tip) else {
        return Some(tree);
    };
    let mut lineage = Some(active.next);
    while let Some(node) = lineage.filter(|node| tree.insert(*node)) {
        lineage = cx.row(&node).and_then(ProjectRevision::parent);
    }
    let (mut todo, mut below) = (vec![active.next], BTreeSet::new());
    while let Some(at) = todo.pop() {
        if below.insert(at) {
            todo.extend(cx.held.children_of(&at).copied());
        }
    }
    tree.extend(below);
    Some(tree)
}
