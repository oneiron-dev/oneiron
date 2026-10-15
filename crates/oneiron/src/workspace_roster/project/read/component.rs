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
            // A frozen view rests on its saved record alone.
            if let Some(saved) = PROJECT_FRONTIER.get(self.store, self.txn, &id)? {
                for hash in saved.dependencies.all() {
                    if let Some(authority) = cx.authority_of(hash) {
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
        let sealed = if over_budget { None } else { sealed_tree(&cx)? };
        if !over_budget {
            // Only a state the fold could walk names a parent here: inside the
            // owner's seal, and a boundary only once a valid signed state
            // builds on it, as for root selection.
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

/// The states the one valid seal keeps: its next, the lineage the next's
/// admission reads, and every descendant. No states when seals conflict.
fn sealed_tree(cx: &FoldCx<'_, '_, '_>) -> Result<Option<BTreeSet<ProjectRevisionHash>>> {
    let tips = cx.seal_tips()?;
    let mut only = tips.iter();
    let (Some(tip), None) = (only.next(), only.next()) else {
        return Ok((!tips.is_empty()).then(BTreeSet::new));
    };
    let mut tree = BTreeSet::new();
    let Some(ProjectRevision::Seal { seal, .. }) = cx.row(tip) else {
        return Ok(Some(tree));
    };
    let mut at = cx.row(&seal.next).and_then(ProjectRevision::parent);
    while let Some(prior) = at.filter(|prior| tree.insert(*prior)) {
        at = cx.row(&prior).and_then(ProjectRevision::parent);
    }
    let mut todo = vec![seal.next];
    while let Some(at) = todo.pop() {
        if tree.insert(at) {
            todo.extend(cx.held.children_of(&at).copied());
        }
    }
    Ok(Some(tree))
}
