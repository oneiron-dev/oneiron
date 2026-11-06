//! Rebuild held retained operations with an unchanged root or exact frontier retarget.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{Atom, AtomId, Parts, Payload, ShallowRoot, Skeleton, Winner};
use loro::json::{JsonOpContent, MapOp};
use loro::{
    ContainerID, ContainerType, Counter, EncodedBlobMode, ImportBlobMetadata, Lamport, LoroDoc,
    LoroValue, PeerID,
};

use super::super::history::needs_whole_hold;
use super::super::{InboundRow, SyncSecretProjection};
use super::{ROWS, WindowAdmission, meta, parts_of, readable_from, same_span};
use crate::store::Store;
use crate::sync::selector::{HELD_EDIT_CAUSALITY_KEY, HELD_EDIT_CAUSALITY_MAP};

impl SyncSecretProjection {
    /// Rebuild retained holds, preserving the root except for the same held frontier write.
    /// Any unsupported shape keeps the caller's original whole-blob hold.
    pub(super) fn admit_held_shallow_snapshot<'a>(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        doc: &LoroDoc,
        input: &ImportBlobMetadata,
    ) -> Option<WindowAdmission<'a>> {
        if input.mode != EncodedBlobMode::ShallowSnapshot {
            return None;
        }
        let parts = parts_of(doc)?;
        let root_plan = self.shallow_root_plan(store, context, &parts)?;
        let Parts {
            mut skeleton,
            mut atoms,
        } = parts;
        let rows = skeleton.roots.iter().position(|root| root == ROWS)?;
        let start = doc.shallow_since_vv().to_vv();
        if !readable_from(doc, &start) {
            return None;
        }
        let mut tail = doc.export_json_updates_without_peer_compression(&start, &doc.oplog_vv());
        let original = tail.clone();
        self.resolve_copy_carriers(store, &mut tail);
        let translated = self.translate_history(store, context, &mut tail).ok()?;
        if tail.peers.is_some() || translated.held.is_empty() || needs_whole_hold(&tail) {
            return None;
        }
        self.unread_rows(store, context, &tail).ok()?;
        let mut operations = BTreeMap::new();
        if original.changes.len() != tail.changes.len() {
            return None;
        }
        for (before, after) in original.changes.iter().zip(&tail.changes) {
            if before.id != after.id || before.ops.len() != after.ops.len() {
                return None;
            }
            for (before_op, after_op) in before.ops.iter().zip(&after.ops) {
                if before_op.counter != after_op.counter
                    || operations
                        .insert((after.id.peer, after_op.counter), (before_op, after_op))
                        .is_some()
                {
                    return None;
                }
            }
        }
        let causality = ContainerID::Root {
            name: HELD_EDIT_CAUSALITY_MAP.into(),
            container_type: ContainerType::Map,
        };
        let causality_index = match skeleton
            .roots
            .iter()
            .position(|root| root == HELD_EDIT_CAUSALITY_MAP)
        {
            Some(index) => index as u32,
            None => {
                skeleton.roots.push(HELD_EDIT_CAUSALITY_MAP.to_string());
                (skeleton.roots.len() - 1) as u32
            }
        };
        let atom_index: BTreeMap<_, _> = atoms
            .iter()
            .enumerate()
            .map(|(index, atom)| (atom.id, index))
            .collect();
        let mut held_atoms = BTreeSet::new();
        for change in &mut skeleton.changes {
            for (index, op) in change.ops.iter_mut().enumerate() {
                let (before, after) =
                    operations.remove(&(change.peer, change.counter + index as Counter))?;
                let ContainerID::Root {
                    name,
                    container_type: ContainerType::Map,
                } = &before.container
                else {
                    return None;
                };
                if skeleton.roots.get(op.root as usize)?.as_str() != name.as_str() {
                    return None;
                }
                let (key, value) = match &after.content {
                    JsonOpContent::Map(MapOp::Insert { key, value }) => (key, Some(value)),
                    JsonOpContent::Map(MapOp::Delete { key }) => (key, None),
                    _ => return None,
                };
                if before.container != after.container {
                    if after.container != causality
                        || key != HELD_EDIT_CAUSALITY_KEY
                        || value.is_some()
                        || op.root as usize != rows
                    {
                        return None;
                    }
                    let atom = op.value?;
                    let frontier = root_plan.held.as_ref().is_some_and(|held| {
                        held.atom == atom
                            && held.peer == change.peer
                            && held.counter == change.counter + index as Counter
                            && held.lamport == change.lamport + index as Lamport
                            && held.key == op.key
                    });
                    if (root_plan.atoms.contains(&atom) && !frontier) || !held_atoms.insert(atom) {
                        return None;
                    }
                    op.root = causality_index;
                    op.key = HELD_EDIT_CAUSALITY_KEY.to_string();
                    op.value = None;
                    continue;
                }
                match (op.value, value) {
                    (Some(id), Some(value)) => {
                        let atom = atoms.get_mut(*atom_index.get(&id)?)?;
                        let Payload::Value(old_value) = &atom.payload else {
                            return None;
                        };
                        let changed_value = old_value != value;
                        if root_plan.atoms.contains(&id) && (op.key != *key || changed_value) {
                            return None;
                        }
                        if changed_value {
                            atom.payload = Payload::Value(value.clone());
                        }
                    }
                    (None, None) => {}
                    _ => return None,
                }
                op.key.clone_from(key);
            }
        }
        if !operations.is_empty() || held_atoms.len() != translated.held.len() {
            return None;
        }
        if let Some(held) = &root_plan.held {
            if !held_atoms.contains(&held.atom) {
                return None;
            }
            let shallow = skeleton.shallow.as_mut()?;
            let winner = shallow.winners.get_mut(held.winner)?;
            if winner.root as usize != rows
                || winner.key != held.key
                || winner.peer != held.peer
                || winner.lamport != held.lamport
                || winner.value != Some(held.atom)
            {
                return None;
            }
            winner.root = causality_index;
            winner.key = HELD_EDIT_CAUSALITY_KEY.to_string();
            winner.value = None;
            if !shallow.maps.contains(&causality_index) {
                shallow.maps.push(causality_index);
            }
        }
        recompute_latest(&mut skeleton);
        if !skeleton.latest_maps.contains(&causality_index) {
            skeleton.latest_maps.push(causality_index);
        }
        let references_held =
            |atom: Option<AtomId>| atom.is_some_and(|id| held_atoms.contains(&id));
        if skeleton.changes.iter().any(|change| {
            references_held(change.message) || change.ops.iter().any(|op| references_held(op.value))
        }) || skeleton
            .shallow
            .as_ref()?
            .winners
            .iter()
            .chain(&skeleton.latest)
            .any(|winner| references_held(winner.value))
        {
            return None;
        }
        atoms.retain(|atom| !held_atoms.contains(&atom.id));
        let erased: Vec<_> = held_atoms.into_iter().collect();
        let joined = LoroDoc::join_root_map_checkpoint(&skeleton, &atoms, &erased).ok()?;
        if !same_span(input, &meta(&joined.bytes)?, &input.mode) {
            return None;
        }
        let check_doc = LoroDoc::from_snapshot(&joined.bytes).ok()?;
        let mut check_parts = parts_of(&check_doc)?;
        if root_plan.expected
            != root_snapshot(
                &check_parts.skeleton.shallow,
                &check_parts.atoms,
                &check_parts.skeleton.roots,
            )?
        {
            return None;
        }
        let mut check_held = Vec::new();
        let mut check_landings = Vec::new();
        if self
            .admit_parts(
                store,
                context,
                &mut check_parts,
                &mut check_held,
                &mut check_landings,
            )
            .ok()?
            || !check_held.is_empty()
            || !check_landings.is_empty()
        {
            return None;
        }
        Some(WindowAdmission::Admit(
            Cow::Owned(joined.bytes),
            translated.landings,
            translated.held,
        ))
    }

    /// Judge each original winner by its own key and payload, not another atom's site.
    fn shallow_root_plan(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        parts: &Parts,
    ) -> Option<ShallowRootPlan> {
        let shallow = parts.skeleton.shallow.as_ref()?;
        let atoms: BTreeMap<_, _> = parts
            .atoms
            .iter()
            .map(|atom| (atom.id, &atom.payload))
            .collect();
        let mut plan = ShallowRootPlan {
            atoms: BTreeSet::new(),
            held: None,
            expected: root_snapshot(&parts.skeleton.shallow, &parts.atoms, &parts.skeleton.roots)?,
        };
        for (index, winner) in shallow.winners.iter().enumerate() {
            let aliased = self.source_key(&winner.key).is_some();
            let Some(atom) = winner.value else {
                if aliased {
                    return None;
                }
                continue;
            };
            plan.atoms.insert(atom);
            if parts.skeleton.roots.get(winner.root as usize)? != ROWS {
                if aliased {
                    return None;
                }
                continue;
            }
            let id = crate::entity_id::EntityId::from_hex(&winner.key).ok()?;
            let Payload::Value(LoroValue::Binary(raw)) = atoms.get(&atom)? else {
                return None;
            };
            let raw: &[u8] = raw;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            match self
                .source_row(&id, carrier.as_deref().unwrap_or(raw))
                .ok()?
            {
                InboundRow::Ordinary if !aliased => self.unread_row(store, context, &id).ok()?,
                InboundRow::Held(_) => {
                    let &[(peer, counter)] = shallow.frontiers.as_slice() else {
                        return None;
                    };
                    let (change, offset, op) =
                        parts.skeleton.changes.iter().find_map(|change| {
                            (change.peer == peer)
                                .then(|| {
                                    change.ops.iter().enumerate().find_map(|(offset, op)| {
                                        (change.counter + offset as Counter == counter)
                                            .then_some((change, offset, op))
                                    })
                                })
                                .flatten()
                        })?;
                    if plan.held.is_some()
                        || winner.peer != peer
                        || winner.lamport != change.lamport + offset as Lamport
                        || op.root != winner.root
                        || op.key != winner.key
                        || op.value != Some(atom)
                        || shallow
                            .winners
                            .iter()
                            .filter(|other| other.value == Some(atom))
                            .count()
                            != 1
                        || parts
                            .skeleton
                            .changes
                            .iter()
                            .flat_map(|change| &change.ops)
                            .filter(|other| other.root == winner.root && other.key == winner.key)
                            .count()
                            != 1
                    {
                        return None;
                    }
                    plan.held = Some(HeldRoot {
                        winner: index,
                        atom,
                        peer,
                        counter,
                        lamport: winner.lamport,
                        key: winner.key.clone(),
                    });
                }
                InboundRow::Ordinary | InboundRow::Source { .. } => return None,
            }
        }
        if let Some(held) = &plan.held {
            if parts
                .skeleton
                .changes
                .iter()
                .flat_map(|change| &change.ops)
                .any(|op| {
                    parts
                        .skeleton
                        .roots
                        .get(op.root as usize)
                        .is_some_and(|name| name == HELD_EDIT_CAUSALITY_MAP)
                        && op.key == HELD_EDIT_CAUSALITY_KEY
                })
            {
                return None;
            }
            let old = plan
                .expected
                .winners
                .remove(&(ROWS.to_string(), held.key.clone()))?;
            if old.0 != held.peer
                || old.1 != held.lamport
                || old.2.is_none()
                || plan
                    .expected
                    .winners
                    .insert(
                        (
                            HELD_EDIT_CAUSALITY_MAP.to_string(),
                            HELD_EDIT_CAUSALITY_KEY.to_string(),
                        ),
                        (held.peer, held.lamport, None),
                    )
                    .is_some()
            {
                return None;
            }
            plan.expected
                .maps
                .insert(HELD_EDIT_CAUSALITY_MAP.to_string());
        }
        Some(plan)
    }
}

struct ShallowRootPlan {
    atoms: BTreeSet<AtomId>,
    held: Option<HeldRoot>,
    expected: RootSnapshot,
}

struct HeldRoot {
    winner: usize,
    atom: AtomId,
    peer: PeerID,
    counter: Counter,
    lamport: Lamport,
    key: String,
}

/// Recompute every group after held retargets and possibly coalescing key rewrites.
fn recompute_latest(skeleton: &mut Skeleton) {
    let mut latest = BTreeMap::new();
    for winner in skeleton.shallow.iter().flat_map(|root| &root.winners) {
        latest.insert((winner.root, winner.key.clone()), winner.clone());
    }
    for change in &skeleton.changes {
        for (index, op) in change.ops.iter().enumerate() {
            let lamport = change.lamport + index as Lamport;
            let slot = (op.root, op.key.clone());
            if latest
                .get(&slot)
                .is_some_and(|winner| (winner.lamport, winner.peer) >= (lamport, change.peer))
            {
                continue;
            }
            latest.insert(
                slot,
                Winner {
                    root: op.root,
                    key: op.key.clone(),
                    peer: change.peer,
                    lamport,
                    value: op.value,
                },
            );
        }
    }
    skeleton.latest = latest.into_values().collect();
}

#[derive(PartialEq)]
struct RootSnapshot {
    vv: Vec<(PeerID, Counter)>,
    frontiers: Vec<(PeerID, Counter)>,
    maps: BTreeSet<String>,
    winners: BTreeMap<(String, String), (PeerID, Lamport, Option<LoroValue>)>,
}

/// Compare roots by map names and actual values, never recapture-dependent atom ordinals.
fn root_snapshot(
    shallow: &Option<ShallowRoot>,
    atoms: &[Atom],
    roots: &[String],
) -> Option<RootSnapshot> {
    let shallow = shallow.as_ref()?;
    let maps = shallow
        .maps
        .iter()
        .map(|map| roots.get(*map as usize).cloned())
        .collect::<Option<_>>()?;
    let by_id: BTreeMap<_, _> = atoms.iter().map(|atom| (atom.id, &atom.payload)).collect();
    let mut winners = BTreeMap::new();
    for winner in &shallow.winners {
        let root = roots.get(winner.root as usize)?.clone();
        let value = match winner.value {
            None => None,
            Some(id) => match by_id.get(&id)? {
                Payload::Value(value) => Some(value.clone()),
                Payload::Message(_) | Payload::Key(_) => return None,
            },
        };
        if winners
            .insert(
                (root, winner.key.clone()),
                (winner.peer, winner.lamport, value),
            )
            .is_some()
        {
            return None;
        }
    }
    Some(RootSnapshot {
        vv: shallow.vv.clone(),
        frontiers: shallow.frontiers.clone(),
        maps,
        winners,
    })
}
