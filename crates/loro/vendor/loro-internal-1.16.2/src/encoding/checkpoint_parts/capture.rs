use std::collections::BTreeMap;

use loro_common::{
    check_root_container_name, parse_mergeable_marker, ContainerID, ContainerType, Counter,
    InternalString, Lamport, LoroValue, PeerID, ID,
};
use rustc_hash::{FxHashMap, FxHashSet};

use super::types::*;
use crate::{
    arena::SharedArena,
    container::idx::ContainerIdx,
    delta::MapValue,
    encoding::json_schema::{
        export_json,
        json::{JsonChange, JsonOpContent, MapOp},
    },
    state::{container_store::ContainerWrapper, ContainerCreationContext, DocState},
    LoroDoc,
};

/// One container of a state store. A map lists every entry, deleted keys
/// included; any other container comes back without entries.
pub(super) struct StoreMap {
    pub cid: Option<ContainerID>,
    pub entries: Option<Vec<(InternalString, MapValue)>>,
}

/// The shallow root as read from a document.
pub(super) struct RawRoot {
    pub vv: Vec<(PeerID, Counter)>,
    pub frontiers: Vec<(PeerID, Counter)>,
    pub maps: Vec<StoreMap>,
}

/// Everything capture reads under the document locks.
pub(super) struct Raw {
    pub vv: Vec<(PeerID, Counter)>,
    pub frontiers: Vec<(PeerID, Counter)>,
    pub root: Option<RawRoot>,
    pub latest: Vec<StoreMap>,
    pub changes: Vec<JsonChange>,
}

/// Reads a quiescent document under its locks. It takes no implicit-commit
/// barrier: a document with uncommitted or pending work is not quiescent.
pub(super) fn read_raw(doc: &LoroDoc) -> Result<Raw, Unsupported> {
    if doc.is_detached() {
        return Err(Unsupported::NonQuiescent);
    }

    let txn = doc.txn.lock();
    let uncommitted = match &*txn {
        Some(txn) => !txn.is_empty(),
        None => false,
    };
    if uncommitted {
        return Err(Unsupported::NonQuiescent);
    }

    let oplog = doc.oplog.lock();
    let mut state = doc.state.lock();
    // An open auto-commit transaction is fine once it is empty: the check above
    // covers uncommitted ops.
    if oplog.batch_importing
        || !oplog.pending_changes.version_range().is_empty()
        || &state.frontiers != oplog.frontiers()
    {
        return Err(Unsupported::NonQuiescent);
    }

    if !doc.config.deleted_root_containers.lock().is_empty() {
        return Err(Unsupported::Shape);
    }

    let vv = oplog.vv().clone();
    let start_vv = oplog.shallow_since_vv().to_vv();
    let changes = export_json(&oplog, &start_vv, &vv, false).changes;
    let (latest, root_maps) = read_stores(&mut state);
    let root = match (oplog.is_shallow(), root_maps) {
        (true, Some(maps)) => Some(RawRoot {
            vv: vv_list(&start_vv),
            frontiers: frontiers_list(oplog.shallow_since_frontiers()),
            maps,
        }),
        (false, None) => None,
        _ => return Err(Unsupported::Shape),
    };

    Ok(Raw {
        vv: vv_list(&vv),
        frontiers: frontiers_list(oplog.frontiers()),
        root,
        latest,
        changes,
    })
}

/// Reads the latest store and, for a shallow document, the shallow-root store.
fn read_stores(state: &mut DocState) -> (Vec<StoreMap>, Option<Vec<StoreMap>>) {
    let peer = state.peer.load(std::sync::atomic::Ordering::Relaxed);
    let ctx = ContainerCreationContext {
        configure: &state.config,
        peer,
    };
    let arena = &state.arena;
    let latest: Vec<StoreMap> = state
        .store
        .iter_all_containers()
        .map(|(idx, container)| read_container(arena, ctx, idx, container))
        .collect();
    let root = state.store.shallow_root_store().map(|gc| {
        let mut store = gc.store.lock();
        let maps: Vec<StoreMap> = store
            .iter_all_containers_mut()
            .map(|(idx, container)| read_container(arena, ctx, idx, container))
            .collect();
        maps
    });
    (latest, root)
}

fn read_container(
    arena: &SharedArena,
    ctx: ContainerCreationContext<'_>,
    idx: ContainerIdx,
    container: &mut ContainerWrapper,
) -> StoreMap {
    let entries = if idx.get_type() == ContainerType::Map {
        container.get_state(idx, ctx).as_map_state().map(|map| {
            map.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
    } else {
        None
    };
    StoreMap {
        cid: arena.get_container_id(idx),
        entries,
    }
}

/// Plain data only: no container reference at any depth.
fn plain_value(value: &LoroValue) -> bool {
    match value {
        LoroValue::Container(_) => false,
        LoroValue::List(list) => list.iter().all(plain_value),
        LoroValue::Map(map) => map.values().all(plain_value),
        _ => true,
    }
}

fn sort_maps(maps: &mut [StoreMap]) {
    maps.sort_by_key(|map| map.cid.as_ref().map(|cid| cid.to_string()));
}

impl LoroDoc {
    /// Splits a checkpoint copy into a payload-free skeleton and one atom per
    /// value or commit message.
    ///
    /// Only a quiescent document (attached, committed, nothing pending) whose
    /// containers are all root maps named in `fixed_roots` is classified, and
    /// only when `classify` proves every key plain and gives every value and
    /// message its holders. Anything else is [`Capture::Unclassified`].
    pub fn export_root_map_checkpoint<C: Classify + ?Sized>(
        &self,
        fixed_roots: &[&str],
        classify: &mut C,
    ) -> Capture {
        let parts = read_raw(self).and_then(|raw| Builder::new(fixed_roots).build(raw, classify));
        match parts {
            Ok(parts) => Capture::Classified(parts),
            Err(why) => Capture::Unclassified(why),
        }
    }
}

struct Builder<'f> {
    fixed: &'f [&'f str],
    roots: Vec<String>,
    root_index: FxHashMap<String, u32>,
    plain: FxHashSet<(u32, String)>,
    slots: Vec<Slot>,
    atoms: Vec<Atom>,
    /// Retained map ops by (peer, lamport): root, key and value atom.
    ops: FxHashMap<(PeerID, Lamport), (u32, String, Option<AtomId>)>,
}

impl<'f> Builder<'f> {
    fn new(fixed: &'f [&'f str]) -> Self {
        Self {
            fixed,
            roots: Vec::new(),
            root_index: FxHashMap::default(),
            plain: FxHashSet::default(),
            slots: Vec::new(),
            atoms: Vec::new(),
            ops: FxHashMap::default(),
        }
    }

    fn build<C: Classify + ?Sized>(mut self, raw: Raw, c: &mut C) -> Result<Parts, Unsupported> {
        let Raw {
            vv,
            frontiers,
            root,
            mut latest,
            mut changes,
        } = raw;
        // Lamport order is causal; the peer breaks ties so the skeleton is canonical.
        changes.sort_by_key(|change| (change.lamport, change.id.peer));
        let mut skeleton_changes = Vec::with_capacity(changes.len());
        for change in &changes {
            skeleton_changes.push(self.change(c, change)?);
        }

        let shallow = match root {
            Some(root) => Some(self.shallow(c, root)?),
            None => None,
        };

        // Each key's latest winner is the greatest (lamport, peer) among its
        // retained ops and its shallow-root winner, as Loro's history cache
        // resolves it. Loro may keep an older id in state when a write did not
        // change the value, so the latest state is checked by value only.
        let mut latest_winners: BTreeMap<(u32, String), Winner> = BTreeMap::new();
        for winner in shallow.iter().flat_map(|root| root.winners.iter()) {
            latest_winners.insert((winner.root, winner.key.clone()), winner.clone());
        }
        for (&(peer, lamport), (root, key, value)) in &self.ops {
            let slot = (*root, key.clone());
            if latest_winners
                .get(&slot)
                .is_some_and(|winner| (winner.lamport, winner.peer) >= (lamport, peer))
            {
                continue;
            }
            let winner = Winner {
                root: *root,
                key: key.clone(),
                peer,
                lamport,
                value: *value,
            };
            latest_winners.insert(slot, winner);
        }

        sort_maps(&mut latest);
        let mut latest_maps = Vec::with_capacity(latest.len());
        let mut checked = 0;
        for map in &latest {
            let root = self.root(map.cid.as_ref())?;
            latest_maps.push(root);
            for (key, entry) in map.entries.as_ref().ok_or(Unsupported::Shape)? {
                let winner = latest_winners
                    .get(&(root, key.to_string()))
                    .ok_or(Unsupported::Shape)?;
                if !self.same(winner.value, &entry.value) {
                    return Err(Unsupported::Shape);
                }
                checked += 1;
            }
        }
        if checked != latest_winners.len() {
            return Err(Unsupported::Shape);
        }

        let Builder {
            roots,
            slots,
            atoms,
            ..
        } = self;
        Ok(Parts {
            skeleton: Skeleton {
                roots,
                shallow,
                vv,
                frontiers,
                latest_maps,
                latest: latest_winners.into_values().collect(),
                changes: skeleton_changes,
                slots,
            },
            atoms,
        })
    }

    fn change<C: Classify + ?Sized>(
        &mut self,
        c: &mut C,
        change: &JsonChange,
    ) -> Result<SkelChange, Unsupported> {
        let message = match change.msg.as_deref() {
            Some(message) => Some(self.message(c, change.id, message)?),
            None => None,
        };
        let mut ops = Vec::with_capacity(change.ops.len());
        for (i, op) in change.ops.iter().enumerate() {
            // Map ops are one atom long, so op i sits at the change counter plus i.
            if i64::from(op.counter) != i64::from(change.id.counter) + i as i64 {
                return Err(Unsupported::Shape);
            }

            let root = self.root(Some(&op.container))?;
            let (key, value) = match &op.content {
                JsonOpContent::Map(MapOp::Insert { key, value }) => (key, Some(value)),
                JsonOpContent::Map(MapOp::Delete { key }) => (key, None),
                _ => return Err(Unsupported::Shape),
            };
            self.key(c, root, key)?;
            let id = ID::new(change.id.peer, op.counter);
            let value = match value {
                Some(value) => Some(self.value(c, root, key, value, Site::Op(id))?),
                None => None,
            };
            let lamport = change.lamport + i as Lamport;
            self.ops
                .insert((id.peer, lamport), (root, key.clone(), value));
            ops.push(SkelOp {
                root,
                key: key.clone(),
                value,
            });
        }

        let mut deps: Vec<_> = change.deps.iter().map(|id| (id.peer, id.counter)).collect();
        deps.sort_unstable();
        Ok(SkelChange {
            peer: change.id.peer,
            counter: change.id.counter,
            lamport: change.lamport,
            timestamp: change.timestamp,
            deps,
            message,
            ops,
        })
    }

    fn shallow<C: Classify + ?Sized>(
        &mut self,
        c: &mut C,
        root: RawRoot,
    ) -> Result<ShallowRoot, Unsupported> {
        let RawRoot {
            vv,
            frontiers,
            mut maps,
        } = root;
        sort_maps(&mut maps);
        let mut root_maps = Vec::with_capacity(maps.len());
        let mut winners = Vec::new();
        for map in &maps {
            let root = self.root(map.cid.as_ref())?;
            root_maps.push(root);
            for (key, entry) in map.entries.as_ref().ok_or(Unsupported::Shape)? {
                self.key(c, root, key)?;
                // A root winner whose op is retained shares that op's atom.
                let value = match self.retained(root, key, entry)? {
                    Some(value) => value,
                    None => match &entry.value {
                        Some(value) => Some(self.value(c, root, key, value, Site::Root)?),
                        None => None,
                    },
                };
                winners.push(Winner {
                    root,
                    key: key.to_string(),
                    peer: entry.peer,
                    lamport: entry.lamp,
                    value,
                });
            }
        }

        Ok(ShallowRoot {
            vv,
            frontiers,
            maps: root_maps,
            winners,
        })
    }

    fn root(&mut self, cid: Option<&ContainerID>) -> Result<u32, Unsupported> {
        let Some(ContainerID::Root {
            name,
            container_type,
        }) = cid
        else {
            return Err(Unsupported::Shape);
        };
        let allowed = *container_type == ContainerType::Map
            && check_root_container_name(name)
            && self.fixed.contains(&name.as_str());
        if !allowed {
            return Err(Unsupported::Root);
        }

        if let Some(&index) = self.root_index.get(name.as_str()) {
            return Ok(index);
        }

        let index = self.roots.len() as u32;
        self.roots.push(name.to_string());
        self.root_index.insert(name.to_string(), index);
        Ok(index)
    }

    fn key<C: Classify + ?Sized>(
        &mut self,
        c: &mut C,
        root: u32,
        key: &str,
    ) -> Result<(), Unsupported> {
        let entry = (root, key.to_string());
        if self.plain.contains(&entry) {
            return Ok(());
        }

        if !c.plain_key(&self.roots[root as usize], key) {
            return Err(Unsupported::Key);
        }

        self.plain.insert(entry);
        Ok(())
    }

    fn value<C: Classify + ?Sized>(
        &mut self,
        c: &mut C,
        root: u32,
        key: &str,
        value: &LoroValue,
        site: Site,
    ) -> Result<AtomId, Unsupported> {
        let name = &self.roots[root as usize];
        let cid = ContainerID::Root {
            name: name.as_str().into(),
            container_type: ContainerType::Map,
        };
        if !plain_value(value) || parse_mergeable_marker(&cid, key, value).is_some() {
            return Err(Unsupported::Shape);
        }

        let holders = c.holders(Field::Value {
            root: name,
            key,
            value,
            site,
        });
        self.push(holders, SlotKind::Value, Payload::Value(value.clone()))
    }

    fn message<C: Classify + ?Sized>(
        &mut self,
        c: &mut C,
        change: ID,
        message: &str,
    ) -> Result<AtomId, Unsupported> {
        let holders = c.holders(Field::Message { change, message });
        self.push(
            holders,
            SlotKind::Message,
            Payload::Message(message.to_string()),
        )
    }

    fn push(
        &mut self,
        holders: Option<Vec<OwnerId>>,
        kind: SlotKind,
        payload: Payload,
    ) -> Result<AtomId, Unsupported> {
        let mut holders = holders
            .filter(|holders| !holders.is_empty())
            .ok_or(Unsupported::Ownership)?;
        holders.sort_unstable();
        holders.dedup();
        let id = self.slots.len() as AtomId;
        self.slots.push(Slot {
            kind,
            holders: holders.clone(),
        });
        self.atoms.push(Atom {
            id,
            holders,
            payload,
        });
        Ok(id)
    }

    /// The atom of the retained op that wrote `entry`, checked against it.
    fn retained(
        &self,
        root: u32,
        key: &str,
        entry: &MapValue,
    ) -> Result<Option<Option<AtomId>>, Unsupported> {
        let Some((op_root, op_key, atom)) = self.ops.get(&(entry.peer, entry.lamp)) else {
            return Ok(None);
        };
        if *op_root != root || op_key != key || !self.same(*atom, &entry.value) {
            return Err(Unsupported::Shape);
        }

        Ok(Some(*atom))
    }

    fn same(&self, atom: Option<AtomId>, value: &Option<LoroValue>) -> bool {
        match (atom, value) {
            (None, None) => true,
            (Some(id), Some(value)) => matches!(
                self.atoms.get(id as usize).map(|atom| &atom.payload),
                Some(Payload::Value(payload)) if payload == value
            ),
            _ => false,
        }
    }
}
