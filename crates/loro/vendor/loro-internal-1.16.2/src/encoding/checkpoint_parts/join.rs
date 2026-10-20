use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{atomic::AtomicI64, Arc},
};

use loro_common::{
    check_root_container_name, ContainerID, ContainerType, Counter, Lamport, LoroValue, PeerID, ID,
};
use rustc_hash::FxHashMap;

use super::{
    capture::{read_raw, StoreMap},
    types::*,
};
use crate::{
    delta::MapValue,
    encoding::{
        encode_with,
        fast_snapshot::{_encode_snapshot, Snapshot},
        json_schema::{
            decode_json_changes,
            json::{JsonChange, JsonOp, JsonOpContent, JsonSchema, MapOp},
        },
        EncodeMode, ExportMode,
    },
    oplog::ChangeStore,
    state::container_store::FRONTIERS_KEY,
    version::Frontiers,
    LoroDoc,
};

/// The only JSON schema version `decode_json_changes` accepts.
const JSON_SCHEMA_VERSION: u8 = 1;

impl LoroDoc {
    /// Rebuilds a native document from a skeleton after some atoms were erased.
    ///
    /// Every slot must be either opened (in `available`) or listed in `erased`.
    /// An erased value becomes a map delete at its original op id and lamport;
    /// an erased message becomes no message. The result is proven against the
    /// skeleton before this returns; on any mismatch it returns
    /// [`CheckpointError::Diverged`] and no bytes.
    pub fn join_root_map_checkpoint(
        skeleton: &Skeleton,
        available: &[Atom],
        erased: &[AtomId],
    ) -> Result<Joined, CheckpointError> {
        validate(skeleton)?;
        let opened = open_slots(skeleton, available, erased)?;
        let history = history_json(skeleton, &opened);
        let assembled = match &skeleton.shallow {
            None => full_history_snapshot(history)?,
            Some(root) => shallow_snapshot(skeleton, root, history, &opened)?,
        };

        // Re-export through Loro's own snapshot path, then prove the bytes as reopened.
        let doc = LoroDoc::from_snapshot(&assembled)?;
        ensure_maps(&doc, skeleton, &skeleton.latest_maps);
        let bytes = doc.export(ExportMode::Snapshot)?;
        let doc = LoroDoc::from_snapshot(&bytes)?;
        let report = verify(&doc, skeleton, &opened)?;
        Ok(Joined { bytes, report })
    }
}

fn malformed(why: &str) -> CheckpointError {
    CheckpointError::Malformed(why.to_string())
}

fn diverged(why: impl Into<String>) -> CheckpointError {
    CheckpointError::Diverged(why.into())
}

fn root_cid(skeleton: &Skeleton, root: u32) -> ContainerID {
    ContainerID::Root {
        name: skeleton.roots[root as usize].as_str().into(),
        container_type: ContainerType::Map,
    }
}

/// Structural checks that keep a malformed skeleton from reaching Loro's
/// internal assertions.
fn validate(skeleton: &Skeleton) -> Result<(), CheckpointError> {
    if !skeleton
        .roots
        .iter()
        .all(|name| check_root_container_name(name))
    {
        return Err(malformed("a root name is invalid"));
    }

    let roots = skeleton.roots.len();
    let slot_is = |atom: Option<AtomId>, kind: SlotKind| match atom {
        None => true,
        Some(id) => skeleton
            .slots
            .get(id as usize)
            .is_some_and(|slot| slot.kind == kind),
    };
    let winners_ok = |winners: &[Winner]| {
        winners
            .iter()
            .all(|winner| (winner.root as usize) < roots && slot_is(winner.value, SlotKind::Value))
    };
    let maps_ok = |maps: &[u32]| maps.iter().all(|&map| (map as usize) < roots);
    let changes_ok = skeleton.changes.iter().all(|change| {
        !change.ops.is_empty()
            && slot_is(change.message, SlotKind::Message)
            && change
                .ops
                .iter()
                .all(|op| (op.root as usize) < roots && slot_is(op.value, SlotKind::Value))
    });
    let shallow_ok = skeleton.shallow.as_ref().map_or(true, |root| {
        winners_ok(&root.winners) && maps_ok(&root.maps) && !root.vv.is_empty()
    });
    if !(changes_ok && shallow_ok && winners_ok(&skeleton.latest) && maps_ok(&skeleton.latest_maps))
    {
        return Err(malformed("a root index or atom id is out of range"));
    }

    // Each peer's retained history runs without gaps from the start version
    // to the latest version.
    let mut ends: FxHashMap<PeerID, Counter> = FxHashMap::default();
    if let Some(root) = &skeleton.shallow {
        ends.extend(root.vv.iter().copied());
    }
    let mut changes: Vec<&SkelChange> = skeleton.changes.iter().collect();
    changes.sort_by_key(|change| (change.peer, change.counter));
    for change in changes {
        let end = ends.entry(change.peer).or_insert(0);
        if *end != change.counter {
            return Err(malformed("the retained history has a gap"));
        }
        *end = change
            .counter
            .checked_add(change.ops.len() as Counter)
            .ok_or_else(|| malformed("a counter overflows"))?;
    }
    let mut want: Vec<_> = ends.into_iter().filter(|&(_, end)| end > 0).collect();
    want.sort_unstable();
    let have: Vec<_> = skeleton
        .vv
        .iter()
        .copied()
        .filter(|&(_, end)| end > 0)
        .collect();
    if want != have {
        return Err(malformed(
            "the retained history does not reach the latest version",
        ));
    }

    // Loro trims at a single frontier and keeps the frontier op itself.
    if let Some(root) = &skeleton.shallow {
        let &[(peer, counter)] = root.frontiers.as_slice() else {
            return Err(malformed("the shallow root is not a single frontier"));
        };
        let starts_there = root.vv.contains(&(peer, counter));
        let retained = skeleton
            .vv
            .iter()
            .any(|&(p, end)| p == peer && end > counter);
        if !(starts_there && retained) {
            return Err(malformed("the shallow frontier op is not retained"));
        }
    }

    Ok(())
}

fn open_slots<'a>(
    skeleton: &Skeleton,
    available: &'a [Atom],
    erased: &[AtomId],
) -> Result<Vec<Option<&'a Payload>>, CheckpointError> {
    let len = skeleton.slots.len();
    let index = |id: AtomId| {
        usize::try_from(id)
            .ok()
            .filter(|&index| index < len)
            .ok_or_else(|| malformed("an atom id is outside the skeleton"))
    };
    let mut covered = vec![false; len];
    let mut opened = vec![None; len];
    for atom in available {
        let i = index(atom.id)?;
        let kind = match atom.payload {
            Payload::Value(_) => SlotKind::Value,
            Payload::Message(_) => SlotKind::Message,
        };
        if covered[i] || skeleton.slots[i].kind != kind {
            return Err(malformed("an atom is repeated or of the wrong kind"));
        }
        covered[i] = true;
        opened[i] = Some(&atom.payload);
    }

    for &id in erased {
        let i = index(id)?;
        if covered[i] {
            return Err(malformed("a slot is both opened and erased"));
        }
        covered[i] = true;
    }

    if covered.contains(&false) {
        return Err(malformed("a slot is neither opened nor erased"));
    }

    Ok(opened)
}

fn opened_value(opened: &[Option<&Payload>], atom: Option<AtomId>) -> Option<LoroValue> {
    match atom.and_then(|id| opened[id as usize]) {
        Some(Payload::Value(value)) => Some(value.clone()),
        _ => None,
    }
}

fn opened_message(opened: &[Option<&Payload>], atom: Option<AtomId>) -> Option<String> {
    match atom.and_then(|id| opened[id as usize]) {
        Some(Payload::Message(message)) => Some(message.clone()),
        _ => None,
    }
}

/// The retained history with opened payloads. An erased value is a delete at
/// the same op id; an erased message is no message.
fn history_json(skeleton: &Skeleton, opened: &[Option<&Payload>]) -> JsonSchema {
    let changes = skeleton
        .changes
        .iter()
        .map(|change| JsonChange {
            id: ID::new(change.peer, change.counter),
            timestamp: change.timestamp,
            deps: change
                .deps
                .iter()
                .map(|&(peer, counter)| ID::new(peer, counter))
                .collect(),
            lamport: change.lamport,
            msg: opened_message(opened, change.message),
            ops: change
                .ops
                .iter()
                .enumerate()
                .map(|(i, op)| JsonOp {
                    content: JsonOpContent::Map(match opened_value(opened, op.value) {
                        Some(value) => MapOp::Insert {
                            key: op.key.clone(),
                            value,
                        },
                        None => MapOp::Delete {
                            key: op.key.clone(),
                        },
                    }),
                    container: root_cid(skeleton, op.root),
                    counter: change.counter + i as Counter,
                })
                .collect(),
        })
        .collect();
    JsonSchema {
        schema_version: JSON_SCHEMA_VERSION,
        start_version: Frontiers::new(),
        peers: None,
        changes,
    }
}

fn full_history_snapshot(history: JsonSchema) -> Result<Vec<u8>, CheckpointError> {
    let doc = LoroDoc::new();
    let status = doc.import_json_updates(history)?;
    if status.pending.is_some() {
        return Err(malformed("the history has missing dependencies"));
    }

    Ok(doc.export(ExportMode::Snapshot)?)
}

/// Assembles a native shallow snapshot: the retained changes over the
/// original start version, and the shallow-root maps rebuilt from their
/// winners. The latest state is left to Loro's own replay on import.
fn shallow_snapshot(
    skeleton: &Skeleton,
    root: &ShallowRoot,
    history: JsonSchema,
    opened: &[Option<&Payload>],
) -> Result<Vec<u8>, CheckpointError> {
    let scratch = LoroDoc::new();
    let oplog_bytes = {
        let oplog = scratch.oplog.lock();
        let mut changes = decode_json_changes(history, &oplog.arena)?;
        changes.sort_by_key(|change| change.id);
        let store = ChangeStore::new_mem(&oplog.arena, Arc::new(AtomicI64::new(0)));
        for change in changes {
            store.insert_change(change, false, false);
        }
        store.encode_from(
            &list_vv(&root.vv),
            &list_frontiers(&root.frontiers),
            &list_vv(&skeleton.vv),
            &list_frontiers(&skeleton.frontiers),
        )
    };

    let shallow_root_state_bytes = {
        let mut state = scratch.state.lock();
        for &map in &root.maps {
            state.store.ensure_container(&root_cid(skeleton, map));
        }
        for winner in &root.winners {
            let cid = root_cid(skeleton, winner.root);
            state.store.ensure_container(&cid);
            let idx = state.arena.register_container(&cid);
            let entry = MapValue {
                value: opened_value(opened, winner.value),
                lamp: winner.lamport,
                peer: winner.peer,
            };
            let map = state
                .store
                .get_container_mut(idx)
                .and_then(|container| container.as_map_state_mut())
                .ok_or_else(|| malformed("a shallow-root container is not a map"))?;
            map.insert(winner.key.as_str().into(), entry);
        }
        state.store.flush();
        let kv = state.store.get_kv_clone();
        kv.insert(
            FRONTIERS_KEY,
            list_frontiers(&root.frontiers).encode().into(),
        );
        kv.export()
    };

    let snapshot = Snapshot {
        oplog_bytes,
        state_bytes: None,
        shallow_root_state_bytes,
    };
    Ok(encode_with(EncodeMode::FastSnapshot, &mut |w| {
        _encode_snapshot(&snapshot, w);
        Ok(())
    })?)
}

fn ensure_maps(doc: &LoroDoc, skeleton: &Skeleton, maps: &[u32]) {
    let mut state = doc.state.lock();
    for &map in maps {
        state.store.ensure_container(&root_cid(skeleton, map));
    }
}

type Entries = BTreeMap<(String, String), (PeerID, Lamport, Option<LoroValue>)>;

/// The map entries of a reopened store, keyed by root name and key.
fn store_entries(
    maps: &[StoreMap],
    what: &str,
) -> Result<(BTreeSet<String>, Entries), CheckpointError> {
    let mut names = BTreeSet::new();
    let mut entries = Entries::new();
    for map in maps {
        let (Some(ContainerID::Root { name, .. }), Some(list)) = (&map.cid, &map.entries) else {
            return Err(diverged(format!(
                "{what} holds a container that is not a root map"
            )));
        };
        names.insert(name.to_string());
        for (key, entry) in list {
            entries.insert(
                (name.to_string(), key.to_string()),
                (entry.peer, entry.lamp, entry.value.clone()),
            );
        }
    }
    Ok((names, entries))
}

fn winner_entries(skeleton: &Skeleton, winners: &[Winner], opened: &[Option<&Payload>]) -> Entries {
    winners
        .iter()
        .map(|winner| {
            (
                (
                    skeleton.roots[winner.root as usize].clone(),
                    winner.key.clone(),
                ),
                (
                    winner.peer,
                    winner.lamport,
                    opened_value(opened, winner.value),
                ),
            )
        })
        .collect()
}

fn compare_entries(got: &Entries, want: &Entries, what: &str) -> Result<(), CheckpointError> {
    if got == want {
        return Ok(());
    }

    let first = got
        .iter()
        .zip(want.iter())
        .find(|(a, b)| a != b)
        .map(|((key, _), _)| key.clone())
        .or_else(|| got.keys().nth(want.len()).cloned())
        .or_else(|| want.keys().nth(got.len()).cloned());
    Err(diverged(format!(
        "{what}: {} entries against {}, first difference at {first:?}",
        got.len(),
        want.len()
    )))
}

/// One retained op with the metadata of its change.
#[derive(Debug, PartialEq)]
struct Row {
    id: (PeerID, Counter),
    lamport: Lamport,
    timestamp: i64,
    deps: Vec<(PeerID, Counter)>,
    message: Option<String>,
    root: String,
    key: String,
    value: Option<LoroValue>,
}

/// Op i > 0 of a change depends on op i - 1. That keeps the rows equal when
/// Loro merges or splits same-peer changes at import.
fn op_deps(
    peer: PeerID,
    offset: Counter,
    counter: Counter,
    deps: &[(PeerID, Counter)],
) -> Vec<(PeerID, Counter)> {
    if offset == 0 {
        deps.to_vec()
    } else {
        vec![(peer, counter - 1)]
    }
}

fn json_rows(changes: &[JsonChange]) -> Result<Vec<Row>, CheckpointError> {
    let mut rows = Vec::new();
    for change in changes {
        let mut deps: Vec<_> = change.deps.iter().map(|id| (id.peer, id.counter)).collect();
        deps.sort_unstable();
        for op in &change.ops {
            let offset = op.counter - change.id.counter;
            let (ContainerID::Root { name, .. }, JsonOpContent::Map(content)) =
                (&op.container, &op.content)
            else {
                return Err(diverged(format!(
                    "history op {}@{} is not a root-map op",
                    op.counter, change.id.peer
                )));
            };
            let (key, value) = match content {
                MapOp::Insert { key, value } => (key.clone(), Some(value.clone())),
                MapOp::Delete { key } => (key.clone(), None),
            };
            rows.push(Row {
                id: (change.id.peer, op.counter),
                lamport: change.lamport + offset as Lamport,
                timestamp: change.timestamp,
                deps: op_deps(change.id.peer, offset, op.counter, &deps),
                message: change.msg.clone(),
                root: name.to_string(),
                key,
                value,
            });
        }
    }
    rows.sort_by_key(|row| row.id);
    Ok(rows)
}

fn skeleton_rows(skeleton: &Skeleton, opened: &[Option<&Payload>]) -> Vec<Row> {
    let mut rows = Vec::new();
    for change in &skeleton.changes {
        let message = opened_message(opened, change.message);
        for (i, op) in change.ops.iter().enumerate() {
            let offset = i as Counter;
            let counter = change.counter + offset;
            rows.push(Row {
                id: (change.peer, counter),
                lamport: change.lamport + i as Lamport,
                timestamp: change.timestamp,
                deps: op_deps(change.peer, offset, counter, &change.deps),
                message: message.clone(),
                root: skeleton.roots[op.root as usize].clone(),
                key: op.key.clone(),
                value: opened_value(opened, op.value),
            });
        }
    }
    rows.sort_by_key(|row| row.id);
    rows
}

/// Proves the reopened document against the skeleton: versions, the retained
/// history op by op, and every shallow-root and latest map winner.
fn verify(
    doc: &LoroDoc,
    skeleton: &Skeleton,
    opened: &[Option<&Payload>],
) -> Result<JoinReport, CheckpointError> {
    let raw = read_raw(doc)
        .map_err(|why| diverged(format!("the joined document is unreadable: {why}")))?;
    if raw.vv != skeleton.vv || raw.frontiers != skeleton.frontiers {
        return Err(diverged("the latest version vector or frontiers changed"));
    }

    match (&raw.root, &skeleton.shallow) {
        (None, None) => {}
        (Some(got), Some(want)) => {
            if got.vv != want.vv || got.frontiers != want.frontiers {
                return Err(diverged("the shallow version vector or frontiers changed"));
            }
            let (names, entries) = store_entries(&got.maps, "the shallow-root state")?;
            let want_names: BTreeSet<String> = want
                .maps
                .iter()
                .map(|&map| skeleton.roots[map as usize].clone())
                .collect();
            if names != want_names {
                return Err(diverged("the shallow-root maps changed"));
            }
            compare_entries(
                &entries,
                &winner_entries(skeleton, &want.winners, opened),
                "the shallow-root state",
            )?;
        }
        _ => return Err(diverged("the shallow root appeared or vanished")),
    }

    // Loro may keep an older id in the latest state when a write left the
    // value unchanged, so the latest state is compared by value; the ids are
    // proven by the history and the shallow root above and below.
    let (_, latest) = store_entries(&raw.latest, "the latest state")?;
    let values = |entries: Entries| -> Entries {
        entries
            .into_iter()
            .map(|(slot, (_, _, value))| (slot, (0, 0, value)))
            .collect()
    };
    compare_entries(
        &values(latest),
        &values(winner_entries(skeleton, &skeleton.latest, opened)),
        "the latest state",
    )?;

    let got = json_rows(&raw.changes)?;
    let want = skeleton_rows(skeleton, opened);
    if got != want {
        let at = got
            .iter()
            .zip(want.iter())
            .find(|(a, b)| a != b)
            .map(|(a, _)| a.id)
            .or_else(|| got.get(want.len()).map(|row| row.id))
            .or_else(|| want.get(got.len()).map(|row| row.id));
        return Err(diverged(format!(
            "the history differs: {} ops against {}, first at {at:?}",
            got.len(),
            want.len()
        )));
    }

    let opened_count = opened.iter().filter(|slot| slot.is_some()).count();
    Ok(JoinReport {
        equivalent: true,
        changes: skeleton.changes.len(),
        ops: want.len(),
        opened: opened_count,
        erased: opened.len() - opened_count,
        root_entries: skeleton
            .shallow
            .as_ref()
            .map_or(0, |root| root.winners.len()),
        latest_entries: skeleton.latest.len(),
    })
}
