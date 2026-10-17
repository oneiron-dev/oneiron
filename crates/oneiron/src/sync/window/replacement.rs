//! Installing a window replacement: a peer's history-free snapshot takes the place of this
//! vault's window, and this vault's own state is written back on top before anything can read
//! the new document.
//!
//! A replacement cannot be merged. Loro imports a snapshot into a document that already holds
//! operations as ordinary changes, and every change past the snapshot's root then waits on
//! history the snapshot leaves out; a shallow document refuses outright any change concurrent
//! with its root. So the candidate is a fresh document built from the snapshot alone, and the
//! old window contributes what this vault holds that the snapshot does not:
//!
//! 1. every key whose value comes from an operation of the old window past the snapshot's
//!    version (its own writes, scrubs and pending mirrors since the peer last saw it) takes that
//!    value again, as a new operation of the candidate, unless the peer changed the key
//!    concurrently and that change wins Loro's order or cannot be ordered, which is a conflict;
//! 2. every tombstone this vault holds as a hard delete (`dt:`) that the candidate lacks; no hard
//!    delete the candidate holds, or takes from this vault, is softened or removed;
//! 3. every queued send the old window could not apply that the candidate can, as itself; a value
//!    a retired queued send wrote, the newest of this vault's writes of its key, that the
//!    installed candidate does not hold is a conflict;
//! 4. delete wins: a carried write of a body the candidate hard-deleted, or of an edge naming
//!    one, comes back out as a conflict;
//! 5. every pending tombstone (`pt:`), left in place for the next open;
//! 6. the reverse and forward rematerializations, as a window open runs.
//!
//! A conflict names a value the candidate does not hold once every step has run, the forward pass
//! and the export scrubs included; one a later step put back is dropped.
//!
//! Below the old window's own shallow root no operation is left to read. There a key carries
//! over when the candidate's value came from a peer whose every operation the old window holds
//! and the old value from one the peer has not fully seen. A key both sides edited there, each
//! unseen by the other, keeps the peer's value; a row the candidate lacks still comes back from
//! LMDB through reverse rematerialization.
//!
//! The candidate, its version and its history-free state are persisted in one transaction that
//! also retires the old window's pending updates and the queued sends it took in, whose effects
//! step 1 carried over, and clears the pending mirrors step 1 replayed. Preparation refused
//! before that transaction leaves every mirror marker in place. The caller attaches observers
//! last.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue, ValueOrContainer, VersionVector};

use super::super::loro_support::{
    TombstoneIndex, doc_version_vector, map_delete, map_for_each_tombstone_value, map_insert_bytes,
};
use super::super::types::WindowKey;
use super::egress::{
    export_scrubbed_window_snapshot, replay_pending_mirrors_kept, scrub_local_claim_carriers,
    scrub_local_only_carriers, scrub_redacted_attribution_carriers,
    scrub_withdrawn_delete_carriers,
};
use super::tombstones::apply_tombstone_to_indexed_window_doc;
use super::{
    forward_rematerialize, persist_window_doc_in_txn, reverse_rematerialize,
    write_window_svf_in_txn,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError, SyncProtocolValidation};
use crate::ports::{DeletionMarker, TombstoneStoreRead, WindowAddress, WindowDeletionRows};
use crate::sync::bridge::Materializer;
use crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
use crate::sync::window_rows::{OFF_RECORD_PROMOTE_PICKUP, WINDOW_UPDATE};

fn rejected() -> Error {
    Error::Sync(SyncError::SyncProtocolError {
        context: SyncProtocolValidation::ReplacementRejected,
    })
}

/// Builds and persists the replacement of window `key` from `snapshot`, carrying over what
/// `old` (the live window's document, or its durable state when closed) holds that the snapshot
/// does not. The snapshot passes the admission an update does, with the same staged `evidence`
/// for a world window. Returns the bare candidate: the caller attaches observers and installs it,
/// and no other holder may write `old` meanwhile. Nothing is persisted when the snapshot is
/// refused.
pub fn prepare_replacement(
    vault: &Vault,
    materializer: &Materializer,
    key: &WindowKey,
    old: &LoroDoc,
    snapshot: &[u8],
    evidence: &HashMap<EntityId, (WindowKey, Vec<u8>)>,
) -> Result<PreparedReplacement> {
    if snapshot.len() > MAX_DECODED_PAYLOAD_BYTES {
        return Err(rejected());
    }
    let meta = LoroDoc::decode_import_blob_meta(snapshot, true).map_err(|_| rejected())?;
    let base = crate::sync::schema::create_window_doc("replacement", key);
    super::validate_window_update_with_staged_worlds(vault, &base, snapshot, key, evidence)
        .map_err(|_| rejected())?;
    // A snapshot decodes into a fresh document whole, with a fresh author peer: the old
    // window's peer may hold counters the snapshot never saw.
    let candidate = LoroDoc::from_snapshot(snapshot).map_err(|_| rejected())?;
    if !candidate.oplog_vv().includes_vv(&meta.partial_end_vv) {
        return Err(rejected());
    }

    // The work happens on a detached copy of the old window: what this prepares there (queued
    // sends, scrubs, pending mirrors) feeds the carry-over and never leaves through the live
    // window's observers, whose document the replacement retires.
    let old = &old.fork();
    // A local write whose `u:w:` row never landed lives only in the outbound queue: bring every
    // queued send into the old window first, so it carries over like any other unseen write. A
    // row that does not apply there is offered to the candidate below.
    let mut carried = Vec::new();
    let mut unapplied = Vec::new();
    // Every send this install retires, by where it applied and the versions it carries.
    let mut sends = Vec::new();
    for (seq, update) in crate::sync::queue::queued_window_updates(vault, key.as_str())? {
        if old
            .import(&update)
            .is_ok_and(|status| status.pending.is_none())
        {
            sends.push((false, send_span(&update)?));
            carried.push(seq);
        } else {
            unapplied.push((seq, update));
        }
    }
    // What carries over is the old window's live state: take off it first what no export may
    // ship, as an export would, so no carried write puts a scrubbed body back.
    scrub_local_only_carriers(vault, key, old)?;
    scrub_local_claim_carriers(vault, key, old)?;
    scrub_redacted_attribution_carriers(vault, key, old)?;
    scrub_withdrawn_delete_carriers(vault, key, old)?;
    super::withdrawn::scrub_withdrawn_generation_carriers(vault, key, old)?;
    // A pending mirror is this vault's own write that a crash kept off the window: it goes into
    // the old window, so the carry-over judges it like any other unseen write and never puts it
    // over a value the peer provably superseded. Its marker clears with the install below.
    let mirrored = replay_pending_mirrors_kept(vault, old, key)?;
    // Delete semantics never weaken: no carried write or queued send may soften or remove a hard
    // delete the replacement holds, nor one of this vault's own once it is carried over.
    let mut hard = hard_tombstones(&candidate);
    let (mut conflicts, mut written) = carry_over_unseen_writes(old, &candidate)?;
    carry_over_hard_deletes(vault, old, &candidate)?;
    hard.extend(hard_tombstones(&candidate));
    // A queued send the old window could not apply may build on history only the peer kept:
    // the candidate takes it as the operation it is. One neither takes stays queued.
    let before = candidate.oplog_vv();
    for (seq, update) in &unapplied {
        if candidate
            .fork()
            .import(update)
            .is_ok_and(|status| status.pending.is_none())
        {
            candidate.import(update).map_err(|_| rejected())?;
            sends.push((true, send_span(update)?));
            carried.push(*seq);
        }
    }
    written.extend(newest_ops(&candidate, &before, &candidate.oplog_vv())?.into_keys());
    conflicts.extend(keep_hard_deletes(&candidate, &hard, &written)?);
    conflicts.extend(delete_wins(&candidate, &written)?);
    let pending: Vec<_> = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .port_pending_tombstones_in_window(&rtxn, WindowAddress::new(key.as_str()))?
            .filter_map(std::result::Result::ok)
            .collect()
    };
    let tombstones = TombstoneIndex::build(&candidate.get_map("tombstones"));
    for marker in &pending {
        apply_tombstone_to_indexed_window_doc(&candidate, &tombstones, &marker.id, &marker.raw)?;
    }
    candidate.commit();
    reverse_rematerialize(vault, &candidate, key)?;
    forward_rematerialize(vault, &candidate, materializer, key)?;

    let state = export_scrubbed_window_snapshot(vault, key, &candidate)?;
    // The candidate is final once its snapshot is cut: the forward pass and the export scrubs can
    // still take a value out. A queued send retires only once each value it wrote is in the
    // window being installed or named as a conflict, and every other conflict is provisional
    // until here: a value a later step put back, such as a newer queued send writing it again,
    // was kept after all.
    for conflict in lost_queued_writes(old, &candidate, &sends)? {
        if !conflicts.contains(&conflict) {
            conflicts.push(conflict);
        }
    }
    conflicts.retain(|conflict| !holds_value(&candidate, conflict));
    let vv = doc_version_vector(&candidate);
    let stale_updates: Vec<_> = {
        let rtxn = vault.store.env.read_txn()?;
        WINDOW_UPDATE
            .iter_from(&vault.store, &rtxn, format!("{key}:").as_bytes())?
            .filter_map(|row| row.ok().map(|(update, _)| update))
            .collect()
    };
    vault.with_write_txn_grouped(|wtxn| {
        persist_window_doc_in_txn(vault, wtxn, key, &state, &vv)?;
        // The old generation's pending updates and the queued sends it took in depend on history
        // the candidate does not hold; their effects are in it as its own operations.
        for update in &stale_updates {
            WINDOW_UPDATE.delete(&vault.store, wtxn, update)?;
        }
        crate::sync::queue::retire_queued_in_txn(vault, wtxn, &carried)?;
        for marker in &mirrored {
            OFF_RECORD_PROMOTE_PICKUP.delete(&vault.store, wtxn, marker)?;
        }
        write_window_svf_in_txn(vault, wtxn, key)
    })?;
    Ok(PreparedReplacement {
        doc: candidate,
        conflicts,
    })
}

/// A persisted replacement, ready to install.
#[derive(Debug)]
pub struct PreparedReplacement {
    /// The new window document, observers not yet attached.
    pub doc: LoroDoc,
    /// The keys this vault's value could not carry over, with that value.
    pub conflicts: Vec<ReplacementConflict>,
}

/// A key this vault changed that the replacement does not carry: the peer changed it too, unseen
/// by this vault, and this vault's change does not provably win Loro's order; or the peer
/// hard-deleted the entity it names. The replacement keeps the peer's state; `held` is the value
/// this vault had, `None` where it had the key removed.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplacementConflict {
    /// The root map, such as `entities`.
    pub map: String,
    pub key: String,
    pub held: Option<LoroValue>,
}

/// Writes into `candidate` the old window's value of every root-map key this vault wrote and the
/// peer never saw: every key whose held value is that of the newest operation of `old` past the
/// candidate's version, where that operation provably wins over anything the peer wrote to the
/// key unseen by this vault, and, below the old window's own shallow root where no operation is
/// left to read, every key whose candidate value came from an operation `old` saw while `old`'s
/// value may have come from one the peer did not. A key this vault changed whose win cannot be
/// proved keeps the peer's value and is returned as a conflict.
///
/// Returns the conflicts and every key it wrote.
fn carry_over_unseen_writes(
    old: &LoroDoc,
    candidate: &LoroDoc,
) -> Result<(Vec<ReplacementConflict>, RootKeys)> {
    old.commit();
    let old_vv = old.oplog_vv();
    let seen = candidate.oplog_vv();
    let shared = seen.intersection(&old_vv);
    let mut from = shared.clone();
    from.merge(&old.shallow_since_vv().to_vv());
    let unseen = newest_ops(old, &from, &old_vv)?;
    // The peer's operations this vault never saw, as far as the candidate's root keeps them.
    let mut theirs_from = shared;
    theirs_from.merge(&candidate.shallow_since_vv().to_vv());
    let theirs = newest_ops(candidate, &theirs_from, &seen)?;
    // Below the candidate's root its operations are gone: what this vault lacks there may have
    // changed any key, and is ordered before the root's own operation.
    let below_root = super::history_free::root_state(
        &candidate.shallow_since_vv().to_vv(),
        &candidate.shallow_since_frontiers(),
    );
    let root_lamport = candidate
        .shallow_since_frontiers()
        .iter()
        .filter_map(|id| {
            let change = candidate.get_change(id)?;
            u32::try_from(id.counter - change.id.counter)
                .ok()
                .map(|offset| change.lamport + offset)
        })
        .max();
    let mut conflicts = Vec::new();
    // A key carries over only when the value it holds is that unseen operation's: an unseen
    // operation that lost to one the peer saw leaves the peer's newer value in place. When the
    // peer may have changed the key too, unseen by this vault, the write carries only where it
    // provably wins Loro's order, as a merge would decide; otherwise the peer's value stands and
    // this vault's comes back as a conflict.
    let mut touched = BTreeSet::new();
    for ((name, key), (lamport, peer, value)) in &unseen {
        let held = old.get_map(name.as_str());
        let holds_it = match (held.get(key), value) {
            (Some(ValueOrContainer::Value(held)), Some(value)) => held == *value,
            (None, None) => true,
            _ => false,
        };
        if !holds_it || held.get_last_editor(key) != Some(*peer) {
            continue;
        }
        let offered = candidate.get_map(name.as_str());
        let ours_wins = match (
            theirs.get(&(name.clone(), key.clone())),
            offered.get_last_editor(key),
        ) {
            (Some((their_lamport, their_peer, _)), _) => {
                (*lamport, *peer) > (*their_lamport, *their_peer)
            }
            // The peer never wrote the key.
            (None, None) => true,
            // Every operation of the writer this vault lacks is past the candidate's root, and
            // none of those touched the key: the peer's value is one this vault's write beat.
            (None, Some(writer)) if holds_all_of(&old_vv, &below_root, writer) => true,
            // The write is ordered after the candidate's root, so after anything below it.
            (None, Some(_)) => root_lamport.is_some_and(|root| *lamport >= root),
        };
        if ours_wins {
            touched.insert((name.clone(), key.clone()));
        } else {
            conflicts.push(ReplacementConflict {
                map: name.clone(),
                key: key.clone(),
                held: value.clone(),
            });
        }
    }
    if !seen.includes_vv(&old.shallow_since_vv().to_vv()) {
        for name in root_maps(old).union(&root_maps(candidate)) {
            let (held, offered) = (old.get_map(name.as_str()), candidate.get_map(name.as_str()));
            let keys: BTreeSet<String> = held
                .keys()
                .chain(offered.keys())
                .map(|key| key.to_string())
                .collect();
            for key in keys {
                if unseen.contains_key(&(name.clone(), key.clone()))
                    || !values_differ(held.get(&key), offered.get(&key))
                {
                    continue;
                }
                // A map value remembers the peer that set it, not the operation: a peer whose
                // every operation one side holds is a peer whose value that side saw.
                let peer_saw_held = held
                    .get_last_editor(&key)
                    .is_none_or(|peer| holds_all_of(&seen, &old_vv, peer));
                let held_saw_offered = offered
                    .get_last_editor(&key)
                    .is_none_or(|peer| holds_all_of(&old_vv, &seen, peer));
                if peer_saw_held {
                    continue;
                }
                if held_saw_offered {
                    touched.insert((name.clone(), key));
                } else {
                    conflicts.push(ReplacementConflict {
                        map: name.clone(),
                        held: match held.get(&key) {
                            Some(ValueOrContainer::Value(value)) => Some(value),
                            _ => None,
                        },
                        key,
                    });
                }
            }
        }
    }
    for (name, key) in &touched {
        let target = candidate.get_map(name.as_str());
        match old.get_map(name.as_str()).get(key) {
            Some(ValueOrContainer::Value(value)) => {
                if target.get(key).is_none_or(|current| match current {
                    ValueOrContainer::Value(current) => current != value,
                    ValueOrContainer::Container(_) => true,
                }) {
                    target.insert(key, value).map_err(|e| {
                        Error::sync_engine(crate::error::SyncEngineContext::LoroMapInsert, e)
                    })?;
                }
            }
            Some(ValueOrContainer::Container(_)) => return Err(rejected()),
            None => {
                if target.get(key).is_some() {
                    map_delete(&target, key)?;
                }
            }
        }
    }
    candidate.commit();
    Ok((conflicts, touched))
}

/// Delete wins over what this vault wrote into `candidate`: a `written` key holding the body of
/// an entity the candidate hard-deleted, or an edge naming one, is taken back out and returned as
/// a conflict with the value it held, so no carried write re-authors an erased body.
fn delete_wins(candidate: &LoroDoc, written: &RootKeys) -> Result<Vec<ReplacementConflict>> {
    let tombstones = TombstoneIndex::build(&candidate.get_map("tombstones"));
    let hard = |id: &EntityId| {
        tombstones
            .values_for(id)
            .iter()
            .any(|value| crate::deletion::decode_tombstone_value(value).is_hard())
    };
    let mut conflicts = Vec::new();
    for (name, key) in written {
        let erased = match name.as_str() {
            "entities" => EntityId::from_hex(key).is_ok_and(|id| hard(&id)),
            "edges" => crate::sync::bridge::parse_edge_key(key)
                .is_some_and(|(source, _, target)| hard(&source) || hard(&target)),
            _ => false,
        };
        let map = candidate.get_map(name.as_str());
        if erased && let Some(ValueOrContainer::Value(held)) = map.get(key) {
            map_delete(&map, key)?;
            conflicts.push(ReplacementConflict {
                map: name.clone(),
                key: key.clone(),
                held: Some(held),
            });
        }
    }
    candidate.commit();
    Ok(conflicts)
}

/// The versions a queued send carries.
fn send_span(update: &[u8]) -> Result<(VersionVector, VersionVector)> {
    let meta = LoroDoc::decode_import_blob_meta(update, true).map_err(|_| rejected())?;
    Ok((meta.partial_start_vv, meta.partial_end_vv))
}

/// The values the queued sends this install retires wrote that `candidate`, as installed, does not
/// hold. Each send is read by the versions it carries in the document it applied to, the old
/// window or the candidate, so a send that window already held counts like one it took in, and a
/// value it lost there that the candidate keeps is no conflict. Of several sends writing one key,
/// only the newest write counts: the older ones are this vault's own superseded values.
fn lost_queued_writes(
    old: &LoroDoc,
    candidate: &LoroDoc,
    sends: &[(bool, (VersionVector, VersionVector))],
) -> Result<Vec<ReplacementConflict>> {
    let mut newest = NewestOps::new();
    for (in_candidate, (from, to)) in sends {
        let doc = if *in_candidate { candidate } else { old };
        for (slot, order) in newest_ops(doc, from, to)? {
            match newest.entry(slot) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(order);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if (order.0, order.1) > (entry.get().0, entry.get().1) {
                        entry.insert(order);
                    }
                }
            }
        }
    }
    Ok(newest
        .into_iter()
        .map(|((map, key), (_, _, held))| ReplacementConflict { map, key, held })
        .filter(|conflict| !holds_value(candidate, conflict))
        .collect())
}

/// Whether `candidate` holds the value `conflict` names for its key: then nothing was lost.
fn holds_value(candidate: &LoroDoc, conflict: &ReplacementConflict) -> bool {
    match (
        candidate.get_map(conflict.map.as_str()).get(&conflict.key),
        &conflict.held,
    ) {
        (Some(ValueOrContainer::Value(held)), Some(value)) => held == *value,
        (None, None) => true,
        _ => false,
    }
}

/// Every hard delete `candidate` holds, as its tombstone key and raw value. A value that is not
/// bytes decodes hard, failing closed.
fn hard_tombstones(candidate: &LoroDoc) -> Vec<(String, Vec<u8>)> {
    let mut hard = Vec::new();
    map_for_each_tombstone_value(&candidate.get_map("tombstones"), |key, value| {
        if crate::deletion::decode_tombstone_value(value).is_hard() {
            hard.push((key.to_owned(), value.to_vec()));
        }
    });
    hard
}

/// Puts back each of the `hard` deletes that a carried write or a queued send softened or
/// removed. A carried tombstone it displaces comes back as a conflict with the value it held.
fn keep_hard_deletes(
    candidate: &LoroDoc,
    hard: &[(String, Vec<u8>)],
    written: &RootKeys,
) -> Result<Vec<ReplacementConflict>> {
    let map = candidate.get_map("tombstones");
    let mut conflicts = Vec::new();
    for (key, raw) in hard {
        let held = map.get(key);
        let still_hard = match &held {
            Some(ValueOrContainer::Value(LoroValue::Binary(value))) => {
                crate::deletion::decode_tombstone_value(value).is_hard()
            }
            Some(_) => true,
            None => false,
        };
        if still_hard {
            continue;
        }
        if written.contains(&("tombstones".to_owned(), key.clone())) {
            conflicts.push(ReplacementConflict {
                map: "tombstones".to_owned(),
                key: key.clone(),
                held: match held {
                    Some(ValueOrContainer::Value(value)) => Some(value),
                    _ => None,
                },
            });
        }
        map_insert_bytes(&map, key, raw)?;
    }
    candidate.commit();
    Ok(conflicts)
}

/// Root-map keys, as (map, key).
type RootKeys = BTreeSet<(String, String)>;

/// Per root-map key (map, key): the newest operation's Lamport and peer, and the value it wrote
/// (`None` for a removal).
type NewestOps = BTreeMap<(String, String), (u32, loro::PeerID, Option<LoroValue>)>;

/// The newest operation of `doc` between `from` and `to` on each root-map key, by Loro's own
/// order (Lamport, then peer), with the value it wrote (`None` for a removal).
fn newest_ops(doc: &LoroDoc, from: &VersionVector, to: &VersionVector) -> Result<NewestOps> {
    let mut newest = NewestOps::new();
    for change in doc
        .export_json_updates_without_peer_compression(from, to)
        .changes
    {
        for op in &change.ops {
            let ContainerID::Root {
                name,
                container_type: ContainerType::Map,
            } = &op.container
            else {
                return Err(rejected());
            };
            let (key, value) = match &op.content {
                JsonOpContent::Map(MapOp::Insert { key, value }) => (key, Some(value.clone())),
                JsonOpContent::Map(MapOp::Delete { key }) => (key, None),
                _ => return Err(rejected()),
            };
            let offset = u32::try_from(op.counter - change.id.counter).map_err(|_| rejected())?;
            let order = (change.lamport + offset, change.id.peer, value);
            match newest.entry((name.to_string(), key.clone())) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(order);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if (order.0, order.1) > (slot.get().0, slot.get().1) {
                        slot.insert(order);
                    }
                }
            }
        }
    }
    Ok(newest)
}

/// The names of `doc`'s root maps.
fn root_maps(doc: &LoroDoc) -> BTreeSet<String> {
    let LoroValue::Map(roots) = doc.get_value() else {
        return BTreeSet::new();
    };
    roots
        .iter()
        .filter_map(|(name, value)| match value {
            LoroValue::Container(ContainerID::Root {
                container_type: ContainerType::Map,
                ..
            }) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Whether two plain values (or absences) differ. No window writer nests a container, so one
/// is never carried over.
fn values_differ(held: Option<ValueOrContainer>, offered: Option<ValueOrContainer>) -> bool {
    match (held, offered) {
        (Some(ValueOrContainer::Container(_)), _) | (_, Some(ValueOrContainer::Container(_))) => {
            false
        }
        (Some(ValueOrContainer::Value(held)), Some(ValueOrContainer::Value(offered))) => {
            held != offered
        }
        (held, offered) => held.is_some() != offered.is_some(),
    }
}

/// Whether `holder` holds every operation of `peer` that `other` holds.
fn holds_all_of(holder: &VersionVector, other: &VersionVector, peer: loro::PeerID) -> bool {
    holder.get(&peer).copied().unwrap_or(0) >= other.get(&peer).copied().unwrap_or(0)
}

/// Every tombstone the old window holds for an entity this vault hard-deleted, as this vault's
/// exact `dt:` bytes, where the candidate lacks it: a delete this vault made below its own root
/// still reaches the peer.
fn carry_over_hard_deletes(vault: &Vault, old: &LoroDoc, candidate: &LoroDoc) -> Result<()> {
    let mut ids = Vec::new();
    map_for_each_tombstone_value(&old.get_map("tombstones"), |key, _| {
        if let Ok(id) = EntityId::from_hex(key) {
            ids.push(id);
        }
    });
    let tombstones = TombstoneIndex::build(&candidate.get_map("tombstones"));
    let mut hard = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for id in ids {
            if let Some(value) =
                vault
                    .store
                    .port_deletion_marker(&rtxn, DeletionMarker::HardDelete, &id)?
                && !tombstones
                    .values_for(&id)
                    .iter()
                    .any(|held| crate::deletion::decode_tombstone_value(held).is_hard())
            {
                hard.push((id, value));
            }
        }
    }
    for (id, value) in &hard {
        apply_tombstone_to_indexed_window_doc(candidate, &tombstones, id, value)?;
    }
    candidate.commit();
    Ok(())
}
