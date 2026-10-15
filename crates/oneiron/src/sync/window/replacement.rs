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
//!    version (its own writes and scrubs since the peer last saw it) takes that value again, as a
//!    new operation of the candidate, unless the peer changed the key concurrently and that
//!    change wins Loro's order or cannot be ordered, which is a conflict;
//! 2. every tombstone this vault holds as a hard delete (`dt:`) that the candidate lacks;
//! 3. every pending tombstone (`pt:`), left in place for the next open;
//! 4. pending mirrors, then the reverse and forward rematerializations, as a window open runs.
//!
//! Below the old window's own shallow root no operation is left to read. There a key carries
//! over when the candidate's value came from a peer whose every operation the old window holds
//! and the old value from one the peer has not fully seen. A key both sides edited there, each
//! unseen by the other, keeps the peer's value; a row the candidate lacks still comes back from
//! LMDB through reverse rematerialization.
//!
//! The candidate, its version and its history-free state are persisted in one transaction that
//! also retires the old window's pending updates and the queued sends it took in, whose effects
//! step 1 carried over. The caller attaches observers last.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue, ValueOrContainer, VersionVector};

use super::super::loro_support::{
    TombstoneIndex, doc_version_vector, map_delete, map_for_each_tombstone_value,
};
use super::super::types::WindowKey;
use super::egress::{
    export_scrubbed_window_snapshot, scrub_local_claim_carriers, scrub_local_only_carriers,
    scrub_redacted_attribution_carriers, scrub_withdrawn_delete_carriers,
};
use super::tombstones::apply_tombstone_to_indexed_window_doc;
use super::{
    forward_rematerialize, persist_window_doc_in_txn, replay_pending_mirrors,
    reverse_rematerialize, write_window_svf_in_txn,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError, SyncProtocolValidation};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::sync::bridge::Materializer;
use crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
use crate::sync::window_rows::{PENDING_TOMBSTONE, WINDOW_UPDATE};

/// The permanent local hard-delete marker (`dt:{entity_hex}`), value = the exact tombstone
/// bytes. Owned by `deletion::tombstone`; bound here for this module's one read, as the
/// reassert drain binds it.
const HARD_DELETE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::DELETION_HARD_DELETE_MARKER);

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

    // A local write whose `u:w:` row never landed lives only in the outbound queue: bring every
    // queued send into the old window first, so it carries over like any other unseen write. A
    // row that does not apply stays queued.
    let mut carried = Vec::new();
    for (seq, update) in crate::sync::queue::queued_window_updates(vault, key.as_str())? {
        if old
            .import(&update)
            .is_ok_and(|status| status.pending.is_none())
        {
            carried.push(seq);
        }
    }
    // What carries over is the old window's live state: take off it first what no export may
    // ship, as an export would, so no carried write puts a scrubbed body back.
    scrub_local_only_carriers(vault, key, old)?;
    scrub_local_claim_carriers(vault, key, old)?;
    scrub_redacted_attribution_carriers(vault, key, old)?;
    scrub_withdrawn_delete_carriers(vault, key, old)?;
    let conflicts = carry_over_unseen_writes(old, &candidate)?;
    carry_over_hard_deletes(vault, old, &candidate)?;
    let pending: Vec<_> = {
        let rtxn = vault.store.env.read_txn()?;
        PENDING_TOMBSTONE
            .iter_from(&vault.store, &rtxn, format!("{key}:").as_bytes())?
            .filter_map(std::result::Result::ok)
            .collect()
    };
    let tombstones = TombstoneIndex::build(&candidate.get_map("tombstones"));
    for (marker, value) in &pending {
        apply_tombstone_to_indexed_window_doc(&candidate, &tombstones, &marker.id, value)?;
    }
    candidate.commit();
    replay_pending_mirrors(vault, &candidate, key)?;
    reverse_rematerialize(vault, &candidate, key)?;
    forward_rematerialize(vault, &candidate, materializer, key)?;

    let state = export_scrubbed_window_snapshot(vault, key, &candidate)?;
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

/// A key this vault and the peer both changed, each unseen by the other, where the peer's change
/// wins Loro's order or its order cannot be read (it lies below either side's shallow root). The
/// replacement keeps the peer's value; `held` is the one this vault had, `None` where it had the
/// key removed.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplacementConflict {
    /// The root map, such as `entities`.
    pub map: String,
    pub key: String,
    pub held: Option<LoroValue>,
}

/// Writes into `candidate` the old window's value of every root-map key this vault wrote and the
/// peer never saw: every key whose held value is that of the newest operation of `old` past the
/// candidate's version, unless the peer changed the key too and that change wins, and, below the
/// old window's own shallow root where no operation is left to read, every key whose candidate
/// value came from an operation `old` saw while `old`'s value may have come from one the peer did
/// not. A key both sides changed, each unseen by the other, that this vault's change does not
/// provably win keeps the peer's value and is returned as a conflict.
fn carry_over_unseen_writes(
    old: &LoroDoc,
    candidate: &LoroDoc,
) -> Result<Vec<ReplacementConflict>> {
    old.commit();
    let old_vv = old.oplog_vv();
    let seen = candidate.oplog_vv();
    let shared = seen.intersection(&old_vv);
    let mut from = shared.clone();
    from.merge(&old.shallow_since_vv().to_vv());
    let unseen = newest_ops(old, &from, &old_vv)?;
    // The peer's operations this vault never saw, as far as the candidate's root keeps them.
    let mut theirs_from = shared.clone();
    theirs_from.merge(&candidate.shallow_since_vv().to_vv());
    let theirs = newest_ops(candidate, &theirs_from, &seen)?;
    // `old` as of what both sides hold, raised to its own root where that is later: the state
    // the peer's value is compared with when the peer's writer has operations this vault lacks.
    let mut common = shared;
    common.merge(&super::history_free::root_state(
        &old.shallow_since_vv().to_vv(),
        &old.shallow_since_frontiers(),
    ));
    let at_common = old.fork();
    let at_common = at_common
        .checkout(&old.vv_to_frontiers(&common))
        .is_ok()
        .then_some(at_common);
    let mut conflicts = Vec::new();
    // A key carries over only when the value it holds is that unseen operation's: an unseen
    // operation that lost to one the peer saw leaves the peer's newer value in place. When the
    // peer changed the key too, unseen by this vault, Loro's order decides as a merge would; a
    // change of the peer's whose order cannot be read keeps its value, and this vault's comes
    // back as a conflict.
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
            // The peer never wrote the key, or this vault holds every operation of the writer
            // whose value the peer holds: that value is one this vault's write already beat.
            (None, None) => true,
            (None, Some(writer)) if holds_all_of(&old_vv, &seen, writer) => true,
            // Else the peer's value is unchanged since what both sides hold, or unordered.
            (None, Some(_)) => at_common.as_ref().is_some_and(|at| {
                let before = at.get_map(name.as_str());
                !values_differ(before.get(key), offered.get(key))
                    && before.get_last_editor(key) == offered.get_last_editor(key)
            }),
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
    for (name, key) in touched {
        let target = candidate.get_map(name.as_str());
        match old.get_map(name.as_str()).get(&key) {
            Some(ValueOrContainer::Value(value)) => {
                if target.get(&key).is_none_or(|current| match current {
                    ValueOrContainer::Value(current) => current != value,
                    ValueOrContainer::Container(_) => true,
                }) {
                    target.insert(&key, value).map_err(|e| {
                        Error::sync_engine(crate::error::SyncEngineContext::LoroMapInsert, e)
                    })?;
                }
            }
            Some(ValueOrContainer::Container(_)) => return Err(rejected()),
            None => {
                if target.get(&key).is_some() {
                    map_delete(&target, &key)?;
                }
            }
        }
    }
    candidate.commit();
    Ok(conflicts)
}

/// The newest operation of `doc` between `from` and `to` on each root-map key, by Loro's own
/// order (Lamport, then peer), with the value it wrote (`None` for a removal).
fn newest_ops(
    doc: &LoroDoc,
    from: &VersionVector,
    to: &VersionVector,
) -> Result<BTreeMap<(String, String), (u32, loro::PeerID, Option<LoroValue>)>> {
    let mut newest: BTreeMap<(String, String), (u32, loro::PeerID, Option<LoroValue>)> =
        BTreeMap::new();
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
            if let Some(value) = HARD_DELETE_MARKER.get(&vault.store, &rtxn, &HexId(id))?
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
