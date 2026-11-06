//! Idempotent local initialization of received conversation DAGs.
//!
//! Parentage comes only from current DAG records and retained ancestry pins;
//! independent turns are never adopted into a time-ordered legacy chain.

use super::graph::{self, MIGRATED, require_type};
use super::writes::set_head_in_txn;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, RegistryError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::RwTxn;
use std::collections::{HashMap, HashSet, VecDeque};

pub(crate) fn migrate_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversation: &EntityId,
) -> Result<bool> {
    initialize_except_in_txn(vault, txn, conversation, None)
}

/// The admitted current producer permits its fresh ChildOf before staging.
pub(crate) fn permit_core_turn_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversation: &EntityId,
    turn: EntityId,
) -> Result<()> {
    super::admission::permit(&vault.store, txn, &turn, conversation)
}

/// A fresh core TURN joins the actual local HEAD in its create transaction.
/// It is excluded only while initializing the pre-existing received DAG;
/// its own Parent and canonical placement are then written explicitly.
pub(crate) fn join_core_turn_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversation: &EntityId,
    turn: EntityId,
    at: u64,
) -> Result<()> {
    // These records already keep their explicit non-trunk placement.
    if graph::is_thread_record(&vault.store, txn, &turn)?
        || super::writes::bound_to_thread(vault, txn, &turn)?
        || graph::is_sub_session_record(&vault.store, txn, &turn)?
    {
        return super::admission::finish(&vault.store, txn, &turn);
    }
    initialize_except_in_txn(vault, txn, conversation, Some(&turn))?;
    if graph::parent(&vault.store, txn, &turn)?.is_none()
        && let Some(parent) = graph::read_id(&vault.store, txn, graph::HEAD, conversation)?
    {
        vault
            .batch_in()
            .edge_with_value_fields(&turn, EdgeKind::Parent, &parent, super::writes::value(at))
            .apply(txn)?;
    }
    set_head_in_txn(vault, txn, conversation, turn)?;
    super::admission::finish(&vault.store, txn, &turn)
}

fn initialize_except_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversation: &EntityId,
    fresh_turn: Option<&EntityId>,
) -> Result<bool> {
    require_type(&vault.store, txn, conversation, ENTITY_TYPE_CONVERSATION)?;
    if let Some(marker) = MIGRATED.get(&vault.store, txn, conversation)? {
        if marker != [1] {
            return Err(Error::CorruptedIndex("conversation DAG migration marker"));
        }
        return Ok(false);
    }
    // Rule 5: adoption reads the whole room, however many records, and
    // counts it as one walk.
    let mut walk = graph::walk_count(&vault.store, txn, conversation)?;
    let mut candidates = graph::all_edge_ids(
        &vault.store,
        txn,
        conversation,
        EdgeKind::ChildOf,
        true,
        &mut walk,
    )?;
    candidates.retain(|id| Some(id) != fresh_turn);
    // A pending received Parent does not turn its source into a trunk root.
    // Check the coordinator's exact source index in this same per-room txn;
    // maintenance skips/names this incomplete room and continues scanning.
    #[cfg(feature = "sync")]
    for id in &candidates {
        if crate::sync::bridge::has_unresolved_parent_for_source_in_txn(vault, txn, id)? {
            return Err(graph::invalid("received DAG Parent dependency pending"));
        }
    }
    // Restore every carrier before classifying any parent, independent of
    // peer key order. Failure rolls back both membership indexes and adoption.
    for id in &candidates {
        super::membership::restore(vault, txn, *id)?;
    }
    let mut turns = Vec::new();
    let mut all_parents = HashMap::new();
    let mut non_trunk = HashSet::new();
    let mut opaque_thread_roots = HashSet::new();
    for id in candidates {
        match live_entity_row_in_txn(&vault.store, txn, &id)? {
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => continue,
            LiveEntityRow::Live { entity_type, .. } if entity_type != ENTITY_TYPE_TURN => continue,
            _ => {}
        }
        graph::require_member(&vault.store, txn, conversation, &id)?;
        let body = graph::require_type(&vault.store, txn, &id, ENTITY_TYPE_TURN)?;
        let record_kind = super::admission::record_kind(&body)?;
        let room_thread = crate::workspace_roster::thread_binding(&body)?.is_some();
        let raw = vault
            .store
            .port_entity_record(txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        super::admission::reconcile_addressing(vault, txn, &id, &body, raw.learned_at).map_err(
            |error| match error {
                Error::EntityNotFound => graph::invalid("received address recipient pending"),
                other => other,
            },
        )?;
        super::admission::pin_record(&vault.store, txn, &id)?;
        if let Some(session) =
            crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &id)?
        {
            crate::compaction::record_turn_session_membership_in_txn(
                &vault.store,
                txn,
                &id,
                Some(session),
            )?;
        }
        let parent = graph::parent(&vault.store, txn, &id)?;
        // FIX 5644: a thread audience edit is a parentless TURN about its
        // root, never a trunk turn; adoption leaves it out of the walk.
        if parent.is_none() && carries_audience_edit(&body) {
            continue;
        }
        all_parents.insert(id, parent);
        // Native opaque room-thread births need no DAG Parent. They remain
        // graph roots for later thread replies, but never trunk roots.
        if parent.is_none() && room_thread && record_kind.is_none() {
            opaque_thread_roots.insert(id);
        }
        let thread = graph::is_thread_record(&vault.store, txn, &id)? || room_thread;
        let sub_session =
            graph::is_sub_session_record(&vault.store, txn, &id).map_err(|error| {
                // This is a received conversation's topology, not a storage
                // failure. Maintenance may skip this room and keep scanning.
                if matches!(error, Error::Registry(RegistryError::CycleDetected)) {
                    graph::invalid("received sub-session contains a Parent cycle")
                } else {
                    error
                }
            })?;
        if thread || sub_session {
            non_trunk.insert(id);
            continue;
        }
        let raw = vault
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let metadata =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        turns.push((metadata.occurred_start, id));
    }
    turns.sort_unstable();
    // A tombstone can arrive before this replica's first DAG adoption. The
    // deleted ancestor is no longer in the room's ChildOf index, but its
    // previously verified content-free pin preserves the Parent chain. Add
    // only such pinned ghosts to the structural walk; never infer an absent
    // root from a live child's unpaired Parent edge.
    let mut pending: VecDeque<_> = all_parents.keys().copied().collect();
    while let Some(id) = pending.pop_front() {
        let Some(parent) = all_parents[&id] else {
            continue;
        };
        if all_parents.contains_key(&parent) {
            continue;
        }
        match live_entity_row_in_txn(&vault.store, txn, &parent)? {
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell
                if super::redacted::read(&vault.store, txn, &parent)?.is_some() => {}
            _ => {
                return Err(graph::invalid(
                    "received Parent is outside the live conversation",
                ));
            }
        }
        graph::require_member(&vault.store, txn, conversation, &parent)?;
        walk.row();
        if graph::is_thread_record(&vault.store, txn, &parent)?
            || graph::is_sub_session_record(&vault.store, txn, &parent)?
        {
            non_trunk.insert(parent);
        }
        all_parents.insert(parent, graph::parent(&vault.store, txn, &parent)?);
        pending.push_back(parent);
    }
    // Check every live TURN plus pinned erased ancestors before writing the
    // migration marker. Thread and
    // sub-session records stay outside HEAD selection, not outside the DAG:
    // a cycle confined to either class must not be silently adopted. This
    // Kahn pass examines each record and Parent once, not every ancestor path.
    let mut all_children: HashMap<EntityId, Vec<EntityId>> = HashMap::new();
    let mut all_ready = VecDeque::new();
    for (&id, &parent) in &all_parents {
        if let Some(parent) = parent {
            if !all_parents.contains_key(&parent) {
                return Err(graph::invalid(
                    "received Parent is outside the live conversation",
                ));
            }
            all_children.entry(parent).or_default().push(id);
        } else if non_trunk.contains(&id) && !opaque_thread_roots.contains(&id) {
            return Err(graph::invalid(
                "received thread or sub-session has no Parent",
            ));
        } else {
            all_ready.push_back(id);
        }
    }
    let mut visited = 0;
    while let Some(id) = all_ready.pop_front() {
        visited += 1;
        if let Some(children) = all_children.remove(&id) {
            all_ready.extend(children);
        }
    }
    if visited != all_parents.len() {
        return Err(graph::invalid("received DAG contains a Parent cycle"));
    }
    {
        // Received DAG edges predate local HEAD state. Validate their
        // parentage and choose a deterministic
        // local initial branch; HEAD remains local after this first adoption.
        // This additional trunk-only pass stays linear: it reads each record
        // and Parent once, never every ancestor path.
        let live_members: HashSet<_> = turns.iter().map(|(_, id)| *id).collect();
        let mut members = live_members.clone();
        let mut pending: VecDeque<_> = live_members.iter().copied().collect();
        let mut children: HashMap<EntityId, Vec<EntityId>> = HashMap::new();
        let mut ready = VecDeque::new();
        while let Some(id) = pending.pop_front() {
            if let Some(parent) = graph::parent(&vault.store, txn, &id)? {
                // A received hard/soft tombstone can remove the owner's
                // ChildOf index before this replica has adopted a local HEAD.
                // Admit only pinned, deleted ancestors: never reinterpret an
                // unrelated live turn as a missing trunk member or hydrate a
                // deleted body. Walk each ghost once.
                if !members.contains(&parent) {
                    match live_entity_row_in_txn(&vault.store, txn, &parent)? {
                        LiveEntityRow::Absent | LiveEntityRow::DeletedShell
                            if super::redacted::read(&vault.store, txn, &parent)?.is_some() => {}
                        _ => return Err(graph::invalid("trunk Parent is outside the trunk")),
                    }
                    graph::require_member(&vault.store, txn, conversation, &parent)?;
                    if graph::is_thread_record(&vault.store, txn, &parent)?
                        || graph::is_sub_session_record(&vault.store, txn, &parent)?
                    {
                        return Err(graph::invalid("trunk Parent is not a trunk record"));
                    }
                    walk.row();
                    members.insert(parent);
                    pending.push_back(parent);
                }
                children.entry(parent).or_default().push(id);
            } else {
                ready.push_back(id);
            }
        }
        if !members.is_empty() && ready.len() != 1 {
            return Err(graph::invalid(
                "received DAG requires exactly one trunk root",
            ));
        }
        let mut visited = 0;
        while let Some(id) = ready.pop_front() {
            visited += 1;
            if let Some(children) = children.remove(&id) {
                ready.extend(children);
            }
        }
        if visited != members.len() {
            return Err(graph::invalid("received DAG contains a Parent cycle"));
        }
    }
    if let Some((_, head)) = turns.last() {
        set_head_in_txn(vault, txn, conversation, *head)?;
    }
    walk.defer(&vault.store);
    MIGRATED.put(&vault.store, txn, conversation, &[1])?;
    Ok(true)
}

/// Whether a TURN's MessagePack `body` carries a thread audience edit.
fn carries_audience_edit(body: &[u8]) -> bool {
    let mut bytes = body;
    matches!(
        rmpv::decode::read_value(&mut bytes),
        Ok(rmpv::Value::Map(fields)) if fields
            .iter()
            .any(|(key, _)| key.as_str() == Some(crate::workspace_roster::ROOM_THREAD_AUDIENCE_KEY))
    )
}

impl Vault {
    /// Initializes a received DAG's local HEAD once, preserving its actual
    /// Parent edges. Bodies and ChildOf edges are untouched; deleted shells
    /// are omitted. Independent turns are never joined by their timestamps.
    pub fn migrate_conversation_dag(&self, conversation: &EntityId) -> Result<bool> {
        self.with_write_txn_grouped(|txn| migrate_in_txn(self, txn, conversation))
    }

    pub(crate) fn migrate_all_conversation_dags(&self) -> Result<(u64, Vec<EntityId>)> {
        // Stream one type-index page at a time, with a separate atomic commit
        // per conversation. No vault-wide unbounded materialization.
        let mut after = None;
        let mut migrated = 0_u64;
        let mut skipped_invalid = Vec::new();
        loop {
            let ids = self.entities_by_type_page(ENTITY_TYPE_CONVERSATION, after.as_ref(), 256)?;
            if ids.is_empty() {
                break;
            }
            for id in &ids {
                let live = {
                    let txn = self.store.env.read_txn()?;
                    live_entity_row_in_txn(&self.store, &txn, id)?.is_live()
                        && (MIGRATED.get(&self.store, &txn, id)?.is_some()
                            || graph::has_edge(&self.store, &txn, id, EdgeKind::ChildOf, true)?)
                };
                if live {
                    match self.migrate_conversation_dag(id) {
                        Ok(true) => migrated += 1,
                        Ok(false) => {}
                        Err(Error::Record(RecordError::InvalidConversationDag(_))) => {
                            skipped_invalid.push(*id);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            after = ids.last().copied();
        }
        Ok((migrated, skipped_invalid))
    }
}
