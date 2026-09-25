//! Idempotent lazy and maintenance migration of legacy conversation turns.

use super::graph::{self, MIGRATED, edge_ids, key, require_type};
use super::writes::{set_head_in_txn, value};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
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
    require_type(&vault.store, txn, conversation, ENTITY_TYPE_CONVERSATION)?;
    if let Some(marker) = vault
        .store
        .vault_meta
        .get(txn, &key(MIGRATED, conversation))?
    {
        if marker.as_ref() != [1] {
            return Err(Error::CorruptedIndex("conversation DAG migration marker"));
        }
        return Ok(false);
    }
    let candidates = edge_ids(
        &vault.store,
        txn,
        conversation,
        EdgeKind::ChildOf,
        true,
        MAX_ANCESTOR_DEPTH,
    )?;
    // Restore every carrier before classifying any parent, independent of
    // peer key order. Failure rolls back both membership indexes and adoption.
    for id in &candidates {
        super::membership::restore(vault, txn, *id)?;
    }
    let mut turns = Vec::new();
    let mut already_dag = false;
    for id in candidates {
        match live_entity_row_in_txn(&vault.store, txn, &id)? {
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => continue,
            LiveEntityRow::Live { entity_type, .. } if entity_type != ENTITY_TYPE_TURN => continue,
            _ => {}
        }
        graph::require_member(&vault.store, txn, conversation, &id)?;
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
        if graph::is_thread_record(&vault.store, txn, &id)?
            || graph::is_sub_session_record(&vault.store, txn, &id)?
        {
            continue;
        }
        already_dag |= graph::parent(&vault.store, txn, &id)?.is_some();
        let raw = vault
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let metadata =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if let Some(body) = raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) {
            already_dag |= super::admission::record_kind(body)?.is_some();
        }
        turns.push((metadata.occurred_start, id));
    }
    turns.sort_unstable();
    if already_dag {
        // Received DAG edges predate local HEAD state. Never overwrite their
        // parentage with a legacy chain. Validate and choose a deterministic
        // local initial branch; HEAD remains local after this first adoption.
        // Each live record and Parent is examined once. Rewalking every
        // ancestor path would reject a valid 142-record chain under a 10k
        // work budget even though the shared depth cap admits it.
        let members: HashSet<_> = turns.iter().map(|(_, id)| *id).collect();
        let mut children: HashMap<EntityId, Vec<EntityId>> = HashMap::new();
        let mut ready = VecDeque::new();
        for (_, id) in &turns {
            if let Some(parent) = graph::parent(&vault.store, txn, id)? {
                if !members.contains(&parent) {
                    graph::require_member(&vault.store, txn, conversation, &parent)?;
                    return Err(graph::invalid("trunk Parent is outside the live trunk"));
                }
                children.entry(parent).or_default().push(*id);
            } else {
                ready.push_back(*id);
            }
        }
        if ready.len() != 1 {
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
        if visited != turns.len() {
            return Err(graph::invalid("received DAG contains a Parent cycle"));
        }
    } else {
        let mut batch = vault.batch_in();
        for pair in turns.windows(2) {
            batch = batch.edge_with_value_fields(
                &pair[1].1,
                EdgeKind::Parent,
                &pair[0].1,
                value(pair[1].0),
            );
        }
        batch.apply(txn)?;
    }
    if let Some((_, head)) = turns.last() {
        set_head_in_txn(vault, txn, conversation, *head)?;
    }
    vault
        .store
        .vault_meta
        .put(txn, &key(MIGRATED, conversation), &[1])?;
    Ok(true)
}

impl Vault {
    /// Builds a time-ordered chain for a legacy conversation, once. Existing
    /// bodies and ChildOf edges are untouched; deleted shells are omitted.
    pub fn migrate_conversation_dag(&self, conversation: &EntityId) -> Result<bool> {
        self.with_write_txn(|txn| migrate_in_txn(self, txn, conversation))
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
                        && (self
                            .store
                            .vault_meta
                            .get(&txn, &key(MIGRATED, id))?
                            .is_some()
                            || !edge_ids(
                                &self.store,
                                &txn,
                                id,
                                EdgeKind::ChildOf,
                                true,
                                MAX_ANCESTOR_DEPTH,
                            )?
                            .is_empty())
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
