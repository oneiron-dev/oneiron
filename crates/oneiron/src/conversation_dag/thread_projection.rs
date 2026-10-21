//! Deterministic root-first, no-forks thread selection over a single read snapshot.
//! A thread continues on Parent edges; a reply's RepliesTo target is its
//! semantic answer and may lie on the trunk.

use super::graph::{all_edge_ids, conversation_of, invalid, require_member, walk_count};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::vault::live_entity_row_in_txn;
use crate::{EntityId, Vault};
use heed::RoTxn;
use std::collections::HashSet;

/// Complete chosen chain. Never substitutes the room's ancestor prefix for replies.
pub(crate) struct SelectedThread {
    pub conversation: EntityId,
    pub trunk: EntityId,
    pub root: EntityId,
    pub tip: EntityId,
    pub replies: Vec<EntityId>,
    pub last_at: u64,
}

pub(super) fn chain_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    anchor: EntityId,
    session: Option<Option<EntityId>>,
) -> Result<Vec<EntityId>> {
    let mut current = anchor;
    let mut seen = HashSet::from([anchor]);
    let mut replies = Vec::new();
    // Rule 5: the thread is read whole, however long, and counted.
    let mut walk = walk_count(&vault.store, txn, &conversation)?;
    loop {
        let mut children = all_edge_ids(
            &vault.store,
            txn,
            &current,
            EdgeKind::Parent,
            true,
            &mut walk,
        )?;
        children.sort_unstable();
        let mut selected = None;
        for child in children {
            if !seen.insert(child) {
                return Err(crate::error::RegistryError::CycleDetected.into());
            }
            if !live_entity_row_in_txn(&vault.store, txn, &child)?.is_live() {
                continue;
            }
            require_member(&vault.store, txn, &conversation, &child)?;
            if super::graph::parent(&vault.store, txn, &child)? != Some(current) {
                return Err(invalid("record needs exactly one Parent"));
            }
            if !super::graph::is_thread_record(&vault.store, txn, &child)? {
                continue;
            }
            if selected.is_none()
                && (session.is_none()
                    || crate::compaction::turn_session_membership_in_txn(
                        &vault.store,
                        txn,
                        &child,
                    )? == session.expect("checked above"))
            {
                selected = Some(child);
            }
        }
        let Some(next) = selected else { break };
        replies.push(next);
        current = next;
    }
    walk.defer(&vault.store);
    Ok(replies)
}

pub(crate) fn selected_thread_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    trunk: EntityId,
) -> Result<Option<SelectedThread>> {
    let conversation = conversation_of(&vault.store, txn, &trunk)?;
    let replies = chain_in_txn(vault, txn, conversation, trunk, None)?;
    let Some(&root) = replies.first() else {
        return Ok(None);
    };
    let tip = *replies.last().expect("nonempty thread has tip");
    let mut last_at = 0;
    for id in &replies {
        let row = vault
            .store
            .port_entity_record(txn, id)?
            .ok_or(Error::EntityNotFound)?;
        last_at = last_at.max(row.occurred.start);
    }
    Ok(Some(SelectedThread {
        conversation,
        trunk,
        root,
        tip,
        replies,
        last_at,
    }))
}
