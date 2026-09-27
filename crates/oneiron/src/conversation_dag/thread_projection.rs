//! Deterministic root-first, no-forks thread selection over a single read snapshot.

use super::graph::{conversation_of, edge_ids, invalid, require_member};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
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
    let mut examined = 0;
    loop {
        let mut children = edge_ids(
            &vault.store,
            txn,
            &current,
            EdgeKind::RepliesTo,
            true,
            MAX_ANCESTOR_DEPTH.saturating_sub(examined),
        )?;
        examined += children.len();
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
            if edge_ids(&vault.store, txn, &child, EdgeKind::RepliesTo, false, 2)? != [current] {
                return Err(invalid("record needs exactly one reply target"));
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
