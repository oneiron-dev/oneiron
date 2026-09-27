//! Read-only selected topology over retained TURN and SESSION headers.
//!
//! A selected path proves branch membership; it does not re-run append or
//! receive admission. Deleted shells remain structural, never renderable.

use super::graph::{self, CANONICAL, HEAD, MIGRATED};
use crate::edge::EdgeKind;
use crate::error::{Error, RegistryError, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::RoTxn;
use std::collections::HashSet;

pub(crate) enum RetainedRow {
    Live { learned_at: u64, body: Vec<u8> },
    SoftDeleted,
    Absent,
}

pub(crate) fn retained_row(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    expected: u8,
) -> Result<RetainedRow> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(RetainedRow::Absent);
    };
    if raw.entity_type != expected {
        return Err(graph::invalid("retained entity has wrong type"));
    }
    match live_entity_row_in_txn(store, txn, id)? {
        LiveEntityRow::Live { entity_type, body } if entity_type == expected => {
            Ok(RetainedRow::Live {
                learned_at: raw.learned_at,
                body,
            })
        }
        LiveEntityRow::DeletedShell => Ok(RetainedRow::SoftDeleted),
        LiveEntityRow::Absent => Err(Error::CorruptedIndex("retained entity row")),
        LiveEntityRow::Live { .. } => Err(graph::invalid("retained entity has wrong type")),
    }
}

pub(crate) struct RetainedTurn {
    pub(crate) id: EntityId,
    pub(crate) row: RetainedRow,
}

pub(crate) struct SelectedPathSnapshot {
    pub(crate) turns: Vec<RetainedTurn>, // root to selected HEAD
}

/// An absent local HEAD is not evidence of a ChildOf-only room by itself.
pub(crate) enum PreviewTopology {
    Selected(SelectedPathSnapshot),
    ChildOfOnly,
}

enum SessionReadEvidence {
    Ordinary,
    Spawned,
    Unresolved,
}

fn session_evidence(
    store: &Store,
    txn: &RoTxn<'_>,
    session: &EntityId,
) -> Result<SessionReadEvidence> {
    let row = retained_row(store, txn, session, ENTITY_TYPE_SESSION)?;
    if matches!(row, RetainedRow::Absent) {
        return Ok(SessionReadEvidence::Unresolved);
    }
    let spawned = graph::edge_ids(store, txn, session, EdgeKind::SpawnedBy, false, 2)?;
    if spawned.len() > 1 {
        return Err(graph::invalid("session has multiple SpawnedBy edges"));
    }
    let declared = if let RetainedRow::Live { body, .. } = row {
        let mut bytes = body.as_slice();
        match rmpv::decode::read_value(&mut bytes) {
            Ok(rmpv::Value::Map(fields)) if bytes.is_empty() => {
                let mut anchors = fields
                    .iter()
                    .filter(|(key, _)| key.as_str() == Some("dag_spawning_turn"));
                let anchor = anchors
                    .next()
                    .map(|(_, value)| {
                        let text = value
                            .as_str()
                            .ok_or_else(|| graph::invalid("invalid sub-session anchor"))?;
                        let id = EntityId::from_hex(text)
                            .map_err(|_| graph::invalid("invalid sub-session anchor"))?;
                        if id.to_hex() != text {
                            return Err(graph::invalid("noncanonical sub-session anchor"));
                        }
                        Ok(id)
                    })
                    .transpose()?;
                if anchors.next().is_some() {
                    return Err(graph::invalid("duplicate sub-session anchor"));
                }
                anchor
            }
            _ => None, // live header-only legacy SESSIONs have no declaration
        }
    } else {
        None // a deleted body cannot supply or erase structural evidence
    };
    match (declared, spawned.as_slice()) {
        (None, []) => Ok(SessionReadEvidence::Ordinary),
        (Some(_), []) => Ok(SessionReadEvidence::Unresolved),
        (Some(expected), [actual]) if expected != *actual => {
            Err(graph::invalid("session anchor disagrees with SpawnedBy"))
        }
        (_, [_]) => Ok(SessionReadEvidence::Spawned),
        _ => Err(graph::invalid("session has multiple SpawnedBy edges")),
    }
}

fn prove_childof_only(vault: &Vault, txn: &RoTxn<'_>, conversation: &EntityId) -> Result<()> {
    let store = &vault.store;
    if store
        .vault_meta
        .get(txn, &graph::key(MIGRATED, conversation))?
        .is_some()
    {
        return Err(graph::invalid("DAG has no selected HEAD"));
    }
    for entry in store.port_edges(
        txn,
        conversation,
        EdgeDirection::In,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let id = entry?.target;
        let Some(raw) = store.port_entity_record(txn, &id)? else {
            return Err(Error::CorruptedIndex("conversation ChildOf row"));
        };
        if raw.entity_type != ENTITY_TYPE_TURN {
            continue;
        }
        if !graph::edge_ids(store, txn, &id, EdgeKind::Parent, false, 2)?.is_empty()
            || graph::read_id(store, txn, CANONICAL, &id)?.is_some()
        {
            return Err(graph::invalid("unselected conversation DAG"));
        }
        #[cfg(feature = "sync")]
        if crate::sync::bridge::has_unresolved_parent_for_source_in_txn(vault, txn, &id)? {
            return Err(graph::invalid("received DAG Parent dependency pending"));
        }
        match retained_row(store, txn, &id, ENTITY_TYPE_TURN)? {
            RetainedRow::Live { body, .. } => {
                if super::topology::record_kind(&body)?.is_some() {
                    return Err(graph::invalid("unselected DAG record"));
                }
            }
            RetainedRow::SoftDeleted => {}
            RetainedRow::Absent => return Err(Error::CorruptedIndex("conversation ChildOf row")),
        }
        if let Some(session) = crate::compaction::turn_session_membership_in_txn(store, txn, &id)? {
            match session_evidence(store, txn, &session)? {
                SessionReadEvidence::Ordinary => {}
                SessionReadEvidence::Spawned => {
                    return Err(graph::invalid("unselected spawned session"));
                }
                SessionReadEvidence::Unresolved => {
                    return Err(graph::invalid("unresolved received session"));
                }
            }
        }
    }
    Ok(())
}

impl SelectedPathSnapshot {
    pub(crate) fn read(
        vault: &Vault,
        txn: &RoTxn<'_>,
        conversation: &EntityId,
    ) -> Result<PreviewTopology> {
        let store = &vault.store;
        let head = graph::read_id(store, txn, HEAD, conversation)?;
        if !matches!(
            retained_row(store, txn, conversation, ENTITY_TYPE_CONVERSATION)?,
            RetainedRow::Live { .. }
        ) {
            return Err(graph::invalid("selected conversation is not live"));
        }
        let Some(head) = head else {
            prove_childof_only(vault, txn, conversation)?;
            return Ok(PreviewTopology::ChildOfOnly);
        };
        let mut seen = HashSet::new();
        let mut reversed = Vec::new();
        let mut cursor = Some(head);
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(RegistryError::CycleDetected.into());
            }
            if reversed.len() >= MAX_ANCESTOR_DEPTH {
                return Err(Error::IndexOverflow("conversation_dag_walk"));
            }
            let row = retained_row(store, txn, &id, ENTITY_TYPE_TURN)?;
            match &row {
                RetainedRow::Absent => return Err(Error::EntityNotFound),
                RetainedRow::Live { body, .. } => {
                    if super::topology::record_kind(body)?
                        == Some(super::topology::RecordKind::Thread)
                    {
                        return Err(graph::invalid("thread on selected path"));
                    }
                }
                RetainedRow::SoftDeleted => {} // no payload to parse
            }
            let owners = graph::edge_ids(store, txn, &id, EdgeKind::ChildOf, false, 2)?;
            if owners.as_slice() != [*conversation] {
                return Err(graph::invalid("record is outside selected conversation"));
            }
            if let Some(session) =
                crate::compaction::turn_session_membership_in_txn(store, txn, &id)?
            {
                match session_evidence(store, txn, &session)? {
                    SessionReadEvidence::Ordinary => {}
                    SessionReadEvidence::Spawned => {
                        return Err(graph::invalid("spawned session on selected path"));
                    }
                    SessionReadEvidence::Unresolved => {
                        return Err(graph::invalid("unresolved selected session"));
                    }
                }
            }
            let parents = graph::edge_ids(store, txn, &id, EdgeKind::Parent, false, 2)?;
            if parents.len() > 1 {
                return Err(graph::invalid("record has multiple Parent edges"));
            }
            cursor = parents.first().copied();
            reversed.push(RetainedTurn { id, row });
        }
        reversed.reverse();
        for (n, turn) in reversed.iter().enumerate() {
            if graph::read_id(store, txn, CANONICAL, &turn.id)?
                != reversed.get(n + 1).map(|next| next.id)
            {
                return Err(Error::CorruptedIndex("conversation canonical mark"));
            }
        }
        Ok(PreviewTopology::Selected(Self { turns: reversed }))
    }
}
