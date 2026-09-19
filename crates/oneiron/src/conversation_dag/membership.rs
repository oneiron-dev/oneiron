//! Replicated TURN session membership: body carrier and local index reconstruction.

use super::graph::{self, invalid, require_type};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault, error::Result, store::Store};
use rmpv::Value;

fn carrier(body: &[u8]) -> Result<Option<EntityId>> {
    let mut input = body;
    let Ok(Value::Map(fields)) = rmpv::decode::read_value(&mut input) else {
        return Ok(None); // Generic opaque TURNs are not DAG records.
    };
    let mut fields = fields
        .iter()
        .filter(|(k, _)| k.as_str() == Some("dag_session_ref"));
    let Some((_, value)) = fields.next() else {
        return Ok(None);
    };
    if !input.is_empty() || fields.next().is_some() {
        return Err(invalid("invalid DAG session carrier"));
    }
    let text = value
        .as_str()
        .ok_or(invalid("invalid DAG session reference"))?;
    let session = EntityId::from_hex(text).map_err(|_| invalid("invalid DAG session reference"))?;
    if session.to_hex() != text {
        return Err(invalid("noncanonical DAG session reference"));
    }
    Ok(Some(session))
}

/// Shape and immutable identity checks apply at every put door. Replay may
/// precede SESSION/SpawnedBy/Parent, so topology is checked at atomic adoption.
pub(crate) fn validate_session_carrier(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    let session = carrier(body)?;
    if let Some(previous) = store.port_entity_record(txn, &turn)? {
        if let Some(original) = carrier(&previous.body)? {
            if session != Some(original) {
                return Err(invalid("DAG session membership is immutable"));
            }
        }
    }
    if let Some(session) = session {
        if !replicated {
            require_type(store, txn, &session, ENTITY_TYPE_SESSION)?;
        }
        if crate::compaction::turn_session_membership_in_txn(store, txn, &turn)?
            .is_some_and(|old| old != session)
        {
            return Err(invalid("DAG session membership conflicts with local index"));
        }
    }
    Ok(())
}

/// Keep the projections beside the received record, including records that
/// arrive after the conversation has already been adopted locally.
pub(crate) fn stage_session_carrier(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    body: &[u8],
) -> Result<()> {
    if let Some(session) = carrier(body)? {
        crate::compaction::record_turn_session_membership_in_txn(store, txn, &turn, Some(session))?;
    }
    Ok(())
}

use crate::ports::EntityStoreRead;

pub(super) fn restore(vault: &Vault, txn: &mut heed::RwTxn<'_>, turn: EntityId) -> Result<()> {
    let Some(row) = vault.store.port_entity_record(txn, &turn)? else {
        return Ok(());
    };
    if row.entity_type != ENTITY_TYPE_TURN || row.body.is_empty() {
        return Ok(());
    }
    if let Some(session) = carrier(&row.body)? {
        require_type(&vault.store, txn, &session, ENTITY_TYPE_SESSION)?;
        if crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &turn)?
            .is_some_and(|old| old != session)
        {
            return Err(invalid("DAG session membership conflicts with local index"));
        }
        crate::compaction::record_turn_session_membership_in_txn(
            &vault.store,
            txn,
            &turn,
            Some(session),
        )?;
    }
    Ok(())
}

pub(super) fn validate_topology(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    turn: EntityId,
) -> Result<()> {
    let Some(session) = crate::compaction::turn_session_membership_in_txn(store, txn, &turn)?
    else {
        return Ok(());
    };
    let spawning = graph::edge_ids(store, txn, &session, crate::EdgeKind::SpawnedBy, false, 2)?;
    if spawning.len() > 1 {
        return Err(invalid("session has multiple SpawnedBy edges"));
    }
    let Some(anchor) = spawning.first() else {
        return Ok(());
    };
    graph::require_member(store, txn, &conversation, anchor)?;
    let parent =
        graph::parent(store, txn, &turn)?.ok_or(invalid("sub-session record has no parent"))?;
    if parent != *anchor
        && crate::compaction::turn_session_membership_in_txn(store, txn, &parent)? != Some(session)
    {
        return Err(invalid("sub-session parent crosses membership boundary"));
    }
    if !graph::chain(store, txn, &conversation, turn)?.contains(anchor) {
        return Err(invalid(
            "sub-session does not descend from its spawning turn",
        ));
    }
    Ok(())
}
