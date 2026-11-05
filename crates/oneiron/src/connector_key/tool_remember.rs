//! Lineage-bound consent for a tool's explicit stop-asking answer.

use super::record::ConnectorKeyRecord;
use super::slate::SlateDisposition;
use super::slate_setting::{connector_tool_setting_in_txn, governing_slate_in_txn};
use crate::EntityId;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::error::Result;
use crate::store::Store;

const TOOL_REMEMBER_CLASS: &str = "outbound.connector_tool";

/// The current owner-setting identity and the exact lineage/tool box a
/// remember act covers. A holder's tighter setting remains independent.
pub(crate) fn connector_tool_remember_bound_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    actor: EntityId,
    server: &str,
    tool: &str,
) -> Result<Option<(EntityId, GrantBound)>> {
    let Some((_, slate)) = governing_slate_in_txn(store, txn, key)? else {
        return Ok(None);
    };
    let Some(row) = slate.row(tool) else {
        return Ok(None);
    };
    if row.effective_disposition() != SlateDisposition::AlwaysAsk
        || connector_tool_setting_in_txn(store, txn, key_id, key, tool)?
            != SlateDisposition::AlwaysAsk
    {
        return Ok(None);
    }
    let bound = GrantBound::action(
        ActorBound::new(actor.to_hex())?,
        ActionClass::new(TOOL_REMEMBER_CLASS)?,
        ActionEnvelope::new([
            format!("server:{}", blake3::hash(server.as_bytes()).to_hex()),
            format!("tool:{}", blake3::hash(tool.as_bytes()).to_hex()),
            format!("settings_act:{}", row.settings_act.to_hex()),
        ])?
        .with_target(format!("settings_act:{}", row.settings_act.to_hex()))?,
    )?;
    Ok(Some((row.settings_act, bound)))
}

/// A distinct, live native consent grant covers this actor and this tool's
/// current setting act. An ordinary scoped-MCP capability grant is not one.
pub(crate) fn connector_tool_remembered_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    actor: Option<EntityId>,
    server: &str,
    tool: &str,
) -> Result<bool> {
    let Some(actor) = actor else {
        return Ok(false);
    };
    let Some((_, bound)) =
        connector_tool_remember_bound_in_txn(store, txn, key_id, key, actor, server, tool)?
    else {
        return Ok(false);
    };
    Ok(crate::consent::load_active_standing_grants(store, txn)?
        .iter()
        .any(|grant| grant.bound().contains(&bound)))
}
