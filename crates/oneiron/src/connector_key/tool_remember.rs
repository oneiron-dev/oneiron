//! Native standing consent for a tool's explicit stop-asking answer.

use serde::{Deserialize, Serialize};

use super::record::ConnectorKeyRecord;
use super::slate::SlateDisposition;
use super::slate_setting::{connector_tool_setting_in_txn, governing_slate_in_txn};
use crate::EntityId;
use crate::consent::tool_scope::ScopedMcpCallContext;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::error::Result;
use crate::store::Store;

const TOOL_REMEMBER_CLASS: &str = "outbound.connector_tool";

/// Engine-resolved scope of the call, frozen with its request. `None` project
/// means this call has no project; it is not a vault-wide selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConnectorToolRememberContext {
    /// Filled only by preparation against the current native connector key.
    pub(crate) connection: Option<EntityId>,
    pub(crate) project: Option<EntityId>,
    pub(crate) lineage: Option<[u8; 32]>,
}

/// The native connection whose settings a key meets, not a display name or
/// an execution principal. A derived per-grant key retains its catalog parent.
pub(crate) fn connector_tool_connection_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
) -> Result<EntityId> {
    Ok(
        super::lifecycle::derived_key_catalog_in_txn(store, txn, key)?
            .map_or(*key_id, |(id, _, _)| id),
    )
}

/// This connection's current setting act and class/project box. The caller
/// may explicitly narrow it to its verified credential lineage.
pub(crate) fn connector_tool_remember_bound_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    call: &ScopedMcpCallContext,
    context: ConnectorToolRememberContext,
    asking_lineage: bool,
) -> Result<Option<(EntityId, GrantBound)>> {
    let Some((_, slate)) = governing_slate_in_txn(store, txn, key)? else {
        return Ok(None);
    };
    let Some(row) = slate.row(&call.tool) else {
        return Ok(None);
    };
    if row.effective_disposition() != SlateDisposition::AlwaysAsk
        || connector_tool_setting_in_txn(store, txn, key_id, key, &call.tool)?
            != SlateDisposition::AlwaysAsk
    {
        return Ok(None);
    }
    // Per-grant keys derive their connection's native catalog identity. The
    // per-caller capability and every other Gate check remain independent.
    let connection = connector_tool_connection_in_txn(store, txn, key_id, key)?;
    if context.connection != Some(connection) {
        return Ok(None);
    }
    let subject = if asking_lineage {
        let Some(lineage) = context.lineage else {
            return Ok(None);
        };
        format!(
            "connector:{}:lineage:{}",
            connection.to_hex(),
            crate::entity_id::bytes_to_hex_lower(&lineage)
        )
    } else {
        format!("connector:{}", connection.to_hex())
    };
    let project = context
        .project
        .map_or_else(|| "none".to_owned(), |id| id.to_hex());
    let bound = GrantBound::action(
        ActorBound::new(subject)?,
        ActionClass::new(format!(
            "{TOOL_REMEMBER_CLASS}.{}",
            call.payload_data_class.as_str()
        ))?,
        ActionEnvelope::new([
            format!("server:{}", blake3::hash(call.server.as_bytes()).to_hex()),
            format!("tool:{}", blake3::hash(call.tool.as_bytes()).to_hex()),
            format!("settings_act:{}", row.settings_act.to_hex()),
        ])?
        .with_target(format!(
            "settings_act:{}:project:{project}",
            row.settings_act.to_hex()
        ))?,
    )?;
    Ok(Some((row.settings_act, bound)))
}

/// A live native grant covers this exact connection, class and project,
/// either for every caller or for this call's verified asking lineage.
pub(crate) fn connector_tool_remembered_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    call: &ScopedMcpCallContext,
    context: Option<ConnectorToolRememberContext>,
) -> Result<bool> {
    let Some(context) = context else {
        return Ok(false);
    };
    let grants = crate::consent::load_active_standing_grants(store, txn)?;
    for asking_lineage in [false, true] {
        if let Some((_, bound)) = connector_tool_remember_bound_in_txn(
            store,
            txn,
            key_id,
            key,
            call,
            context,
            asking_lineage,
        )? && grants.iter().any(|grant| grant.bound().contains(&bound))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
