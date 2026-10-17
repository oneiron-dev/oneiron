//! The four capability settings at call time (DEC-0006 §MCP connector
//! permissions). A key with no slate (a legacy or per-grant key) has no rows
//! and stays on the per-call verdict. No setting widens scope or passes the
//! catastrophe floor: `always allow` is only a covering grant.
use super::record::{ConnectorKeyRecord, ConnectorKeyStatus, ScopedCapabilityProvenance};
use super::slate::{SlateDisposition, read_slate_in_store_txn};
use super::txn::{governing_connector_key, read_connector_key_in_txn};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};

/// The setting a call on `tool` meets under the key's bound slate.
pub(crate) fn connector_tool_setting_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
    tool: &str,
) -> Result<SlateDisposition> {
    let Some(slate_id) = key.slate_ref else {
        return Ok(SlateDisposition::Auto);
    };
    let slate = read_slate_in_store_txn(store, txn, slate_id)?
        .ok_or_else(|| super::record::invalid_body("connector slate missing"))?;
    Ok(slate.tool_setting(tool))
}

/// Whether the effect's governing key gives its tool `always allow`. The Gate
/// folds a yes in as a covering grant, the way it folds a scoped-MCP grant,
/// so the consent verdict still asks on a catastrophe.
pub(crate) fn effect_slate_always_allows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    channel: &str,
    verb: &str,
    scoped: Option<(&str, &EntityId, &str)>,
    actor: Option<&EntityId>,
) -> Result<bool> {
    let (connector, tool) = match scoped {
        Some((server, grant_id, tool)) => {
            let Some(capability) = ScopedCapabilityProvenance::mint(server, grant_id) else {
                return Ok(false);
            };
            (capability.connector().to_owned(), tool)
        }
        None => (super::record::normalize_connector_key(channel), verb),
    };
    let Some((_, key)) = governing_connector_key(store, txn, &connector, actor)? else {
        return Ok(false);
    };
    Ok(key.status == ConnectorKeyStatus::Active
        && connector_tool_setting_in_txn(store, txn, &key, tool)? == SlateDisposition::AlwaysAllow)
}

/// `never allow` removes a tool from what the connector lists as callable.
pub(super) fn callable_verbs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
    verbs: Vec<String>,
) -> Result<Vec<String>> {
    let Some(slate_id) = key.slate_ref else {
        return Ok(verbs);
    };
    let Some(slate) = read_slate_in_store_txn(store, txn, slate_id)? else {
        return Ok(verbs);
    };
    Ok(verbs
        .into_iter()
        .filter(|verb| slate.tool_setting(verb) != SlateDisposition::NeverAllow)
        .collect())
}

impl Vault {
    /// The capability setting a call on `tool` meets under key `id`.
    pub fn connector_tool_setting(&self, id: &EntityId, tool: &str) -> Result<SlateDisposition> {
        let txn = self.store.env.read_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &txn, id)?.ok_or(Error::EntityNotFound)?;
        connector_tool_setting_in_txn(&self.store, &txn, &record, tool)
    }
}
