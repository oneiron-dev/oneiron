//! Authenticated, exact-key edits to the owner-policy table in the default manifest.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;

use super::constants::{
    POLICY_OWNER_POLICY_ENABLED_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_ROW_ACTION_KEY,
    POLICY_ROW_ACTIVE_KEY, POLICY_ROW_REF_KEY, POLICY_ROW_TEXT_KEY, POLICY_ROW_WORLD_REF_KEY,
};
use super::default_policy_manifest_id;
use super::manifest_authenticity::manifest_is_trusted;

const PROJECT_REF_KEY: &str = "project_ref";

/// The row's exact scope. A vault row has neither scope key on disk.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PolicyRowScope {
    Vault,
    World(String),
    Project(String),
}

/// The allowed row actions, with the same spellings as the manifest decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRowAction {
    Warn,
    Block,
    RouteToHelp,
}

impl PolicyRowAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
        }
    }
}

/// An exact-key edit: add refuses an occupied key, edit/remove refuse a missing key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PolicyRowChange {
    Add {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
    },
    Edit {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
    },
    Remove {
        row_ref: String,
        scope: PolicyRowScope,
    },
}

impl PolicyRowChange {
    /// Exact row reference targeted by this change.
    #[must_use]
    pub fn row_ref(&self) -> &str {
        target(self).0
    }

    /// Exact scope targeted by this change.
    #[must_use]
    pub fn scope(&self) -> &PolicyRowScope {
        target(self).1
    }
}

fn invalid(message: &'static str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    let mut matching = entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(invalid("duplicate policy manifest field"));
    }
    Ok(first)
}

fn row_key(row: &Value) -> Result<(&str, PolicyRowScope)> {
    let Value::Map(entries) = row else {
        return Err(invalid("malformed owner policy row"));
    };
    // The decoder also checks row contents; check the keys here so that a
    // future decoder change cannot silently make an ambiguous mutation target.
    for (key, _) in entries {
        if !matches!(
            key.as_str(),
            Some(
                POLICY_ROW_REF_KEY
                    | POLICY_ROW_TEXT_KEY
                    | POLICY_ROW_ACTION_KEY
                    | POLICY_ROW_ACTIVE_KEY
                    | POLICY_ROW_WORLD_REF_KEY
                    | PROJECT_REF_KEY
                    | "human"
            )
        ) {
            return Err(invalid("malformed owner policy row"));
        }
    }
    let row_ref = field(entries, POLICY_ROW_REF_KEY)?
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid("invalid owner policy row ref"))?;
    let world = field(entries, POLICY_ROW_WORLD_REF_KEY)?;
    let project = field(entries, PROJECT_REF_KEY)?;
    let scope = match (world, project) {
        (None, None) => PolicyRowScope::Vault,
        (Some(Value::String(world)), None) if world.as_str().is_some_and(|s| !s.is_empty()) => {
            PolicyRowScope::World(world.as_str().expect("checked").to_owned())
        }
        (None, Some(Value::String(project))) if project.as_str().is_some_and(|s| !s.is_empty()) => {
            PolicyRowScope::Project(project.as_str().expect("checked").to_owned())
        }
        _ => return Err(invalid("ambiguous owner policy row scope")),
    };
    Ok((row_ref, scope))
}

fn target(change: &PolicyRowChange) -> (&str, &PolicyRowScope) {
    match change {
        PolicyRowChange::Add { row_ref, scope, .. }
        | PolicyRowChange::Edit { row_ref, scope, .. }
        | PolicyRowChange::Remove { row_ref, scope } => (row_ref, scope),
    }
}

fn validate_target(row_ref: &str, scope: &PolicyRowScope) -> Result<()> {
    if row_ref.trim().is_empty()
        || matches!(scope, PolicyRowScope::World(s) | PolicyRowScope::Project(s) if s.trim().is_empty())
    {
        return Err(invalid("empty owner policy row key"));
    }
    Ok(())
}

fn set_field(entries: &mut Vec<(Value, Value)>, key: &str, value: Value) -> Result<()> {
    let mut found = false;
    for (name, existing) in entries.iter_mut() {
        if name.as_str() == Some(key) {
            if found {
                return Err(invalid("duplicate owner policy row field"));
            }
            *existing = value.clone();
            found = true;
        }
    }
    if !found {
        entries.push((Value::from(key), value));
    }
    Ok(())
}

fn row_value(row_ref: &str, scope: &PolicyRowScope, text: &str, action: PolicyRowAction) -> Value {
    let mut entries = vec![
        (Value::from(POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(POLICY_ROW_ACTION_KEY),
            Value::from(action.as_str()),
        ),
        (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
    ];
    match scope {
        PolicyRowScope::Vault => {}
        PolicyRowScope::World(world) => {
            entries.push((
                Value::from(POLICY_ROW_WORLD_REF_KEY),
                Value::from(world.as_str()),
            ));
        }
        PolicyRowScope::Project(project) => {
            entries.push((Value::from(PROJECT_REF_KEY), Value::from(project.as_str())));
        }
    }
    Value::Map(entries)
}

/// Mutate inside the caller's transaction, without committing or issuing a receipt.
///
/// The owner proof is required because the shared write door revalidates it and
/// stamps the new manifest's local origin. The caller handles separate consent,
/// audit logging, events, and notifications.
pub(crate) fn apply_owner_policy_row_change_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &mut heed::RwTxn<'_>,
    change: &PolicyRowChange,
    now: u64,
) -> Result<()> {
    owner.revalidate_in_txn(vault, txn)?;
    let (row_ref, scope) = target(change);
    validate_target(row_ref, scope)?;
    let id = default_policy_manifest_id()?;
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("default policy manifest header"))?;
    if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
        return Err(invalid(
            "default policy manifest id belongs to another entity",
        ));
    }
    let body = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("default policy manifest body"))?;
    if !manifest_is_trusted(&vault.store, txn, &id, body)? {
        return Err(invalid("default policy manifest is not owner trusted"));
    }
    let decoded = super::decode::decode_policy_manifest(body)
        .ok_or_else(|| invalid("malformed default policy manifest"))?;
    if decoded.owner_policy_rows_dropped
        || decoded.unsupported_schema
        || decoded.engine_version_floor
    {
        return Err(invalid(
            "invalid default policy manifest owner policy table",
        ));
    }
    let mut cursor = Cursor::new(body);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("default policy manifest body"))?
    else {
        return Err(invalid("default policy manifest is not a map"));
    };
    if cursor.position() != body.len() as u64 {
        return Err(invalid("trailing default policy manifest bytes"));
    }
    let table_index = entries
        .iter()
        .position(|(key, _)| key.as_str() == Some(POLICY_OWNER_POLICY_ROWS_KEY))
        .ok_or_else(|| invalid("default policy manifest has no owner policy table"))?;
    if entries
        .iter()
        .skip(table_index + 1)
        .any(|(key, _)| key.as_str() == Some(POLICY_OWNER_POLICY_ROWS_KEY))
    {
        return Err(invalid("duplicate owner policy table"));
    }
    let Value::Array(rows) = &mut entries[table_index].1 else {
        return Err(invalid("malformed owner policy table"));
    };
    let mut found = None;
    let mut seen = std::collections::HashSet::new();
    for (index, row) in rows.iter().enumerate() {
        let (key, row_scope) = row_key(row)?;
        if !seen.insert((key.to_owned(), row_scope.clone())) {
            return Err(invalid("duplicate owner policy row key"));
        }
        if key == row_ref && &row_scope == scope {
            found = Some(index);
        }
    }
    match change {
        PolicyRowChange::Add { text, action, .. } => {
            if found.is_some() {
                return Err(invalid("owner policy row already exists"));
            }
            if text.trim().is_empty() {
                return Err(invalid("empty owner policy row text"));
            }
            rows.push(row_value(row_ref, scope, text, *action));
        }
        PolicyRowChange::Edit { text, action, .. } => {
            let index = found.ok_or_else(|| invalid("owner policy row does not exist"))?;
            if text.trim().is_empty() {
                return Err(invalid("empty owner policy row text"));
            }
            let Value::Map(fields) = &mut rows[index] else {
                unreachable!("validated row map")
            };
            // Keep owner-authored metadata such as `human`; only edit the
            // requested content and reactivate the row.
            set_field(fields, POLICY_ROW_TEXT_KEY, Value::from(text.as_str()))?;
            set_field(fields, POLICY_ROW_ACTION_KEY, Value::from(action.as_str()))?;
            set_field(fields, POLICY_ROW_ACTIVE_KEY, Value::Boolean(true))?;
        }
        PolicyRowChange::Remove { .. } => {
            rows.remove(found.ok_or_else(|| invalid("owner policy row does not exist"))?);
        }
    }
    if !matches!(change, PolicyRowChange::Remove { .. }) {
        let enabled_index = entries
            .iter()
            .position(|(key, _)| key.as_str() == Some(POLICY_OWNER_POLICY_ENABLED_KEY))
            .ok_or_else(|| invalid("default policy manifest has no enabled flag"))?;
        if entries
            .iter()
            .skip(enabled_index + 1)
            .any(|(key, _)| key.as_str() == Some(POLICY_OWNER_POLICY_ENABLED_KEY))
        {
            return Err(invalid("duplicate owner policy enabled flag"));
        }
        if !matches!(entries[enabled_index].1, Value::Boolean(_)) {
            return Err(invalid("malformed owner policy enabled flag"));
        }
        entries[enabled_index].1 = Value::Boolean(true);
    }
    let mut updated = Vec::new();
    rmpv::encode::write_value(&mut updated, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("owner policy manifest encode"))?;
    let decoded = super::decode::decode_policy_manifest(&updated)
        .ok_or_else(|| invalid("edited owner policy manifest is malformed"))?;
    if decoded.owner_policy_rows_dropped {
        return Err(invalid("edited owner policy table is malformed"));
    }
    vault.write_owner_policy_manifest_in_txn(owner, txn, id, updated, now)
}

#[cfg(test)]
mod tests;
