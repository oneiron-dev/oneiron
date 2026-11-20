//! Authenticated, exact-key edits to the owner-policy table in the default manifest.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;

use super::ceiling::OwnerRowAction;
use super::constants::{
    POLICY_OWNER_POLICY_ENABLED_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_ROW_ACTION_KEY,
    POLICY_ROW_ACTIVE_KEY, POLICY_ROW_REF_KEY, POLICY_ROW_TEXT_KEY, POLICY_ROW_WORLD_REF_KEY,
};
use super::default_policy_manifest_id;
use super::manifest_authenticity::manifest_is_trusted;
use oneiron_contracts::msgpack::Entries;

const PROJECT_REF_KEY: &str = "project_ref";

#[doc(hidden)]
pub use oneiron_verb_wire::gate::owner_policy_mutation::PolicyRowScope;

/// The allowed row actions, with the same spellings as the manifest decoder.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRowAction {
    Warn,
    Reword,
    Block,
    RouteToHelp,
}

impl PolicyRowAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Reword => "reword",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
        }
    }
}

/// Provenance of optional explanatory text. Model-authored drafts are never
/// allowed to replace an owner's own reason.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyWhySource {
    Owner,
    Drafted,
}

impl PolicyWhySource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Drafted => "drafted",
        }
    }
}

/// An exact-key edit: add refuses an occupied key, edit/remove refuse a missing key.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
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
    /// An add/edit with an explicit owner reason in the same receipt.
    AddWithWhy {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
        why: String,
    },
    EditWithWhy {
        row_ref: String,
        text: String,
        action: PolicyRowAction,
        scope: PolicyRowScope,
        why: String,
    },
    /// A model suggestion is explicitly marked and never outranks an owner reason.
    DraftWhy {
        row_ref: String,
        scope: PolicyRowScope,
        why: String,
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

/// The reason a holder who is not the vault's Owner is refused a change that
/// ends or weakens a stored withholding row's withholding
/// ([`ends_withholding`]).
const POLICY_ROW_WITHHOLDING_OWNER_ONLY_REASON: &str = "check_in.policy_row:withholding_owner_only";

fn invalid(message: &'static str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    Entries::new(entries)
        .get(key)
        .map_err(|_| invalid("duplicate policy manifest field"))
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
                    | "why"
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
        (Some(Value::String(world)), Some(Value::String(project)))
            if world.as_str().is_some_and(|s| !s.is_empty())
                && project.as_str().is_some_and(|s| !s.is_empty()) =>
        {
            PolicyRowScope::WorldProject {
                world: world.as_str().expect("checked").to_owned(),
                project: project.as_str().expect("checked").to_owned(),
            }
        }
        _ => return Err(invalid("ambiguous owner policy row scope")),
    };
    Ok((row_ref, scope))
}

/// Whether `change` ends or weakens the withholding of `row`, the stored row it
/// targets: `row` is an active Block or Reword row, read as the manifest
/// decoder reads it, and `change` removes it, or edits it to an action other
/// than Block or its own, or edits its text. Rewriting the rubric can disable
/// the row as surely as a removal (Engine ruling 21 Nov 01:29 = B). An add, a
/// why draft, an edit that keeps the text and makes the row Block or keeps its
/// action, and any change of a Warn, RouteToHelp or inactive row withdraw no
/// withholding.
fn ends_withholding(row: &Value, change: &PolicyRowChange) -> Result<bool> {
    let Value::Map(entries) = row else {
        return Err(invalid("malformed owner policy row"));
    };
    let active = match field(entries, POLICY_ROW_ACTIVE_KEY)? {
        None => true,
        Some(Value::Boolean(active)) => *active,
        Some(_) => return Err(invalid("invalid owner policy row active flag")),
    };
    let stored = match field(entries, POLICY_ROW_ACTION_KEY)? {
        None => OwnerRowAction::Warn,
        Some(action) => action
            .as_str()
            .and_then(super::decode::parse_owner_row_action)
            .ok_or_else(|| invalid("invalid owner policy row action"))?,
    };
    if !active || !matches!(stored, OwnerRowAction::Block | OwnerRowAction::Reword) {
        return Ok(false);
    }
    Ok(match change {
        PolicyRowChange::Remove { .. } => true,
        PolicyRowChange::Edit { text, action, .. }
        | PolicyRowChange::EditWithWhy { text, action, .. } => {
            let keeps_text =
                field(entries, POLICY_ROW_TEXT_KEY)?.and_then(Value::as_str) == Some(text.as_str());
            let keeps_withholding = *action == PolicyRowAction::Block
                || super::decode::parse_owner_row_action(action.as_str()) == Some(stored);
            !(keeps_text && keeps_withholding)
        }
        PolicyRowChange::Add { .. }
        | PolicyRowChange::AddWithWhy { .. }
        | PolicyRowChange::DraftWhy { .. } => false,
    })
}

fn target(change: &PolicyRowChange) -> (&str, &PolicyRowScope) {
    match change {
        PolicyRowChange::Add { row_ref, scope, .. }
        | PolicyRowChange::Edit { row_ref, scope, .. }
        | PolicyRowChange::Remove { row_ref, scope }
        | PolicyRowChange::AddWithWhy { row_ref, scope, .. }
        | PolicyRowChange::EditWithWhy { row_ref, scope, .. }
        | PolicyRowChange::DraftWhy { row_ref, scope, .. } => (row_ref, scope),
    }
}

fn validate_target(row_ref: &str, scope: &PolicyRowScope) -> Result<()> {
    if row_ref.trim().is_empty()
        || match scope {
            PolicyRowScope::Vault => false,
            PolicyRowScope::World(s) | PolicyRowScope::Project(s) => s.trim().is_empty(),
            PolicyRowScope::WorldProject { world, project } => {
                world.trim().is_empty() || project.trim().is_empty()
            }
        }
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

fn row_value(
    row_ref: &str,
    scope: &PolicyRowScope,
    text: &str,
    action: PolicyRowAction,
    why: Option<(&str, PolicyWhySource)>,
) -> Value {
    let mut entries = vec![
        (Value::from(POLICY_ROW_REF_KEY), Value::from(row_ref)),
        (Value::from(POLICY_ROW_TEXT_KEY), Value::from(text)),
        (
            Value::from(POLICY_ROW_ACTION_KEY),
            Value::from(action.as_str()),
        ),
        (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
    ];
    if let Some((text, source)) = why {
        entries.push((Value::from("why"), why_value(text, source)));
    }
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
        PolicyRowScope::WorldProject { world, project } => {
            entries.push((
                Value::from(POLICY_ROW_WORLD_REF_KEY),
                Value::from(world.as_str()),
            ));
            entries.push((Value::from(PROJECT_REF_KEY), Value::from(project.as_str())));
        }
    }
    Value::Map(entries)
}

/// The row's `why` in the shared policy-row format: `{text, source}`.
fn why_value(text: &str, source: PolicyWhySource) -> Value {
    Value::Map(vec![
        (Value::from("text"), Value::from(text)),
        (Value::from("source"), Value::from(source.as_str())),
    ])
}

fn set_why(fields: &mut Vec<(Value, Value)>, why: &str, source: PolicyWhySource) -> Result<()> {
    if why.trim().is_empty() {
        return Err(invalid("empty owner policy why"));
    }
    let existing = super::policy_values::parse_optional_why(fields)
        .ok_or_else(|| invalid("malformed owner policy why"))?;
    if source == PolicyWhySource::Drafted
        && existing.is_some_and(|why| why.source == super::policy_values::WhySource::Owner)
    {
        return Err(invalid("a draft cannot replace an owner-written why"));
    }
    set_field(fields, "why", why_value(why, source))
}

/// Mutate inside the caller's transaction, without committing or issuing a receipt.
///
/// The proof is required because the shared write door revalidates it and
/// stamps the new manifest's local origin. The caller has found the proof's
/// actor among the change's named holders in this transaction, so the proof
/// takes the person tier (the holder's grant is the authority). The caller
/// handles separate consent, audit logging, events, and notifications.
pub(crate) fn apply_owner_policy_row_change_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &mut heed::RwTxn<'_>,
    change: &PolicyRowChange,
    now: u64,
) -> Result<()> {
    let actor = owner.revalidate_person_in_txn(vault, txn)?;
    // Only an owner switches the owner-policy plane on, and only an owner ends
    // a stored row's withholding: a holder's grant names one row in one scope,
    // never the vault-wide enable flag.
    let is_owner = crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)?;
    let (row_ref, scope) = target(change);
    validate_target(row_ref, scope)?;
    let id = default_policy_manifest_id()?;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
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
    // Trust is checked against the original bytes. Normalizing a historically
    // omitted notification key uses the current shipped manifest DATA before
    // mutation, so a schema-valid owner manifest remains editable.
    let normalized =
        super::default_manifest::with_default_owner_policy_notifications(body.to_vec())?;
    let body = normalized.as_slice();
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
    // CHECK-IN-POLICY-ROW-HOLDER-NO-JUDGE (Engine ruling 21 Nov 00:30 = B): a
    // holder's change inside its named powers is its own proof and lands at
    // once, in either direction (ARCH-0082:113, DEC-0005:58), except a C act,
    // which moves only by the Owner's own row (ARCH-0082:243). On this table
    // the C act is turning a withholding control off.
    if !is_owner
        && let Some(index) = found
        && ends_withholding(&rows[index], change)?
    {
        return Err(Error::InvalidConfig(
            POLICY_ROW_WITHHOLDING_OWNER_ONLY_REASON.to_owned(),
        ));
    }
    match change {
        PolicyRowChange::Add { text, action, .. }
        | PolicyRowChange::AddWithWhy { text, action, .. } => {
            if found.is_some() {
                return Err(invalid("owner policy row already exists"));
            }
            if text.trim().is_empty() {
                return Err(invalid("empty owner policy row text"));
            }
            let why = match change {
                PolicyRowChange::AddWithWhy { why, .. } => {
                    if why.trim().is_empty() {
                        return Err(invalid("empty owner policy why"));
                    }
                    Some((why.as_str(), PolicyWhySource::Owner))
                }
                _ => None,
            };
            rows.push(row_value(row_ref, scope, text, *action, why));
        }
        PolicyRowChange::Edit { text, action, .. }
        | PolicyRowChange::EditWithWhy { text, action, .. } => {
            let index = found.ok_or_else(|| invalid("owner policy row does not exist"))?;
            if text.trim().is_empty() {
                return Err(invalid("empty owner policy row text"));
            }
            let Value::Map(fields) = &mut rows[index] else {
                unreachable!("validated row map")
            };
            // Keep owner-authored metadata such as `human` unless explicitly edited.
            set_field(fields, POLICY_ROW_TEXT_KEY, Value::from(text.as_str()))?;
            set_field(fields, POLICY_ROW_ACTION_KEY, Value::from(action.as_str()))?;
            set_field(fields, POLICY_ROW_ACTIVE_KEY, Value::Boolean(true))?;
            if let PolicyRowChange::EditWithWhy { why, .. } = change {
                set_why(fields, why, PolicyWhySource::Owner)?;
            }
        }
        PolicyRowChange::DraftWhy { why, .. } => {
            let index = found.ok_or_else(|| invalid("owner policy row does not exist"))?;
            let Value::Map(fields) = &mut rows[index] else {
                unreachable!("validated row map")
            };
            set_why(fields, why, PolicyWhySource::Drafted)?;
        }
        PolicyRowChange::Remove { .. } => {
            rows.remove(found.ok_or_else(|| invalid("owner policy row does not exist"))?);
        }
    }
    if !matches!(
        change,
        PolicyRowChange::Remove { .. } | PolicyRowChange::DraftWhy { .. }
    ) {
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
        if is_owner {
            entries[enabled_index].1 = Value::Boolean(true);
        }
    }
    let mut updated = Vec::new();
    rmpv::encode::write_value(&mut updated, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("owner policy manifest encode"))?;
    let decoded = super::decode::decode_policy_manifest(&updated)
        .ok_or_else(|| invalid("edited owner policy manifest is malformed"))?;
    if decoded.owner_policy_rows_dropped {
        return Err(invalid("edited owner policy table is malformed"));
    }
    vault.write_holder_policy_manifest_in_txn(owner, txn, id, updated, now)
}

#[cfg(test)]
mod tests;
