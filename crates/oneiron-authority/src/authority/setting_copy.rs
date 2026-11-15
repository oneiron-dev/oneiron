//! A move's carried setting rows as one engine copy (stage 7a-4; DESIGN 1.6 "A move across
//! machines"), and its wire codec.
//!
//! A project that moves keeps what it read from the lines it left as carried rows of its own
//! (DESIGN 1.5, "A move carries its settings"). The mover writes them in its own write; a
//! machine that receives the moved project by sync runs no carry. So the mover also appends one
//! copy: for each carried row, the acts that gave the project its bound there (the live heads of
//! the rows and pins on the lines it left, and the carried row's own live heads). Every machine
//! that folds it reads each carried row as the meet of the acts it names, by its own counting of
//! them.
//!
//! A copy carries no value and no owner act. It states what the mover's log held, never what
//! anyone chose: a carrier cannot invent a bound, only repeat one the log holds. So the install
//! key of the carrier signs it alone, as it signs a home candidacy (RULING SETTING-7A-4-COPY,
//! Q1 = A); the setting act ([`super::PolicySettingSet`]) stays "an act someone decided".
//!
//! The record is shape only. Each row names a carried row (mode `Carried`, a project's scope) of
//! a catalogue key's name, its target's revision as the mover's fold showed it (`seen`), and at
//! least one act, each by the row of its own entry it copies: a row of the same key and item, at
//! a project's scope. Which acts a machine holds, counts and can read, and whether the copy names
//! every head it replaces, each machine's fold and projection judge.

use std::collections::BTreeSet;

use oneiron_setting_contract::{RowKey, SettingMode, SettingScope};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_SETTING_COPY: &str = "setting_copy";
const SETTING_COPY_KEYS: [&str; 3] = [OP_KEY_KIND, "machine", "rows"];
/// The keys of each carried row a copy names.
const SETTING_COPY_ROW_KEYS: [&str; 3] = ["slot", "seen", "names"];
/// The keys of each act a row names.
const SETTING_COPY_NAME_KEYS: [&str; 2] = ["slot", "act"];

/// One move's carried rows as one copy, signed by the install key of `machine`, the mover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingCopy {
    /// The carrier: the machine whose install key signed the copy.
    pub machine: EntityId,
    /// The carried rows, at least one, no two on one target.
    pub rows: Vec<SettingCopyRow>,
}

/// One carried row of a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingCopyRow {
    /// The carried row: mode `Carried`, a project's scope.
    pub slot: RowKey,
    /// The row's target revision the mover's fold showed
    /// ([`super::policy_setting_revision`]): the copy supersedes exactly those live acts.
    pub seen: [u8; 32],
    /// The acts the row copies, at least one, none twice.
    pub names: Vec<SettingCopyName>,
}

/// One act a carried row copies, by the row of its entry it copies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SettingCopyName {
    /// The row of the named entry: of the carried row's key and item, at a project's scope.
    pub slot: RowKey,
    /// The named entry: a setting act, or an earlier copy, on that row.
    pub act: AuthorityEntryHash,
}

impl SettingCopyRow {
    /// The row's target ([`setting_slot_target`]), the frontier its setting acts name.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn target(&self) -> Result<EntityId> {
        setting_slot_target(&self.slot)
    }

    /// A carried row of a catalogue key's name, at a project's scope, naming at least one act,
    /// each once, each on a row of the same key and item at a project's scope.
    fn validate(&self) -> Result<()> {
        if !is_policy_setting_name(&self.slot.name)
            || PolicySetting::parse(&self.slot.name).is_some()
            || self.slot.mode != SettingMode::Carried
            || !matches!(self.slot.scope, SettingScope::Project(_))
            || self.names.is_empty()
        {
            return Err(invalid_authority());
        }
        let mut named = BTreeSet::new();
        for name in &self.names {
            if name.slot.name != self.slot.name
                || name.slot.item != self.slot.item
                || !matches!(name.slot.scope, SettingScope::Project(_))
                || !named.insert(name)
            {
                return Err(invalid_authority());
            }
        }
        Ok(())
    }
}

impl SettingCopy {
    /// At least one row, each well formed ([`SettingCopyRow::validate`]), no two on one target.
    pub fn validate(&self) -> Result<()> {
        if self.rows.is_empty() {
            return Err(invalid_authority());
        }
        let mut targets = BTreeSet::new();
        for row in &self.rows {
            row.validate()?;
            if !targets.insert(row.target()?) {
                return Err(invalid_authority());
            }
        }
        Ok(())
    }

    /// The copy's row on `target`; `None` when no row names it.
    ///
    /// # Errors
    /// As [`owner_act_target`].
    pub fn on_target(&self, target: EntityId) -> Result<Option<&SettingCopyRow>> {
        for row in &self.rows {
            if row.target()? == target {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }
}

pub(super) fn setting_copy_value(copy: &SettingCopy) -> Value {
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(OP_KIND_SETTING_COPY)),
        (Value::from("machine"), Value::from(copy.machine.to_hex())),
        (
            Value::from("rows"),
            Value::Array(copy.rows.iter().map(setting_copy_row_value).collect()),
        ),
    ])
}

fn setting_copy_row_value(row: &SettingCopyRow) -> Value {
    Value::Map(vec![
        (Value::from("slot"), Value::Binary(row.slot.encode())),
        (Value::from("seen"), binary_value(row.seen)),
        (
            Value::from("names"),
            Value::Array(
                row.names
                    .iter()
                    .map(|name| {
                        Value::Map(vec![
                            (Value::from("slot"), Value::Binary(name.slot.encode())),
                            (Value::from("act"), binary_value(name.act)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// A machine and a list of rows, each a canonical slot, a digest and a list of names; the op's
/// shape check then pins the rows ([`SettingCopy::validate`]).
pub(super) fn decode_setting_copy(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &SETTING_COPY_KEYS)?;
    Ok(AuthorityOp::SettingCopy(SettingCopy {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        rows: list(required(entries, "rows")?)?
            .iter()
            .map(decode_copy_row)
            .collect::<Result<_>>()?,
    }))
}

fn decode_copy_row(value: &Value) -> Result<SettingCopyRow> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SETTING_COPY_ROW_KEYS)?;
    Ok(SettingCopyRow {
        slot: super::policy_setting::decode_slot(required(entries, "slot")?)?,
        seen: decode_hash(required(entries, "seen")?)?,
        names: list(required(entries, "names")?)?
            .iter()
            .map(decode_copy_name)
            .collect::<Result<_>>()?,
    })
}

fn decode_copy_name(value: &Value) -> Result<SettingCopyName> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SETTING_COPY_NAME_KEYS)?;
    Ok(SettingCopyName {
        slot: super::policy_setting::decode_slot(required(entries, "slot")?)?,
        act: decode_hash(required(entries, "act")?)?,
    })
}

/// The items of a list value.
fn list(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(invalid_authority()),
    }
}
