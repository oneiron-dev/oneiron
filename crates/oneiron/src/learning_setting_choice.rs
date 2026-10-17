//! The owner's spawn choices (ARCH-0003 #learning-settings, ARCH-0079
//! #seed-pin): a seed or pin over a spawn's model, width, pattern or budget,
//! laid at a project's goal, a project, a task type or the vault.
//!
//! A choice is its own value, never a number standing for one: a model is its
//! id, a pattern its token, a width a count of agents, a budget lease units.
//! The rows share the numeric rows' scopes, key layout, modes and owner rule
//! ([`crate::learning_setting`]) and keep their own table.
//!
//! Canon scopes a row `spawn | goal | project | vault`. The spawn layer is the
//! spawn call's own seed or pin on its `SpawnNeed`; the planner reads the
//! rows here beneath it through [`LivePlanRequest::with_owner_choices`]: any
//! pin before any seed, narrowest scope first, and a call's pin is never
//! displaced. The planner keeps learning under every choice from the
//! receipts it already reads.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{CoordinationPattern, LivePlanRequest, SpawnNeed, SpawnOverride};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning_setting::{
    SettingMode, SettingScope, check_row_terms, parse_row_key, read_scopes_in_txn, scoped_row_key,
};
use crate::llm::ModelId;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::write_envelope::WriteActor;

/// The four spawn fields an owner row may steer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpawnChoice {
    Model,
    Width,
    Pattern,
    Budget,
}

impl SpawnChoice {
    pub const ALL: [Self; 4] = [Self::Model, Self::Width, Self::Pattern, Self::Budget];

    /// The row key: canon's choice name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Width => "width",
            Self::Pattern => "pattern",
            Self::Budget => "budget",
        }
    }

    /// The choice a row key names, if it names one.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|choice| choice.as_str() == key)
    }
}

/// One choice's value, in its own type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceValue {
    Model(ModelId),
    /// Agents in the spawn, at least one.
    Width(u32),
    Pattern(CoordinationPattern),
    /// The spawn's hard spend cap in lease units, at least one. It only ever
    /// narrows the caller's budget.
    Budget(u64),
}

impl ChoiceValue {
    /// The field this value steers.
    #[must_use]
    pub const fn choice(&self) -> SpawnChoice {
        match self {
            Self::Model(_) => SpawnChoice::Model,
            Self::Width(_) => SpawnChoice::Width,
            Self::Pattern(_) => SpawnChoice::Pattern,
            Self::Budget(_) => SpawnChoice::Budget,
        }
    }
}

/// One owner seed or pin over a spawn choice. The setter is the owner who
/// writes it ([`put_choice_row`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ChoiceRow {
    pub mode: SettingMode,
    pub value: ChoiceValue,
    /// The seed's weight in runs; `None` for a pin.
    pub weight_runs: Option<f64>,
    /// Unix seconds the row was set.
    pub at: u64,
    /// The owner's own reason, kept as written.
    pub why: String,
}

/// Owner choice rows, keyed as the numeric rows are: `choice "\0" mode`, then
/// the scope.
const CHOICE: SideTable<String, StoredChoiceRow, Raw> =
    SideTable::new(&side_table::LEARNING_CHOICE);

const ROW_VERSION: u8 = 1;
const ROW_LABEL: &str = "learning choice row";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChoiceRow {
    v: u8,
    value: ChoiceValue,
    weight_runs: Option<f64>,
    by: String,
    at: u64,
    why: String,
}

impl RawValue for StoredChoiceRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| CodecError::Value(Error::InvariantViolation(ROW_LABEL)))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| CodecError::Value(Error::CorruptedIndex(ROW_LABEL)))?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(ROW_LABEL)));
        }
        Ok(row)
    }
}

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

/// Records an owner seed or pin over a spawn choice at `scope`, replacing the
/// row of the same choice, mode and scope. Only the owner may, checked in the
/// transaction that writes the row.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a width or budget of zero, a malformed type
/// reference, a pin carrying a weight or a seed without a positive one, or a
/// reason over 1 KiB; the owner-write refusal; storage errors.
pub fn put_choice_row(
    vault: &Vault,
    owner: &WriteActor,
    scope: &SettingScope,
    row: &ChoiceRow,
) -> Result<()> {
    if let SettingScope::Type(type_ref) = scope {
        type_ref.validate()?;
    }
    check_row_terms(row.mode, row.weight_runs, &row.why)?;
    match row.value {
        ChoiceValue::Width(0) => return Err(invalid("a spawn width is at least one agent")),
        ChoiceValue::Budget(0) => return Err(invalid("a spawn budget is more than zero units")),
        _ => {}
    }
    let stored = StoredChoiceRow {
        v: ROW_VERSION,
        value: row.value.clone(),
        weight_runs: row.weight_runs,
        by: owner.entity_ref().to_hex(),
        at: row.at,
        why: row.why.clone(),
    };
    let key = scoped_row_key(row.value.choice().as_str(), row.mode, scope);
    vault.with_write_txn_grouped(|wtxn| {
        vault.verify_owner_write_actor_in_txn(wtxn, owner)?;
        CHOICE.put(&vault.store, wtxn, &key, &stored)?;
        Ok(())
    })
}

/// Withdraws the owner's seed or pin over `choice` at `scope`. Clearing an
/// absent row succeeds.
///
/// # Errors
///
/// The owner-write refusal; storage errors.
pub fn clear_choice_row(
    vault: &Vault,
    owner: &WriteActor,
    scope: &SettingScope,
    choice: SpawnChoice,
    mode: SettingMode,
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        vault.verify_owner_write_actor_in_txn(wtxn, owner)?;
        CHOICE.delete(
            &vault.store,
            wtxn,
            &scoped_row_key(choice.as_str(), mode, scope),
        )?;
        Ok(())
    })
}

/// Every owner choice row as stored, in key order: its scope, the row, and
/// the owner who set it (32 hex).
///
/// # Errors
///
/// A row that does not decode; storage errors.
pub fn list_choice_rows(vault: &Vault) -> Result<Vec<(SettingScope, ChoiceRow, String)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (stored_key, stored) in CHOICE.scan(&vault.store, &rtxn)? {
        let Some((key, mode, scope)) = parse_row_key(&stored_key) else {
            continue;
        };
        if SpawnChoice::from_key(key) != Some(stored.value.choice()) {
            continue;
        }
        out.push((
            scope,
            ChoiceRow {
                mode,
                value: stored.value,
                weight_runs: stored.weight_runs,
                at: stored.at,
                why: stored.why,
            },
            stored.by,
        ));
    }
    Ok(out)
}

/// The owner's rows over `choice` a read walks, in the order it takes them:
/// every pin, narrowest scope first, then every seed.
fn rows_in_order(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    scopes: &[SettingScope],
    choice: SpawnChoice,
) -> Result<Vec<SpawnOverride<ChoiceValue>>> {
    let mut out = Vec::new();
    for mode in [SettingMode::Pin, SettingMode::Seed] {
        for scope in scopes {
            let Some(row) =
                CHOICE.get(store, txn, &scoped_row_key(choice.as_str(), mode, scope))?
            else {
                continue;
            };
            if row.value.choice() != choice {
                continue;
            }
            out.push(match (mode, row.weight_runs) {
                (SettingMode::Pin, _) => SpawnOverride::Pin { value: row.value },
                (SettingMode::Seed, Some(weight_runs)) => SpawnOverride::Seed {
                    value: row.value,
                    weight_runs,
                },
                (SettingMode::Seed, None) => continue,
            });
        }
    }
    Ok(out)
}

/// Lays the owner's choices under one spawn's need: each field takes the
/// first row in [`rows_in_order`] it admits. A field the call pinned keeps
/// the call's pin; a field the call seeded keeps its seed unless an owner
/// pin stands, since any pin outranks any seed. A model row counts only when
/// a seat serves that model, and a pinned pattern and a pinned width must
/// agree, so a row never turns a valid need into an invalid one. The pattern
/// is laid before the width.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub(crate) fn lay_owner_choices_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    scopes: &[SettingScope],
    seats: &[ModelId],
    need: &mut SpawnNeed,
) -> Result<()> {
    let width = need.pinned_width();
    lay(
        &mut need.pattern,
        rows_in_order(store, txn, scopes, SpawnChoice::Pattern)?,
        |value| match value {
            ChoiceValue::Pattern(pattern) => Some(pattern),
            _ => None,
        },
        |pattern| width.is_none_or(|width| pattern.admits_width(width)),
    );
    let pattern = need.pinned_pattern();
    lay(
        &mut need.width,
        rows_in_order(store, txn, scopes, SpawnChoice::Width)?,
        |value| match value {
            ChoiceValue::Width(width) => Some(width),
            _ => None,
        },
        |width| pattern.is_none_or(|pattern| pattern.admits_width(*width)),
    );
    lay(
        &mut need.model,
        rows_in_order(store, txn, scopes, SpawnChoice::Model)?,
        |value| match value {
            ChoiceValue::Model(model) if seats.contains(&model) => Some(model),
            _ => None,
        },
        |_| true,
    );
    lay(
        &mut need.budget_cap_units,
        rows_in_order(store, txn, scopes, SpawnChoice::Budget)?,
        |value| match value {
            ChoiceValue::Budget(units) => Some(units),
            _ => None,
        },
        |_| true,
    );
    Ok(())
}

/// Lays over `field` the first of `rows` whose value `take` reads, a pin
/// only when `admits_pin` agrees: over an unset field any row, over the
/// call's seed only a pin, over the call's pin nothing.
fn lay<T>(
    field: &mut Option<SpawnOverride<T>>,
    rows: Vec<SpawnOverride<ChoiceValue>>,
    take: impl Fn(ChoiceValue) -> Option<T>,
    admits_pin: impl Fn(&T) -> bool,
) {
    if field.as_ref().is_some_and(SpawnOverride::is_pin) {
        return;
    }
    let call_seeded = field.is_some();
    let found = rows.into_iter().find_map(|row| match row {
        SpawnOverride::Pin { value } => take(value)
            .filter(|value| admits_pin(value))
            .map(|value| SpawnOverride::Pin { value }),
        SpawnOverride::Seed { .. } if call_seeded => None,
        SpawnOverride::Seed { value, weight_runs } => {
            take(value).map(|value| SpawnOverride::Seed { value, weight_runs })
        }
    });
    if found.is_some() {
        *field = found;
    }
}

impl LivePlanRequest<'_> {
    /// This request with the owner's choices laid under its need
    /// ([`lay_owner_choices_in_txn`]), read where the parent's `project`
    /// and the need's type apply: the project's goal, the project, the type,
    /// the vault.
    ///
    /// # Errors
    ///
    /// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
    pub(crate) fn with_owner_choices(
        &self,
        vault: &Vault,
        project: Option<EntityId>,
    ) -> Result<Self> {
        let mut need = self.need.clone();
        let type_ref = crate::learning::TypeRef::from(&need.type_ref);
        let seats: Vec<ModelId> = self.seats.iter().map(|seat| seat.model.clone()).collect();
        {
            let txn = vault.store.env.read_txn()?;
            let scopes = read_scopes_in_txn(vault, &txn, project, Some(&type_ref))?;
            lay_owner_choices_in_txn(&vault.store, &txn, &scopes, &seats, &mut need)?;
        }
        Ok(Self {
            need,
            seats: self.seats,
            skills: self.skills,
            executor: self.executor,
            decisions: self.decisions,
        })
    }
}
