//! A move carries its rows (DESIGN 1.5, "A move carries its rows"; stage 6.0, part 3). A project
//! reads the rows of every parent line on a key whose rows meet. When a write moves it, the lines
//! it leaves would stop narrowing what it reads, so the move would loosen it with no one's yes.
//! The door that moves it therefore writes, in the same write, one carried row on the project for
//! each such key: the meet of the rows the project read on the lines it left, and of its own
//! earlier carried row. The project's sub-projects read its line, so the carried row reaches them
//! too. A key that reads one row reads only the project's own row, so a move changes none of its
//! reads and nothing is carried for it.
//!
//! A carried row is the engine's (`Setter::Engine`), so it counts as the owner's: a holder asks
//! before it clears one, as over any row the owner set, and only the owner's clear releases it at
//! once. No caller writes one ([`super::set`] refuses a carried row with a value).

use std::collections::{BTreeMap, BTreeSet};

use oneiron_setting_contract::{ChangeDirection, RowKey};

use super::change::record_change_in_txn;
use super::read::{StoredRow, table_of};
use super::{
    EncodedValue, ScopeKind, Setter, SettingChange, SettingMode, SettingScope, SettingSpec,
    catalogue,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// After a write that moved `project`, whose lines were `lines_before`
/// ([`Vault::lines_before_move_in_txn`]): carries the rows of the lines it left onto it, in the
/// mover's write. Returns how many carried rows it wrote.
///
/// # Errors
///
/// A stored parent that is not an id; a key's `on_change` refusal; storage errors.
pub(crate) fn carry_settings_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    lines_before: &[EntityId],
) -> Result<usize> {
    let lines_after = vault.project_lines_in_txn(txn, project)?;
    carry_between_in_txn(vault, txn, project, lines_before, &lines_after)
}

/// [`carry_settings_in_txn`] over lines the caller names: `before` and `after` are the project's
/// lines either side of the move. The lines it leaves are those in `before` and not in `after`,
/// the project itself aside. For each key whose rows meet and that admits a project scope, the
/// rows at a line it left (a value row, a carried row, or the owner's pin), met per item and for
/// the item-less row with the project's own carried row, become its carried row. A row that does
/// not decode carries the key's strictest value, as a read of it would; on a key that names none
/// it is passed over.
///
/// # Errors
///
/// As [`carry_settings_in_txn`].
pub(crate) fn carry_between_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    before: &[EntityId],
    after: &[EntityId],
) -> Result<usize> {
    let left: BTreeSet<EntityId> = before
        .iter()
        .filter(|line| **line != project && !after.contains(line))
        .copied()
        .collect();
    if left.is_empty() {
        return Ok(0);
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let why = format!("carried by the move of project {}", project.to_hex());
    let mut written = 0;
    for spec in catalogue() {
        if !spec.reads_met() || !spec.scopes.contains(&ScopeKind::Project) {
            continue;
        }
        for (item, bound) in bounds_at_lines_in_txn(vault, txn, spec, &left)? {
            let key = RowKey {
                name: spec.name.to_owned(),
                item,
                mode: SettingMode::Carried,
                scope: SettingScope::Project(project),
            };
            if write_carried_in_txn(vault, txn, spec, &key, bound, now, &why)? {
                written += 1;
            }
        }
    }
    Ok(written)
}

/// The meet of `spec`'s rows at the lines `left`, per item (`None` for the item-less row).
fn bounds_at_lines_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &'static SettingSpec,
    left: &BTreeSet<EntityId>,
) -> Result<BTreeMap<Option<String>, EncodedValue>> {
    let strictest = spec.kind.strictest_value()?;
    let mut bounds: BTreeMap<Option<String>, EncodedValue> = BTreeMap::new();
    for row in table_of(spec).iter_raw_from(&vault.store, txn, &RowKey::name_prefix(spec.name))? {
        let (key, bytes) = row?;
        let Some(row_key) = RowKey::decode(&key) else {
            continue;
        };
        let SettingScope::Project(line) = row_key.scope else {
            continue;
        };
        if row_key.name != spec.name || !left.contains(&line) {
            continue;
        }
        let stored = rmp_serde::from_slice::<StoredRow>(&bytes).ok();
        // A pin no owner set decides nothing, so it carries nothing.
        if row_key.mode == SettingMode::Pin && stored.as_ref().is_some_and(|row| !row.by_owner()) {
            continue;
        }
        let value = stored
            .map(|row| row.value)
            .filter(|value| spec.kind.decodes(value))
            .or_else(|| strictest.clone());
        let Some(value) = value else {
            continue;
        };
        let met = match bounds.remove(&row_key.item) {
            Some(so_far) => spec.kind.meet(&so_far, &value).unwrap_or(so_far),
            None => value,
        };
        bounds.insert(row_key.item, met);
    }
    Ok(bounds)
}

/// Writes the carried row `key` as the meet of `bound` and the row already there, with its change
/// row and the key's `on_change`; `false` when the row already holds that value.
fn write_carried_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    key: &RowKey,
    bound: EncodedValue,
    now: u64,
    why: &str,
) -> Result<bool> {
    let table = table_of(spec);
    let key_bytes = key.encode();
    let prior = table
        .get_bytes(&vault.store, txn, &key_bytes)?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok())
        .map(|row| row.value)
        .filter(|value| spec.kind.decodes(value));
    let value = match &prior {
        Some(prior) => spec.kind.meet(prior, &bound).unwrap_or(bound),
        None => bound,
    };
    if prior.as_ref() == Some(&value) {
        return Ok(false);
    }
    let no_wider = |a: &EncodedValue, b: &EncodedValue| spec.kind.no_wider(a, b).unwrap_or(false);
    let direction = prior.as_ref().map_or(ChangeDirection::Tighter, |prior| {
        ChangeDirection::of(&value, prior, no_wider)
    });
    let setter = Setter::Engine { ask: None };
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: spec.name.to_owned(),
            item: key.item.clone(),
            scope: key.scope.clone(),
            mode: SettingMode::Carried,
            by: None,
            setter,
            prior,
            value: Some(value.clone()),
            at: now,
            why: Some(why.to_owned()),
            weight_runs: None,
            direction: Some(direction),
            surface: None,
            signed: None,
        },
    )?;
    let row = StoredRow {
        value,
        by: None,
        setter,
        set_at: now,
        change: recorded.sequence,
        weight_runs: None,
    };
    table.put(&vault.store, txn, &key_bytes, &row)?;
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(true)
}
