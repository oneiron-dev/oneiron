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
//!
//! Across machines a move's carried rows are one copy (stage 7a-4; DESIGN 1.6 "A move across
//! machines"). A machine that receives the moved project by sync runs no carry, so in a rooted
//! vault whose install can carry, the mover also appends one `SettingCopy` entry in its write:
//! for each carried row of a key that travels, the live acts of the rows it met on the lines left
//! and of the carried row itself ([`copy_names_in_txn`]). Every machine then projects the row
//! from the copy ([`super::project`]). The mover keeps its own bound on the row
//! (`StoredRow::local`): the meet of every row it read there, acts behind them or not, so the
//! copy never loosens what it carried, and the rows no act backs (a holder's, a subject's, an
//! approved one, the engine's, one written before rooting) bound it here alone. The copy is best
//! effort: when it cannot be appended, the move stands, with its rows on this install alone.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_authority::authority::{SettingCopyName, setting_slot_target};
use oneiron_setting_contract::{ChangeDirection, RowKey};

use super::change::record_change_in_txn;
use super::project::{project_target_in_txn, rooted_in_txn, travels};
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
/// it is passed over. In a rooted vault whose install can carry, the carried rows of keys that
/// travel are then appended as one copy and projected from it (stage 7a-4, module doc).
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
    let copying = rooted_in_txn(vault, txn)? && vault.can_carry_owner_act_in_txn(txn)?;
    let mut written = 0;
    let mut copied = Vec::new();
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
            if copying && travels(spec) {
                let names = copy_names_in_txn(vault, txn, &key, &left)?;
                if !names.is_empty() {
                    copied.push((key.clone(), names));
                }
            }
            if write_carried_in_txn(vault, txn, spec, &key, bound, now, &why)? {
                written += 1;
            }
        }
    }
    if !copied.is_empty() {
        copy_carried_rows_in_txn(vault, txn, copied, now)?;
    }
    Ok(written)
}

/// The acts a copy of the carried row `key` names (stage 7a-4): the live acts of each value row,
/// pin and carried row of its key and item on the lines `left`, and of `key` itself, each by its
/// own row. A row no act names adds none: this install's own bound keeps it (`StoredRow::local`).
fn copy_names_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &RowKey,
    left: &BTreeSet<EntityId>,
) -> Result<Vec<SettingCopyName>> {
    let lines = left.iter().flat_map(|line| {
        [SettingMode::Value, SettingMode::Pin, SettingMode::Carried].map(|mode| RowKey {
            name: key.name.clone(),
            item: key.item.clone(),
            mode,
            scope: SettingScope::Project(*line),
        })
    });
    let mut names = BTreeSet::new();
    for slot in lines.chain(std::iter::once(key.clone())) {
        for act in vault.setting_slot_live_in_txn(txn, setting_slot_target(&slot)?)? {
            names.insert(SettingCopyName {
                slot: slot.clone(),
                act,
            });
        }
    }
    Ok(names.into_iter().collect())
}

/// Appends the move's copy of `rows` (stage 7a-4) and projects each row from the fold, in the
/// mover's write `txn`, at `now`. Best effort: whatever stops the append (no carrier, a frontier
/// too wide, a fold that does not count it) is logged and rolled back alone, and the carried rows
/// stand on this install, as before stage 7a-4: a move never fails for its copy.
fn copy_carried_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    rows: Vec<(RowKey, Vec<SettingCopyName>)>,
    now: u64,
) -> Result<()> {
    let targets = rows
        .iter()
        .map(|(slot, _)| setting_slot_target(slot))
        .collect::<std::result::Result<Vec<EntityId>, _>>()?;
    if let Err(error) = vault.append_setting_copy_in_txn(txn, rows) {
        tracing::warn!(
            %error,
            "a move's carried setting rows stand on this install alone: no copy of them was appended"
        );
        return Ok(());
    }
    for target in targets {
        project_target_in_txn(vault, txn, target, now)?;
    }
    Ok(())
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
/// row and the key's `on_change`, and keeps that meet as the row's own bound
/// (`StoredRow::local`, stage 7a-4); `false` when the row already holds that value, whose own
/// bound it then sets alone.
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
    let stored = table
        .get_bytes(&vault.store, txn, &key_bytes)?
        .and_then(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok());
    let prior = stored
        .as_ref()
        .map(|row| row.value.clone())
        .filter(|value| spec.kind.decodes(value));
    let value = match &prior {
        Some(prior) => spec.kind.meet(prior, &bound).unwrap_or(bound),
        None => bound,
    };
    let local = Some(value.clone());
    if prior.as_ref() == Some(&value) {
        if let Some(row) = stored
            && row.local != local
        {
            table.put(&vault.store, txn, &key_bytes, &StoredRow { local, ..row })?;
        }
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
        local,
    };
    table.put(&vault.store, txn, &key_bytes, &row)?;
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(true)
}
