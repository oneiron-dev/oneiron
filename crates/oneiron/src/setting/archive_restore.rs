//! The owner's archive restore over the Setting primitive's tables (OF-222): the value and pin
//! rows of `SETTING` and `SETTING_CONTENT`, the change history and its counter.
//!
//! A row lands through the checks its key's catalogue row names, never through the set door. The
//! owner's restore permit is the power, and who set a row is not judged again, because every
//! read already holds that line (`oneiron_setting_contract::decide`): only an owner pin decides,
//! and a holder's row on a key with a tighter direction is read inside the owner's nearest row
//! or the catalogue default. So a validated row installs as stored, with its setter, its time
//! and its revision: an absent row installs, equal bytes are unchanged, a different live row is
//! kept.
//!
//! A key's change hook is its own check on this vault's state and the start of its effect (a
//! seat ref that is never installed twice, a route the manifest in force admits, a feed's poll
//! chain). An absent row of such a key installs through the hook, as a change with no prior,
//! inside a savepoint: a refusal rolls the row back and its envelope stays retained. The effect
//! starts from now and catches nothing up (ARCHIVE-RESTORE-LIVE = B). Before its writer opens,
//! the restore takes the write turn of each key the archive holds a source-live row of
//! ([`take_write_turns`]), so no hooked row lands inside another holder's run, as no set of that
//! key does.
//!
//! The change history installs at absent sequences, and the counter never goes back: it ends at
//! the highest of the live counter, the archived counter, every landed change's sequence and
//! every landed row's revision, so a row's revision still only grows and no sequence is handed
//! out twice.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_setting_contract::RowKey;

use super::change::{CHANGE_NEXT, CHANGES, SettingChange};
use super::read::{CONTENT_ROWS, ROWS, StoredRow, table_of};
use super::{OnChange, OnCommitted, SettingMode, SettingSpec, WriteTurn, spec_named};
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Named, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// One of the two tables that hold value and pin rows.
type RowTable = SideTable<Vec<u8>, StoredRow, Named>;

/// One archived value or pin row that passed its key's checks.
struct CheckedRow {
    spec: &'static SettingSpec,
    key: RowKey,
    key_bytes: Vec<u8>,
    stored: StoredRow,
}

/// One checked row of a key with a change hook, absent on this vault: it installs through the hook.
struct HookedRow {
    /// Its place in the lander's input.
    at: usize,
    table: RowTable,
    checked: CheckedRow,
    on_change: OnChange,
}

/// What the landed rows ask of the counter and of the hosts that read their keys.
struct Landed<'a> {
    /// The highest sequence a landed change holds or a landed row names as its revision.
    highest_sequence: u64,
    /// The keys whose wake is already queued.
    woken: BTreeSet<&'static str>,
    /// The wakes to run once the import has committed.
    wakes: &'a mut Vec<OnCommitted>,
}

impl Landed<'_> {
    /// Notes one value or pin row's outcome: a row that is live with the archive's bytes names
    /// its revision, and an installed row wakes the hosts that read its key, once per key.
    fn note_row(&mut self, checked: &CheckedRow, outcome: &ArchivedSideRowOutcome) {
        use ArchivedSideRowOutcome::{Installed, Unchanged};
        if matches!(outcome, Installed | Unchanged) {
            self.highest_sequence = self.highest_sequence.max(checked.stored.change);
        }
        if matches!(outcome, Installed)
            && let Some(after_commit) = checked.spec.after_commit
            && self.woken.insert(checked.spec.name)
        {
            self.wakes.push(after_commit);
        }
    }
}

/// Lands the owner's archived setting envelopes, one outcome per row in input order. Rows of a
/// key with a change hook land after the others, in key order, and are tried again while any of
/// them lands, so keys whose hooks read each other (a floor and its count) do not depend on the
/// archive's order. `wakes` receives the after-commit wake of each key with an installed row;
/// the caller runs them once the import has committed.
///
/// # Errors
///
/// Storage errors. A row that fails a check is an outcome, never an error.
pub(crate) fn land_archived_setting_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
    wakes: &mut Vec<OnCommitted>,
) -> Result<Vec<ArchivedSideRowOutcome>> {
    use ArchivedSideRowOutcome::HeldBack;
    use RetainedSideHeldBackReason::InvalidEncoding;

    let mut outcomes: Vec<Option<ArchivedSideRowOutcome>> = Vec::new();
    outcomes.resize_with(rows.len(), || None);
    let mut hooked: Vec<HookedRow> = Vec::new();
    let mut archived_counters: Vec<(usize, u64)> = Vec::new();
    let mut landed = Landed {
        highest_sequence: 0,
        woken: BTreeSet::new(),
        wakes,
    };

    for (at, row) in rows.iter().enumerate() {
        let table = match row.source_table.as_str() {
            name if name == side_table::SETTING.name => ROWS,
            name if name == side_table::SETTING_CONTENT.name => CONTENT_ROWS,
            name if name == side_table::SETTING_CHANGE.name => {
                outcomes[at] = Some(land_change_in_txn(vault, txn, permit, row, &mut landed)?);
                continue;
            }
            name if name == side_table::SETTING_CHANGE_NEXT.name => {
                match decode_archived_row(&CHANGE_NEXT, row) {
                    Ok(((), archived)) => archived_counters.push((at, archived)),
                    Err(reason) => outcomes[at] = Some(HeldBack(reason)),
                }
                continue;
            }
            // The dispatcher never sends a foreign envelope here; without an owning table the
            // envelope has no decoding.
            _ => {
                outcomes[at] = Some(HeldBack(InvalidEncoding));
                continue;
            }
        };
        let checked = match check_row_in_txn(vault, txn, &table, row)? {
            Ok(checked) => checked,
            Err(reason) => {
                outcomes[at] = Some(HeldBack(reason));
                continue;
            }
        };
        // Only an absent row passes its key's hook: a live row is compared, never replaced.
        if let Some(on_change) = checked.spec.on_change
            && table.get_bytes(vault, txn, &checked.key_bytes)?.is_none()
        {
            hooked.push(HookedRow {
                at,
                table,
                checked,
                on_change,
            });
            continue;
        }
        let outcome = install_archived_row(&table, vault, txn, permit, &checked.key_bytes, row)?;
        landed.note_row(&checked, &outcome);
        outcomes[at] = Some(outcome);
    }

    land_hooked_rows_in_txn(vault, txn, permit, rows, hooked, &mut landed, &mut outcomes)?;
    settle_counter_in_txn(
        vault,
        txn,
        &archived_counters,
        landed.highest_sequence,
        &mut outcomes,
    )?;
    outcomes
        .into_iter()
        .map(|outcome| {
            outcome.ok_or(Error::InvariantViolation(
                "every archived setting envelope takes an outcome",
            ))
        })
        .collect()
}

/// The write turn of the key an archived envelope holds a row of, when the owner's restore may
/// land that row: a source-live value or pin row of a key that names a turn. Read before the
/// restore's writer opens, so it checks only what can name the key; a row that names a key but
/// fails a later check takes a turn it never needed, never the other way round.
pub(crate) fn write_turn_of_archived_row(row: &ArchiveRetainedSideRow) -> Option<WriteTurn> {
    if !row.source_live {
        return None;
    }
    let key_bytes = match row.source_table.as_str() {
        name if name == side_table::SETTING.name => decode_archived_row(&ROWS, row).ok()?.0,
        name if name == side_table::SETTING_CONTENT.name => {
            decode_archived_row(&CONTENT_ROWS, row).ok()?.0
        }
        _ => return None,
    };
    spec_named(&RowKey::decode(&key_bytes)?.name)
        .ok()?
        .write_turn
}

/// Takes `turns`, each once and in name order, for the owner's restore to hold from before its
/// writer opens until the wakes after its commit are done, as [`Vault::set_setting`] holds one
/// key's. The caller names the turns of the keys its archive holds rows of
/// ([`write_turn_of_archived_row`]): the restore can install an absent row of such a key through
/// its hook, and which rows land is known only inside its writer. A restore whose archive holds no
/// row of a key with a turn takes none, so it waits on no admission and is refused by none
/// (REVIEW-9493 round 2).
///
/// # Errors
///
/// A turn's refusal: the calendar admission turn refuses a thread that already holds it.
pub(crate) fn take_write_turns(
    vault: &Vault,
    turns: impl IntoIterator<Item = WriteTurn>,
) -> Result<Vec<Box<dyn std::any::Any>>> {
    let turns: BTreeMap<&str, WriteTurn> =
        turns.into_iter().map(|turn| (turn.name, turn)).collect();
    turns.values().map(|turn| (turn.take)(vault)).collect()
}

/// Lands the absent rows of keys with a change hook, in key order, and tries the refused ones
/// again while any of them lands. A row its hook still refuses is held back.
fn land_hooked_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
    mut hooked: Vec<HookedRow>,
    landed: &mut Landed<'_>,
    outcomes: &mut [Option<ArchivedSideRowOutcome>],
) -> Result<()> {
    hooked.sort_by(|left, right| left.checked.key_bytes.cmp(&right.checked.key_bytes));
    loop {
        let mut any_landed = false;
        let mut refused = Vec::new();
        for row in hooked {
            match install_through_hook_in_txn(vault, txn, permit, &row, &rows[row.at])? {
                Some(outcome) => {
                    any_landed |= matches!(outcome, ArchivedSideRowOutcome::Installed);
                    landed.note_row(&row.checked, &outcome);
                    outcomes[row.at] = Some(outcome);
                }
                None => refused.push(row),
            }
        }
        hooked = refused;
        if !any_landed || hooked.is_empty() {
            break;
        }
    }
    for row in hooked {
        outcomes[row.at] = Some(ArchivedSideRowOutcome::HeldBack(
            RetainedSideHeldBackReason::InvalidValue,
        ));
    }
    Ok(())
}

/// Raises the change counter to the highest of the live counter, the archived counters and
/// `highest_sequence`, and gives each archived counter its outcome: equal to the live one is
/// unchanged, below it the live one is kept, and otherwise the counter now covers it.
fn settle_counter_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    archived_counters: &[(usize, u64)],
    highest_sequence: u64,
    outcomes: &mut [Option<ArchivedSideRowOutcome>],
) -> Result<()> {
    use ArchivedSideRowOutcome::{Installed, KeptLive, Unchanged};
    let live_counter = CHANGE_NEXT.get(&vault.store, txn, &())?;
    let highest_archived_counter = archived_counters
        .iter()
        .map(|(_, archived)| *archived)
        .max()
        .unwrap_or(0);
    let counter = live_counter
        .unwrap_or(0)
        .max(highest_sequence)
        .max(highest_archived_counter);
    if counter > 0 && live_counter != Some(counter) {
        CHANGE_NEXT.put(&vault.store, txn, &(), &counter)?;
    }
    for (at, archived) in archived_counters {
        outcomes[*at] = Some(match live_counter {
            Some(live) if live == *archived => Unchanged,
            Some(live) if live > *archived => KeptLive,
            _ => Installed,
        });
    }
    Ok(())
}

/// The checks of one archived value or pin row, in the order the set door makes them: the key
/// bytes name a row key; the key is in the catalogue and its rows live in `table`; the item and
/// the scope kind are ones it admits; a learned seed carries its weight and no other row does;
/// the value passes the key's own check, through its JSON form and back; the entity the scope
/// names is live here.
fn check_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    table: &RowTable,
    row: &ArchiveRetainedSideRow,
) -> Result<std::result::Result<CheckedRow, RetainedSideHeldBackReason>> {
    use RetainedSideHeldBackReason::{InvalidEncoding, InvalidValue, MissingLiveEntity};
    let (key_bytes, stored) = match decode_archived_row(table, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(Err(reason)),
    };
    let Some(key) = RowKey::decode(&key_bytes).filter(|key| key.encode() == key_bytes) else {
        return Ok(Err(InvalidEncoding));
    };
    let Ok(spec) = spec_named(&key.name) else {
        return Ok(Err(InvalidValue));
    };
    let admitted = table_of(spec).decl().name == table.decl().name
        && spec.check_item(key.item.as_deref()).is_ok()
        && spec.admits_scope(key.scope.kind())
        && seed_weight_stands(spec, key.mode, stored.weight_runs)
        && spec
            .kind
            .to_json(&stored.value)
            .is_some_and(|json| spec.kind.from_json(json).is_ok());
    if !admitted {
        return Ok(Err(InvalidValue));
    }
    if let Some(entity) = key.scope.entity()
        && !matches!(
            live_entity_row_in_txn(&vault.store, txn, &entity)?,
            LiveEntityRow::Live { .. }
        )
    {
        return Ok(Err(MissingLiveEntity));
    }
    Ok(Ok(CheckedRow {
        spec,
        key,
        key_bytes,
        stored,
    }))
}

/// Whether a stored row carries the weight its key and mode ask for: a learned key's value row
/// is a seed and names a finite weight above zero; no other row names one (the set door's
/// `checked_weight`).
fn seed_weight_stands(spec: &SettingSpec, mode: SettingMode, weight_runs: Option<f64>) -> bool {
    match (spec.is_learned() && mode == SettingMode::Value, weight_runs) {
        (true, Some(weight)) => weight.is_finite() && weight > 0.0,
        (false, None) => true,
        _ => false,
    }
}

/// Installs an absent row of a key with a change hook: the row as stored, then the hook over a
/// change with no prior, both inside a savepoint. The row keeps its archived set time; the hook's
/// change is stamped with this restore's time, so an effect the hook starts restarts from now
/// (ARCHIVE-RESTORE-LIVE = B). `None` when the hook refused: the savepoint rolled back the row
/// and whatever the hook wrote before it refused, and the caller may try the row again after
/// other rows have landed.
fn install_through_hook_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    hooked: &HookedRow,
    row: &ArchiveRetainedSideRow,
) -> Result<Option<ArchivedSideRowOutcome>> {
    let checked = &hooked.checked;
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match hooked.table.put_archived_as_stored_in_txn(
        vault,
        &mut savepoint,
        permit,
        &checked.key_bytes,
        &row.source_value,
    ) {
        Ok(()) => {}
        Err(Error::Store(StoreError::SideTableRow { .. })) => {
            savepoint.abort();
            return Ok(Some(ArchivedSideRowOutcome::HeldBack(
                RetainedSideHeldBackReason::InvalidEncoding,
            )));
        }
        Err(error) => return Err(error),
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, &mut savepoint)?;
    let change = SettingChange {
        id: vault.store.clock.entity_id()?,
        sequence: checked.stored.change,
        key: checked.spec.name.to_owned(),
        item: checked.key.item.clone(),
        scope: checked.key.scope.clone(),
        mode: checked.key.mode,
        by: checked.stored.by,
        setter: checked.stored.setter,
        prior: None,
        value: Some(checked.stored.value.clone()),
        at: now,
        why: None,
        weight_runs: checked.stored.weight_runs,
        // The owner's archived row comes back as it was: no move the rule judges (DESIGN 1.5).
        direction: None,
        surface: None,
        signed: None,
        with: Vec::new(),
        standing: None,
    };
    if (hooked.on_change)(vault, &mut savepoint, &change).is_err() {
        savepoint.abort();
        return Ok(None);
    }
    savepoint.commit()?;
    Ok(Some(ArchivedSideRowOutcome::Installed))
}

/// Lands one archived change: its key is its own sequence, and it installs at an absent
/// sequence. Whichever change is live at that sequence afterwards, the counter covers it.
fn land_change_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
    landed: &mut Landed<'_>,
) -> Result<ArchivedSideRowOutcome> {
    use ArchivedSideRowOutcome::HeldBack;
    let (sequence, change) = match decode_archived_row(&CHANGES, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(HeldBack(reason)),
    };
    if sequence == 0 || change.sequence != sequence {
        return Ok(HeldBack(RetainedSideHeldBackReason::InvalidValue));
    }
    let outcome = install_archived_row(&CHANGES, vault, txn, permit, &sequence, row)?;
    if !matches!(outcome, HeldBack(_)) {
        landed.highest_sequence = landed.highest_sequence.max(sequence);
    }
    Ok(outcome)
}
