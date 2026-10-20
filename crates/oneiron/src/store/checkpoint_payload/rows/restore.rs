//! Putting an opened compartment's rows back, through the one restore-only
//! raw-row sink.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::super::{OWNER_LEN, Subtype, corrupt, ensure_enabled};
use super::{ACTOR_KEYED_ROW, ActorPart, Dependency, OwnerRef, RowDb, RowLocator, RowPart, frame};
use crate::error::Result;
use crate::store::ManifestDbs;

/// One owner's rows as its compartment opened, for the getter that framed
/// them: its content, the actor parts whose actors opened, and the owners
/// that did not open (retired, erased, or with no custody on this host).
#[derive(Clone, Debug)]
pub(crate) struct OpenedOwnerRows {
    pub(crate) subtype: Subtype,
    pub(crate) owner32: [u8; OWNER_LEN],
    pub(crate) occurrence_hint: Option<[u8; 16]>,
    pub(crate) rows: Vec<RowPart>,
    pub(crate) dependencies: Vec<Dependency>,
    pub(crate) actor_parts: Vec<ActorPart>,
    pub(crate) unavailable: BTreeSet<OwnerRef>,
}

impl OpenedOwnerRows {
    /// The content a getter's `bytes_for_owner` framed, opened, with the
    /// actor parts whose actors opened and the owners that did not.
    pub(crate) fn open(
        bytes: &[u8],
        actor_parts: Vec<ActorPart>,
        unavailable: BTreeSet<OwnerRef>,
    ) -> Result<Self> {
        let content = frame::read_owner(bytes)?;
        Ok(Self {
            subtype: content.subtype,
            owner32: content.owner32,
            occurrence_hint: content.occurrence_hint,
            rows: content.rows,
            dependencies: content.dependencies,
            actor_parts,
            unavailable,
        })
    }

    /// The parts an owner that did not open holds up.
    fn held_up(&self) -> BTreeSet<&RowLocator> {
        self.dependencies
            .iter()
            .filter(|dependency| self.unavailable.contains(&dependency.on))
            .map(|dependency| &dependency.at)
            .collect()
    }
}

/// What a restore of one owner's rows wrote, and what it left out.
#[derive(Debug, Default)]
pub(crate) struct Restored {
    pub(crate) written: usize,
    /// Each part left out: one an owner that did not open holds up, an
    /// actor-keyed row whose actor did not open, or a row its family's
    /// no-one rule leaves out (a pending fork whose opener stays erased).
    pub(crate) dropped: Vec<RowLocator>,
}

/// The join of a getter that splits no actor out: an opened no-one-form
/// part is not its own, so it refuses.
pub(crate) fn no_join(
    _: &RoTxn<'_>,
    _: &RowLocator,
    _: &[u8],
    _: &[&ActorPart],
) -> Result<Option<Vec<u8>>> {
    Err(corrupt())
}

/// Puts one getter's opened rows back in `txn`. Each part a dependency that
/// did not open holds up is left out; an exact part is checked by `check`
/// (the getter's own codecs) and written as it is; a no-one-form part goes
/// through `join` (its opened actor parts put back, or the family's no-one
/// rule: `None` leaves it out); an actor-keyed part writes the row its
/// opened actor part holds, or nothing. A part that fails its check refuses
/// the restore: the compartment opened, so its bytes must be whole.
pub(crate) fn restore_parts(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: &OpenedOwnerRows,
    check: impl Fn(&RowLocator, &[u8]) -> Result<()>,
    join: impl Fn(&RoTxn<'_>, &RowLocator, &[u8], &[&ActorPart]) -> Result<Option<Vec<u8>>>,
) -> Result<Restored> {
    restore_parts_keyed(dbs, txn, opened, check, |view, at, value, parts| {
        Ok(join(view, at, value, parts)?.map(|value| (at.clone(), value)))
    })
}

/// [`restore_parts`] for a getter whose join spells back a no-one-form
/// part's key as well as its value, where the key names an actor and the
/// part's locator does not (a NOTE title reservation, FIX 6075): `join`
/// answers the row's own locator and value. The row stays in its part's
/// table, its key leading with the part's, as an actor-keyed row does, and
/// goes through the same check and sink.
pub(crate) fn restore_parts_keyed(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: &OpenedOwnerRows,
    check: impl Fn(&RowLocator, &[u8]) -> Result<()>,
    join: impl Fn(
        &RoTxn<'_>,
        &RowLocator,
        &[u8],
        &[&ActorPart],
    ) -> Result<Option<(RowLocator, Vec<u8>)>>,
) -> Result<Restored> {
    ensure_enabled()?;
    let held = opened.held_up();
    let mut restored = Restored::default();
    for part in &opened.rows {
        let at = part.at();
        let actors: Vec<&ActorPart> = opened
            .actor_parts
            .iter()
            .filter(|actor| &actor.content_locator == at)
            .collect();
        let row = if held.contains(at) {
            None
        } else {
            match part {
                RowPart::Exact { value, .. } => Some((at.clone(), value.clone())),
                RowPart::NoActor { value, .. } => {
                    let view: &RoTxn<'_> = txn;
                    join(view, at, value.as_slice(), actors.as_slice())?
                        .map(|row| in_part_table(at, row))
                        .transpose()?
                }
                RowPart::ActorKeyed { .. } => actor_keyed_row(at, &actors)?,
            }
        };
        let Some((row_at, value)) = row else {
            restored.dropped.push(at.clone());
            continue;
        };
        check(&row_at, value.as_slice())?;
        restore_row_in_txn(dbs, txn, &row_at, &value)?;
        restored.written += 1;
    }
    Ok(restored)
}

/// A joined row, refused unless it stays in the table of the part it was
/// joined from: the part's database, and a key leading with the part's key.
fn in_part_table(
    at: &RowLocator,
    (row_at, value): (RowLocator, Vec<u8>),
) -> Result<(RowLocator, Vec<u8>)> {
    if row_at.db != at.db || !row_at.key.starts_with(&at.key) {
        return Err(corrupt());
    }
    Ok((row_at, value))
}

/// An actor-keyed row's own key and value, out of the actor part naming its
/// placeholder; `None` when that actor did not open.
fn actor_keyed_row(
    at: &RowLocator,
    actors: &[&ActorPart],
) -> Result<Option<(RowLocator, Vec<u8>)>> {
    let Some(part) = actors.first() else {
        return Ok(None);
    };
    if part.field != ACTOR_KEYED_ROW {
        return Err(corrupt());
    }
    let (key, value) = frame::read_row(&part.bytes)?;
    // The row stays in its placeholder's table.
    if !key.starts_with(&at.key) {
        return Err(corrupt());
    }
    Ok(Some((RowLocator::row(at.db, key), value)))
}

/// The one restore-only raw-row sink: writes `value` at `at`'s key exactly,
/// with no side-row wall, no remint and no index work. Only a restore of an
/// opened compartment's checked rows calls it, and it refuses while
/// [`super::super::CHECKPOINT_PAYLOADS_ENABLED`] is false.
pub(crate) fn restore_row_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    at: &RowLocator,
    value: &[u8],
) -> Result<()> {
    ensure_enabled()?;
    match at.db {
        RowDb::Entities => dbs.entities().put(txn, &at.key, value),
        RowDb::EdgesOut => dbs.edges_out().put(txn, &at.key, value),
        RowDb::EdgesIn => dbs.edges_in().put(txn, &at.key, value),
        RowDb::VaultMeta => dbs.vault_meta().put(txn, &at.key, value),
        RowDb::SyncState => {
            let key = std::str::from_utf8(&at.key).map_err(|_| corrupt())?;
            dbs.sync_state().put(txn, key, value)
        }
    }
}
