//! One state per source; a row's readers are computed from its sources'
//! states (Fable design pass 31; READ-LINEAGE L1).
//!
//! A row's floor ([`super::floor`]) is the sources it took, stored in
//! `DERIVED`. A row also stores its **open set** ([`OPEN`]): each input it
//! was written from whose floor it has not taken yet. An entry leaves the
//! open set in one way only: the input reads bound and whole here, and the
//! row takes its floor ([`fold_waiters_in_txn`]). Everything else is read at
//! the read from the input's own facts ([`StateReader::state`]): its row, its
//! binding, its hold, its delete markers. No delete, archive, restore or
//! release door writes anything about a row that waits.
//!
//! A row's **verdict** ([`verdict_in`]) is its stored floor plus, for each
//! open entry, what the input is now: bound and whole hands over its floor;
//! not landed, held without its binding, held back, released, or waiting
//! on inputs of its own keeps the row waiting; erased by a fact other than
//! a release seals the row, the owner included (READ-LINEAGE-L3 = A). Two
//! histories that end with the same stored rows give the same verdict, so
//! the order of a sweep, a purge, a replayed tombstone, an archive or a
//! restore changes no answer.
//!
//! A link is judged once, in the write that creates it here
//! ([`judge_rows_in_txn`]): a bound input's floor joins the row's; a pending
//! one opens an entry; an erased birth input, dependency source or named
//! word source seals the row, as a fact born from an erased input is sealed
//! (#9289 review r1 P1). A later put of the same row, edge or dependency only
//! takes the floor of a bound input ([`Fresh::None`]).
//!
//! Rows a vault held before floors were written are judged once by the
//! migration ([`super::floor_migration`]); until it ends, a row it has not
//! judged is judged one level at each read, and an input erased before
//! floors leaves an old fact waiting for good (FLOOR-OLD-FACT-ERASED-INPUT =
//! A), owner-readable, until a later owner erase of that input seals it.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use self::judge::sweep_page_in_txn;
use self::reader::StateReader;
use super::floor_migration;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod erase;
mod judge;
mod reader;

pub(crate) use erase::{
    before_erase_in_store_txn, before_erase_in_txn, erase_open_entries_in_txn,
    note_shell_erased_in_txn, seal_waiters_in_txn,
};
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) use judge::forget_floor_state_in_txn;
pub(crate) use judge::{LinksBefore, fold_waiters_in_txn, judge_rows_in_txn};
pub(super) use judge::{heal_row_in_txn, id_of, judge_row_in_txn};

/// Each input whose floor a row has not taken yet: the row, then the input;
/// the value is the entry's [`OpenFlags`].
const OPEN: SideTable<(EntityId, EntityId), u8, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_OPEN);
/// The entries of [`OPEN`] by input: the input, then the row.
const OPEN_BY: SideTable<(EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_OPEN_BY);
/// Whether the migration from the wait marks has ended.
const MIGRATED: SideTable<(), bool, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_MIGRATED);
/// Each redirect shell an owner's erase of its head scrubbed
/// (SOURCE-STATE-L2 = A).
const SHELL_ERASED: SideTable<EntityId, (), Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_FLOOR_SHELL_ERASED);

/// How deep one read follows inputs that wait on inputs of their own; past
/// it an input reads pending.
const MAX_DEPTH: usize = 8;

/// Rounds one write judges its rows again, so a row written from another
/// row of the same write takes that row's floor once it is judged.
const JUDGE_ROUNDS: usize = 16;

/// Rows one fold makes whole and follows on to the rows waiting on them;
/// the sweep takes the rest.
const FOLD_CASCADE: usize = 64;

/// The level of a delete that stood before floors were written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteLevel {
    /// A soft delete: the row's body was scrubbed to its shell.
    Soft,
    /// A hard delete: the permanent `dt:` marker stands.
    Hard,
}

/// The flags of one open entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct OpenFlags(u8);

impl OpenFlags {
    const BEFORE_SOFT: u8 = 0b01;
    const BEFORE_HARD: u8 = 0b10;
    const BEFORE_MASK: u8 = 0b11;
    const ATTESTATION: u8 = 0b100;

    /// An ordinary entry: the row waits until its input is bound and whole.
    pub(crate) const ORDINARY: Self = Self(0);

    /// An old fact's entry on an input deleted before floors, at `level`:
    /// the row waits for good (FLOOR-OLD-FACT-ERASED-INPUT = A).
    pub(crate) const fn before_floors(level: DeleteLevel) -> Self {
        Self(match level {
            DeleteLevel::Soft => Self::BEFORE_SOFT,
            DeleteLevel::Hard => Self::BEFORE_HARD,
        })
    }

    /// The same entry, for a CLAIM's support.
    #[must_use]
    pub(crate) const fn attestation(self) -> Self {
        Self(self.0 | Self::ATTESTATION)
    }

    /// The level of the delete that stood before floors, for an old fact's
    /// entry.
    pub(crate) const fn before_floors_level(self) -> Option<DeleteLevel> {
        match self.0 & Self::BEFORE_MASK {
            Self::BEFORE_SOFT => Some(DeleteLevel::Soft),
            Self::BEFORE_HARD => Some(DeleteLevel::Hard),
            _ => None,
        }
    }

    /// Whether the entry is a CLAIM's support.
    pub(crate) const fn is_attestation(self) -> bool {
        self.0 & Self::ATTESTATION != 0
    }

    /// One entry two sides hold: an old fact's flag stands if either has
    /// one, at the softer level.
    #[must_use]
    pub(crate) const fn merge(self, other: Self) -> Self {
        let before = match (self.before_floors_level(), other.before_floors_level()) {
            (Some(DeleteLevel::Soft), _) | (_, Some(DeleteLevel::Soft)) => Self::BEFORE_SOFT,
            (Some(DeleteLevel::Hard), _) | (_, Some(DeleteLevel::Hard)) => Self::BEFORE_HARD,
            (None, None) => 0,
        };
        Self(before | ((self.0 | other.0) & Self::ATTESTATION))
    }

    pub(crate) const fn to_byte(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_byte(byte: u8) -> Self {
        Self(byte & (Self::BEFORE_MASK | Self::ATTESTATION))
    }
}

/// What one input of a row is now, as a floor reads it (section 1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceState {
    /// Held, live, bound and whole here: its floor.
    Bound(BTreeSet<EntityId>),
    /// Not landed, released, held without its binding, held back, or
    /// waiting on inputs of its own; `held` when its bytes are here.
    Pending { held: bool },
    /// Its own floor reads sealed.
    Sealed,
    /// Erased here by a fact other than a release.
    Erased,
}

/// Who reads a row, as its sources say (section 1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// No one, the owner included.
    Sealed,
    /// Whoever every source of the set admits.
    Whole(BTreeSet<EntityId>),
    /// A live owner who reads every source the vault holds; no one else.
    Waiting,
}

/// How a reader that reads the stored floor meets a row: whole as stored,
/// waiting (an input still open, or a floor taken at the read and not yet
/// folded into the stored one), or sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloorRead {
    Whole,
    Waiting,
    Sealed,
}

/// Which of a row's links are new in this vault, in the write that judges
/// it (section 1.5: a link is judged once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fresh {
    /// The row was first held here in this write: each of its links is new.
    Row,
    /// The links to these inputs are new; the rest were judged before.
    Links(BTreeSet<EntityId>),
    /// No link is new: a later put of the same row, edge or dependency only
    /// takes the floor of a bound input.
    None,
}

impl Fresh {
    fn covers(&self, input: &EntityId) -> bool {
        match self {
            Self::Row => true,
            Self::Links(inputs) => inputs.contains(input),
            Self::None => false,
        }
    }
}

/// A sweep cursor's first byte: the pass over the open set after the entry
/// key that follows it.
const SWEEPING: u8 = 16;

/// One run of housekeeping's `SourceFloorBackfill` sweep: from `cursor`,
/// where an unfinished run stopped, a page per write, stopping between pages
/// once `stop` says so. Until the migration has ended it runs the
/// migration's phases ([`super::floor_migration`]); then, and in each later
/// run, one pass over the open set, which folds every entry whose input is
/// bound and whole now, judges each self entry again and writes each missing
/// index pair. In a vault where no row can have a floor yet it does nothing,
/// and runs at the next pass again. What it did, and where an unfinished run
/// goes on (`None` once this run has ended).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn sweep_floors(
    vault: &Vault,
    cursor: Option<&[u8]>,
    stop: impl Fn() -> bool,
) -> Result<(u64, Option<Vec<u8>>)> {
    let mut cursor = cursor.map(<[u8]>::to_vec).unwrap_or_default();
    let mut done = 0_u64;
    loop {
        let (page, next) = vault.with_write_txn(|txn| sweep_step_in_txn(vault, txn, &cursor))?;
        done = done.saturating_add(page);
        let Some(next) = next else {
            return Ok((done, None));
        };
        cursor = next;
        if stop() {
            return Ok((done, Some(cursor)));
        }
    }
}

/// One write of [`sweep_floors`] from `cursor`.
fn sweep_step_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    cursor: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    if !migrated_in(&vault.store, txn)? {
        if !super::floor::floors_possible_in(vault, txn)? {
            return Ok((0, None));
        }
        let (page, next) = floor_migration::step_in_txn(vault, txn, cursor)?;
        return Ok((page, Some(next.unwrap_or_else(|| vec![SWEEPING]))));
    }
    let after = match cursor.split_first() {
        Some((&SWEEPING, after)) => after,
        _ => &[],
    };
    let (page, next) = sweep_page_in_txn(vault, txn, after)?;
    Ok((
        page,
        next.map(|key| [SWEEPING].into_iter().chain(key).collect()),
    ))
}

/// Whether the migration from the wait marks has ended here.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn migrated_in(store: &crate::store::Store, txn: &RoTxn<'_>) -> Result<bool> {
    Ok(MIGRATED.get(store, txn, &())?.unwrap_or(false))
}

/// Marks the migration ended.
pub(super) fn mark_migrated_in_txn(store: &crate::store::Store, txn: &mut RwTxn<'_>) -> Result<()> {
    MIGRATED.put(store, txn, &(), &true)
}

/// Whether a later owner erase reached `input`, an input deleted before
/// floors: its permanent `dt:` marker stands, or an owner's erase of its
/// head scrubbed it as a redirect shell.
fn later_owner_erase_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    input: &EntityId,
) -> Result<bool> {
    Ok(hard_marker_in(store, txn, input)? || SHELL_ERASED.contains(store, txn, input)?)
}

/// Whether the permanent `dt:` marker of `id` stands.
fn hard_marker_in(store: &crate::store::Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    crate::ports::TombstoneStoreRead::port_deletion_marked(
        store,
        txn,
        crate::ports::DeletionMarker::HardDelete,
        id,
    )
}

/// The level of the delete that erases `id` now.
pub(super) fn delete_level_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<DeleteLevel> {
    Ok(if hard_marker_in(store, txn, id)? {
        DeleteLevel::Hard
    } else {
        DeleteLevel::Soft
    })
}

/// The open entries of `row`.
pub(super) fn open_of_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    row: &EntityId,
) -> Result<Vec<(EntityId, OpenFlags)>> {
    OPEN.iter_from(store, txn, row.as_bytes())?
        .map(|entry| entry.map(|((_, input), flags)| (input, OpenFlags::from_byte(flags))))
        .collect()
}

/// Whether `row` has an open entry.
fn has_open_in(store: &crate::store::Store, txn: &RoTxn<'_>, row: &EntityId) -> Result<bool> {
    Ok(OPEN.iter_from(store, txn, row.as_bytes())?.next().is_some())
}

/// Opens, in `txn`, the entry of `row` on `input` with `flags`; an entry
/// already there keeps its flags, merged with these. Whether it is new.
pub(super) fn open_entry_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    input: &EntityId,
    flags: OpenFlags,
) -> Result<bool> {
    let key = (*row, *input);
    let (stored, new) = match OPEN.get(store, txn, &key)? {
        Some(byte) => (OpenFlags::from_byte(byte).merge(flags), false),
        None => (flags, true),
    };
    OPEN.put(store, txn, &key, &stored.to_byte())?;
    OPEN_BY.put(store, txn, &(*input, *row), &())?;
    Ok(new)
}

/// Takes, in `txn`, the entry of `row` on `input` away.
fn close_entry_in_txn(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    input: &EntityId,
) -> Result<()> {
    OPEN.delete(store, txn, &(*row, *input))?;
    OPEN_BY.delete(store, txn, &(*input, *row)).map(drop)
}

/// Whether every one of `viewers` reads a row whose verdict waits
/// ([`Verdict::Waiting`]): each is a live owner of this vault and reads every
/// source policy it holds, so no source the floor could name hides the row
/// from them. A policy that does not resolve here reads to no one, so a
/// vault holding one reads such a row to no one.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn waiting_floor_readable_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    viewers: &[EntityId],
) -> Result<bool> {
    if viewers.is_empty() {
        return Ok(false);
    }
    for viewer in viewers {
        if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, viewer)?
            && super::embedded_owner_person_in(vault, txn, *viewer)?.is_none()
        {
            return Ok(false);
        }
    }
    for entry in super::POLICIES.iter_from(&vault.store, txn, &[])? {
        let (policy, _) = entry?;
        let readers = match super::readers_in(vault, txn, &policy)? {
            None => return Ok(false),
            Some(None) => continue,
            Some(Some(readers)) => readers,
        };
        for viewer in viewers {
            if !super::names_reader_in(vault, txn, &readers, *viewer)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Each row with an open entry, once.
///
/// # Errors
///
/// Storage failures.
pub(super) fn rows_with_open_entries_in(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let mut rows = BTreeSet::new();
    for entry in OPEN.iter_from(store, txn, &[])? {
        let ((row, _), _) = entry?;
        rows.insert(row);
    }
    Ok(rows)
}

/// The verdict of `row` as `txn` holds it (section 1.4).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn verdict_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<Verdict> {
    StateReader::reader(vault, txn)?.verdict(row, None)
}

/// How a reader of the stored floor meets `row` ([`FloorRead`]): sealed
/// when its verdict is, waiting when its verdict waits or names a source the
/// stored floor does not hold yet (a bound input not folded in), else whole.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn floor_read_in(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId) -> Result<FloorRead> {
    let mut reader = StateReader::reader(vault, txn)?;
    if !reader.floors_possible {
        return Ok(FloorRead::Whole);
    }
    let raw = vault.get_raw_in(txn, row)?;
    Ok(match reader.verdict(row, raw.as_deref())? {
        Verdict::Sealed => FloorRead::Sealed,
        Verdict::Waiting => FloorRead::Waiting,
        Verdict::Whole(sources) => {
            let stored = match &raw {
                Some(raw) => super::floor::floor_in(vault, txn, row, raw)?,
                None => super::DERIVED
                    .get(&vault.store, txn, row)?
                    .unwrap_or_default(),
            };
            if sources.is_subset(&stored) {
                FloorRead::Whole
            } else {
                FloorRead::Waiting
            }
        }
    })
}
