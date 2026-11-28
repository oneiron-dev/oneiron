//! The writes of a floor (Fable design pass 31, section 1.5): a link judged
//! once, in the write that creates it; the fold of the rows that waited on
//! an input that is bound and whole now; the sweep over the open set.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use super::reader::{LinkKind, Links, StateReader, took_floor_of_in, word_sources_now_in};
use super::{
    FOLD_CASCADE, Fresh, JUDGE_ROUNDS, OPEN, OPEN_BY, OpenFlags, SourceState, close_entry_in_txn,
    delete_level_in, has_open_in, migrated_in, open_entry_in_txn, open_of_in,
};
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
use super::{MIGRATED, SHELL_ERASED};
use crate::error::Result;
use crate::source_audience::floor::OwnSource;
use crate::source_audience::floor_migration;
use crate::{EntityId, Vault};

/// What one write does for one link of a row it judges.
enum Act {
    /// The input's floor joins the row's.
    Take(BTreeSet<EntityId>),
    /// The row waits on the input.
    Open(OpenFlags),
    /// The row is born sealed.
    Seal,
    /// The row's lineage does not resolve yet: it waits on itself.
    OpenSelf,
    /// A free support frees the row: every open support of it goes.
    Free,
}

/// What `fresh` and the row's own state say each link of the held row
/// `row` gets (section 1.5). `old` when the row was not judged here yet: each
/// link is judged as an old fact's (section 5, M2).
fn judge_acts_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
    fresh: &Fresh,
    old: bool,
) -> Result<Vec<(EntityId, Act)>> {
    let mut reader = StateReader::reader(vault, txn)?;
    let links = Links::of(vault, txn, row, raw)?;
    // A row a source landed reads under its own binding; it waits on
    // nothing it names.
    let landed = crate::source_audience::obligation::row_obligation(raw).is_present();
    let mut acts = Vec::new();
    if links.unresolved && !landed {
        acts.push((*row, Act::OpenSelf));
    }
    let supports: Vec<EntityId> = links.supports().copied().collect();
    let freed = reader.frees_any(&supports)?;
    if freed {
        acts.push((*row, Act::Free));
    }
    let mut floor = crate::source_audience::floor::floor_in(vault, txn, row, raw)?;
    for (input, kind) in &links.links {
        if *kind == LinkKind::Attestation && freed {
            continue;
        }
        let new = fresh.covers(input);
        let judged_now = new || old;
        let flags = if *kind == LinkKind::Attestation {
            OpenFlags::ORDINARY.attestation()
        } else {
            OpenFlags::ORDINARY
        };
        match reader.state(input)? {
            SourceState::Bound(add) => {
                floor.extend(add.iter().copied());
                acts.push((*input, Act::Take(add)));
            }
            SourceState::Pending { held } => {
                if judged_now && !landed && (held || *kind == LinkKind::Unwalked) {
                    acts.push((*input, Act::Open(flags)));
                }
            }
            SourceState::Sealed => {
                if judged_now && !landed {
                    acts.push((*input, Act::Open(flags)));
                }
            }
            SourceState::Erased => {
                if !judged_now || landed || *kind != LinkKind::Unwalked {
                    continue;
                }
                if new {
                    acts.push((*input, Act::Seal));
                } else if !took_floor_of_in(vault, txn, input, &floor)? {
                    acts.push((
                        *input,
                        Act::Open(OpenFlags::before_floors(delete_level_in(
                            vault, txn, input,
                        )?)),
                    ));
                }
            }
        }
    }
    Ok(acts)
}

/// Judges the links of each of `rows` in `txn`, the write that gave them
/// words or a source (section 1.5), then folds the rows that waited on
/// each: a row the same write wrote from another row of it takes that
/// row's floor once that row is judged, so the write judges its rows again
/// until no floor or open set grows. A vault where no row can have a floor
/// judges nothing ([`crate::source_audience::floor::floors_possible_in`]); its rows are
/// judged by the migration once one can.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn judge_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    rows: Vec<(EntityId, Fresh)>,
) -> Result<()> {
    if rows.is_empty() || !crate::source_audience::floor::floors_possible_in(vault, txn)? {
        return Ok(());
    }
    let mut merged: BTreeMap<EntityId, Fresh> = BTreeMap::new();
    for (row, fresh) in rows {
        let joined = match (merged.remove(&row), fresh) {
            (None, fresh) => fresh,
            (Some(Fresh::Row), _) | (_, Fresh::Row) => Fresh::Row,
            (Some(Fresh::None), fresh) | (Some(fresh), Fresh::None) => fresh,
            (Some(Fresh::Links(mut held)), Fresh::Links(more)) => {
                held.extend(more);
                Fresh::Links(held)
            }
        };
        merged.insert(row, joined);
    }
    let migrating = !migrated_in(vault, txn)?;
    let mut old: BTreeSet<EntityId> = BTreeSet::new();
    if migrating && !floor_migration::old_backfill_done_in(vault, txn)? {
        for row in merged.keys() {
            if !floor_migration::raised_in(vault, txn, row)? {
                old.insert(*row);
            }
        }
    }
    for _ in 0..JUDGE_ROUNDS {
        let mut grew = false;
        for (row, fresh) in &merged {
            grew |= judge_row_in_txn(vault, txn, row, fresh, old.contains(row))?;
        }
        if !grew {
            break;
        }
    }
    if migrating {
        for row in merged.keys() {
            floor_migration::mark_judged_in_txn(vault, txn, row)?;
        }
    }
    for row in merged.keys() {
        fold_waiters_in_txn(vault, txn, row)?;
    }
    Ok(())
}

/// The links each row of one write held before it (section 1.5: a link is
/// judged once, in the write that creates it here), so the judgement after
/// the write judges in full only the links the write created: every link of
/// a row this vault did not hold (or held erased), and each link a held row
/// did not have. Read before the write, judged after it
/// ([`Self::judge_in_txn`]).
pub(crate) struct LinksBefore {
    rows: Vec<(EntityId, Before)>,
}

/// What one row held before a write.
enum Before {
    /// Not held here, or held erased: every link it has after is new.
    NotHeld,
    /// Held, with these links.
    Held(BTreeSet<EntityId>),
    /// Held while no row here could have a floor: its links were never
    /// judged, and the migration judges them as an old fact's.
    Unread,
}

impl LinksBefore {
    /// The links each of `rows` holds in `txn`, before the write.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn read_in(
        vault: &Vault,
        txn: &RoTxn<'_>,
        rows: impl IntoIterator<Item = EntityId>,
    ) -> Result<Self> {
        let floors_possible = crate::source_audience::floor::floors_possible_in(vault, txn)?;
        let mut held = Vec::new();
        let mut seen = BTreeSet::new();
        for row in rows {
            if !seen.insert(row) {
                continue;
            }
            let before = match vault.get_raw_in(txn, &row)? {
                Some(_) if crate::ports::erased_in_txn(&vault.store, txn, &row)? => Before::NotHeld,
                Some(_) if !floors_possible => Before::Unread,
                Some(raw) => Before::Held(Links::of(vault, txn, &row, &raw)?.inputs()),
                None => Before::NotHeld,
            };
            held.push((row, before));
        }
        Ok(Self { rows: held })
    }

    /// Judges, in `txn`, the write's rows: each link the write created in
    /// full, each other link only by the floor of a bound input.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn judge_in_txn(self, vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
        if self.rows.is_empty() || !crate::source_audience::floor::floors_possible_in(vault, txn)? {
            return Ok(());
        }
        let mut rows = Vec::with_capacity(self.rows.len());
        for (row, before) in self.rows {
            let fresh = match before {
                Before::NotHeld => Fresh::Row,
                Before::Unread => Fresh::None,
                Before::Held(held) => match vault.get_raw_in(txn, &row)? {
                    Some(raw) => Fresh::Links(
                        Links::of(vault, txn, &row, &raw)?
                            .inputs()
                            .difference(&held)
                            .copied()
                            .collect(),
                    ),
                    None => Fresh::None,
                },
            };
            rows.push((row, fresh));
        }
        judge_rows_in_txn(vault, txn, rows)
    }
}

/// Judges the links of the row `row` once: whether its floor or its open
/// set grew. `old` judges every link as an old fact's (section 5, M2).
pub(in crate::source_audience) fn judge_row_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    fresh: &Fresh,
    old: bool,
) -> Result<bool> {
    if crate::ports::erased_in_txn(&vault.store, txn, row)? {
        return Ok(false);
    }
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(false);
    };
    let acts = judge_acts_in(vault, txn, row, &raw, fresh, old)?;
    let mut grew = false;
    for (input, act) in acts {
        grew |= match act {
            Act::Take(floor) => take_floor_in_txn(vault, txn, row, &raw, &floor)?,
            Act::Open(flags) => open_entry_in_txn(vault, txn, row, &input, flags)?,
            Act::OpenSelf => open_entry_in_txn(vault, txn, row, row, OpenFlags::ORDINARY)?,
            Act::Seal => crate::source_audience::add_derived_policies_in_txn(
                vault,
                txn,
                row,
                &BTreeSet::from([crate::source_audience::floor::sealed_source()]),
            )?,
            Act::Free => {
                free_attestations_in_txn(vault, txn, row)?;
                false
            }
        };
    }
    Ok(grew)
}

/// Adds `floor`, an input's, to the stored floor of `row` (bytes `raw`):
/// whether it grew. The row's own source is read from its bytes, so it is
/// not stored; a live row born under no source (a peer's phone mark that
/// names no thread) stores the seal, as its own write would (#9289 review 2
/// P2-5).
fn take_floor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    raw: &[u8],
    floor: &BTreeSet<EntityId>,
) -> Result<bool> {
    let mut add = floor.clone();
    match crate::source_audience::floor::own_source_in(vault, txn, row, raw)? {
        // An archived row is held, not an erased shell: it keeps the seal
        // (#10265 Opus review 3 P2-1).
        OwnSource::Source(own) if own == crate::source_audience::floor::sealed_source() => {
            if !crate::ports::removed_in_txn(&vault.store, &**txn, row)? {
                add.insert(own);
            }
        }
        OwnSource::Source(own) => {
            add.remove(&own);
        }
        OwnSource::None | OwnSource::Unbound => {}
    }
    if add.is_empty() {
        return Ok(false);
    }
    crate::source_audience::add_derived_policies_in_txn(vault, txn, row, &add)
}

/// Takes every open support of `row` away: a free support frees it
/// (pass 30's "one free attestation frees").
fn free_attestations_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<()> {
    for (input, flags) in open_of_in(vault, txn, row)? {
        if flags.is_attestation() && flags.before_floors_level().is_none() {
            close_entry_in_txn(&vault.store, txn, row, &input)?;
        }
    }
    Ok(())
}

/// Folds, in `txn`, the rows waiting on `input` (section 1.5): when `input`
/// reads bound and whole now, each row with an ordinary entry on it takes
/// its floor and the entry goes; a free support frees its row. A row this
/// leaves with no entry is whole, and the rows waiting on it fold in turn,
/// up to [`FOLD_CASCADE`] rows; the sweep folds the rest. It never seals,
/// never drops an entry for another reason, and leaves an old fact's entry
/// alone, so it is safe to call from anywhere, and a call missed fails
/// closed.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn fold_waiters_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    input: &EntityId,
) -> Result<()> {
    let mut queue = vec![*input];
    let mut followed = 0_usize;
    while let Some(input) = queue.pop() {
        let waiters: Vec<EntityId> = OPEN_BY
            .scan_keys(&vault.store, txn, input.as_bytes())?
            .into_iter()
            .map(|(_, row)| row)
            .collect();
        if waiters.is_empty() {
            continue;
        }
        let SourceState::Bound(floor) = StateReader::reader(vault, txn)?.state(&input)? else {
            continue;
        };
        for row in waiters {
            if fold_entry_in_txn(vault, txn, &row, &input, &floor)?
                && !has_open_in(vault, txn, &row)?
                && followed < FOLD_CASCADE
            {
                followed += 1;
                queue.push(row);
            }
        }
    }
    Ok(())
}

/// Folds the entry of `row` on `input`, an input bound and whole with
/// `floor`: whether the entry went.
fn fold_entry_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    input: &EntityId,
    floor: &BTreeSet<EntityId>,
) -> Result<bool> {
    let Some(byte) = OPEN.get(&vault.store, txn, &(*row, *input))? else {
        // An index pair whose entry went is stale.
        OPEN_BY.delete(&vault.store, txn, &(*input, *row))?;
        return Ok(false);
    };
    let flags = OpenFlags::from_byte(byte);
    if flags.before_floors_level().is_some() {
        return Ok(false);
    }
    if flags.is_attestation() && floor.is_empty() {
        free_attestations_in_txn(vault, txn, row)?;
        return Ok(true);
    }
    if let Some(raw) = vault.get_raw_in(txn, row)? {
        take_floor_in_txn(vault, txn, row, &raw, floor)?;
    } else {
        crate::source_audience::add_derived_policies_in_txn(vault, txn, row, floor)?;
    }
    close_entry_in_txn(&vault.store, txn, row, input)?;
    Ok(true)
}

/// Heals, in `txn`, a row the old backfill raised (section 5, M2): its birth
/// inputs and dependency sources are read again. It takes the floor of each
/// that is bound and whole, opens an entry on each that has not landed, is
/// held without its binding or waits on inputs of its own, and leaves a
/// released or erased input alone, since nothing here says whether the row
/// took its floor before (limit 3). This gives back the marks a row lost
/// while it was archived, and hides no row whose floor is whole.
///
/// # Errors
///
/// Storage failures.
pub(in crate::source_audience) fn heal_row_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
) -> Result<()> {
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(());
    };
    if crate::source_audience::obligation::row_obligation(&raw).is_present() {
        return Ok(());
    }
    let mut inputs: BTreeSet<EntityId> =
        crate::store::birth_record::input_rows_in_txn(&vault.store, txn, row)?
            .into_iter()
            .collect();
    inputs.extend(crate::ports::dependency_sources_in(&vault.store, txn, row)?);
    inputs.remove(row);
    let mut acts = Vec::new();
    {
        let mut reader = StateReader::reader(vault, txn)?;
        for input in &inputs {
            if crate::ports::removed_in_txn(&vault.store, txn, input)? {
                continue;
            }
            match reader.state(input)? {
                SourceState::Bound(floor) => acts.push((*input, Act::Take(floor))),
                SourceState::Pending { .. } => {
                    acts.push((*input, Act::Open(OpenFlags::ORDINARY)));
                }
                SourceState::Sealed | SourceState::Erased => {}
            }
        }
    }
    for (input, act) in acts {
        match act {
            Act::Take(floor) => {
                take_floor_in_txn(vault, txn, row, &raw, &floor)?;
            }
            Act::Open(flags) => {
                open_entry_in_txn(vault, txn, row, &input, flags)?;
            }
            Act::Seal | Act::OpenSelf | Act::Free => {}
        }
    }
    Ok(())
}

/// Entries one sweep write reads.
const SWEEP_PAGE: usize = 256;

/// One write of the sweep over the open set (section 4, the sweep): from
/// the entry after `after`, in key order, it writes each index pair that is
/// missing, judges each self entry again (a row whose lineage resolves now
/// takes its sources' floors, or waits on them), and folds each entry whose
/// input reads bound and whole. Where the sweep goes on, or `None` once it
/// has read every entry.
pub(super) fn sweep_page_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    after: &[u8],
) -> Result<(u64, Option<Vec<u8>>)> {
    let start = match after.split_at_checked(16) {
        Some((row, input)) => match (id_of(row), id_of(input)) {
            (Some(row), Some(input)) => Some((row, input)),
            _ => None,
        },
        None => None,
    };
    let lower = match &start {
        Some(key) => Bound::Excluded(key),
        None => Bound::Unbounded,
    };
    let mut entries = Vec::new();
    for entry in OPEN.iter_range(&vault.store, txn, lower, Bound::Unbounded)? {
        let ((row, input), _) = entry?;
        let mut key = row.as_bytes().to_vec();
        key.extend_from_slice(input.as_bytes());
        entries.push((row, input, key));
        if entries.len() == SWEEP_PAGE {
            break;
        }
    }
    let mut folded = 0_u64;
    for (row, input, _) in &entries {
        if !OPEN_BY.contains(&vault.store, txn, &(*input, *row))? {
            OPEN_BY.put(&vault.store, txn, &(*input, *row), &())?;
        }
        if row == input {
            if resolve_self_in_txn(vault, txn, row)? {
                folded = folded.saturating_add(1);
            }
            continue;
        }
        let state = StateReader::reader(vault, txn)?.state(input)?;
        if let SourceState::Bound(floor) = state
            && fold_entry_in_txn(vault, txn, row, input, &floor)?
        {
            folded = folded.saturating_add(1);
            if !has_open_in(vault, txn, row)? {
                fold_waiters_in_txn(vault, txn, row)?;
            }
        }
    }
    Ok((
        folded,
        match entries.last() {
            Some((_, _, key)) if entries.len() == SWEEP_PAGE => Some(key.clone()),
            _ => None,
        },
    ))
}

/// The id whose bytes are `bytes`, if they are one.
pub(in crate::source_audience) fn id_of(bytes: &[u8]) -> Option<EntityId> {
    let bytes = <[u8; 16]>::try_from(bytes).ok()?;
    EntityId::from_bytes(bytes).ok()
}

/// Judges again the row `row` that waits on its own lineage: once its word
/// sources resolve, the self entry is replaced by the judgement of the links
/// it names now, each a new link. Whether the entry went.
fn resolve_self_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, row: &EntityId) -> Result<bool> {
    let Some(raw) = vault.get_raw_in(txn, row)? else {
        return Ok(false);
    };
    let Some(named) = word_sources_now_in(vault, txn, row, &raw)? else {
        return Ok(false);
    };
    close_entry_in_txn(&vault.store, txn, row, row)?;
    let named: BTreeSet<EntityId> = named.into_iter().filter(|source| source != row).collect();
    judge_row_in_txn(vault, txn, row, &Fresh::Links(named), false)?;
    if !has_open_in(vault, txn, row)? {
        fold_waiters_in_txn(vault, txn, row)?;
    }
    Ok(true)
}

/// Forgets, in `txn`, every floor's open set and the migration's state: the
/// vault reads as one whose rows were written before floors were.
#[cfg(any(test, feature = "test-support", oneiron_test_support))]
pub(crate) fn forget_floor_state_in_txn(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
    OPEN.delete_from(&vault.store, txn, &[])?;
    OPEN_BY.delete_from(&vault.store, txn, &[])?;
    MIGRATED.delete_from(&vault.store, txn, &[])?;
    SHELL_ERASED.delete_from(&vault.store, txn, &[])?;
    floor_migration::forget_in_txn(vault, txn)
}
