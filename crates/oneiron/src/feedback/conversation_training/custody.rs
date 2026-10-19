//! Local custody of publisher training offers and controls (OF-420;
//! TRAINING-LINK = C): what this vault prepared, published, withdrew and
//! purged, by id, and the private half of every link the outbox never
//! carries.
//!
//! Two Named families, each LIVE across a restore: they record acts that
//! already left the vault, so an older image never brings back a withdrawn
//! submission or replays an event number.
//!
//! - custody (`publisher_training:custody:v1:`): one row per submission
//!   (`s` + id) and per control (`c` + id). A row holds raw ids, revisions,
//!   states, the month and link generation whose scope it rides and its
//!   ordinal in that scope, never text: an offer's bytes live only sealed,
//!   in the outbox. The raw ids stay here; what leaves names only their
//!   codes for that month, made under that generation's key (`link`).
//! - state (`publisher_training:state:v1`): the vault's private local order
//!   (never exported), every (month, generation) it used with that pair's
//!   scope, next ordinal and receipt cursor, whether the training link key
//!   was minted and its current generation, when it was last minted afresh,
//!   the withdrawals not yet reported unavailable, and the purge's controls,
//!   one per scope, once it is recorded.
//!
//! A generation older than the current one is orphaned (FIX 5892): its key
//! was lost with a restore that brought no custody head, so its codes cannot
//! be made again. Its scopes stay, still purgeable whole, but a withdrawal
//! that needs its codes is recorded nowhere and counted unavailable.
//!
//! A person's erase (FIX 3520) forgets their name here: every submission
//! carrying their words stands withdrawn, each that reached the intake named
//! by an id-only forget control in the erase's own transaction, one control
//! per month those submissions were prepared in, so the withdrawal still
//! flows without naming them.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV2;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::lifecycle::{ReceiptCursor, TrainingControlId, TrainingScope, TrainingSubmissionId};
use super::link;

/// A custody key: the row's kind, then its id.
pub(super) type CustodyKey = ([u8; 1], [u8; 16]);

/// The kind byte of a submission row.
pub(super) const SUBMISSION: [u8; 1] = *b"s";
/// The kind byte of a control row.
pub(super) const CONTROL: [u8; 1] = *b"c";

/// Each submission this vault prepared.
pub(super) const SUBMISSIONS: SideTable<CustodyKey, SubmissionCustody, Named> =
    SideTable::new(&side_table::PUBLISHER_TRAINING_CUSTODY);
/// Each control this vault recorded.
pub(super) const CONTROLS: SideTable<CustodyKey, ControlCustody, Named> =
    SideTable::new(&side_table::PUBLISHER_TRAINING_CUSTODY);
/// The private order, the months used, the link flag and the purge.
const STATE: SideTable<(), OutboxState, Named> =
    SideTable::new(&side_table::PUBLISHER_TRAINING_STATE);

/// One submission, by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SubmissionCustody {
    /// The CONVERSATION it was selected from.
    pub(super) source: EntityId,
    /// Every person whose words it carries, members and guests alike; empty
    /// for text only agents wrote. A person's erase removes them.
    pub(super) persons: BTreeSet<EntityId>,
    /// The worlds the selected rows sit in.
    pub(super) worlds: BTreeSet<EntityId>,
    /// The selected MESSAGE rows, for the deletion check.
    pub(super) messages: Vec<EntityId>,
    /// The digest of the exact selected snapshot (D4).
    pub(super) source_revision: [u8; 32],
    /// The vault's training setting revision it was prepared on.
    pub(super) setting_revision: [u8; 32],
    /// The vault's training setting act in force then.
    pub(super) setting_act: Option<[u8; 32]>,
    /// The worlds' settings revision digest then.
    pub(super) policy_revision: [u8; 32],
    /// Its place in the vault's private local order: never exported.
    pub(super) local_seq: u64,
    /// The UTC month of its first preparation, `YYYY-MM`: with its
    /// generation, the scope it rides. A retry keeps it.
    pub(super) month: String,
    /// The training link key generation it was prepared under. A retry
    /// keeps it.
    pub(super) generation: u32,
    /// Its ordinal within its scope. A retry keeps it.
    pub(super) scope_seq: u64,
    /// Unix seconds, of its first preparation. A retry keeps it.
    pub(super) prepared_at: u64,
    /// When it was published; `None` while it never left.
    pub(super) published_at: Option<u64>,
    pub(super) state: SubmissionState,
    /// Whether its files may still be in the outbox.
    pub(super) files: bool,
    /// The intake's last receipt for it.
    pub(super) receipt: Option<ReceiptMark>,
    /// The runs the intake says used it (C3).
    pub(super) used_runs: Vec<UsedRun>,
}

/// Where a submission stands here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum SubmissionState {
    /// Prepared, staged, awaiting its release.
    Held,
    /// Released and published.
    Published,
    /// Its release held it back.
    Withheld,
    /// Withdrawn after it was prepared: a deleted source, a person's erase,
    /// a world no longer everywhere, or a newer offer of its source.
    Withdrawn,
}

/// The intake's last word on a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReceiptMark {
    pub(super) status: TrainingReceiptStatusV2,
    /// Whether the receipt carried the no-human-read attestation (C5).
    pub(super) attested: bool,
    pub(super) sequence: u64,
}

/// One run that used a submission (C3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct UsedRun {
    pub(super) run_id: String,
    pub(super) model: String,
    pub(super) used_at: u64,
}

/// One control, by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ControlCustody {
    /// Its place in the vault's private local order: never exported.
    pub(super) local_seq: u64,
    /// The month whose scope it rides: that of the submissions it reaches,
    /// or for a purge control the month whose scope it purges.
    pub(super) month: String,
    /// The link generation whose scope it rides, with its month.
    pub(super) generation: u32,
    /// Its ordinal within that scope.
    pub(super) scope_seq: u64,
    pub(super) change: ControlChange,
    /// Unix seconds.
    pub(super) recorded_at: u64,
    /// Whether its file was written and the write recorded.
    pub(super) spooled: bool,
    /// Whether it can never be written: it needs codes of an orphaned
    /// generation, whose key is gone (FIX 5892).
    pub(super) unsendable: bool,
    pub(super) receipt: Option<ReceiptMark>,
}

/// What a control says, as the engine keeps it: raw ids, coded for the
/// control's month only when it is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum ControlChange {
    /// Remove these submissions of one source.
    ForgetSource {
        source: EntityId,
        submissions: Vec<[u8; 16]>,
    },
    /// A world's eligibility now.
    WorldEligibility { world: EntityId, everywhere: bool },
    /// Purge everything under the control's own scope (TL-5).
    PurgeScope,
}

impl ControlChange {
    /// Whether the wire spelling of this change carries codes, so signing it
    /// needs its generation's key. A purge names none.
    pub(super) const fn needs_codes(&self) -> bool {
        !matches!(self, Self::PurgeScope)
    }
}

/// The outbox's private state.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OutboxState {
    /// The vault's private local order; events start at 1. It orders the
    /// latest submission of each source and private sorting, and is never
    /// exported.
    pub(super) next_local_seq: u64,
    /// Every (month, generation) this vault used, each once, in the order
    /// first used.
    pub(super) months: Vec<MonthState>,
    /// Whether the training link key was minted.
    pub(super) link_minted: bool,
    /// The current training link key's custody generation: 0 for the first,
    /// one more for each key minted afresh after a restore left the slot
    /// missing (FIX 5892). A retired or unreadable key is never replaced.
    pub(super) link_generation: u32,
    /// When the key was last minted afresh, unix seconds.
    pub(super) link_reminted_at: Option<u64>,
    /// Withdrawals of an orphaned generation recorded nowhere, or never to
    /// be written, since the last upkeep pass reported them.
    pub(super) withdrawals_unavailable: u64,
    /// The purge, once recorded (TL-5).
    pub(super) purge: Option<PurgeState>,
}

/// One (month, generation) this vault used.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MonthState {
    /// The UTC month, `YYYY-MM`.
    pub(super) month: String,
    /// The training link key generation its scope was made under.
    pub(super) generation: u32,
    /// Its scope tag S, kept so listing scopes never needs the key.
    pub(super) scope: [u8; 32],
    /// The next ordinal in its scope; ordinals start at 1.
    pub(super) next_event_seq: u64,
    /// The highest publisher sequence applied in its scope.
    pub(super) receipt_cursor: u64,
}

/// The purge (TL-5): its controls, one per scope the vault used, and when
/// they were recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PurgeState {
    pub(super) controls: Vec<[u8; 16]>,
    /// Unix seconds.
    pub(super) recorded_at: u64,
}

impl OutboxState {
    /// The (`month`, `generation`) entry, when this vault used it.
    pub(super) fn month(&self, month: &str, generation: u32) -> Option<&MonthState> {
        self.months
            .iter()
            .find(|entry| entry.month == month && entry.generation == generation)
    }

    /// The scope of (`month`, `generation`), which this vault used.
    ///
    /// # Errors
    /// A pair the vault never used: damaged custody.
    pub(super) fn scope_of(&self, month: &str, generation: u32) -> Result<[u8; 32]> {
        self.month(month, generation)
            .map(|entry| entry.scope)
            .ok_or(Error::CorruptedIndex("publisher training month"))
    }

    /// Whether `generation` is orphaned: older than the current key's, its
    /// key lost, its codes never to be made again.
    pub(super) const fn orphaned(&self, generation: u32) -> bool {
        generation < self.link_generation
    }

    /// Every scope this vault used, every generation's, and its receipt
    /// cursor, in scope order: what the scopes file lists.
    pub(super) fn cursors(&self) -> Vec<ReceiptCursor> {
        let mut cursors: Vec<ReceiptCursor> = self
            .months
            .iter()
            .map(|entry| ReceiptCursor {
                scope: TrainingScope(entry.scope),
                sequence: entry.receipt_cursor,
            })
            .collect();
        cursors.sort_unstable();
        cursors
    }
}

/// A fresh random 16-byte id.
pub(super) fn random_id() -> [u8; 16] {
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// The outbox's private state, as `txn` reads it.
pub(super) fn state(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<OutboxState> {
    Ok(STATE.get(&vault.store, txn, &())?.unwrap_or_default())
}

/// Writes the outbox's private state.
pub(super) fn put_state_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    state: &OutboxState,
) -> Result<()> {
    STATE.put(&vault.store, txn, &(), state)
}

/// Takes the next number of the vault's private local order, in the
/// caller's transaction.
pub(super) fn next_local_seq_in(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let mut state = state(vault, txn)?;
    let seq = state.next_local_seq.max(1);
    state.next_local_seq = seq.saturating_add(1);
    put_state_in(vault, txn, &state)?;
    Ok(seq)
}

/// The current training link key's generation, in the caller's
/// transaction, its key made live first: minted on the vault's first
/// training use, or minted afresh under the next generation when a restore
/// left its slot missing (FIX 5892). A new offer takes this generation.
///
/// # Errors
/// A retired or unreadable key, and custody faults.
pub(super) fn link_generation_in(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<u32> {
    let mut state = state(vault, txn)?;
    link::training_link_key_in(vault, txn, &mut state)?;
    put_state_in(vault, txn, &state)?;
    Ok(state.link_generation)
}

/// Takes the next ordinal of the (`month`, `generation`) scope, in the
/// caller's transaction: the scope, and that ordinal. A pair this vault
/// never used joins its list, its scope made under the current training
/// link key, which this first use mints when the vault has none yet; only
/// the current generation can join.
///
/// # Errors
/// A pair of an older generation the vault never used, and the key's own
/// errors.
pub(super) fn next_scope_seq_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    month: &str,
    generation: u32,
) -> Result<([u8; 32], u64)> {
    let mut state = state(vault, txn)?;
    let known = state.month(month, generation).map(|entry| entry.scope);
    let scope = match known {
        Some(scope) => scope,
        None => {
            if generation != state.link_generation {
                return Err(Error::CorruptedIndex("publisher training month"));
            }
            let key = link::training_link_key_in(vault, txn, &mut state)?;
            if state.link_generation != generation {
                return Err(Error::InvariantViolation(
                    "a training month's link generation moved while it was placed",
                ));
            }
            link::scope_tag(&key, month)
        }
    };
    let at = match state
        .months
        .iter()
        .position(|entry| entry.month == month && entry.generation == generation)
    {
        Some(at) => at,
        None => {
            state.months.push(MonthState {
                month: month.to_owned(),
                generation,
                scope,
                next_event_seq: 1,
                receipt_cursor: 0,
            });
            state.months.len().saturating_sub(1)
        }
    };
    let entry = state
        .months
        .get_mut(at)
        .ok_or(Error::InvariantViolation("a training month joined no list"))?;
    let seq = entry.next_event_seq.max(1);
    entry.next_event_seq = seq.saturating_add(1);
    put_state_in(vault, txn, &state)?;
    Ok((scope, seq))
}

/// Adds `count` withdrawals of an orphaned generation to those the next
/// upkeep pass reports unavailable, in the caller's transaction.
pub(super) fn add_withdrawals_unavailable_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    count: u64,
) -> Result<()> {
    let mut state = state(vault, txn)?;
    state.withdrawals_unavailable = state.withdrawals_unavailable.saturating_add(count);
    put_state_in(vault, txn, &state)
}

/// Takes the count of withdrawals reported unavailable since the last
/// upkeep pass, in the caller's transaction, and zeroes it.
pub(super) fn take_withdrawals_unavailable_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let mut state = state(vault, txn)?;
    let count = std::mem::take(&mut state.withdrawals_unavailable);
    if count > 0 {
        put_state_in(vault, txn, &state)?;
    }
    Ok(count)
}

/// Whether the intake's `removed` receipt for every purge control is in
/// (TL-5): it holds nothing under any of this vault's scopes.
pub(super) fn purge_removed(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let Some(purge) = state(vault, txn)?.purge else {
        return Ok(false);
    };
    for id in purge.controls {
        let removed = control(vault, txn, TrainingControlId(id))?
            .and_then(|row| row.receipt)
            .is_some_and(|mark| mark.status == TrainingReceiptStatusV2::Removed);
        if !removed {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Every submission, in id order.
pub(super) fn submissions(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(TrainingSubmissionId, SubmissionCustody)>> {
    Ok(SUBMISSIONS
        .scan_from(&vault.store, txn, &SUBMISSION)?
        .into_iter()
        .map(|((_, id), row)| (TrainingSubmissionId(id), row))
        .collect())
}

/// One submission.
pub(super) fn submission(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: TrainingSubmissionId,
) -> Result<Option<SubmissionCustody>> {
    SUBMISSIONS.get(&vault.store, txn, &(SUBMISSION, id.0))
}

/// Writes one submission.
pub(super) fn put_submission_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: TrainingSubmissionId,
    row: &SubmissionCustody,
) -> Result<()> {
    SUBMISSIONS.put(&vault.store, txn, &(SUBMISSION, id.0), row)
}

/// Every control, in id order.
pub(super) fn controls(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(TrainingControlId, ControlCustody)>> {
    Ok(CONTROLS
        .scan_from(&vault.store, txn, &CONTROL)?
        .into_iter()
        .map(|((_, id), row)| (TrainingControlId(id), row))
        .collect())
}

/// One control.
pub(super) fn control(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: TrainingControlId,
) -> Result<Option<ControlCustody>> {
    CONTROLS.get(&vault.store, txn, &(CONTROL, id.0))
}

/// Writes one control.
pub(super) fn put_control_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: TrainingControlId,
    row: &ControlCustody,
) -> Result<()> {
    CONTROLS.put(&vault.store, txn, &(CONTROL, id.0), row)
}

/// Records one control, unspooled, riding the (`month`, `generation`)
/// scope at its next ordinal (and the next number of the private order):
/// its id. A change that needs codes of an orphaned generation records
/// nothing (its codes cannot be made again): it is counted unavailable, and
/// `None` comes back.
pub(super) fn record_control_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (month, generation): (&str, u32),
    change: ControlChange,
    now: u64,
) -> Result<Option<TrainingControlId>> {
    if change.needs_codes() && state(vault, txn)?.orphaned(generation) {
        add_withdrawals_unavailable_in(vault, txn, 1)?;
        return Ok(None);
    }
    let id = TrainingControlId(random_id());
    let local_seq = next_local_seq_in(vault, txn)?;
    let (_, scope_seq) = next_scope_seq_in(vault, txn, month, generation)?;
    let row = ControlCustody {
        local_seq,
        month: month.to_owned(),
        generation,
        scope_seq,
        change,
        recorded_at: now,
        spooled: false,
        unsendable: false,
        receipt: None,
    };
    put_control_in(vault, txn, id, &row)?;
    Ok(Some(id))
}

impl Vault {
    /// A person's erase over the custody family (FIX 3520), in the erase's
    /// own transaction: the submissions carrying their words that reached
    /// the intake get id-only forget controls, one per source, month and
    /// generation, each under that pair's scope (none for an orphaned
    /// generation, counted unavailable), and every such row forgets their id
    /// and stands withdrawn, its files left for the next pass to purge.
    pub(crate) fn erase_publisher_training_custody_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        let mut forgets: BTreeMap<(EntityId, String, u32), Vec<[u8; 16]>> = BTreeMap::new();
        for ((_, id), mut row) in SUBMISSIONS.scan_from(&self.store, wtxn, &SUBMISSION)? {
            if !row.persons.contains(actor) {
                continue;
            }
            let removed = row
                .receipt
                .is_some_and(|mark| mark.status == TrainingReceiptStatusV2::Removed);
            if row.published_at.is_some() && !removed {
                forgets
                    .entry((row.source, row.month.clone(), row.generation))
                    .or_default()
                    .push(id);
            }
            row.persons.remove(actor);
            if matches!(
                row.state,
                SubmissionState::Held | SubmissionState::Published
            ) {
                row.state = SubmissionState::Withdrawn;
            }
            SUBMISSIONS.put(&self.store, wtxn, &(SUBMISSION, id), &row)?;
        }
        let now = crate::unix_seconds_now();
        for ((source, month, generation), submissions) in forgets {
            record_control_in(
                self,
                wtxn,
                (&month, generation),
                ControlChange::ForgetSource {
                    source,
                    submissions,
                },
                now,
            )?;
        }
        Ok(())
    }
}
