//! Local custody of publisher training offers and controls (OF-420): what
//! this vault prepared, published and withdrew, by id, and the scope it last
//! delivered for each person.
//!
//! Three Named families, each LIVE across a restore: they record acts that
//! already left the vault, so an older image never brings back a withdrawn
//! scope or replays an event number.
//!
//! - custody (`publisher_training:custody:v1:`): one row per submission
//!   (`s` + id) and per control (`c` + id). A row holds ids, revisions and
//!   states, never text: an offer's bytes live only sealed, in the outbox.
//! - person (`publisher_training:person:v1:`): the scope last delivered for
//!   each person, what reconciliation compares their choice with.
//! - state (`publisher_training:state:v1`): the next event number and the
//!   receipt cursor.
//!
//! A person's erase (FIX 3520) forgets their name here: their scope row
//! goes, their pending choice controls go, and every submission of theirs
//! that reached the intake gets an id-only forget control in the erase's
//! own transaction, so the withdrawal still flows without naming them.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV1;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::lifecycle::{ReceiptCursor, TrainingControlId, TrainingSubmissionId};

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
/// The scope last delivered for each person.
pub(super) const SCOPES: SideTable<EntityId, DeliveredScope, Named> =
    SideTable::new(&side_table::PUBLISHER_TRAINING_PERSON);
/// The event counter and the receipt cursor.
const STATE: SideTable<(), OutboxState, Named> =
    SideTable::new(&side_table::PUBLISHER_TRAINING_STATE);

/// One submission, by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SubmissionCustody {
    /// The CONVERSATION it was selected from.
    pub(super) source: EntityId,
    /// Whose words; `None` once their erase forgot them.
    pub(super) person: Option<EntityId>,
    /// The worlds the selected rows sit in.
    pub(super) worlds: BTreeSet<EntityId>,
    /// The selected MESSAGE rows, for the deletion check.
    pub(super) messages: Vec<EntityId>,
    /// The digest of the exact selected snapshot (D4).
    pub(super) source_revision: [u8; 32],
    /// The person's choice revision it was prepared on.
    pub(super) consent_revision: [u8; 32],
    /// The worlds the person's choice counted then.
    pub(super) consent_worlds: BTreeSet<EntityId>,
    /// The worlds' settings revision digest then.
    pub(super) policy_revision: [u8; 32],
    /// Its place in the event order.
    pub(super) event_seq: u64,
    /// Unix seconds.
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
    /// Withdrawn after it was prepared: off, a narrower scope, a deleted
    /// source or person, a world no longer everywhere.
    Withdrawn,
}

/// The intake's last word on a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ReceiptMark {
    pub(super) status: TrainingReceiptStatusV1,
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
    pub(super) event_seq: u64,
    pub(super) change: ControlChange,
    /// Unix seconds.
    pub(super) recorded_at: u64,
    /// Whether its file was written and the write recorded.
    pub(super) spooled: bool,
    pub(super) receipt: Option<ReceiptMark>,
}

/// What a control says, as the engine keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum ControlChange {
    /// A person's choice now: `None` worlds is off.
    PersonChoice {
        person: EntityId,
        act: Option<[u8; 32]>,
        revision: [u8; 32],
        allowed_worlds: Option<BTreeSet<EntityId>>,
    },
    /// Remove these submissions of one source.
    ForgetSource {
        source: EntityId,
        submissions: Vec<[u8; 16]>,
    },
    /// A world's eligibility now.
    WorldEligibility { world: EntityId, everywhere: bool },
}

/// The scope last delivered for one person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct DeliveredScope {
    /// The worlds their choice counted at the last offer or scope control.
    pub(super) worlds: BTreeSet<EntityId>,
    /// Their choice revision then.
    pub(super) revision: [u8; 32],
    /// The event that delivered it.
    pub(super) event_seq: u64,
}

/// The event counter and the receipt cursor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct OutboxState {
    /// The next event number; events start at 1.
    next_event_seq: u64,
    /// The highest publisher sequence applied.
    receipt_cursor: u64,
}

/// A fresh random 16-byte id.
pub(super) fn random_id() -> [u8; 16] {
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// Takes the next event number, in the caller's transaction.
pub(super) fn next_event_seq_in(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let mut state = STATE.get(&vault.store, txn, &())?.unwrap_or_default();
    let seq = state.next_event_seq.max(1);
    state.next_event_seq = seq.saturating_add(1);
    STATE.put(&vault.store, txn, &(), &state)?;
    Ok(seq)
}

/// The highest publisher sequence this vault applied.
pub(super) fn receipt_cursor(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ReceiptCursor> {
    Ok(ReceiptCursor(
        STATE
            .get(&vault.store, txn, &())?
            .unwrap_or_default()
            .receipt_cursor,
    ))
}

/// Moves the receipt cursor up to `sequence`, never down.
pub(super) fn advance_receipt_cursor_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    sequence: u64,
) -> Result<()> {
    let mut state = STATE.get(&vault.store, txn, &())?.unwrap_or_default();
    if sequence > state.receipt_cursor {
        state.receipt_cursor = sequence;
        STATE.put(&vault.store, txn, &(), &state)?;
    }
    Ok(())
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

/// Records one control, unspooled, at the next event number: its id and
/// that number.
pub(super) fn record_control_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: ControlChange,
    now: u64,
) -> Result<(TrainingControlId, u64)> {
    let id = TrainingControlId(random_id());
    let event_seq = next_event_seq_in(vault, txn)?;
    let row = ControlCustody {
        event_seq,
        change,
        recorded_at: now,
        spooled: false,
        receipt: None,
    };
    put_control_in(vault, txn, id, &row)?;
    Ok((id, event_seq))
}

/// Each person's delivered scope.
pub(super) fn scopes(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, DeliveredScope)>> {
    SCOPES.scan(&vault.store, txn)
}

impl Vault {
    /// A person's erase over the custody family (FIX 3520), in the erase's
    /// own transaction: their pending choice controls go, each submission
    /// of theirs that reached the intake gets an id-only forget control,
    /// and every row of theirs forgets their id and stands withdrawn, its
    /// files left for the next pass to purge.
    pub(crate) fn erase_publisher_training_custody_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        for ((_, id), row) in CONTROLS.scan_from(&self.store, wtxn, &CONTROL)? {
            if matches!(&row.change, ControlChange::PersonChoice { person, .. } if person == actor)
            {
                CONTROLS.delete(&self.store, wtxn, &(CONTROL, id))?;
            }
        }
        let mut forgets: BTreeMap<EntityId, Vec<[u8; 16]>> = BTreeMap::new();
        for ((_, id), mut row) in SUBMISSIONS.scan_from(&self.store, wtxn, &SUBMISSION)? {
            if row.person != Some(*actor) {
                continue;
            }
            let removed = row
                .receipt
                .is_some_and(|mark| mark.status == TrainingReceiptStatusV1::Removed);
            if row.published_at.is_some() && !removed {
                forgets.entry(row.source).or_default().push(id);
            }
            row.person = None;
            if matches!(
                row.state,
                SubmissionState::Held | SubmissionState::Published
            ) {
                row.state = SubmissionState::Withdrawn;
            }
            SUBMISSIONS.put(&self.store, wtxn, &(SUBMISSION, id), &row)?;
        }
        let now = crate::unix_seconds_now();
        for (source, submissions) in forgets {
            record_control_in(
                self,
                wtxn,
                ControlChange::ForgetSource {
                    source,
                    submissions,
                },
                now,
            )?;
        }
        Ok(())
    }

    /// A person's erase over the delivered-scope family (FIX 3520): their
    /// row goes. The custody scrub, before it in catalog order, already
    /// sent their withdrawals by id.
    pub(crate) fn erase_publisher_training_scope_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        SCOPES.delete(&self.store, wtxn, actor)?;
        Ok(())
    }
}
