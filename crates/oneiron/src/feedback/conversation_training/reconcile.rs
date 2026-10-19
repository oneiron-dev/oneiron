//! Withdrawal by reconciliation (OF-420 A4, D2), receipts (C2, C3, C5) and
//! the outbox's upkeep.
//!
//! Each pass checks every held or published source for deletion (the room
//! or any selected message), which gets an id-only forget control, and
//! every world in play: one that no longer reads everywhere, or no longer
//! exists, gets a world control. Whatever they withdraw is purged from local
//! custody and from `offers/`. Controls name ids only and are written
//! whatever the learning state. The vault's setting turned off, or a person
//! opting out, withdraws nothing (FIX 5502 owner rulings): it stops new
//! sharing, and what was shared follows the intake's retention.
//!
//! It runs at every export tick and once after every commit that stored an
//! authority row ([`Vault::reconcile_training_after_authority_ingest`]),
//! which records controls durably and never touches a file; the next tick
//! writes them. Nothing is signed into the authority log: the signed choice
//! and its fold are as they were.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::{
    TRAINING_CONTROL_TYPE, TRAINING_SCHEMA_VERSION, TRAINING_WITHDRAWAL_NOTE,
    TrainingControlBodyV1, TrainingControlChangeV1, TrainingControlV1, TrainingForgetSourceV1,
    TrainingReceiptBodyV1, TrainingReceiptStatusV1, TrainingReceiptSubjectV1,
    TrainingWorldEligibilityV1, control_file_name,
};

use crate::Vault;
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;

use super::crypto::{IntakeReceiptKey, receipt_verifies, sign_training_payload};
use super::custody::{
    self, ControlChange, ControlCustody, ReceiptMark, SubmissionCustody, SubmissionState, UsedRun,
    put_control_in, put_submission_in, record_control_in,
};
use super::lifecycle::{
    PublisherTrainingLifecycle, SignedTrainingControl, TrainingControlId, TrainingSubmissionId,
    TrainingUnavailable,
};

/// C2 (CALLS-2) retention: whether an offer's local bytes outlive the
/// intake's receipt for them. Conservative: they do not. Once an
/// authenticated `stored` receipt (that retires custody, C5) or `removed`
/// receipt lands, the offer's files go; its id-only custody row stays, for
/// later withdrawals and used-run history.
const OFFER_BYTES_OUTLIVE_INTAKE_RECEIPT: bool = false;

/// C5: whether a `stored` receipt retires local custody. The intake's
/// attestation that no person reads what it holds is the intake's to make,
/// and the engine claims nothing about it. Default: a stored receipt without
/// it retires nothing.
const fn stored_receipt_retires_custody(attested: bool) -> bool {
    attested
}

/// What one upkeep pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainingUpkeep {
    /// Receipts applied and removed.
    pub receipts_applied: usize,
    /// Receipt files left in place: not signed by the intake's key, or for
    /// another vault.
    pub receipts_refused: Vec<String>,
    /// Controls reconciliation recorded.
    pub controls_recorded: usize,
    /// Control files written.
    pub controls_written: usize,
    /// Submissions whose offer files were purged.
    pub offers_purged: usize,
}

/// What a reconciliation found, before it writes.
#[derive(Default)]
struct Plan {
    /// Active submissions whose room or a selected message is gone.
    gone: BTreeSet<TrainingSubmissionId>,
    /// Worlds in play that no longer count.
    worlds: BTreeSet<EntityId>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.gone.is_empty() && self.worlds.is_empty()
    }
}

impl Vault {
    /// One upkeep pass over the outbox (A2, A4): the intake's receipts the
    /// `receipt_key` authenticates (none without one), reconciliation,
    /// purges, then every pending control written. It never reads, filters
    /// or sends conversation text.
    ///
    /// # Errors
    /// Storage faults, a choice read that fails, a transport that could not
    /// read, write or remove a file, and an install with no key to sign a
    /// pending control: the pass stops, and what it recorded stays for the
    /// next.
    pub fn publisher_training_upkeep(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        receipt_key: Option<&IntakeReceiptKey>,
    ) -> Result<TrainingUpkeep> {
        let mut upkeep = TrainingUpkeep::default();
        if let Some(key) = receipt_key {
            self.apply_training_receipts(sink, key, &mut upkeep)?;
        }
        upkeep.controls_recorded = self.reconcile_conversation_training()?;
        upkeep.offers_purged = self.purge_training_offers(sink)?;
        upkeep.controls_written = self.spool_training_controls(sink, true)?;
        Ok(upkeep)
    }

    /// Reconciles every held or published source with what counts now (A4,
    /// D2), recording each control it needs and withdrawing what no longer
    /// counts. Returns how many controls it recorded. Idempotent: a second
    /// run over an unchanged vault records nothing.
    ///
    /// # Errors
    /// Storage faults: nothing is recorded.
    pub fn reconcile_conversation_training(&self) -> Result<usize> {
        let plan = self.reconcile_plan()?;
        if plan.is_empty() {
            return Ok(0);
        }
        let now = crate::unix_seconds_now();
        // Its own write, never grouped: the post-ingest call runs inside
        // another write's after-commit work.
        self.with_write_txn(|txn| apply_plan(self, txn, &plan, now))
    }

    /// The post-ingest call (D2): after a commit that stored an authority
    /// row (`noted`), whichever door stored it, reconcile. It records
    /// controls only, never a file. A failure is logged and left to the
    /// next export tick: it is never an ingest failure.
    pub(crate) fn reconcile_training_after_authority_ingest(&self, noted: bool) {
        if !noted {
            return;
        }
        if let Err(error) = self.reconcile_conversation_training() {
            tracing::warn!(
                %error,
                "publisher training reconciliation after an authority ingest failed; the next \
                 export tick runs it"
            );
        }
    }

    /// Writes every control not yet written, in event order. With `record`,
    /// each written control is recorded as written; without it (a pass that
    /// may not write the vault) the files are written and the next pass
    /// records them. Returns how many it wrote.
    ///
    /// # Errors
    /// Storage faults, a control the transport could not write, and an
    /// install with no key to sign one.
    pub fn spool_training_controls(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        record: bool,
    ) -> Result<usize> {
        let mut pending: Vec<(TrainingControlId, ControlCustody)> = {
            let txn = self.store.env.read_txn()?;
            custody::controls(self, &txn)?
                .into_iter()
                .filter(|(_, row)| !row.spooled)
                .collect()
        };
        pending.sort_by_key(|(_, row)| row.event_seq);
        let mut written = Vec::with_capacity(pending.len());
        for (id, row) in &pending {
            let control = self.sign_control(*id, row)?;
            sink.control(&control)?;
            written.push(*id);
        }
        if record && !written.is_empty() {
            self.with_write_txn_grouped(|txn| {
                for id in &written {
                    if let Some(mut row) = custody::control(self, txn, *id)? {
                        row.spooled = true;
                        put_control_in(self, txn, *id, &row)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(written.len())
    }

    /// Everything a reconciliation needs, read before it writes.
    fn reconcile_plan(&self) -> Result<Plan> {
        let mut plan = Plan::default();
        let txn = self.store.env.read_txn()?;
        let active: Vec<(TrainingSubmissionId, SubmissionCustody)> =
            custody::submissions(self, &txn)?
                .into_iter()
                .filter(|(_, row)| is_active(row))
                .collect();
        // Nothing held or published: nothing to withdraw, and no fold to
        // read.
        if active.is_empty() {
            return Ok(plan);
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let mut in_play: BTreeSet<EntityId> = BTreeSet::new();
        for (id, row) in &active {
            in_play.extend(row.worlds.iter().copied());
            if source_gone(self, &txn, row)? {
                plan.gone.insert(*id);
            }
        }
        for world in in_play {
            if !world_counts(self, &txn, &fold, world)? {
                plan.worlds.insert(world);
            }
        }
        Ok(plan)
    }

    /// Applies the intake's receipts the key authenticates, past the cursor,
    /// in publisher order, then removes their files. A receipt for another
    /// vault, or not signed by the key, stays where it is and is named.
    fn apply_training_receipts(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        key: &IntakeReceiptKey,
        upkeep: &mut TrainingUpkeep,
    ) -> Result<()> {
        let cursor = {
            let txn = self.store.env.read_txn()?;
            custody::receipt_cursor(self, &txn)?
        };
        let page = sink.receipts(cursor)?;
        for file in &page.stale {
            sink.retire_receipt(file)?;
        }
        let vault_id = oneiron_vault_contract::hex(self.vault_id().as_bytes());
        let mut accepted = Vec::new();
        for received in page.receipts {
            if received.receipt.body.engine_vault_id == vault_id
                && receipt_verifies(key, &received.receipt)
            {
                accepted.push(received);
            } else {
                upkeep.receipts_refused.push(received.file);
            }
        }
        if accepted.is_empty() {
            return Ok(());
        }
        accepted.sort_by_key(|received| received.receipt.body.publisher_sequence);
        self.with_write_txn_grouped(|txn| {
            for received in &accepted {
                apply_receipt_in(self, txn, &received.receipt.body)?;
            }
            Ok(())
        })?;
        for received in &accepted {
            sink.retire_receipt(&received.file)?;
        }
        upkeep.receipts_applied = accepted.len();
        Ok(())
    }

    /// Purges the files of every submission whose bytes may go: withheld,
    /// withdrawn, or published and retired by the intake's receipt. Returns
    /// how many it purged.
    fn purge_training_offers(&self, sink: &dyn PublisherTrainingLifecycle) -> Result<usize> {
        let due: Vec<TrainingSubmissionId> = {
            let txn = self.store.env.read_txn()?;
            custody::submissions(self, &txn)?
                .into_iter()
                .filter(|(_, row)| row.files && purge_due(row))
                .map(|(id, _)| id)
                .collect()
        };
        for id in &due {
            sink.purge(*id)?;
        }
        if !due.is_empty() {
            self.with_write_txn_grouped(|txn| {
                for id in &due {
                    if let Some(mut row) = custody::submission(self, txn, *id)?
                        && purge_due(&row)
                    {
                        row.files = false;
                        put_submission_in(self, txn, *id, &row)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(due.len())
    }

    /// One control's signed file.
    fn sign_control(
        &self,
        id: TrainingControlId,
        row: &ControlCustody,
    ) -> Result<SignedTrainingControl> {
        let control_id = id.to_hex();
        let body = TrainingControlBodyV1 {
            control_id: control_id.clone(),
            event_seq: row.event_seq,
            engine_vault_id: oneiron_vault_contract::hex(self.vault_id().as_bytes()),
            change: wire_change(&row.change),
            recorded_at: row.recorded_at,
            note: TRAINING_WITHDRAWAL_NOTE.to_owned(),
        };
        let signature = sign_training_payload(self, TRAINING_CONTROL_TYPE, &body)?
            .ok_or_else(|| Error::Refused(TrainingUnavailable::NoInstallKey.to_string()))?;
        let file = control_file_name(row.event_seq, &control_id).ok_or(
            Error::InvariantViolation("a control id names no control file"),
        )?;
        let bytes = serde_json::to_vec_pretty(&TrainingControlV1 {
            schema_version: TRAINING_SCHEMA_VERSION,
            file_type: TRAINING_CONTROL_TYPE.to_owned(),
            body,
            signature,
        })
        .map_err(|_| Error::InvariantViolation("a training control does not encode"))?;
        Ok(SignedTrainingControl {
            control: id,
            event_seq: row.event_seq,
            file,
            bytes,
        })
    }
}

/// Writes what a plan found, re-reading each row so a concurrent pass never
/// records the same control twice.
fn apply_plan(vault: &Vault, txn: &mut heed::RwTxn<'_>, plan: &Plan, now: u64) -> Result<usize> {
    let mut recorded = 0;
    let mut withdraw: BTreeMap<TrainingSubmissionId, Withdrawal> = BTreeMap::new();
    let active: Vec<(TrainingSubmissionId, SubmissionCustody)> = custody::submissions(vault, txn)?
        .into_iter()
        .filter(|(_, row)| is_active(row))
        .collect();
    for world in &plan.worlds {
        let control = ControlChange::WorldEligibility {
            world: *world,
            everywhere: false,
        };
        record_control_in(vault, txn, control, now)?;
        recorded += 1;
        for (id, row) in &active {
            if row.worlds.contains(world) {
                withdraw.insert(*id, Withdrawal::Covered);
            }
        }
    }
    for id in &plan.gone {
        withdraw.entry(*id).or_insert(Withdrawal::Forget);
    }
    let mut forgets: BTreeMap<EntityId, Vec<[u8; 16]>> = BTreeMap::new();
    for (id, mut row) in active {
        let Some(how) = withdraw.get(&id) else {
            continue;
        };
        if *how == Withdrawal::Forget && row.published_at.is_some() {
            forgets.entry(row.source).or_default().push(id.0);
        }
        row.state = SubmissionState::Withdrawn;
        put_submission_in(vault, txn, id, &row)?;
    }
    for (source, submissions) in forgets {
        let control = ControlChange::ForgetSource {
            source,
            submissions,
        };
        record_control_in(vault, txn, control, now)?;
        recorded += 1;
    }
    Ok(recorded)
}

/// How a withdrawn submission reaches the intake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Withdrawal {
    /// A world control recorded in the same pass covers it.
    Covered,
    /// Its source is gone: it needs a forget control of its own.
    Forget,
}

/// Whether a submission is still held or published here.
fn is_active(row: &SubmissionCustody) -> bool {
    matches!(
        row.state,
        SubmissionState::Held | SubmissionState::Published
    )
}

/// Whether a submission's room, or any message it selected, is deleted,
/// archived or stale now.
fn source_gone(vault: &Vault, txn: &heed::RoTxn<'_>, row: &SubmissionCustody) -> Result<bool> {
    for id in std::iter::once(&row.source).chain(&row.messages) {
        let marker = vault.store.port_deletion_state(txn, id)?;
        if marker.deleted || marker.archived || marker.stale {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `world` still counts: base reality, or a stored, live WORLD row,
/// that reads everywhere on `fold`.
fn world_counts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    world: EntityId,
) -> Result<bool> {
    if world != crate::claim::base_world_id() {
        if vault.get_entity_type_in_txn(txn, &world)? != Some(ENTITY_TYPE_WORLD) {
            return Ok(false);
        }
        let marker = vault.store.port_deletion_state(txn, &world)?;
        if marker.deleted || marker.archived || marker.stale {
            return Ok(false);
        }
    }
    Ok(fold.world_privacy(world).read == EffectiveRead::Everywhere)
}

/// Whether a submission's files may go now.
fn purge_due(row: &SubmissionCustody) -> bool {
    match row.state {
        SubmissionState::Held => false,
        SubmissionState::Withheld | SubmissionState::Withdrawn => true,
        SubmissionState::Published => row.receipt.is_some_and(|mark| match mark.status {
            TrainingReceiptStatusV1::Stored => {
                !OFFER_BYTES_OUTLIVE_INTAKE_RECEIPT && stored_receipt_retires_custody(mark.attested)
            }
            TrainingReceiptStatusV1::Removed => !OFFER_BYTES_OUTLIVE_INTAKE_RECEIPT,
            TrainingReceiptStatusV1::Excluded | TrainingReceiptStatusV1::Rejected => true,
            TrainingReceiptStatusV1::RemovalPending => false,
        }),
    }
}

/// Applies one authenticated receipt: its subject's mark, past the cursor,
/// and each used run on the submissions it names (C3).
fn apply_receipt_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: &TrainingReceiptBodyV1,
) -> Result<()> {
    if body.publisher_sequence <= custody::receipt_cursor(vault, txn)?.0 {
        return Ok(());
    }
    let mark = ReceiptMark {
        status: body.status,
        attested: body.no_human_read.is_some(),
        sequence: body.publisher_sequence,
    };
    match &body.subject {
        TrainingReceiptSubjectV1::Submission(id) => {
            if let Some(id) = TrainingSubmissionId::from_hex(id)
                && let Some(mut row) = custody::submission(vault, txn, id)?
            {
                row.receipt = Some(mark);
                put_submission_in(vault, txn, id, &row)?;
            }
        }
        TrainingReceiptSubjectV1::Control(id) => {
            if let Some(id) = TrainingControlId::from_hex(id)
                && let Some(mut row) = custody::control(vault, txn, id)?
            {
                row.receipt = Some(mark);
                put_control_in(vault, txn, id, &row)?;
            }
        }
    }
    for run in &body.used_runs {
        for submission in &run.submissions {
            let Some(id) = TrainingSubmissionId::from_hex(submission) else {
                continue;
            };
            let Some(mut row) = custody::submission(vault, txn, id)? else {
                continue;
            };
            if row.used_runs.iter().any(|used| used.run_id == run.run_id) {
                continue;
            }
            row.used_runs.push(UsedRun {
                run_id: run.run_id.clone(),
                model: run.model.clone(),
                used_at: run.used_at,
            });
            put_submission_in(vault, txn, id, &row)?;
        }
    }
    custody::advance_receipt_cursor_in(vault, txn, body.publisher_sequence)
}

/// A control's change as the wire spells it.
fn wire_change(change: &ControlChange) -> TrainingControlChangeV1 {
    match change {
        ControlChange::ForgetSource {
            source,
            submissions,
        } => TrainingControlChangeV1::ForgetSource(TrainingForgetSourceV1 {
            source: source.to_hex(),
            submissions: submissions
                .iter()
                .map(|id| oneiron_vault_contract::hex(id.as_slice()))
                .collect(),
        }),
        ControlChange::WorldEligibility { world, everywhere } => {
            TrainingControlChangeV1::WorldEligibility(TrainingWorldEligibilityV1 {
                world: world.to_hex(),
                everywhere: *everywhere,
            })
        }
    }
}
