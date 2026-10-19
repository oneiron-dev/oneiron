//! Withdrawal by reconciliation (OF-420 A4, D2), receipts (C2, C3, C5) and
//! the outbox's upkeep.
//!
//! Each pass checks every held or published source for deletion (the room
//! or any selected message), which gets an id-only forget control, and
//! every world in play: one that no longer reads everywhere, or no longer
//! exists, gets a world control. Whatever they withdraw is purged from local
//! custody and from `offers/`. Controls name codes and ids only, and are
//! written whatever the learning state. A withdrawal that reaches
//! submissions of several months is one control per month, each riding that
//! month's scope and naming that month's codes (TRAINING-LINK = C). The
//! vault's setting turned off, or a person opting out, withdraws nothing
//! (FIX 5502 owner rulings): it stops new sharing, and what was shared
//! follows the intake's retention.
//!
//! Receipts apply per scope: each scope keeps its own cursor, and no
//! scope's publisher sequence is compared with another's. Every scope rides
//! one (month, link generation) pair, and every control rides its own pair's
//! scope. A withdrawal that needs the codes of an orphaned generation (its
//! key lost with a restore that brought none, FIX 5892) is recorded nowhere
//! and never written; each pass counts those unavailable, while a purge,
//! which carries no codes, still goes for every generation's scopes. A receipt for a
//! scope this vault never used is refused and left where it is. The writer
//! that applies the last `removed` receipt of the purge (TL-5) stages the
//! training link key's retirement; the pass finishes it after the commit.
//!
//! It runs at every export tick and once after every commit that stored an
//! authority row ([`Vault::reconcile_training_after_authority_ingest`]),
//! which records controls durably and never touches a file; the next tick
//! writes them. Nothing is signed into the authority log: the signed choice
//! and its fold are as they were.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::{
    TRAINING_CONTROL_TYPE, TRAINING_SCHEMA_VERSION, TRAINING_WITHDRAWAL_NOTE,
    TrainingControlBodyV2, TrainingControlChangeV2, TrainingControlV2, TrainingForgetSourceV2,
    TrainingPurgeScopeV2, TrainingReceiptBodyV2, TrainingReceiptStatusV2, TrainingReceiptSubjectV2,
    TrainingWorldEligibilityV2, control_file_name,
};

use zeroize::Zeroizing;

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
    PublisherTrainingLifecycle, ReceivedTrainingReceipt, SignedTrainingControl, TrainingControlId,
    TrainingScope, TrainingSubmissionId, TrainingUnavailable,
};
use super::link;

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
    /// a scope this vault never used.
    pub receipts_refused: Vec<String>,
    /// Controls reconciliation recorded.
    pub controls_recorded: usize,
    /// Control files written.
    pub controls_written: usize,
    /// Submissions whose offer files were purged.
    pub offers_purged: usize,
    /// Withdrawals that need the codes of an orphaned link generation (its
    /// key lost with a restore that brought none, FIX 5892): recorded
    /// nowhere, or never to be written, since the last pass. Their local
    /// rows still stand withdrawn.
    pub withdrawals_unavailable: u64,
}

/// What one spool pass meets, read in one snapshot.
struct Spool {
    /// Each control to write, with the scope it rides.
    pending: Vec<([u8; 32], TrainingControlId, ControlCustody)>,
    /// Unwritten withdrawals of an orphaned generation: never written.
    orphaned: Vec<TrainingControlId>,
    /// The current link key, read only when a pending control carries
    /// codes: a purge is signed without it.
    key: Option<Zeroizing<[u8; 32]>>,
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
    /// `receipt_key` authenticates (none without one), the training link
    /// key's staged retirement once its rule holds, a fresh key when a
    /// restore lost it (FIX 5892), reconciliation, purges, every pending
    /// control written, then the vault's scopes handed to the transport and
    /// the withdrawals that could not go counted (one warning names the
    /// count, never an id, code, scope or key). It never reads, filters or
    /// sends conversation text.
    ///
    /// # Errors
    /// Storage faults, a choice read that fails, a transport that could not
    /// read, write or remove a file, an install with no key to sign a
    /// pending control, and a training link key that is retired or
    /// unreadable: the pass stops, and what it recorded stays for the next.
    pub fn publisher_training_upkeep(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        receipt_key: Option<&IntakeReceiptKey>,
    ) -> Result<TrainingUpkeep> {
        let mut upkeep = TrainingUpkeep::default();
        if let Some(key) = receipt_key {
            self.apply_training_receipts(sink, key, &mut upkeep)?;
        }
        self.finish_training_link_retirement_after_commit();
        self.renew_lost_training_link()?;
        upkeep.controls_recorded = self.reconcile_conversation_training()?;
        upkeep.offers_purged = self.purge_training_offers(sink)?;
        upkeep.controls_written = self.spool_training_controls(sink, true)?;
        self.write_training_scopes(sink)?;
        upkeep.withdrawals_unavailable = self.take_withdrawals_unavailable()?;
        if upkeep.withdrawals_unavailable > 0 {
            tracing::warn!(
                count = upkeep.withdrawals_unavailable,
                "publisher training withdrawals unavailable: their training link key was lost \
                 with a restore; the rows stand withdrawn here, and an erase still purges them"
            );
        }
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

    /// Writes every control not yet written, by scope and in event order
    /// within it. With `record`, each written control is recorded as
    /// written; without it (a pass that may not write the vault) the files
    /// are written and the next pass records them. Returns how many it
    /// wrote. Once the intake's `removed` receipt for every purge control is
    /// in, it holds nothing under any of this vault's scopes and the
    /// training link key is retiring: nothing more is written. Only a
    /// control that carries codes reads the key; a withdrawal that needs an
    /// orphaned generation's codes is never written, and a pass that records
    /// marks it unsendable and counts it unavailable (FIX 5892).
    ///
    /// # Errors
    /// Storage faults, a control the transport could not write, an install
    /// with no key to sign one, and a training link key that is gone.
    pub fn spool_training_controls(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        record: bool,
    ) -> Result<usize> {
        let Some(Spool {
            mut pending,
            orphaned,
            key,
        }) = self.spool_snapshot()?
        else {
            return Ok(0);
        };
        pending.sort_by_key(|(scope, _, row)| (*scope, row.scope_seq));
        let mut written = Vec::with_capacity(pending.len());
        for (scope, id, row) in &pending {
            let control = self.sign_control(key.as_deref(), *scope, *id, row)?;
            sink.control(&control)?;
            written.push(*id);
        }
        if record {
            self.with_write_txn_grouped(|txn| {
                for id in &written {
                    if let Some(mut row) = custody::control(self, txn, *id)? {
                        row.spooled = true;
                        put_control_in(self, txn, *id, &row)?;
                    }
                }
                let mut unsendable = 0_u64;
                for id in &orphaned {
                    if let Some(mut row) = custody::control(self, txn, *id)?
                        && !row.spooled
                        && !row.unsendable
                    {
                        row.unsendable = true;
                        put_control_in(self, txn, *id, &row)?;
                        unsendable = unsendable.saturating_add(1);
                    }
                }
                if unsendable > 0 {
                    custody::add_withdrawals_unavailable_in(self, txn, unsendable)?;
                }
                Ok(())
            })?;
        }
        Ok(written.len())
    }

    /// The controls a spool pass meets, in one snapshot: `None` when there
    /// are none, or once every purge control's `removed` receipt is in.
    fn spool_snapshot(&self) -> Result<Option<Spool>> {
        let txn = self.store.env.read_txn()?;
        if custody::purge_removed(self, &txn)? {
            return Ok(None);
        }
        let state = custody::state(self, &txn)?;
        let mut pending = Vec::new();
        let mut orphaned = Vec::new();
        for (id, row) in custody::controls(self, &txn)? {
            if row.spooled || row.unsendable {
                continue;
            }
            if row.change.needs_codes() && state.orphaned(row.generation) {
                orphaned.push(id);
            } else {
                pending.push((state.scope_of(&row.month, row.generation)?, id, row));
            }
        }
        if pending.is_empty() && orphaned.is_empty() {
            return Ok(None);
        }
        let key = if pending.iter().any(|(_, _, row)| row.change.needs_codes()) {
            Some(link::training_link_key(self, &txn, state.link_generation)?)
        } else {
            None
        };
        Ok(Some(Spool {
            pending,
            orphaned,
            key,
        }))
    }

    /// Takes the count of withdrawals that could not go since the last
    /// pass, zeroing it: a writer only when there are any.
    fn take_withdrawals_unavailable(&self) -> Result<u64> {
        let any = {
            let txn = self.store.env.read_txn()?;
            custody::state(self, &txn)?.withdrawals_unavailable > 0
        };
        if !any {
            return Ok(0);
        }
        self.with_write_txn_grouped(|txn| custody::take_withdrawals_unavailable_in(self, txn))
    }

    /// Hands the transport every scope this vault used, with its receipt
    /// cursor, for the scopes file it rewrites when either changed.
    ///
    /// # Errors
    /// Storage faults, and a file the transport could not write.
    pub(super) fn write_training_scopes(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
    ) -> Result<()> {
        let cursors = {
            let txn = self.store.env.read_txn()?;
            custody::state(self, &txn)?.cursors()
        };
        sink.scopes(&cursors)
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

    /// Applies the intake's receipts the key authenticates, each for one of
    /// this vault's scopes and past that scope's cursor, by scope and in
    /// publisher order within it, then removes their files. A receipt for a
    /// scope this vault never used, or not signed by the key, stays where it
    /// is and is named.
    fn apply_training_receipts(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        key: &IntakeReceiptKey,
        upkeep: &mut TrainingUpkeep,
    ) -> Result<()> {
        let cursors = {
            let txn = self.store.env.read_txn()?;
            custody::state(self, &txn)?.cursors()
        };
        let page = sink.receipts(&cursors)?;
        for file in &page.stale {
            sink.retire_receipt(file)?;
        }
        let mut accepted: Vec<(TrainingScope, ReceivedTrainingReceipt)> = Vec::new();
        for received in page.receipts {
            let scope = cursors
                .iter()
                .find(|cursor| cursor.scope.to_hex() == received.receipt.body.scope)
                .map(|cursor| cursor.scope);
            match scope {
                Some(scope) if receipt_verifies(key, &received.receipt) => {
                    accepted.push((scope, received));
                }
                _ => upkeep.receipts_refused.push(received.file),
            }
        }
        if accepted.is_empty() {
            return Ok(());
        }
        accepted
            .sort_by_key(|(scope, received)| (*scope, received.receipt.body.publisher_sequence));
        self.with_write_txn_grouped(|txn| {
            for (_, received) in &accepted {
                apply_receipt_in(self, txn, &received.receipt.body)?;
            }
            Ok(())
        })?;
        for (_, received) in &accepted {
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

    /// One control's signed file: under `scope`, its pair's, at its ordinal
    /// there, naming that month's codes made under `key`, the current link
    /// key, which only a control that carries codes needs.
    fn sign_control(
        &self,
        key: Option<&[u8; 32]>,
        scope: [u8; 32],
        id: TrainingControlId,
        row: &ControlCustody,
    ) -> Result<SignedTrainingControl> {
        let control_id = id.to_hex();
        let scope_hex = oneiron_vault_contract::hex(&scope);
        let body = TrainingControlBodyV2 {
            control_id: control_id.clone(),
            scope: scope_hex.clone(),
            event_seq: row.scope_seq,
            change: wire_change(key, &row.month, &row.change)?,
            recorded_at: row.recorded_at,
            note: TRAINING_WITHDRAWAL_NOTE.to_owned(),
        };
        let signature = sign_training_payload(self, TRAINING_CONTROL_TYPE, &body)?
            .ok_or_else(|| Error::Refused(TrainingUnavailable::NoInstallKey.to_string()))?;
        let file = control_file_name(&scope_hex, row.scope_seq, &control_id).ok_or(
            Error::InvariantViolation("a control id names no control file"),
        )?;
        let bytes = serde_json::to_vec_pretty(&TrainingControlV2 {
            schema_version: TRAINING_SCHEMA_VERSION,
            file_type: TRAINING_CONTROL_TYPE.to_owned(),
            body,
            signature,
        })
        .map_err(|_| Error::InvariantViolation("a training control does not encode"))?;
        Ok(SignedTrainingControl {
            control: id,
            scope: TrainingScope(scope),
            event_seq: row.scope_seq,
            file,
            bytes,
        })
    }
}

/// Writes what a plan found, re-reading each row so a concurrent pass never
/// records the same control twice. A world's control goes to every (month,
/// generation) in which a retained submission names it, one control per
/// pair; a gone source's forget control to every pair its withdrawn
/// published submissions were prepared in. Each rides its pair's scope at
/// its next ordinal, in this one writer with the withdrawal; none goes to
/// an orphaned generation, whose rows still stand withdrawn.
fn apply_plan(vault: &Vault, txn: &mut heed::RwTxn<'_>, plan: &Plan, now: u64) -> Result<usize> {
    let mut recorded = 0;
    let mut withdraw: BTreeMap<TrainingSubmissionId, Withdrawal> = BTreeMap::new();
    let retained = custody::submissions(vault, txn)?;
    for world in &plan.worlds {
        let months: BTreeSet<(&str, u32)> = retained
            .iter()
            .filter(|(_, row)| row.worlds.contains(world))
            .map(|(_, row)| (row.month.as_str(), row.generation))
            .collect();
        for pair in months {
            let control = ControlChange::WorldEligibility {
                world: *world,
                everywhere: false,
            };
            if record_control_in(vault, txn, pair, control, now)?.is_some() {
                recorded += 1;
            }
        }
        for (id, row) in &retained {
            if is_active(row) && row.worlds.contains(world) {
                withdraw.insert(*id, Withdrawal::Covered);
            }
        }
    }
    for id in &plan.gone {
        withdraw.entry(*id).or_insert(Withdrawal::Forget);
    }
    let mut forgets: BTreeMap<(EntityId, String, u32), Vec<[u8; 16]>> = BTreeMap::new();
    for (id, mut row) in retained {
        if !is_active(&row) {
            continue;
        }
        let Some(how) = withdraw.get(&id) else {
            continue;
        };
        if *how == Withdrawal::Forget && row.published_at.is_some() {
            forgets
                .entry((row.source, row.month.clone(), row.generation))
                .or_default()
                .push(id.0);
        }
        row.state = SubmissionState::Withdrawn;
        put_submission_in(vault, txn, id, &row)?;
    }
    for ((source, month, generation), submissions) in forgets {
        let control = ControlChange::ForgetSource {
            source,
            submissions,
        };
        if record_control_in(vault, txn, (&month, generation), control, now)?.is_some() {
            recorded += 1;
        }
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
            TrainingReceiptStatusV2::Stored => {
                !OFFER_BYTES_OUTLIVE_INTAKE_RECEIPT && stored_receipt_retires_custody(mark.attested)
            }
            TrainingReceiptStatusV2::Removed => !OFFER_BYTES_OUTLIVE_INTAKE_RECEIPT,
            TrainingReceiptStatusV2::Excluded | TrainingReceiptStatusV2::Rejected => true,
            TrainingReceiptStatusV2::RemovalPending => false,
        }),
    }
}

/// Applies one authenticated receipt in its scope: past that scope's
/// cursor, its subject's mark when the subject rides the same scope, and
/// each used run on the submissions it names (C3). A receipt for a scope
/// this vault never used applies nothing.
fn apply_receipt_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: &TrainingReceiptBodyV2,
) -> Result<()> {
    let mut state = custody::state(vault, txn)?;
    let link_generation = state.link_generation;
    let Some(entry) = state
        .months
        .iter_mut()
        .find(|entry| oneiron_vault_contract::hex(&entry.scope) == body.scope)
    else {
        return Ok(());
    };
    if body.publisher_sequence <= entry.receipt_cursor {
        return Ok(());
    }
    entry.receipt_cursor = body.publisher_sequence;
    let (month, generation) = (entry.month.clone(), entry.generation);
    custody::put_state_in(vault, txn, &state)?;
    let mark = ReceiptMark {
        status: body.status,
        attested: body.no_human_read.is_some(),
        sequence: body.publisher_sequence,
    };
    match &body.subject {
        TrainingReceiptSubjectV2::Submission(id) => {
            if let Some(id) = TrainingSubmissionId::from_hex(id)
                && let Some(mut row) = custody::submission(vault, txn, id)?
                && row.month == month
                && row.generation == generation
            {
                row.receipt = Some(mark);
                put_submission_in(vault, txn, id, &row)?;
            }
        }
        TrainingReceiptSubjectV2::Control(id) => {
            if let Some(id) = TrainingControlId::from_hex(id)
                && let Some(mut row) = custody::control(vault, txn, id)?
                && row.month == month
                && row.generation == generation
            {
                row.receipt = Some(mark);
                put_control_in(vault, txn, id, &row)?;
                if row.change == ControlChange::PurgeScope
                    && mark.status == TrainingReceiptStatusV2::Removed
                    && custody::purge_removed(vault, txn)?
                {
                    // TL-5: the last purge control is removed; the training
                    // link key may retire. Finished after this write commits.
                    vault
                        .store
                        .stage_training_link_retirement_in_txn(txn, link_generation)?;
                }
            }
        }
    }
    record_used_runs_in(vault, txn, body)
}

/// Each run a receipt names, appended to the submissions it used (C3).
fn record_used_runs_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: &TrainingReceiptBodyV2,
) -> Result<()> {
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
    Ok(())
}

/// A control's change as the wire spells it: raw ids coded for `month`
/// under `key`, submission ids as they are. A purge names no code and needs
/// no key.
fn wire_change(
    key: Option<&[u8; 32]>,
    month: &str,
    change: &ControlChange,
) -> Result<TrainingControlChangeV2> {
    let coded_key = || {
        key.ok_or(Error::InvariantViolation(
            "a coded training control has no key",
        ))
    };
    Ok(match change {
        ControlChange::ForgetSource {
            source,
            submissions,
        } => TrainingControlChangeV2::ForgetSource(TrainingForgetSourceV2 {
            source: link::code_hex(coded_key()?, link::SOURCE, source, month),
            submissions: submissions
                .iter()
                .map(|id| oneiron_vault_contract::hex(id.as_slice()))
                .collect(),
        }),
        ControlChange::WorldEligibility { world, everywhere } => {
            TrainingControlChangeV2::WorldEligibility(TrainingWorldEligibilityV2 {
                world: link::code_hex(coded_key()?, link::WORLD, world, month),
                everywhere: *everywhere,
            })
        }
        ControlChange::PurgeScope => TrainingControlChangeV2::PurgeScope(TrainingPurgeScopeV2 {}),
    })
}
