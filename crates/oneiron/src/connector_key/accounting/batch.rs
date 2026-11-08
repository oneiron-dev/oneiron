//! Connector-key batch admission: a batch of send-like dispatches charged
//! through one key, one transaction chunk after another (FIX 8683), under a
//! caller-named batch ref whose committed prefix is durable (FIX 11058).
//! Entry: `Vault::admit_connector_key_dispatches`. Defines its own items.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Named, SideTable};

use super::super::meter::{
    ConnectorDispatchTelemetry, ConnectorKeyDispatchTally, EffectorBudgetChargeOutcome,
    budget_exhausted_reason, charge_effector_budgets,
};
use super::super::record::{
    ConnectorKeyStatus, EffectorBudgetOnExhaust, invalid_body, normalize_connector_key,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, suspend_connector_key_in_txn,
};
use super::send_paced_until;

/// Dispatches one batch-admission writer accounts before it commits and the
/// next writer starts. A transaction chunk, never a bound on the batch: a
/// larger batch is accounted whole, chunk after chunk, and the
/// `ConnectorDispatchBatch` limit row asks past its own count.
pub const CONNECTOR_DISPATCH_TRANSACTION_CHUNK: u64 = 4096;

/// The longest batch ref, as long as a logical send's.
const CONNECTOR_DISPATCH_BATCH_REF_MAX_LEN: usize = 128;

/// vault_meta dispatch-batch rows (FIX 11058): key id ++ `batch_ref` -> the
/// batch's normalized input and the prefix of it that has a final outcome.
/// Each chunk's writer debits, records and moves this row together, so a
/// later chunk's failure leaves the committed prefix charged once and
/// recorded, and a retry under the same ref resumes after it.
const DISPATCH_BATCH: SideTable<(EntityId, String), DispatchBatchProgress, Named> =
    SideTable::new(&side_table::CONNECTOR_KEY_DISPATCH_BATCH);

/// One batch's normalized input and committed progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DispatchBatchProgress {
    /// The normalized effect channel and the size the batch was submitted
    /// with: a ref names one batch.
    effect_channel: String,
    count: u64,
    /// Dispatches admitted and refused so far: a prefix of the batch, each
    /// with its final outcome.
    admitted: u64,
    refused: u64,
    /// When the windows that paced the rest open again; `None` while no
    /// window holds it.
    paced_until: Option<u64>,
    /// The first chunk's engine-clock sample, and the latest chunk's.
    accounted_at: u64,
    last_accounted_at: u64,
}

impl DispatchBatchProgress {
    /// A batch no writer has charged yet, first sampled at `accounted_at`.
    fn fresh(batch: &DispatchBatch, accounted_at: u64) -> Self {
        Self {
            effect_channel: batch.effect_channel.clone(),
            count: batch.count,
            admitted: 0,
            refused: 0,
            paced_until: None,
            accounted_at,
            last_accounted_at: accounted_at,
        }
    }

    /// Dispatches with a final outcome.
    fn settled(&self) -> u64 {
        self.admitted.saturating_add(self.refused)
    }

    /// An empty tally, with nothing counted and no ladder events.
    fn tally(&self, caller_observed_at: Option<u64>) -> ConnectorKeyDispatchTally {
        ConnectorKeyDispatchTally {
            admitted: self.admitted,
            refused: self.refused,
            paced: 0,
            paced_until: None,
            ladder_events: Vec::new(),
            pool_key_ref: None,
            pool_ladder_events: Vec::new(),
            accounted_at: self.accounted_at,
            last_accounted_at: self.last_accounted_at,
            caller_observed_at,
        }
    }

    /// Writes the batch's counts and samples into `tally`, and the rest as
    /// paced while windows hold it; the ladder events stay the call's.
    fn report(&self, tally: &mut ConnectorKeyDispatchTally) {
        tally.admitted = self.admitted;
        tally.refused = self.refused;
        tally.accounted_at = self.accounted_at;
        tally.last_accounted_at = self.last_accounted_at;
        tally.paced = 0;
        tally.paced_until = None;
        if let Some(until) = self.paced_until {
            tally.paced = self.count - self.settled();
            tally.paced_until = Some(until);
        }
    }
}

/// One batch as a call names it: its row key, normalized channel and size.
struct DispatchBatch {
    key: (EntityId, String),
    effect_channel: String,
    count: u64,
}

impl Vault {
    /// Applies the existing effector-budget charger sequentially to a batch
    /// of send-like dispatches through one key, under `batch_ref`.
    ///
    /// `batch_ref` names the batch (nonblank, at most 128 bytes, no NUL) the
    /// way a logical send's ref names a send. Each chunk's debits, op records
    /// and the batch's progress commit in one writer (FIX 11058): a failure in
    /// a later chunk returns its error with the earlier chunks charged once
    /// and recorded, and a call under the same ref resumes after them instead
    /// of charging them again. A finished batch's call charges nothing and
    /// returns its tally. The ref names one batch: another channel or count
    /// under it is refused.
    ///
    /// Accounting time is the ENGINE clock, sampled ONCE per transaction
    /// chunk: every budget window selection/roll, usage entry, suspension
    /// transition, and op record in a chunk takes that chunk's one sample, so
    /// a chunk cannot straddle two windows and a caller cannot pick the
    /// window it debits. A later chunk samples afresh and never backdates
    /// into an earlier window. `telemetry` carries the caller's own
    /// observation as a declared fact — echoed in the tally, never handed to
    /// the charger.
    ///
    /// A dispatch whose only full rows are count-bound windows that refuse
    /// is paced, not refused (FIX 8686): it and the rest of the batch stay
    /// uncharged and come back counted in `paced`, to be admitted again at
    /// `paced_until` by a call under the same ref; one sooner charges nothing.
    /// Each resumed chunk reads the key and its rows live. A Spend row, and a
    /// row set to suspend, refuse as before. The counts are the batch's whole;
    /// the ladder events are the ones this call fired.
    pub fn admit_connector_key_dispatches(
        &self,
        id: &EntityId,
        batch_ref: &str,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
    ) -> Result<ConnectorKeyDispatchTally> {
        self.admit_connector_key_dispatch_batch(
            id,
            batch_ref,
            effect_channel,
            count,
            telemetry,
            || self.store.clock.now_recorded_at(),
        )
    }

    /// Freezes the accounting clock for a dispatch batch: every chunk takes
    /// `accounting_now`.
    ///
    /// The ONLY door that takes an accounting timestamp, and it exists solely
    /// so budget-window behavior is testable without sleeping. Compiled out of
    /// production builds: `test` covers this crate's own unit tests,
    /// `test-support` this crate's integration tests (self dev-dependency),
    /// `test-hooks` downstream crates' tests.
    #[cfg(any(test, feature = "test-support", feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn admit_connector_key_dispatches_at(
        &self,
        id: &EntityId,
        batch_ref: &str,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
        accounting_now: u64,
    ) -> Result<ConnectorKeyDispatchTally> {
        self.admit_connector_key_dispatch_batch(
            id,
            batch_ref,
            effect_channel,
            count,
            telemetry,
            || accounting_now,
        )
    }

    /// Sole body of connector-key batch admission. `accounting_clock` gives
    /// each chunk its one engine sample; it reaches this function from the
    /// public door above and, under test cfg only, from the freezing seam.
    fn admit_connector_key_dispatch_batch(
        &self,
        id: &EntityId,
        batch_ref: &str,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
        accounting_clock: impl Fn() -> u64,
    ) -> Result<ConnectorKeyDispatchTally> {
        if batch_ref.trim().is_empty() {
            return Err(invalid_body("batch_ref must not be blank"));
        }
        if batch_ref.len() > CONNECTOR_DISPATCH_BATCH_REF_MAX_LEN {
            return Err(invalid_body("batch_ref too long"));
        }
        if batch_ref.as_bytes().contains(&0) {
            return Err(invalid_body("batch_ref must not contain NUL"));
        }
        let effect_channel = normalize_connector_key(effect_channel);
        if effect_channel.is_empty() {
            return Err(invalid_body("effect channel must not be blank"));
        }
        self.measure_limit(EngineLimit::ConnectorDispatchBatch, count);
        let batch = DispatchBatch {
            key: (*id, batch_ref.to_owned()),
            effect_channel,
            count,
        };
        // The counts come from the batch's row as each writer reads it; the
        // ladder events gather across this call's chunks.
        let mut tally = DispatchBatchProgress::fresh(&batch, 0).tally(telemetry.caller_observed_at);
        loop {
            if self.admit_dispatch_chunk(&batch, accounting_clock(), &mut tally)? {
                return Ok(tally);
            }
        }
    }

    /// One writer's share of a batch, its progress read and written in the
    /// same transaction as its debits and op records (FIX 11058): a call
    /// racing another under the same ref charges only what the row it reads
    /// leaves unsettled. The writer reads the batch's row (a first call starts
    /// one), refuses another channel or count under the ref, and returns
    /// finished without writing when the batch is settled or its rest still
    /// waits for its windows. Otherwise it admits up to one chunk against the
    /// key's live state at `accounting_now`: a refusal settles the whole rest
    /// refused, a pace leaves it waiting until `paced_until`. `tally` takes
    /// the row's counts and the chunk's ladder events once the writer commits.
    /// Returns whether the batch is done for this call.
    fn admit_dispatch_chunk(
        &self,
        batch: &DispatchBatch,
        accounting_now: u64,
        tally: &mut ConnectorKeyDispatchTally,
    ) -> Result<bool> {
        let id = &batch.key.0;
        let mut wtxn = self.store.env.write_txn()?;
        let stored = DISPATCH_BATCH.get(&self.store, &wtxn, &batch.key)?;
        let started = stored.is_none();
        let progress = match stored {
            Some(progress) => {
                if progress.effect_channel != batch.effect_channel || progress.count != batch.count
                {
                    return Err(invalid_body("a batch_ref names one batch"));
                }
                progress
            }
            None => DispatchBatchProgress::fresh(batch, accounting_now),
        };
        if progress.settled() == progress.count
            || progress
                .paced_until
                .is_some_and(|until| until > accounting_now)
        {
            // Nothing to charge. An empty batch's first call still files its
            // row, so the ref names this batch from then on; otherwise the
            // writer aborts and the row stands.
            if started {
                DISPATCH_BATCH.put(&self.store, &mut wtxn, &batch.key, &progress)?;
                wtxn.commit()?;
            }
            progress.report(tally);
            return Ok(true);
        }
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let chunk = (progress.count - progress.settled()).min(CONNECTOR_DISPATCH_TRANSACTION_CHUNK);
        let mut next = progress;
        next.paced_until = None;
        next.last_accounted_at = accounting_now;
        // The dispatches after this chunk, settled with it on a refusal.
        let after = next.count - next.settled() - chunk;
        let mut charges = Vec::new();
        let mut stopped = false;
        for i in 0..chunk {
            if record.status != ConnectorKeyStatus::Active {
                next.refused = next.refused.saturating_add(chunk - i + after);
                stopped = true;
                break;
            }
            match charge_effector_budgets(
                &self.store,
                &mut wtxn,
                id,
                &mut record,
                &next.effect_channel,
                true,
                accounting_now,
            )? {
                EffectorBudgetChargeOutcome::NoRows(charge)
                | EffectorBudgetChargeOutcome::Charged(charge) => {
                    next.admitted = next.admitted.saturating_add(1);
                    charges.push(charge);
                }
                EffectorBudgetChargeOutcome::Exhausted {
                    location,
                    on_exhaust,
                    charge,
                } => {
                    // FIX 8686: an exhausted charge debited nothing, so the
                    // rows read as the charger read them. When every full
                    // one paces, this dispatch and the rest wait, uncharged.
                    if let Some(next_eligible_at) = send_paced_until(
                        &self.store,
                        &wtxn,
                        id,
                        &record,
                        &next.effect_channel,
                        accounting_now,
                    )? {
                        charges.push(charge);
                        next.paced_until = Some(next_eligible_at);
                        stopped = true;
                        break;
                    }
                    if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                        record = suspend_connector_key_in_txn(
                            &self.store,
                            &mut wtxn,
                            id,
                            &record,
                            budget_exhausted_reason(&location),
                            accounting_now,
                        )?;
                        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
                        append_connector_key_op_record(
                            &self.store,
                            &mut wtxn,
                            id,
                            "gate.connector_key.dispatch_suspend",
                            &record,
                            policy.read_frontier_hash()?,
                            accounting_now,
                        )?;
                    }
                    charges.push(charge);
                    next.refused = next.refused.saturating_add(chunk - i + after);
                    stopped = true;
                    break;
                }
            }
        }
        DISPATCH_BATCH.put(&self.store, &mut wtxn, &batch.key, &next)?;
        wtxn.commit()?;
        for charge in charges {
            tally.take_ladder_events(charge);
        }
        next.report(tally);
        Ok(stopped || next.settled() == next.count)
    }
}
