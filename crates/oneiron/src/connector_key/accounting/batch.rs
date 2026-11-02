//! Connector-key batch admission: a batch of send-like dispatches charged
//! through one key, one transaction chunk after another (FIX 8683).
//! Entry: `Vault::admit_connector_key_dispatches`. Defines its own items.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;

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

/// Dispatches one batch-admission writer accounts before it commits and the
/// next writer starts. A transaction chunk, never a bound on the batch: a
/// larger batch is accounted whole, chunk after chunk, and the
/// `ConnectorDispatchBatch` limit row asks past its own count.
pub const CONNECTOR_DISPATCH_TRANSACTION_CHUNK: u64 = 4096;

impl Vault {
    /// Applies the existing effector-budget charger sequentially to a batch
    /// of send-like dispatches through one key.
    ///
    /// Accounting time is the ENGINE clock, sampled ONCE per transaction
    /// chunk: every budget window selection/roll, usage entry, suspension
    /// transition, and op record in a chunk takes that chunk's one sample, so
    /// a chunk cannot straddle two windows and a caller cannot pick the
    /// window it debits. A later chunk samples afresh and never backdates
    /// into an earlier window. `telemetry` carries the caller's own
    /// observation as a declared fact — echoed in the tally, never handed to
    /// the charger.
    pub fn admit_connector_key_dispatches(
        &self,
        id: &EntityId,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
    ) -> Result<ConnectorKeyDispatchTally> {
        self.admit_connector_key_dispatch_batch(id, effect_channel, count, telemetry, || {
            self.store.clock.now_recorded_at()
        })
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
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
        accounting_now: u64,
    ) -> Result<ConnectorKeyDispatchTally> {
        self.admit_connector_key_dispatch_batch(id, effect_channel, count, telemetry, || {
            accounting_now
        })
    }

    /// Sole body of connector-key batch admission. `accounting_clock` gives
    /// each chunk its one engine sample; it reaches this function from the
    /// public door above and, under test cfg only, from the freezing seam.
    fn admit_connector_key_dispatch_batch(
        &self,
        id: &EntityId,
        effect_channel: &str,
        count: u64,
        telemetry: ConnectorDispatchTelemetry,
        accounting_clock: impl Fn() -> u64,
    ) -> Result<ConnectorKeyDispatchTally> {
        let effect_channel = normalize_connector_key(effect_channel);
        if effect_channel.is_empty() {
            return Err(invalid_body("effect channel must not be blank"));
        }
        self.measure_limit(EngineLimit::ConnectorDispatchBatch, count);
        let accounted_at = accounting_clock();
        let mut tally = ConnectorKeyDispatchTally {
            admitted: 0,
            refused: 0,
            ladder_events: Vec::new(),
            pool_key_ref: None,
            pool_ladder_events: Vec::new(),
            accounted_at,
            last_accounted_at: accounted_at,
            caller_observed_at: telemetry.caller_observed_at,
        };
        let mut accounting_now = accounted_at;
        let mut processed = 0_u64;
        loop {
            let chunk = (count - processed).min(CONNECTOR_DISPATCH_TRANSACTION_CHUNK);
            let stopped =
                self.admit_dispatch_chunk(id, &effect_channel, chunk, accounting_now, &mut tally)?;
            processed += chunk;
            tally.last_accounted_at = accounting_now;
            if stopped {
                tally.refused = tally.refused.saturating_add(count - processed);
                break;
            }
            if processed == count {
                break;
            }
            accounting_now = accounting_clock();
        }
        Ok(tally)
    }

    /// One writer's share of a batch: up to `chunk` dispatches against the
    /// key's live state at `accounting_now`. Returns true when the key
    /// stopped admitting (not active, or an exhausted row), after counting
    /// the chunk's unprocessed rest as refused.
    fn admit_dispatch_chunk(
        &self,
        id: &EntityId,
        effect_channel: &str,
        chunk: u64,
        accounting_now: u64,
        tally: &mut ConnectorKeyDispatchTally,
    ) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let mut stopped = false;
        for i in 0..chunk {
            if record.status != ConnectorKeyStatus::Active {
                tally.refused = tally.refused.saturating_add(chunk - i);
                stopped = true;
                break;
            }
            match charge_effector_budgets(
                &self.store,
                &mut wtxn,
                id,
                &mut record,
                effect_channel,
                true,
                accounting_now,
            )? {
                EffectorBudgetChargeOutcome::NoRows(charge)
                | EffectorBudgetChargeOutcome::Charged(charge) => {
                    tally.admitted = tally.admitted.saturating_add(1);
                    tally.take_ladder_events(charge);
                }
                EffectorBudgetChargeOutcome::Exhausted {
                    location,
                    on_exhaust,
                    charge,
                } => {
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
                    tally.take_ladder_events(charge);
                    tally.refused = tally.refused.saturating_add(chunk - i);
                    stopped = true;
                    break;
                }
            }
        }
        wtxn.commit()?;
        Ok(stopped)
    }
}
