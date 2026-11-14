//! Account-local learned retrieval state, rebuilt only by the Coach at sleep.

use std::collections::BTreeMap;

use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::EngineScan;
use crate::store::read_shape_policy::{
    AttemptRunEvidence, put_read_shape_posterior_in_txn, rebuild_read_shape_posterior_in_txn,
};
use crate::store::retrieval_policy::{RetrievalPolicyAction, RetrievalPolicyPosterior};
use crate::store::scan_count::ScanCount;
use crate::store::{Store, active_write_txn_depth};

use super::run_store::{
    RETRIEVAL_RUN, RETRIEVAL_RUN_PROVISIONAL, RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT,
    retrieval_outcomes_for_run_in_txn,
};

// A posterior is learned Layer-2 state, not a policy manifest or a new database.
const POSTERIOR: SideTable<(), RetrievalPolicyPosterior, Named> =
    SideTable::new(&side_table::RETRIEVAL_POLICY_POSTERIOR);

impl Store {
    pub(crate) fn retrieval_policy_posterior(&self) -> Result<RetrievalPolicyPosterior> {
        let txn = self.env.read_txn()?;
        let posterior = POSTERIOR.get(self, &txn, &())?.unwrap_or_default();
        posterior.validate()?;
        Ok(posterior)
    }

    /// Rebuild the bounded posterior from terminal, attribution-gated labels.
    /// Rebuilding makes repeated nights and corrected outcomes idempotent:
    /// the same run is never counted as another pull merely because time passed.
    ///
    /// The same pass rebuilds the read-shape arm family from the labelled
    /// runs that name their dispatch attempt (ARCH-0053 #one-bandit-pick-rules:
    /// one posterior, one attribution gate, one update at sleep), and writes
    /// both posteriors in one transaction.
    pub(crate) fn update_retrieval_policy_at_sleep(&self) -> Result<usize> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval policy update skipped inside active write transaction",
            ));
        }
        // The runs' rows may still be queued detached writes (FIX 12023).
        self.wait_for_deferred_commits();
        let _guard = self
            .retrieval_blend_tuning_lock
            .lock()
            .map_err(|_| Error::InvariantViolation("retrieval tuning mutex poisoned"))?;
        let txn = self.env.read_txn()?;
        let mut posterior = RetrievalPolicyPosterior::default();
        let mut scanned = ScanCount::start(self, &txn, EngineScan::BlendTuningRuns, &[])?;
        let mut accepted_runs = 0;
        let mut attempt_runs = 0;
        let mut attempts: BTreeMap<AttemptId, AttemptRunEvidence> = BTreeMap::new();
        for row in RETRIEVAL_RUN.iter_rev_from(self, &txn, &[])? {
            if accepted_runs == RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT
                && attempt_runs == RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT
            {
                break;
            }
            let (id, run) = row?;
            scanned.row();
            if RETRIEVAL_RUN_PROVISIONAL.contains(self, &txn, &id)? {
                continue;
            }
            if id != run.run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            let trace = run
                .policy_trace
                .as_ref()
                .filter(|_| accepted_runs < RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT);
            let attempt = run
                .dispatch_attempt
                .filter(|_| attempt_runs < RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT);
            if trace.is_none() && attempt.is_none() {
                continue;
            }
            if let Some(trace) = trace {
                accepted_runs += 1;
                trace.validate()?;
            }
            if attempt.is_some() {
                attempt_runs += 1;
            }
            let mut reward = 0.0;
            let mut gate = 0.0;
            let mut labels = 0_u32;
            for outcome in retrieval_outcomes_for_run_in_txn(self, &txn, id)? {
                let Some(evidence) = outcome.reward_evidence else {
                    continue;
                };
                let computed = evidence
                    .reward(&run)
                    .map_err(|_| Error::CorruptedIndex("retrieval gated reward"))?;
                if outcome.reward != Some(computed)
                    || outcome.accepted != Some(evidence.confirmed_fact_hit)
                {
                    return Err(Error::CorruptedIndex("retrieval gated reward"));
                }
                reward += f64::from(computed);
                gate += f64::from(evidence.gate_score);
                labels += 1;
            }
            if labels == 0 {
                continue;
            }
            let reward = ((reward / f64::from(labels)).clamp(-1.0, 1.0) + 1.0) / 2.0;
            if let Some(attempt) = attempt {
                attempts
                    .entry(attempt)
                    .or_default()
                    .add_run(reward, gate / f64::from(labels));
            }
            let Some(trace) = trace else {
                continue;
            };
            // One run contributes at most one pull across its decisions, even
            // when several terminal attributions name it explicitly.
            let decisions = trace
                .decisions
                .iter()
                .filter(|d| d.action != RetrievalPolicyAction::Search)
                .count();
            let weight = gate / f64::from(labels) / decisions.max(1) as f64;
            for decision in &trace.decisions {
                if decision.action != RetrievalPolicyAction::Search {
                    posterior.observe(
                        trace.identity,
                        &decision.state,
                        decision.action,
                        reward,
                        weight,
                    )?;
                }
            }
            posterior.labeled_runs += 1;
        }
        let mut shapes = rebuild_read_shape_posterior_in_txn(self, &txn, &attempts)?;
        drop(txn);
        scanned.defer(self);
        posterior.tuned_at = self.clock.now_recorded_at();
        posterior.validate()?;
        shapes.tuned_at = posterior.tuned_at;
        let mut txn = self.env.write_txn()?;
        POSTERIOR.put(self, &mut txn, &(), &posterior)?;
        put_read_shape_posterior_in_txn(self, &mut txn, &shapes)?;
        txn.commit()?;
        Ok(posterior.labeled_runs)
    }
}
