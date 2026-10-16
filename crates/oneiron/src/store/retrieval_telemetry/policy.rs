//! Account-local learned retrieval state, rebuilt only by the Coach at sleep.

use crate::error::{Error, Result};
use crate::pipeline::retrieval_policy::{RetrievalPolicyAction, RetrievalPolicyPosterior};
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, SideTable};
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
    pub(crate) fn update_retrieval_policy_at_sleep(&self) -> Result<usize> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval policy update skipped inside active write transaction",
            ));
        }
        let _guard = self
            .retrieval_blend_tuning_lock
            .lock()
            .map_err(|_| Error::InvariantViolation("retrieval tuning mutex poisoned"))?;
        let txn = self.env.read_txn()?;
        let mut posterior = RetrievalPolicyPosterior::default();
        let mut scanned = ScanCount::start(self, &txn, EngineScan::BlendTuningRuns, &[])?;
        let mut accepted_runs = 0;
        for row in RETRIEVAL_RUN.iter_rev_from(self, &txn, &[])? {
            if accepted_runs == RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT {
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
            let Some(trace) = &run.policy_trace else {
                continue;
            };
            accepted_runs += 1;
            trace.validate()?;
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
            // One run contributes at most one pull across its decisions, even
            // when several terminal attributions name it explicitly.
            let decisions = trace
                .decisions
                .iter()
                .filter(|d| d.action != RetrievalPolicyAction::Search)
                .count();
            let reward = ((reward / f64::from(labels)).clamp(-1.0, 1.0) + 1.0) / 2.0;
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
        drop(txn);
        scanned.defer(self);
        posterior.tuned_at = self.clock.now_recorded_at();
        posterior.validate()?;
        let mut txn = self.env.write_txn()?;
        POSTERIOR.put(self, &mut txn, &(), &posterior)?;
        txn.commit()?;
        Ok(posterior.labeled_runs)
    }
}
