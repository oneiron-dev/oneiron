//! Terminal attribution-gated retrieval outcome writer.

use std::collections::HashSet;

use crate::batch::secret_scan;
use crate::error::{Error, Result};
use crate::store::{Store, active_write_txn_depth};

use super::run_store::{
    OutcomeKey, RETRIEVAL_OUTCOME, RETRIEVAL_RUN, RETRIEVAL_RUN_PROVISIONAL,
    vet_retrieval_outcome_key,
};
use super::types::{
    RETRIEVAL_TELEMETRY_VERSION, RetrievalEndOutcome, RetrievalOutcomeRecord,
    RetrievalRewardEvidence,
};

impl Store {
    /// Atomically attribute a turn's terminal signal to its exact contributing
    /// retrieval runs. Each gets the full gate signal and its own observed cost,
    /// never a share inferred from activated-memory overlap.
    pub(crate) fn record_retrieval_end_outcome(&self, outcome: RetrievalEndOutcome) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval end outcome skipped inside active write transaction",
            ));
        }
        let contributing: HashSet<_> = outcome.retrieval_run_ids.iter().copied().collect();
        if contributing.len() != outcome.retrieval_run_ids.len() {
            return Err(Error::InvalidConfig(
                "retrieval end outcome contains duplicate run ids".to_owned(),
            ));
        }
        let evidence = RetrievalRewardEvidence {
            retrieval_run_ids: outcome.retrieval_run_ids,
            turn_id: outcome.turn_id,
            gate_score: outcome.gate_score,
            confirmed_fact_hit: outcome.confirmed_fact_hit,
            latency_scale_us: outcome.latency_scale_us,
            cost_weight: outcome.cost_weight,
        };
        evidence.validate()?;
        vet_retrieval_outcome_key(&outcome.key)?;
        secret_scan::scan_metadata_field(&outcome.key)?;
        for (key, value) in &outcome.metadata {
            secret_scan::scan_metadata_field(key)?;
            secret_scan::scan_metadata_field(value)?;
        }
        let mut wtxn = self.env.write_txn()?;
        let updated_at = self.clock.now_recorded_at();
        for run_id in &evidence.retrieval_run_ids {
            let run = RETRIEVAL_RUN.get(self, &wtxn, run_id)?.ok_or_else(|| {
                Error::InvalidConfig("retrieval end outcome references unknown run id".to_owned())
            })?;
            if RETRIEVAL_RUN_PROVISIONAL.contains(self, &wtxn, run_id)? {
                return Err(Error::InvalidConfig(
                    "retrieval end outcome references unpublished run id".to_owned(),
                ));
            }
            if run.run_id != *run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            let reward = evidence.reward(&run)?;
            let record = RetrievalOutcomeRecord {
                version: RETRIEVAL_TELEMETRY_VERSION,
                run_id: *run_id,
                key: outcome.key.clone(),
                reward: Some(reward),
                accepted: Some(outcome.confirmed_fact_hit),
                metadata: outcome.metadata.clone(),
                updated_at,
                reward_evidence: Some(evidence.clone()),
            };
            RETRIEVAL_OUTCOME.put(
                self,
                &mut wtxn,
                &OutcomeKey(*run_id, outcome.key.clone()),
                &record,
            )?;
        }
        // A corrected terminal outcome may remove contributors, including all
        // of them. The turn index is used only to retract those old labels.
        for run_id in super::turn_index::read(self, &wtxn, &outcome.turn_id)? {
            if contributing.contains(&run_id) {
                continue;
            }
            let key = OutcomeKey(run_id, outcome.key.clone());
            if RETRIEVAL_OUTCOME
                .get(self, &wtxn, &key)?
                .and_then(|record| record.reward_evidence)
                .is_some_and(|previous| previous.turn_id == outcome.turn_id)
            {
                RETRIEVAL_OUTCOME.delete(self, &mut wtxn, &key)?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }
}
