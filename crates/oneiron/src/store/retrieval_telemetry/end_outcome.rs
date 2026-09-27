//! Terminal attribution-gated retrieval outcome writer.

use crate::batch::secret_scan;
use crate::error::{Error, Result};
use crate::store::{Store, active_write_txn_depth};

use super::run_store::{
    decode_retrieval_run, encode_retrieval_outcome, retrieval_outcome_key, retrieval_run_key,
    retrieval_run_provisional_key, vet_retrieval_outcome,
};
use super::types::{
    RETRIEVAL_TELEMETRY_VERSION, RetrievalEndOutcome, RetrievalOutcome, RetrievalOutcomeRecord,
    RetrievalRewardEvidence,
};

impl Store {
    /// Link a terminal user confirmation/correction to one surfaced memory.
    /// The gate judgement is supplied by the ARCH-0053 owner, never inferred
    /// from a success flag or from intermediate telemetry. Cost is normalized
    /// from the observed run duration using the producer's fixed scale; hops
    /// also come from the captured run state.
    pub(crate) fn record_retrieval_end_outcome(&self, outcome: RetrievalEndOutcome) -> Result<()> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval end outcome skipped inside active write transaction",
            ));
        }
        let evidence = RetrievalRewardEvidence {
            turn_id: outcome.turn_id,
            activated_memory_id: outcome.activated_memory_id,
            gate_score: outcome.gate_score,
            confirmed_fact_hit: outcome.confirmed_fact_hit,
            latency_scale_us: outcome.latency_scale_us,
            cost_weight: outcome.cost_weight,
        };
        let input = RetrievalOutcome {
            run_id: outcome.run_id,
            key: outcome.key,
            reward: None,
            accepted: Some(outcome.confirmed_fact_hit),
            metadata: outcome.metadata,
        };
        vet_retrieval_outcome(&input)?;
        secret_scan::scan_metadata_field(&input.key)?;
        for (key, value) in &input.metadata {
            secret_scan::scan_metadata_field(key)?;
            secret_scan::scan_metadata_field(value)?;
        }
        let mut wtxn = self.env.write_txn()?;
        let run_key = retrieval_run_key(input.run_id);
        let raw = self.vault_meta.get(&wtxn, &run_key)?.ok_or_else(|| {
            Error::InvalidConfig("retrieval end outcome references unknown run id".to_owned())
        })?;
        if self
            .vault_meta
            .get(&wtxn, &retrieval_run_provisional_key(input.run_id))?
            .is_some()
        {
            return Err(Error::InvalidConfig(
                "retrieval end outcome references unpublished run id".to_owned(),
            ));
        }
        let run = decode_retrieval_run(&raw)?;
        if run.run_id != input.run_id {
            return Err(Error::CorruptedIndex("retrieval run telemetry"));
        }
        let reward = evidence.reward(&run)?;
        let record = RetrievalOutcomeRecord {
            version: RETRIEVAL_TELEMETRY_VERSION,
            run_id: input.run_id,
            key: input.key,
            reward: Some(reward),
            accepted: input.accepted,
            metadata: input.metadata,
            updated_at: self.clock.now_recorded_at(),
            reward_evidence: Some(evidence),
        };
        self.vault_meta.put(
            &mut wtxn,
            &retrieval_outcome_key(record.run_id, &record.key),
            &encode_retrieval_outcome(&record)?,
        )?;
        wtxn.commit()?;
        Ok(())
    }
}
