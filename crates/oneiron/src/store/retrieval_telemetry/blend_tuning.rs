//! Reward-weighted retrieval-blend tuning: weight-table methods, codecs, validators, and gradient math.

use std::collections::BTreeMap;

use heed::RoTxn;

use crate::error::{Error, Result};
use crate::store::{Store, active_write_txn_depth};

use super::run_store::{
    RETRIEVAL_RUN_KEY_PREFIX, decode_retrieval_run, retrieval_outcomes_for_run_in_txn,
    retrieval_run_id_from_key, retrieval_run_provisional_key, retrieval_run_upper_bound,
};
use super::types::{
    RETRIEVAL_BLEND_TUNER_ALGORITHM, RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION, RetrievalBlendSignal,
    RetrievalBlendTuningConfig, RetrievalBlendWeightDataWindow, RetrievalBlendWeightTableEntry,
    RetrievalBlendWeights, RetrievalOutcomeRecord, RetrievalRunRecord, RetrievalSignal,
};

pub(in crate::store) const RETRIEVAL_BLEND_WEIGHT_TABLE_KEY: &[u8] =
    b"retr_blend_weights:v0:active";

impl Store {
    pub(crate) fn retrieval_blend_weight_table_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let Some(value) = self
            .vault_meta
            .get(rtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY)?
        else {
            return Ok(RetrievalBlendWeightTableEntry::bootstrap());
        };
        decode_retrieval_blend_weight_table(&value)
    }

    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        let rtxn = self.env.read_txn()?;
        self.retrieval_blend_weight_table_in_txn(&rtxn)
    }

    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        validate_retrieval_blend_tuning_config(config)?;
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(
                "retrieval blend weight tuning skipped inside active write transaction",
            ));
        }
        let _tuning_guard = self
            .retrieval_blend_tuning_lock
            .lock()
            .map_err(|_| Error::InvariantViolation("retrieval blend tuning mutex poisoned"))?;

        let rtxn = self.env.read_txn()?;
        let previous = self.retrieval_blend_weight_table_in_txn(&rtxn)?;
        let upper = retrieval_run_upper_bound();
        let mut gradient = [0.0_f64; 4];
        let mut reward_count = 0_usize;
        let mut component_count = 0_usize;
        let mut data_window = RetrievalBlendWeightDataWindow::default();

        let mut accepted_runs = 0_usize;
        for row in self.vault_meta.rev_range(
            &rtxn,
            &(
                std::ops::Bound::Included(RETRIEVAL_RUN_KEY_PREFIX),
                std::ops::Bound::Excluded(upper.as_slice()),
            ),
        )? {
            let (key, value) = row?;
            if !key.starts_with(RETRIEVAL_RUN_KEY_PREFIX) {
                break;
            }
            let run_id = retrieval_run_id_from_key(&key)?;
            if self
                .vault_meta
                .get(&rtxn, &retrieval_run_provisional_key(run_id))?
                .is_some()
            {
                continue;
            }
            let record = decode_retrieval_run(&value)?;
            if record.run_id != run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            if accepted_runs == config.max_runs {
                break;
            }
            accepted_runs += 1;

            let outcomes = retrieval_outcomes_for_run_in_txn(&self.vault_meta, &rtxn, run_id)?;
            let run_reward_count_before = reward_count;
            let run_candidate_count_before = data_window.candidate_count;
            for outcome in outcomes.iter().filter(|outcome| outcome.reward.is_some()) {
                let reward = f64::from(outcome.reward.expect("filtered reward"));
                let mut outcome_gradient = [0.0_f64; 4];
                let mut outcome_component_count = 0_usize;
                let mut outcome_candidate_count = 0_u32;
                for candidate in &record.score_breakdown {
                    let rank_credit = 1.0 / f64::from(candidate.final_rank.max(1));
                    let mut candidate_has_blend_component = false;
                    for component in &candidate.components {
                        let Some(index) = retrieval_blend_component_index(component.signal) else {
                            continue;
                        };
                        if !component.score.is_finite() {
                            return Err(Error::CorruptedIndex("retrieval blend tuning"));
                        }
                        outcome_gradient[index] +=
                            reward * rank_credit * f64::from(component.score);
                        outcome_component_count += 1;
                        candidate_has_blend_component = true;
                    }
                    if candidate_has_blend_component {
                        outcome_candidate_count = outcome_candidate_count.saturating_add(1);
                    }
                }
                if outcome_component_count == 0 {
                    continue;
                }
                for (total, outcome) in gradient.iter_mut().zip(outcome_gradient) {
                    *total += outcome;
                }
                component_count += outcome_component_count;
                reward_count += 1;
                observe_retrieval_blend_outcome(&mut data_window, outcome);
                data_window.candidate_count = data_window
                    .candidate_count
                    .saturating_add(outcome_candidate_count);
            }
            if reward_count > run_reward_count_before
                && data_window.candidate_count > run_candidate_count_before
            {
                observe_retrieval_blend_run(&mut data_window, &record);
            }
        }
        drop(rtxn);

        if reward_count < config.min_reward_count {
            return Err(Error::InvalidConfig(format!(
                "retrieval blend tuning requires at least {} reward outcome(s), found {reward_count}",
                config.min_reward_count
            )));
        }
        if component_count == 0 {
            return Err(Error::InvalidConfig(
                "retrieval blend tuning requires blend-signal score components".to_owned(),
            ));
        }

        let weights = apply_retrieval_blend_weight_update(
            previous.weights,
            gradient,
            config.learning_rate,
            reward_count,
        )?;
        let mut provenance = BTreeMap::new();
        provenance.insert("source".to_owned(), "RetrievalOutcomeRecord".to_owned());
        provenance.insert(
            "algorithm".to_owned(),
            RETRIEVAL_BLEND_TUNER_ALGORITHM.to_owned(),
        );
        provenance.insert("max_runs".to_owned(), config.max_runs.to_string());
        provenance.insert("learning_rate".to_owned(), config.learning_rate.to_string());
        provenance.insert(
            "previous_tuned_at".to_owned(),
            previous.tuned_at.to_string(),
        );
        let entry = RetrievalBlendWeightTableEntry {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights,
            tuned_at: crate::unix_seconds_now(),
            provenance,
            data_window,
        };
        self.put_retrieval_blend_weight_table_entry(&entry)?;
        Ok(entry)
    }

    fn put_retrieval_blend_weight_table_entry(
        &self,
        entry: &RetrievalBlendWeightTableEntry,
    ) -> Result<()> {
        vet_retrieval_blend_weight_table_entry(entry)
            .map_err(|_| Error::InvalidConfig("invalid retrieval blend weight table".to_owned()))?;
        let value = encode_retrieval_blend_weight_table(entry)?;
        let mut wtxn = self.env.write_txn()?;
        self.vault_meta
            .put(&mut wtxn, RETRIEVAL_BLEND_WEIGHT_TABLE_KEY, &value)?;
        wtxn.commit()?;
        Ok(())
    }
}

fn encode_retrieval_blend_weight_table(entry: &RetrievalBlendWeightTableEntry) -> Result<Vec<u8>> {
    vet_retrieval_blend_weight_table_entry(entry)?;
    rmp_serde::to_vec_named(entry)
        .map_err(|_| Error::InvariantViolation("retrieval blend weight table encode failed"))
}

fn decode_retrieval_blend_weight_table(raw: &[u8]) -> Result<RetrievalBlendWeightTableEntry> {
    let mut entry: RetrievalBlendWeightTableEntry = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    vet_retrieval_blend_weight_table_entry(&entry)?;
    entry.weights = entry
        .weights
        .normalized()
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    Ok(entry)
}

fn vet_retrieval_blend_weight_table_entry(entry: &RetrievalBlendWeightTableEntry) -> Result<()> {
    if entry.version != RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION
        || entry.provenance.is_empty()
        || !entry.provenance.contains_key("source")
        || !entry.provenance.contains_key("algorithm")
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    validate_retrieval_blend_weights(entry.weights)
        .map_err(|_| Error::CorruptedIndex("retrieval blend weight table"))?;
    if entry.data_window.outcome_count > 0
        && (entry.data_window.outcome_updated_at_min.is_none()
            || entry.data_window.outcome_updated_at_max.is_none())
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    if entry.data_window.run_count > 0
        && (entry.data_window.started_at_min.is_none()
            || entry.data_window.started_at_max.is_none())
    {
        return Err(Error::CorruptedIndex("retrieval blend weight table"));
    }
    Ok(())
}

pub(super) fn validate_retrieval_blend_weights(
    weights: RetrievalBlendWeights,
) -> std::result::Result<(), String> {
    let values = [
        ("recency", weights.recency),
        ("salience", weights.salience),
        ("confidence", weights.confidence),
        ("gravity", weights.gravity),
    ];
    for (name, value) in values {
        if !value.is_finite() || value < 0.0 {
            return Err(format!(
                "retrieval blend {name} weight must be finite and non-negative"
            ));
        }
    }
    if weights.sum() <= 0.0 {
        return Err("retrieval blend weights must have positive total mass".to_owned());
    }
    Ok(())
}

fn validate_retrieval_blend_tuning_config(config: RetrievalBlendTuningConfig) -> Result<()> {
    if config.max_runs == 0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning max_runs must be positive".to_owned(),
        ));
    }
    if config.min_reward_count == 0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning min_reward_count must be positive".to_owned(),
        ));
    }
    if !config.learning_rate.is_finite() || config.learning_rate <= 0.0 {
        return Err(Error::InvalidConfig(
            "retrieval blend tuning learning_rate must be finite and positive".to_owned(),
        ));
    }
    Ok(())
}

fn retrieval_blend_component_index(signal: RetrievalSignal) -> Option<usize> {
    match signal.as_blend_signal()? {
        RetrievalBlendSignal::Recency => Some(0),
        RetrievalBlendSignal::Salience => Some(1),
        RetrievalBlendSignal::Confidence => Some(2),
        RetrievalBlendSignal::Gravity => Some(3),
    }
}

fn observe_retrieval_blend_run(
    data_window: &mut RetrievalBlendWeightDataWindow,
    record: &RetrievalRunRecord,
) {
    data_window.run_count = data_window.run_count.saturating_add(1);
    data_window.started_at_min = Some(
        data_window
            .started_at_min
            .map_or(record.started_at, |current| current.min(record.started_at)),
    );
    data_window.started_at_max = Some(
        data_window
            .started_at_max
            .map_or(record.started_at, |current| current.max(record.started_at)),
    );
}

fn observe_retrieval_blend_outcome(
    data_window: &mut RetrievalBlendWeightDataWindow,
    record: &RetrievalOutcomeRecord,
) {
    data_window.outcome_count = data_window.outcome_count.saturating_add(1);
    data_window.outcome_updated_at_min = Some(
        data_window
            .outcome_updated_at_min
            .map_or(record.updated_at, |current| current.min(record.updated_at)),
    );
    data_window.outcome_updated_at_max = Some(
        data_window
            .outcome_updated_at_max
            .map_or(record.updated_at, |current| current.max(record.updated_at)),
    );
}

pub(in crate::store) fn apply_retrieval_blend_weight_update(
    previous: RetrievalBlendWeights,
    gradient: [f64; 4],
    learning_rate: f32,
    reward_count: usize,
) -> Result<RetrievalBlendWeights> {
    let reward_scale = reward_count.max(1) as f64;
    let learning_rate = f64::from(learning_rate);
    let mut next = [
        f64::from(previous.recency) + learning_rate * gradient[0] / reward_scale,
        f64::from(previous.salience) + learning_rate * gradient[1] / reward_scale,
        f64::from(previous.confidence) + learning_rate * gradient[2] / reward_scale,
        f64::from(previous.gravity) + learning_rate * gradient[3] / reward_scale,
    ];
    for value in &mut next {
        if !value.is_finite() {
            return Err(Error::InvalidConfig(
                "retrieval blend tuning produced non-finite weight".to_owned(),
            ));
        }
        *value = value.max(0.0);
    }
    let sum = next.iter().sum::<f64>();
    if sum <= f64::EPSILON {
        return previous.normalized();
    }
    RetrievalBlendWeights::new(
        (next[0] / sum) as f32,
        (next[1] / sum) as f32,
        (next[2] / sum) as f32,
        (next[3] / sum) as f32,
    )
    .normalized()
}
