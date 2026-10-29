//! Reward-weighted retrieval-blend tuning: weight-table methods, codecs, validators, and gradient math.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};
use oneiron_contracts::retrieval_telemetry::validate_retrieval_blend_weights;

use crate::error::{Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideTable};
use crate::store::{Store, active_write_txn_depth};

use super::run_store::{RETRIEVAL_RUN, retrieval_outcomes_for_run_in_txn};
use super::types::{
    RETRIEVAL_BLEND_TUNER_ALGORITHM, RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION, RetrievalBlendSignal,
    RetrievalBlendTuningConfig, RetrievalBlendWeightDataWindow, RetrievalBlendWeightTableEntry,
    RetrievalBlendWeights, RetrievalOutcomeRecord, RetrievalPolicyCandidate,
    RetrievalPolicyEvaluation, RetrievalPolicyHeldOut, RetrievalPolicyPin, RetrievalPolicyPins,
    RetrievalPolicyVerdict, RetrievalRunRecord, RetrievalSignal, RetrievalWeightOrigin,
    retrieval_weight_rows,
};

/// Kept as a standalone constant (not just `TABLE.decl().prefix`) because
/// `store::tests` plants raw rows at this exact key.
#[cfg(test)]
pub(in crate::store) const RETRIEVAL_BLEND_WEIGHT_TABLE_KEY: &[u8] =
    b"retr_blend_weights:v0:active";

/// Codec fixed `Raw` (see the decls.rs note): decode also re-normalizes the
/// weights and vets provenance, so [`RawValue`] delegates to the module's own
/// `encode_retrieval_blend_weight_table`/`decode_retrieval_blend_weight_table`.
const TABLE: SideTable<(), RetrievalBlendWeightTableEntry, Raw> =
    SideTable::new(&side_table::RETRIEVAL_BLEND_WEIGHTS_ACTIVE);

const PINS: SideTable<(), RetrievalPolicyPins, Named> =
    SideTable::new(&side_table::RETRIEVAL_POLICY_PINS);

/// ARCH-0037's hold-out: the newest accepted run and every fifth after it
/// never train the update; they judge it against the active weights.
const RETRIEVAL_BLEND_HOLDOUT_EVERY: usize = 5;

impl RawValue for RetrievalBlendWeightTableEntry {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_retrieval_blend_weight_table(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_retrieval_blend_weight_table(bytes)?)
    }
}

/// One snapshot of the gated evidence an update trains and is judged on.
struct BlendEvidence {
    previous: RetrievalBlendWeightTableEntry,
    pins: RetrievalPolicyPins,
    gradient: [f64; 5],
    reward_count: usize,
    component_count: usize,
    data_window: RetrievalBlendWeightDataWindow,
    holdout_gradient: [f64; 5],
    holdout_rewards: usize,
    ungated_skipped: u32,
    manifest_digest: String,
}

fn held_out_score(weights: RetrievalBlendWeights, holdout_gradient: [f64; 5]) -> f64 {
    [
        weights.recency,
        weights.salience,
        weights.confidence,
        weights.gravity,
        weights.relevance,
    ]
    .into_iter()
    .zip(holdout_gradient)
    .map(|(weight, credit)| f64::from(weight) * credit)
    .sum()
}

fn held_out_assessment(
    evidence: &BlendEvidence,
    config: RetrievalBlendTuningConfig,
    candidate: RetrievalBlendWeights,
) -> RetrievalPolicyHeldOut {
    let candidate_score = held_out_score(candidate, evidence.holdout_gradient);
    let active_score = held_out_score(evidence.previous.weights, evidence.holdout_gradient);
    let verdict = if evidence.reward_count < config.min_reward_count
        || evidence.component_count == 0
        || evidence.holdout_rewards == 0
    {
        RetrievalPolicyVerdict::Insufficient
    } else if candidate_score < active_score {
        RetrievalPolicyVerdict::Regression
    } else {
        RetrievalPolicyVerdict::NotWorse
    };
    RetrievalPolicyHeldOut {
        candidate_score,
        active_score,
        reward_count: evidence.holdout_rewards as u32,
        verdict,
    }
}

impl Store {
    pub(crate) fn retrieval_blend_weight_table_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let Some(entry) = TABLE.get(self, rtxn, &())? else {
            return Ok(RetrievalBlendWeightTableEntry::bootstrap());
        };
        Ok(entry)
    }

    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        let rtxn = self.env.read_txn()?;
        self.retrieval_blend_weight_table_in_txn(&rtxn)
    }

    fn retrieval_policy_pins_in_txn(&self, rtxn: &RoTxn<'_>) -> Result<RetrievalPolicyPins> {
        let pins = PINS.get(self, rtxn, &())?.unwrap_or_default();
        pins.validate()?;
        Ok(pins)
    }

    /// The owner pins no learned retrieval-policy update may move.
    pub fn retrieval_policy_pins(&self) -> Result<RetrievalPolicyPins> {
        let rtxn = self.env.read_txn()?;
        self.retrieval_policy_pins_in_txn(&rtxn)
    }

    /// Replaces the owner pins and holds the active weights to them, in the
    /// same write transaction. Returns the active entry as now served.
    pub fn put_retrieval_policy_pins(
        &self,
        pins: RetrievalPolicyPins,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        pins.validate()?;
        let _tuning_guard =
            self.tuning_guard("retrieval policy pin skipped inside active write transaction")?;
        let mut wtxn = self.env.write_txn()?;
        let entry = self.write_retrieval_policy_pins_in_txn(&mut wtxn, &pins)?;
        wtxn.commit()?;
        Ok(entry)
    }

    /// Sets one owner pin at `value`, or clears it when `value` is absent,
    /// merging against the pins read inside the same write transaction so
    /// a concurrent pin change is never silently dropped.
    pub fn put_retrieval_policy_pin(
        &self,
        signal: RetrievalBlendSignal,
        value: Option<f32>,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let _tuning_guard =
            self.tuning_guard("retrieval policy pin skipped inside active write transaction")?;
        let mut wtxn = self.env.write_txn()?;
        let mut pins = self.retrieval_policy_pins_in_txn(&wtxn)?;
        pins.pins.retain(|pin| pin.signal != signal);
        if let Some(value) = value {
            pins.pins.push(RetrievalPolicyPin { signal, value });
        }
        pins.validate()?;
        let entry = self.write_retrieval_policy_pins_in_txn(&mut wtxn, &pins)?;
        wtxn.commit()?;
        Ok(entry)
    }

    fn write_retrieval_policy_pins_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        pins: &RetrievalPolicyPins,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let previous = self.retrieval_blend_weight_table_in_txn(wtxn)?;
        let mut provenance = previous.provenance.clone();
        provenance.insert("owner_pins".to_owned(), pins.pins.len().to_string());
        let entry = RetrievalBlendWeightTableEntry {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights: pins.apply(previous.weights)?,
            tuned_at: self.clock.now_recorded_at(),
            provenance,
            data_window: previous.data_window.clone(),
        };
        vet_retrieval_blend_weight_table_entry(&entry)
            .map_err(|_| Error::InvalidConfig("invalid retrieval blend weight table".to_owned()))?;
        PINS.put(self, wtxn, &(), pins)?;
        TABLE.put(self, wtxn, &(), &entry)?;
        Ok(entry)
    }

    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        self.tune_retrieval_blend_weights_when_ready(config)?
            .map_err(Error::InvalidConfig)
    }

    fn tuning_guard(&self, what: &'static str) -> Result<std::sync::MutexGuard<'_, ()>> {
        if active_write_txn_depth() > 0 {
            return Err(Error::ConcurrentWrite(what));
        }
        self.retrieval_blend_tuning_lock
            .lock()
            .map_err(|_| Error::InvariantViolation("retrieval blend tuning mutex poisoned"))
    }

    /// [`Self::tune_retrieval_blend_weights`] for the Coach's nightly pass: a
    /// window without enough gated rewards is an answer, `Ok(Err(reason))`,
    /// and writes nothing.
    pub(crate) fn tune_retrieval_blend_weights_when_ready(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<std::result::Result<RetrievalBlendWeightTableEntry, String>> {
        validate_retrieval_blend_tuning_config(config)?;
        let _tuning_guard = self.tuning_guard(
            "retrieval blend weight tuning skipped inside active write transaction",
        )?;
        let evidence = self.collect_blend_evidence(config)?;
        if evidence.reward_count < config.min_reward_count {
            return Ok(Err(format!(
                "retrieval blend tuning requires at least {} reward outcome(s), found {}",
                config.min_reward_count, evidence.reward_count
            )));
        }
        if evidence.component_count == 0 {
            return Ok(Err(
                "retrieval blend tuning requires blend-signal score components".to_owned(),
            ));
        }
        let weights = evidence.pins.apply(apply_retrieval_blend_weight_update(
            evidence.previous.weights,
            evidence.gradient,
            config.learning_rate,
            evidence.reward_count,
        )?)?;
        // The update replaces the active row only when it does no worse than
        // the active weights on the held-out runs it never trained on.
        if evidence.holdout_rewards == 0 {
            return Ok(Err(
                "retrieval blend tuning requires a held-out reward outcome".to_owned(),
            ));
        }
        if held_out_score(weights, evidence.holdout_gradient)
            < held_out_score(evidence.previous.weights, evidence.holdout_gradient)
        {
            return Ok(Err(
                "retrieval blend tuning update did not pass the held-out gate".to_owned(),
            ));
        }
        Ok(Ok(self.write_admitted_entry(&evidence, config, weights)?))
    }

    /// Trains a candidate over the current gated evidence without serving
    /// it. Owner pins are held; too little evidence yields the active
    /// weights as the candidate with an `Insufficient` verdict.
    pub fn train_retrieval_policy_candidate(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalPolicyCandidate> {
        validate_retrieval_blend_tuning_config(config)?;
        let _tuning_guard =
            self.tuning_guard("retrieval policy training skipped inside active write transaction")?;
        let evidence = self.collect_blend_evidence(config)?;
        let weights = if evidence.reward_count > 0 && evidence.component_count > 0 {
            evidence.pins.apply(apply_retrieval_blend_weight_update(
                evidence.previous.weights,
                evidence.gradient,
                config.learning_rate,
                evidence.reward_count,
            )?)?
        } else {
            evidence.pins.apply(evidence.previous.weights)?
        };
        Ok(RetrievalPolicyCandidate {
            rows: retrieval_weight_rows(weights, &evidence.pins, RetrievalWeightOrigin::Learned),
            held_out: held_out_assessment(&evidence, config, weights),
            training_reward_count: evidence.reward_count as u32,
            ungated_outcomes_skipped: evidence.ungated_skipped,
            manifest_digest: evidence.manifest_digest.clone(),
            data_window: evidence.data_window.clone(),
            weights,
            algorithm: RETRIEVAL_BLEND_TUNER_ALGORITHM.to_owned(),
        })
    }

    /// Judges caller-supplied candidate weights on the same held-out runs
    /// the tuner trains against. Read-only; nothing is served or stored.
    pub fn evaluate_retrieval_policy_candidate(
        &self,
        config: RetrievalBlendTuningConfig,
        weights: RetrievalBlendWeights,
    ) -> Result<RetrievalPolicyEvaluation> {
        validate_retrieval_blend_tuning_config(config)?;
        let weights = weights.normalized()?;
        let _tuning_guard = self
            .tuning_guard("retrieval policy evaluation skipped inside active write transaction")?;
        let evidence = self.collect_blend_evidence(config)?;
        Ok(RetrievalPolicyEvaluation {
            candidate_weights: weights,
            active_weights: evidence.previous.weights,
            rows: retrieval_weight_rows(weights, &evidence.pins, RetrievalWeightOrigin::Learned),
            manifest_digest: evidence.manifest_digest.clone(),
            held_out: held_out_assessment(&evidence, config, weights),
            pins_respected: evidence.pins.respects(weights),
            ungated_outcomes_skipped: evidence.ungated_skipped,
        })
    }

    /// Admits candidate weights as the active table only when they were
    /// trained and judged on the current manifest, hold every owner pin,
    /// and do no worse than the active weights on the held-out runs.
    pub fn admit_retrieval_policy_candidate(
        &self,
        config: RetrievalBlendTuningConfig,
        weights: RetrievalBlendWeights,
        expected_manifest_digest: &str,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        validate_retrieval_blend_tuning_config(config)?;
        let weights = weights.normalized()?;
        let _tuning_guard = self
            .tuning_guard("retrieval policy admission skipped inside active write transaction")?;
        let evidence = self.collect_blend_evidence(config)?;
        if evidence.manifest_digest != expected_manifest_digest {
            return Err(Error::InvalidConfig(
                "retrieval policy candidate was judged on a stale evidence manifest".to_owned(),
            ));
        }
        if !evidence.pins.respects(weights) {
            return Err(Error::InvalidConfig(
                "retrieval policy candidate would overwrite an owner-pinned weight".to_owned(),
            ));
        }
        match held_out_assessment(&evidence, config, weights).verdict {
            RetrievalPolicyVerdict::NotWorse => {}
            RetrievalPolicyVerdict::Regression => {
                return Err(Error::InvalidConfig(
                    "retrieval policy candidate regressed on held-out runs".to_owned(),
                ));
            }
            RetrievalPolicyVerdict::Insufficient => {
                return Err(Error::InvalidConfig(
                    "retrieval policy candidate lacks held-out evidence for admission".to_owned(),
                ));
            }
        }
        self.write_admitted_entry(&evidence, config, weights)
    }

    /// Writes an admitted weight set, re-checking inside the write
    /// transaction that the pins and the active entry it was judged against
    /// are still the ones in force.
    fn write_admitted_entry(
        &self,
        evidence: &BlendEvidence,
        config: RetrievalBlendTuningConfig,
        weights: RetrievalBlendWeights,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        let held_out = held_out_assessment(evidence, config, weights);
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
            evidence.previous.tuned_at.to_string(),
        );
        provenance.insert(
            "manifest_digest".to_owned(),
            evidence.manifest_digest.clone(),
        );
        provenance.insert(
            "held_out_candidate_score".to_owned(),
            held_out.candidate_score.to_string(),
        );
        provenance.insert(
            "held_out_active_score".to_owned(),
            held_out.active_score.to_string(),
        );
        let entry = RetrievalBlendWeightTableEntry {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights,
            tuned_at: self.clock.now_recorded_at(),
            provenance,
            data_window: evidence.data_window.clone(),
        };
        vet_retrieval_blend_weight_table_entry(&entry)
            .map_err(|_| Error::InvalidConfig("invalid retrieval blend weight table".to_owned()))?;
        let mut wtxn = self.env.write_txn()?;
        let current_pins = self.retrieval_policy_pins_in_txn(&wtxn)?;
        let current = self.retrieval_blend_weight_table_in_txn(&wtxn)?;
        if current_pins != evidence.pins
            || !current_pins.respects(weights)
            || current.tuned_at != evidence.previous.tuned_at
            || current.weights != evidence.previous.weights
        {
            return Err(Error::InvalidConfig(
                "retrieval policy changed under the candidate; retrain before admission".to_owned(),
            ));
        }
        TABLE.put(self, &mut wtxn, &(), &entry)?;
        wtxn.commit()?;
        Ok(entry)
    }

    fn collect_blend_evidence(&self, config: RetrievalBlendTuningConfig) -> Result<BlendEvidence> {
        let rtxn = self.env.read_txn()?;
        let previous = self.retrieval_blend_weight_table_in_txn(&rtxn)?;
        let pins = self.retrieval_policy_pins_in_txn(&rtxn)?;
        let mut gradient = [0.0_f64; 5];
        let mut reward_count = 0_usize;
        let mut component_count = 0_usize;
        let mut data_window = RetrievalBlendWeightDataWindow::default();
        let mut holdout_gradient = [0.0_f64; 5];
        let mut holdout_rewards = 0_usize;
        let mut ungated_skipped = 0_u32;
        let mut manifest = String::new();
        manifest.push_str(RETRIEVAL_BLEND_TUNER_ALGORITHM);
        manifest.push_str(&format!(
            "\nconfig:{}:{}:{}",
            config.max_runs,
            config.learning_rate.to_bits(),
            config.min_reward_count
        ));
        manifest.push_str(&format!(
            "\nprevious:{}:{}:{}:{}:{}:{}",
            previous.tuned_at,
            previous.weights.recency.to_bits(),
            previous.weights.salience.to_bits(),
            previous.weights.confidence.to_bits(),
            previous.weights.gravity.to_bits(),
            previous.weights.relevance.to_bits()
        ));
        for pin in &pins.pins {
            manifest.push_str(&format!("\npin:{:?}:{}", pin.signal, pin.value.to_bits()));
        }

        let mut accepted_runs = 0_usize;
        // Provisional runs are read and passed over until the sample is full:
        // past the ledger's threshold row the walk raises one check and reads
        // on, so no finalized run is lost to the provisional ones before it.
        let mut scanned = ScanCount::start(self, &rtxn, EngineScan::BlendTuningRuns, &[])?;
        for row in RETRIEVAL_RUN.iter_rev_from(self, &rtxn, &[])? {
            if accepted_runs == config.max_runs {
                break;
            }
            let (run_id, record) = row?;
            scanned.row();
            if super::run_store::RETRIEVAL_RUN_PROVISIONAL.contains(self, &rtxn, &run_id)? {
                continue;
            }
            if record.run_id != run_id {
                return Err(Error::CorruptedIndex("retrieval run telemetry"));
            }
            accepted_runs += 1;
            let held_out = (accepted_runs - 1) % RETRIEVAL_BLEND_HOLDOUT_EVERY == 0;
            manifest.push_str(&format!(
                "\nrun:{}:{}:{}",
                run_id.to_hex(),
                record.started_at,
                held_out
            ));

            let outcomes = retrieval_outcomes_for_run_in_txn(self, &rtxn, run_id)?;
            let run_reward_count_before = reward_count;
            let run_candidate_count_before = data_window.candidate_count;
            for outcome in &outcomes {
                let Some(evidence) = &outcome.reward_evidence else {
                    ungated_skipped = ungated_skipped.saturating_add(1);
                    continue;
                };
                let computed = evidence
                    .reward(&record)
                    .map_err(|_| Error::CorruptedIndex("retrieval gated reward"))?;
                if outcome.reward != Some(computed)
                    || outcome.accepted != Some(evidence.confirmed_fact_hit)
                {
                    return Err(Error::CorruptedIndex("retrieval gated reward"));
                }
                manifest.push_str(&format!(
                    "\noutcome:{}:{}",
                    outcome.updated_at,
                    computed.to_bits()
                ));
                let reward = f64::from(computed);
                let mut outcome_gradient = [0.0_f64; 5];
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
                if held_out {
                    for (total, outcome) in holdout_gradient.iter_mut().zip(outcome_gradient) {
                        *total += outcome;
                    }
                    holdout_rewards += 1;
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
        scanned.defer(self);
        Ok(BlendEvidence {
            previous,
            pins,
            gradient,
            reward_count,
            component_count,
            data_window,
            holdout_gradient,
            holdout_rewards,
            ungated_skipped,
            manifest_digest: blake3::hash(manifest.as_bytes()).to_hex().to_string(),
        })
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
        RetrievalBlendSignal::Relevance => Some(4),
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
    gradient: [f64; 5],
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
        f64::from(previous.relevance) + learning_rate * gradient[4] / reward_scale,
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
        (next[4] / sum) as f32,
    )
    .normalized()
}
