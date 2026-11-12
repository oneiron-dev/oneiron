//! Mechanical candidate selection. Numeric policy is a reloadable row, not a judge instruction.
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Operator-set candidate-selection policy row. Key: ().
const SELECTION: SideTable<(), SelectionConfig, LegacyJson> =
    SideTable::new(&side_table::DREAMER_CONSOLIDATION_SELECTION);

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrengthWeights {
    pub type_prior: f64,
    pub frequency: f64,
    pub recency: f64,
    pub diversity: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionConfig {
    pub version: u8,
    pub soak_ms: u64,
    pub evidence_minimum: usize,
    pub cosine_threshold: f64,
    pub weights: StrengthWeights,
    pub type_priors: BTreeMap<String, f64>,
    pub default_type_prior: f64,
    pub frequency_scale: u64,
    pub diversity_scale: u64,
    pub recency_window_ms: u64,
    /// Maximum extraction calls in flight; low-trust partitions still run serially.
    pub extraction_parallelism: usize,
    /// Maximum TURNs in one neighbourhood child.
    pub extraction_turns_per_child: usize,
    /// Maximum Micro or Meso partitions extracting side by side in one
    /// wake pass ([`windowed_partition`]); their resolves and commits stay
    /// serial in admission order.
    #[serde(default = "default_partition_extraction_parallelism")]
    pub partition_extraction_parallelism: usize,
}

/// The consolidation scopes whose plain partitions share a wake pass's
/// extraction window: Micro, and Meso (a sitting's round, one partition per
/// conversation). A Macro pass runs concurrent executors instead.
const WINDOWED_SCOPES: [crate::dreamer_runner::DreamerConsolidationScope; 2] = [
    crate::dreamer_runner::DreamerConsolidationScope::Micro,
    crate::dreamer_runner::DreamerConsolidationScope::Meso,
];

/// Whether an attempt of queue `kind` with payload `attempt_type` is a
/// plain partition of a windowed scope: that scope's own consolidation
/// kind and attempt type.
pub(crate) fn windowed_partition(kind: &str, attempt_type: &str) -> bool {
    WINDOWED_SCOPES
        .iter()
        .any(|scope| kind == scope.attempt_kind() && attempt_type == scope.as_str())
}

/// Whether an attempt of queue `kind` with payload `attempt_type` is a
/// sieve rung job (a span reading, a window audit or a TURN's typing
/// carrier), which a window runs whole beside its partitions: its evidence
/// check, its model reading and its commit are its own spans', so no other
/// slot's outcome moves it.
pub(crate) fn windowed_rung(kind: &str, attempt_type: &str) -> bool {
    kind == crate::dreamer_runner::DreamerConsolidationScope::Micro.attempt_kind()
        && (attempt_type == crate::dreamer_wake::sieve::RUNG_ATTEMPT
            || attempt_type == crate::dreamer_wake::sieve::TYPING_BATCH_ATTEMPT)
}

/// The shipped partition width, for a stored selection row written before
/// the field existed.
fn default_partition_extraction_parallelism() -> usize {
    8
}
impl Default for SelectionConfig {
    fn default() -> Self {
        serde_json::from_str(include_str!("selection_defaults.json"))
            .expect("checked selection defaults")
    }
}
impl SelectionConfig {
    pub fn validate(&self) -> Result<()> {
        let w = self.weights;
        if self.version != 1
            || self.frequency_scale == 0
            || self.diversity_scale == 0
            || self.recency_window_ms == 0
            || self.extraction_parallelism == 0
            || self.extraction_turns_per_child == 0
            || self.partition_extraction_parallelism == 0
            || !unit(self.cosine_threshold)
            || !unit(self.default_type_prior)
            || self.type_priors.values().any(|n| !unit(*n))
            || [w.type_prior, w.frequency, w.recency, w.diversity]
                .iter()
                .any(|n| !unit(*n))
            || w.type_prior <= w.frequency + w.recency + w.diversity
        {
            return Err(Error::InvalidConfig(
                "invalid consolidation selection policy".into(),
            ));
        }
        Ok(())
    }
}
fn unit(n: f64) -> bool {
    n.is_finite() && (0.0..=1.0).contains(&n)
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrengthSignals {
    pub type_prior: f64,
    pub frequency: f64,
    pub recency: f64,
    pub diversity: f64,
}
impl StrengthSignals {
    /// Shared by live candidate ordering and the nightly archive recipe.
    pub fn from_evidence(
        predicate: &str,
        count: usize,
        latest_ms: u64,
        diversity: usize,
        now_ms: u64,
        config: &SelectionConfig,
    ) -> Self {
        Self {
            type_prior: config
                .type_priors
                .get(predicate)
                .copied()
                .unwrap_or(config.default_type_prior),
            frequency: (count as f64 / config.frequency_scale as f64).min(1.0),
            recency: 1.0
                - (now_ms.saturating_sub(latest_ms) as f64 / config.recency_window_ms as f64)
                    .min(1.0),
            diversity: (diversity as f64 / config.diversity_scale as f64).min(1.0),
        }
    }
    /// Only the four contract signals are accepted. Surprise/perplexity have no
    /// score input, even when a producer supplies them alongside its signals.
    pub fn from_named(values: &BTreeMap<String, f64>) -> Self {
        let get = |key| values.get(key).copied().unwrap_or_default();
        Self {
            type_prior: get("type_prior"),
            frequency: get("frequency"),
            recency: get("recency"),
            diversity: get("diversity"),
        }
    }
}

pub fn strength_score(signals: StrengthSignals, config: &SelectionConfig) -> Result<f64> {
    config.validate()?;
    let s = signals;
    if [s.type_prior, s.frequency, s.recency, s.diversity]
        .iter()
        .any(|n| !unit(*n))
    {
        return Err(Error::InvalidConfig(
            "strength signals must be finite unit values".into(),
        ));
    }
    let w = config.weights;
    Ok(s.type_prior * w.type_prior
        + s.frequency * w.frequency
        + s.recency * w.recency
        + s.diversity * w.diversity)
}

#[derive(Debug, Clone, PartialEq)]
pub struct SelectionCandidate {
    pub claim_id: EntityId,
    pub first_seen_ms: u64,
    pub evidence_count: usize,
    pub fan_in: u64,
    pub new_refs: u64,
    pub signals: StrengthSignals,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionHold {
    Soak,
    EvidenceCount,
}
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionPlan {
    /// Strength first, cheap fan-in ranking second, stable identity last.
    pub ready: Vec<EntityId>,
    pub held: Vec<(EntityId, SelectionHold)>,
}

pub fn select_candidates(
    candidates: &[SelectionCandidate],
    now_ms: u64,
    config: &SelectionConfig,
) -> Result<SelectionPlan> {
    config.validate()?;
    let mut ready = Vec::new();
    let mut held = Vec::new();
    for c in candidates {
        let score = strength_score(c.signals, config)?;
        if now_ms < c.first_seen_ms || now_ms - c.first_seen_ms < config.soak_ms {
            held.push((c.claim_id, SelectionHold::Soak));
        } else if c.evidence_count < config.evidence_minimum {
            held.push((c.claim_id, SelectionHold::EvidenceCount));
        } else {
            let rank = u128::from(c.fan_in) * (1 + u128::from(c.new_refs));
            ready.push((c.claim_id, score, rank));
        }
    }
    ready.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    held.sort_by_key(|h| h.0);
    Ok(SelectionPlan {
        ready: ready.into_iter().map(|r| r.0).collect(),
        held,
    })
}

impl Vault {
    /// Operator configuration seam, like the prefilter row. It is not an agent verb.
    pub fn set_consolidation_selection(&self, config: &SelectionConfig) -> Result<()> {
        config.validate()?;
        self.with_write_txn_grouped(|txn| {
            SELECTION.put(&self.store, txn, &(), config)?;
            Ok(())
        })
    }

    /// The owner, by its proof, or a holder of `engine.controls` sets the selection timing: the
    /// soak and the recency window. Every other field stays as it stands (untangle 6.6b;
    /// maintenance cadence), through the one check, with a receipt naming it. Untangle 6.6d gives
    /// it its verb. Returns the receipt.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when `actor` is neither the owner, by a proof that still holds, nor a live
    /// holder of `engine.controls`; the row's own validation; store failures.
    pub fn set_consolidation_selection_timing_by(
        &self,
        actor: crate::federation::EngineControlActor<'_>,
        soak_ms: u64,
        recency_window_ms: u64,
    ) -> Result<crate::entity_id::EntityId> {
        self.apply_engine_control(
            actor,
            crate::federation::EngineControlClass::MaintenanceCadence,
            "DREAMER_CONSOLIDATION_SELECTION",
            &crate::federation::rendered_change(&serde_json::json!({
                "soak_ms": soak_ms,
                "recency_window_ms": recency_window_ms,
            }))?,
            |txn| {
                let mut config = self.consolidation_selection_in_txn(&*txn)?;
                config.soak_ms = soak_ms;
                config.recency_window_ms = recency_window_ms;
                config.validate()?;
                SELECTION.put(&self.store, txn, &(), &config)
            },
        )
    }

    /// [`Self::set_consolidation_selection_timing_by`] for a holder of `engine.controls` (untangle
    /// 6.6b).
    ///
    /// # Errors
    ///
    /// As [`Self::set_consolidation_selection_timing_by`].
    pub fn set_consolidation_selection_timing_as_holder(
        &self,
        holder: crate::entity_id::EntityId,
        soak_ms: u64,
        recency_window_ms: u64,
    ) -> Result<crate::entity_id::EntityId> {
        self.set_consolidation_selection_timing_by(
            crate::federation::EngineControlActor::Holder(holder),
            soak_ms,
            recency_window_ms,
        )
    }
    pub fn consolidation_selection(&self) -> Result<SelectionConfig> {
        let txn = self.store.env.read_txn()?;
        self.consolidation_selection_in_txn(&txn)
    }
    pub(crate) fn consolidation_selection_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<SelectionConfig> {
        let config = SELECTION.get(&self.store, txn, &())?.unwrap_or_default();
        config.validate()?;
        Ok(config)
    }
}

/// The effective scoring config's domain-separated pin in this transaction.
pub(crate) fn selection_config_pin_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<String> {
    let encoded = serde_json::to_vec(&vault.consolidation_selection_in_txn(txn)?)
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:consolidation:selection-config:v1\0");
    hash.update(&encoded);
    Ok(hash.finalize().to_hex().to_string())
}
