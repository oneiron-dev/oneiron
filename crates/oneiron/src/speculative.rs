//! EMB-5 speculative retrieval over ASR partials (ONE-EMBED E7).
//!
//! A thin per-utterance session: the host feeds ASR-partial observations in
//! ([`SpeculativePartial`]); the session fires a reduced-limit, prefix-only
//! (EMB-2 skip-rescore hot lane) retrieval whenever the partial's MEANING
//! changes — the entity-label ∪ salient-term signature differs from the last
//! FIRED signature — capped at [`SpeculativeSessionConfig::max_fires`] per
//! utterance. At end of utterance [`SpeculativeSession::finalize`] either
//! promotes the last warm pack verbatim (zero additional retrieval) or runs
//! one full-quality pass and warm-fills the shortfall.
//!
//! The engine runs no ASR and no entity-spot model: labels, terms, and query
//! vectors are host-supplied. Every speculative fire is tagged
//! [`RetrievalAction::Speculative`] in telemetry; the finalize pass logs as
//! `Pipeline` — only the fires are the measurable wasted-retrieval budget.
//!
//! Accepted E7 latency-for-quality tradeoff (RATIFY-20260710 R0): the
//! promote path returns fire-shaped results (`fire_limit`-capped,
//! prefix-quality) while the finalize path returns `final_limit`
//! full-dim-rescored results — see [`SpeculativeFinal`]. A host can set
//! `fire_limit == final_limit` to erase the count half.
//!
//! Snapshot posture (recorded deviation from E7's literal "one
//! read-snapshot" wording, designer-resolved): per-fire LMDB snapshot
//! isolation + a session-owned warm pack, NOT one read txn held across the
//! utterance — a multi-second-held `RoTxn` would pin LMDB free-page
//! reclamation exactly while the voice path is writing. Each fire is
//! internally consistent, refires only happen on meaning change where
//! fresher data is strictly better, and the promote path returns the stored
//! warm pack verbatim.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::pipeline::ScoredEntity;
use crate::store::{RetrievalAction, RetrievalRunId};

/// Max speculative fires per utterance (E7: cap ~4 fires/utterance).
pub const SPECULATIVE_FIRE_CAP_DEFAULT: u8 = 4;
/// Reduced per-fire result limit (E7 "fast lane, reduced limit").
pub const SPECULATIVE_FIRE_LIMIT_DEFAULT: usize = 8;

pub struct SpeculativeSessionConfig {
    /// Max speculative fires per utterance (host-tunable, E7).
    pub max_fires: u8,
    /// `result_limit` for speculative fires.
    pub fire_limit: usize,
    /// `result_limit` for the end-of-utterance full-quality pass.
    pub final_limit: usize,
}

impl Default for SpeculativeSessionConfig {
    fn default() -> Self {
        Self {
            max_fires: SPECULATIVE_FIRE_CAP_DEFAULT,
            fire_limit: SPECULATIVE_FIRE_LIMIT_DEFAULT,
            final_limit: crate::pipeline::DEFAULT_RESULT_LIMIT,
        }
    }
}

/// One ASR-partial observation. The engine runs no models: entity labels
/// come from the host's TINY entity-spot pass, salient terms from the
/// host's extraction; `query_vector` (if any) is host-embedded (full-length
/// or `fast_dims`-length per EMB-2).
pub struct SpeculativePartial<'a> {
    pub text: &'a str,
    pub query_vector: Option<&'a [f32]>,
    pub entity_labels: &'a [String],
    pub salient_terms: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpeculativeFireDecision {
    Fired {
        run_id: Option<RetrievalRunId>,
    },
    /// Signature identical to the last fired signature.
    SkippedUnchanged,
    /// No entities/terms spotted yet — nothing meaningful.
    SkippedEmptySignature,
    /// `max_fires` reached.
    SkippedCapExhausted,
}

/// End-of-utterance outcome.
///
/// The `Promoted`/`Finalized` count+quality asymmetry is ACCEPTED and
/// intentional (E7 latency-for-quality tradeoff, RATIFY-20260710 R0):
/// `Promoted` returns at most `fire_limit` prefix-quality (skip-rescore)
/// candidates with zero additional retrieval; `Finalized` returns up to
/// `final_limit` full-dim-rescored candidates from one fresh pass. Setting
/// `fire_limit == final_limit` erases the count half of the asymmetry.
pub enum SpeculativeFinal {
    /// Diff empty at end-of-utterance: the last warm pack is promoted
    /// verbatim — zero additional retrieval (E7 promote path). `run_id` is
    /// the promoted fire's run id; no new telemetry row is written.
    Promoted {
        scores: Vec<ScoredEntity>,
        run_id: Option<RetrievalRunId>,
    },
    /// Diff non-empty: one full-quality pass ran; warm candidates absent
    /// from the fresh results were appended (in warm order) up to
    /// `final_limit`, counted in `warm_appended`.
    ///
    /// Warm-appended entries keep their fire-time scores (prefix-space,
    /// since fires skip the rescore) behind full-dim fresh scores — score
    /// VALUES are NOT cross-comparable across the fresh/warm boundary;
    /// order is the contract, not score scale.
    Finalized {
        scores: Vec<ScoredEntity>,
        run_id: Option<RetrievalRunId>,
        warm_appended: usize,
    },
}

struct WarmPack {
    scores: Vec<ScoredEntity>,
    run_id: Option<RetrievalRunId>,
}

/// Per-utterance speculative-retrieval session (see the module docs).
///
/// Owns an `Arc<Vault>` (the `PendingEmbeddingReconciler` precedent): the
/// session outlives individual call frames in a host voice loop.
pub struct SpeculativeSession {
    vault: std::sync::Arc<crate::Vault>,
    config: SpeculativeSessionConfig,
    last_signature: BTreeSet<String>,
    fires_used: u8,
    warm: Option<WarmPack>,
}

impl SpeculativeSession {
    #[must_use]
    pub fn new(vault: std::sync::Arc<crate::Vault>, config: SpeculativeSessionConfig) -> Self {
        Self {
            vault,
            config,
            last_signature: BTreeSet::new(),
            fires_used: 0,
            warm: None,
        }
    }

    /// Observes one ASR partial; fires a speculative retrieval when its
    /// signature differs from the last FIRED signature (never per-token).
    /// A fire error propagates and leaves the session state un-advanced —
    /// the next partial may retry within the cap.
    pub fn observe_partial(
        &mut self,
        partial: SpeculativePartial<'_>,
    ) -> Result<SpeculativeFireDecision> {
        let signature = partial_signature(&partial);
        if signature.is_empty() {
            return Ok(SpeculativeFireDecision::SkippedEmptySignature);
        }
        if signature == self.last_signature {
            return Ok(SpeculativeFireDecision::SkippedUnchanged);
        }
        if self.fires_used >= self.config.max_fires {
            return Ok(SpeculativeFireDecision::SkippedCapExhausted);
        }

        if self.config.fire_limit == 0 {
            return Err(crate::error::Error::InvalidConfig(
                "speculative limits must be greater than zero".to_owned(),
            ));
        }
        let mut builder = self
            .vault
            .query()
            .search_text(partial.text, self.config.fire_limit);
        if let Some(vector) = partial.query_vector {
            // EMB-2 voice hot lane: prefix-only, no full-dim rescore.
            builder = builder
                .search_vector(vector, self.config.fire_limit)
                .skip_vector_rescore(true);
        }
        let fired = builder
            .limit(self.config.fire_limit)
            .telemetry_action(RetrievalAction::Speculative)
            // Deliberately this run variant: surfaced-pending claims get the
            // EMB-1 priority-0 hot bump.
            .run_with_pending_vectors()?;

        self.warm = Some(WarmPack {
            scores: fired.value,
            run_id: fired.run_id,
        });
        self.last_signature = signature;
        self.fires_used += 1;
        Ok(SpeculativeFireDecision::Fired {
            run_id: self.warm.as_ref().and_then(|warm| warm.run_id),
        })
    }

    /// The last fired warm pack (empty before the first fire).
    #[must_use]
    pub fn warm_candidates(&self) -> &[ScoredEntity] {
        self.warm
            .as_ref()
            .map(|warm| warm.scores.as_slice())
            .unwrap_or(&[])
    }

    #[must_use]
    pub fn fires_used(&self) -> u8 {
        self.fires_used
    }

    /// End-of-utterance: promote the warm pack verbatim when the final
    /// signature matches the last fired one, else run ONE full-quality pass
    /// (logged as `RetrievalAction::Pipeline`; it IS a real retrieval) and
    /// warm-fill the shortfall. Never counts against `max_fires`.
    pub fn finalize(self, final_partial: SpeculativePartial<'_>) -> Result<SpeculativeFinal> {
        let signature = partial_signature(&final_partial);
        if signature == self.last_signature
            && let Some(warm) = self.warm
        {
            return Ok(SpeculativeFinal::Promoted {
                scores: warm.scores,
                run_id: warm.run_id,
            });
        }

        if self.config.final_limit == 0 {
            return Err(crate::error::Error::InvalidConfig(
                "speculative limits must be greater than zero".to_owned(),
            ));
        }
        let mut builder = self
            .vault
            .query()
            .search_text(final_partial.text, self.config.final_limit);
        if let Some(vector) = final_partial.query_vector {
            builder = builder.search_vector(vector, self.config.final_limit);
        }
        let fresh = builder
            .limit(self.config.final_limit)
            .telemetry_action(RetrievalAction::Pipeline)
            .run_with_pending_vectors()?;

        let mut scores = fresh.value;
        let fresh_ids: BTreeSet<crate::entity_id::EntityId> =
            scores.iter().map(|scored| scored.id).collect();
        let mut warm_appended = 0;
        if let Some(warm) = self.warm {
            for candidate in warm.scores {
                if scores.len() >= self.config.final_limit {
                    break;
                }
                if fresh_ids.contains(&candidate.id) {
                    continue;
                }
                scores.push(candidate);
                warm_appended += 1;
            }
        }

        Ok(SpeculativeFinal::Finalized {
            scores,
            run_id: fresh.run_id,
            warm_appended,
        })
    }
}

/// Normalized meaning signature: `entity_labels ∪ salient_terms`, each
/// trimmed and Unicode-lowercased, empties dropped.
fn partial_signature(partial: &SpeculativePartial<'_>) -> BTreeSet<String> {
    partial
        .entity_labels
        .iter()
        .chain(partial.salient_terms.iter())
        .map(|term| term.trim().to_lowercase())
        .filter(|term| !term.is_empty())
        .collect()
}

#[cfg(test)]
mod tests;
