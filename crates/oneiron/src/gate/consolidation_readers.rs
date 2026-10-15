//! The readers that consolidate a claim, and the question each asks first.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::vault::Vault;

/// Every reader that consolidates a claim: folds it into derived state, holds
/// it as a prior, ranks a candidate by it, counts it as evidence, or counts it
/// toward waking a Dreamer pass. Each asks
/// [`claim_consolidation_eligible_in_txn`] before it reads a head, so a
/// critical claim whose owner-answer obligation is open reaches none of them
/// (ARCH-0026 §G3). A write its owner authored in person attaches no
/// confirmation, so it is eligible at once. Readers of reserved heads and of
/// critic calibration ask too: a reserved predicate's own door attaches no
/// confirmation, but its head can land on a claim id whose obligation is
/// still open, and only the owner's answer closes that. A restrictive read,
/// a closure or a supersession is no consolidation and never asks. The
/// invariant check walks this list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsolidationReader {
    /// Affect VAD consolidation of one claim.
    ClaimVad,
    /// The coping outcome a turn's VAD delta updates.
    CopingOutcome,
    /// A turn's VAD annotation that consolidation or coping folds in.
    VadAnnotation,
    /// The Dreamer's known-claims listing for a subject.
    NewestClaims,
    /// A Dreamer candidate's graph signals: fan-in and new references.
    GraphSignal,
    /// A prior head an explicit branch scope admits.
    ExplicitPrior,
    /// A source the consolidation fence pinned.
    FenceSource,
    /// A replacement the consolidation fence relies on.
    FenceReplacement,
    /// Evidence Dreamer promotion counts.
    PromotionEvidence,
    /// Evidence the Dreamer precommit floor counts.
    PrecommitEvidence,
    /// A claim anchor of the entity-resolution waterfall.
    ResolutionWaterfall,
    /// A fact a question's answer is checked against, when its arrival is
    /// projected into a label and when a label is read back.
    ArrivalFact,
    /// The answer claim whose prediction that fact labels, on both roads.
    AnswerPrediction,
    /// A head derived-attachment verification counts as support.
    DerivedSupport,
    /// A goal-velocity or engagement signal the state index blends.
    StateIndexSignal,
    /// A new record the Dreamer wake policy counts toward a pass.
    WakeCount,
    /// A provider's confidence prior (`actor.confidence_prior`), the trust
    /// multiplier entity resolution ranks candidates by.
    ProviderPrior,
    /// The calibration an anchored review outcome trains its next posterior
    /// from (`critic_reliability.*`).
    CriticOutcome,
    /// The calibration that weights a critic's review (`critic_reliability.*`).
    CriticReliability,
    /// A provider-attributed claim whose confidence the resolution waterfall
    /// scores.
    ProviderConfidence,
    /// A claim vertex of the PPR community graph, the retrieval prior.
    PprCommunity,
}

impl ConsolidationReader {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 21] = [
        Self::ClaimVad,
        Self::CopingOutcome,
        Self::VadAnnotation,
        Self::NewestClaims,
        Self::GraphSignal,
        Self::ExplicitPrior,
        Self::FenceSource,
        Self::FenceReplacement,
        Self::PromotionEvidence,
        Self::PrecommitEvidence,
        Self::ResolutionWaterfall,
        Self::ArrivalFact,
        Self::AnswerPrediction,
        Self::DerivedSupport,
        Self::StateIndexSignal,
        Self::WakeCount,
        Self::ProviderPrior,
        Self::CriticOutcome,
        Self::CriticReliability,
        Self::ProviderConfidence,
        Self::PprCommunity,
    ];

    const fn code(self) -> &'static str {
        match self {
            Self::ClaimVad => "claim_vad",
            Self::CopingOutcome => "coping_outcome",
            Self::VadAnnotation => "vad_annotation",
            Self::NewestClaims => "newest_claims",
            Self::GraphSignal => "graph_signal",
            Self::ExplicitPrior => "explicit_prior",
            Self::FenceSource => "fence_source",
            Self::FenceReplacement => "fence_replacement",
            Self::PromotionEvidence => "promotion_evidence",
            Self::PrecommitEvidence => "precommit_evidence",
            Self::ResolutionWaterfall => "resolution_waterfall",
            Self::ArrivalFact => "arrival_fact",
            Self::AnswerPrediction => "answer_prediction",
            Self::DerivedSupport => "derived_support",
            Self::StateIndexSignal => "state_index_signal",
            Self::WakeCount => "wake_count",
            Self::ProviderPrior => "provider_prior",
            Self::CriticOutcome => "critic_outcome",
            Self::CriticReliability => "critic_reliability",
            Self::ProviderConfidence => "provider_confidence",
            Self::PprCommunity => "ppr_community",
        }
    }
}

/// Whether `reader` may consolidate the claim `id`: no owner confirmation of a
/// critical write is outstanding on it
/// ([`super::claim_critical_confirm_settled_in_txn`]). Retrieval never asks.
pub(crate) fn claim_consolidation_eligible_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    reader: ConsolidationReader,
) -> Result<bool> {
    let settled = super::claim_critical_confirm_settled_in_txn(store, txn, id)?;
    if !settled {
        tracing::debug!(
            target: "oneiron::gate",
            reader = reader.code(),
            "a consolidation reader held back a claim awaiting its critical confirm"
        );
    }
    Ok(settled)
}

impl Vault {
    /// [`claim_consolidation_eligible_in_txn`] in its own read transaction,
    /// for a reader that holds none.
    pub(crate) fn claim_consolidation_eligible(
        &self,
        id: &EntityId,
        reader: ConsolidationReader,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        claim_consolidation_eligible_in_txn(&self.store, &txn, id, reader)
    }
}
