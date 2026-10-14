//! The readers that consolidate a claim, and the question each asks first.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::vault::Vault;

/// Every reader that consolidates a claim: folds it into derived state, holds
/// it as a prior, ranks a candidate by it, or counts it as evidence. Each asks
/// [`claim_consolidation_eligible_in_txn`] before it reads a head, so a
/// critical claim whose owner confirmation is outstanding reaches none of
/// them (ARCH-0026 §G3). A write its owner authored in person attaches no
/// confirmation, so it is eligible at once. The invariant check walks this
/// list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsolidationReader {
    /// Affect VAD consolidation of one claim.
    ClaimVad,
    /// The coping outcome a turn's VAD delta updates.
    CopingOutcome,
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
    /// A fact a question's arrival projects.
    ArrivalProjection,
    /// A fact a question's answer is checked against.
    ArrivalFact,
    /// A head derived-attachment verification counts as support.
    DerivedSupport,
}

impl ConsolidationReader {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 13] = [
        Self::ClaimVad,
        Self::CopingOutcome,
        Self::NewestClaims,
        Self::GraphSignal,
        Self::ExplicitPrior,
        Self::FenceSource,
        Self::FenceReplacement,
        Self::PromotionEvidence,
        Self::PrecommitEvidence,
        Self::ResolutionWaterfall,
        Self::ArrivalProjection,
        Self::ArrivalFact,
        Self::DerivedSupport,
    ];

    const fn code(self) -> &'static str {
        match self {
            Self::ClaimVad => "claim_vad",
            Self::CopingOutcome => "coping_outcome",
            Self::NewestClaims => "newest_claims",
            Self::GraphSignal => "graph_signal",
            Self::ExplicitPrior => "explicit_prior",
            Self::FenceSource => "fence_source",
            Self::FenceReplacement => "fence_replacement",
            Self::PromotionEvidence => "promotion_evidence",
            Self::PrecommitEvidence => "precommit_evidence",
            Self::ResolutionWaterfall => "resolution_waterfall",
            Self::ArrivalProjection => "arrival_projection",
            Self::ArrivalFact => "arrival_fact",
            Self::DerivedSupport => "derived_support",
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
