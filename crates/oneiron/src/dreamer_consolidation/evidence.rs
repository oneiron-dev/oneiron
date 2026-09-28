//! Parent-verified evidence is the sole scoped consolidation handoff.
//! Raw model locators carry no source/trust authority; the prepared reader
//! binds each citation to one exact source version before selection or writes.
use super::SwarmEvidenceRef;
use super::provenance::{ConsolidationEvidenceEnvelope, PromotionCandidate, source_meet};
use super::resources::BranchResources;
use super::support::invalid_consolidation;
use crate::claim::ClaimSource;
use crate::llm::ScopeResource;
use crate::{EntityId, Result};
use rmpv::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Only these two shapes may arrive from extraction; whole TURNs are an
/// explicit deterministic internal citation, never an absent-locator fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum EvidenceLocator {
    Claim {
        source_id: EntityId,
        claim_id: EntityId,
    },
    TurnTextRange {
        source_id: EntityId,
        start: usize,
        end: usize,
    },
    #[cfg(test)]
    WholeTurn { source_id: EntityId },
}

impl EvidenceLocator {
    pub(super) fn claim(source_id: EntityId, claim_id: EntityId) -> Result<Self> {
        if source_id != claim_id {
            return Err(invalid_consolidation("claim locator identity mismatch"));
        }
        Ok(Self::Claim {
            source_id,
            claim_id,
        })
    }
    pub(super) fn turn_range(source_id: EntityId, start: usize, end: usize) -> Result<Self> {
        if start >= end {
            return Err(invalid_consolidation("empty evidence text span"));
        }
        Ok(Self::TurnTextRange {
            source_id,
            start,
            end,
        })
    }
    #[cfg(test)]
    pub(super) const fn whole_turn(source_id: EntityId) -> Self {
        Self::WholeTurn { source_id }
    }
    pub(super) const fn source_id(self) -> EntityId {
        match self {
            Self::Claim { source_id, .. } | Self::TurnTextRange { source_id, .. } => source_id,
            #[cfg(test)]
            Self::WholeTurn { source_id } => source_id,
        }
    }
    pub(super) const fn reference(self) -> SwarmEvidenceRef {
        match self {
            Self::Claim {
                source_id,
                claim_id,
            } => SwarmEvidenceRef {
                source_id,
                claim_id: Some(claim_id),
                byte_range: None,
            },
            Self::TurnTextRange {
                source_id,
                start,
                end,
            } => SwarmEvidenceRef {
                source_id,
                claim_id: None,
                byte_range: Some((start, end)),
            },
            #[cfg(test)]
            Self::WholeTurn { source_id } => SwarmEvidenceRef::whole_turn(source_id),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExtractedCandidate {
    proposal: PromotionCandidate,
    refs: Vec<EvidenceLocator>,
}
impl ExtractedCandidate {
    pub(super) fn new(
        mut proposal: PromotionCandidate,
        refs: Vec<EvidenceLocator>,
    ) -> Result<Self> {
        if refs.is_empty() {
            return Err(invalid_consolidation("extraction requires evidence refs"));
        }
        let mut ids: Vec<_> = refs.iter().map(|r| r.source_id()).collect();
        ids.sort_unstable();
        ids.dedup();
        proposal.evidence_turn_refs = ids;
        Ok(Self { proposal, refs })
    }
    pub(super) fn proposal(&self) -> &PromotionCandidate {
        &self.proposal
    }
    pub(super) fn into_parts(self) -> (PromotionCandidate, Vec<EvidenceLocator>) {
        (self.proposal, self.refs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedCitation {
    locator: EvidenceLocator,
    hash: [u8; 32],
    version: ScopeResource,
    trust: ClaimSource,
}

/// Private constructor; a bare ID or a caller-chosen meet cannot become a
/// scoped write. All output doors consume this SAME parent-verified value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedEvidenceSet {
    rows: Vec<VerifiedCitation>,
    inherited_meet: ClaimSource,
}

impl VerifiedEvidenceSet {
    pub(super) fn verify(
        resources: &BranchResources<'_>,
        refs: &[EvidenceLocator],
        inherited_meet: ClaimSource,
    ) -> Result<Self> {
        if refs.is_empty() {
            return Err(invalid_consolidation("empty scoped evidence"));
        }
        let raw: Vec<_> = refs.iter().map(|locator| locator.reference()).collect();
        let verified = resources.verify_evidence_refs(&raw)?;
        let mut rows = Vec::new();
        for (locator, fact) in refs.iter().zip(verified) {
            rows.push(VerifiedCitation {
                locator: *locator,
                hash: fact.content_hash,
                version: resources.source_version(&locator.source_id())?,
                trust: fact.trust_class,
            });
        }
        Ok(Self::from_rows(rows, inherited_meet))
    }
    fn from_rows(rows: Vec<VerifiedCitation>, inherited_meet: ClaimSource) -> Self {
        let mut independent: BTreeMap<(EntityId, [u8; 32]), VerifiedCitation> = BTreeMap::new();
        for row in rows {
            match independent.entry((row.locator.source_id(), row.hash)) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let kept = entry.get_mut();
                    kept.trust = source_meet(kept.trust, row.trust);
                    if row.locator < kept.locator {
                        kept.locator = row.locator;
                    }
                }
            }
        }
        Self {
            rows: independent.into_values().collect(),
            inherited_meet,
        }
    }
    pub(crate) fn for_source(&self, source: EntityId) -> Self {
        Self::from_rows(
            self.rows
                .iter()
                .filter(|row| row.locator.source_id() == source)
                .cloned()
                .collect(),
            self.meet(),
        )
    }
    pub(crate) fn union(&self, other: &Self) -> Self {
        Self::from_rows(
            self.rows.iter().chain(other.rows.iter()).cloned().collect(),
            source_meet(self.inherited_meet, other.inherited_meet),
        )
    }
    pub(crate) fn restrict(mut self, inherited: ClaimSource) -> Self {
        self.inherited_meet = source_meet(self.inherited_meet, inherited);
        self
    }
    pub(crate) fn meet(&self) -> ClaimSource {
        self.rows.iter().fold(self.inherited_meet, |meet, row| {
            source_meet(meet, row.trust)
        })
    }
    pub(crate) fn count(&self) -> usize {
        self.rows.len()
    }
    pub(crate) fn signal_sources(&self) -> Vec<(EntityId, [u8; 32], bool)> {
        self.rows
            .iter()
            .map(|row| {
                (
                    row.locator.source_id(),
                    row.hash,
                    matches!(row.locator, EvidenceLocator::Claim { .. }),
                )
            })
            .collect()
    }
    pub(crate) fn refs(&self) -> Vec<EntityId> {
        self.rows
            .iter()
            .map(|r| r.locator.source_id())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub(crate) fn locators(&self) -> Vec<SwarmEvidenceRef> {
        self.rows.iter().map(|r| r.locator.reference()).collect()
    }
    pub(crate) fn verified_locators(&self) -> Vec<(SwarmEvidenceRef, [u8; 32])> {
        self.rows
            .iter()
            .map(|r| (r.locator.reference(), r.hash))
            .collect()
    }
    pub(super) fn check_pins(&self, resources: &BranchResources<'_>) -> Result<()> {
        for row in &self.rows {
            let id = row.locator.source_id();
            if resources.source_version(&id)? != row.version {
                return Err(invalid_consolidation("verified source version changed"));
            }
            let verified = resources.verify_evidence_refs(&[row.locator.reference()])?;
            if verified[0].content_hash != row.hash || verified[0].trust_class != row.trust {
                return Err(invalid_consolidation("verified evidence binding changed"));
            }
        }
        Ok(())
    }
    pub(crate) fn envelope(&self, chain: Vec<super::ConsolidationProvenanceHop>) -> Value {
        super::encode_consolidation_evidence_with_locators(
            &ConsolidationEvidenceEnvelope {
                refs: self.refs(),
                chain,
                source_meet: self.meet(),
            },
            &self.verified_locators(),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedCandidate {
    pub(crate) proposal: PromotionCandidate,
    pub(crate) evidence: VerifiedEvidenceSet,
}
impl std::ops::Deref for VerifiedCandidate {
    type Target = PromotionCandidate;
    fn deref(&self) -> &PromotionCandidate {
        &self.proposal
    }
}
impl VerifiedCandidate {
    pub(super) fn from_extracted(
        resources: &BranchResources<'_>,
        extracted: ExtractedCandidate,
    ) -> Result<Self> {
        let (mut proposal, refs) = extracted.into_parts();
        let evidence = VerifiedEvidenceSet::verify(resources, &refs, proposal.evidence_meet)?;
        proposal.evidence_turn_refs = evidence.refs();
        proposal.evidence_meet = evidence.meet();
        Ok(Self { proposal, evidence })
    }
}
