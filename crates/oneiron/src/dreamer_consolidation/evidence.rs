//! Parent-verified evidence is the sole scoped consolidation handoff.
//! Raw model locators carry no source/trust authority; the prepared reader
//! binds each citation to one exact source version before selection or writes.
use super::SwarmEvidenceRef;
use super::provenance::{ConsolidationEvidenceEnvelope, PromotionCandidate, source_meet};
use super::resources::BranchResources;
use super::support::invalid_consolidation;
use super::turn_text::MessageSpan;
use crate::claim::ClaimSource;
use crate::llm::ScopeResource;
use crate::{EntityId, Result, Vault};
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
    /// The listed head the extractor named in `corrects`.
    corrects: Option<EntityId>,
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
        Ok(Self {
            proposal,
            refs,
            corrects: None,
        })
    }
    /// Marks the candidate as the extractor's correction of `head`.
    pub(super) fn correcting(mut self, head: EntityId) -> Self {
        self.corrects = Some(head);
        self
    }
    pub(super) fn corrects(&self) -> Option<EntityId> {
        self.corrects
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
    /// The MESSAGE words a witnessed TURN locator covers; empty otherwise.
    messages: Vec<MessageSpan>,
    /// The MESSAGEs the cited TURN text joined, in order, when it was read
    /// from them (FIX 5755); empty otherwise. Ids only, never their words.
    projection: Vec<EntityId>,
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
                messages: resources.message_spans(&locator.reference())?,
                projection: resources.projection(&locator.reference()),
            });
        }
        Ok(Self::from_rows(rows, inherited_meet))
    }
    /// Binds a stored citation set again in the caller's transaction, as the
    /// Dreamer reads each source there (FIX 496): a TURN range must still
    /// hash to the words it cited and cover the same MESSAGE slices, a claim
    /// must still be admissible and hash the same, and each source's trust is
    /// read again. The meet folds onto `inherited_meet`, so it never rises.
    /// A TURN range the TURN as read now no longer binds is bound once more
    /// against the exact projection its branch read, when `projections`
    /// keeps it (FIX 5755): the same MESSAGEs, rebuilt as they stand now.
    pub(super) fn reverify_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        stored: &[super::provenance::VerifiedLocator],
        projections: &[(EntityId, Vec<EntityId>)],
        inherited_meet: ClaimSource,
    ) -> Result<Self> {
        if stored.is_empty() {
            return Err(invalid_consolidation("empty retained evidence"));
        }
        let read = super::turn_text::dreamer_read(vault)?;
        let mut rows = Vec::with_capacity(stored.len());
        for (reference, hash, messages) in stored {
            let locator = match (reference.claim_id, reference.byte_range) {
                (Some(claim), None) => EvidenceLocator::claim(reference.source_id, claim)?,
                (None, Some((start, end))) => {
                    EvidenceLocator::turn_range(reference.source_id, start, end)?
                }
                _ => {
                    return Err(invalid_consolidation(
                        "retained evidence is neither a text range nor a claim",
                    ));
                }
            };
            let (kind, _, body) = read
                .get_entities_parts_in_txn(txn, &[reference.source_id])?
                .pop()
                .flatten()
                .ok_or_else(|| invalid_consolidation("retained evidence is not readable"))?;
            let (trust, text) = if kind == crate::registry::ENTITY_TYPE_CLAIM {
                let claim = crate::claim::decode_claim_body(&body, true)?;
                if !crate::claim::claim_evidence_admissible(&claim) {
                    return Err(invalid_consolidation("generated claim cannot corroborate"));
                }
                (super::provenance::evidence_source_from_claim(&claim), None)
            } else {
                let trust = super::resources::native_turn_source(vault, &body)?;
                let live =
                    super::turn_text::collect_in(&read, txn, &reference.source_id, &body, &mut 0);
                let projection = projections
                    .iter()
                    .find(|(source, _)| *source == reference.source_id)
                    .map(|(_, ids)| ids.as_slice());
                let text = match (live, projection) {
                    (Ok(text), _)
                        if binds(*reference, kind, &body, &text, trust, hash, messages) =>
                    {
                        text
                    }
                    (_, Some(projection)) => super::turn_text::projection::rebuild_in(
                        &read,
                        txn,
                        &reference.source_id,
                        &body,
                        projection,
                    )?,
                    (live, None) => live?,
                };
                (trust, Some(text))
            };
            let verified = super::conflict::verify_swarm_evidence_bytes(
                *reference,
                kind,
                &body,
                text.as_ref().and_then(super::turn_text::TurnText::text),
                trust,
            )?;
            let live = match &text {
                Some(text) => text.spans(reference.byte_range)?,
                None => Vec::new(),
            };
            if verified.content_hash != *hash || live != *messages {
                return Err(invalid_consolidation("retained evidence changed"));
            }
            rows.push(VerifiedCitation {
                locator,
                hash: *hash,
                version: super::resources::document_version(reference.source_id, &body),
                trust,
                messages: live,
                projection: match &text {
                    Some(text) => text.projection(),
                    None => Vec::new(),
                },
            });
        }
        Ok(Self::from_rows(rows, inherited_meet))
    }
    fn from_rows(rows: Vec<VerifiedCitation>, inherited_meet: ClaimSource) -> Self {
        let collapsed = super::conflict::collapse_verified_evidence(
            rows.iter()
                .map(|row| super::VerifiedSwarmEvidence {
                    source_id: row.locator.source_id(),
                    content_hash: row.hash,
                    trust_class: row.trust,
                })
                .collect(),
        );
        let mut independent: BTreeMap<(EntityId, [u8; 32]), VerifiedCitation> = BTreeMap::new();
        for row in rows {
            match independent.entry((row.locator.source_id(), row.hash)) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let kept = entry.get_mut();
                    if row.locator < kept.locator {
                        kept.locator = row.locator;
                        kept.messages = row.messages;
                        kept.projection = row.projection;
                    }
                }
            }
        }
        let rows = collapsed
            .independent
            .into_iter()
            .map(|entry| {
                let mut row = independent
                    .remove(&(entry.source_id, entry.content_hash))
                    .expect("collapsed evidence came from these citations");
                row.trust = entry.trust_class;
                row
            })
            .collect();
        Self {
            rows,
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
    /// Every MESSAGE whose words a citation names.
    pub(crate) fn cited_messages(&self) -> Vec<EntityId> {
        self.rows
            .iter()
            .flat_map(|row| &row.messages)
            .map(|span| span.message)
            .collect()
    }
    /// Each cited TURN's projection, by source, as its branch read it
    /// (FIX 5755): what a retained alternative keeps beside its citations.
    pub(super) fn projections(&self) -> BTreeMap<EntityId, Vec<EntityId>> {
        self.rows
            .iter()
            .filter(|row| !row.projection.is_empty())
            .map(|row| (row.locator.source_id(), row.projection.clone()))
            .collect()
    }
    pub(crate) fn verified_locators(&self) -> Vec<super::provenance::VerifiedLocator> {
        self.rows
            .iter()
            .map(|r| (r.locator.reference(), r.hash, r.messages.clone()))
            .collect()
    }
    /// The citing write's dependencies on the MESSAGE words it names, in that
    /// write's own transaction: erasing a named MESSAGE stales `citing`
    /// through the source-dependency index, and (with `sync`) each cited slice
    /// records an EntityDoc citation floor at the frontier it names (the
    /// MESSAGE's birth state when it had no document). While `citing` is live
    /// an owner purge keeps that history, and a value-only recovery that
    /// rebuilds the MESSAGE's document stales `citing`. Gap-queue rows are not
    /// entities and record neither.
    pub(crate) fn record_message_dependencies_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        citing: &EntityId,
    ) -> Result<()> {
        for span in self.rows.iter().flat_map(|row| &row.messages) {
            crate::ports::record_derived_edge_in_txn(&vault.store, txn, citing, &span.message)?;
            #[cfg(feature = "sync")]
            crate::entity_doc::record_citation_floor_in_txn(
                &vault.store,
                txn,
                &span.message,
                citing,
                span.frontier.as_deref(),
            )?;
        }
        Ok(())
    }
    pub(super) fn check_pins(&self, resources: &BranchResources<'_>) -> Result<()> {
        for row in &self.rows {
            let id = row.locator.source_id();
            if resources.source_version(&id)? != row.version {
                return Err(invalid_consolidation("verified source version changed"));
            }
            let verified = resources.verify_evidence_refs(&[row.locator.reference()])?;
            if verified[0].content_hash != row.hash
                || verified[0].trust_class != row.trust
                || resources.message_spans(&row.locator.reference())? != row.messages
            {
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

/// Whether `text` still holds the words a stored TURN citation names: the
/// same range hash over it and the same MESSAGE slices behind it.
fn binds(
    reference: SwarmEvidenceRef,
    kind: u8,
    body: &[u8],
    text: &super::turn_text::TurnText,
    trust: ClaimSource,
    hash: &[u8; 32],
    messages: &[MessageSpan],
) -> bool {
    super::conflict::verify_swarm_evidence_bytes(reference, kind, body, text.text(), trust)
        .is_ok_and(|verified| verified.content_hash == *hash)
        && text
            .spans(reference.byte_range)
            .is_ok_and(|live| live == messages)
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
