//! Sealed resource handoff. Only the executor can construct one; every real
//! promotion and attachment checks its pins inside the write transaction.
use super::{BranchResources, FallbackOutputPin, SourcePin, document_version};
#[cfg(test)]
use crate::claim::ClaimSource;
use crate::claim::{ScopedReadActorKey, ScopedReadReceipt};
use crate::dreamer_consolidation::PromotionCandidate;
use crate::dreamer_consolidation::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::turn_text::TurnText;
use crate::llm::Scope;
use crate::{EntityId, Result, Vault, WriteActor};
use std::collections::{BTreeMap, BTreeSet};

pub struct ScopedConsolidationWrite {
    pub(crate) candidates: Vec<PromotionCandidate>,
    pub(crate) candidate_evidence: Vec<VerifiedEvidenceSet>,
    pub(crate) attachments: Vec<(EntityId, PromotionCandidate, VerifiedEvidenceSet)>,
    pub(crate) fence: ConsolidationFence,
    read_receipt: ScopedReadReceipt,
}

impl ScopedConsolidationWrite {
    /// Inspection for non-writing sinks. Persistence must use the sealed write.
    pub fn candidates(&self) -> &[PromotionCandidate] {
        &self.candidates
    }

    /// Every scoped read behind these candidates, folded: sources, priors,
    /// graph signals and the wake's pinned read. Rows withheld from the Dreamer
    /// actor are counted here, never silently dropped.
    pub fn read_receipt(&self) -> &ScopedReadReceipt {
        &self.read_receipt
    }
}

pub(crate) struct ConsolidationFence {
    actor: WriteActor,
    attempt: crate::attempt_queue::AttemptId,
    fallback_binding: Option<FallbackOutputPin>,
    sources: BTreeMap<EntityId, SourcePin>,
    turns: BTreeSet<EntityId>,
    texts: BTreeMap<EntityId, TurnText>,
    conversation: EntityId,
    rules: crate::dreamer_consolidation::routing::PredicateKeyRules,
    /// Priors a correction in this same handoff closed with its grant, at
    /// the revision that grant wrote: the handoff's later writes hold them to
    /// it instead of their pins.
    closed: std::sync::Mutex<BTreeMap<EntityId, RowRevision>>,
    /// Replacements the conflict closes under way rely on, at the revision
    /// whose standing they checked: each close refuses once one changes or no
    /// longer reads.
    standing: std::sync::Mutex<BTreeMap<EntityId, RowRevision>>,
}

/// A row as it is stored: its type, learned time and document version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RowRevision {
    entity_type: u8,
    learned_at: u64,
    resource: crate::llm::ScopeResource,
}

impl RowRevision {
    /// `id`'s revision in `txn`; `None` when it is gone or has no header.
    pub(crate) fn read_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Self>> {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
        else {
            return Ok(None);
        };
        Ok(
            crate::batch::EntityMetadataHeader::parse(&raw).map(|header| Self {
                entity_type: header.entity_type,
                learned_at: header.learned_at,
                resource: document_version(*id, &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]),
            }),
        )
    }

    fn of_pin(pin: &SourcePin) -> Self {
        Self {
            entity_type: pin.entity_type,
            learned_at: pin.learned_at,
            resource: pin.resource.clone(),
        }
    }
}

impl ConsolidationFence {
    /// The executor's own actor and attempt: the only run this sealed write
    /// may promote under (`validate_run` refuses any other).
    pub(crate) fn run_identity(&self) -> (WriteActor, crate::attempt_queue::AttemptId) {
        (self.actor, self.attempt)
    }

    /// Records a prior this handoff's own granted correction closed, at the
    /// revision the grant wrote (read inside the grant's transaction). A
    /// poisoned lock records nothing, and the later writes refuse.
    pub(crate) fn closed_by_this_write(&self, prior: EntityId, revision: RowRevision) {
        if let Ok(mut closed) = self.closed.lock() {
            closed.insert(prior, revision);
        }
    }

    /// Records a replacement a conflict close relies on, at the revision
    /// whose standing the close checked, until [`Self::released`]. A
    /// poisoned lock fails the later writes' fence.
    pub(crate) fn relies_on(&self, replacement: EntityId, revision: RowRevision) {
        if let Ok(mut standing) = self.standing.lock() {
            standing.insert(replacement, revision);
        }
    }

    /// The closes that relied on `replacement` are done.
    pub(crate) fn released(&self, replacement: EntityId) {
        if let Ok(mut standing) = self.standing.lock() {
            standing.remove(&replacement);
        }
    }
}

impl BranchResources<'_> {
    pub(super) fn prepare_write_verified(
        &self,
        scope: &Scope,
        candidates: Vec<VerifiedCandidate>,
    ) -> Result<ScopedConsolidationWrite> {
        self.require_output(scope)?;
        let rules = self.key_rules();
        let mut writes = Vec::new();
        let mut written_evidence = Vec::new();
        let mut attachments = Vec::new();
        for verified in candidates {
            verified.evidence.check_pins(self)?;
            let mut candidate = verified.proposal;
            let evidence = verified.evidence;
            if candidate.evidence_turn_refs != evidence.refs()
                || candidate.evidence_meet != evidence.meet()
            {
                return Err(invalid_consolidation(
                    "candidate does not match verified evidence",
                ));
            }
            // Supersession is an engine resolution, never a model-selected id.
            let prior = candidate.supersedes.take();
            self.validate_candidates(scope, std::slice::from_ref(&candidate))?;
            if let Some(id) = prior {
                self.require_prior_write(scope, id)?;
            }
            let matches = self.matching_priors(&candidate, rules)?;
            if prior.is_some_and(|id| !matches.iter().any(|(matched, _)| *matched == id)) {
                return Err(invalid_consolidation(
                    "resolved supersession crossed its prior question",
                ));
            }
            if matches.len() > 1 && prior.is_some() {
                return Err(invalid_consolidation(
                    "multiple admitted prior heads for one question",
                ));
            }
            if let [(id, true)] = matches.as_slice() {
                let id = *id;
                // Nothing attaches to an unvetted head, so a candidate that
                // restates one is already said; this attempt's own head met
                // again is its replay.
                if self.provisional.contains(&id) && id != candidate.claim_id {
                    continue;
                }
                if candidate.evidence_turn_refs.contains(&id) {
                    return Err(invalid_consolidation(
                        "claim evidence cannot support itself",
                    ));
                }
                self.require_prior_write(scope, id)?;
                attachments.push((id, candidate, evidence));
            } else {
                candidate.supersedes = prior;
                writes.push(candidate);
                written_evidence.push(evidence);
            }
        }
        Ok(ScopedConsolidationWrite {
            candidates: writes,
            candidate_evidence: written_evidence,
            attachments,
            fence: self.write_fence(),
            read_receipt: self.read_receipt()?,
        })
    }

    pub(in crate::dreamer_consolidation) fn write_fence(&self) -> ConsolidationFence {
        ConsolidationFence {
            actor: self.actor,
            attempt: self.attempt,
            fallback_binding: self.fallback_binding(),
            sources: self.sources.clone(),
            turns: self.turns.clone(),
            texts: self.texts.clone(),
            conversation: self.partition.conversation_ref,
            rules: self.rules.clone(),
            closed: std::sync::Mutex::default(),
            standing: std::sync::Mutex::default(),
        }
    }
}

impl ConsolidationFence {
    pub(crate) fn validate_run(
        &self,
        run: &crate::dreamer_promotion::DreamerRunContext,
    ) -> Result<()> {
        if run.agent_actor != self.actor || run.attempt_id != self.attempt {
            return Err(invalid_consolidation(
                "scoped sink run does not match executor",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        let actor = ScopedReadActorKey::with_actor_class(
            self.actor.entity_ref().to_hex(),
            self.actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| invalid_consolidation("invalid pinned actor"))?;
        let recorded = vault
            .scoped_read(actor.clone())
            .with_claim_status(crate::claim::ClaimReadStatus::Recorded);
        let read = vault.scoped_read(actor);
        let rules: crate::dreamer_consolidation::routing::PredicateKeyRules =
            match crate::dreamer_consolidation::routing::KEY_RULES.get(&vault.store, txn, &())? {
                Some(rules) => rules,
                None => serde_json::from_str(include_str!("../key_defaults.json"))
                    .map_err(|_| invalid_consolidation("invalid default key rules"))?,
            };
        if rules != self.rules {
            return Err(invalid_consolidation("consolidation key rules changed"));
        }
        // Resolve fresh policy here. ScopedRead's cached manifest is not a
        // lease to retain a grant revoked during model or checker work.
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        if let Some(binding) = self.fallback_binding
            && !crate::llm::verified_step_consolidation_eligible_in_txn(
                vault,
                txn,
                &policy,
                binding.step,
                self.actor.entity_ref(),
                binding.response_hash,
            )
            .map_err(|_| invalid_consolidation("invalid extraction fallback checkpoint"))?
        {
            return Err(invalid_consolidation(
                "extraction fallback eligibility revoked",
            ));
        }
        let closed = self
            .closed
            .lock()
            .map_err(|_| invalid_consolidation("fence closed-prior lock"))?
            .clone();
        for (id, pin) in &self.sources {
            // A prior this handoff's own grant closed is held to the revision
            // that grant wrote, and read on the record lane: a closed claim
            // never surfaces, and every other read check still applies.
            let closed_at = closed.get(id);
            let lane = if closed_at.is_some() {
                &recorded
            } else {
                &read
            };
            if !lane.is_entity_readable_with_policy_in(txn, &policy, id)? {
                return Err(invalid_consolidation("pinned source read revoked"));
            }
            if closed_at.is_none()
                && !crate::gate::claim_consolidation_eligible_in_txn(
                    &vault.store,
                    txn,
                    id,
                    crate::gate::ConsolidationReader::FenceSource,
                )?
            {
                return Err(invalid_consolidation(
                    "pinned source awaits its owner's confirmation",
                ));
            }
            let stored = RowRevision::read_in(vault, txn, id)?
                .ok_or_else(|| invalid_consolidation("pinned source missing"))?;
            let expected = closed_at
                .cloned()
                .unwrap_or_else(|| RowRevision::of_pin(pin));
            if stored != expected {
                return Err(invalid_consolidation("pinned source revision changed"));
            }
        }
        let standing = self
            .standing
            .lock()
            .map_err(|_| invalid_consolidation("fence standing lock"))?
            .clone();
        for (id, revision) in &standing {
            if !read.is_entity_readable_with_policy_in(txn, &policy, id)?
                || RowRevision::read_in(vault, txn, id)?.as_ref() != Some(revision)
                || !crate::gate::claim_consolidation_eligible_in_txn(
                    &vault.store,
                    txn,
                    id,
                    crate::gate::ConsolidationReader::FenceReplacement,
                )?
            {
                return Err(invalid_consolidation("a replacement no longer stands"));
            }
        }
        for turn in &self.turns {
            let peers = crate::ports::EdgeStoreRead::port_edge_peers(
                &vault.store,
                txn,
                turn,
                crate::ports::EdgeDirection::Out,
                crate::edge::EdgeKind::ChildOf,
            )?
            .collect::<Result<Vec<_>>>()?;
            if peers != [self.conversation] {
                return Err(invalid_consolidation("pinned source partition changed"));
            }
        }
        // A witnessed TURN's text is its MESSAGE children: the exact child
        // set, bindings, versions and frontiers must still match the pin.
        for (turn, text) in &self.texts {
            text.check_live_in(&read, txn, turn)?;
        }
        Ok(())
    }

    /// The extraction fallback this branch consumed, with its Dreamer actor.
    pub(in crate::dreamer_consolidation) fn fallback(
        &self,
    ) -> Option<(FallbackOutputPin, EntityId)> {
        self.fallback_binding
            .map(|binding| (binding, self.actor.entity_ref()))
    }

    /// The frozen text the model saw for one fenced turn.
    pub(in crate::dreamer_consolidation) fn turn_text(
        &self,
        turn: &EntityId,
    ) -> Result<Option<&str>> {
        self.texts
            .get(turn)
            .map(TurnText::text)
            .ok_or_else(|| invalid_consolidation("unfenced extraction turn"))
    }

    #[cfg(test)]
    pub(crate) fn evidence_source(&self, candidate: &PromotionCandidate) -> Result<ClaimSource> {
        if candidate.evidence_turn_refs.is_empty() || !candidate.provenance_chain.is_empty() {
            return Err(invalid_consolidation("unadmitted consolidation evidence"));
        }
        let stored_meet =
            candidate
                .evidence_turn_refs
                .iter()
                .try_fold(ClaimSource::Generated, |meet, id| {
                    if !self.turns.contains(id) {
                        return Err(invalid_consolidation("unadmitted consolidation evidence"));
                    }
                    let trust = self
                        .sources
                        .get(id)
                        .and_then(|pin| pin.trust_class)
                        .ok_or_else(|| {
                            invalid_consolidation("unclassified consolidation evidence")
                        })?;
                    Ok(crate::dreamer_consolidation::source_meet(meet, trust))
                })?;
        if crate::dreamer_consolidation::source_meet(stored_meet, candidate.evidence_meet)
            != candidate.evidence_meet
        {
            return Err(invalid_consolidation(
                "native branch evidence source mismatch",
            ));
        }
        Ok(candidate.evidence_meet)
    }
}

impl ConsolidationFence {
    #[cfg(test)]
    pub(crate) fn for_reader_test(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: WriteActor,
        pinned: Option<EntityId>,
    ) -> Result<Self> {
        let mut sources = BTreeMap::new();
        if let Some(id) = pinned {
            let revision =
                RowRevision::read_in(vault, txn, &id)?.ok_or(crate::Error::EntityNotFound)?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
                .ok_or(crate::Error::EntityNotFound)?;
            let body = crate::claim::decode_claim_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                true,
            )?;
            sources.insert(
                id,
                SourcePin {
                    resource: revision.resource,
                    entity_type: revision.entity_type,
                    learned_at: revision.learned_at,
                    project: Some(body.scope_project),
                    trust_class: body.source,
                },
            );
        }
        let rules =
            match crate::dreamer_consolidation::routing::KEY_RULES.get(&vault.store, txn, &())? {
                Some(rules) => rules,
                None => serde_json::from_str(include_str!("../key_defaults.json"))
                    .map_err(|_| invalid_consolidation("invalid default key rules"))?,
            };
        Ok(Self {
            actor,
            attempt: crate::attempt_queue::AttemptId::now(),
            fallback_binding: None,
            sources,
            turns: BTreeSet::new(),
            texts: BTreeMap::new(),
            conversation: actor.entity_ref(),
            rules,
            closed: std::sync::Mutex::default(),
            standing: std::sync::Mutex::default(),
        })
    }
}
