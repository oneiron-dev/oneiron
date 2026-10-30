//! Interpreted reaction evidence for landing and commitment outcome bindings.
//! Normalization never guesses meaning. The host asks its configured typed
//! decision seat using a scoped snapshot, then records that decision here.
//! An acknowledgement is not consent and never fulfills a commitment.
use super::chain::{admission_in, reactions_on_in};
use super::value::decode_reaction;
use super::write::invalid;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, ScopedRead};
use crate::commitment::{CommitmentStatus, decode_commitment_claim};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestion, EvidenceVersion, TypedDecision,
};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::{ClaimCandidate, EntityId, Result, TimeRange, Vault, WriteEnvelope};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// String-valued facts consumed by the existing OF-516 event outcome projector.
/// Subjects are the reacted message and any explicitly selected commitments.
pub const PREDICATE_REACTION_OUTCOME: &str = "conversation.reaction.outcome";
pub const REACTION_MEANINGS: [&str; 5] = ["ack", "agree", "disagree", "affect", "none"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactionMeaning {
    Ack,
    Agree,
    Disagree,
    Affect,
    None,
}
impl ReactionMeaning {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Agree => "agree",
            Self::Disagree => "disagree",
            Self::Affect => "affect",
            Self::None => "none",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "ack" => Ok(Self::Ack),
            "agree" => Ok(Self::Agree),
            "disagree" => Ok(Self::Disagree),
            "affect" => Ok(Self::Affect),
            "none" => Ok(Self::None),
            _ => Err(invalid("invalid reaction meaning")),
        }
    }
}

/// The wording is host configuration. No emoji-to-stance rule is built in.
pub fn reaction_outcome_question(text: String) -> Result<DecisionQuestion> {
    crate::llm::decision::catalogue::REACTION_MEANING.question(
        &[],
        text,
        AnswerContract::Choice {
            options: REACTION_MEANINGS.iter().map(|s| (*s).to_owned()).collect(),
        },
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReactionOutcome {
    pub claim: EntityId,
    pub subject: EntityId,
    pub reaction: EntityId,
    pub message: EntityId,
    pub meaning: ReactionMeaning,
    pub decision: TypedDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourcePin {
    id: EntityId,
    entity_type: u8,
    learned_at: u64,
    body: Vec<u8>,
    frontier: Option<Vec<u8>>,
}
impl SourcePin {
    fn version(&self) -> EvidenceVersion {
        let mut hash = blake3::Hasher::new();
        hash.update(&(self.body.len() as u64).to_be_bytes());
        hash.update(&self.body);
        if let Some(frontier) = &self.frontier {
            hash.update(frontier);
        }
        EvidenceVersion {
            id: self.id,
            body_hash: *hash.finalize().as_bytes(),
        }
    }
}

/// A prepared, immutable read snapshot. Use `state` and `evidence` with the
/// shared decision ladder (local first; remote only within the host's dial).
/// No available decision leaves the reaction uninterpreted, not `none`.
#[derive(Debug, Clone)]
pub struct ReactionOutcomeEvidence {
    principal: EntityId,
    question: DecisionQuestion,
    reaction: EntityId,
    message: EntityId,
    occurred_at: u64,
    targets: Vec<EntityId>,
    sources: Vec<SourcePin>,
    glyph: String,
    by: EntityId,
}
impl ReactionOutcomeEvidence {
    #[must_use]
    pub fn evidence(&self) -> Vec<EntityId> {
        self.sources.iter().map(|source| source.id).collect()
    }

    #[must_use]
    pub fn question(&self) -> &DecisionQuestion {
        &self.question
    }

    /// Source bodies are data, never instructions. Live message projections
    /// include the document text, and each source is pinned again at landing.
    #[must_use]
    pub fn state(&self) -> serde_json::Value {
        serde_json::json!({
            "reaction": self.reaction.to_hex(), "message": self.message.to_hex(),
            "by": self.by.to_hex(), "glyph": self.glyph, "occurred_at": self.occurred_at,
            "claims_not_instructions": true,
            "sources": self.sources.iter().map(|source| {
                let mut encoded = source.body.as_slice();
                let body = match rmpv::decode::read_value(&mut encoded) {
                    Ok(value) if encoded.is_empty() => value.to_string(),
                    _ => String::from_utf8_lossy(&source.body).into_owned(),
                };
                serde_json::json!({"id": source.id.to_hex(), "body": body})
            }).collect::<Vec<_>>()
        })
    }
}

fn sources_in(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<Option<Vec<SourcePin>>> {
    let rows = read.get_entities_parts_in_txn(txn, ids)?;
    let mut sources = Vec::new();
    for (&id, row) in ids.iter().zip(rows) {
        let Some((entity_type, learned_at, body)) = row else {
            return Ok(None);
        };
        sources.push(SourcePin {
            id,
            entity_type,
            learned_at,
            body,
            frontier: crate::entity_doc::source_frontier_in_txn(&read.vault().store, txn, &id)?,
        });
    }
    Ok(Some(sources))
}

impl ScopedRead<'_> {
    /// Prepares a received reaction to this reader's own message. Commitments
    /// are explicit, readable obligations owed by this author to this reactor;
    /// the question sees their content and never treats acknowledgement as done.
    pub fn prepare_reaction_outcome(
        &self,
        question: &DecisionQuestion,
        reaction: EntityId,
        commitments: &[EntityId],
    ) -> Result<Option<ReactionOutcomeEvidence>> {
        question.validate()?;
        let expected: BTreeSet<_> = REACTION_MEANINGS.iter().map(|s| (*s).to_owned()).collect();
        if question.class != DecisionClass::Judgment
            || !matches!(&question.contract, AnswerContract::Choice { options }
                if options.iter().cloned().collect::<BTreeSet<_>>() == expected)
        {
            return Err(invalid(
                "reaction outcome requires the reaction meaning contract",
            ));
        }
        let principal = EntityId::from_hex(self.actor_key().actor_ref())
            .map_err(|_| invalid("reaction outcome reader is not an entity"))?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn()?;
        let Some(initial) = sources_in(self, &txn, &[reaction])? else {
            return Ok(None);
        };
        let body = crate::claim::decode_claim_body(&initial[0].body, true)?;
        let Some(value) = decode_reaction(&body) else {
            return Ok(None);
        };
        let ClaimSubject::Entity(message) = body.subject else {
            return Ok(None);
        };
        let fold = admission_in(vault, &txn)?;
        if value.by == principal
            || !reactions_on_in(vault, &txn, &fold, message)?
                .iter()
                .any(|row| row.id == reaction && row.live())
            || !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, &txn, &reaction)?
        {
            return Ok(None);
        }
        let mut authored = false;
        for edge in vault.store.port_edges(
            &txn,
            &message,
            EdgeDirection::Out,
            Some(EdgeKind::AuthoredBy),
            None,
        )? {
            authored |= edge?.target == principal;
        }
        if !authored {
            return Ok(None);
        }
        let mut targets = vec![message];
        targets.extend(commitments.iter().copied().collect::<BTreeSet<_>>());
        let mut ids = vec![reaction];
        ids.extend(&targets);
        let Some(sources) = sources_in(self, &txn, &ids)? else {
            return Ok(None);
        };
        for source in sources.iter().skip(2) {
            let body = crate::claim::decode_claim_body(&source.body, true)?;
            let Some(commitment) = decode_commitment_claim(&body)? else {
                return Err(invalid("reaction outcome target is not a commitment"));
            };
            if !crate::claim::claim_surfaceable(&body)
                || commitment.status != CommitmentStatus::Open
                || commitment.obligor.entity_ref != principal
                || commitment.beneficiary != value.by
            {
                return Err(invalid(
                    "reaction outcome commitment has different parties or is closed",
                ));
            }
        }
        Ok(Some(ReactionOutcomeEvidence {
            principal,
            question: question.clone(),
            reaction,
            message,
            occurred_at: value.occurred_at,
            targets,
            sources,
            glyph: value.glyph,
            by: value.by,
        }))
    }

    /// Records the extractor's typed interpretation, never a belief inferred
    /// from a raw glyph. Ordinary claim Gate/approval applies. The resulting
    /// string facts feed OF-516 `OutcomeSource::Event` mappings on the message
    /// (landing) or commitment. No status, grant or outbound receipt is changed.
    pub fn record_reaction_outcome(
        &self,
        prepared: ReactionOutcomeEvidence,
        mut decision: TypedDecision,
        envelope: &WriteEnvelope,
    ) -> Result<Vec<ReactionOutcome>> {
        if self.actor_key().actor_ref() != prepared.principal.to_hex()
            || envelope.actor().entity_ref() != prepared.principal
            || envelope.actor().actor_class() == EdgeActorClass::System
            || envelope.source() != ClaimSource::Generated
            || !matches!(
                envelope.approval(),
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
            )
            || decision.receipt.principal != prepared.principal
            || decision.receipt.question != prepared.question.id
            || decision.receipt.question_version != prepared.question.version
            || !prepared.question.contract.accepts(&decision.answer)
            || decision.evidence.iter().copied().collect::<BTreeSet<_>>()
                != prepared.evidence().into_iter().collect::<BTreeSet<_>>()
        {
            return Err(invalid(
                "reaction outcome differs from its scoped question evidence",
            ));
        }
        let DecisionAnswer::Choice(label) = &decision.answer else {
            return Ok(Vec::new());
        };
        if decision.in_band || decision.human_ask.is_some() {
            return Ok(Vec::new());
        }
        let meaning = ReactionMeaning::parse(label)?;
        let probability = decision
            .probability
            .filter(|p| p.is_finite() && (0.0..=1.0).contains(p))
            .ok_or_else(|| invalid("reaction outcome has no measured confidence"))?;
        let versions: Vec<_> = prepared.sources.iter().map(SourcePin::version).collect();
        let source_scope = crate::claim::decode_claim_body(&prepared.sources[0].body, true)?;
        if !decision.receipt.evidence_versions.is_empty()
            && decision.receipt.evidence_versions != versions
        {
            return Err(invalid("reaction outcome source versions differ"));
        }
        decision.receipt.evidence_versions = versions;
        let decision_value = encoded_value(&decision)?;
        let evidence = Value::Map(vec![
            (
                Value::from("reaction"),
                Value::Binary(prepared.reaction.as_bytes().to_vec()),
            ),
            (
                Value::from("message"),
                Value::Binary(prepared.message.as_bytes().to_vec()),
            ),
            (Value::from("decision"), decision_value),
        ]);
        let vault = self.vault();
        vault.with_write_txn_grouped(|txn| {
            if sources_in(self, txn, &prepared.evidence())?.as_ref() != Some(&prepared.sources)
                || vault
                    .get_claim_for_effect_in_txn(txn, &prepared.reaction)?
                    .is_none_or(|body| !crate::claim::claim_surfaceable(&body))
            {
                return Err(invalid("reaction outcome evidence changed before landing"));
            }
            let now = vault.store.clock.now_recorded_at();
            let existing = source_outcomes_in(vault, txn, prepared.reaction)?;
            let envelope = WriteEnvelope::with_lineage(
                envelope.actor(),
                envelope.source(),
                envelope.provenance().clone(),
                envelope.approval(),
                envelope.lineage().clone().with(ClaimSource::Observed),
            );
            let mut results = Vec::new();
            for &subject in &prepared.targets {
                let mut replay = None;
                for &id in &existing {
                    let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
                        continue;
                    };
                    let Some(outcome) = decode_outcome(id, &body)? else {
                        continue;
                    };
                    if outcome.subject != subject
                        || outcome.decision.receipt.principal != prepared.principal
                        || outcome.decision.receipt.question != prepared.question.id
                        || outcome.decision.receipt.question_version != prepared.question.version
                        || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
                        || body.stale
                    {
                        continue;
                    }
                    if outcome.meaning == meaning {
                        replay = Some(outcome);
                    } else {
                        vault.retract_claim_in_txn_as(txn, &id, now, None)?;
                    }
                }
                if let Some(outcome) = replay {
                    results.push(outcome);
                    continue;
                }
                let id = vault.store.clock.entity_id()?;
                let mut candidate = ClaimCandidate::new(
                    PREDICATE_REACTION_OUTCOME,
                    ClaimSubject::Entity(subject),
                    Value::from(meaning.as_str()),
                    probability as f32,
                )
                .with_evidence(evidence.clone())
                .with_scope_stamps(source_scope.scope_facet, source_scope.scope_project);
                if let Some(world) = source_scope.world {
                    candidate = candidate.with_world(world);
                }
                candidate = candidate.with_relationships(source_scope.rel.clone());
                if let Some(scope) = &source_scope.scope {
                    candidate = candidate.with_scope(scope.clone());
                }
                let candidate = candidate
                    .with_private_reader(prepared.principal)?
                    .with_evidence_taint(ClaimSource::Observed)?;
                let mut batch = vault.batch_in().claim_candidate(
                    &id,
                    candidate,
                    &envelope,
                    TimeRange {
                        start: prepared.occurred_at,
                        end: prepared.occurred_at,
                    },
                    now,
                );
                for source in &prepared.sources {
                    batch = batch.edge(&id, EdgeKind::DerivedFrom, &source.id, 1.0);
                }
                batch.apply(txn)?;
                results.push(ReactionOutcome {
                    claim: id,
                    subject,
                    reaction: prepared.reaction,
                    message: prepared.message,
                    meaning,
                    decision: decision.clone(),
                });
            }
            Ok(results)
        })
    }
}

fn encoded_value(value: &impl Serialize) -> Result<Value> {
    let bytes =
        rmp_serde::to_vec_named(value).map_err(|_| invalid("reaction outcome decision encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| invalid("reaction outcome decision value"))
}

pub(super) fn decode_outcome(id: EntityId, body: &ClaimBody) -> Result<Option<ReactionOutcome>> {
    if body.predicate != PREDICATE_REACTION_OUTCOME {
        return Ok(None);
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Ok(None);
    };
    let Some(Value::Map(stamped)) = &body.evidence else {
        return Ok(None);
    };
    let Some(Value::Map(evidence)) = stamped.iter().find_map(|(key, value)| {
        (key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
            .then_some(value)
    }) else {
        return Ok(None);
    };
    let get = |name: &str| {
        evidence
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
    };
    let entity = |name| -> Option<EntityId> {
        let Value::Binary(bytes) = get(name)? else {
            return None;
        };
        EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
    };
    let (Some(reaction), Some(message), Some(decision)) =
        (entity("reaction"), entity("message"), get("decision"))
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, decision)
        .map_err(|_| invalid("reaction outcome decision"))?;
    let decision =
        rmp_serde::from_slice(&bytes).map_err(|_| invalid("reaction outcome decision"))?;
    Ok(Some(ReactionOutcome {
        claim: id,
        subject,
        reaction,
        message,
        meaning: ReactionMeaning::parse(
            body.value
                .as_str()
                .ok_or_else(|| invalid("reaction outcome meaning"))?,
        )?,
        decision,
    }))
}

pub(super) fn source_outcomes_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for edge in vault.store.port_edges(
        txn,
        &source,
        EdgeDirection::In,
        Some(EdgeKind::DerivedFrom),
        None,
    )? {
        let id = edge?.target;
        if super::chain::stored_claim_in(vault, txn, &id)?
            .is_some_and(|(body, _)| body.predicate == PREDICATE_REACTION_OUTCOME)
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Removing a reaction withdraws its interpreted evidence too, so an old ack
/// cannot keep labelling predictions after a provider removal or a toggle.
pub(super) fn retract_source_outcomes_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    now: u64,
) -> Result<()> {
    for id in source_outcomes_in(vault, txn, source)? {
        if vault
            .get_claim_in_txn(txn, &id)?
            .is_some_and(|body| body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
        {
            vault.retract_claim_in_txn_as(txn, &id, now, None)?;
        }
    }
    Ok(())
}

/// A model interpretation is not ordinary factual evidence. Only this event
/// adapter may use it as a noisy outcome label, grounded in its still-live
/// observed reaction. Generated claims remain ineligible everywhere else.
pub(crate) fn outcome_fact_admissible_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    if body.predicate != PREDICATE_REACTION_OUTCOME
        || body.source != Some(ClaimSource::Generated)
        || !crate::claim::claim_surfaceable(body)
    {
        return Ok(false);
    }
    let Some(outcome) = decode_outcome(id, body)? else {
        return Ok(false);
    };
    let decision = &outcome.decision;
    if decision.answer != DecisionAnswer::Choice(outcome.meaning.as_str().to_owned())
        || decision.in_band
        || decision.human_ask.is_some()
        || decision.receipt.question_version == 0
        || crate::memory::claim_author(body) != Some(decision.receipt.principal)
        || !decision
            .probability
            .is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p))
        || !decision.evidence.contains(&outcome.reaction)
        || !decision.evidence.contains(&outcome.message)
        || !decision.evidence.contains(&outcome.subject)
        || decision.receipt.evidence_versions.len() != decision.evidence.len()
    {
        return Ok(false);
    }
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    for source in &decision.receipt.evidence_versions {
        if !decision.evidence.contains(&source.id)
            || crate::vault_cleanup::is_archived_in_txn(store, txn, &source.id)?
        {
            return Ok(false);
        }
        let Some(raw) =
            crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, &source.id)?
        else {
            return Ok(false);
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
            return Ok(false);
        };
        if raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN {
            return Ok(false);
        }
        let mut source_body = raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec();
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let mut claim = crate::claim::decode_claim_body(&source_body, true)?;
            if crate::authority::machine_claim_needs_history(store, txn, &claim)? {
                let Ok(projection) = crate::claim::history_projection::resolved_machine_history(
                    store, txn, &fold, source.id,
                ) else {
                    return Ok(false);
                };
                claim = crate::claim::history_projection::project_machine_claim(&projection);
            }
            if !crate::authority::claim_causal_admitted(store, txn, &fold, &source.id, &claim)?
                || !crate::gate::claim_critical_confirm_settled_in_txn(store, txn, &source.id)?
            {
                return Ok(false);
            }
            if source.id == outcome.reaction {
                let Some(reaction) = decode_reaction(&claim) else {
                    return Ok(false);
                };
                if claim.subject != ClaimSubject::Entity(outcome.message)
                    || reaction.by == decision.receipt.principal
                    || !crate::claim::claim_consolidatable(&claim)
                    || !crate::claim::claim_evidence_admissible(&claim)
                {
                    return Ok(false);
                }
            }
            source_body = crate::claim::encode_claim_body(&claim)?;
        } else {
            if source.id == outcome.reaction {
                return Ok(false);
            }
            source_body =
                crate::entity_doc::resolve_record_body(store, txn, &source.id, &source_body)?;
        }
        let pin = SourcePin {
            id: source.id,
            entity_type: header.entity_type,
            learned_at: header.learned_at,
            body: source_body,
            frontier: crate::entity_doc::source_frontier_in_txn(store, txn, &source.id)?,
        };
        if pin.version() != *source {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn outcome_sources(body: &ClaimBody) -> Result<Vec<EntityId>> {
    // The id is only an output label on the decoded view, not evidence.
    let id = match body.subject {
        ClaimSubject::Entity(id) => id,
        ClaimSubject::Edge { source, .. } => source,
    };
    Ok(decode_outcome(id, body)?.map_or_else(Vec::new, |outcome| outcome.decision.evidence))
}

pub(crate) fn outcome_question(body: &ClaimBody) -> Result<Option<EntityId>> {
    let id = match body.subject {
        ClaimSubject::Entity(id) => id,
        ClaimSubject::Edge { source, .. } => source,
    };
    Ok(decode_outcome(id, body)?.map(|outcome| outcome.decision.receipt.question))
}
