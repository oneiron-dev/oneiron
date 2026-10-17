//! Explicit graph-unit backfill with same-snapshot authority and source pins.

use super::super::types::invalid;
use super::{records::*, store::*};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey,
};
use crate::llm::decision::{
    DecisionAnswer, DecisionReceipt, PairedReading, ProviderPin, TypedDecision,
};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;

/// One backfill identity: question id + `backfill` family + version, unit and frontier.
#[derive(Clone, Copy)]
struct BackfillKey {
    question: EntityId,
    version: u32,
    unit: EntityId,
    frontier: [u8; 32],
}
impl SideKey for BackfillKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.question, b"backfill"));
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(self.unit.as_bytes());
        out.extend_from_slice(&self.frontier);
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (question, tail) = super::store::decode_family(bytes, b"backfill")?;
        let (version, tail) = tail.split_at_checked(4)?;
        let (unit, frontier) = tail.split_at_checked(16)?;
        Some(Self {
            question,
            version: u32::from_be_bytes(version.try_into().ok()?),
            unit: EntityId::from_bytes(unit.try_into().ok()?).ok()?,
            frontier: frontier.try_into().ok()?,
        })
    }
}
const QUESTION_BACKFILL: SideTable<BackfillKey, EntityIdBytes, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);

/// The host obtains `source_frontier` before asking a provider. Admission
/// refuses a response if any source changed while the provider was working.
#[derive(Debug, Clone)]
pub struct StandingAnswer {
    pub unit: EntityId,
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    pub evidence: Vec<EntityId>,
    pub providers: Vec<ProviderPin>,
    /// Paired readings the providers measured with this answer; none means none was taken.
    pub paired: Vec<PairedReading>,
    pub source_frontier: [u8; 32],
}

/// What one source row puts on an answer resting on it.
pub(super) struct Source {
    kind: u8,
    claim: Option<ClaimBody>,
    position: (EntityId, EntityId, EntityId),
    sensitivity: u8,
}

impl Source {
    /// The row `raw` of type `kind` under its record Scope `scope`: its one
    /// facet, project and world, its sensitivity and, for a claim, its body.
    /// A Scope with no single position bounds no answer.
    pub(super) fn of_row(kind: u8, raw: &[u8], scope: &crate::federation::Scope) -> Result<Self> {
        let position = (
            singleton(&scope.facets)?,
            singleton(&scope.audience)?,
            singleton(&scope.worlds)?,
        );
        let sensitivity = match scope.sensitivity {
            crate::federation::SensitivityCeiling::AtMost(level) => match level {
                crate::federation::Sensitivity::Public => 0,
                crate::federation::Sensitivity::Private => 1,
                crate::federation::Sensitivity::Sensitive => 2,
                crate::federation::Sensitivity::Restricted => 3,
            },
            crate::federation::SensitivityCeiling::Bottom => {
                return Err(invalid("unrepresentable evidence sensitivity"));
            }
        };
        let claim = if kind == crate::registry::ENTITY_TYPE_CLAIM {
            Some(crate::claim::decode_claim_body(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                true,
            )?)
        } else {
            None
        };
        Ok(Self {
            kind,
            claim,
            position,
            sensitivity,
        })
    }
}

fn singleton(axis: &crate::federation::ScopeAxis<crate::federation::ScopeId>) -> Result<EntityId> {
    let crate::federation::ScopeAxis::Some(ids) = axis else {
        return Err(invalid("unrepresentable evidence scope"));
    };
    if ids.len() != 1 {
        return Err(invalid("unrepresentable evidence scope"));
    }
    Ok(ids.iter().next().expect("one scope member").0)
}

fn standing_record(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    question: EntityId,
    version: u32,
) -> Result<(QuestionHead, QuestionRecord)> {
    let head = owned_head(vault, txn, principal, question)?;
    if head.version != version {
        return Err(Error::ConcurrentWrite("standing question changed"));
    }
    let record: QuestionRecord = QUESTION_VERSION
        .get(
            &vault.store,
            txn,
            &VersionKey {
                id: question,
                version,
            },
        )?
        .ok_or(Error::EntityNotFound)?;
    if record.schema_version != 1 {
        return Err(invalid("unsupported question schema"));
    }
    record.definition.validate()?;
    if record.definition.activation != QuestionActivation::Standing
        || record.definition.adapter != "graph"
    {
        return Err(invalid("not a standing graph question"));
    }
    Ok((head, record))
}

fn sources_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    actor: WriteActor,
    unit: EntityId,
    evidence: &[EntityId],
    proposals: &[AnswerRecord],
) -> Result<([u8; 32], Vec<Source>)> {
    if evidence.len() > 4096 {
        return Err(invalid("too many standing answer sources"));
    }
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    // Relationship membership and AccessGrants are the question principal's,
    // for both reads: the writer's own grant never widens what the
    // principal's answer may rest on. The vault's live owner reads its
    // relationships' rows as it does on every lane.
    let reader = super::graph_ask::asker_reader_in_txn(vault, txn, principal)?;
    let holder = ScopedReadActorKey::with_actor_class(
        actor.entity_ref().to_hex(),
        actor.actor_class().gate_actor_class(),
    )
    .ok_or(Error::InvariantViolation("canonical question actor"))?
    .exempt_while_owner(principal);
    let mut hasher = blake3::Hasher::new();
    let mut sources = Vec::with_capacity(evidence.len() + 1);
    for id in std::iter::once(&unit).chain(evidence.iter()) {
        let proposal = proposals
            .iter()
            .find(|answer| answer.claim == *id && *id != unit);
        let reader_lane = vault.scoped_read(reader.clone());
        let readable = if proposal.is_some() {
            // Only results already returned to this workflow may feed its next
            // proposal. They remain private to the asker and are never kept here.
            reader_lane
                .recorded_lane()?
                .is_entity_readable_with_policy_in(txn, &policy, id)?
        } else {
            reader_lane.is_entity_readable_with_policy_in(txn, &policy, id)?
                && vault
                    .scoped_read(holder.clone())
                    .is_entity_readable_with_policy_in(txn, &policy, id)?
        };
        if !readable {
            return Err(Error::EntityNotFound);
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("standing source header"))?;
        // A claim awaiting its owner's answer is a missing required source.
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
            || raw.len() == ENTITY_METADATA_HEADER_LEN
            || (header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && !crate::gate::claim_consolidation_eligible_in_txn(
                    &vault.store,
                    txn,
                    id,
                    crate::gate::ConsolidationReader::StandingAnswerSource,
                )?)
        {
            return Err(Error::EntityNotFound);
        }
        if let Some(answer) = proposal {
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                return Err(Error::EntityNotFound);
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            let value = rmpv::decode::read_value(&mut encode(answer)?.as_slice())
                .map_err(|_| Error::CorruptedIndex("workflow answer encoding"))?;
            if answer.decision.receipt.principal != principal
                || body.predicate != "judgment.answer"
                || body.subject != ClaimSubject::Entity(answer.unit)
                || body.value != value
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.approval == ClaimApprovalStatus::Rejected
                || body.stale
            {
                return Err(Error::EntityNotFound);
            }
        }
        hasher.update(id.as_bytes());
        hasher.update(&(raw.len() as u64).to_be_bytes());
        hasher.update(&raw);
        #[cfg(feature = "sync")]
        let entity_doc = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, id)?;
        #[cfg(not(feature = "sync"))]
        let entity_doc: Option<Vec<u8>> = None;
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE && entity_doc.is_none() {
            let frontier = crate::note::live_frontier_in_txn(vault, txn, *id)?;
            hasher.update(&(frontier.len() as u64).to_be_bytes());
            hasher.update(&frontier);
        }
        if let Some(frontier) = entity_doc {
            hasher.update(b"entity-document");
            hasher.update(&(frontier.len() as u64).to_be_bytes());
            hasher.update(&frontier);
        }
        let scope = crate::federation::record_scope::scope_for_blob(&vault.store, txn, *id, &raw)?
            .ok_or(Error::EntityNotFound)?;
        // The shared scoped reader checks NOTE authorship, but its NOTE branch
        // returns before the non-claim record-position grant. Conjoin both.
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE
            && (!crate::gate::scoped_read_record_allowed(&policy, &reader, &scope)
                || !crate::gate::scoped_read_record_allowed(&policy, &holder, &scope))
        {
            return Err(Error::EntityNotFound);
        }
        sources.push(Source::of_row(header.entity_type, &raw, &scope)?);
    }
    Ok((*hasher.finalize().as_bytes(), sources))
}

/// Resolve the complete source set under the principal and writing actor in
/// one read snapshot. Pass this pin to `backfill_standing_answer` after work.
pub fn standing_source_frontier(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    expected_version: u32,
    actor: WriteActor,
    unit: EntityId,
    evidence: &[EntityId],
) -> Result<[u8; 32]> {
    // Grant expiry is judged at a clock persisted before the snapshot, as
    // every read lane judges it.
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let (_, record) = standing_record(vault, &txn, principal, question, expected_version)?;
    if !record.definition.units.contains(&unit) {
        return Err(Error::EntityNotFound);
    }
    Ok(sources_in_txn(vault, &txn, principal, actor, unit, evidence, &[])?.0)
}

/// Keep a graph answer and its immutable-version receipt atomically. Repeated
/// work at one source frontier is idempotent; an edited source may refresh.
/// Manual backfill remains available while automatic refresh is paused.
pub fn backfill_standing_answer(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    expected_version: u32,
    actor: WriteActor,
    input: StandingAnswer,
    now: u64,
) -> Result<AnswerRecord> {
    backfill_answer(
        vault,
        principal,
        question,
        expected_version,
        actor,
        input,
        Measured::Bare,
        &[],
        now,
    )
}

/// Read an explicit recipe and pin every source in the same authorized snapshot.
pub(super) fn prepare_graph_answer(
    vault: &Vault,
    principal: EntityId,
    reference: super::GraphQuestionRef,
    actor: WriteActor,
    input: &super::GraphQuestionInput,
    proposals: &[AnswerRecord],
) -> Result<(QuestionRecord, super::GraphUnitContext, [u8; 32])> {
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let (_, record) = standing_record(vault, &txn, principal, reference.id, reference.version)?;
    if !record.definition.units.contains(&input.unit) {
        return Err(Error::EntityNotFound);
    }
    let (frontier, _) = sources_in_txn(
        vault,
        &txn,
        principal,
        actor,
        input.unit,
        &input.evidence,
        proposals,
    )?;
    let scoped = vault.scoped_read(super::graph_ask::asker_reader_in_txn(
        vault, &txn, principal,
    )?);
    let mut sources = Vec::with_capacity(input.evidence.len() + 1);
    for id in std::iter::once(&input.unit).chain(input.evidence.iter()) {
        let lane = if proposals
            .iter()
            .any(|answer| answer.claim == *id && *id != input.unit)
        {
            scoped.recorded_lane()?
        } else {
            vault.scoped_read(super::graph_ask::asker_reader_in_txn(
                vault, &txn, principal,
            )?)
        };
        let Some((kind, _, body)) = lane.graph_ask_parts_in_txn(&txn, id)? else {
            return Err(Error::EntityNotFound);
        };
        if !super::graph_ask::kind_is_graph_evidence(kind)
            || body.is_empty()
            || body.len() > 1_048_576
        {
            return Err(Error::EntityNotFound);
        }
        sources.push(super::GraphContextSource {
            id: *id,
            entity_type: kind,
            hash: *blake3::hash(&body).as_bytes(),
            body,
        });
    }
    Ok((
        record,
        super::GraphUnitContext {
            unit: input.unit,
            sources,
        },
        frontier,
    ))
}

pub(super) fn backfill_graph_answer(
    vault: &Vault,
    principal: EntityId,
    reference: super::GraphQuestionRef,
    actor: WriteActor,
    context: super::GraphUnitContext,
    frontier: [u8; 32],
    prediction: super::GraphPrediction,
    proposals: &[AnswerRecord],
    now: u64,
) -> Result<AnswerRecord> {
    let versions = context
        .sources
        .iter()
        .map(|source| crate::llm::decision::EvidenceVersion {
            id: source.id,
            body_hash: source.hash,
        })
        .collect();
    let input = StandingAnswer {
        unit: context.unit,
        answer: prediction.answer,
        probability: Some(prediction.probability),
        evidence: context
            .sources
            .iter()
            .skip(1)
            .map(|source| source.id)
            .collect(),
        providers: vec![prediction.provider.clone()],
        paired: prediction
            .paired
            .map(|reading| reading.bind(prediction.provider))
            .into_iter()
            .collect(),
        source_frontier: frontier,
    };
    backfill_answer(
        vault,
        principal,
        reference.id,
        reference.version,
        actor,
        input,
        Measured::Graph(versions, prediction.cost_per_thousand),
        proposals,
        now,
    )
}

/// [`backfill_graph_answer`] for a full ladder decision: its band, readings,
/// clock and owner-ask reason stay its own, over the engine's source, image
/// and audio versions.
pub(super) fn backfill_graph_decision(
    vault: &Vault,
    principal: EntityId,
    reference: super::GraphQuestionRef,
    actor: WriteActor,
    context: super::GraphUnitContext,
    frontier: [u8; 32],
    images: &[crate::llm::decision::DecisionImage],
    audio: &[crate::llm::decision::DecisionAudio],
    decision: TypedDecision,
    proposals: &[AnswerRecord],
    now: u64,
) -> Result<AnswerRecord> {
    let decision = super::graph_ask::decided(&context, images, audio, decision);
    let input = StandingAnswer {
        unit: context.unit,
        answer: decision.answer.clone(),
        probability: decision.probability,
        evidence: context
            .sources
            .iter()
            .skip(1)
            .map(|source| source.id)
            .collect(),
        providers: decision.receipt.providers.clone(),
        paired: decision.receipt.paired.clone(),
        source_frontier: frontier,
    };
    backfill_answer(
        vault,
        principal,
        reference.id,
        reference.version,
        actor,
        input,
        Measured::Decided(Box::new(decision)),
        proposals,
        now,
    )
}

/// What the engine pins beside a standing answer's providers.
enum Measured {
    /// Nothing more: a host's own backfill.
    Bare,
    /// A graph prediction's source versions and cost.
    Graph(Vec<crate::llm::decision::EvidenceVersion>, f64),
    /// A full ladder decision, its evidence versions already the engine's.
    Decided(Box<TypedDecision>),
}

fn backfill_answer(
    vault: &Vault,
    principal: EntityId,
    question: EntityId,
    expected_version: u32,
    actor: WriteActor,
    input: StandingAnswer,
    measurement: Measured,
    proposals: &[AnswerRecord],
    now: u64,
) -> Result<AnswerRecord> {
    vault.store.authorization_now()?;
    vault.with_write_txn_grouped(|txn| {
        let (mut head, record) =
            standing_record(vault, txn, principal, question, expected_version)?;
        if !record.definition.units.contains(&input.unit)
            || !record.definition.question.contract.accepts(&input.answer)
            || matches!(input.answer, DecisionAnswer::Abstain)
            || input
                .probability
                .is_some_and(|p| !p.is_finite() || !(0.0..=1.0).contains(&p))
            || input.providers.len() > 64
            || input.providers.iter().any(|pin| {
                pin.model.is_empty()
                    || pin.version.is_empty()
                    || pin.model.len() > 256
                    || pin.version.len() > 256
                    || pin.rung < record.definition.dial.first
                    || pin.rung > record.definition.dial.ceiling
            })
            || !PairedReading::rows_valid(&input.paired, question, &input.providers)
        {
            return Err(invalid("invalid standing answer"));
        }
        let (frontier, sources) = sources_in_txn(
            vault,
            txn,
            principal,
            actor,
            input.unit,
            &input.evidence,
            proposals,
        )?;
        if frontier != input.source_frontier {
            return Err(Error::ConcurrentWrite("standing source changed"));
        }
        let dedup = BackfillKey {
            question,
            version: expected_version,
            unit: input.unit,
            frontier,
        };
        if let Some(claim) = QUESTION_BACKFILL.get(&vault.store, txn, &dedup)? {
            let answer = QUESTION_ANSWER
                .get(
                    &vault.store,
                    txn,
                    &AnswerKey {
                        question,
                        claim: EntityId::from_bytes(claim.0)?,
                    },
                )?
                .ok_or(Error::CorruptedIndex("standing backfill answer"))?;
            if answer.unit != input.unit
                || answer.frontier != frontier
                || answer.decision.evidence != input.evidence
                || answer.decision.receipt.question != question
                || answer.decision.receipt.question_version != expected_version
                || answer.decision.receipt.principal != principal
            {
                return Err(Error::CorruptedIndex("standing backfill identity"));
            }
            let id = answer.claim;
            let reader = ScopedReadActorKey::with_actor_class(
                principal.to_hex(),
                actor.actor_class().gate_actor_class(),
            )
            .ok_or(Error::InvariantViolation("canonical question principal"))?;
            let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
            if crate::vault_cleanup::is_archived_in_txn(&vault.store, txn, &id)? {
                return Err(Error::EntityNotFound);
            }
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("standing answer header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
                return Err(Error::EntityNotFound);
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            let encoded = encode(&answer)?;
            let value = rmpv::decode::read_value(&mut encoded.as_slice())
                .map_err(|_| Error::CorruptedIndex("standing answer encoding"))?;
            if body.predicate != "judgment.answer"
                || body.subject != ClaimSubject::Entity(input.unit)
                || body.value != value
                || body.stale
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.approval == ClaimApprovalStatus::Rejected
                || !crate::gate::scoped_read_claim_allowed(
                    &policy,
                    &reader,
                    &body,
                    &crate::claim::facet_refs_in_port(&vault.store, txn, &id)?,
                )
            {
                return Err(Error::EntityNotFound);
            }
            return Ok(answer);
        }
        let mut answer = AnswerRecord {
            claim: EntityId::now(),
            unit: input.unit,
            decision: TypedDecision {
                in_band: input
                    .probability
                    .is_some_and(|p| record.definition.dial.band.contains(p)),
                answer: input.answer,
                probability: input.probability,
                evidence: input.evidence,
                receipt: DecisionReceipt {
                    question,
                    question_version: expected_version,
                    principal,
                    providers: input.providers,
                    band: record.definition.dial.band,
                    band_version: 0,
                    evidence_versions: Vec::new(),
                    cost_per_thousand: None,
                    paired: input.paired,
                    person: Vec::new(),
                    time: None,
                    images: Vec::new(),
                },
                human_ask: None,
            },
            frontier,
            source_kind: sources[0].kind,
            answered_at: now,
        };
        match &measurement {
            Measured::Bare => {}
            Measured::Graph(versions, cost) => {
                answer.decision.receipt.evidence_versions = versions.clone();
                answer.decision.receipt.cost_per_thousand = Some(*cost);
            }
            Measured::Decided(decided) => {
                let receipt = &mut answer.decision.receipt;
                receipt.band = decided.receipt.band;
                receipt.band_version = decided.receipt.band_version;
                receipt.evidence_versions = decided.receipt.evidence_versions.clone();
                receipt.cost_per_thousand = decided.receipt.cost_per_thousand;
                receipt.person = decided.receipt.person.clone();
                receipt.time = decided.receipt.time.clone();
                answer.decision.in_band = decided.in_band;
                answer.decision.human_ask = decided.human_ask;
            }
        }
        let encoded = encode(&answer)?;
        let value = rmpv::decode::read_value(&mut encoded.as_slice())
            .map_err(|_| Error::CorruptedIndex("standing answer encoding"))?;
        let mut candidate = ClaimCandidate::new(
            "judgment.answer",
            ClaimSubject::Entity(input.unit),
            value.clone(),
            1.0,
        );
        let taint = constrain_sources(&mut candidate, &sources, principal)?;
        let mut refs = vec![input.unit];
        for id in &answer.decision.evidence {
            if !refs.contains(id) {
                refs.push(*id);
            }
        }
        candidate = candidate
            .with_evidence_taint(taint)?
            .with_private_reader(principal)?
            .with_evidence(Value::Array(
                refs.iter().map(|id| Value::from(id.to_hex())).collect(),
            ));
        let source = crate::dreamer_consolidation::source_meet(ClaimSource::Generated, taint);
        let envelope = WriteEnvelope::new(
            actor,
            source,
            WriteProvenance::new(value)?,
            ClaimApprovalStatus::Proposed,
        );
        vault
            .batch_in()
            .claim_candidate(
                &answer.claim,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply(txn)?;
        QUESTION_ANSWER.put(
            &vault.store,
            txn,
            &AnswerKey {
                question,
                claim: answer.claim,
            },
            &answer,
        )?;
        QUESTION_BACKFILL.put(
            &vault.store,
            txn,
            &dedup,
            &EntityIdBytes(*answer.claim.as_bytes()),
        )?;
        head.last_refresh = Some(now);
        QUESTION_HEAD.put(&vault.store, txn, &HeadKey(question), &head)?;
        Ok(answer)
    })
}

/// Bounds `candidate` by every source it rests on: their one position, the
/// highest sensitivity, the claims' scope terms and relationship. Returns the
/// sources' met taint.
pub(super) fn constrain_sources(
    candidate: &mut ClaimCandidate,
    sources: &[Source],
    principal: EntityId,
) -> Result<ClaimSource> {
    let mut taint = ClaimSource::UserStated;
    let mut facet = None;
    let mut project = None;
    let mut world = None;
    let mut rel = None;
    let mut scope: Vec<(Value, Value)> = Vec::new();
    let mut sensitivity = 0_u8;
    let principal_hex = principal.to_hex();
    for source in sources {
        sensitivity = sensitivity.max(source.sensitivity);
        for (slot, id) in [
            (&mut facet, source.position.0),
            (&mut project, source.position.1),
            (&mut world, source.position.2),
        ] {
            if slot.is_some_and(|existing| existing != id) {
                return Err(invalid("incompatible evidence scope"));
            }
            *slot = Some(id);
        }
        let Some(body) = &source.claim else {
            taint = crate::dreamer_consolidation::source_meet(taint, ClaimSource::Imported);
            continue;
        };
        taint = crate::dreamer_consolidation::source_meet(
            taint,
            body.source.unwrap_or(ClaimSource::Imported),
        );
        if let Some(inherited) = crate::claim::claim_evidence_taint(body) {
            taint = crate::dreamer_consolidation::source_meet(taint, inherited);
        }
        if let Some(id) = body.rel {
            if rel.is_some_and(|existing| existing != id) {
                return Err(invalid("incompatible evidence scope"));
            }
            rel = Some(id);
        }
        if let Some(value) = &body.scope {
            let Value::Map(entries) = value else {
                return Err(invalid("unrepresentable evidence scope"));
            };
            for (key, value) in entries {
                match key.as_str() {
                    Some(
                        "evidence_taint" | "facet" | "facet_ref" | "facetRef" | "scopeProjectId"
                        | "sensitivity",
                    ) => continue,
                    Some("typed_question_principal")
                        if value.as_str() == Some(principal_hex.as_str()) =>
                    {
                        continue;
                    }
                    Some("typed_question_principal") => {
                        return Err(invalid("incompatible evidence principal"));
                    }
                    _ => {}
                }
                if let Some((_, existing)) = scope.iter().find(|(name, _)| name == key) {
                    if existing != value {
                        return Err(invalid("incompatible evidence scope"));
                    }
                } else {
                    scope.push((key.clone(), value.clone()));
                }
            }
        }
    }
    if sensitivity != 2 {
        scope.push((Value::from("sensitivity"), Value::from(sensitivity)));
    }
    if let Some(id) = facet {
        scope.push((Value::from("facet"), Value::Binary(id.as_bytes().to_vec())));
    }
    if let Some(id) = project {
        scope.push((
            Value::from("scopeProjectId"),
            Value::Binary(id.as_bytes().to_vec()),
        ));
    }
    if let Some(id) = world.filter(|id| *id != crate::claim::base_world_id()) {
        *candidate = candidate.clone().with_world(id);
    }
    if let Some(id) = rel {
        *candidate = candidate.clone().with_relationship(id);
    }
    if !scope.is_empty() {
        *candidate = candidate.clone().with_scope(Value::Map(scope));
    }
    Ok(taint)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EntityIdBytes([u8; 16]);
