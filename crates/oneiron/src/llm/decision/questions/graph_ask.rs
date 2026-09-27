//! One-off graph judgment: scoped context, injected answerer, and proposed claims.

use super::{records::AnswerRecord, store::encode};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject, ScopedReadActorKey};
use crate::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionQuestion, DecisionReceipt, DecisionRung, EvidenceVersion,
    ProviderPin, TypedDecision,
};
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use std::collections::HashSet;

const MAX_UNITS: usize = 4096;
const MAX_NEIGHBORS: usize = 16;
const MAX_SOURCE_BYTES: usize = 1_048_576;

/// An already-authorized, live source. The answerer never receives hidden neighbors.
#[derive(Debug, Clone)]
pub struct GraphContextSource {
    pub id: EntityId,
    pub entity_type: u8,
    pub body: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct GraphUnitContext {
    pub unit: EntityId,
    /// The unit comes first, followed by at most 16 readable outgoing neighbors.
    pub sources: Vec<GraphContextSource>,
}

/// The answerer's inference, before the engine fixes the principal and receipt.
#[derive(Debug, Clone)]
pub struct GraphPrediction {
    pub answer: DecisionAnswer,
    pub probability: f64,
    pub provider: ProviderPin,
    pub cost_per_thousand: f64,
}

/// Host-injected answerer. The agent/provider layer chooses the rung and enforces
/// its own model locality and egress policy; this callback cannot grant reads or
/// writes. `None` means missing input or refusal, never a negative prediction.
pub trait GraphAnswerer {
    fn answer(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>>;
}

#[derive(Debug, Clone)]
pub struct GraphAskResult {
    /// One proposed, receipt-bearing claim per answer (not automatically kept).
    pub answers: Vec<AnswerRecord>,
    /// Only visible units with missing input or an abstaining answerer appear here.
    pub abstained: Vec<EntityId>,
}

/// Enumerate up to `limit` live units of a graph type under the asker's
/// scoped-read authority. The type index only nominates IDs: no raw row or
/// count from that index reaches the answerer or the result without a scoped
/// point read. This scan has a fixed bound, including invisible rows.
pub fn select_graph_units_by_type(
    vault: &Vault,
    principal: EntityId,
    entity_type: u8,
    limit: usize,
) -> Result<Vec<EntityId>> {
    if limit > MAX_UNITS {
        return Err(Error::InvalidConfig(
            "graph ask selection exceeds limit".into(),
        ));
    }
    let scoped = vault.scoped_read(asker_reader(vault, principal)?);
    let mut selected = Vec::new();
    let mut after = None;
    let mut scanned = 0;
    while selected.len() < limit && scanned < 100_000 {
        let page = vault.entities_by_type_page(entity_type, after.as_ref(), 256)?;
        if page.is_empty() {
            break;
        }
        scanned += page.len();
        after = page.last().copied();
        let values = scoped.get_entities_parts_with_receipt(&page, None)?;
        for (id, value) in page.into_iter().zip(values.value) {
            if matches!(value, Some((kind, _, _)) if kind == entity_type)
                && kind_is_graph_evidence(entity_type)
            {
                selected.push(id);
                if selected.len() == limit {
                    break;
                }
            }
        }
    }
    Ok(selected)
}

/// Bounded type selector for a one-off ask.
#[derive(Debug, Clone, Copy)]
pub struct GraphTypeSelection {
    pub entity_type: u8,
    pub limit: usize,
}

/// Enumerate and answer one entity type without publishing hidden IDs.
pub fn run_graph_ask_by_type(
    vault: &Vault,
    principal: EntityId,
    actor: WriteActor,
    question: DecisionQuestion,
    selection: GraphTypeSelection,
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> Result<GraphAskResult> {
    let units =
        select_graph_units_by_type(vault, principal, selection.entity_type, selection.limit)?;
    run_graph_ask(vault, principal, actor, question, &units, answerer, now)
}

// A NOTE's author-only read requires an identity-checked actor class. The
// asker is the reader even when a distinct agent performs the write.
fn asker_reader(vault: &Vault, principal: EntityId) -> Result<ScopedReadActorKey> {
    let txn = vault.store.env.read_txn()?;
    asker_reader_in_txn(vault, &txn, principal)
}

fn asker_reader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
) -> Result<ScopedReadActorKey> {
    let class = match crate::vault::live_entity_row_in_txn(&vault.store, txn, &principal)? {
        crate::vault::LiveEntityRow::Live { entity_type, .. } => match entity_type {
            crate::registry::ENTITY_TYPE_PERSON => Some("human"),
            crate::registry::ENTITY_TYPE_AGENT_DEF => Some("agent"),
            crate::registry::ENTITY_TYPE_MACHINE => Some("system"),
            _ => None,
        },
        _ => None,
    };
    let key = match class {
        Some(class) => ScopedReadActorKey::with_actor_class(principal.to_hex(), class),
        None => ScopedReadActorKey::new(principal.to_hex()),
    };
    key.ok_or(Error::InvariantViolation("canonical ask principal"))
}

fn kind_is_graph_evidence(kind: u8) -> bool {
    kind == crate::registry::ENTITY_TYPE_CLAIM || !(64..100).contains(&kind)
}

/// Evaluate a bounded caller-selected set of graph units. Selection is never
/// authority: both each source and its neighborhood are read under the asker's
/// scoped-read lane. No standing question definition or scheduling row is saved.
/// The host supplies a provider behind the locality/egress policy; this engine
/// path owns the immutable principal, receipt, and gated claim landing.
pub fn run_graph_ask(
    vault: &Vault,
    principal: EntityId,
    actor: WriteActor,
    question: DecisionQuestion,
    units: &[EntityId],
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> Result<GraphAskResult> {
    question.validate()?;
    if units.len() > MAX_UNITS || units.iter().copied().collect::<HashSet<_>>().len() != units.len()
    {
        return Err(Error::InvalidConfig(
            "invalid graph ask unit selection".into(),
        ));
    }
    let scoped = vault.scoped_read(asker_reader(vault, principal)?);
    let mut result = GraphAskResult {
        answers: Vec::new(),
        abstained: Vec::new(),
    };
    for &unit in units {
        let Some((kind, _, body)) = scoped.get_entity_parts_with_receipt(&unit, None)?.value else {
            // A hidden unit is indistinguishable from a missing id to the caller.
            continue;
        };
        if !kind_is_graph_evidence(kind) {
            continue;
        }
        if body.is_empty() || body.len() > MAX_SOURCE_BYTES {
            result.abstained.push(unit);
            continue;
        }
        let mut sources = vec![source(unit, kind, body)];
        if let Some(edges) = scoped.edges_out(&unit)?.value {
            for edge in edges {
                if sources.len() > MAX_NEIGHBORS {
                    break;
                }
                if sources.iter().any(|item| item.id == edge.target) {
                    continue;
                }
                if let Some((kind, _, body)) = scoped
                    .get_entity_parts_with_receipt(&edge.target, None)?
                    .value
                    && kind_is_graph_evidence(kind)
                    && !body.is_empty()
                    && body.len() <= MAX_SOURCE_BYTES
                {
                    sources.push(source(edge.target, kind, body));
                }
            }
        }
        let context = GraphUnitContext { unit, sources };
        let Some(prediction) = answerer.answer(&question, &context)? else {
            result.abstained.push(unit);
            continue;
        };
        if prediction.answer == DecisionAnswer::Abstain {
            result.abstained.push(unit);
            continue;
        }
        validate_prediction(&question, &prediction)?;
        // A callback may take arbitrarily long. Recheck visibility and every
        // actual context body before allowing a claim on the now-current unit.
        let fresh = vault.scoped_read(asker_reader(vault, principal)?);
        let current = fresh.get_entities_parts_with_receipt(
            &context.sources.iter().map(|s| s.id).collect::<Vec<_>>(),
            None,
        )?;
        if context.sources.iter().zip(current.value.iter()).any(|(old, new)| {
            !matches!(new, Some((kind, _, body)) if *kind == old.entity_type && *blake3::hash(body).as_bytes() == old.hash)
        }) {
            result.abstained.push(unit);
            continue;
        }
        let record = vault.with_write_txn(|txn| {
            let (source_kind, raw) = super::task_ask::validate_task_answer_unit(
                vault,
                txn,
                principal,
                actor.entity_ref(),
                unit,
            )?;
            // The provider ran outside the transaction. The final authority
            // check must use the write snapshot, not a second independent
            // read transaction: a revoked grant or a changed NOTE owner is a
            // missing source, even when its stored bytes stayed the same.
            let scoped = vault.scoped_read(asker_reader_in_txn(vault, txn, principal)?);
            let mut taint = ClaimSource::UserStated;
            for source in &context.sources {
                let Some((kind, _, body)) = scoped.graph_ask_parts_in_txn(txn, &source.id)? else {
                    return Err(Error::EntityNotFound);
                };
                if kind != source.entity_type || *blake3::hash(&body).as_bytes() != source.hash {
                    return Err(Error::ConcurrentWrite("graph ask evidence changed"));
                }
                let observed = if kind == crate::registry::ENTITY_TYPE_CLAIM {
                    let claim = crate::claim::decode_claim_body(&body, true)?;
                    let original = claim.source.unwrap_or(ClaimSource::Imported);
                    crate::claim::claim_evidence_taint(&claim).map_or(original, |inherited| {
                        crate::dreamer_consolidation::source_meet(original, inherited)
                    })
                } else {
                    ClaimSource::Imported
                };
                taint = crate::dreamer_consolidation::source_meet(taint, observed);
            }
            if source_kind != context.sources[0].entity_type {
                return Err(Error::ConcurrentWrite("graph ask unit changed"));
            }
            let band = DecisionBand::default();
            let answer = AnswerRecord {
                claim: EntityId::now(),
                unit,
                decision: TypedDecision {
                    answer: prediction.answer.clone(),
                    probability: Some(prediction.probability),
                    evidence: context.sources.iter().map(|s| s.id).collect(),
                    in_band: band.contains(prediction.probability),
                    receipt: DecisionReceipt {
                        question: question.id,
                        question_version: question.version,
                        principal,
                        providers: vec![prediction.provider.clone()],
                        band,
                        evidence_versions: context
                            .sources
                            .iter()
                            .map(|s| EvidenceVersion {
                                id: s.id,
                                body_hash: s.hash,
                            })
                            .collect(),
                        cost_per_thousand: Some(prediction.cost_per_thousand),
                    },
                    human_ask: None,
                },
                frontier: context.sources[0].hash,
                source_kind,
                answered_at: now,
            };
            let encoded = encode(&answer)?;
            let value = rmpv::decode::read_value(&mut encoded.as_slice())
                .map_err(|_| Error::CorruptedIndex("graph ask answer encoding"))?;
            let mut candidate = ClaimCandidate::new(
                "judgment.answer",
                ClaimSubject::Entity(unit),
                value.clone(),
                prediction.probability as f32,
            );
            if source_kind == crate::registry::ENTITY_TYPE_CLAIM {
                let body = crate::claim::decode_claim_body(&raw, true)?;
                if let Some(scope) = body.scope {
                    candidate = candidate.with_scope(scope);
                }
                if let Some(world) = body.world {
                    candidate = candidate.with_world(world);
                }
            }
            candidate = candidate
                .with_evidence_taint(taint)?
                .with_private_reader(principal)?
                .with_evidence(rmpv::Value::Array(
                    context
                        .sources
                        .iter()
                        .map(|s| rmpv::Value::from(s.id.to_hex()))
                        .collect(),
                ));
            let envelope = WriteEnvelope::new(
                actor,
                crate::dreamer_consolidation::source_meet(ClaimSource::Generated, taint),
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
            Ok(answer)
        })?;
        result.answers.push(record);
    }
    Ok(result)
}

fn source(id: EntityId, entity_type: u8, body: Vec<u8>) -> GraphContextSource {
    GraphContextSource {
        id,
        entity_type,
        hash: *blake3::hash(&body).as_bytes(),
        body,
    }
}

fn validate_prediction(question: &DecisionQuestion, prediction: &GraphPrediction) -> Result<()> {
    if !question.contract.accepts(&prediction.answer)
        || !prediction.probability.is_finite()
        || !(0.0..=1.0).contains(&prediction.probability)
        || prediction.provider.rung == DecisionRung::Human
        || crate::llm::ModelId::new(format!(
            "{}@{}",
            prediction.provider.model, prediction.provider.version
        ))
        .is_err()
        || !prediction.cost_per_thousand.is_finite()
        || prediction.cost_per_thousand < 0.0
    {
        return Err(Error::InvalidConfig("invalid graph ask prediction".into()));
    }
    Ok(())
}
