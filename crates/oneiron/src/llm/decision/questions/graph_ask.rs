//! One-off graph judgment: scoped context, injected answerer, and proposed claims.

use super::super::held::{cut_text, fit_state};
use super::super::types::paired_valid;
use super::{records::AnswerRecord, store::encode};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject, ScopedRead, ScopedReadActorKey};
use crate::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionImage, DecisionQuestion, DecisionReceipt, DecisionRung,
    EvidenceVersion, MAX_DECISION_IMAGE_BYTES, MAX_DECISION_IMAGES, MAX_DECISION_IMAGES_BYTES,
    PairedAnswer, PairedReading, ProviderPin, TypedDecision,
};
use crate::receipt::{PixelPull, ServedForm};
use crate::{
    ClaimCandidate, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use serde_json::{Value, json};
use std::collections::HashSet;

const MAX_UNITS: usize = 4096;
const MAX_NEIGHBORS: usize = 16;
const MAX_NEIGHBOR_SCAN: usize = 4096;
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
    /// The paired reading from the same measurement, when the provider takes one.
    pub paired: Option<PairedAnswer>,
}

/// What an answerer returns for one unit: a bare prediction the engine wraps
/// in its own receipt, or a full decision from the decision ladder. The engine
/// keeps a decision's providers, band, paired and person readings, clock and
/// owner-ask reason, and sets its evidence to the sources and images it was
/// shown.
#[derive(Debug, Clone)]
pub enum GraphDecision {
    Prediction(GraphPrediction),
    Decision(Box<TypedDecision>),
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

    /// Whether it reads images. When it does, the engine reads the image each
    /// ASSET source holds, under the asker's own read, and passes it to
    /// [`Self::decide`].
    fn reads_images(&self) -> bool {
        false
    }

    /// The unit's answer over its sources and `images`, each named in
    /// [`GraphUnitContext::state`]. The default answers through
    /// [`Self::answer`] and reads no image.
    fn decide(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
        images: &[DecisionImage],
    ) -> Result<Option<GraphDecision>> {
        let _ = images;
        Ok(self
            .answer(question, context)?
            .map(GraphDecision::Prediction))
    }
}

impl GraphUnitContext {
    /// The unit and its sources as a decision's state: each body as the JSON
    /// a reader is served, all cut evenly to fit the ladder's state bound. A
    /// source an image was read from names that image.
    #[must_use]
    pub fn state(&self, images: &[DecisionImage]) -> Value {
        let texts: Vec<String> = self.sources.iter().map(|s| body_text(&s.body)).collect();
        let longest = texts.iter().map(String::len).max().unwrap_or(0);
        fit_state(longest, |cut| {
            json!({
                "unit": self.unit.to_hex(),
                "sources": self
                    .sources
                    .iter()
                    .zip(&texts)
                    .map(|(source, text)| {
                        let mut view = json!({
                            "ref": source.id.to_hex(),
                            "kind": kind_name(source.entity_type),
                            "body": cut_text(text, cut),
                        });
                        if let Some(image) =
                            images.iter().find(|image| image.evidence.id == source.id)
                        {
                            view["image"] = json!(image.name);
                        }
                        view
                    })
                    .collect::<Vec<_>>(),
            })
        })
    }
}

/// A stored body as the served JSON text a reader sees; a body that is not
/// one MessagePack value shows nothing.
fn body_text(body: &[u8]) -> String {
    let mut cursor = body;
    match rmpv::decode::read_value(&mut cursor) {
        Ok(value) if cursor.is_empty() => {
            crate::batch::export::served_stored_messagepack_json(body, value).to_string()
        }
        _ => String::new(),
    }
}

fn kind_name(entity_type: u8) -> String {
    crate::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}

#[derive(Debug, Clone)]
pub struct GraphAskResult {
    /// One proposed, receipt-bearing claim per answer (not automatically kept).
    pub answers: Vec<AnswerRecord>,
    /// Only visible units with missing input or an abstaining answerer appear here.
    pub abstained: Vec<EntityId>,
}

/// A run's result, with the receipt of each unit whose answerer declined
/// through a full decision: its providers, clock and owner-ask reason.
#[derive(Debug, Clone)]
pub struct GraphAskReceipts {
    pub result: GraphAskResult,
    /// Each declined unit and its abstention, in `result.abstained` order.
    pub declined: Vec<(EntityId, TypedDecision)>,
}

/// A failed run can already have committed earlier per-unit answers. Callers
/// receive those receipts and the exact failing unit instead of losing them.
#[derive(Debug, thiserror::Error)]
#[error("graph ask failed at {failed_unit:?}: {error}")]
pub struct GraphAskFailure {
    pub failed_unit: Option<EntityId>,
    pub error: Box<Error>,
    pub completed: GraphAskResult,
}

impl GraphAskFailure {
    pub(super) fn before_units(error: Error) -> Self {
        Self {
            failed_unit: None,
            error: Box::new(error),
            completed: GraphAskResult {
                answers: Vec::new(),
                abstained: Vec::new(),
            },
        }
    }
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
) -> std::result::Result<GraphAskResult, GraphAskFailure> {
    let units =
        select_graph_units_by_type(vault, principal, selection.entity_type, selection.limit)
            .map_err(GraphAskFailure::before_units)?;
    run_graph_ask(vault, principal, actor, question, &units, answerer, now)
}

// A NOTE's author-only read requires an identity-checked actor class. The
// asker is the reader even when a distinct agent performs the write.
pub(super) fn asker_reader(vault: &Vault, principal: EntityId) -> Result<ScopedReadActorKey> {
    let txn = vault.store.env.read_txn()?;
    asker_reader_in_txn(vault, &txn, principal)
}

pub(super) fn asker_reader_in_txn(
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
    // A relationship's rows answer the asker only on its own membership or
    // live grant, as on every other read lane, unless the asker is the
    // vault's live owner; the vault's own rows stay its to read.
    key.map(|key| key.exempt_while_owner(principal))
        .ok_or(Error::InvariantViolation("canonical ask principal"))
}

pub(super) fn kind_is_graph_evidence(kind: u8) -> bool {
    kind == crate::registry::ENTITY_TYPE_CLAIM || !(64..100).contains(&kind)
}

/// Evaluate selected graph units. Earlier committed answers remain in
/// `GraphAskFailure::completed` if a later provider or write fails.
pub fn run_graph_ask(
    vault: &Vault,
    principal: EntityId,
    actor: WriteActor,
    question: DecisionQuestion,
    units: &[EntityId],
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> std::result::Result<GraphAskResult, GraphAskFailure> {
    run_graph_ask_receipted(vault, principal, actor, question, units, answerer, now)
        .map(|receipts| receipts.result)
}

/// [`run_graph_ask`], keeping the receipt of each unit its answerer declined
/// through a full decision.
pub fn run_graph_ask_receipted(
    vault: &Vault,
    principal: EntityId,
    actor: WriteActor,
    question: DecisionQuestion,
    units: &[EntityId],
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> std::result::Result<GraphAskReceipts, GraphAskFailure> {
    question.validate().map_err(GraphAskFailure::before_units)?;
    if units.len() > MAX_UNITS || units.iter().copied().collect::<HashSet<_>>().len() != units.len()
    {
        return Err(GraphAskFailure::before_units(Error::InvalidConfig(
            "invalid graph ask unit selection".into(),
        )));
    }
    let scoped =
        vault.scoped_read(asker_reader(vault, principal).map_err(GraphAskFailure::before_units)?);
    let mut completed = GraphAskResult {
        answers: Vec::new(),
        abstained: Vec::new(),
    };
    let mut declined = Vec::new();
    for &unit in units {
        match answer_unit(&scoped, principal, actor, &question, unit, answerer, now) {
            Ok(UnitOutcome::Hidden) => {}
            Ok(UnitOutcome::Abstain) => completed.abstained.push(unit),
            Ok(UnitOutcome::Declined(decision)) => {
                completed.abstained.push(unit);
                declined.push((unit, *decision));
            }
            Ok(UnitOutcome::Answered(answer)) => completed.answers.push(*answer),
            Err(error) => {
                return Err(GraphAskFailure {
                    failed_unit: Some(unit),
                    error: Box::new(error),
                    completed,
                });
            }
        }
    }
    Ok(GraphAskReceipts {
        result: completed,
        declined,
    })
}

enum UnitOutcome {
    Hidden,
    Abstain,
    /// The answerer's own receipted abstention.
    Declined(Box<TypedDecision>),
    Answered(Box<AnswerRecord>),
}

/// Whether a graph source may inform an answer: a claim awaiting its owner's
/// answer informs none.
fn source_eligible(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, kind: u8) -> Result<bool> {
    Ok(kind != crate::registry::ENTITY_TYPE_CLAIM
        || crate::gate::claim_consolidation_eligible_in_txn(
            &vault.store,
            txn,
            id,
            crate::gate::ConsolidationReader::GraphAnswer,
        )?)
}

/// Whether the unit's eligible neighbours are still the prepared ones.
fn same_eligible_neighbors(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    neighbors: Option<Vec<(EntityId, u8, Vec<u8>)>>,
    context: &GraphUnitContext,
) -> Result<bool> {
    let Some(neighbors) = neighbors else {
        return Ok(false);
    };
    let mut eligible = Vec::with_capacity(neighbors.len());
    for (id, kind, _) in neighbors {
        if source_eligible(vault, txn, &id, kind)? {
            eligible.push(id);
        }
    }
    Ok(eligible
        .into_iter()
        .eq(context.sources.iter().skip(1).map(|source| source.id)))
}

fn answer_unit(
    scoped: &crate::claim::ScopedRead<'_>,
    principal: EntityId,
    actor: WriteActor,
    question: &DecisionQuestion,
    unit: EntityId,
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> Result<UnitOutcome> {
    let vault = scoped.vault();
    let Some((kind, _, body)) = scoped.get_entity_parts_with_receipt(&unit, None)?.value else {
        // A hidden unit is indistinguishable from a missing id to the caller.
        return Ok(UnitOutcome::Hidden);
    };
    if !kind_is_graph_evidence(kind) {
        return Ok(UnitOutcome::Hidden);
    }
    if body.is_empty() || body.len() > MAX_SOURCE_BYTES {
        return Ok(UnitOutcome::Abstain);
    }
    if !source_eligible(vault, &vault.store.env.read_txn()?, &unit, kind)? {
        return Ok(UnitOutcome::Abstain);
    }
    let mut sources = vec![source(unit, kind, body)];
    if let Some(neighbors) =
        scoped.graph_ask_neighbors(&unit, MAX_NEIGHBORS, MAX_NEIGHBOR_SCAN, MAX_SOURCE_BYTES)?
    {
        let txn = vault.store.env.read_txn()?;
        for (id, kind, body) in neighbors {
            if source_eligible(vault, &txn, &id, kind)? {
                sources.push(source(id, kind, body));
            }
        }
    } else {
        return Ok(UnitOutcome::Abstain);
    }
    let context = GraphUnitContext { unit, sources };
    let images = if answerer.reads_images() {
        unit_images(scoped, &context)?
    } else {
        Vec::new()
    };
    let decision = match answerer.decide(question, &context, &images)? {
        None => return Ok(UnitOutcome::Abstain),
        Some(GraphDecision::Prediction(prediction)) => {
            if prediction.answer == DecisionAnswer::Abstain {
                return Ok(UnitOutcome::Abstain);
            }
            validate_prediction(question, &prediction)?;
            predicted(question, principal, &context, prediction)
        }
        Some(GraphDecision::Decision(decision)) => {
            validate_decision(question, principal, &decision)?;
            let decision = decided(&context, &images, *decision);
            if decision.answer == DecisionAnswer::Abstain {
                return Ok(UnitOutcome::Declined(Box::new(decision)));
            }
            decision
        }
    };
    let confidence = decision.probability.unwrap_or_default() as f32;
    // A callback can take arbitrarily long. A cheap preflight avoids waiting
    // for the writer when authority or source bytes have already changed.
    let fresh = vault.scoped_read(asker_reader(vault, principal)?);
    let neighbors =
        fresh.graph_ask_neighbors(&unit, MAX_NEIGHBORS, MAX_NEIGHBOR_SCAN, MAX_SOURCE_BYTES)?;
    if !same_eligible_neighbors(vault, &vault.store.env.read_txn()?, neighbors, &context)? {
        return Ok(UnitOutcome::Abstain);
    }
    let current = fresh.get_entities_parts_with_receipt(
        &context.sources.iter().map(|s| s.id).collect::<Vec<_>>(),
        None,
    )?;
    if context.sources.iter().zip(current.value.iter()).any(|(old, new)| {
        !matches!(new, Some((kind, _, body)) if *kind == old.entity_type && *blake3::hash(body).as_bytes() == old.hash)
    }) {
        return Ok(UnitOutcome::Abstain);
    }
    #[cfg(test)]
    vault.test_hooks().signal_graph_ask_preflight(unit);
    // A second, transaction-local authority check closes the race between
    // the preflight and this write. A missing/changed source is an abstention,
    // but provider and write-gate failures remain typed failures.
    let record = vault.with_write_txn_grouped(|txn| {
        let scoped = vault.scoped_read(asker_reader_in_txn(vault, txn, principal)?);
        let neighbors = scoped.graph_ask_neighbors_in_txn(
            txn,
            &unit,
            MAX_NEIGHBORS,
            MAX_NEIGHBOR_SCAN,
            MAX_SOURCE_BYTES,
        )?;
        if !same_eligible_neighbors(vault, txn, neighbors, &context)? {
            return Ok(None);
        }
        let mut taint = ClaimSource::UserStated;
        for source in &context.sources {
            let Some((kind, _, body)) = scoped.graph_ask_parts_in_txn(txn, &source.id)? else {
                return Ok(None);
            };
            if kind != source.entity_type
                || *blake3::hash(&body).as_bytes() != source.hash
                || !source_eligible(vault, txn, &source.id, kind)?
            {
                return Ok(None);
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
        let answer = AnswerRecord {
            claim: EntityId::now(),
            unit,
            decision: decision.clone(),
            frontier: context.sources[0].hash,
            source_kind: context.sources[0].entity_type,
            answered_at: now,
        };
        let encoded = encode(&answer)?;
        let value = rmpv::decode::read_value(&mut encoded.as_slice())
            .map_err(|_| Error::CorruptedIndex("graph ask answer encoding"))?;
        let mut candidate = ClaimCandidate::new(
            "judgment.answer",
            ClaimSubject::Entity(unit),
            value.clone(),
            confidence,
        );
        if context.sources[0].entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            let body = crate::claim::decode_claim_body(&context.sources[0].body, true)?;
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
        Ok(Some(answer))
    })?;
    Ok(record.map_or(UnitOutcome::Abstain, |answer| {
        UnitOutcome::Answered(Box::new(answer))
    }))
}

fn source(id: EntityId, entity_type: u8, body: Vec<u8>) -> GraphContextSource {
    GraphContextSource {
        id,
        entity_type,
        hash: *blake3::hash(&body).as_bytes(),
        body,
    }
}

/// A bare prediction in the engine's receipt: the default band, every
/// source at the version read, and the provider's own cost and pairing.
fn predicted(
    question: &DecisionQuestion,
    principal: EntityId,
    context: &GraphUnitContext,
    prediction: GraphPrediction,
) -> TypedDecision {
    let band = DecisionBand::default();
    let paired = prediction
        .paired
        .map(|reading| reading.bind(prediction.provider.clone()))
        .into_iter()
        .collect();
    TypedDecision {
        answer: prediction.answer,
        probability: Some(prediction.probability),
        evidence: context.sources.iter().map(|s| s.id).collect(),
        in_band: band.contains(prediction.probability),
        receipt: DecisionReceipt {
            question: question.id,
            question_version: question.version,
            principal,
            providers: vec![prediction.provider],
            band,
            band_version: 0,
            evidence_versions: source_versions(context),
            cost_per_thousand: Some(prediction.cost_per_thousand),
            paired,
            person: Vec::new(),
            time: None,
        },
        human_ask: None,
    }
}

/// A ladder decision with the engine's own evidence: every source it was
/// shown at the version read, then each image at its pixels' hash.
pub(super) fn decided(
    context: &GraphUnitContext,
    images: &[DecisionImage],
    mut decision: TypedDecision,
) -> TypedDecision {
    decision.evidence = context.sources.iter().map(|s| s.id).collect();
    decision.receipt.evidence_versions = source_versions(context)
        .into_iter()
        .chain(images.iter().map(|image| image.evidence.clone()))
        .collect();
    decision
}

fn source_versions(context: &GraphUnitContext) -> Vec<EvidenceVersion> {
    context
        .sources
        .iter()
        .map(|s| EvidenceVersion {
            id: s.id,
            body_hash: s.hash,
        })
        .collect()
}

/// The images the context's ASSET sources hold, read through `lane` (the
/// asker's own read) for an answerer that reads them: PNG or JPEG only,
/// inside a call's count and byte bounds, each named `image_<n>` and pinned
/// at its pixels' hash. The pull is recorded as an ask-image served form
/// before any model reads it. An asset the lane withholds, or one past a
/// bound, is read as text alone.
pub(super) fn unit_images(
    lane: &ScopedRead<'_>,
    context: &GraphUnitContext,
) -> Result<Vec<DecisionImage>> {
    let mut images: Vec<DecisionImage> = Vec::new();
    let mut total = 0usize;
    for source in &context.sources {
        if images.len() == MAX_DECISION_IMAGES {
            break;
        }
        if source.entity_type != crate::registry::ENTITY_TYPE_ASSET {
            continue;
        }
        let Some(pixels) = crate::memory::asset_image_in_lane(lane, source.id)
            .map_err(|_| Error::CorruptedIndex("graph ask image"))?
        else {
            continue;
        };
        let image = DecisionImage {
            name: format!("image_{}", images.len()),
            evidence: EvidenceVersion {
                id: source.id,
                body_hash: *blake3::hash(&pixels.bytes).as_bytes(),
            },
            image: pixels,
        };
        let bytes = image.image.bytes.len();
        if image.format().is_none()
            || bytes > MAX_DECISION_IMAGE_BYTES
            || total.saturating_add(bytes) > MAX_DECISION_IMAGES_BYTES
        {
            continue;
        }
        total += bytes;
        images.push(image);
    }
    if !images.is_empty() {
        let pulls: Vec<_> = images
            .iter()
            .map(|image| ServedForm::pulled(image.evidence.id, PixelPull::AskImage))
            .collect();
        lane.commit_served_forms(&pulls)?;
    }
    Ok(images)
}

/// A full decision is for this question, asker and contract; an answer
/// carries a probability; no person answered it; and its readings are
/// well formed.
pub(super) fn validate_decision(
    question: &DecisionQuestion,
    principal: EntityId,
    decision: &TypedDecision,
) -> Result<()> {
    let receipt = &decision.receipt;
    let answered = decision.answer != DecisionAnswer::Abstain;
    if receipt.question != question.id
        || receipt.question_version != question.version
        || receipt.principal != principal
        || !question.contract.accepts(&decision.answer)
        || (answered && (decision.probability.is_none() || receipt.providers.is_empty()))
        || decision
            .probability
            .is_some_and(|p| !p.is_finite() || !(0.0..=1.0).contains(&p))
        || receipt.band.validate().is_err()
        || receipt.providers.len() > 64
        || receipt.providers.iter().any(|pin| {
            pin.rung == DecisionRung::Human
                || crate::llm::ModelId::new(format!("{}@{}", pin.model, pin.version)).is_err()
        })
        || receipt
            .time
            .as_ref()
            .is_some_and(|time| time.answered == Some(DecisionRung::Human))
        || receipt
            .cost_per_thousand
            .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
        || !PairedReading::readings_valid(
            &receipt.paired,
            &receipt.person,
            question.id,
            &receipt.providers,
        )
    {
        return Err(Error::InvalidConfig("invalid graph ask decision".into()));
    }
    Ok(())
}

pub(super) fn validate_prediction(
    question: &DecisionQuestion,
    prediction: &GraphPrediction,
) -> Result<()> {
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
        || prediction.paired.is_some_and(|reading| {
            !paired_valid(
                question.id,
                reading.question,
                reading.question_version,
                reading.probability,
            )
        })
    {
        return Err(Error::InvalidConfig("invalid graph ask prediction".into()));
    }
    Ok(())
}
