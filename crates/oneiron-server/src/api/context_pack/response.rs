//! Response DTOs and engine-to-wire mapping functions for context-pack assembly.

use super::super::{
    MemoriesRequest, VadPayload, advance_memories_cursor, core_engine_error, hex_bytes,
};
use super::controls::{ContextPackBudgetControls, CoreDisclosureAssembly, CoreInterlocutorStamp};
use super::resolve::{ContextPackResponseLimits, apply_context_pack_response_limits};
use crate::error::ApiError;
use crate::projection::View;
use oneiron::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use utoipa::ToSchema;

/// Hydrated context edge.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextEdge {
    /// Numeric edge-kind discriminant.
    #[schema(example = 1)]
    kind: u8,
    /// Hex target entity id.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    target: String,
    /// Target short id when the target is present in the same context pack.
    #[serde(rename = "target_short_id", skip_serializing_if = "Option::is_none")]
    #[schema(example = "tn2")]
    target_short_id: Option<String>,
    /// Edge weight.
    #[schema(example = 1.0)]
    weight: f32,
    /// Edge creation timestamp in Unix seconds.
    #[schema(example = 1782357635_u64)]
    created_at: u64,
    /// Optional edge VAD payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    vad: Option<VadPayload>,
}

/// Hydrated context entity.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextEntity {
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Short id allocated by the vault, or hex fallback when no short id exists.
    #[serde(rename = "short_id")]
    #[schema(example = "tn1")]
    short_id: String,
    /// One-byte content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    entity_type: u8,
    /// Retrieval score.
    #[schema(example = 0.87)]
    score: f32,
    /// Hydrated fields when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    fields: Option<BTreeMap<String, Value>>,
    /// Hydrated edges when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    edges: Option<Vec<CoreContextEdge>>,
    /// Stored vector when requested and present.
    #[serde(skip_serializing_if = "Option::is_none")]
    vector: Option<Vec<f32>>,
}

/// Context-pack item accounting.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackItemAccounting {
    /// Number of items affected.
    #[schema(example = 0)]
    count: usize,
    /// Accounting reason.
    #[schema(example = "token_budget")]
    reason: String,
}

/// Context-pack stats.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackStats {
    /// Candidate count considered by the pack.
    #[schema(example = 1)]
    candidates_considered: usize,
    /// Retrieval signals used.
    signals_used: Vec<String>,
    /// Query execution duration in microseconds.
    #[schema(example = 1000_u64)]
    query_time_us: u64,
    /// Primary entities hydrated.
    #[schema(example = 1)]
    entities_hydrated: usize,
    /// Neighbor entities hydrated.
    #[schema(example = 0)]
    neighbors_hydrated: usize,
    /// Vector-only candidates dampened by cosine-ghost suppression.
    #[schema(example = 0)]
    cosine_ghosts_dampened: usize,
    /// Claims suppressed by read-path gates.
    #[schema(example = 0)]
    claims_suppressed: usize,
    /// Item truncation accounting.
    items_truncated: CoreContextPackItemAccounting,
    /// Item drop accounting.
    items_dropped: CoreContextPackItemAccounting,
}

/// Typed context-pack result state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackState {
    /// Stable state discriminator.
    kind: CoreContextPackStateKind,
    /// Empty-result reason when the pack did not surface entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CoreContextPackStateReason>,
    /// Total records in scope when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_in_scope: Option<usize>,
    /// Caller-facing hint from the retrieval layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// Stable context-pack state discriminator.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreContextPackStateKind {
    Ok,
    MissingData,
    LowConfidence,
}

/// Stable context-pack empty-result reason.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreContextPackStateReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Score component that contributed to a context-pack result.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackScoreComponent {
    /// Retrieval signal name.
    signal: String,
    /// Rank within the signal.
    rank: u32,
    /// Raw signal score.
    score: f32,
}

/// Per-result context-pack score evidence.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackScoreEvidence {
    /// Hex entity id.
    result_id: String,
    /// Final rank after context-pack hydration.
    final_rank: u32,
    /// Final fused score.
    final_score: f32,
    /// Read-side access factor applied to the fused score, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    access_factor: Option<f32>,
    /// Signal-level score components.
    components: Vec<CoreContextPackScoreComponent>,
}

/// Retrieval evidence attached to a context-pack response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackEvidence {
    /// Whether the retrieval telemetry row was persisted and finalized.
    pub(crate) telemetry_persisted: bool,
    /// Retrieval telemetry run id when persistence succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) retrieval_run_id: Option<String>,
    /// Surfaced result ids recorded in telemetry.
    pub(crate) result_ids: Vec<String>,
    /// Final score evidence recorded in telemetry.
    pub(crate) scores: Vec<CoreContextPackScoreEvidence>,
}

/// Context-pack response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreContextPackResponse {
    /// Execution quality projected from the engine's shared report.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    quality: Option<RetrievalQuality>,
    /// Observed reasons for degraded execution; absent when none were recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<String>>)]
    degradation: Option<Vec<RetrievalDegradation>>,
    /// Pinned presentation confidence adjustment for the execution tier: 0, -0.15, or -0.35.
    #[serde(
        rename = "confidenceAdjustment",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = Option<f32>, example = -0.15)]
    confidence_adjustment: Option<ConfidenceAdjustment>,
    /// Primary hydrated retrieval results.
    results: Vec<CoreContextEntity>,
    /// Neighbor entities hydrated through edge expansion.
    neighbors: Vec<CoreContextEntity>,
    /// Retrieval and hydration stats.
    stats: CoreContextPackStats,
    /// Typed missing-data / low-confidence state.
    state: CoreContextPackState,
    /// Retrieval evidence and score breakdown.
    evidence: CoreContextPackEvidence,
    /// Resolved per-speaker interlocutor stamps when an interlocutors block
    /// was supplied or the auth is principal_ref-scoped (OF-365 ILD-1).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<CoreInterlocutorStamp>>)]
    pub(super) interlocutors: Option<Vec<oneiron::InterlocutorStamp>>,
    /// Disclosure block for the clamp applied to this assembly (OF-365
    /// ILD-2); present under the same rule as `interlocutors`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<CoreDisclosureAssembly>)]
    disclosure: Option<oneiron::DisclosureAssembly>,
    /// Empty-result context when no entities surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    empty: Option<Value>,
}

pub(crate) async fn run_context_pack_builder(
    vault: &oneiron::Vault,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    builder: oneiron::ContextPackBuilder<'_>,
    projection: oneiron::serialize::SerializeConfig,
    response_limits: ContextPackResponseLimits,
    memories: Option<MemoriesRequest>,
    disclosure: Option<oneiron::DisclosureContext>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    let mut pack = builder.run_unfinalized_with_telemetry().map_err(|error| {
        tracing::error!(error = %error, "core context-pack failed");
        core_engine_error("core context-pack failed", error)
    })?;
    let clamped_out = pack.clamped_out();
    scoped_read
        .filter_context_pack(&mut pack.value)
        .map_err(|error| {
            pack.discard_telemetry();
            tracing::error!(error = %error, "core context-pack scoped read failed");
            core_engine_error("core context-pack scoped read failed", error)
        })?;
    apply_context_pack_response_limits(&mut pack.value, response_limits);
    let pack = pack.finish_projected_json(&projection);
    let run_id = pack.run_id;
    let pack = pack.value;
    let evidence = core_context_pack_evidence(vault, run_id)?;
    let evidence = core_context_pack_evidence_for_results(evidence, &pack.results);
    let assembly = disclosure.as_ref().map(|ctx| ctx.assembly(clamped_out));
    let (section, cursor) = match memories.as_ref() {
        Some(request) => {
            let section = request.memory_board_budget.map(|budget| {
                oneiron::context_board::project_memories_section(
                    &pack,
                    budget,
                    request.companion.clone(),
                    assembly.clone(),
                )
            });
            let cursor = advance_memories_cursor(
                vault,
                &request.session_scope_id,
                &request.session_id,
                &pack,
                &evidence,
            )
            .await;
            (section, Some(cursor))
        }
        None => (None, None),
    };
    Ok((
        core_context_pack_response(pack, evidence, assembly),
        section,
        cursor,
    ))
}

pub(crate) fn field_profile_for_view(view: View) -> oneiron::FieldProfile {
    match view {
        View::Summary => oneiron::FieldProfile::Minimal,
        View::Standard => oneiron::FieldProfile::Standard,
        View::Full => oneiron::FieldProfile::Full,
    }
}

pub(crate) fn context_pack_json_projection_config(
    view: View,
    budget: Option<&ContextPackBudgetControls>,
) -> oneiron::serialize::SerializeConfig {
    oneiron::serialize::SerializeConfig {
        format: oneiron::PackFormat::Json,
        profile: field_profile_for_view(view),
        budget: budget.and_then(|budget| budget.token_budget).unwrap_or(0),
        allocation: oneiron::TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: false,
        max_field_chars: budget
            .and_then(|budget| budget.max_field_chars)
            .unwrap_or(oneiron::context_pack::DEFAULT_MAX_FIELD_CHARS),
        max_item_tokens: budget
            .and_then(|budget| budget.max_item_tokens)
            .unwrap_or(0),
    }
}

pub(crate) fn core_context_pack_evidence_for_results(
    mut evidence: CoreContextPackEvidence,
    results: &[oneiron::ContextEntity],
) -> CoreContextPackEvidence {
    let result_ids: BTreeSet<String> = results.iter().map(|entity| entity.id.to_hex()).collect();
    evidence
        .result_ids
        .retain(|result_id| result_ids.contains(result_id));
    evidence
        .scores
        .retain(|score| result_ids.contains(&score.result_id));
    evidence
}

pub(crate) fn core_context_pack_response(
    pack: oneiron::ContextPack,
    evidence: CoreContextPackEvidence,
    disclosure: Option<oneiron::DisclosureAssembly>,
) -> CoreContextPackResponse {
    let state = core_context_pack_state(pack.empty.as_ref());
    CoreContextPackResponse {
        quality: Some(pack.retrieval_quality.quality),
        degradation: (!pack.retrieval_quality.degradation.is_empty())
            .then_some(pack.retrieval_quality.degradation),
        confidence_adjustment: Some(pack.retrieval_quality.confidence_adjustment),
        results: pack.results.into_iter().map(core_context_entity).collect(),
        neighbors: pack
            .neighbors
            .into_iter()
            .map(core_context_entity)
            .collect(),
        stats: core_context_pack_stats(pack.stats),
        state,
        evidence,
        interlocutors: None,
        disclosure,
        empty: pack
            .empty
            .map(|empty| serde_json::to_value(empty).expect("EmptyContext serializes")),
    }
}

pub(crate) fn core_context_entity(entity: oneiron::ContextEntity) -> CoreContextEntity {
    CoreContextEntity {
        id: entity.id.to_hex(),
        short_id: entity.short_id,
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        score: entity.score,
        fields: entity.fields.map(BTreeMap::from_iter),
        edges: entity
            .edges
            .map(|edges| edges.into_iter().map(core_context_edge).collect()),
        vector: entity.vector,
    }
}

pub(crate) fn core_context_edge(edge: oneiron::EdgeInfo) -> CoreContextEdge {
    CoreContextEdge {
        kind: edge.kind as u8,
        target: edge.target.to_hex(),
        target_short_id: edge.target_short_id,
        weight: edge.weight,
        created_at: edge.created_at,
        vad: edge.vad.map(Into::into),
    }
}

pub(crate) fn core_context_pack_stats(stats: oneiron::PackStats) -> CoreContextPackStats {
    CoreContextPackStats {
        candidates_considered: stats.candidates_considered,
        signals_used: stats
            .signals_used
            .into_iter()
            .map(|signal| signal_name(signal).to_owned())
            .collect(),
        query_time_us: stats.query_time_us,
        entities_hydrated: stats.entities_hydrated,
        neighbors_hydrated: stats.neighbors_hydrated,
        cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
        claims_suppressed: stats.claims_suppressed,
        items_truncated: CoreContextPackItemAccounting {
            count: stats.items_truncated.count,
            reason: stats.items_truncated.reason.as_str().to_owned(),
        },
        items_dropped: CoreContextPackItemAccounting {
            count: stats.items_dropped.count,
            reason: stats.items_dropped.reason.as_str().to_owned(),
        },
    }
}

pub(crate) fn core_context_pack_state(
    empty: Option<&oneiron::EmptyContext>,
) -> CoreContextPackState {
    let Some(empty) = empty else {
        return CoreContextPackState {
            kind: CoreContextPackStateKind::Ok,
            reason: None,
            total_in_scope: None,
            hint: None,
        };
    };
    CoreContextPackState {
        kind: match empty.reason {
            oneiron::EmptyReason::BelowThreshold => CoreContextPackStateKind::LowConfidence,
            oneiron::EmptyReason::FilterMatchedNone
            | oneiron::EmptyReason::NoData
            | oneiron::EmptyReason::AllActivated => CoreContextPackStateKind::MissingData,
        },
        reason: Some(core_context_pack_state_reason(empty.reason)),
        total_in_scope: Some(empty.total_in_scope),
        hint: Some(empty.hint.clone()),
    }
}

pub(crate) fn core_context_pack_state_reason(
    reason: oneiron::EmptyReason,
) -> CoreContextPackStateReason {
    match reason {
        oneiron::EmptyReason::FilterMatchedNone => CoreContextPackStateReason::FilterMatchedNone,
        oneiron::EmptyReason::NoData => CoreContextPackStateReason::NoData,
        oneiron::EmptyReason::AllActivated => CoreContextPackStateReason::AllActivated,
        oneiron::EmptyReason::BelowThreshold => CoreContextPackStateReason::BelowThreshold,
    }
}

pub(crate) fn core_context_pack_evidence(
    vault: &oneiron::Vault,
    run_id: Option<oneiron::RetrievalRunId>,
) -> Result<CoreContextPackEvidence, ApiError> {
    let Some(run_id) = run_id else {
        return Ok(CoreContextPackEvidence {
            telemetry_persisted: false,
            retrieval_run_id: None,
            result_ids: Vec::new(),
            scores: Vec::new(),
        });
    };
    let Some(record) = vault.retrieval_run(run_id).map_err(|error| {
        tracing::error!(error = %error, "context-pack telemetry lookup failed");
        core_engine_error("context-pack telemetry lookup failed", error)
    })?
    else {
        return Ok(CoreContextPackEvidence {
            telemetry_persisted: false,
            retrieval_run_id: None,
            result_ids: Vec::new(),
            scores: Vec::new(),
        });
    };
    Ok(CoreContextPackEvidence {
        telemetry_persisted: true,
        retrieval_run_id: Some(record.run_id.to_hex()),
        result_ids: record.result_ids.iter().map(|id| hex_bytes(id)).collect(),
        scores: record
            .score_breakdown
            .into_iter()
            .map(core_context_pack_score_evidence)
            .collect(),
    })
}

pub(crate) fn core_context_pack_score_evidence(
    score: oneiron::RetrievalScoreBreakdown,
) -> CoreContextPackScoreEvidence {
    CoreContextPackScoreEvidence {
        result_id: hex_bytes(&score.result_id),
        final_rank: score.final_rank,
        final_score: score.final_score,
        access_factor: score.access_factor,
        components: score
            .components
            .into_iter()
            .map(core_context_pack_score_component)
            .collect(),
    }
}

pub(crate) fn core_context_pack_score_component(
    component: oneiron::RetrievalScoreComponent,
) -> CoreContextPackScoreComponent {
    CoreContextPackScoreComponent {
        signal: retrieval_signal_name(component.signal).to_owned(),
        rank: component.rank,
        score: component.score,
    }
}

pub(crate) fn signal_name(signal: oneiron::Signal) -> &'static str {
    match signal {
        oneiron::Signal::Vector => "vector",
        oneiron::Signal::Text => "text",
        oneiron::Signal::Phonetic => "phonetic",
        oneiron::Signal::Temporal => "temporal",
        oneiron::Signal::Ppr => "ppr",
        _ => "unknown",
    }
}

pub(crate) fn retrieval_signal_name(signal: oneiron::RetrievalSignal) -> &'static str {
    match signal {
        oneiron::RetrievalSignal::Vector => "vector",
        oneiron::RetrievalSignal::Text => "text",
        oneiron::RetrievalSignal::Phonetic => "phonetic",
        oneiron::RetrievalSignal::Temporal => "temporal",
        oneiron::RetrievalSignal::Ppr => "ppr",
        oneiron::RetrievalSignal::Recency => "recency",
        oneiron::RetrievalSignal::Salience => "salience",
        oneiron::RetrievalSignal::Confidence => "confidence",
        oneiron::RetrievalSignal::Gravity => "gravity",
        oneiron::RetrievalSignal::Rerank => "rerank",
        oneiron::RetrievalSignal::Hyde => "hyde",
        oneiron::RetrievalSignal::HydeRetry => "hyde_retry",
    }
}
