//! Reasoning reads over actor-admitted evidence. Quality comes from the depth executor.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::claim::ScopedRead;
use oneiron::llm::BudgetLease;
use oneiron::retrieval_depth::{
    BackendSpend, DeepSearchBackend, DepthSearchRequest, DepthSearchResult, RetrievalResult,
    SearchProbe, SessionScope, short_ref_or_hex,
};
use oneiron::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use oneiron::{Effort, EntityId, ScoredEntity};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::{Map, Value};
use utoipa::ToSchema;

use super::{
    json_payload, parse_entity_id_param, project_scoped_search_result, scoped_read_for_core_auth,
};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorEnvelope, EnvelopedApiError};
use crate::projection::View;
use crate::server::SyncServer;

mod deep_admission;
mod render;
pub(crate) use deep_admission::{DeepAdmission, DeepRetrievalHost, admit_deep_retrieval};
use render::render_evidence;

/// Evidence rows a reasoning read retrieves when the caller names no limit.
pub(crate) const MEMORY_REASON_DEFAULT_LIMIT: usize = 10;

/// Ceiling on retrieved evidence rows. A reasoning answer is built from what
/// it can cite, and a caller asking for a thousand rows is asking for a dump.
pub(crate) const MEMORY_REASON_MAX_LIMIT: usize = 100;

/// Default composition budget, matching the engine's own recall budget.
pub(crate) const MEMORY_REASON_DEFAULT_TOKEN_BUDGET: usize = 4_000;

/// Ceiling on the composition budget a caller may request.
pub(crate) const MEMORY_REASON_MAX_TOKEN_BUDGET: usize = 65_536;

/// Raw search omits `depth` into the CHEAPEST tier, on purpose: a caller that
/// never heard of this parameter must keep paying what it paid before.
pub(crate) const fn minimal_effort() -> Effort {
    Effort::Minimal
}

/// The reasoning read omits `depth` into `standard`: a question asked in prose
/// wants graph context, and standard is still model-free and lease-free, so
/// the default costs no tokens.
pub(crate) const fn standard_effort() -> Effort {
    Effort::Standard
}

/// Rendering for the extractive answer and the composer's format hint.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryReasonFormat {
    /// JSON evidence rows (the default, matching the engine pack default).
    #[default]
    Json,
    /// Markdown bullets.
    Markdown,
    /// One line per evidence row.
    Plaintext,
    /// TOON tabular rows.
    Toon,
    /// YAML block sequence.
    Yaml,
}

/// Caller-supplied session narrowing.
///
/// Every field can only REMOVE evidence. That direction is the contract: a
/// session hint that could widen an actor-keyed read would be a way to ask for
/// someone else's memory by naming their world.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MemoryReasonSessionContext {
    /// Keep only claims scoped to this WORLD entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) world_ref: Option<String>,
    /// Keep only entities carrying a `facet_of` edge to this facet entity id.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    pub(crate) facet_ref: Option<String>,
    /// Keep only these short ids. Empty means "no document narrowing".
    #[serde(default)]
    #[schema(example = json!(["cl_7f3a:2b"]))]
    pub(crate) document_short_ids: Vec<String>,
}

/// One reasoning request.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(example = json!({
    "query": "what did we decide about the launch date",
    "depth": "standard",
    "tokenBudget": 4000,
    "format": "markdown"
}))]
pub(crate) struct MemoryReasonRequest {
    /// The question, in prose. Must not be blank.
    #[schema(example = "what did we decide about the launch date")]
    pub(crate) query: String,
    /// Retrieval effort. Omitted means `standard`.
    #[serde(default = "standard_effort")]
    #[schema(value_type = String, default = "standard", example = "standard")]
    pub(crate) depth: Effort,
    /// Evidence rows to retrieve. Omitted means `10`; must be at least 1.
    #[schema(example = 10)]
    pub(crate) limit: Option<usize>,
    /// Composition budget in tokens, `1..=65536`. Omitted means `4000`.
    ///
    /// A BUDGET, never the reported spend: `tokensUsed` in the response is
    /// what the backend actually spent, which for the model-free tiers is 0
    /// however large a budget was offered.
    #[schema(example = 4000)]
    pub(crate) token_budget: Option<usize>,
    /// Rendering for the answer. Omitted means `json`.
    #[serde(default)]
    #[schema(example = "markdown")]
    pub(crate) format: MemoryReasonFormat,
    /// Optional session narrowing. Narrows only; never widens.
    pub(crate) session_context: Option<MemoryReasonSessionContext>,
}

/// What the read did, for a caller that needs to explain its own answer.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryReasonTrace {
    /// The text queries the read executed, in order.
    ///
    /// At `standard` these are the caller's own query and the deterministic
    /// variants derived from it, so the trace is checkable: the same question
    /// produces the same list.
    #[schema(example = json!(["launch date", "launch"]))]
    pub(crate) queries_run: Vec<String>,
    /// Stable signal tokens, in the order the signals ran.
    #[schema(example = json!(["text", "subqueries", "ppr"]))]
    pub(crate) signals_used: Vec<String>,
    /// Candidates considered before dedupe and the final cut.
    #[schema(example = 37)]
    pub(crate) candidates_scanned: u64,
}

/// One reasoning answer.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({
    "answer": "- **cl_7f3a:2b** (CLAIM) — launch moved to March 14",
    "sources": ["cl_7f3a:2b"],
    "confidence": 0.82,
    "gaps": [],
    "tokensUsed": 0
}))]
pub(crate) struct MemoryReasonResponse {
    /// The answer text. Never blank on a successful read: a read with no
    /// admissible evidence answers with a gap, not with an empty string.
    pub(crate) answer: String,
    /// Short ids from the retrieved evidence, and only from it.
    pub(crate) sources: Vec<String>,
    /// Calibrated confidence in `[0, 1]`.
    #[schema(example = 0.82)]
    pub(crate) confidence: f32,
    /// What the read could not answer from.
    pub(crate) gaps: Vec<String>,
    /// How the answer was reached. Absent at `minimal`, which is a single
    /// direct pass with no reasoning to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reasoning: Option<MemoryReasonTrace>,
    /// ACTUAL backend spend: decompose + rerank + compose, summed from what
    /// the backend reported. `0` whenever no backend ran.
    #[schema(example = 0)]
    pub(crate) tokens_used: u64,
    /// Retrieval execution quality, independent of answer confidence and evidence count.
    #[schema(value_type = String)]
    pub(crate) quality: RetrievalQuality,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<String>)]
    pub(crate) degradation: Vec<RetrievalDegradation>,
    #[schema(value_type = f32, example = -0.15)]
    pub(crate) confidence_adjustment: ConfidenceAdjustment,
}

/// One retrieved, actor-admitted evidence row.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MemoryReasonEvidence {
    /// The row's citable short id.
    pub(crate) short_id: String,
    /// Registry kind string.
    pub(crate) kind: String,
    /// Text rendering of the row's value.
    pub(crate) text: String,
    /// Calibrated-absolute confidence carried by the row; `1.0` for a
    /// structural record, which is not a ranked guess.
    pub(crate) confidence: f32,
}

/// What a host composer is given.
///
/// Every field is read HOST-SIDE. This crate builds the value and hands it
/// across the seam, so having no in-crate reader for some of them is the
/// contract working rather than dead weight.
#[allow(dead_code)]
pub(crate) struct MemoryReasonComposeRequest<'a> {
    /// The caller's question.
    pub(crate) question: &'a str,
    /// The tier that retrieved the evidence.
    pub(crate) depth: Effort,
    /// The rendering the caller asked for.
    pub(crate) format: MemoryReasonFormat,
    /// The caller's composition budget, in tokens.
    pub(crate) token_budget: usize,
    /// The evidence, already actor-admitted and session-narrowed.
    pub(crate) evidence: &'a [MemoryReasonEvidence],
}

/// What a host composer returns.
pub(crate) struct MemoryReasonComposition {
    /// The composed answer.
    pub(crate) answer: String,
    /// Short ids the answer stands on. Checked against the evidence.
    pub(crate) source_short_ids: Vec<String>,
    /// Calibrated confidence in `[0, 1]`.
    pub(crate) confidence: f32,
    /// What the composer could not answer from.
    pub(crate) gaps: Vec<String>,
    /// The composer declining outright, which is a value and not a failure.
    pub(crate) declined: bool,
}

/// Host-injected deep reasoning: the deep search seam plus composition.
pub(crate) trait MemoryReasonBackend: DeepSearchBackend {
    /// Composes one answer from the retrieved evidence, under the lease the
    /// budget guard minted for this read. Errors report this call's spent
    /// tokens, just like the deep search methods; the host settles the total.
    fn compose(
        &self,
        request: &MemoryReasonComposeRequest<'_>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<MemoryReasonComposition>>;
}

/// Maps an engine refusal from the depth executor onto the wire.
///
/// `InvalidConfig` is the executor's contract refusal and only that: a
/// zero limit, a leaseless deep read, an ungrounded deep vector probe, or a
/// backend that broke the score-per-candidate rule. Those are about the
/// request, so they answer 400 in the engine's own words.
///
/// Everything else keeps the mapping these routes already had. A malformed
/// query VECTOR in particular stays a 500 rather than being reclassified on
/// the way past — the depth dial is not the place to change what an existing
/// failure on a landed endpoint answers with.
pub(crate) fn depth_search_error(error: oneiron::Error) -> ApiError {
    match error.kind() {
        oneiron::ErrorKind::InvalidConfig => ApiError::bad_request(error.to_string(), None),
        _ => {
            tracing::error!(error = %error, "depth-dialed search failed");
            ApiError::internal_server_error("depth-dialed search failed")
        }
    }
}

/// Answer a question from memory at a caller-chosen retrieval depth.
#[utoipa::path(
    post,
    path = "/v1/companion/memory/reason",
    request_body(content = MemoryReasonRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "Answer composed from actor-readable memory, citing the short ids it was built from.",
            body = MemoryReasonResponse,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Blank query, out-of-range limit or tokenBudget, unknown depth, or an unknown field.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid core auth.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 403,
            description = "Token lacks core:read.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 503,
            description = "depth=deep was requested and this server has no deep retrieval backend attached.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn companion_memory_reason(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<MemoryReasonRequest>, JsonRejection>,
) -> Result<Json<MemoryReasonResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let request = json_payload(payload)?;
    let query = request.query.trim().to_owned();
    if query.is_empty() {
        return Err(ApiError::bad_request("query must not be blank", Some("query")).into());
    }
    let limit = validate_limit(request.limit)?;
    let token_budget = validate_token_budget(request.token_budget)?;
    let scope = session_scope(request.session_context.as_ref())?;

    // Refused BEFORE the vault is touched: an unavailable tier must not cost a
    // read whose results are then discarded.
    let admission = admit_deep_retrieval(&server, request.depth)?;

    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let depth_request = DepthSearchRequest {
        probe: SearchProbe::Text {
            query: query.clone(),
        },
        effort: request.depth,
        limit,
        session_scope: Some(&scope),
        lease: admission.as_ref().map(DeepAdmission::lease),
        backend: admission.as_ref().map(DeepAdmission::search_backend),
    };
    let result = (|| {
        let retrieved = scoped_read.search_with_effort(&depth_request);
        if let Some(admission) = admission.as_ref() {
            admission.record_usage(retrieved.as_ref().map_or_else(
                |failure| failure.tokens_used,
                |retrieved| retrieved.tokens_used,
            ));
        }
        let retrieved = retrieved.map_err(|failure| depth_search_error(failure.error))?;
        let evidence = collect_evidence(&server.vault, &scoped_read, retrieved.hits.clone())?;
        let answered = answer_from(
            &request,
            &query,
            token_budget,
            &evidence,
            admission.as_ref(),
        )?;
        let tokens_used = retrieved.tokens_used.saturating_add(answered.tokens_used);
        Ok(Json(reason_response(
            request.depth,
            &retrieved,
            answered,
            tokens_used,
        )))
    })();
    // The closure contains every fallible step after retrieval starts. Even
    // projection or composition errors must settle the usage already recorded.
    match admission.as_ref() {
        Some(admission) => admission.finish(result),
        None => result,
    }
    .map_err(Into::into)
}

/// Project the engine report without inferring execution health from answer gaps.
/// Composition fallbacks stay in `gaps`; they are not embedding or cache failures.
fn reason_response(
    effort: Effort,
    retrieved: &DepthSearchResult,
    answered: AnsweredRead,
    tokens_used: u64,
) -> MemoryReasonResponse {
    MemoryReasonResponse {
        answer: answered.answer,
        sources: answered.sources,
        confidence: answered.confidence,
        gaps: answered.gaps,
        reasoning: trace_for(effort, retrieved),
        tokens_used,
        quality: retrieved.retrieval_quality.quality,
        degradation: retrieved.retrieval_quality.degradation.clone(),
        confidence_adjustment: retrieved.retrieval_quality.confidence_adjustment,
    }
}

fn validate_limit(limit: Option<usize>) -> Result<usize, ApiError> {
    let limit = limit.unwrap_or(MEMORY_REASON_DEFAULT_LIMIT);
    if (1..=MEMORY_REASON_MAX_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(ApiError::bad_request(
            format!("limit must be between 1 and {MEMORY_REASON_MAX_LIMIT}"),
            Some("limit"),
        ))
    }
}

fn validate_token_budget(token_budget: Option<usize>) -> Result<usize, ApiError> {
    let token_budget = token_budget.unwrap_or(MEMORY_REASON_DEFAULT_TOKEN_BUDGET);
    if (1..=MEMORY_REASON_MAX_TOKEN_BUDGET).contains(&token_budget) {
        Ok(token_budget)
    } else {
        Err(ApiError::bad_request(
            format!("tokenBudget must be between 1 and {MEMORY_REASON_MAX_TOKEN_BUDGET}"),
            Some("tokenBudget"),
        ))
    }
}

fn session_scope(context: Option<&MemoryReasonSessionContext>) -> Result<SessionScope, ApiError> {
    let Some(context) = context else {
        return Ok(SessionScope::default());
    };
    Ok(SessionScope {
        world_ref: parse_scope_ref(context.world_ref.as_deref(), "sessionContext.worldRef")?,
        facet_ref: parse_scope_ref(context.facet_ref.as_deref(), "sessionContext.facetRef")?,
        document_short_ids: context
            .document_short_ids
            .iter()
            .map(|short_id| short_id.trim().to_owned())
            .filter(|short_id| !short_id.is_empty())
            .collect(),
    })
}

fn parse_scope_ref(value: Option<&str>, field: &'static str) -> Result<Option<EntityId>, ApiError> {
    value
        .map(|value| parse_entity_id_param(value, field))
        .transpose()
}

/// A trace is reported for the tiers that had something to trace.
///
/// `minimal` is one direct channel, so its trace would say only "one text
/// query ran" — the tier name already says that, and an always-present field
/// carrying no information is worse than an absent one.
fn trace_for(effort: Effort, retrieved: &DepthSearchResult) -> Option<MemoryReasonTrace> {
    if effort == Effort::Minimal {
        return None;
    }
    Some(MemoryReasonTrace {
        queries_run: retrieved.queries_run.clone(),
        signals_used: retrieved.signals_used.clone(),
        candidates_scanned: retrieved.candidates_scanned,
    })
}

/// Projects admitted hits into citable evidence rows.
///
/// Every row goes back through the actor-keyed projection, so a hit the
/// ranking produced but the projection cannot read is dropped here rather than
/// cited as a source with no content behind it.
fn collect_evidence(
    vault: &oneiron::Vault,
    scoped_read: &ScopedRead<'_>,
    hits: Vec<ScoredEntity>,
) -> Result<Vec<MemoryReasonEvidence>, ApiError> {
    let mut evidence = Vec::with_capacity(hits.len());
    for hit in hits {
        let id = hit.id;
        let projected =
            project_scoped_search_result(scoped_read, hit, View::Full).map_err(|error| {
                tracing::error!(error = %error, "memory reason projection failed");
                ApiError::internal_server_error("memory reason projection failed")
            })?;
        let Some(Value::Object(fields)) = projected else {
            continue;
        };
        let short_id = short_ref_or_hex(vault, &id).map_err(|error| {
            tracing::error!(error = %error, "memory reason short id lookup failed");
            ApiError::internal_server_error("memory reason projection failed")
        })?;
        evidence.push(MemoryReasonEvidence {
            kind: string_field(&fields, "kind").unwrap_or_else(|| "UNKNOWN".to_owned()),
            text: evidence_text(&fields),
            confidence: evidence_confidence(&fields),
            short_id,
        });
    }
    Ok(evidence)
}

fn string_field(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|value| !value.trim().is_empty())
}

/// The row's text, preferring the claim value, then the common content keys,
/// then the projection's own label. Non-string values are rendered as compact
/// JSON so a structured value is still shown rather than silently dropped.
fn evidence_text(fields: &Map<String, Value>) -> String {
    for key in ["val", "content", "text", "txt", "body"] {
        match fields.get(key) {
            Some(Value::String(text)) if !text.trim().is_empty() => return text.clone(),
            Some(Value::Null) | Some(Value::String(_)) | None => {}
            Some(other) => return other.to_string(),
        }
    }
    string_field(fields, "label").unwrap_or_default()
}

/// The row's calibrated confidence.
///
/// `conf` is the claim codec's own calibrated-absolute field. A structural
/// record carries none and is `1.0`: the caller named a stored fact, and
/// nothing about it is a ranked guess.
fn evidence_confidence(fields: &Map<String, Value>) -> f32 {
    fields
        .get("conf")
        .and_then(Value::as_f64)
        .map_or(1.0, |confidence| confidence.clamp(0.0, 1.0) as f32)
}

struct AnsweredRead {
    answer: String,
    sources: Vec<String>,
    confidence: f32,
    gaps: Vec<String>,
    tokens_used: u64,
}

fn answer_from(
    request: &MemoryReasonRequest,
    query: &str,
    token_budget: usize,
    evidence: &[MemoryReasonEvidence],
    admission: Option<&DeepAdmission>,
) -> Result<AnsweredRead, ApiError> {
    if evidence.is_empty() {
        return Ok(AnsweredRead {
            answer: "Not in memory.".to_owned(),
            sources: Vec::new(),
            confidence: 0.0,
            gaps: vec![format!("no actor-readable memory matched {query:?}")],
            tokens_used: 0,
        });
    }
    let Some(admission) = admission else {
        return Ok(extractive_read(request.format, evidence));
    };
    compose_read(request, query, token_budget, evidence, admission)
}

/// The model-free answer: the evidence, rendered, citing everything it shows.
///
/// This is `memory::chat`'s extractive shape rebuilt for this route's rows —
/// render the retrieval, else fall back to the first row's text — and it is
/// why `minimal` and `standard` can answer at all without a host.
fn extractive_read(format: MemoryReasonFormat, evidence: &[MemoryReasonEvidence]) -> AnsweredRead {
    let rendered = render_evidence(format, evidence);
    let answer = if rendered.trim().is_empty() {
        evidence
            .first()
            .map(|row| row.text.clone())
            .unwrap_or_default()
    } else {
        rendered
    };
    AnsweredRead {
        answer,
        sources: evidence.iter().map(|row| row.short_id.clone()).collect(),
        confidence: mean_confidence(evidence),
        gaps: Vec::new(),
        tokens_used: 0,
    }
}

/// The deep answer, and the citation gate on it.
///
/// A composer that declines, answers blank, or cites something the retrieval
/// never returned does not get to speak: the read falls back to the extractive
/// answer over the same evidence and says so in `gaps`. The spend still counts
/// — the tokens were spent whether or not the answer was usable.
fn compose_read(
    request: &MemoryReasonRequest,
    query: &str,
    token_budget: usize,
    evidence: &[MemoryReasonEvidence],
    admission: &DeepAdmission,
) -> Result<AnsweredRead, ApiError> {
    let composed = admission.host.backend.compose(
        &MemoryReasonComposeRequest {
            question: query,
            depth: request.depth,
            format: request.format,
            token_budget,
            evidence,
        },
        admission.lease(),
    );
    admission.record_usage(composed.as_ref().map_or_else(
        |failure| failure.tokens_used,
        |composed| composed.tokens_used,
    ));
    let composed = composed.map_err(|failure| {
        tracing::error!(error = %failure.error, "memory reason composition failed");
        ApiError::internal_server_error("memory reason composition failed")
    })?;
    let tokens_used = composed.tokens_used;
    let composed = composed.value;

    let sources = validated_sources(evidence, &composed.source_short_ids);
    let usable = !composed.declined && !composed.answer.trim().is_empty() && sources.is_some();
    let Some(sources) = sources.filter(|_| usable) else {
        let mut fallback = extractive_read(request.format, evidence);
        fallback.gaps.extend(composed.gaps);
        fallback
            .gaps
            .push("deep composition was not usable; answered from the evidence itself".to_owned());
        fallback.tokens_used = tokens_used;
        return Ok(fallback);
    };

    Ok(AnsweredRead {
        answer: composed.answer,
        sources,
        confidence: composed.confidence.clamp(0.0, 1.0),
        gaps: composed.gaps,
        tokens_used,
    })
}

/// All-or-nothing, deliberately.
///
/// An unknown citation is not quietly dropped to salvage the rest: a composer
/// citing something the evidence never contained has already shown that its
/// sourcing cannot be trusted for the citations that happen to match.
fn validated_sources(
    evidence: &[MemoryReasonEvidence],
    proposed: &[String],
) -> Option<Vec<String>> {
    let mut sources: Vec<String> = Vec::new();
    for candidate in proposed {
        let candidate = candidate.trim();
        if candidate.is_empty() || !evidence.iter().any(|row| row.short_id == candidate) {
            return None;
        }
        let candidate = candidate.to_owned();
        if !sources.contains(&candidate) {
            sources.push(candidate);
        }
    }
    (!sources.is_empty()).then_some(sources)
}

fn mean_confidence(evidence: &[MemoryReasonEvidence]) -> f32 {
    if evidence.is_empty() {
        return 0.0;
    }
    let total: f32 = evidence.iter().map(|row| row.confidence).sum();
    (total / evidence.len() as f32).clamp(0.0, 1.0)
}

#[cfg(test)]
mod quality_tests;
