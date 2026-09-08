//! MEMORIES request controls, response DTOs, slot-budget resolution and companion assembly.

use super::super::companion_scope_resolution_authorized;
use super::super::core_engine_error;
use super::super::parse_entity_id_param;
use super::cursor::MEMORIES_CURSOR_SESSION_ID_MAX_BYTES;
use super::cursor::SHARED_SESSION_SCOPE_IDS;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;

/// Eiri Context v4 memory-board per-slot row caps.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesSlotControls {
    #[serde(default)]
    #[schema(example = 4)]
    pub(crate) claims: Option<usize>,
    #[serde(default)]
    #[schema(example = 2)]
    pub(crate) turns: Option<usize>,
    #[serde(default)]
    #[schema(example = 2)]
    pub(crate) summaries: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) facets: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) companions: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) other: Option<usize>,
}

/// Eiri Context v4 memory-board controls.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesControls {
    /// Whether to emit the v4 memory board. Defaults to true when v4 is requested.
    #[serde(default)]
    #[schema(example = true)]
    pub(crate) enabled: Option<bool>,
    /// Exact per-slot row caps for the memory board.
    #[serde(default)]
    pub(crate) slots: Option<ContextBoardMemoriesSlotControls>,
}

/// Eiri Context v4 session RAG controls.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardSessionControls {
    /// Stable caller/session key used to carry RAG state across calls.
    #[serde(default, rename = "session_id", alias = "sessionId")]
    #[schema(example = "default")]
    session_id: Option<String>,
}

/// Companion context that influences Eiri Context v4 assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardCompanionControls {
    #[serde(default, rename = "person_ref", alias = "personRef")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    person_ref: Option<String>,
    #[serde(default, rename = "persona_ref", alias = "personaRef")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    persona_ref: Option<String>,
    #[serde(default)]
    #[schema(example = "warm")]
    expression: Option<String>,
}

pub(crate) struct MemoriesRequest {
    pub(crate) memory_board_budget: Option<oneiron::MemoriesBudget>,
    pub(crate) session_scope_id: String,
    pub(crate) session_id: String,
    pub(crate) companion: Option<oneiron::CompanionAssembly>,
}

/// Stable Eiri Context v4 memory-board slot name.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardMemorySlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Companions,
    Other,
}

/// Source section for one Eiri Context v4 memory-board row.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardMemorySource {
    Result,
    Neighbor,
}

/// Per-slot row caps for an Eiri Context v4 memory board.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesBudget {
    /// Claim row cap.
    #[schema(example = 2)]
    claims: usize,
    /// Turn/message row cap.
    #[schema(example = 4)]
    turns: usize,
    /// Summary row cap.
    #[schema(example = 1)]
    summaries: usize,
    /// Facet row cap.
    #[schema(example = 1)]
    facets: usize,
    /// Companion-register row cap.
    #[schema(example = 0)]
    companions: usize,
    /// Row cap for all other entity types.
    #[schema(example = 2)]
    other: usize,
}

/// Companion assembly metadata echoed with an Eiri Context v4 memory board.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardCompanionAssembly {
    /// Effective caller/session identity used for the v4 board.
    #[schema(example = "session-123")]
    caller: Option<String>,
    /// Effective companion scope selected from active companion records.
    #[schema(example = "personal")]
    scope: Option<String>,
    /// Active record class that selected the companion scope.
    #[serde(rename = "scope_source")]
    #[schema(example = "persona_and_relationship_records")]
    scope_source: Option<String>,
    /// Optional person entity id for companion-aware assembly metadata.
    #[serde(rename = "person_ref")]
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: Option<String>,
    /// Optional persona entity id for companion-aware assembly metadata.
    #[serde(rename = "persona_ref")]
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: Option<String>,
    /// Effective expression register boundary.
    #[schema(example = "warm")]
    expression: Option<String>,
}

/// Stable row in an Eiri Context v4 memory board.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoryRow {
    /// Zero-based index after stable sorting and slot-budget filtering.
    #[serde(rename = "row_index")]
    #[schema(example = 0)]
    row_index: usize,
    /// Budget slot that owns this row.
    slot: ContextBoardMemorySlot,
    /// Whether the row came from primary results or neighbors.
    source: ContextBoardMemorySource,
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Short id used for compact display.
    #[serde(rename = "short_id")]
    #[schema(example = "tr_a1b2c3d4")]
    short_id: String,
    /// One-byte content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Numeric entity type byte.
    #[serde(rename = "entity_type")]
    #[schema(example = 1)]
    entity_type: u8,
    /// Short ref for ASSET and ASSET_TEXT rows. Consumers pass this to the core hydrate resolver.
    #[serde(rename = "asset_ref", skip_serializing_if = "Option::is_none")]
    #[schema(example = "tx123:a7")]
    asset_ref: Option<String>,
    /// Retrieval score.
    #[schema(example = 0.87)]
    score: f32,
}

/// Eiri Context v4 memory-board response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemories {
    /// Context version for this memory-board envelope.
    #[schema(example = "v4")]
    version: String,
    /// Applied per-slot row budget.
    budget: ContextBoardMemoriesBudget,
    /// Stable memory-board rows.
    rows: Vec<ContextBoardMemoryRow>,
    /// Companion assembly metadata when v4 companion controls are present.
    companion: Option<ContextBoardCompanionAssembly>,
}

/// Eiri Context v4 session RAG cursor response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesCursor {
    /// Effective v4 session id.
    #[serde(rename = "session_id")]
    #[schema(example = "session-123")]
    session_id: String,
    /// Monotonic cursor revision for this session.
    #[schema(example = 2_u64)]
    revision: u64,
    /// Number of context-pack queries observed for this session.
    #[serde(rename = "query_count")]
    #[schema(example = 2_u64)]
    query_count: u64,
    /// Last persisted retrieval telemetry run id, when available.
    #[serde(rename = "last_retrieval_run_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    last_retrieval_run_id: Option<String>,
    /// Bounded list of most recent context-pack result ids for this session.
    #[serde(rename = "last_result_ids")]
    last_result_ids: Vec<String>,
}

/// Resolves the MEMORIES half of a context-board request: the slot budget,
/// the caller's session scope and session id, and the companion assembly.
///
/// The session scope is the authenticated actor (`principal_ref`, else the
/// principal); a shared credential has no isolated scope and is refused.
#[expect(
    dead_code,
    reason = "called by the context-board handler, which lands in FOLD B4"
)]
pub(crate) fn resolve_memories_request(
    vault: &oneiron::Vault,
    memories: Option<&ContextBoardMemoriesControls>,
    session: Option<&ContextBoardSessionControls>,
    companion: Option<&ContextBoardCompanionControls>,
    budget_shape: (usize, usize),
    auth: &CoreAuth,
) -> Result<MemoriesRequest, ApiError> {
    let session_scope_id = auth.principal_ref().unwrap_or(auth.principal()).trim();
    validate_session_id(session_scope_id, "session.scope")?;
    if is_shared_session_scope_id(session_scope_id) {
        return Err(ApiError::bad_request(
            "session.session_id requires an isolated caller identity",
            Some("session.session_id"),
        ));
    }

    let session_id = session
        .and_then(|controls| controls.session_id.as_deref())
        .unwrap_or(session_scope_id)
        .trim();
    validate_session_id(session_id, "session.session_id")?;

    let memory_board_budget = memories
        .and_then(|controls| controls.enabled)
        .unwrap_or(true)
        .then(|| memories_budget(memories, budget_shape.0, budget_shape.1));

    let companion = resolve_companion_assembly(vault, companion, session_id, auth)?;

    Ok(MemoriesRequest {
        memory_board_budget,
        session_scope_id: session_scope_id.to_owned(),
        session_id: session_id.to_owned(),
        companion: Some(companion),
    })
}

pub(crate) fn resolve_companion_assembly(
    vault: &oneiron::Vault,
    companion: Option<&ContextBoardCompanionControls>,
    session_id: &str,
    companion_auth: &CoreAuth,
) -> Result<oneiron::CompanionAssembly, ApiError> {
    let (person_ref_wire, person_ref) = parse_companion_ref(
        companion.and_then(|controls| controls.person_ref.as_deref()),
        "companion.person_ref",
    )?;
    let (persona_ref_wire, persona_ref) = parse_companion_ref(
        companion.and_then(|controls| controls.persona_ref.as_deref()),
        "companion.persona_ref",
    )?;
    let requested_expression = companion
        .and_then(|controls| controls.expression.as_deref())
        .map(|value| {
            oneiron::CompanionExpression::parse(value).ok_or_else(|| {
                ApiError::bad_request(
                    "companion.expression must be professional, warm, or unrestricted",
                    Some("companion.expression"),
                )
            })
        })
        .transpose()?;
    let fallback_expression =
        requested_expression.unwrap_or(oneiron::CompanionExpression::Professional);
    if !companion_scope_resolution_authorized(vault, companion_auth, person_ref, persona_ref)? {
        return Ok(oneiron::CompanionAssembly {
            caller: Some(session_id.to_owned()),
            scope: Some(companion_scope_wire(&oneiron::CompanionScope::neutral()).to_owned()),
            scope_source: Some(
                oneiron::CompanionScopeResolutionSource::NeutralDefault
                    .as_str()
                    .to_owned(),
            ),
            person_ref: person_ref_wire,
            persona_ref: persona_ref_wire,
            expression: Some(fallback_expression.as_str().to_owned()),
        });
    }
    let register = vault.companion_register().map_err(|error| {
        tracing::error!(error = %error, "companion scope resolution failed");
        core_engine_error("companion scope resolution failed", error)
    })?;
    let relationship_ref = person_ref.zip(persona_ref);
    let mut expressions = oneiron::CompanionExpressionRegister::new();
    let resolution = if let Some(expression) = requested_expression {
        let seed_resolution = register.resolve_companion_scope(
            &expressions,
            person_ref,
            persona_ref,
            relationship_ref,
        );
        if let Some(key) = seed_resolution
            .relationship_key
            .as_ref()
            .or(seed_resolution.persona_key.as_ref())
        {
            expressions
                .update(key.clone(), expression)
                .map_err(|error| {
                    tracing::error!(error = %error, "companion expression registration failed");
                    core_engine_error("companion expression registration failed", error)
                })?;
            register.resolve_companion_scope(
                &expressions,
                person_ref,
                persona_ref,
                relationship_ref,
            )
        } else {
            seed_resolution
        }
    } else {
        register.resolve_companion_scope(&expressions, person_ref, persona_ref, relationship_ref)
    };
    let expression = requested_expression.unwrap_or(resolution.expression);

    Ok(oneiron::CompanionAssembly {
        caller: Some(session_id.to_owned()),
        scope: Some(companion_scope_wire(&resolution.scope).to_owned()),
        scope_source: Some(resolution.source.as_str().to_owned()),
        person_ref: person_ref_wire,
        persona_ref: persona_ref_wire,
        expression: Some(expression.as_str().to_owned()),
    })
}

pub(crate) fn parse_companion_ref(
    value: Option<&str>,
    field: &'static str,
) -> Result<(Option<String>, Option<oneiron::EntityId>), ApiError> {
    let Some(raw) = value else {
        return Ok((None, None));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok((None, None));
    }
    if trimmed.len() == 32 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let id = parse_entity_id_param(trimmed, field)?;
        return Ok((Some(id.to_hex()), Some(id)));
    }
    Ok((Some(trimmed.to_owned()), None))
}

pub(crate) fn validate_session_id(session_id: &str, field: &'static str) -> Result<(), ApiError> {
    if session_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            format!("{field} must be non-empty"),
            Some(field),
        ));
    }
    if session_id.len() > MEMORIES_CURSOR_SESSION_ID_MAX_BYTES {
        return Err(ApiError::bad_request(
            format!("{field} must be at most {MEMORIES_CURSOR_SESSION_ID_MAX_BYTES} bytes"),
            Some(field),
        ));
    }
    Ok(())
}

pub(crate) fn is_shared_session_scope_id(session_scope_id: &str) -> bool {
    SHARED_SESSION_SCOPE_IDS.contains(&session_scope_id)
}

pub(crate) fn companion_scope_wire(scope: &oneiron::CompanionScope) -> &'static str {
    match scope {
        oneiron::CompanionScope::Neutral => "neutral",
        oneiron::CompanionScope::Personal { .. } => "personal",
        oneiron::CompanionScope::SharedVault { .. } => "shared_vault",
        _ => "unknown",
    }
}

pub(crate) fn memories_budget(
    controls: Option<&ContextBoardMemoriesControls>,
    limit: usize,
    default_selected_edges: usize,
) -> oneiron::MemoriesBudget {
    let retrieval_defaults = oneiron::ContextPackRetrievalBudget::from_limit(
        limit,
        oneiron::TokenAllocation::default(),
        default_selected_edges,
    );
    let defaults = oneiron::MemoriesBudget::new(
        retrieval_defaults.claims,
        retrieval_defaults.turns,
        retrieval_defaults.summaries,
        retrieval_defaults.facets,
        0,
        retrieval_defaults.other,
    );
    let Some(slots) = controls.and_then(|controls| controls.slots.as_ref()) else {
        return defaults;
    };

    let companions = slots.companions.unwrap_or(defaults.companions);
    let other = slots
        .other
        .unwrap_or_else(|| retrieval_defaults.other.saturating_sub(companions));
    oneiron::MemoriesBudget::new(
        slots.claims.unwrap_or(defaults.claims),
        slots.turns.unwrap_or(defaults.turns),
        slots.summaries.unwrap_or(defaults.summaries),
        slots.facets.unwrap_or(defaults.facets),
        companions,
        other,
    )
}
