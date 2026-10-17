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

/// MEMORIES per-slot row caps.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesSlotControls {
    /// Claim row cap.
    #[serde(default)]
    #[schema(example = 4)]
    pub(crate) claims: Option<usize>,
    /// Turn/message row cap.
    #[serde(default)]
    #[schema(example = 2)]
    pub(crate) turns: Option<usize>,
    /// Summary row cap.
    #[serde(default)]
    #[schema(example = 2)]
    pub(crate) summaries: Option<usize>,
    /// Facet row cap.
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) facets: Option<usize>,
    /// Row cap for all other entity types; defaults to the retrieval budget's other cap.
    #[serde(default)]
    #[schema(example = 1)]
    pub(crate) other: Option<usize>,
}

/// MEMORIES section controls.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesControls {
    /// Whether to project the MEMORIES section. Defaults to true.
    #[serde(default)]
    #[schema(example = true)]
    pub(crate) enabled: Option<bool>,
    /// Exact per-slot row caps for the MEMORIES section.
    #[serde(default)]
    pub(crate) slots: Option<ContextBoardMemoriesSlotControls>,
    /// One row cap across every active world (pinned rows remain).
    #[serde(default)]
    pub(crate) shared_total: Option<usize>,
    /// Explicit engine-issued short refs. These bypass query scope, never read authority.
    #[serde(default)]
    pub(crate) pinned_refs: Vec<String>,
}

/// Session controls for the MEMORIES cursor.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardSessionControls {
    /// Stable session key that carries the MEMORIES cursor across calls.
    /// Defaults to the caller's own identity.
    #[serde(default, rename = "session_id", alias = "sessionId")]
    #[schema(example = "session-123")]
    pub(super) session_id: Option<String>,
    /// The conversation branch this board renders for. A hook block
    /// addressed to a branch reaches only a board that names it.
    #[serde(default)]
    #[schema(example = "branch-2")]
    pub(super) branch: Option<String>,
}

/// Companion scope that influences MEMORIES assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub(crate) struct ContextBoardCompanionControls {
    /// Optional PERSON identity (32-hex entity id) or opaque person label.
    #[serde(default, rename = "person_ref", alias = "personRef")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    person_ref: Option<String>,
    /// Optional other endpoint of the relationship (32-hex entity id) or opaque label.
    #[serde(default, rename = "persona_ref", alias = "personaRef")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    persona_ref: Option<String>,
    /// Requested expression register: professional, warm, or unrestricted.
    #[serde(default)]
    #[schema(example = "warm")]
    expression: Option<String>,
}

pub(crate) struct MemoriesRequest {
    pub(crate) memory_board_budget: Option<oneiron::MemoriesBudget>,
    pub(crate) pinned_refs: Vec<String>,
    /// The hook blocks reaching this board, pinned after the explicit and
    /// manifest pins (ARCH-0080 §11).
    pub(crate) hook_pins: Vec<oneiron::context_board::HookPin>,
    pub(crate) session_scope_id: String,
    pub(crate) session_id: String,
    pub(crate) companion: Option<oneiron::CompanionAssembly>,
}

/// Stable MEMORIES slot name.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardMemorySlot {
    Claims,
    Turns,
    Summaries,
    Facets,
    Other,
}

/// Source of one MEMORIES row.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardMemorySource {
    Result,
    Neighbor,
}

/// Per-slot row caps for a MEMORIES section.
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
    /// Row cap for all other entity types.
    #[schema(example = 2)]
    other: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_total: Option<usize>,
}

/// Companion assembly metadata echoed with a MEMORIES section.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardCompanionAssembly {
    /// Effective caller/session identity used for the MEMORIES section.
    #[schema(example = "session-123")]
    caller: Option<String>,
    /// Effective companion scope: personal when both refs resolve to PERSON
    /// identities, otherwise neutral.
    #[schema(example = "personal")]
    scope: Option<String>,
    /// How the companion scope was resolved: `person_identity` when both refs
    /// are PERSON entities, otherwise `neutral_default`.
    #[serde(rename = "scope_source")]
    #[schema(example = "person_identity")]
    scope_source: Option<String>,
    /// Optional PERSON identity used for companion-aware assembly metadata.
    #[serde(rename = "person_ref")]
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: Option<String>,
    /// Optional other relationship endpoint used for companion-aware assembly metadata.
    #[serde(rename = "persona_ref")]
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: Option<String>,
    /// Effective expression register boundary.
    #[schema(example = "warm")]
    expression: Option<String>,
}

/// One stable row in a MEMORIES section.
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
    /// Canonical engine-issued source-trust label, never inferred from prose.
    claim_source: Option<String>,
    /// World partition; foreign ids render outside the first-party wrapper.
    world: Option<String>,
    /// pinned, snippet, or index_only.
    tier: String,
    /// Escaped only at rendering, absent for foreign index-only rows.
    snippet: Option<String>,
    /// `<pack>/<hook>` when a hook block pins this row; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "local/remind")]
    hook: Option<String>,
}

/// MEMORIES section envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemories {
    /// Section format version.
    #[schema(example = "v4")]
    version: String,
    /// Applied per-slot row budget.
    budget: ContextBoardMemoriesBudget,
    /// Stable MEMORIES rows.
    rows: Vec<ContextBoardMemoryRow>,
    /// Companion assembly metadata when companion controls are present.
    companion: Option<ContextBoardCompanionAssembly>,
}

/// The caller's MEMORIES cursor.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardMemoriesCursor {
    /// Effective session id.
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

    let pinned_refs = bounded_pinned_refs(memories)?.to_vec();
    let companion = resolve_companion_assembly(vault, companion, session_id, auth)?;

    Ok(MemoriesRequest {
        memory_board_budget,
        pinned_refs,
        hook_pins: Vec::new(),
        session_scope_id: session_scope_id.to_owned(),
        session_id: session_id.to_owned(),
        companion: Some(companion),
    })
}

/// The caller's explicit MEMORIES pins, refused past the bounded reference list.
fn bounded_pinned_refs(
    memories: Option<&ContextBoardMemoriesControls>,
) -> Result<&[String], ApiError> {
    let pinned_refs = memories.map_or(&[][..], |controls| controls.pinned_refs.as_slice());
    if pinned_refs.len() > 128 || pinned_refs.iter().any(|reference| reference.len() > 128) {
        return Err(ApiError::bad_request(
            "memory pins exceed the bounded reference list",
            Some("memories.pinned_refs"),
        ));
    }
    Ok(pinned_refs)
}

/// The MEMORIES section a board that runs no retrieval still owes its pins (OF-579): the
/// caller's `memories.pinned_refs`, the policy manifest's pins and each hook block's rows, read
/// as a context pack reads its pins, under the caller's read narrowed to the board's room (or
/// the caller alone) and the disclosure clamp of those present. A once answer waits for a pack
/// assembly, so these rows read under standing clearance alone. `None` when MEMORIES is turned
/// off or no row is admitted. What goes out under a contact's standing clearance gets the
/// owner's post-hoc receipt, as a pack's rows do.
pub(crate) async fn board_pins_section(
    server: &crate::server::SyncServer,
    auth: &CoreAuth,
    memories: Option<&ContextBoardMemoriesControls>,
    room_id: Option<oneiron::EntityId>,
    hook_pins: &[oneiron::context_board::HookPin],
) -> Result<Option<oneiron::MemoriesSection>, ApiError> {
    if memories.and_then(|controls| controls.enabled) == Some(false) {
        return Ok(None);
    }
    let pins = BoardPinSources {
        refs: bounded_pinned_refs(memories)?,
        manifest: true,
        hooks: hook_pins,
    };
    let read = super::super::scoped_read_for_core_auth(&server.vault, auth)?;
    let Some(pinned) = board_pins_projection(&server.vault, auth, read, room_id, &pins)? else {
        return Ok(None);
    };
    pinned.receipt.record(&server.vault).await?;
    Ok(Some(pinned.section))
}

/// What a board that runs no retrieval pins into MEMORIES, in a pack's order: explicit refs,
/// then the policy manifest's pins when `manifest`, then hook blocks.
pub(crate) struct BoardPinSources<'a> {
    pub(crate) refs: &'a [String],
    pub(crate) manifest: bool,
    pub(crate) hooks: &'a [oneiron::context_board::HookPin],
}

/// A no-retrieval board's pinned rows and the receipt their delivery owes.
pub(crate) struct BoardPins {
    pub(crate) section: oneiron::MemoriesSection,
    pub(crate) receipt: PinsReceipt,
}

/// The owner's post-hoc receipt for pinned rows that go out under a contact's standing
/// clearance, held until the board carrying them is delivered.
pub(crate) struct PinsReceipt {
    delivered: Vec<oneiron::EntityId>,
    interlocutors: Option<oneiron::InterlocutorSet>,
    channels: std::collections::BTreeSet<String>,
}

/// [`board_pins_section`]'s rows, read under `read` (the caller's own ceiling) narrowed to the
/// board's room (or the caller alone) and clamped to those present, with the receipt left for
/// the caller to record once the board is delivered. `None` when no row is admitted.
pub(crate) fn board_pins_projection<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
    read: oneiron::claim::ScopedRead<'a>,
    room_id: Option<oneiron::EntityId>,
    pins: &BoardPinSources<'_>,
) -> Result<Option<BoardPins>, ApiError> {
    if pins.refs.is_empty() && !pins.manifest && pins.hooks.is_empty() {
        return Ok(None);
    }
    let (room_members, room) = super::super::resolve_core_room(vault, auth, &read, room_id)?;
    let interlocutors =
        super::super::resolve_core_interlocutor_set(vault, auth, &read, None, room.as_ref())?;
    let read = super::super::narrow_to_core_audience(
        vault,
        auth,
        read,
        room_members.as_deref(),
        room.as_ref(),
        interlocutors.as_ref(),
    )?;
    let disclosure = super::super::resolve_core_disclosure(
        vault,
        interlocutors.as_ref(),
        room.as_ref().map(|room| room.reader.is_some()),
    )?;
    let mut section =
        oneiron::MemoriesSection::pins_only(disclosure.as_ref().map(|ctx| ctx.assembly(0)));
    section
        .include_pinned_refs_with_disclosure(&read, pins.refs, disclosure.as_ref())
        .map_err(|error| core_engine_error("memory pin read failed", error))?;
    if pins.manifest {
        let automatic = read
            .manifest_pinned_refs()
            .map_err(|error| core_engine_error("manifest pin read failed", error))?;
        section
            .include_pinned_refs_with_disclosure(&read, &automatic.value, disclosure.as_ref())
            .map_err(|error| core_engine_error("manifest pin disclosure failed", error))?;
    }
    section
        .include_hook_pins(&read, pins.hooks, disclosure.as_ref())
        .map_err(|error| core_engine_error("hook pin read failed", error))?;
    if section.rows.is_empty() {
        return Ok(None);
    }
    let delivered = section
        .rows
        .iter()
        .map(|row| oneiron::EntityId::from_hex(&row.id))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| core_engine_error("memory delivery id failed", error))?;
    let channels = room_id
        .map(|room| oneiron::consent::contact_disclosure_room_channel(&room))
        .into_iter()
        .collect();
    Ok(Some(BoardPins {
        section,
        receipt: PinsReceipt {
            delivered,
            interlocutors,
            channels,
        },
    }))
}

impl PinsReceipt {
    /// The rows this receipt covers.
    pub(crate) fn delivered(&self) -> &[oneiron::EntityId] {
        &self.delivered
    }

    /// Records the receipt: call it once the rows are going out, never for a board only read.
    pub(crate) async fn record(
        self,
        vault: &std::sync::Arc<oneiron::Vault>,
    ) -> Result<(), ApiError> {
        let vault = std::sync::Arc::clone(vault);
        tokio::task::spawn_blocking(move || {
            vault.record_standing_disclosure_uses(
                &self.delivered,
                self.interlocutors.as_ref(),
                &std::collections::BTreeMap::new(),
                &self.channels,
            )
        })
        .await
        .map_err(|_| ApiError::internal_server_error("disclosure receipt task failed"))?
        .map_err(|error| core_engine_error("disclosure receipt failed", error))?;
        Ok(())
    }
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
            scope_source: Some("neutral_default".to_owned()),
            person_ref: person_ref_wire,
            persona_ref: persona_ref_wire,
            expression: Some(fallback_expression.as_str().to_owned()),
        });
    }
    // A companion persona is a PERSON identity.
    // Authorization is checked above, before either identity is inspected.
    let personal = match (person_ref, persona_ref) {
        (Some(person), Some(persona)) => {
            let person_kind = vault
                .get_entity_type(&person)
                .map_err(|error| core_engine_error("companion PERSON resolution failed", error))?;
            let persona_kind = vault
                .get_entity_type(&persona)
                .map_err(|error| core_engine_error("companion PERSON resolution failed", error))?;
            person_kind == Some(oneiron::registry::ENTITY_TYPE_PERSON)
                && persona_kind == Some(oneiron::registry::ENTITY_TYPE_PERSON)
        }
        _ => false,
    };
    let scope = if personal {
        oneiron::CompanionScope::personal(person_ref.expect("checked PERSON"))
    } else {
        oneiron::CompanionScope::neutral()
    };
    Ok(oneiron::CompanionAssembly {
        caller: Some(session_id.to_owned()),
        scope: Some(companion_scope_wire(&scope).to_owned()),
        scope_source: Some(
            if personal {
                "person_identity"
            } else {
                "neutral_default"
            }
            .to_owned(),
        ),
        person_ref: person_ref_wire,
        persona_ref: persona_ref_wire,
        expression: Some(fallback_expression.as_str().to_owned()),
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
        retrieval_defaults.other,
    );
    let Some(slots) = controls.and_then(|controls| controls.slots.as_ref()) else {
        return controls
            .and_then(|controls| controls.shared_total)
            .map_or(defaults, |total| defaults.with_shared_total(total));
    };

    let selected = oneiron::MemoriesBudget::new(
        slots.claims.unwrap_or(defaults.claims),
        slots.turns.unwrap_or(defaults.turns),
        slots.summaries.unwrap_or(defaults.summaries),
        slots.facets.unwrap_or(defaults.facets),
        slots.other.unwrap_or(defaults.other),
    );
    controls
        .and_then(|controls| controls.shared_total)
        .map_or(selected, |total| selected.with_shared_total(total))
}
