//! Schema description-gap filler.

use super::*;
use serde_json::Value;

#[expect(clippy::too_many_lines)]
pub(crate) fn fill_schema_description_gaps(spec: &mut Value) {
    set_schema_property_description(
        spec,
        "VectorSearchQuery",
        "view",
        "Optional projection view for returned items. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "TextSearchQuery",
        "view",
        "Optional projection view for returned items. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "CoreQueryRequest",
        "view",
        "Optional projection view for returned items. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateRequest",
        "view",
        "Optional projection view for the hydrated live entity. Defaults to full.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "view",
        "Optional field profile for hydrated context-pack fields. Defaults to standard.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "depth",
        "Optional nested edge-depth controls for context-pack assembly.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "policy",
        "Optional nested ranking and projection policy controls.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "time",
        "Optional time-window filters for context-pack retrieval.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "budget",
        "Optional retrieval and serialization budget controls.",
    );
    set_schema_property_description(
        spec,
        "ContextPackDepthControls",
        "edge_hop",
        "Edge expansion depth for neighbor hydration.",
    );
    set_schema_property_description(
        spec,
        "ContextPackDepthControls",
        "max_neighbors",
        "Maximum neighbors to hydrate during edge expansion.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "hydrate",
        "Whether to include hydrated fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "include_edges",
        "Whether to include edge records in hydrated entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "include_vectors",
        "Whether to include stored vectors when present.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "view",
        "Field profile for hydrated fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_recency_days",
        "Apply recency boost with the supplied half-life in days.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_salience",
        "Apply salience boost.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_confidence",
        "Apply confidence boost.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_contiguity",
        "Apply contiguity boost.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "since",
        "Keep entities learned at or after this Unix timestamp.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "occurred_start",
        "Occurrence window start, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "occurred_end",
        "Occurrence window end, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "learned_start",
        "Learned-at window start, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "learned_end",
        "Learned-at window end, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "claims",
        "Maximum claim entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "turns",
        "Maximum turn entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "summaries",
        "Maximum summary entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "facets",
        "Maximum facet entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "other",
        "Maximum other entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "selected_edges",
        "Edge-walk neighbor selection budget.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "token_budget",
        "Serialized token budget for downstream serialized packs.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "max_item_tokens",
        "Per-item token cap for context-pack serialization.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "max_field_chars",
        "Maximum field characters before serialization truncation.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "retrieval",
        "Per-kind retrieval item budgets before final truncation.",
    );
    set_schema_property_description(
        spec,
        "CoreListQuery",
        "view",
        "Optional projection view for returned entities. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateResponse",
        "item",
        "Projected live entity; omitted when the short ref resolves to a deleted entity.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateResponse",
        "deletion",
        "Deletion metadata when the short ref resolves to a deleted entity.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateDeletionMetadata",
        "reason",
        "Decoded tombstone reason, absent for legacy, malformed, or dangling deletion rows.",
    );
    set_schema_property_description(
        spec,
        "CoreBatchShortIdHydrateRequest",
        "view",
        "Optional projection view for live hydrate results. Defaults to full.",
    );
    set_schema_property_description(
        spec,
        "CoreBatchShortIdHydrateItem",
        "result",
        "Live or deleted hydrate payload when the input resolves.",
    );
    set_schema_property_description(
        spec,
        "CoreBatchShortIdHydrateItem",
        "error",
        "Typed per-input hydrate error for malformed or not-found refs.",
    );
    set_schema_property_description(
        spec,
        "CoreShortIdHydrateError",
        "field",
        "Request field that failed validation, when known.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEdge",
        "vad",
        "Optional edge VAD payload for semantic edges.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEntity",
        "fields",
        "Hydrated entity fields when requested.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEntity",
        "edges",
        "Hydrated outbound edges when requested.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEntity",
        "vector",
        "Stored vector when requested and present.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "quality",
        "Execution quality projected from the engine's shared report: full, degraded, or passthrough.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "degradation",
        "Observed reasons for degraded execution; absent when none were recorded.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "confidenceAdjustment",
        "Pinned presentation confidence adjustment for the execution tier: 0, -0.15, or -0.35.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "empty",
        "Structured empty-result context when no entities surface.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "state",
        "Typed missing-data or low-confidence state.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "evidence",
        "Retrieval telemetry evidence and score breakdown.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "interlocutors",
        "Optional interlocutor presence controls (OF-365 ILD-1).",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "interlocutors",
        "Resolved per-speaker interlocutor stamps when an interlocutors block was supplied or the auth is narrowed (scoped or principal_ref-bound).",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "disclosure",
        "Disclosure block for the clamp applied to this assembly; present under the same rule as interlocutors.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesBudget",
        "claims",
        "Claim row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesBudget",
        "turns",
        "Turn/message row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesBudget",
        "summaries",
        "Summary row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesBudget",
        "facets",
        "Facet row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesBudget",
        "companions",
        "Companion-register row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesBudget",
        "other",
        "Row cap for all other entity types.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardCompanionAssembly",
        "caller",
        "Effective caller/session identity used for the MEMORIES section.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardCompanionAssembly",
        "person_ref",
        "Optional person entity id for companion-aware assembly metadata.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardCompanionAssembly",
        "persona_ref",
        "Optional persona entity id for companion-aware assembly metadata.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "row_index",
        "Zero-based index after stable sorting and slot-budget filtering.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "slot",
        "Budget slot that owns this row.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "source",
        "Whether the row came from primary results or neighbors.",
    );
    set_schema_property_description(spec, "ContextBoardMemoryRow", "id", "Hex entity id.");
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "short_id",
        "Short id used for compact display.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "content_hash",
        "One-byte content hash as two lowercase hex digits.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "entity_type",
        "Numeric entity type byte.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoryRow",
        "asset_ref",
        "Short ref for ASSET and ASSET_TEXT rows. Consumers pass this to the core hydrate resolver.",
    );
    set_schema_property_description(spec, "ContextBoardMemoryRow", "score", "Retrieval score.");
    set_schema_property_description(
        spec,
        "ContextBoardMemories",
        "version",
        "Section format version.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemories",
        "budget",
        "Applied per-slot row budget.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemories",
        "rows",
        "Stable MEMORIES rows.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemories",
        "companion",
        "Companion assembly metadata when companion controls are present.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesCursor",
        "session_id",
        "Effective session id.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesCursor",
        "revision",
        "Monotonic cursor revision for this session.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesCursor",
        "query_count",
        "Number of context-pack queries observed for this session.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesCursor",
        "last_retrieval_run_id",
        "Last persisted retrieval telemetry run id, when available.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesCursor",
        "last_result_ids",
        "Bounded list of most recent context-pack result ids for this session.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardRequest",
        "retrieval",
        "Retrieval for this turn. When present the shared context-pack pipeline runs, its MEMORIES projection and pack ride the response, and the cursor advances.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardRequest",
        "memories",
        "MEMORIES section controls: whether to project it and the per-slot row caps.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardRequest",
        "session",
        "Session controls: the session id that carries the cursor across calls.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardRequest",
        "companion",
        "Companion scope that influences MEMORIES assembly.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "session",
        "Session prefix: API level, entity counts, latest activity.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "notifications",
        "Pending notifications scoped to the caller and not yet surfaced.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "unprocessed",
        "Work items that still need caller-side processing.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "budget",
        "Token meter snapshot.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "cursor",
        "The caller's MEMORIES cursor: advanced when retrieval ran, otherwise current.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "memories",
        "This turn's MEMORIES section; absent when retrieval was skipped or disabled.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardResponse",
        "pack",
        "The context pack retrieval produced; absent when retrieval was skipped.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardSession",
        "api_version",
        "Stable API level string.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardSession",
        "counts",
        "Live entity counts keyed by numeric entity type; zero counts are omitted.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardSession",
        "last_activity",
        "Latest learned-at timestamp across agent-visible entities.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardNotification",
        "id",
        "Hex notification entity id.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardNotification",
        "learned_at",
        "Learned-at timestamp of the notification.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardNotification",
        "body",
        "Decoded notification body.",
    );
    set_schema_property_description(spec, "ContextBoardUnprocessedItem", "id", "Hex entity id.");
    set_schema_property_description(
        spec,
        "ContextBoardUnprocessedItem",
        "entity_type",
        "Numeric entity type byte.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardUnprocessedItem",
        "learned_at",
        "Learned-at timestamp of the item.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardUnprocessedItem",
        "body",
        "Decoded item body.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardBudget",
        "tokens_used",
        "Tokens consumed so far.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardBudget",
        "tokens_limit",
        "Token limit for the session.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardBudget",
        "tokens_remaining",
        "Saturated tokens_limit minus tokens_used.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesControls",
        "enabled",
        "Whether to project the MEMORIES section. Defaults to true.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesControls",
        "slots",
        "Exact per-slot row caps for the MEMORIES section.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesSlotControls",
        "claims",
        "Claim row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesSlotControls",
        "turns",
        "Turn/message row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesSlotControls",
        "summaries",
        "Summary row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesSlotControls",
        "facets",
        "Facet row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesSlotControls",
        "companions",
        "Companion-register row cap.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardMemoriesSlotControls",
        "other",
        "Row cap for all other entity types; defaults to the retrieval budget's other cap minus companions.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardSessionControls",
        "session_id",
        "Stable session key that carries the MEMORIES cursor across calls. Defaults to the caller's own identity.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardCompanionControls",
        "person_ref",
        "Optional person entity id (32 hex) or opaque person label.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardCompanionControls",
        "persona_ref",
        "Optional persona entity id (32 hex) or opaque persona label.",
    );
    set_schema_property_description(
        spec,
        "ContextBoardCompanionControls",
        "expression",
        "Requested expression register: professional, warm, or unrestricted.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "kind",
        "Stable state discriminator.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "reason",
        "Empty-result reason when no entities surfaced.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "total_in_scope",
        "Total records in scope when known.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "hint",
        "Caller-facing hint from the retrieval layer.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "telemetry_persisted",
        "Whether the retrieval telemetry row was finalized.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "retrieval_run_id",
        "Retrieval telemetry run id when persistence succeeded.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "result_ids",
        "Surfaced result ids recorded in telemetry.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "scores",
        "Final score evidence recorded in telemetry.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "result_id",
        "Hex entity id.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "final_rank",
        "Final rank after context-pack hydration.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "final_score",
        "Final fused score.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "access_factor",
        "Read-side access factor applied to the fused score, when available.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "components",
        "Signal-level score components.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreComponent",
        "signal",
        "Retrieval signal name.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreComponent",
        "rank",
        "Rank within the signal.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreComponent",
        "score",
        "Raw signal score.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterSubjectPayload",
        "relationship_ref",
        "Source and target entity pair for relationship records.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordPayload",
        "scope",
        "Visibility and privacy scope for this register record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordPayload",
        "subject",
        "Persona or relationship subject for this register record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordPayload",
        "provenance",
        "Provenance stamp for this register record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterCreateRecordRequest",
        "record",
        "Typed companion register record envelope to create.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterUpdateRecordRequest",
        "record",
        "Replacement record envelope; scope and subject must match the existing record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordResponse",
        "record",
        "Typed companion register record envelope.",
    );
}
