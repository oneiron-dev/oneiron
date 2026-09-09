//! Schema description-gap filler.

use super::*;
use serde_json::Value;

/// Property descriptions applied on top of the derived schemas, keyed by
/// component schema name. Each entry sets one property description; the
/// helper skips targets the generated document does not contain.
const PROPERTY_DESCRIPTIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "VectorSearchQuery",
        &[(
            "view",
            "Optional projection view for returned items. Defaults to summary.",
        )],
    ),
    (
        "TextSearchQuery",
        &[(
            "view",
            "Optional projection view for returned items. Defaults to summary.",
        )],
    ),
    (
        "CoreQueryRequest",
        &[(
            "view",
            "Optional projection view for returned items. Defaults to summary.",
        )],
    ),
    (
        "CoreHydrateRequest",
        &[(
            "view",
            "Optional projection view for the hydrated live entity. Defaults to full.",
        )],
    ),
    (
        "CoreContextPackRequest",
        &[
            (
                "view",
                "Optional field profile for hydrated context-pack fields. Defaults to standard.",
            ),
            (
                "depth",
                "Optional nested edge-depth controls for context-pack assembly.",
            ),
            (
                "policy",
                "Optional nested ranking and projection policy controls.",
            ),
            (
                "time",
                "Optional time-window filters for context-pack retrieval.",
            ),
            (
                "budget",
                "Optional retrieval and serialization budget controls.",
            ),
        ],
    ),
    (
        "ContextPackDepthControls",
        &[
            ("edge_hop", "Edge expansion depth for neighbor hydration."),
            (
                "max_neighbors",
                "Maximum neighbors to hydrate during edge expansion.",
            ),
        ],
    ),
    (
        "ContextPackPolicyControls",
        &[
            ("hydrate", "Whether to include hydrated fields."),
            (
                "include_edges",
                "Whether to include edge records in hydrated entities.",
            ),
            (
                "include_vectors",
                "Whether to include stored vectors when present.",
            ),
            ("view", "Field profile for hydrated fields."),
            (
                "boost_recency_days",
                "Apply recency boost with the supplied half-life in days.",
            ),
            ("boost_salience", "Apply salience boost."),
            ("boost_confidence", "Apply confidence boost."),
            ("boost_contiguity", "Apply contiguity boost."),
        ],
    ),
    (
        "ContextPackTimeControls",
        &[
            (
                "since",
                "Keep entities learned at or after this Unix timestamp.",
            ),
            ("occurred_start", "Occurrence window start, inclusive."),
            ("occurred_end", "Occurrence window end, inclusive."),
            ("learned_start", "Learned-at window start, inclusive."),
            ("learned_end", "Learned-at window end, inclusive."),
        ],
    ),
    (
        "ContextPackRetrievalBudgetControls",
        &[
            ("claims", "Maximum claim entities."),
            ("turns", "Maximum turn entities."),
            ("summaries", "Maximum summary entities."),
            ("facets", "Maximum facet entities."),
            ("other", "Maximum other entities."),
            ("selected_edges", "Edge-walk neighbor selection budget."),
        ],
    ),
    (
        "ContextPackBudgetControls",
        &[
            (
                "token_budget",
                "Serialized token budget for downstream serialized packs.",
            ),
            (
                "max_item_tokens",
                "Per-item token cap for context-pack serialization.",
            ),
            (
                "max_field_chars",
                "Maximum field characters before serialization truncation.",
            ),
            (
                "retrieval",
                "Per-kind retrieval item budgets before final truncation.",
            ),
        ],
    ),
    (
        "CoreListQuery",
        &[(
            "view",
            "Optional projection view for returned entities. Defaults to summary.",
        )],
    ),
    (
        "CoreHydrateResponse",
        &[
            (
                "item",
                "Projected live entity; omitted when the short ref resolves to a deleted entity.",
            ),
            (
                "deletion",
                "Deletion metadata when the short ref resolves to a deleted entity.",
            ),
        ],
    ),
    (
        "CoreHydrateDeletionMetadata",
        &[(
            "reason",
            "Decoded tombstone reason, absent for legacy, malformed, or dangling deletion rows.",
        )],
    ),
    (
        "CoreBatchShortIdHydrateRequest",
        &[(
            "view",
            "Optional projection view for live hydrate results. Defaults to full.",
        )],
    ),
    (
        "CoreBatchShortIdHydrateItem",
        &[
            (
                "result",
                "Live or deleted hydrate payload when the input resolves.",
            ),
            (
                "error",
                "Typed per-input hydrate error for malformed or not-found refs.",
            ),
        ],
    ),
    (
        "CoreShortIdHydrateError",
        &[("field", "Request field that failed validation, when known.")],
    ),
    (
        "CoreContextEdge",
        &[("vad", "Optional edge VAD payload for semantic edges.")],
    ),
    (
        "CoreContextEntity",
        &[
            ("fields", "Hydrated entity fields when requested."),
            ("edges", "Hydrated outbound edges when requested."),
            ("vector", "Stored vector when requested and present."),
        ],
    ),
    (
        "CoreContextPackResponse",
        &[
            (
                "quality",
                "Execution quality projected from the engine's shared report: full, degraded, or passthrough.",
            ),
            (
                "degradation",
                "Observed reasons for degraded execution; absent when none were recorded.",
            ),
            (
                "confidenceAdjustment",
                "Pinned presentation confidence adjustment for the execution tier: 0, -0.15, or -0.35.",
            ),
            (
                "empty",
                "Structured empty-result context when no entities surface.",
            ),
            ("state", "Typed missing-data or low-confidence state."),
            (
                "evidence",
                "Retrieval telemetry evidence and score breakdown.",
            ),
        ],
    ),
    (
        "CoreContextPackRequest",
        &[(
            "interlocutors",
            "Optional interlocutor presence controls (OF-365 ILD-1).",
        )],
    ),
    (
        "CoreContextPackResponse",
        &[
            (
                "interlocutors",
                "Resolved per-speaker interlocutor stamps when an interlocutors block was supplied or the auth is narrowed (scoped or principal_ref-bound).",
            ),
            (
                "disclosure",
                "Disclosure block for the clamp applied to this assembly; present under the same rule as interlocutors.",
            ),
        ],
    ),
    (
        "ContextBoardMemoriesBudget",
        &[
            ("claims", "Claim row cap."),
            ("turns", "Turn/message row cap."),
            ("summaries", "Summary row cap."),
            ("facets", "Facet row cap."),
            ("companions", "Companion-register row cap."),
            ("other", "Row cap for all other entity types."),
        ],
    ),
    (
        "ContextBoardCompanionAssembly",
        &[
            (
                "caller",
                "Effective caller/session identity used for the MEMORIES section.",
            ),
            (
                "person_ref",
                "Optional person entity id for companion-aware assembly metadata.",
            ),
            (
                "persona_ref",
                "Optional persona entity id for companion-aware assembly metadata.",
            ),
        ],
    ),
    (
        "ContextBoardMemoryRow",
        &[
            (
                "row_index",
                "Zero-based index after stable sorting and slot-budget filtering.",
            ),
            ("slot", "Budget slot that owns this row."),
            (
                "source",
                "Whether the row came from primary results or neighbors.",
            ),
            ("id", "Hex entity id."),
            ("short_id", "Short id used for compact display."),
            (
                "content_hash",
                "One-byte content hash as two lowercase hex digits.",
            ),
            ("entity_type", "Numeric entity type byte."),
            (
                "asset_ref",
                "Short ref for ASSET and ASSET_TEXT rows. Consumers pass this to the core hydrate resolver.",
            ),
            ("score", "Retrieval score."),
        ],
    ),
    (
        "ContextBoardMemories",
        &[
            ("version", "Section format version."),
            ("budget", "Applied per-slot row budget."),
            ("rows", "Stable MEMORIES rows."),
            (
                "companion",
                "Companion assembly metadata when companion controls are present.",
            ),
        ],
    ),
    (
        "ContextBoardMemoriesCursor",
        &[
            ("session_id", "Effective session id."),
            ("revision", "Monotonic cursor revision for this session."),
            (
                "query_count",
                "Number of context-pack queries observed for this session.",
            ),
            (
                "last_retrieval_run_id",
                "Last persisted retrieval telemetry run id, when available.",
            ),
            (
                "last_result_ids",
                "Bounded list of most recent context-pack result ids for this session.",
            ),
        ],
    ),
    (
        "ContextBoardRequest",
        &[
            (
                "retrieval",
                "Retrieval for this turn. When present the shared context-pack pipeline runs, its MEMORIES projection and pack ride the response, and the cursor advances.",
            ),
            (
                "memories",
                "MEMORIES section controls: whether to project it and the per-slot row caps.",
            ),
            (
                "session",
                "Session controls: the session id that carries the cursor across calls.",
            ),
            (
                "companion",
                "Companion scope that influences MEMORIES assembly.",
            ),
        ],
    ),
    (
        "ContextBoardResponse",
        &[
            (
                "session",
                "Session prefix: API level, entity counts, latest activity.",
            ),
            (
                "notifications",
                "Pending notifications scoped to the caller and not yet surfaced.",
            ),
            (
                "unprocessed",
                "Work items that still need caller-side processing.",
            ),
            ("budget", "Token meter snapshot."),
            (
                "cursor",
                "The caller's MEMORIES cursor: advanced when retrieval ran, otherwise current.",
            ),
            (
                "memories",
                "This turn's MEMORIES section; absent when retrieval was skipped or disabled.",
            ),
            (
                "pack",
                "The context pack retrieval produced; absent when retrieval was skipped.",
            ),
        ],
    ),
    (
        "ContextBoardSession",
        &[
            ("api_version", "Stable API level string."),
            (
                "counts",
                "Live entity counts keyed by numeric entity type; zero counts are omitted.",
            ),
            (
                "last_activity",
                "Latest learned-at timestamp across agent-visible entities.",
            ),
        ],
    ),
    (
        "ContextBoardNotification",
        &[
            ("id", "Hex notification entity id."),
            ("learned_at", "Learned-at timestamp of the notification."),
            ("body", "Decoded notification body."),
        ],
    ),
    (
        "ContextBoardUnprocessedItem",
        &[
            ("id", "Hex entity id."),
            ("entity_type", "Numeric entity type byte."),
            ("learned_at", "Learned-at timestamp of the item."),
            ("body", "Decoded item body."),
        ],
    ),
    (
        "ContextBoardBudget",
        &[
            ("tokens_used", "Tokens consumed so far."),
            ("tokens_limit", "Token limit for the session."),
            (
                "tokens_remaining",
                "Saturated tokens_limit minus tokens_used.",
            ),
        ],
    ),
    (
        "ContextBoardMemoriesControls",
        &[
            (
                "enabled",
                "Whether to project the MEMORIES section. Defaults to true.",
            ),
            ("slots", "Exact per-slot row caps for the MEMORIES section."),
        ],
    ),
    (
        "ContextBoardMemoriesSlotControls",
        &[
            ("claims", "Claim row cap."),
            ("turns", "Turn/message row cap."),
            ("summaries", "Summary row cap."),
            ("facets", "Facet row cap."),
            ("companions", "Companion-register row cap."),
            (
                "other",
                "Row cap for all other entity types; defaults to the retrieval budget's other cap minus companions.",
            ),
        ],
    ),
    (
        "ContextBoardSessionControls",
        &[(
            "session_id",
            "Stable session key that carries the MEMORIES cursor across calls. Defaults to the caller's own identity.",
        )],
    ),
    (
        "ContextBoardCompanionControls",
        &[
            (
                "person_ref",
                "Optional person entity id (32 hex) or opaque person label.",
            ),
            (
                "persona_ref",
                "Optional persona entity id (32 hex) or opaque persona label.",
            ),
            (
                "expression",
                "Requested expression register: professional, warm, or unrestricted.",
            ),
        ],
    ),
    (
        "CoreContextPackState",
        &[
            ("kind", "Stable state discriminator."),
            ("reason", "Empty-result reason when no entities surfaced."),
            ("total_in_scope", "Total records in scope when known."),
            ("hint", "Caller-facing hint from the retrieval layer."),
        ],
    ),
    (
        "CoreContextPackEvidence",
        &[
            (
                "telemetry_persisted",
                "Whether the retrieval telemetry row was finalized.",
            ),
            (
                "retrieval_run_id",
                "Retrieval telemetry run id when persistence succeeded.",
            ),
            ("result_ids", "Surfaced result ids recorded in telemetry."),
            ("scores", "Final score evidence recorded in telemetry."),
        ],
    ),
    (
        "CoreContextPackScoreEvidence",
        &[
            ("result_id", "Hex entity id."),
            ("final_rank", "Final rank after context-pack hydration."),
            ("final_score", "Final fused score."),
            (
                "access_factor",
                "Read-side access factor applied to the fused score, when available.",
            ),
            ("components", "Signal-level score components."),
        ],
    ),
    (
        "CoreContextPackScoreComponent",
        &[
            ("signal", "Retrieval signal name."),
            ("rank", "Rank within the signal."),
            ("score", "Raw signal score."),
        ],
    ),
    (
        "CompanionRegisterSubjectPayload",
        &[(
            "relationship_ref",
            "Source and target entity pair for relationship records.",
        )],
    ),
    (
        "CompanionRegisterRecordPayload",
        &[
            (
                "scope",
                "Visibility and privacy scope for this register record.",
            ),
            (
                "subject",
                "Persona or relationship subject for this register record.",
            ),
            ("provenance", "Provenance stamp for this register record."),
        ],
    ),
    (
        "CompanionRegisterCreateRecordRequest",
        &[(
            "record",
            "Typed companion register record envelope to create.",
        )],
    ),
    (
        "CompanionRegisterUpdateRecordRequest",
        &[(
            "record",
            "Replacement record envelope; scope and subject must match the existing record.",
        )],
    ),
    (
        "CompanionRegisterRecordResponse",
        &[("record", "Typed companion register record envelope.")],
    ),
];

pub(crate) fn fill_schema_description_gaps(spec: &mut Value) {
    for (schema, properties) in PROPERTY_DESCRIPTIONS {
        for (property, description) in *properties {
            set_schema_property_description(spec, schema, property, description);
        }
    }
}
