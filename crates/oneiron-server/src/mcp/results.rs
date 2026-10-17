//! MCP result envelopes: metadata, board keyframes, and setup payloads.

use super::actors::McpConnectorScope;
use super::endpoint_args::McpCacheHint;
use super::paging::{
    MCP_PAGE_CURSOR_INVALID_CODE, McpPageBudget, McpRetrievalHealth, clamp_foreign_cache_ttl_ms,
};
use super::surface::{
    MCP_CODE_HOST_UNBOUND_CODE, MCP_RESULT_CACHE_SCOPE, MCP_RESULT_META_SCHEMA_VERSION,
    MCP_SETUP_INSTRUCTIONS, MCP_VERB_GRAMMAR_SCHEMA_VERSION, McpGeneratedVerbTool,
    McpSurfaceConstructionError, McpSurfaceMode, generated_verb_tools,
};
use crate::server::LiveRunRefusal;
use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, BoardRenderMetadata, BoardSection,
};
use serde_json::Value;
use serde_json::json;

/// The closed metadata envelope every actor-derived result carries.
#[derive(Clone, Debug, PartialEq)]
pub struct McpResultMetadata {
    pub request_id: String,
    pub surface_mode: McpSurfaceMode,
    pub effective_scope: McpConnectorScope,
    pub retrieval_health: McpRetrievalHealth,
    pub page: McpPageBudget,
    pub help: Vec<String>,
    pub cache_ttl_ms: u64,
}

impl McpResultMetadata {
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        surface_mode: McpSurfaceMode,
        effective_scope: McpConnectorScope,
        retrieval_health: McpRetrievalHealth,
        page: McpPageBudget,
        help: Vec<String>,
        cache: Option<McpCacheHint>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            surface_mode,
            effective_scope,
            retrieval_health,
            page,
            help,
            cache_ttl_ms: clamp_foreign_cache_ttl_ms(cache.and_then(|hint| hint.ttl_ms)),
        }
    }

    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "schema_version": MCP_RESULT_META_SCHEMA_VERSION,
            "request_id": self.request_id,
            "surface_mode": self.surface_mode.as_str(),
            "effective_scope": mcp_effective_scope_value(&self.effective_scope),
            "retrieval_health": self.retrieval_health.as_str(),
            "end": self.page.end().as_str(),
            "page": self.page.to_value(),
            "help": self.help,
            "ttlMs": self.cache_ttl_ms,
            "cacheScope": MCP_RESULT_CACHE_SCOPE,
        })
    }
}

/// The effective scope a result was produced under.
#[must_use]
pub fn mcp_effective_scope_value(scope: &McpConnectorScope) -> Value {
    json!({
        "world_ref": scope.world_ref.map(|id| id.to_hex()),
        "facet_ref": scope.facet_ref.map(|id| id.to_hex()),
    })
}

/// A short, stable scope label for the board header.
#[must_use]
pub fn mcp_effective_scope_label(scope: &McpConnectorScope) -> String {
    match (scope.world_ref, scope.facet_ref) {
        (None, None) => "VaultWide".to_owned(),
        (world, facet) => format!(
            "Scoped(world={}, facet={})",
            world.map_or_else(|| "*".to_owned(), |id| id.to_hex()),
            facet.map_or_else(|| "*".to_owned(), |id| id.to_hex()),
        ),
    }
}

/// The recovery suggestions that travel with one structured error code.
///
/// Closed mapping with an explicit default arm, so a new refusal cannot ship a
/// bare code with nothing a caller can act on.
///
/// A live-run refusal of `invoke_action` (OF-181) carries the suggestion its
/// HTTP door states, `LiveRunRefusal::suggestion`, after the arm's own. Only
/// `code_run_busy` has an arm of its own: it is also `execute_code`'s
/// refusal, so that door's suggestions come first.
#[must_use]
pub fn mcp_recovery_suggestions(error_code: &str) -> Vec<String> {
    let live_run = LiveRunRefusal::from_code(error_code).map(LiveRunRefusal::suggestion);
    let suggestions: &[&str] = match error_code {
        "unknown_tool" => &[
            "call tools/list on this endpoint and use a name it registered",
            "a tool registered on the other endpoint is not callable here",
        ],
        "tool_args_invalid" => &[
            "re-read this tool's inputSchema from tools/list",
            "remove fields the named verb does not accept",
        ],
        "mcp_actor_mismatch" => &[
            "omit actor: the call runs as the credential's own actor",
            "call setup_oneiron to read the effective scope back",
        ],
        "mcp_auth_required"
        | "mcp_credential_unknown"
        | "mcp_credential_expired"
        | "mcp_credential_revoked" => &[
            "present a registered MCP connector credential",
            "ask the vault owner to re-register or renew this connector",
        ],
        "mcp_actor_ceiling_missing" => {
            &["ask the vault owner to add a Gate actor ceiling row for this actor"]
        }
        "scoped_mcp_grant_required" => &[
            "name a live scoped-MCP grant in consent.approval_ref",
            "ask the vault owner to widen or re-issue the grant",
        ],
        "board_render_failed" => &["retry setup_oneiron with a smaller board_budget_tok"],
        "budget_spent" => &[
            "recall at medium, which makes no model call",
            "ask the vault owner to raise the line the call spends on",
        ],
        "model_unavailable" => &[
            "recall at medium, which needs no reranker",
            "ask the vault owner to check the model route in [models]",
        ],
        "identity_unsettled" => &[
            "call self.identity.settle with the person's name and this effect, then act again",
            "if it answers needs_person, wait for the person's choice on the card before acting",
        ],
        "verb_dispatch_failed" => {
            &["re-read the board with self.focus.refresh and retry against the current epoch"]
        }
        "payload_too_large" => &["shorten the field to at most max_bytes bytes and retry"],
        "mcp_verb_not_bound" => &[
            "this credential is bound to a narrower verb set than the endpoint lists",
            "ask the vault owner to widen the connector's bound verbs",
        ],
        "mcp_scope_refused" => &[
            "this credential is narrowed to one world and facet; the target is outside it",
            "call setup_oneiron to read the effective scope back",
        ],
        MCP_CODE_HOST_UNBOUND_CODE => &[
            "this server has no verified execute_code host bound; no run was created",
            "ask the vault owner to bind McpQuickJsProvider with a backend and budget lease",
            "use setup_oneiron and the tool-first verbs while execution is unconfigured",
        ],
        MCP_PAGE_CURSOR_INVALID_CODE => &[
            "page cursors are bound to one connector, tool, argument set, and board snapshot",
            "re-request page one with the same arguments and follow its fresh cursor",
        ],
        // Also a busy live run's code; its own suggestion follows these.
        "code_run_busy" => &[
            "this run is still active; no second worker was started",
            "retry later with the SAME run_ref and task",
        ],
        "code_run_waited_out" => &[
            "this run waited its whole deadline for a turn among the runs ahead of it; no run was started",
            "retry with the same run_ref; the server's code_mode.max_runs row has asked whether everything is okay",
        ],
        "code_run_binding_failed" | "code_run_failed" => &[
            "retry with the SAME run_ref to re-enter the durable run",
            "report the run_ref and request id to the vault owner",
        ],
        // Every other live-run refusal: its own suggestion alone, below.
        _ if live_run.is_some() => &[],
        _ => &["retry once, then report the error_code and request id to the vault owner"],
    };
    suggestions
        .iter()
        .copied()
        .chain(live_run)
        .map(String::from)
        .collect()
}

/// The board keyframe half of `setup_oneiron`, with the engine's render
/// metadata carried through losslessly.
#[derive(Clone, Debug, PartialEq)]
pub struct McpBoardKeyframe {
    pub epoch: u64,
    pub text: String,
    pub metadata: BoardRenderMetadata,
}

impl McpBoardKeyframe {
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "keyframe": self.text,
            "render": {
                "budget_tok": self.metadata.budget_tok,
                "budget_source": board_budget_source_value(&self.metadata),
                "explicit_override_tok": self.metadata.explicit_override_tok,
                "rendered_tok": self.metadata.rendered_tok,
                "floor_exceeds_cap": self.metadata.floor_exceeds_cap,
            },
        })
    }
}

fn board_budget_source_value(metadata: &BoardRenderMetadata) -> Value {
    match metadata.budget_source {
        oneiron::context_board::BoardBudgetSource::AdaptiveMin {
            caller_limit_tok,
            harness_default_tok,
        } => json!({
            "kind": "adaptive_min",
            "caller_limit_tok": caller_limit_tok,
            "harness_default_tok": harness_default_tok,
        }),
        oneiron::context_board::BoardBudgetSource::ExplicitOverride {
            requested_tok,
            caller_limit_tok,
            harness_default_tok,
        } => json!({
            "kind": "explicit_override",
            "requested_tok": requested_tok,
            "caller_limit_tok": caller_limit_tok,
            "harness_default_tok": harness_default_tok,
        }),
    }
}

/// The three parts `setup_oneiron` returns in ONE result.
#[derive(Clone, Debug, PartialEq)]
pub struct McpSetupPayload {
    pub board: McpBoardKeyframe,
    pub verb_grammar: Vec<McpGeneratedVerbTool>,
    pub instructions: &'static str,
}

impl McpSetupPayload {
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "board": self.board.to_value(),
            "verb_grammar": {
                "schema_version": MCP_VERB_GRAMMAR_SCHEMA_VERSION,
                "verbs": self
                    .verb_grammar
                    .iter()
                    .map(|verb| json!({
                        "name": verb.name,
                        "family": verb.family.as_str(),
                        "verb": verb.verb,
                        "tool_first_tool": verb.name,
                    }))
                    .collect::<Vec<_>>(),
            },
            "instructions": self.instructions,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpSetupPayloadError {
    #[error("board keyframe could not be rendered: {0}")]
    BoardRender(#[from] oneiron::context_board::BoardFrameError),
    #[error("verb grammar could not be generated: {0}")]
    VerbGrammar(#[from] McpSurfaceConstructionError),
}

/// Assembles the whole `setup_oneiron` result from typed board state.
///
/// The gateway supplies vault-derived sections; a test supplies fixture
/// sections. Both reach the SAME assembly, so what an oracle observes is what
/// a client receives.
///
/// # Errors
///
/// Propagates the engine's own render refusal and the generated-projection
/// refusal; neither is flattened into a partial payload.
pub fn mcp_setup_payload(
    header: &BoardBlockHeader,
    sections: &[BoardSection],
    budget: BoardBudgetRequest,
) -> Result<McpSetupPayload, McpSetupPayloadError> {
    let render = oneiron::board_verb::render_current_keyframe(header, sections, budget)?;
    Ok(McpSetupPayload {
        board: McpBoardKeyframe {
            epoch: header.epoch,
            text: render.text,
            metadata: render.metadata,
        },
        verb_grammar: generated_verb_tools()?,
        instructions: MCP_SETUP_INSTRUCTIONS,
    })
}

/// The always-present pinned VERBS section: the grammar restated as board
/// state, so a resident board and a setup result never disagree.
///
/// # Errors
///
/// Propagates the engine's section validation.
pub fn mcp_verb_board_section(
    verbs: &[McpGeneratedVerbTool],
) -> Result<BoardSection, oneiron::context_board::BoardFrameError> {
    BoardSection::new(
        "VERBS",
        verbs.iter().map(|verb| verb.name.to_owned()).collect(),
        Vec::new(),
        Vec::new(),
        oneiron::context_board::SectionPolicy {
            pinned: true,
            shed_rank: None,
        },
    )
}

/// States a `tools/call` result's call receipt (OF-538) in its metadata
/// envelope, `structuredContent.meta`: `receipt_ref`, or `receipt_ref: null`
/// with `no_record: true` for a call inside an anonymous off-record session.
/// The text content that restates `structuredContent` as canonical JSON is
/// restated again, so the two still agree byte for byte.
pub(crate) fn mcp_stamp_call_receipt(
    result: &mut Value,
    stamp: &crate::api::call_receipt::CallStamp,
) {
    let Some(structured) = result.get_mut("structuredContent") else {
        return;
    };
    let before = super::paging::mcp_canonical_json(structured);
    let Some(object) = structured.as_object_mut() else {
        return;
    };
    let meta = object.entry("meta").or_insert_with(|| json!({}));
    let Some(meta) = meta.as_object_mut() else {
        return;
    };
    stamp.stamp_json(meta);
    let after = super::paging::mcp_canonical_json(structured);
    if let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) {
        for item in content {
            if item.get("text").and_then(Value::as_str) == Some(before.as_str())
                && let Some(item) = item.as_object_mut()
            {
                item.insert("text".to_owned(), Value::String(after.clone()));
            }
        }
    }
}
