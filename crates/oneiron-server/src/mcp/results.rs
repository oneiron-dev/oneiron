//! MCP result envelopes: metadata, board keyframes, and setup payloads.

use super::actors::McpConnectorScope;
use super::endpoint_args::McpCacheHint;
use super::paging::{
    MCP_PAGE_CURSOR_INVALID_CODE, McpPageBudget, McpRetrievalHealth, clamp_foreign_cache_ttl_ms,
};
use super::surface::{
    MCP_EXECUTE_CODE_UNAVAILABLE_CODE, MCP_RESULT_CACHE_SCOPE, MCP_RESULT_META_SCHEMA_VERSION,
    MCP_SETUP_INSTRUCTIONS, MCP_VERB_GRAMMAR_SCHEMA_VERSION, McpGeneratedVerbTool,
    McpSurfaceConstructionError, McpSurfaceMode, generated_verb_tools,
};
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
#[must_use]
pub fn mcp_recovery_suggestions(error_code: &str) -> Vec<String> {
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
            "send the actor metadata bound to this credential",
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
        "verb_dispatch_failed" => {
            &["re-read the board with board.refresh and retry against the current epoch"]
        }
        "mcp_verb_not_bound" => &[
            "this credential is bound to a narrower verb set than the endpoint lists",
            "ask the vault owner to widen the connector's bound verbs",
        ],
        "mcp_scope_refused" => &[
            "this credential is narrowed to one world and facet; the target is outside it",
            "call setup_oneiron to read the effective scope back",
        ],
        "code_host_unbound" => &[
            "this server has no execute_code host bound; nothing ran",
            "ask the vault owner to bind a sandbox/REPL provider, or use the tool-first endpoint",
        ],
        MCP_EXECUTE_CODE_UNAVAILABLE_CODE => &[
            "this release does not ship execute_code; no run was created and none can be resumed",
            "call setup_oneiron for the verb grammar and run the verbs on the tool-first endpoint",
        ],
        MCP_PAGE_CURSOR_INVALID_CODE => &[
            "page cursors are bound to one connector, tool, argument set, and board snapshot",
            "re-request page one with the same arguments and follow its fresh cursor",
        ],
        "code_run_binding_failed" | "code_run_failed" => &[
            "retry with the SAME run_ref to re-enter the durable run",
            "report the run_ref and request id to the vault owner",
        ],
        _ => &["retry once, then report the error_code and request id to the vault owner"],
    };
    suggestions.iter().copied().map(String::from).collect()
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
