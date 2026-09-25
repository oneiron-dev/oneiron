//! Endpoint tool argument envelopes: setup, execute-code, paging, and verbs.

use super::args::{McpActorMetadata, McpConsentMetadata};
use super::codec::deserialize_optional_u32;
use super::codec::deserialize_optional_u64;
use super::codec::{McpToolArguments, schema_normalized_arguments};
use super::surface::{
    MCP_BOARD_BUDGET_TOK, MCP_EXECUTE_CODE_TOOL, MCP_SETUP_TOOL, McpEndpointTool,
    McpGeneratedVerbTool,
};
use super::tool_catalog::{McpToolValidationError, McpValidatedToolArgs};
use super::validators::{
    validate_nonblank, validate_optional_entity_ref, validate_optional_nonblank,
    validate_schema_version,
};
use oneiron::context_board::{BoardBudgetRequest, SubscriptionScope};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A caller's cache wish. It can only ever NARROW this endpoint's policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpCacheHint {
    /// Draft 2020-12 `type: integer` admits integral JSON number spellings such
    /// as `1.0` and `1e0`. Decode through the original JSON number text so this
    /// door has the same domain as the advertised schema without rounding a
    /// value near the `u64` ceiling.
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub ttl_ms: Option<u64>,
}

/// A caller's page wish. The granted budget is the adaptive `min` with the
/// server ceiling, unless an explicit forceful override is asked for and
/// RECORDED.
///
/// ONE-1704 M6: `cursor` is a real INPUT of the same closed
/// `deny_unknown_fields` object the schema advertises, so a `More` result's
/// successor handle can actually be presented back. It is opaque and BOUND —
/// see [`McpConnectorActorRegistry::mint_page_cursor`](crate::mcp::McpConnectorActorRegistry::mint_page_cursor) — never an offset a
/// caller could arithmetic its way past the budget with.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpPageRequest {
    #[serde(default, deserialize_with = "deserialize_optional_u32")]
    pub limit: Option<u32>,
    /// A gate, not a wall: an override may exceed the harness default, and the
    /// response metadata says it did.
    #[serde(default)]
    pub forceful_override: bool,
    /// The opaque continuation handle a previous `More` result minted for THIS
    /// connector, tool, arguments, and snapshot.
    #[serde(default)]
    pub cursor: Option<String>,
}

impl McpPageRequest {
    /// The advertised schema pins `limit` at `minimum: 1` and `cursor` at a
    /// nonblank string; this is the runtime door that agrees with both. A zero
    /// page is a refusal, never "unset", and a blank cursor is a refusal,
    /// never "page one".
    pub(super) fn validate(&self, tool: &'static str) -> Result<(), McpToolValidationError> {
        if self.limit == Some(0) {
            return Err(McpToolValidationError::field(
                tool,
                "page.limit",
                "must be greater than zero",
            ));
        }
        validate_optional_nonblank(tool, "page.cursor", self.cursor.as_deref())?;
        Ok(())
    }

    /// Validates an OPTIONAL page wish at one runtime door.
    ///
    /// # Errors
    ///
    /// Returns [`McpToolValidationError`] when the caller asked for a
    /// zero-sized page, which the advertised `minimum: 1` already forbids, or
    /// presented a blank continuation handle.
    pub fn validate_optional(
        page: Option<&Self>,
        tool: &'static str,
    ) -> Result<(), McpToolValidationError> {
        match page {
            Some(page) => page.validate(tool),
            None => Ok(()),
        }
    }
}

/// `setup_oneiron` arguments.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpSetupToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    /// Caller-side board budget. Narrows the harness default, never widens it.
    #[serde(default, deserialize_with = "deserialize_optional_u32")]
    pub board_budget_tok: Option<u32>,
    #[serde(default)]
    pub page: Option<McpPageRequest>,
    #[serde(default)]
    pub cache: Option<McpCacheHint>,
}

impl McpSetupToolArgs {
    fn validate(&self) -> Result<(), McpToolValidationError> {
        validate_schema_version(MCP_SETUP_TOOL, &self.schema_version)?;
        self.actor.validate(MCP_SETUP_TOOL)?;
        self.consent.validate(MCP_SETUP_TOOL)?;
        if self.board_budget_tok == Some(0) {
            return Err(McpToolValidationError::field(
                MCP_SETUP_TOOL,
                "board_budget_tok",
                "must be greater than zero",
            ));
        }
        McpPageRequest::validate_optional(self.page.as_ref(), MCP_SETUP_TOOL)?;
        Ok(())
    }

    /// The adaptive board budget request this call resolves to.
    #[must_use]
    pub fn board_budget_request(&self) -> BoardBudgetRequest {
        BoardBudgetRequest {
            harness_default_tok: MCP_BOARD_BUDGET_TOK,
            caller_limit_tok: self.board_budget_tok.map(|limit| limit as usize),
            explicit_override_tok: None,
        }
    }
}

/// `execute_code` arguments: ONE durable REPL run against the injected host.
///
/// There is no gateway-side program grammar any more. The task text is what
/// the bound sandbox/REPL provider carries out through `EngineNativeExecutor`,
/// and `run_ref` is the caller's handle onto the DURABLE run: the same handle
/// under the same connector scope re-enters the same persisted run.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpExecuteCodeToolArgs {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    pub run_ref: String,
    pub task: String,
    #[serde(default)]
    pub page: Option<McpPageRequest>,
    #[serde(default)]
    pub cache: Option<McpCacheHint>,
}

/// Hard ceiling on one `execute_code` task statement.
pub const MCP_CODE_TASK_MAX_CHARS: usize = 8_192;

impl McpExecuteCodeToolArgs {
    fn validate(&self) -> Result<(), McpToolValidationError> {
        validate_schema_version(MCP_EXECUTE_CODE_TOOL, &self.schema_version)?;
        self.actor.validate(MCP_EXECUTE_CODE_TOOL)?;
        self.consent.validate(MCP_EXECUTE_CODE_TOOL)?;
        validate_nonblank(MCP_EXECUTE_CODE_TOOL, "run_ref", &self.run_ref)?;
        validate_nonblank(MCP_EXECUTE_CODE_TOOL, "task", &self.task)?;
        if self.task.chars().count() > MCP_CODE_TASK_MAX_CHARS {
            return Err(McpToolValidationError::field(
                MCP_EXECUTE_CODE_TOOL,
                "task",
                format!("must be at most {MCP_CODE_TASK_MAX_CHARS} characters"),
            ));
        }
        McpPageRequest::validate_optional(self.page.as_ref(), MCP_EXECUTE_CODE_TOOL)?;
        Ok(())
    }
}

/// The closed argument envelope every generated verb tool shares.
///
/// One struct, per-binding admission: a field that belongs to another verb is
/// a validation failure, not an ignored extra — the same discipline the edit
/// verbs already use.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpVerbArguments {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub frame_epoch: Option<u64>,
    #[serde(default)]
    pub scopes: Option<Vec<SubscriptionScope>>,
    #[serde(default)]
    pub task_ref: Option<String>,
    #[serde(default)]
    pub room_ref: Option<String>,
    #[serde(default)]
    pub turn_ref: Option<String>,
    #[serde(default)]
    pub spec: Option<Value>,
    /// One native request. A present JSON null is distinct from omission for
    /// the runtime-reserved methods, whose native payload is opaque JSON.
    #[serde(default, deserialize_with = "deserialize_present_request")]
    pub request: Option<Value>,
    #[serde(default)]
    pub label: Option<String>,
}

impl McpVerbArguments {
    fn present_fields(&self) -> [(&'static str, bool); 9] {
        [
            ("key", self.key.is_some()),
            ("frame_epoch", self.frame_epoch.is_some()),
            ("scopes", self.scopes.is_some()),
            ("task_ref", self.task_ref.is_some()),
            ("room_ref", self.room_ref.is_some()),
            ("turn_ref", self.turn_ref.is_some()),
            ("spec", self.spec.is_some()),
            ("request", self.request.is_some()),
            ("label", self.label.is_some()),
        ]
    }

    fn validate(
        &self,
        tool: &'static str,
        verb: McpGeneratedVerbTool,
    ) -> Result<(), McpToolValidationError> {
        let allowed = verb.argument_fields();
        for (field, present) in self.present_fields() {
            if present && !allowed.contains(&field) {
                return Err(McpToolValidationError::field(
                    tool,
                    field,
                    "is not valid for this verb",
                ));
            }
        }
        for (field, present) in self.present_fields() {
            if !present && verb.required_fields().contains(&field) {
                return Err(McpToolValidationError::field(tool, field, "is required"));
            }
        }
        validate_optional_nonblank(tool, "arguments.key", self.key.as_deref())?;
        // The WRITER's bound, applied before any persistence: a label the
        // engine's board row ceiling cannot render is refused here rather than
        // stored and then made to reject the whole TASKS section on every later
        // render (ONE-1704 repair).
        if let Some(label) = self.label.as_deref() {
            oneiron::task_verb::check_task_label(label).map_err(|error| {
                McpToolValidationError::field(tool, "arguments.label", error.message)
            })?;
        }
        validate_optional_entity_ref(tool, "arguments.task_ref", self.task_ref.as_deref())?;
        validate_optional_entity_ref(tool, "arguments.room_ref", self.room_ref.as_deref())?;
        validate_optional_entity_ref(tool, "arguments.turn_ref", self.turn_ref.as_deref())?;
        if self.scopes.as_ref().is_some_and(Vec::is_empty) {
            return Err(McpToolValidationError::field(
                tool,
                "arguments.scopes",
                "must name at least one subscription scope",
            ));
        }
        Ok(())
    }
}

/// The wire payload of one generated verb tool call.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpVerbToolPayload {
    pub schema_version: String,
    pub actor: McpActorMetadata,
    pub consent: McpConsentMetadata,
    #[serde(default)]
    pub arguments: McpVerbArguments,
    #[serde(default)]
    pub page: Option<McpPageRequest>,
    #[serde(default)]
    pub cache: Option<McpCacheHint>,
}

/// A validated generated-verb call: the tool it resolved to plus its payload.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct McpVerbToolArgs {
    #[serde(skip)]
    pub tool: McpGeneratedVerbTool,
    pub payload: McpVerbToolPayload,
}

/// Validates arguments for a tool THIS endpoint registered.
///
/// # Errors
///
/// Returns [`McpToolValidationError`] when the arguments do not decode against
/// the tool's closed schema or violate its per-verb admission.
pub fn validate_mcp_endpoint_tool_args(
    tool: McpEndpointTool,
    args: impl Into<McpToolArguments>,
) -> Result<McpValidatedToolArgs, McpToolValidationError> {
    let args = args.into();
    // The tool's OWN advertised schema is what says where an integer lives, so
    // the raw number text is judged against the very document `tools/list`
    // published for this name (ONE-1704 repair).
    let schema = tool.input_schema();
    match tool {
        McpEndpointTool::Setup => {
            let parsed = decode_endpoint_args::<McpSetupToolArgs>(MCP_SETUP_TOOL, &schema, args)?;
            parsed.validate()?;
            Ok(McpValidatedToolArgs::Setup(Box::new(parsed)))
        }
        McpEndpointTool::ExecuteCode => {
            let parsed = decode_endpoint_args::<McpExecuteCodeToolArgs>(
                MCP_EXECUTE_CODE_TOOL,
                &schema,
                args,
            )?;
            parsed.validate()?;
            Ok(McpValidatedToolArgs::ExecuteCode(Box::new(parsed)))
        }
        McpEndpointTool::Verb(tool) => {
            let payload = decode_endpoint_args::<McpVerbToolPayload>(tool.name, &schema, args)?;
            validate_schema_version(tool.name, &payload.schema_version)?;
            payload.actor.validate(tool.name)?;
            payload.consent.validate(tool.name)?;
            payload.arguments.validate(tool.name, tool)?;
            McpPageRequest::validate_optional(payload.page.as_ref(), tool.name)?;
            Ok(McpValidatedToolArgs::Verb(Box::new(McpVerbToolArgs {
                tool,
                payload,
            })))
        }
    }
}

fn decode_endpoint_args<T: DeserializeOwned>(
    tool: &'static str,
    schema: &Value,
    args: McpToolArguments,
) -> Result<T, McpToolValidationError> {
    let args = schema_normalized_arguments(schema, args)
        .map_err(|message| McpToolValidationError::Decode { tool, message })?;
    serde_json::from_value::<T>(args).map_err(|error| McpToolValidationError::Decode {
        tool,
        message: error.to_string(),
    })
}

fn deserialize_present_request<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
