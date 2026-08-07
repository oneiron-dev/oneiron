use super::CORE_MAX_LIST_LIMIT;
use super::hydrate_short_id_response;
use super::parse_entity_id_param;
use super::parse_short_ref;
use super::unix_seconds_now;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ErrorCode;
use crate::mcp::McpActorClass;
use crate::mcp::McpActorMetadata;
use crate::mcp::McpAskToolArgs;
use crate::mcp::McpConnectorActorResolutionError;
use crate::mcp::McpEditToolArgs;
use crate::mcp::McpEditVerb;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpRoutedAskToolArgs;
use crate::mcp::McpToolName;
use crate::mcp::McpToolValidationError;
use crate::mcp::McpValidatedToolArgs;
use crate::mcp::validate_mcp_tool_args;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::IntoResponse;
use axum::response::Json;
use oneiron::EdgeKind;
use oneiron::ErrorKind;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

pub(crate) const MCP_CREDENTIAL_HEADER: &str = "x-oneiron-mcp-credential";

pub(crate) const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Deserialize)]
pub(crate) struct McpJsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug)]
pub(crate) struct McpGatewayError {
    code: i64,
    kind: &'static str,
    message: String,
    field: Option<String>,
    /// Set only by the stale-write-verb-target refusal (ONE-1936); surfaces as
    /// `error.data.successor_short_id` so a client reads a FIELD instead of
    /// parsing the message.
    successor_short_id: Option<String>,
}

impl McpGatewayError {
    fn new(code: i64, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            field: None,
            successor_short_id: None,
        }
    }

    fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    fn with_successor_short_id(mut self, successor_short_id: impl Into<String>) -> Self {
        self.successor_short_id = Some(successor_short_id.into());
        self
    }
}

pub(crate) async fn mcp_gateway(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    body: Bytes,
) -> impl IntoResponse {
    let raw: Value = match serde_json::from_slice(&body) {
        Ok(raw) => raw,
        Err(error) => {
            return Json(mcp_error_response(
                Value::Null,
                McpGatewayError::new(-32700, "parse_error", error.to_string()),
            ));
        }
    };
    let id = raw.get("id").cloned().unwrap_or(Value::Null);
    let request = match serde_json::from_value::<McpJsonRpcRequest>(raw) {
        Ok(request) => request,
        Err(error) => {
            return Json(mcp_error_response(
                id,
                McpGatewayError::new(-32600, "invalid_request", error.to_string()),
            ));
        }
    };
    let id = request.id.clone().unwrap_or(id);

    let result = handle_mcp_request(&headers, &server, request).await;
    Json(match result {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        Err(error) => mcp_error_response(id, error),
    })
}

pub(crate) async fn handle_mcp_request(
    headers: &HeaderMap,
    server: &Arc<SyncServer>,
    request: McpJsonRpcRequest,
) -> Result<Value, McpGatewayError> {
    if request.jsonrpc != "2.0" {
        return Err(
            McpGatewayError::new(-32600, "invalid_request", "jsonrpc must be \"2.0\"")
                .with_field("jsonrpc"),
        );
    }

    match request.method.as_str() {
        "initialize" => {
            let actor = resolve_mcp_gateway_actor(headers, server).await?;
            Ok(json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {
                    "name": "oneiron",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "tools": { "listChanged": false },
                },
                "instructions": "Oneiron MCP exposes foreign-client tools over the same read and write Gate as the REST core surface. Use tools/list for schemas and tools/call with connector actor metadata matching this authenticated credential.",
                "actor": mcp_actor_result(&actor),
            }))
        }
        "notifications/initialized" => Ok(json!({})),
        "tools/list" => {
            let actor = resolve_mcp_gateway_actor(headers, server).await?;
            Ok(json!({
                "tools": crate::mcp::mcp_tool_schemas(),
                "actor": mcp_actor_result(&actor),
            }))
        }
        "tools/call" => {
            let actor = resolve_mcp_gateway_actor(headers, server).await?;
            let params: McpToolCallParams = mcp_params(request.params, "params")?;
            let tool = McpToolName::from_name(&params.name).ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "unknown_tool",
                    "tool name is not advertised by this Oneiron MCP gateway",
                )
                .with_field("name")
            })?;
            let args = validate_mcp_tool_args(tool, params.arguments)
                .map_err(mcp_tool_validation_error)?;
            ensure_mcp_actor_matches(&args, &actor)?;
            execute_mcp_tool(server, args, &actor)
        }
        _ => Err(McpGatewayError::new(
            -32601,
            "method_not_found",
            format!("unsupported MCP method {}", request.method),
        )
        .with_field("method")),
    }
}

pub(crate) async fn resolve_mcp_gateway_actor(
    headers: &HeaderMap,
    server: &Arc<SyncServer>,
) -> Result<McpResolvedActor, McpGatewayError> {
    let credential = mcp_connector_credential(headers)?;
    let registry = server.mcp_registry.lock().await;
    registry
        .resolve(&credential, unix_seconds_now(), |actor_class, actor_ref| {
            server
                .vault
                .gate_actor_ceiling_exists(actor_class, actor_ref)
                .unwrap_or(false)
        })
        .map_err(mcp_actor_resolution_error)
}

pub(crate) fn mcp_connector_credential(headers: &HeaderMap) -> Result<String, McpGatewayError> {
    if let Some(value) = headers
        .get(MCP_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(value.to_owned());
    }

    let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "missing MCP connector credential",
        ));
    };
    let value = value.trim_start();
    let Some((scheme, credential)) = value.split_once(char::is_whitespace) else {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "Authorization must use Bearer credentials",
        )
        .with_field("authorization"));
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "Authorization must use Bearer credentials",
        )
        .with_field("authorization"));
    }
    let credential = credential.trim();
    if credential.is_empty() {
        return Err(McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "MCP connector credential must not be empty",
        )
        .with_field("authorization"));
    }
    Ok(credential.to_owned())
}

pub(crate) fn mcp_actor_resolution_error(
    error: McpConnectorActorResolutionError,
) -> McpGatewayError {
    let kind = match error {
        McpConnectorActorResolutionError::UnknownCredential => "mcp_credential_unknown",
        McpConnectorActorResolutionError::ExpiredCredential => "mcp_credential_expired",
        McpConnectorActorResolutionError::RevokedCredential => "mcp_credential_revoked",
        McpConnectorActorResolutionError::MissingActorCeiling => "mcp_actor_ceiling_missing",
    };
    McpGatewayError::new(-32001, kind, error.to_string())
}

pub(crate) fn mcp_params<T: DeserializeOwned>(
    params: Option<Value>,
    field: &'static str,
) -> Result<T, McpGatewayError> {
    let params = params.ok_or_else(|| {
        McpGatewayError::new(-32602, "invalid_params", "params are required").with_field(field)
    })?;
    serde_json::from_value(params).map_err(|error| {
        McpGatewayError::new(-32602, "invalid_params", error.to_string()).with_field(field)
    })
}

pub(crate) fn mcp_tool_validation_error(error: McpToolValidationError) -> McpGatewayError {
    match error {
        McpToolValidationError::Decode { tool, message } => McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool} arguments could not be decoded: {message}"),
        ),
        McpToolValidationError::Field {
            tool,
            field,
            message,
        } => McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool}.{field}: {message}"),
        )
        .with_field(field),
    }
}

pub(crate) fn ensure_mcp_actor_matches(
    args: &McpValidatedToolArgs,
    resolved: &McpResolvedActor,
) -> Result<(), McpGatewayError> {
    let actor = mcp_validated_actor(args);
    if actor.actor_ref != resolved.actor_ref.to_hex() {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor_ref must match the authenticated connector actor",
        )
        .with_field("actor.actor_ref"));
    }
    if mcp_actor_class_wire(actor.actor_class) != resolved.gate_actor_class {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor_class must match the authenticated connector actor class",
        )
        .with_field("actor.actor_class"));
    }
    if actor.gate_actor_ref != resolved.gate_actor_ref {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool gate_actor_ref must match the authenticated connector actor",
        )
        .with_field("actor.gate_actor_ref"));
    }
    if mcp_actor_class_wire(actor.gate_actor_class) != resolved.gate_actor_class {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool gate_actor_class must match the authenticated connector actor class",
        )
        .with_field("actor.gate_actor_class"));
    }
    let scope = &resolved.scope;
    if actor.scope.world_ref.as_deref()
        != scope
            .world_ref
            .as_ref()
            .map(oneiron::EntityId::to_hex)
            .as_deref()
    {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor.scope.world_ref must match the authenticated connector scope",
        )
        .with_field("actor.scope.world_ref"));
    }
    if actor.scope.facet_ref.as_deref()
        != scope
            .facet_ref
            .as_ref()
            .map(oneiron::EntityId::to_hex)
            .as_deref()
    {
        return Err(McpGatewayError::new(
            -32602,
            "mcp_actor_mismatch",
            "tool actor.scope.facet_ref must match the authenticated connector scope",
        )
        .with_field("actor.scope.facet_ref"));
    }
    Ok(())
}

pub(crate) fn mcp_validated_actor(args: &McpValidatedToolArgs) -> &McpActorMetadata {
    match args {
        McpValidatedToolArgs::Nav(args) => &args.actor,
        McpValidatedToolArgs::Read(args) => &args.actor,
        McpValidatedToolArgs::Edit(args) => &args.actor,
        McpValidatedToolArgs::Ask(args) => &args.actor,
        McpValidatedToolArgs::RoutedAsk(args) => &args.actor,
        McpValidatedToolArgs::Calendar(args) => &args.actor,
    }
}

pub(crate) fn execute_mcp_tool(
    server: &SyncServer,
    args: McpValidatedToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    match args {
        McpValidatedToolArgs::Nav(args) => execute_mcp_nav(server, args, actor),
        McpValidatedToolArgs::Read(args) => execute_mcp_read(server, args, actor),
        McpValidatedToolArgs::Edit(args) => execute_mcp_edit(server, *args, actor),
        McpValidatedToolArgs::Ask(args) => Ok(mcp_ask_result(args, actor)),
        McpValidatedToolArgs::RoutedAsk(args) => Ok(mcp_routed_ask_result(args, actor)),
        McpValidatedToolArgs::Calendar(args) => execute_mcp_calendar(server, args, actor),
    }
}

/// Dispatches `oneiron.calendar`.
///
/// Every arm goes through [`oneiron::MemoryFacade`] — the calendar dialect owns
/// no vault access of its own, so the actor binding, the scoped-read lane, and
/// the outbound gate are all the engine's, not a second server-side copy. The
/// invite arm in particular reaches the connector only via `schedule_outbound`;
/// there is no direct execution path in this file.
pub(crate) fn execute_mcp_calendar(
    server: &SyncServer,
    args: crate::mcp::McpCalendarToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let op = args.operation.op();
    let facade = server
        .vault
        .memory_facade(actor.actor_ref, actor.actor_class);

    let mut structured = match args.operation {
        crate::mcp::McpCalendarOperation::Read { event_ref } => {
            let item = facade
                .calendar_read(&oneiron::CalendarReadRequest { event_ref })
                .map_err(mcp_facade_error)?;
            json!({ "found": item.is_some(), "item": item })
        }
        crate::mcp::McpCalendarOperation::Search {
            calendars,
            range,
            text,
            limit,
        } => {
            let items = facade
                .calendar_search(&oneiron::CalendarSearchRequest {
                    calendars: calendar_selectors(calendars),
                    range: range.map(|range| oneiron::CalendarRangeDto {
                        start: range.start,
                        end: range.end,
                    }),
                    text,
                    limit: limit.unwrap_or(CORE_MAX_LIST_LIMIT as u32),
                })
                .map_err(mcp_facade_error)?;
            json!({ "count": items.len(), "items": items })
        }
        crate::mcp::McpCalendarOperation::Freebusy { calendars, range } => {
            let intervals = facade
                .calendar_freebusy(
                    &calendar_selectors(calendars),
                    oneiron::TimeRange {
                        start: range.start,
                        end: range.end,
                    },
                )
                .map_err(mcp_facade_error)?;
            json!({ "count": intervals.len(), "intervals": intervals })
        }
        crate::mcp::McpCalendarOperation::Invite {
            method,
            uid,
            sequence,
            ics_blob_ref,
            recipient,
        } => {
            let receipt = facade
                .calendar_invite(&oneiron::CalendarInviteSurfaceInput {
                    method,
                    uid,
                    sequence,
                    ics_blob_ref,
                    recipient,
                })
                .map_err(mcp_facade_error)?;
            json!({ "receipt": receipt })
        }
    };

    if let Some(object) = structured.as_object_mut() {
        object.insert(
            "tool".to_owned(),
            Value::String(McpToolName::Calendar.as_str().to_owned()),
        );
        object.insert("op".to_owned(), Value::String(op.to_owned()));
        object.insert("actor".to_owned(), mcp_actor_result(actor));
    }
    Ok(json!({
        "content": [mcp_text_content(format!("calendar {op} completed"))],
        "structuredContent": structured,
        "isError": false,
    }))
}

fn calendar_selectors(
    selectors: Vec<crate::mcp::McpCalendarSelector>,
) -> Vec<oneiron::CalendarSel> {
    selectors
        .into_iter()
        .map(|selector| oneiron::CalendarSel {
            system: selector.system,
        })
        .collect()
}

/// Maps a typed engine facade error onto the gateway's JSON-RPC vocabulary.
pub(crate) fn mcp_facade_error(error: oneiron::FacadeError) -> McpGatewayError {
    let code = match error.code.as_str() {
        oneiron::FACADE_CODE_NOT_FOUND => -32004,
        oneiron::FACADE_CODE_FORBIDDEN | oneiron::FACADE_CODE_INVALID_STATE => -32020,
        oneiron::FACADE_CODE_INTERNAL => -32603,
        _ => -32602,
    };
    // A facade refusal carrying a successor keeps the same stable kind and
    // typed data the engine-error path emits (ONE-1936) — one vocabulary for
    // one condition, whichever door reported it.
    match error.successor_short_id {
        Some(successor_short_id) => {
            McpGatewayError::new(code, "write_verb_target_stale", error.message)
                .with_successor_short_id(successor_short_id)
        }
        None => McpGatewayError::new(code, "facade_error", error.message),
    }
}

pub(crate) fn execute_mcp_nav(
    server: &SyncServer,
    args: crate::mcp::McpNavToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    let limit = args.limit.unwrap_or(10).min(CORE_MAX_LIST_LIMIT as u32) as usize;
    match args.mode {
        crate::mcp::McpNavMode::Search => {
            let query = args.query.as_deref().ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "oneiron.nav query is required for search mode",
                )
                .with_field("query")
            })?;
            let results = scoped_read
                .search_text(query, limit)
                .map_err(|error| mcp_engine_error("mcp nav search failed", error))?;
            let items = results
                .into_iter()
                .map(|result| {
                    projection::project_search_result(scoped_read.vault(), result, View::Summary)
                        .map_err(|error| mcp_engine_error("mcp nav projection failed", error))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            Ok(json!({
                "content": [mcp_text_content(format!("{} result(s)", items.len()))],
                "structuredContent": {
                    "tool": McpToolName::Nav.as_str(),
                    "mode": "search",
                    "items": items,
                },
                "isError": false,
            }))
        }
        _ => Ok(json!({
            "content": [mcp_text_content("navigation mode accepted")],
            "structuredContent": {
                "tool": McpToolName::Nav.as_str(),
                "mode": format!("{:?}", args.mode).to_ascii_lowercase(),
                "status": "accepted",
            },
            "isError": false,
        })),
    }
}

pub(crate) fn execute_mcp_read(
    server: &SyncServer,
    args: crate::mcp::McpReadToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let scoped_read = mcp_scoped_read(&server.vault, actor)?;
    if let Some(entity_ref) = args.target.entity_ref.as_deref() {
        let id = parse_entity_id_param(entity_ref, "target.entity_ref").map_err(mcp_api_error)?;
        let item = scoped_read
            .get_entity_parts(&id)
            .map_err(|error| mcp_engine_error("mcp read failed", error))?
            .map(|(entity_type, learned_at, body)| {
                projection::project_entity_parts(&id, entity_type, learned_at, &body, View::Full)
            });
        return Ok(json!({
            "content": [mcp_text_content(if item.is_some() { "entity found" } else { "entity not found" })],
            "structuredContent": {
                "tool": McpToolName::Read.as_str(),
                "target": { "entity_ref": entity_ref },
                "found": item.is_some(),
                "item": item,
            },
            "isError": false,
        }));
    }
    if let Some(short_ref) = args.target.short_ref.as_deref() {
        let (short_id, content_hash) = parse_short_ref(short_ref).map_err(mcp_api_error)?;
        let item = hydrate_short_id_response(&scoped_read, short_id, content_hash, View::Full)
            .map_err(mcp_api_error)?;
        return Ok(json!({
            "content": [mcp_text_content(if item.is_some() { "short ref found" } else { "short ref not found" })],
            "structuredContent": {
                "tool": McpToolName::Read.as_str(),
                "target": { "short_ref": short_ref },
                "found": item.is_some(),
                "item": item,
            },
            "isError": false,
        }));
    }
    Ok(json!({
        "content": [mcp_text_content("context pack reference accepted")],
        "structuredContent": {
            "tool": McpToolName::Read.as_str(),
            "target": { "context_pack": args.target.context_pack },
        },
        "isError": false,
    }))
}

pub(crate) fn execute_mcp_edit(
    server: &SyncServer,
    args: McpEditToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    if args.dry_run {
        // A dry run that skipped the guard would report "validated" for an
        // edit the real call is about to refuse. It reports the SAME stale
        // condition and writes nothing (ONE-1936).
        mcp_guard_lifecycle_target(&server.vault, &args)?;
        return Ok(mcp_edit_receipt(
            &args,
            actor,
            None,
            "validated",
            "dry_run",
            "edit validated",
        ));
    }

    match args.verb {
        McpEditVerb::ProposeClaim => execute_mcp_propose_claim(server, &args, actor),
        McpEditVerb::AttestEdgeProvenance
        | McpEditVerb::SupersedeClaim
        | McpEditVerb::RetractClaim
        | McpEditVerb::ProposeEntity
        | McpEditVerb::PostTask
        | McpEditVerb::ReportTask
        | McpEditVerb::ChannelSend => execute_mcp_proposed_control_record(server, &args, actor),
    }
}

pub(crate) fn execute_mcp_propose_claim(
    server: &SyncServer,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let id = mcp_idempotency_entity_id("claim", args, actor);
    if let Some(receipt) = mcp_existing_edit_receipt(
        server,
        args,
        actor,
        id,
        "immediate_proposed_claim",
        "claim replayed",
    )? {
        return Ok(receipt);
    }

    let candidate = mcp_claim_candidate_from_args(args)?;
    let envelope = mcp_write_envelope(args, actor, "immediate_proposed_claim")?;
    let learned_at = unix_seconds_now();
    let occurred = oneiron::TimeRange {
        start: learned_at,
        end: learned_at,
    };
    server
        .vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, occurred, learned_at)
        .commit()
        .map_err(|error| mcp_engine_error("mcp propose_claim failed", error))?;

    Ok(mcp_edit_receipt(
        args,
        actor,
        Some(id),
        "proposed",
        "immediate_proposed_claim",
        "claim proposed",
    ))
}

pub(crate) fn execute_mcp_proposed_control_record(
    server: &SyncServer,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> Result<Value, McpGatewayError> {
    let lifecycle = mcp_edit_lifecycle(args.verb);
    let id = mcp_idempotency_entity_id("proposal", args, actor);
    if let Some(receipt) =
        mcp_existing_edit_receipt(server, args, actor, id, lifecycle, "edit replayed")?
    {
        return Ok(receipt);
    }

    let target = mcp_lifecycle_target_id(args)?;
    let candidate = mcp_control_record_candidate(args, actor, lifecycle)?;
    let envelope = mcp_write_envelope(args, actor, lifecycle)?;
    let learned_at = unix_seconds_now();
    let occurred = oneiron::TimeRange {
        start: learned_at,
        end: learned_at,
    };
    // Guard and proposal share ONE write transaction. Checking the target in
    // its own transaction and then opening a second one to write is exactly
    // the grounding-read race this ticket closes: the target could move in
    // between. On a stale target the transaction rolls back, so no proposal
    // Claim, no gate receipt, and no idempotency row commits.
    let verb = args.verb;
    server
        .vault
        .with_write_txn(|wtxn| {
            if let Some(target) = target {
                match verb {
                    McpEditVerb::AttestEdgeProvenance => server
                        .vault
                        .require_named_provenance_target_active_in(&*wtxn, &target)?,
                    _ => {
                        server
                            .vault
                            .require_named_claim_target_active_in(&*wtxn, &target)?;
                    }
                }
            }
            server
                .vault
                .batch_in()
                .claim_candidate(&id, candidate, &envelope, occurred, learned_at)
                .apply(wtxn)
        })
        .map_err(|error| mcp_engine_error("mcp proposed control record failed", error))?;

    Ok(mcp_edit_receipt(
        args,
        actor,
        Some(id),
        "proposed",
        lifecycle,
        "edit proposed",
    ))
}

/// The engine id of the lifecycle target this verb NAMES, if it names one.
/// The field name travels with the error so a bad ref points at the argument
/// the caller actually wrote.
pub(crate) fn mcp_lifecycle_target_id(
    args: &McpEditToolArgs,
) -> Result<Option<oneiron::EntityId>, McpGatewayError> {
    let Some(target_ref) = args.lifecycle_target_ref() else {
        return Ok(None);
    };
    let field = match args.verb {
        McpEditVerb::RetractClaim => "claim_id",
        _ => "old_claim_id",
    };
    parse_entity_id_param(target_ref, field)
        .map(Some)
        .map_err(mcp_api_error)
}

/// Guards the verb's named lifecycle target on its OWN read transaction.
///
/// This is the DRY-RUN door only: it reports the stale condition without
/// writing. A path that goes on to write must guard inside the transaction it
/// writes in — see [`execute_mcp_proposed_control_record`].
pub(crate) fn mcp_guard_lifecycle_target(
    vault: &oneiron::Vault,
    args: &McpEditToolArgs,
) -> Result<(), McpGatewayError> {
    let Some(target) = mcp_lifecycle_target_id(args)? else {
        return Ok(());
    };
    // Edge-provenance wrappers pick their current head by D14 cohort
    // precedence, not by a Supersedes chain, so attest has its own guard.
    match args.verb {
        McpEditVerb::AttestEdgeProvenance => vault.require_named_provenance_target_active(&target),
        _ => vault.require_named_claim_target_active(&target).map(|_| ()),
    }
    .map_err(|error| mcp_engine_error("mcp edit target guard failed", error))
}

pub(crate) fn mcp_claim_candidate_from_args(
    args: &McpEditToolArgs,
) -> Result<oneiron::ClaimCandidate, McpGatewayError> {
    let value =
        oneiron::companion_value_from_json(mcp_required_json(args.value.as_ref(), "value")?)
            .map_err(|error| mcp_engine_error("mcp claim value conversion failed", error))?;
    let mut candidate = oneiron::ClaimCandidate::new(
        mcp_required_str(args.predicate.as_deref(), "predicate")?,
        mcp_claim_subject(args.subject.as_ref())?,
        value,
        mcp_required_f32(args.confidence, "confidence")?,
    );
    if let Some(evidence) = args.evidence.as_ref() {
        candidate = candidate.with_evidence(
            oneiron::companion_value_from_json(evidence)
                .map_err(|error| mcp_engine_error("mcp claim evidence conversion failed", error))?,
        );
    }
    if let Some(salience) = args.salience {
        candidate = candidate.with_salience(salience);
    }
    candidate = candidate.with_validity(args.valid_from, args.valid_to);
    if let Some(world_ref) = args.world.as_deref() {
        candidate =
            candidate.with_world(parse_entity_id_param(world_ref, "world").map_err(mcp_api_error)?);
    }
    if let Some(scope) = args.scope.as_ref() {
        candidate = candidate.with_scope(
            oneiron::companion_value_from_json(scope)
                .map_err(|error| mcp_engine_error("mcp claim scope conversion failed", error))?,
        );
    }
    Ok(candidate)
}

pub(crate) fn mcp_control_record_candidate(
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    lifecycle: &'static str,
) -> Result<oneiron::ClaimCandidate, McpGatewayError> {
    let arguments = serde_json::to_value(args).map_err(|error| {
        McpGatewayError::new(
            -32603,
            "mcp_args_serialize_failed",
            format!("failed to serialize MCP edit arguments: {error}"),
        )
    })?;
    let value = oneiron::companion_value_from_json(&json!({
        "verb": mcp_edit_verb_name(args.verb),
        "idempotency_key": args.idempotency_key,
        "lifecycle": lifecycle,
        "arguments": arguments,
    }))
    .map_err(|error| mcp_engine_error("mcp control record value conversion failed", error))?;
    Ok(oneiron::ClaimCandidate::new(
        format!("mcp.proposal.{}", mcp_edit_verb_name(args.verb)),
        oneiron::ClaimSubject::Entity(actor.actor_ref),
        value,
        1.0,
    ))
}

pub(crate) fn mcp_write_envelope(
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    lifecycle: &'static str,
) -> Result<oneiron::WriteEnvelope, McpGatewayError> {
    let provenance = oneiron::WriteProvenance::new(
        oneiron::companion_value_from_json(&json!({
            "surface": "mcp",
            "tool": McpToolName::Edit.as_str(),
            "verb": mcp_edit_verb_name(args.verb),
            "idempotency_key": args.idempotency_key,
            "lifecycle": lifecycle,
            "consent": {
                "policy_ref": args.consent.policy_ref,
                "purpose": args.consent.purpose,
                "approval_ref": args.consent.approval_ref,
                "consent_receipt_ref": args.consent.consent_receipt_ref,
                "require_human_approval": args.consent.require_human_approval,
            }
        }))
        .map_err(|error| mcp_engine_error("mcp provenance conversion failed", error))?,
    )
    .map_err(|error| mcp_engine_error("mcp provenance invalid", error))?;
    Ok(oneiron::WriteEnvelope::new(
        actor.write_actor(),
        oneiron::ClaimSource::ToolOutput,
        provenance,
        oneiron::ClaimApprovalStatus::Proposed,
    ))
}

pub(crate) fn mcp_claim_subject(
    subject: Option<&crate::mcp::McpEditSubject>,
) -> Result<oneiron::ClaimSubject, McpGatewayError> {
    let subject = subject.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "subject is required")
            .with_field("subject")
    })?;
    match (subject.entity.as_deref(), subject.edge.as_ref()) {
        (Some(entity), None) => Ok(oneiron::ClaimSubject::Entity(
            parse_entity_id_param(entity, "subject.entity").map_err(mcp_api_error)?,
        )),
        (None, Some(edge)) => Ok(oneiron::ClaimSubject::Edge {
            source: parse_entity_id_param(&edge.source, "subject.edge.source")
                .map_err(mcp_api_error)?,
            kind: EdgeKind::try_from_u8(edge.kind).ok_or_else(|| {
                McpGatewayError::new(
                    -32602,
                    "tool_args_invalid",
                    "subject.edge.kind is not a registered edge kind",
                )
                .with_field("subject.edge.kind")
            })?,
            target: parse_entity_id_param(&edge.target, "subject.edge.target")
                .map_err(mcp_api_error)?,
        }),
        _ => Err(McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "subject must include exactly one of entity or edge",
        )
        .with_field("subject")),
    }
}

pub(crate) fn mcp_required_str<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, McpGatewayError> {
    value.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", format!("{field} is required"))
            .with_field(field)
    })
}

pub(crate) fn mcp_required_json<'a>(
    value: Option<&'a Value>,
    field: &'static str,
) -> Result<&'a Value, McpGatewayError> {
    value.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", format!("{field} is required"))
            .with_field(field)
    })
}

pub(crate) fn mcp_required_f32(
    value: Option<f32>,
    field: &'static str,
) -> Result<f32, McpGatewayError> {
    value.ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", format!("{field} is required"))
            .with_field(field)
    })
}

pub(crate) fn mcp_edit_receipt(
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    proposal_id: Option<oneiron::EntityId>,
    status: &'static str,
    lifecycle: &'static str,
    message: &'static str,
) -> Value {
    let mut structured = json!({
        "tool": McpToolName::Edit.as_str(),
        "verb": mcp_edit_verb_name(args.verb),
        "idempotency_key": args.idempotency_key,
        "status": status,
        "lifecycle": lifecycle,
        "forced_source": "tool_output",
        "forced_approval": "proposed",
        "dryRun": args.dry_run,
        "actor": mcp_actor_result(actor),
    });
    if let Some(proposal_id) = proposal_id
        && let Some(object) = structured.as_object_mut()
    {
        object.insert("id".to_owned(), Value::String(proposal_id.to_hex()));
        object.insert(
            "proposal_id".to_owned(),
            Value::String(proposal_id.to_hex()),
        );
    }
    json!({
        "content": [mcp_text_content(message)],
        "structuredContent": structured,
        "isError": false,
    })
}

pub(crate) fn mcp_existing_edit_receipt(
    server: &SyncServer,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
    id: oneiron::EntityId,
    lifecycle: &'static str,
    message: &'static str,
) -> Result<Option<Value>, McpGatewayError> {
    let existing = server
        .vault
        .get_claim(&id)
        .map_err(|error| mcp_engine_error("mcp edit replay lookup failed", error))?;
    Ok(existing.map(|_| mcp_edit_receipt(args, actor, Some(id), "replayed", lifecycle, message)))
}

pub(crate) fn mcp_idempotency_entity_id(
    namespace: &'static str,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> oneiron::EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mcp.edit.v1");
    hasher.update(namespace.as_bytes());
    hasher.update(actor.actor_ref.as_bytes());
    hasher.update(actor.gate_actor_class.as_bytes());
    hasher.update(actor.gate_actor_ref.as_bytes());
    if let Some(world_ref) = actor.scope.world_ref {
        hasher.update(world_ref.as_bytes());
    }
    if let Some(facet_ref) = actor.scope.facet_ref {
        hasher.update(facet_ref.as_bytes());
    }
    hasher.update(mcp_edit_verb_name(args.verb).as_bytes());
    hasher.update(args.idempotency_key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    loop {
        if let Ok(id) = oneiron::EntityId::from_bytes(bytes) {
            return id;
        }
        bytes[0] ^= 0x42;
    }
}

pub(crate) fn mcp_edit_lifecycle(verb: McpEditVerb) -> &'static str {
    match verb {
        McpEditVerb::ProposeClaim => "immediate_proposed_claim",
        McpEditVerb::SupersedeClaim | McpEditVerb::RetractClaim | McpEditVerb::ProposeEntity => {
            "deferred_proposed"
        }
        McpEditVerb::AttestEdgeProvenance
        | McpEditVerb::PostTask
        | McpEditVerb::ReportTask
        | McpEditVerb::ChannelSend => "proposed_control_record",
    }
}

pub(crate) fn mcp_edit_verb_name(verb: McpEditVerb) -> &'static str {
    match verb {
        McpEditVerb::ProposeClaim => "propose_claim",
        McpEditVerb::AttestEdgeProvenance => "attest_edge_provenance",
        McpEditVerb::SupersedeClaim => "supersede_claim",
        McpEditVerb::RetractClaim => "retract_claim",
        McpEditVerb::ProposeEntity => "propose_entity",
        McpEditVerb::PostTask => "post_task",
        McpEditVerb::ReportTask => "report_task",
        McpEditVerb::ChannelSend => "channel_send",
    }
}

pub(crate) fn mcp_ask_result(args: McpAskToolArgs, actor: &McpResolvedActor) -> Value {
    json!({
        "content": [mcp_text_content("ask accepted")],
        "structuredContent": {
            "tool": McpToolName::Ask.as_str(),
            "status": "accepted",
            "query": args.query,
            "context_pack": args.context_pack,
            "effort": args.effort,
            "citation_mode": args.citation_mode,
            "actor": mcp_actor_result(actor),
        },
        "isError": false,
    })
}

pub(crate) fn mcp_routed_ask_result(args: McpRoutedAskToolArgs, actor: &McpResolvedActor) -> Value {
    json!({
        "content": [mcp_text_content("routed ask accepted")],
        "structuredContent": {
            "tool": McpToolName::RoutedAsk.as_str(),
            "status": "accepted",
            "query": args.query,
            "context_pack": args.context_pack,
            "route": args.route,
            "effort": args.effort,
            "citation_mode": args.citation_mode,
            "actor": mcp_actor_result(actor),
        },
        "isError": false,
    })
}

pub(crate) fn mcp_scoped_read<'a>(
    vault: &'a oneiron::Vault,
    actor: &McpResolvedActor,
) -> Result<oneiron::claim::ScopedRead<'a>, McpGatewayError> {
    let key = oneiron::claim::ScopedReadActorKey::with_actor_class(
        &actor.gate_actor_ref,
        actor.gate_actor_class,
    )
    .ok_or_else(|| {
        McpGatewayError::new(
            -32003,
            "mcp_actor_invalid",
            "resolved actor cannot be used as a scoped read key",
        )
    })?;
    Ok(vault.scoped_read(key))
}

pub(crate) fn mcp_actor_result(actor: &McpResolvedActor) -> Value {
    json!({
        "actor_ref": actor.actor_ref.to_hex(),
        "actor_class": actor.gate_actor_class,
        "gate_actor_ref": actor.gate_actor_ref,
        "gate_actor_class": actor.gate_actor_class,
        "scope": {
            "world_ref": actor.scope.world_ref.map(|id| id.to_hex()),
            "facet_ref": actor.scope.facet_ref.map(|id| id.to_hex()),
        },
    })
}

pub(crate) fn mcp_actor_class_wire(actor_class: McpActorClass) -> &'static str {
    match actor_class {
        McpActorClass::Human => "human",
        McpActorClass::Agent => "agent",
    }
}

pub(crate) fn mcp_text_content(text: impl Into<String>) -> Value {
    json!({
        "type": "text",
        "text": text.into(),
    })
}

pub(crate) fn mcp_api_error(error: ApiError) -> McpGatewayError {
    let code = match error.code() {
        ErrorCode::BadRequest => -32602,
        ErrorCode::NotFound => -32004,
        ErrorCode::InvalidState => -32020,
        ErrorCode::InternalServerError => -32603,
        _ => -32000,
    };
    let mut gateway = McpGatewayError::new(code, error.code().as_str(), error.message());
    if let ApiErrorDetails::BadRequest { field } = error.details()
        && let Some(field) = field
    {
        gateway = gateway.with_field(field.clone());
    }
    gateway
}

pub(crate) fn mcp_engine_error(context: &'static str, error: oneiron::Error) -> McpGatewayError {
    // ONE-1936: a stale write-verb target gets its own stable kind, not the
    // generic engine_error bucket, and carries the current head as data. The
    // caller re-gets that ref and decides again; nothing was written.
    if let oneiron::Error::WriteVerbTargetStale {
        successor_short_id, ..
    } = &error
    {
        return McpGatewayError::new(-32020, "write_verb_target_stale", error.to_string())
            .with_successor_short_id(successor_short_id.clone());
    }
    match error.kind() {
        ErrorKind::GateWriteRejected => {
            McpGatewayError::new(-32020, "gate_write_rejected", error.to_string())
        }
        ErrorKind::GateConsentStale => {
            McpGatewayError::new(-32020, "gate_consent_stale", error.to_string())
        }
        ErrorKind::EntityNotFound => {
            McpGatewayError::new(-32004, "entity_not_found", error.to_string())
        }
        _ => McpGatewayError::new(-32603, "engine_error", format!("{context}: {error}")),
    }
}

pub(crate) fn mcp_error_response(id: Value, error: McpGatewayError) -> Value {
    let mut data = json!({ "kind": error.kind });
    if let Some(field) = error.field
        && let Some(object) = data.as_object_mut()
    {
        object.insert("field".to_owned(), Value::String(field));
    }
    if let Some(successor_short_id) = error.successor_short_id
        && let Some(object) = data.as_object_mut()
    {
        object.insert(
            "successor_short_id".to_owned(),
            Value::String(successor_short_id),
        );
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message,
            "data": data,
        },
    })
}
