//! Facade-backed MCP verb executors.

use super::{
    McpGatewayError, mcp_actor_result, mcp_api_error, mcp_engine_error, mcp_scoped_read,
    mcp_text_content,
};
use crate::api::CORE_MAX_LIST_LIMIT;
use crate::api::hydrate_short_id_response;
use crate::api::parse_entity_id_param;
use crate::api::parse_short_ref;
use crate::api::unix_seconds_now;
use crate::mcp::McpAskToolArgs;
use crate::mcp::McpEditToolArgs;
use crate::mcp::McpEditVerb;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpRoutedAskToolArgs;
use crate::mcp::McpToolName;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use oneiron::EdgeKind;
use serde_json::Value;
use serde_json::json;

/// Dispatches `oneiron.calendar`.
///
/// Every arm goes through [`oneiron::Memory`] — the calendar dialect owns
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
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);

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
pub(crate) fn mcp_facade_error(error: oneiron::MemoryError) -> McpGatewayError {
    let code = match error.code.as_str() {
        oneiron::MEMORY_CODE_NOT_FOUND => -32004,
        oneiron::MEMORY_CODE_FORBIDDEN | oneiron::MEMORY_CODE_INVALID_STATE => -32020,
        oneiron::MEMORY_CODE_INTERNAL => -32603,
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
                .search_text(query, limit, None)
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

/// The retained edit adapter's idempotency row id.
///
/// Routed through the ONE central derivation (ONE-1704 M3) so this adapter and
/// the `execute_code` run handle cannot drift into two identity rules: the
/// credential fingerprint and the whole immutable connector scope are mixed in
/// there, not here.
pub(crate) fn mcp_idempotency_entity_id(
    namespace: &'static str,
    args: &McpEditToolArgs,
    actor: &McpResolvedActor,
) -> oneiron::EntityId {
    crate::mcp::mcp_scoped_identity_id(
        namespace,
        &format!(
            "{verb}\u{1f}{key}",
            verb = mcp_edit_verb_name(args.verb),
            key = args.idempotency_key,
        ),
        actor,
    )
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
